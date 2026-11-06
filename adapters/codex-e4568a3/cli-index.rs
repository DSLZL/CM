//! Bounded data transport for the first-party binary index. Never spawns an installer.
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use cm_runtime::index::{self, Resource, Transport};
use cm_runtime::{LoadError, config};
use url::Url;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Refresh or read a signed index without changing the enabled selection.
    List {
        #[arg(long)]
        source: String,
        #[arg(long)]
        offline: bool,
    },
    /// Download exact precompiled versions and write a private immutable preview.
    Plan {
        #[arg(long)]
        source: String,
        #[arg(long = "mod", required = true, value_name = "ID@VERSION")]
        selections: Vec<String>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        offline: bool,
    },
    /// Revalidate a preview and atomically select its complete next generation.
    Install {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        offline: bool,
    },
}

fn failure(code: &str, text: &str) -> LoadError {
    LoadError::input(code, "", text)
}

fn safe_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
        && url.username().is_empty() && url.password().is_none()
        && url.query().is_none() && url.fragment().is_none()
}

fn same_origin(base: &Url, target: &Url) -> bool {
    safe_url(target) && base.origin() == target.origin()
}

enum Source {
    File(PathBuf),
    Http { index: Url, client: reqwest::Client },
}

impl Source {
    fn new(source: &str) -> Result<Self, LoadError> {
        if source.starts_with("http://") || source.starts_with("https://") {
            let index = Url::parse(source).map_err(|_| failure("index_source", "invalid HTTP source"))?;
            if !safe_url(&index) { return Err(failure("index_source", "credential-free HTTP(S) source required")); }
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .read_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(20))
                .no_proxy().referer(false)
                .no_gzip().no_brotli().no_deflate().no_zstd()
                .build().map_err(|_| failure("index_source", "cannot initialize HTTP transport"))?;
            Ok(Self::Http { index, client })
        } else {
            let path = PathBuf::from(source);
            if !path.is_absolute() || path.file_name().is_none()
                || path.components().any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
            { return Err(failure("index_source", "absolute regular index file required")); }
            Ok(Self::File(path))
        }
    }

    fn identity(&self) -> Result<String, LoadError> {
        match self {
            Self::File(path) => path.to_str().map(str::to_owned)
                .ok_or_else(|| failure("index_source", "UTF8 source required")),
            Self::Http { index, .. } => Ok(index.as_str().to_owned()),
        }
    }
}

impl Transport for Source {
    async fn fetch(&mut self, resource: Resource<'_>, limit: u64) -> Result<Vec<u8>, LoadError> {
        match self {
            Self::File(index) => {
                let path = match resource {
                    Resource::Index => index.clone(),
                    Resource::IndexBundle => PathBuf::from(format!("{}.bundle.jsonl", index.to_str()
                        .ok_or_else(|| failure("index_source", "UTF8 source required"))?)),
                    Resource::Artifact(relative) => index.parent().expect("source parent").join(relative),
                };
                index::read_transport_file(&path, limit)
            }
            Self::Http { index, client } => {
                let mut target = match resource {
                    Resource::Index => index.clone(),
                    Resource::IndexBundle => Url::parse(&format!("{}.bundle.jsonl", index.as_str()))
                        .map_err(|_| failure("index_source", "invalid sidecar URL"))?,
                    Resource::Artifact(relative) => index.join(relative)
                        .map_err(|_| failure("index_source", "invalid artifact URL"))?,
                };
                let operation = async {
                    for redirects in 0..=3 {
                        if !same_origin(index, &target) {
                            return Err(failure("index_redirect", "cross-origin or unsafe URL rejected"));
                        }
                        let mut response = client.get(target.clone()).header(reqwest::header::ACCEPT_ENCODING, "identity")
                            .send().await.map_err(|e| failure(if e.is_timeout() {"index_timeout"} else {"index_http"}, "HTTP request failed"))?;
                        if response.status().is_redirection() {
                            if redirects == 3 { return Err(failure("index_redirect", "redirect limit exceeded")); }
                            let location = response.headers().get(reqwest::header::LOCATION)
                                .and_then(|v| v.to_str().ok()).filter(|v| v.len() <= 2048)
                                .ok_or_else(|| failure("index_redirect", "invalid redirect location"))?;
                            let next = target.join(location).map_err(|_| failure("index_redirect", "invalid redirect URL"))?;
                            if !same_origin(index, &next) { return Err(failure("index_redirect", "cross-origin redirect rejected")); }
                            target = next;
                            continue;
                        }
                        if !response.status().is_success() { return Err(failure("index_http", "HTTP status rejected")); }
                        if response.content_length().is_some_and(|size| size > limit) {
                            return Err(failure("index_size", "HTTP content length exceeds limit"));
                        }
                        if response.headers().get(reqwest::header::CONTENT_ENCODING).is_some_and(|v| v != "identity") {
                            return Err(failure("index_http", "compressed HTTP transfer rejected"));
                        }
                        let mut bytes = Vec::new();
                        while let Some(chunk) = response.chunk().await
                            .map_err(|e| failure(if e.is_timeout() {"index_timeout"} else {"index_http"}, "HTTP body failed"))?
                        {
                            if bytes.len() as u64 + chunk.len() as u64 > limit {
                                return Err(failure("index_size", "streamed body exceeds limit"));
                            }
                            bytes.extend_from_slice(&chunk);
                        }
                        return Ok(bytes);
                    }
                    unreachable!("redirect limit returns above")
                };
                tokio::time::timeout(Duration::from_secs(20), operation).await
                    .map_err(|_| failure("index_timeout", "HTTP operation timed out"))?
            }
        }
    }
}

pub(crate) async fn run(home: &Path, args: &Args, options: &config::Options) -> Result<serde_json::Value, LoadError> {
    let (source, offline, command) = match &args.command {
        Command::List { source, offline } => (source.clone(), *offline, index::Command::List),
        Command::Plan { source, selections, out, offline } =>
            (source.clone(), *offline, index::Command::Plan { selections, output:out }),
        Command::Install { plan, offline } => (index::plan_source(plan)?, *offline, index::Command::Install { plan }),
    };
    let mut transport = Source::new(&source)?;
    let identity = transport.identity()?;
    index::run(home, &identity, command, offline, &mut transport, options).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_preserve_the_exact_origin_without_credentials() {
        let base = Url::parse("https://example.invalid/index.json").unwrap();
        assert!(same_origin(&base, &base.join("packages/mod.cmod").unwrap()));
        for value in ["http://example.invalid/a", "https://example.invalid:8443/a", "https://other.invalid/a",
            "https://user:secret@example.invalid/a", "file:///tmp/index.json", "https://example.invalid/a?token=secret"] {
            assert!(!same_origin(&base, &Url::parse(value).unwrap()), "{value}");
        }
    }
}
