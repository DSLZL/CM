use super::*;
use clap::{ArgMatches, FromArgMatches};
use cm_runtime::commands::{Graph, Input, Section};
use std::sync::OnceLock;

static GRAPH: OnceLock<Result<Graph, cm_runtime::LoadError>> = OnceLock::new();

pub(super) fn graph() -> Result<&'static Graph, cm_runtime::LoadError> {
    GRAPH.get_or_init(|| {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if !args.iter().any(|value| ["run", "completion", "help", "--help", "-h"].iter().any(|name| value == *name)) {
            return Ok(Graph::default());
        }
        let mut home = None;
        let mut options = cm_runtime::config::Options::default();
        let mut index = 0;
        while index < args.len() {
            let token = args[index].to_str().unwrap_or("");
            if token == "--" { break; }
            let mut value = |flag: &str| -> Option<std::ffi::OsString> {
                if token == flag { index += 1; args.get(index).cloned() }
                else { token.strip_prefix(&format!("{flag}=")).map(Into::into) }
            };
            if let Some(value) = value("--home") { home = Some(std::path::PathBuf::from(value)); }
            else if let Some(value) = value("--cm-profile") { options.profile = value.into_string().ok(); }
            else if let Some(value) = value("--cm-set") {
                if let Ok(value) = value.into_string() { options.overrides.push(value); }
            }
            index += 1;
        }
        let home = match home {
            Some(home) => home,
            None => find_codex_home().map_err(|error| cm_runtime::LoadError::input("command_graph", "", &error.to_string()))?,
        };
        Graph::prepare(&home, &options)
    }).as_ref().map_err(Clone::clone)
}

pub(super) fn command() -> Result<clap::Command, clap::Error> {
    let graph = graph().map_err(|error| clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string()))?;
    graph.check_names(Section::Cli, ["help"])
        .map_err(|error| clap::Error::raw(clap::error::ErrorKind::InvalidValue, error.to_string()))?;
    Ok(MultitoolCli::command().mut_subcommand("cm", |cm| cm.mut_subcommand("run", |mut run| {
        for command in graph.entries(Section::Cli) {
            let mut child = clap::Command::new(command.spec.name.clone()).about(command.spec.help.clone());
            if command.spec.input != Input::None {
                child = child.arg(clap::Arg::new("input").value_name("INPUT").required(command.spec.input == Input::Required));
            }
            run = run.subcommand(child);
        }
        run
    })))
}

pub(super) fn try_parse() -> Result<MultitoolCli, clap::Error> {
    let mut matches = command()?.try_get_matches()?;
    MultitoolCli::from_arg_matches_mut(&mut matches)
}

pub(super) fn parse() -> MultitoolCli { try_parse().unwrap_or_else(|error| error.exit()) }

#[derive(Debug)]
pub(super) struct Run { pub(super) name: String, pub(super) input: Option<String> }

impl clap::Args for Run {
    fn augment_args(command: clap::Command) -> clap::Command { command.subcommand_required(true).arg_required_else_help(true) }
    fn augment_args_for_update(command: clap::Command) -> clap::Command { Self::augment_args(command) }
}

impl FromArgMatches for Run {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let (name, child) = matches.subcommand().ok_or_else(|| clap::Error::raw(clap::error::ErrorKind::MissingSubcommand, "CM command required"))?;
        Ok(Self { name: name.into(), input: child.try_get_one::<String>("input").ok().flatten().cloned() })
    }
    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> { *self = Self::from_arg_matches(matches)?; Ok(()) }
}
