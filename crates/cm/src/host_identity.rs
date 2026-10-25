use std::io::Write;

const IDENTITY: &str = include_str!(env!("CM_HOST_IDENTITY_JSON"));

pub fn print() -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(IDENTITY.as_bytes())?;
    stdout.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::IDENTITY;

    #[test]
    fn embedded_identity_is_complete() -> anyhow::Result<()> {
        let identity: serde_json::Value = serde_json::from_str(IDENTITY)?;
        let build_id = identity["host_build_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing Host build identity"))?;
        assert_eq!(build_id.len(), "sha256:".len() + 64);
        assert!(build_id.starts_with("sha256:"));
        assert_eq!(identity["stage"], "runtime-consumer-output-limit");
        assert_eq!(
            identity["capabilities"],
            serde_json::json!([
                "core.tool_parallel_eligibility.v1",
                "core.tool_parallel_eligibility.compose.v1",
                "core.exec_output_limit.v1"
            ])
        );
        assert!(identity.get("artifact_sha256").is_none());
        Ok(())
    }
}
