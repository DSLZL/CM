use cm_sdk::{Host, Init, Mod, Request, abi::Bytes, v22};

const RESPONSE: &[u8] = br#"{"version":"v2","result":"hello from native-mod"}"#;

struct Greeting {
    host: Host,
}

fn create(init: Init) -> Result<Greeting, String> {
    Ok(Greeting { host: init.host })
}

impl Mod for Greeting {
    fn dispatch(&mut self, request: Request) -> Result<(), String> {
        if request.event != v22::TOOL_CALL || request.route != 1 {
            return Err("unsupported greeting request".into());
        }
        self.host
            .complete(request.handle, v22::SUCCEEDED, RESPONSE, true)
            .map_err(|_| "greeting completion rejected".into())
    }

    fn cancel(&mut self, _request: v22::Handle) -> Result<(), String> {
        // Synchronous completion is already quiescent; no worker retains the handle.
        Ok(())
    }
}

const CONTRIBUTIONS: &[v22::RuntimeContribution] = &[v22::RuntimeContribution {
    header: v22::header::<v22::RuntimeContribution>(),
    id: Bytes::from_static("greet"),
    capability: Bytes::from_static(v22::TOOL),
    resource: Bytes::from_static("native-mod__greet"),
    kind: v22::KIND_TOOL,
    reserved: 0,
    route: 1,
}];

cm_sdk::export_mod!(Greeting, "native-mod", create, crate::CONTRIBUTIONS);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_has_an_explicit_version_and_no_untrusted_input() {
        assert!(RESPONSE.starts_with(b"{\"version\":"));
        assert!(RESPONSE.ends_with(b"\"}"));
        assert_eq!(CONTRIBUTIONS[0].route, 1);
    }
}
