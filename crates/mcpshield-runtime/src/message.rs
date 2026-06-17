use mcpshield_policy::{proxy_filter, PolicyEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC application error code for policy denials.
pub const ERR_CODE_POLICY_DENIED: i64 = -32001;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: String,
    pub id: Value,
    pub error: JsonRpcError,
}

impl JsonRpcErrorResponse {
    pub fn policy_denied(id: Value, reason: &str) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            error: JsonRpcError {
                code: ERR_CODE_POLICY_DENIED,
                message: format!("policy denied: {reason}"),
            },
        }
    }
}

/// Inspect a raw JSON-RPC line and enforce policy against the given engine.
///
/// Returns `Some(error_json_string)` when the call is blocked, `None` when it
/// should be forwarded unchanged to the child server.
///
/// Enforcement covers:
/// - `tools/call`: capability allowlist check + exhaustive outbound-host scan of
///   all string values in the arguments tree (any key, any nesting depth).
/// - `resources/read`: resource URI allowlist check.
///
/// JSON-RPC notifications (no `"id"` field) are always passed through — they
/// cannot carry tool invocations and blocking them would break the MCP protocol.
pub fn check_policy_for_line(engine: &PolicyEngine, raw: &str) -> Option<String> {
    let msg: Value = serde_json::from_str(raw).ok()?;

    let method = msg.get("method")?.as_str()?;
    // JSON-RPC notifications have no "id" — pass them through without policy check.
    let id = msg.get("id")?.clone();

    let deny_reason: Option<String> = match method {
        "tools/call" => {
            let tool_name = msg
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");

            match engine.check_tool(tool_name) {
                Err(e) => Some(e.to_string()),
                Ok(()) => {
                    let args = msg
                        .get("params")
                        .and_then(|p| p.get("arguments"))
                        .unwrap_or(&Value::Null);

                    // Outbound evaluation pipeline (PLAN-RULE-01), fail-closed,
                    // in order: proxy filter → DLP scan. A failure at any stage
                    // denies the entire request.
                    //
                    // Stage — proxy filter: recursively extract every URL-like
                    // string from the tool arguments and check each host against
                    // the proxy filter. A single blocked host denies the request
                    // regardless of argument key name or nesting.
                    let outbound_denied = proxy_filter::extract_hosts_from_value(args)
                        .into_iter()
                        .find_map(|host| engine.check_outbound(&host).err());

                    // Stage — DLP scan: recursively scan the arguments for
                    // sensitive data (PII, secrets); any match denies the request.
                    outbound_denied
                        .or_else(|| engine.check_payload(args).err())
                        .map(|e| e.to_string())
                }
            }
        }
        "resources/read" => {
            let uri = msg
                .get("params")
                .and_then(|p| p.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("");
            engine.check_resource(uri).err().map(|e| e.to_string())
        }
        _ => None,
    };

    let deny_reason = deny_reason?;
    let resp = JsonRpcErrorResponse::policy_denied(id, &deny_reason);
    serde_json::to_string(&resp).ok()
}

#[cfg(test)]
mod tests {
    use mcpshield_policy::{
        CapabilityAllowlist, DlpRuleset, OutboundFilter, PolicyEngine, PolicySnapshot,
    };

    use super::*;

    fn engine() -> PolicyEngine {
        let allowlist = CapabilityAllowlist::new(
            vec!["read_file".into(), "search_web".into()],
            vec!["file:///tmp/".into()],
        );
        let filter = OutboundFilter::new(vec!["api.example.com".into()]);
        let snap = PolicySnapshot::new(
            allowlist,
            filter,
            DlpRuleset::with_defaults(),
            1,
            b"test-key",
        )
        .unwrap();
        PolicyEngine::new(snap).unwrap()
    }

    // --- Red-team: malicious tool calls that must be blocked ---

    #[test]
    fn blocks_exec_shell() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_shell","arguments":{"cmd":"rm -rf /"}}}"#;
        let result = check_policy_for_line(&engine(), line);
        assert!(result.is_some(), "exec_shell must be blocked");
        let err: Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(err["error"]["code"], ERR_CODE_POLICY_DENIED);
    }

    #[test]
    fn blocks_system_exec() {
        let line =
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"system_exec"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_arbitrary_code_eval() {
        let line =
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"eval_code"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_write_file_not_in_allowlist() {
        let line =
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_delete_file_not_in_allowlist() {
        let line =
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_file"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_resource_read_outside_prefix() {
        let line = r#"{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"file:///etc/shadow"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_resource_read_etc_passwd() {
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"file:///etc/passwd"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_outbound_call_to_evil_host_via_url_key() {
        let line = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_file","arguments":{"url":"https://evil.com/exfil"}}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_outbound_call_via_endpoint_key() {
        let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"endpoint":"http://attacker.example/steal"}}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    #[test]
    fn blocks_network_fetch_not_in_tool_allowlist() {
        // fetch_url is not in the tool allowlist even if the host would be allowed.
        let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://api.example.com/data"}}}"#;
        assert!(check_policy_for_line(&engine(), line).is_some());
    }

    // --- Comprehensive outbound filter tests ---

    #[test]
    fn blocks_evil_host_in_nested_argument() {
        // Host hidden inside a nested object — must still be blocked.
        let line = r#"{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"read_file","arguments":{"config":{"server":"evil.com"}}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "nested evil host must be blocked"
        );
    }

    #[test]
    fn blocks_evil_host_in_array_argument() {
        // Hosts buried in an array value.
        let line = r#"{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"read_file","arguments":{"targets":["https://api.example.com/ok","https://evil.com/exfil"]}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "evil host inside array must be blocked"
        );
    }

    #[test]
    fn blocks_evil_host_in_host_key_without_scheme() {
        // Plain hostname in a "host" key — no URL scheme to signal a URL.
        let line = r#"{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"read_file","arguments":{"host":"evil.com"}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "plain evil hostname in host key must be blocked"
        );
    }

    #[test]
    fn blocks_evil_host_in_target_key() {
        let line = r#"{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"read_file","arguments":{"target":"evil.com"}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "evil host in target key must be blocked"
        );
    }

    #[test]
    fn blocks_evil_host_via_arbitrary_key_with_scheme() {
        // Non-standard key, but value starts with https:// — must be caught.
        let line = r#"{"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"read_file","arguments":{"x_custom_cb":"https://evil.com/steal"}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "https:// value on arbitrary key must be blocked"
        );
    }

    #[test]
    fn blocks_evil_host_in_deeply_nested_structure() {
        let line = r#"{"jsonrpc":"2.0","id":25,"method":"tools/call","params":{"name":"read_file","arguments":{"a":{"b":{"c":{"url":"https://evil.com/deep"}}}}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "deeply nested evil host must be blocked"
        );
    }

    #[test]
    fn blocks_when_one_of_multiple_hosts_is_evil() {
        // Even though api.example.com is allowed, evil.com is not — request blocked.
        let line = r#"{"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"read_file","arguments":{"primary":"https://api.example.com/ok","secondary":"https://evil.com/bad"}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "presence of one blocked host must deny the request"
        );
    }

    // --- DLP scan: sensitive data in tool-call arguments must be blocked ---

    #[test]
    fn blocks_tool_call_leaking_ssn_in_arguments() {
        let line = r#"{"jsonrpc":"2.0","id":50,"method":"tools/call","params":{"name":"read_file","arguments":{"note":"ssn 123-45-6789"}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "SSN in arguments must be blocked by DLP"
        );
    }

    #[test]
    fn blocks_tool_call_leaking_secret_in_nested_arguments() {
        let line = r#"{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"read_file","arguments":{"env":{"key":"AKIAIOSFODNN7EXAMPLE"}}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_some(),
            "AWS key in nested arguments must be blocked by DLP"
        );
    }

    #[test]
    fn dlp_block_uses_policy_denied_code_and_names_rule_only() {
        let line = r#"{"jsonrpc":"2.0","id":52,"method":"tools/call","params":{"name":"read_file","arguments":{"data":"123-45-6789"}}}"#;
        let result = check_policy_for_line(&engine(), line).unwrap();
        let err: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(err["error"]["code"], ERR_CODE_POLICY_DENIED);
        let message = err["error"]["message"].as_str().unwrap();
        assert!(message.contains("us_ssn"), "deny reason must name the rule");
        assert!(
            !message.contains("123-45-6789"),
            "deny reason must not leak the matched value"
        );
    }

    // --- Green path: legitimate calls that must pass through ---

    #[test]
    fn allows_permitted_tool() {
        let line =
            r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_file"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    #[test]
    fn allows_permitted_tool_with_allowed_host_in_url() {
        let line = r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"read_file","arguments":{"url":"https://api.example.com/data"}}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    #[test]
    fn allows_permitted_tool_with_allowed_host_in_host_key() {
        let line = r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"read_file","arguments":{"host":"api.example.com"}}}"#;
        assert!(
            check_policy_for_line(&engine(), line).is_none(),
            "allowed host in host key must pass through"
        );
    }

    #[test]
    fn allows_permitted_resource() {
        let line = r#"{"jsonrpc":"2.0","id":13,"method":"resources/read","params":{"uri":"file:///tmp/data.json"}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    #[test]
    fn passes_through_initialize() {
        let line = r#"{"jsonrpc":"2.0","id":14,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    #[test]
    fn passes_through_tools_list() {
        let line = r#"{"jsonrpc":"2.0","id":15,"method":"tools/list","params":{}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    #[test]
    fn passes_through_notifications() {
        // Notifications have no "id" field — must never be blocked.
        let line = r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    #[test]
    fn passes_through_non_json() {
        // Non-JSON lines (e.g. startup banner) must be forwarded unchanged.
        assert!(check_policy_for_line(&engine(), "not json at all").is_none());
    }

    #[test]
    fn passes_through_json_without_method() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        assert!(check_policy_for_line(&engine(), line).is_none());
    }

    // --- Error response shape ---

    #[test]
    fn blocked_tool_error_contains_tool_name() {
        let line =
            r#"{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"exec_shell"}}"#;
        let result = check_policy_for_line(&engine(), line).unwrap();
        let err: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(err["error"]["code"], ERR_CODE_POLICY_DENIED);
        assert!(err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exec_shell"));
        assert_eq!(err["id"], 40);
    }

    #[test]
    fn blocked_host_error_contains_host() {
        let line = r#"{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"read_file","arguments":{"url":"https://evil.com/x"}}}"#;
        let result = check_policy_for_line(&engine(), line).unwrap();
        let err: Value = serde_json::from_str(&result).unwrap();
        assert!(err["error"]["message"]
            .as_str()
            .unwrap()
            .contains("evil.com"));
    }
}
