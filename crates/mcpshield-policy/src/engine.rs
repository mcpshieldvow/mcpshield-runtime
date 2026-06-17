use serde_json::Value;

use crate::{dlp::DlpEngine, error::PolicyError, snapshot::PolicySnapshot};

/// Enforces the active policy snapshot for every inbound tool call and outbound network request.
pub struct PolicyEngine {
    snapshot: PolicySnapshot,
    dlp: DlpEngine,
}

impl PolicyEngine {
    /// Build an engine from a signed snapshot, compiling its DLP ruleset.
    ///
    /// Fails with [`PolicyError::InvalidDlpRule`] when a DLP pattern in the
    /// snapshot is not a valid regular expression — a malformed ruleset must
    /// abort startup rather than silently leave payloads unscanned.
    pub fn new(snapshot: PolicySnapshot) -> Result<Self, PolicyError> {
        let dlp = DlpEngine::compile(&snapshot.dlp)?;
        Ok(Self { snapshot, dlp })
    }

    /// Returns the version of the loaded policy snapshot.
    pub fn version(&self) -> u64 {
        self.snapshot.version
    }

    /// Check whether a named MCP tool call is permitted.
    pub fn check_tool(&self, tool_name: &str) -> Result<(), PolicyError> {
        if self.snapshot.allowlist.allows_tool(tool_name) {
            tracing::debug!(
                tool = tool_name,
                policy_version = self.snapshot.version,
                action = "allowed",
                "tool call permitted by capability allowlist"
            );
            return Ok(());
        }
        tracing::warn!(
            tool = tool_name,
            policy_version = self.snapshot.version,
            action = "blocked",
            "tool call blocked by capability allowlist"
        );
        Err(PolicyError::CapabilityDenied(tool_name.to_owned()))
    }

    /// Check whether an outbound network request to the given host is permitted.
    pub fn check_outbound(&self, host: &str) -> Result<(), PolicyError> {
        if self.snapshot.outbound_filter.allows_host(host) {
            tracing::debug!(
                host,
                policy_version = self.snapshot.version,
                action = "allowed",
                "outbound call permitted by proxy filter"
            );
            return Ok(());
        }
        tracing::warn!(
            host,
            policy_version = self.snapshot.version,
            action = "blocked",
            "outbound call blocked by proxy filter"
        );
        Err(PolicyError::OutboundBlocked(host.to_owned()))
    }

    /// Check whether a resource URI is accessible.
    pub fn check_resource(&self, resource_uri: &str) -> Result<(), PolicyError> {
        if self.snapshot.allowlist.allows_resource(resource_uri) {
            tracing::debug!(
                resource_uri,
                policy_version = self.snapshot.version,
                action = "allowed",
                "resource access permitted by capability allowlist"
            );
            return Ok(());
        }
        tracing::warn!(
            resource_uri,
            policy_version = self.snapshot.version,
            action = "blocked",
            "resource access blocked by capability allowlist"
        );
        Err(PolicyError::CapabilityDenied(resource_uri.to_owned()))
    }

    /// Scan an outbound payload for sensitive data via the DLP ruleset.
    ///
    /// This is the DLP stage of the outbound evaluation pipeline (PLAN-RULE-01):
    /// any match denies the request fail-closed. The error and the log carry
    /// only the offending rule name, never the matched value (CONST-LOG-03).
    pub fn check_payload(&self, payload: &Value) -> Result<(), PolicyError> {
        let findings = self.dlp.scan_value(payload);
        let Some(finding) = findings.into_iter().next() else {
            tracing::debug!(
                policy_version = self.snapshot.version,
                action = "allowed",
                "outbound payload passed DLP scan"
            );
            return Ok(());
        };
        tracing::warn!(
            rule = %finding.rule,
            policy_version = self.snapshot.version,
            action = "blocked",
            "outbound payload blocked by DLP scan"
        );
        Err(PolicyError::DlpViolation(finding.rule))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityAllowlist, DlpRuleset, OutboundFilter, PolicySnapshot};
    use serde_json::json;

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

    // --- Green path ---

    #[test]
    fn allows_permitted_tool() {
        assert!(engine().check_tool("read_file").is_ok());
    }

    #[test]
    fn blocks_unpermitted_tool() {
        assert!(engine().check_tool("exec_shell").is_err());
    }

    #[test]
    fn allows_permitted_host() {
        assert!(engine().check_outbound("api.example.com").is_ok());
    }

    #[test]
    fn blocks_unpermitted_host() {
        assert!(engine().check_outbound("evil.com").is_err());
    }

    #[test]
    fn allows_permitted_resource() {
        assert!(engine().check_resource("file:///tmp/data.json").is_ok());
    }

    #[test]
    fn blocks_unpermitted_resource() {
        assert!(engine().check_resource("file:///etc/passwd").is_err());
    }

    // --- Red-team: malicious tool calls that must be blocked ---

    #[test]
    fn redteam_blocks_system_exec() {
        assert!(engine().check_tool("system_exec").is_err());
    }

    #[test]
    fn redteam_blocks_eval_code() {
        assert!(engine().check_tool("eval_code").is_err());
    }

    #[test]
    fn redteam_blocks_write_file() {
        assert!(engine().check_tool("write_file").is_err());
    }

    #[test]
    fn redteam_blocks_delete_file() {
        assert!(engine().check_tool("delete_file").is_err());
    }

    #[test]
    fn redteam_blocks_empty_tool_name() {
        assert!(engine().check_tool("").is_err());
    }

    #[test]
    fn redteam_blocks_null_byte_in_tool_name() {
        // Null byte must not allow bypassing the exact-match check.
        assert!(engine().check_tool("read_file\0exec_shell").is_err());
    }

    #[test]
    fn redteam_blocks_shell_injection_in_tool_name() {
        assert!(engine().check_tool("read_file; rm -rf /").is_err());
    }

    #[test]
    fn redteam_blocks_uppercase_variant_of_permitted_tool() {
        // Allowlist matching is case-sensitive.
        assert!(engine().check_tool("READ_FILE").is_err());
    }

    #[test]
    fn redteam_blocks_path_traversal_resource() {
        // /tmp/../etc/passwd normalises past the allowed prefix.
        assert!(engine()
            .check_resource("file:///tmp/../etc/passwd")
            .is_err());
    }

    #[test]
    fn redteam_blocks_etc_shadow_resource() {
        assert!(engine().check_resource("file:///etc/shadow").is_err());
    }

    #[test]
    fn redteam_blocks_proc_environ_resource() {
        assert!(engine()
            .check_resource("file:///proc/self/environ")
            .is_err());
    }

    #[test]
    fn redteam_blocks_subdomain_confusion_host() {
        // "api.example.com.evil.com" is not the same as "api.example.com".
        assert!(engine().check_outbound("api.example.com.evil.com").is_err());
    }

    #[test]
    fn redteam_blocks_prefix_suffix_on_allowed_host() {
        assert!(engine().check_outbound("api.example.comx").is_err());
    }

    #[test]
    fn redteam_blocks_empty_host() {
        assert!(engine().check_outbound("").is_err());
    }

    // --- Error messages carry the denied value ---

    #[test]
    fn blocked_tool_error_contains_tool_name() {
        let err = engine().check_tool("exec_shell").unwrap_err();
        assert!(err.to_string().contains("exec_shell"));
    }

    #[test]
    fn blocked_host_error_contains_host() {
        let err = engine().check_outbound("evil.com").unwrap_err();
        assert!(err.to_string().contains("evil.com"));
    }

    #[test]
    fn blocked_resource_error_contains_uri() {
        let err = engine().check_resource("file:///etc/passwd").unwrap_err();
        assert!(err.to_string().contains("file:///etc/passwd"));
    }

    // --- DLP payload scan (PLAN-RULE-01 stage 3) ---

    #[test]
    fn allows_clean_payload() {
        let payload = json!({"path": "/tmp/data.json", "limit": 10});
        assert!(engine().check_payload(&payload).is_ok());
    }

    #[test]
    fn blocks_payload_with_ssn() {
        let payload = json!({"note": "user ssn is 123-45-6789"});
        assert!(engine().check_payload(&payload).is_err());
    }

    #[test]
    fn blocks_payload_with_credit_card() {
        let payload = json!({"data": "4111 1111 1111 1111"});
        assert!(engine().check_payload(&payload).is_err());
    }

    #[test]
    fn blocks_payload_with_secret_in_nested_field() {
        let payload = json!({"config": {"creds": {"key": "AKIAIOSFODNN7EXAMPLE"}}});
        assert!(engine().check_payload(&payload).is_err());
    }

    #[test]
    fn dlp_error_names_rule_without_leaking_value() {
        let err = engine()
            .check_payload(&json!({"x": "123-45-6789"}))
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("us_ssn"));
        assert!(
            !msg.contains("123-45-6789"),
            "must not leak the matched value"
        );
    }

    #[test]
    fn engine_construction_fails_on_invalid_dlp_rule() {
        let snap = PolicySnapshot::new(
            CapabilityAllowlist::new(vec![], vec![]),
            OutboundFilter::new(vec![]),
            DlpRuleset::new(vec![crate::DlpRule::new("broken", "(unterminated")]),
            1,
            b"k",
        )
        .unwrap();
        assert!(PolicyEngine::new(snap).is_err());
    }

    #[test]
    fn empty_dlp_ruleset_allows_any_payload() {
        let snap = PolicySnapshot::new(
            CapabilityAllowlist::new(vec![], vec![]),
            OutboundFilter::new(vec![]),
            DlpRuleset::default(),
            1,
            b"k",
        )
        .unwrap();
        let engine = PolicyEngine::new(snap).unwrap();
        assert!(engine.check_payload(&json!({"ssn": "123-45-6789"})).is_ok());
    }
}
