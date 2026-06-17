use std::sync::Arc;

use mcpshield_policy::{PolicyEngine, PolicySnapshot};

use crate::{config::RuntimeConfig, config::Transport, error::RuntimeError, transport};

/// Sandboxed MCP runtime: owns the policy engine and exposes enforcement hooks
/// used by the transport layer.
pub struct McpRuntime {
    config: RuntimeConfig,
    policy: PolicyEngine,
}

impl McpRuntime {
    /// Create a new runtime from config. Validates and signs the initial policy snapshot.
    pub fn new(config: RuntimeConfig) -> Result<Self, RuntimeError> {
        let snapshot = PolicySnapshot::new(
            config.allowlist.clone(),
            config.outbound_filter.clone(),
            config.dlp.clone(),
            1,
            &config.policy_signing_key,
        )?;

        let policy = PolicyEngine::new(snapshot)?;
        tracing::info!(
            transport = ?config.transport,
            policy_version = policy.version(),
            "MCP runtime initialised"
        );

        Ok(Self { config, policy })
    }

    /// Returns a reference to the active policy engine.
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// Returns the runtime configuration.
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Start the transport layer, wrapping the configured child MCP server.
    ///
    /// This method consumes the runtime. Wrap it in an `Arc` before calling if
    /// you need to share it across tasks.
    pub async fn run(self) -> Result<(), RuntimeError> {
        let transport = self.config.transport.clone();
        let runtime = Arc::new(self);

        match transport {
            Transport::Stdio => transport::stdio::run(runtime).await,
            Transport::Http {
                bind_addr,
                upstream,
            } => transport::http::run(runtime, bind_addr, upstream).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use mcpshield_policy::{CapabilityAllowlist, DlpRuleset, OutboundFilter};
    use mcpshield_telemetry::TelemetryConfig;

    use super::*;
    use crate::config::Transport;

    fn sample_config() -> RuntimeConfig {
        RuntimeConfig {
            server_command: vec!["mcp-server".into()],
            transport: Transport::Http {
                bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
                upstream: "http://127.0.0.1:9000".into(),
            },
            allowlist: CapabilityAllowlist::new(vec!["read_file".into()], vec![]),
            outbound_filter: OutboundFilter::new(vec!["api.example.com".into()]),
            dlp: DlpRuleset::with_defaults(),
            policy_signing_key: b"test-signing-key".to_vec(),
            telemetry: TelemetryConfig::default(),
        }
    }

    #[test]
    fn runtime_initialises_with_valid_config() {
        let rt = McpRuntime::new(sample_config()).unwrap();
        assert_eq!(rt.policy().version(), 1);
    }

    #[test]
    fn runtime_policy_enforces_allowlist() {
        let rt = McpRuntime::new(sample_config()).unwrap();
        assert!(rt.policy().check_tool("read_file").is_ok());
        assert!(rt.policy().check_tool("exec_shell").is_err());
    }

    #[test]
    fn runtime_policy_enforces_dlp() {
        let rt = McpRuntime::new(sample_config()).unwrap();
        assert!(rt
            .policy()
            .check_payload(&serde_json::json!({"note": "ok"}))
            .is_ok());
        assert!(rt
            .policy()
            .check_payload(&serde_json::json!({"ssn": "123-45-6789"}))
            .is_err());
    }

    #[test]
    fn runtime_construction_fails_on_invalid_dlp_rule() {
        let mut config = sample_config();
        config.dlp = mcpshield_policy::DlpRuleset::new(vec![mcpshield_policy::DlpRule::new(
            "broken",
            "(unterminated",
        )]);
        assert!(McpRuntime::new(config).is_err());
    }
}
