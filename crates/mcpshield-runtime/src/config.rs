use serde::{Deserialize, Serialize};

use mcpshield_policy::{CapabilityAllowlist, DlpRuleset, OutboundFilter};
use mcpshield_telemetry::TelemetryConfig;

/// Transport mode for the wrapped MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Wrap an MCP server communicating over stdin/stdout. The runtime spawns the
    /// process in [`RuntimeConfig::server_command`] and faithfully proxies its stdio.
    Stdio,
    /// Wrap an MCP server speaking HTTP. The runtime listens on `bind_addr` (the
    /// address clients now use) and faithfully forwards every request to the
    /// already-running upstream server, enforcing policy in between.
    Http {
        /// Address the runtime's proxy listens on.
        bind_addr: std::net::SocketAddr,
        /// Base URL of the wrapped MCP server, e.g. `http://127.0.0.1:9000`.
        upstream: String,
    },
}

/// Full configuration for a [`McpRuntime`](crate::McpRuntime) instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Command and arguments for the MCP server process (used by the stdio transport).
    pub server_command: Vec<String>,
    /// Transport the server uses.
    pub transport: Transport,
    /// Policy: which capabilities are allowed.
    pub allowlist: CapabilityAllowlist,
    /// Policy: which outbound hosts are allowed.
    pub outbound_filter: OutboundFilter,
    /// Policy: regex DLP ruleset scanning outbound payloads for sensitive data.
    pub dlp: DlpRuleset,
    /// Key used to sign and verify policy snapshots.
    #[serde(skip)]
    pub policy_signing_key: Vec<u8>,
    /// Telemetry export configuration.
    pub telemetry: TelemetryConfig,
}
