use thiserror::Error;

/// Errors raised while wrapping and proxying an MCP server.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("policy enforcement failed: {0}")]
    Policy(#[from] mcpshield_policy::PolicyError),

    #[error("transport error: {0}")]
    Transport(#[source] anyhow::Error),

    #[error("failed to reach upstream MCP server: {0}")]
    Upstream(#[from] reqwest::Error),

    #[error("MCP server process exited unexpectedly with status {0}")]
    ProcessExited(i32),
}
