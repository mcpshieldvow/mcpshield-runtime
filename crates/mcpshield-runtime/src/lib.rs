//! MCPShield runtime: wraps any MCP server and enforces capability allowlist + proxy filter.

pub mod config;
pub mod error;
pub mod runtime;

pub(crate) mod message;
pub(crate) mod process;
pub(crate) mod transport;

pub use config::RuntimeConfig;
pub use error::RuntimeError;
pub use runtime::McpRuntime;
