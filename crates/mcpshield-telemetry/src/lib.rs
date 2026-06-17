//! OpenTelemetry GenAI semconv telemetry for MCPShield.
//!
//! Exports spans and metrics via OTLP (HTTP/proto) to a configured collector endpoint.

pub mod config;
pub mod init;
pub mod span;

pub use config::TelemetryConfig;
pub use init::{init_telemetry, TelemetryHandle};
pub use span::{record_tool_call, ToolCallSpan, OPERATION_TOOL_CALL, SYSTEM_MCP};
