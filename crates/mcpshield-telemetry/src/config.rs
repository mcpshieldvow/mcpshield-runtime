use serde::{Deserialize, Serialize};

/// Configuration for the telemetry subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// OTLP HTTP endpoint, e.g. `http://localhost:4318`.
    pub otlp_endpoint: String,
    /// Service name reported in all spans.
    pub service_name: String,
    /// Service version reported in all spans.
    pub service_version: String,
}

impl TelemetryConfig {
    pub fn new(
        otlp_endpoint: impl Into<String>,
        service_name: impl Into<String>,
        service_version: impl Into<String>,
    ) -> Self {
        Self {
            otlp_endpoint: otlp_endpoint.into(),
            service_name: service_name.into(),
            service_version: service_version.into(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self::new(
            "http://localhost:4318",
            "mcpshield",
            env!("CARGO_PKG_VERSION"),
        )
    }
}
