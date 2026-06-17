use anyhow::Context;
use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::TelemetryConfig;

/// Active telemetry session. Drop or call [`TelemetryHandle::shutdown`] to flush and stop.
pub struct TelemetryHandle {
    tracer_provider: SdkTracerProvider,
}

impl TelemetryHandle {
    /// Flush pending spans and shut down the tracer provider.
    pub fn shutdown(self) {
        // Best-effort flush; errors during shutdown are non-fatal for the process.
        let _ = self.tracer_provider.shutdown();
    }
}

/// Initialise the global tracer provider and `tracing` subscriber.
///
/// Must be called once at process start, before any instrumented code runs.
pub fn init_telemetry(config: &TelemetryConfig) -> anyhow::Result<TelemetryHandle> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp_endpoint)
        .build()
        .context("failed to build OTLP HTTP span exporter")?;

    let resource = Resource::builder()
        .with_attributes([
            opentelemetry::KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                config.service_name.clone(),
            ),
            opentelemetry::KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                config.service_version.clone(),
            ),
        ])
        .build();

    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    global::set_tracer_provider(tracer_provider.clone());

    let otel_layer =
        tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("mcpshield"));

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .try_init()
        .context("failed to initialise tracing subscriber")?;

    Ok(TelemetryHandle { tracer_provider })
}
