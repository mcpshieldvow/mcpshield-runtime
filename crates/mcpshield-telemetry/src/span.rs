use opentelemetry::{
    global,
    trace::{Span, SpanKind, Status, Tracer},
    KeyValue,
};

/// Attribute keys from the OpenTelemetry GenAI semantic conventions v1.36+.
pub mod gen_ai {
    /// The name of the GenAI tool/function being called.
    pub const TOOL_NAME: &str = "gen_ai.tool.name";
    /// The type of GenAI operation: `tool_call`, `resource_read`, etc.
    pub const OPERATION_NAME: &str = "gen_ai.operation.name";
    /// The GenAI system identifier (e.g. `mcp`).
    pub const SYSTEM: &str = "gen_ai.system";
    /// The MCP server name proxied by the runtime.
    pub const MCP_SERVER: &str = "gen_ai.mcp.server";
    /// Whether the tool call was permitted by the policy engine.
    pub const POLICY_PERMITTED: &str = "mcpshield.policy.permitted";
    /// Unique identifier of the tool call (JSON-RPC id or provider-assigned id).
    pub const TOOL_CALL_ID: &str = "gen_ai.tool.call.id";
}

/// `gen_ai.operation.name` value for MCP tool invocations.
pub const OPERATION_TOOL_CALL: &str = "tool_call";

/// `gen_ai.system` value for the MCP protocol.
pub const SYSTEM_MCP: &str = "mcp";

/// Parameters for a single MCP tool-call span.
pub struct ToolCallSpan<'a> {
    /// Name of the tool being called (maps to `gen_ai.tool.name`).
    pub tool_name: &'a str,
    /// Name of the wrapped MCP server (maps to `gen_ai.mcp.server`).
    pub mcp_server: &'a str,
    /// Optional call id, e.g. the JSON-RPC `id` field.
    pub call_id: Option<&'a str>,
    /// Whether the policy engine permitted the call.
    pub permitted: bool,
    /// Error message when the call was denied or failed.
    pub error: Option<&'a str>,
}

/// Record a single MCP tool-call span using the global OTel tracer.
///
/// Span name follows the GenAI semconv v1.36+ pattern:
/// `{gen_ai.operation.name} {gen_ai.tool.name}` → e.g. `tool_call read_file`.
/// Span kind is `CLIENT`. Status is set to `ERROR` when `error` is provided.
pub fn record_tool_call(event: &ToolCallSpan<'_>) {
    let tracer = global::tracer("mcpshield-telemetry");
    emit_tool_call_span(&tracer, event);
}

/// Core span emission — decoupled from the global tracer for testability.
pub(crate) fn emit_tool_call_span<T: Tracer>(tracer: &T, event: &ToolCallSpan<'_>) {
    let span_name = format!("{} {}", OPERATION_TOOL_CALL, event.tool_name);

    let mut attrs = vec![
        KeyValue::new(gen_ai::OPERATION_NAME, OPERATION_TOOL_CALL),
        KeyValue::new(gen_ai::SYSTEM, SYSTEM_MCP),
        KeyValue::new(gen_ai::TOOL_NAME, event.tool_name.to_owned()),
        KeyValue::new(gen_ai::MCP_SERVER, event.mcp_server.to_owned()),
        KeyValue::new(gen_ai::POLICY_PERMITTED, event.permitted),
    ];

    if let Some(id) = event.call_id {
        attrs.push(KeyValue::new(gen_ai::TOOL_CALL_ID, id.to_owned()));
    }

    let mut span = tracer
        .span_builder(span_name)
        .with_kind(SpanKind::Client)
        .with_attributes(attrs)
        .start(tracer);

    if let Some(err) = event.error {
        span.set_status(Status::error(err.to_owned()));
    }

    span.end();
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{SpanKind, Status, TracerProvider as _};
    use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
    use std::collections::HashMap;

    fn setup() -> (
        SdkTracerProvider,
        opentelemetry_sdk::trace::InMemorySpanExporter,
    ) {
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        (provider, exporter)
    }

    fn attr_map(
        spans: &[opentelemetry_sdk::trace::SpanData],
        idx: usize,
    ) -> HashMap<String, opentelemetry::Value> {
        spans[idx]
            .attributes
            .iter()
            .map(|kv| (kv.key.as_str().to_owned(), kv.value.clone()))
            .collect()
    }

    // --- Span name ---

    #[test]
    fn span_name_follows_semconv_pattern() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "test-server",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].name.as_ref(), "tool_call read_file");
    }

    // --- Span kind ---

    #[test]
    fn span_kind_is_client() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "search_web",
                mcp_server: "s",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans[0].span_kind, SpanKind::Client);
    }

    // --- Required GenAI semconv attributes ---

    #[test]
    fn required_attributes_present() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "my-server",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        let attrs = attr_map(&spans, 0);

        assert_eq!(
            attrs.get(gen_ai::OPERATION_NAME).map(|v| v.as_str()),
            Some(std::borrow::Cow::Borrowed(OPERATION_TOOL_CALL))
        );
        assert_eq!(
            attrs.get(gen_ai::SYSTEM).map(|v| v.as_str()),
            Some(std::borrow::Cow::Borrowed(SYSTEM_MCP))
        );
        assert_eq!(
            attrs.get(gen_ai::TOOL_NAME).map(|v| v.as_str()),
            Some(std::borrow::Cow::Borrowed("read_file"))
        );
        assert_eq!(
            attrs.get(gen_ai::MCP_SERVER).map(|v| v.as_str()),
            Some(std::borrow::Cow::Borrowed("my-server"))
        );
    }

    // --- Policy permitted flag ---

    #[test]
    fn policy_permitted_true_recorded() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "s",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        let attrs = attr_map(&spans, 0);
        assert_eq!(
            attrs.get(gen_ai::POLICY_PERMITTED),
            Some(&opentelemetry::Value::Bool(true))
        );
    }

    #[test]
    fn policy_permitted_false_recorded() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "exec_shell",
                mcp_server: "s",
                call_id: None,
                permitted: false,
                error: Some("tool not in allowlist"),
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        let attrs = attr_map(&spans, 0);
        assert_eq!(
            attrs.get(gen_ai::POLICY_PERMITTED),
            Some(&opentelemetry::Value::Bool(false))
        );
    }

    // --- Optional call_id attribute ---

    #[test]
    fn call_id_present_when_provided() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "s",
                call_id: Some("rpc-42"),
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        let attrs = attr_map(&spans, 0);
        assert_eq!(
            attrs.get(gen_ai::TOOL_CALL_ID).map(|v| v.as_str()),
            Some(std::borrow::Cow::Borrowed("rpc-42"))
        );
    }

    #[test]
    fn call_id_absent_when_not_provided() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "s",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        let attrs = attr_map(&spans, 0);
        assert!(!attrs.contains_key(gen_ai::TOOL_CALL_ID));
    }

    // --- Status ---

    #[test]
    fn status_ok_when_no_error() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "s",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        assert!(matches!(spans[0].status, Status::Unset | Status::Ok));
    }

    #[test]
    fn status_error_when_error_provided() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "exec_shell",
                mcp_server: "s",
                call_id: None,
                permitted: false,
                error: Some("tool not in allowlist"),
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        assert!(matches!(spans[0].status, Status::Error { .. }));
    }

    // --- Distinct tool names produce distinct span names ---

    #[test]
    fn span_name_reflects_tool_name() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");

        for tool in &["read_file", "search_web", "list_directory"] {
            emit_tool_call_span(
                &tracer,
                &ToolCallSpan {
                    tool_name: tool,
                    mcp_server: "s",
                    call_id: None,
                    permitted: true,
                    error: None,
                },
            );
        }

        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 3);

        let names: Vec<&str> = spans.iter().map(|s| s.name.as_ref()).collect();
        assert!(names.contains(&"tool_call read_file"));
        assert!(names.contains(&"tool_call search_web"));
        assert!(names.contains(&"tool_call list_directory"));
    }

    // --- Span is finished (has a non-zero end time) ---

    #[test]
    fn span_is_finished() {
        let (provider, exporter) = setup();
        let tracer = provider.tracer("test");
        emit_tool_call_span(
            &tracer,
            &ToolCallSpan {
                tool_name: "read_file",
                mcp_server: "s",
                call_id: None,
                permitted: true,
                error: None,
            },
        );
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(
            spans[0].end_time >= spans[0].start_time,
            "end_time must be >= start_time"
        );
    }
}
