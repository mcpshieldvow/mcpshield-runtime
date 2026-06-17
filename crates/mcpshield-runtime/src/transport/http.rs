use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, Method, StatusCode, Uri},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use reqwest::Client;
use serde_json::Value;
use tokio::net::TcpListener;

use crate::{message::check_policy_for_line, McpRuntime, RuntimeError};

/// Hop-by-hop / recomputed headers that must not be copied between client,
/// proxy and upstream. `host` and `content-length` are recomputed by reqwest;
/// the rest are connection-specific per RFC 7230.
const SKIPPED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-connection",
    "upgrade",
];

#[derive(Clone)]
struct AppState {
    runtime: Arc<McpRuntime>,
    http: Client,
    /// Base URL of the wrapped MCP server, without a trailing slash.
    upstream: String,
}

/// Run the HTTP transport: bind an Axum server on `bind_addr` and faithfully
/// reverse-proxy every request to the wrapped MCP server at `upstream`.
///
/// Policy is enforced on each JSON-RPC request before it is forwarded; blocked
/// requests receive a JSON-RPC error response and never reach the upstream.
/// Allowed requests are forwarded unchanged (method, path, headers, body) and
/// the upstream response is relayed back verbatim — a transparent passthrough.
pub(crate) async fn run(
    runtime: Arc<McpRuntime>,
    bind_addr: SocketAddr,
    upstream: String,
) -> Result<(), RuntimeError> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(|e| RuntimeError::Transport(e.into()))?;
    tracing::info!(addr = %bind_addr, upstream = %upstream, "HTTP transport listening");
    serve(listener, runtime, upstream).await
}

async fn serve(
    listener: TcpListener,
    runtime: Arc<McpRuntime>,
    upstream: String,
) -> Result<(), RuntimeError> {
    let state = AppState {
        runtime,
        http: Client::new(),
        upstream: upstream.trim_end_matches('/').to_owned(),
    };

    // MCP servers expose the JSON-RPC endpoint at `/` or `/mcp` depending on the
    // implementation; both are proxied so the wrapper is a drop-in for either.
    let app = Router::new()
        .route("/", post(handle_request))
        .route("/mcp", post(handle_request))
        .with_state(state);

    axum::serve(listener, app)
        .await
        .map_err(|e| RuntimeError::Transport(e.into()))
}

async fn handle_request(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    // Policy is checked on the JSON-RPC body. Non-UTF-8 / non-JSON bodies carry
    // no enforceable method and are forwarded unchanged (check returns None).
    if let Ok(raw) = std::str::from_utf8(&body) {
        if let Some(error_json) = check_policy_for_line(state.runtime.policy(), raw) {
            tracing::warn!("HTTP transport: policy blocked request");
            let val: Value = serde_json::from_str(&error_json).unwrap_or(Value::Null);
            return (StatusCode::OK, Json(val)).into_response();
        }
    }

    forward(&state, method, &uri, headers, body).await
}

async fn forward(
    state: &AppState,
    method: Method,
    uri: &Uri,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target = format!("{}{}", state.upstream, path_and_query);

    let response = state
        .http
        .request(method, &target)
        .headers(filter_headers(&headers))
        .body(body)
        .send()
        .await;

    match response {
        Ok(resp) => relay_response(resp).await,
        Err(e) => {
            tracing::error!(error = %e, upstream = %target, "failed to reach upstream MCP server");
            (
                StatusCode::BAD_GATEWAY,
                Json(error_value(
                    "ERR_UPSTREAM_UNREACHABLE",
                    "upstream MCP server unreachable",
                )),
            )
                .into_response()
        }
    }
}

async fn relay_response(resp: reqwest::Response) -> axum::response::Response {
    let status = resp.status();
    let headers = filter_headers(resp.headers());
    match resp.bytes().await {
        Ok(body) => (status, headers, body).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "failed to read upstream response body");
            (
                StatusCode::BAD_GATEWAY,
                Json(error_value(
                    "ERR_UPSTREAM_BODY",
                    "failed to read upstream response",
                )),
            )
                .into_response()
        }
    }
}

/// Copy headers for forwarding, dropping hop-by-hop and recomputed entries so
/// reqwest (request) or axum (response) can set them correctly.
fn filter_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if is_skipped(name) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

fn is_skipped(name: &HeaderName) -> bool {
    SKIPPED_HEADERS
        .iter()
        .any(|skip| name.as_str().eq_ignore_ascii_case(skip))
}

fn error_value(code: &str, message: &str) -> Value {
    serde_json::json!({
        "error": {
            "code": code,
            "message": message,
            "field": Value::Null,
            "details": {}
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::{extract::State as AxumState, routing::post, Json, Router};
    use mcpshield_policy::{CapabilityAllowlist, DlpRuleset, OutboundFilter};
    use mcpshield_telemetry::TelemetryConfig;
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    use super::*;
    use crate::{config::RuntimeConfig, config::Transport, McpRuntime};

    #[derive(Clone)]
    struct UpstreamState {
        hits: Arc<AtomicUsize>,
    }

    // Minimal MCP server stand-in: records that it was reached and echoes the
    // request back inside a JSON-RPC result.
    async fn upstream_handler(
        AxumState(state): AxumState<UpstreamState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        state.hits.fetch_add(1, Ordering::SeqCst);
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        Json(json!({"jsonrpc": "2.0", "id": id, "result": {"echo": body}}))
    }

    async fn spawn_upstream() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let state = UpstreamState { hits: hits.clone() };
        let app = Router::new()
            .route("/", post(upstream_handler))
            .route("/mcp", post(upstream_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), hits)
    }

    fn runtime(upstream: &str) -> Arc<McpRuntime> {
        let config = RuntimeConfig {
            server_command: vec!["mock-server".into()],
            transport: Transport::Http {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                upstream: upstream.to_owned(),
            },
            allowlist: CapabilityAllowlist::new(vec!["read_file".into()], vec![]),
            outbound_filter: OutboundFilter::new(vec!["api.example.com".into()]),
            dlp: DlpRuleset::with_defaults(),
            policy_signing_key: b"test-key".to_vec(),
            telemetry: TelemetryConfig::default(),
        };
        Arc::new(McpRuntime::new(config).unwrap())
    }

    async fn spawn_wrapper(rt: Arc<McpRuntime>, upstream: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            super::serve(listener, rt, upstream).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn post_json(client: &Client, url: &str, body: &str) -> (StatusCode, Value) {
        let resp = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_owned())
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let val: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        (status, val)
    }

    #[tokio::test]
    async fn forwards_allowed_request_to_upstream() {
        let (upstream_url, hits) = spawn_upstream().await;
        let rt = runtime(&upstream_url);
        let proxy_url = spawn_wrapper(rt, upstream_url).await;
        let client = Client::new();

        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#;
        let (status, body) = post_json(&client, &format!("{proxy_url}/mcp"), req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["echo"]["method"], "tools/call");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "upstream must be reached once"
        );
    }

    #[tokio::test]
    async fn blocks_denied_request_without_touching_upstream() {
        let (upstream_url, hits) = spawn_upstream().await;
        let rt = runtime(&upstream_url);
        let proxy_url = spawn_wrapper(rt, upstream_url).await;
        let client = Client::new();

        let req =
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"exec_shell"}}"#;
        let (status, body) = post_json(&client, &format!("{proxy_url}/mcp"), req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["error"]["code"],
            crate::message::ERR_CODE_POLICY_DENIED
        );
        assert_eq!(body["id"], 7, "JSON-RPC id must be echoed in the error");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "blocked request must never reach the upstream"
        );
    }

    #[tokio::test]
    async fn relays_response_for_root_path() {
        let (upstream_url, hits) = spawn_upstream().await;
        let rt = runtime(&upstream_url);
        let proxy_url = spawn_wrapper(rt, upstream_url).await;
        let client = Client::new();

        let req = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#;
        let (status, body) = post_json(&client, &proxy_url, req).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], 2);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
