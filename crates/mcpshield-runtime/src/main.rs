//! `mcpshield-runtime` — wrap any stdio MCP server and stream detection
//! telemetry to the MCPShield console.
//!
//! Usage:
//!
//! ```text
//! MCPSHIELD_API_URL=https://mcp-api.shieldvow.com \
//! MCPSHIELD_SERVER_ID=<uuid> \
//! MCPSHIELD_TOKEN=<token> \
//! mcpshield-runtime -- <your-mcp-server-command> [args...]
//! ```
//!
//! The runtime spawns the wrapped server and faithfully proxies its stdio
//! (stdin/stdout carry the JSON-RPC MCP protocol untouched). In parallel it
//! inspects every `tools/call` request for outbound hosts and sensitive data
//! (DLP), and ships a detection-event batch to `POST /runtime/telemetry`
//! authenticated with the per-server bearer token.
//!
//! This release runs in **monitor mode**: requests are never blocked, so
//! wrapping a server never changes its behaviour — it only adds visibility.
//! Logs go to stderr so they never corrupt the protocol stream on stdout.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use mcpshield_policy::{proxy_filter, DlpEngine, DlpRuleset};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

/// Telemetry ingest path appended to the configured API base URL.
const TELEMETRY_PATH: &str = "/api/v1/runtime/telemetry";
/// Max events buffered before an early flush (matches the API's batch ceiling).
const MAX_BATCH: usize = 500;
/// How often the reporter flushes buffered events.
const FLUSH_INTERVAL: Duration = Duration::from_secs(2);
/// Placeholder tenant id: with bearer-token auth the server pins the real
/// tenant from the token and ignores this field (PLAN-RULE-04), but the API
/// request schema still requires it to be present.
const TENANT_PLACEHOLDER: &str = "00000000-0000-0000-0000-000000000000";

/// Runtime configuration resolved from the environment.
struct Config {
    api_url: String,
    server_id: String,
    token: String,
    server_class: String,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("MCPSHIELD_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("mcpshield-runtime {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let command = parse_command(&args)?;
    let config = load_config()?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(config, command))
}

/// Everything after the first `--` is the wrapped server command; if no `--` is
/// present, every argument after the program name is taken as the command.
fn parse_command(args: &[String]) -> Result<Vec<String>> {
    let command: Vec<String> = match args.iter().position(|a| a == "--") {
        Some(i) => args[i + 1..].to_vec(),
        None => args[1..].to_vec(),
    };
    if command.is_empty() {
        print_usage();
        bail!("no MCP server command provided");
    }
    Ok(command)
}

fn load_config() -> Result<Config> {
    let api_url = env("MCPSHIELD_API_URL")?.trim_end_matches('/').to_string();
    let server_id = env("MCPSHIELD_SERVER_ID")?;
    let token = env("MCPSHIELD_TOKEN")?;
    // The wrapped server's class, surfaced on every event. Defaults to "other".
    let server_class = std::env::var("MCPSHIELD_SERVER_CLASS")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "other".to_string());
    Ok(Config {
        api_url,
        server_id,
        token,
        server_class,
    })
}

fn env(key: &str) -> Result<String> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .with_context(|| format!("missing required environment variable {key}"))
}

fn print_usage() {
    eprintln!(
        "mcpshield-runtime {}\n\n\
         Wrap an MCP server and stream detection telemetry to MCPShield.\n\n\
         USAGE:\n    \
         MCPSHIELD_API_URL=<url> MCPSHIELD_SERVER_ID=<uuid> MCPSHIELD_TOKEN=<token> \\\n    \
         mcpshield-runtime -- <your-mcp-server-command> [args...]\n\n\
         ENVIRONMENT:\n    \
         MCPSHIELD_API_URL      Console API base URL (required)\n    \
         MCPSHIELD_SERVER_ID    Registered server id (required)\n    \
         MCPSHIELD_TOKEN        Per-server runtime token (required)\n    \
         MCPSHIELD_SERVER_CLASS Server class label (optional, default \"other\")\n    \
         MCPSHIELD_LOG          Log filter (optional, default \"info\")",
        env!("CARGO_PKG_VERSION")
    );
}

async fn run(config: Config, command: Vec<String>) -> Result<()> {
    let dlp =
        DlpEngine::compile(&DlpRuleset::with_defaults()).context("compile default DLP ruleset")?;

    let (program, args) = command.split_first().expect("command is non-empty");
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn MCP server: {program}"))?;

    let mut child_stdin = child.stdin.take().context("child stdin unavailable")?;
    let child_stdout = child.stdout.take().context("child stdout unavailable")?;

    // Telemetry reporter: buffers detections off the hot path and flushes them
    // to the console on an interval. A bounded channel applies backpressure
    // without ever blocking the proxy loop for long.
    let (tx, rx) = mpsc::channel::<Value>(1024);
    let reporter = tokio::spawn(reporter_loop(
        rx,
        format!("{}{}", config.api_url, TELEMETRY_PATH),
        config.token.clone(),
    ));

    let mut client_in = BufReader::new(tokio::io::stdin()).lines();
    let mut child_out = BufReader::new(child_stdout).lines();
    let mut client_out = tokio::io::stdout();

    tracing::info!(
        server_id = %config.server_id,
        api = %config.api_url,
        "mcpshield-runtime active (monitor mode — requests are never blocked)"
    );

    loop {
        tokio::select! {
            line = client_in.next_line() => {
                match line.context("read from client stdin")? {
                    None => break, // client closed stdin
                    Some(line) => {
                        for event in detect(&line, &config, &dlp) {
                            // Drop telemetry rather than stall the proxy if the
                            // reporter is saturated — observability is best-effort.
                            let _ = tx.try_send(event);
                        }
                        write_line(&mut child_stdin, &line).await?;
                    }
                }
            }
            line = child_out.next_line() => {
                match line.context("read from server stdout")? {
                    None => break, // server exited
                    Some(line) => write_line(&mut client_out, &line).await?,
                }
            }
        }
    }

    // Flush outstanding telemetry, then reap the child.
    drop(tx);
    let _ = reporter.await;
    let _ = child.wait().await;
    tracing::info!("mcpshield-runtime shut down");
    Ok(())
}

/// Inspect one client→server JSON-RPC line and produce zero or more detection
/// events. Only `tools/call` requests are inspected; everything else (protocol
/// handshakes, notifications, responses) produces no events.
fn detect(raw: &str, config: &Config, dlp: &DlpEngine) -> Vec<Value> {
    let Ok(msg) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    if msg.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Vec::new();
    }
    let args = msg
        .get("params")
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);

    let dlp_hit = !dlp.scan_value(&args).is_empty();
    let hosts = proxy_filter::extract_hosts_from_value(&args);

    let mk = |outbound_host: &str| {
        // A sensitive-data match is the actionable verdict (block); a plain
        // outbound call is observed (allow). Either way it is forwarded.
        let decision = if dlp_hit { "block" } else { "allow" };
        json!({
            "tenant_id": TENANT_PLACEHOLDER,
            "mcp_server_id": config.server_id,
            "server_class": config.server_class,
            "decision": decision,
            "outbound_host": outbound_host,
            "dlp_hit": dlp_hit,
        })
    };

    if hosts.is_empty() {
        // No outbound host, but sensitive data in the call still warrants an event.
        if dlp_hit {
            return vec![mk("")];
        }
        return Vec::new();
    }
    hosts.iter().map(|h| mk(h)).collect()
}

/// Buffer detection events and POST them to the console in batches.
async fn reporter_loop(mut rx: mpsc::Receiver<Value>, endpoint: String, token: String) {
    let client = reqwest::Client::new();
    let mut buf: Vec<Value> = Vec::new();
    let mut tick = tokio::time::interval(FLUSH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(event) => {
                        buf.push(event);
                        if buf.len() >= MAX_BATCH {
                            flush(&client, &endpoint, &token, &mut buf).await;
                        }
                    }
                    None => {
                        // Channel closed: final flush and exit.
                        flush(&client, &endpoint, &token, &mut buf).await;
                        break;
                    }
                }
            }
            _ = tick.tick() => {
                flush(&client, &endpoint, &token, &mut buf).await;
            }
        }
    }
}

async fn flush(client: &reqwest::Client, endpoint: &str, token: &str, buf: &mut Vec<Value>) {
    if buf.is_empty() {
        return;
    }
    let body = json!({ "events": buf });
    match client
        .post(endpoint)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!(count = buf.len(), "detection telemetry sent");
            buf.clear();
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), count = buf.len(), "telemetry rejected; dropping batch");
            buf.clear();
        }
        Err(e) => {
            tracing::warn!(error = %e, count = buf.len(), "telemetry send failed; dropping batch");
            buf.clear();
        }
    }
}

async fn write_line<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, line: &str) -> Result<()> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            api_url: "https://example.test".into(),
            server_id: "srv-1".into(),
            token: "tok".into(),
            server_class: "filesystem".into(),
        }
    }

    fn dlp() -> DlpEngine {
        DlpEngine::compile(&DlpRuleset::with_defaults()).unwrap()
    }

    #[test]
    fn ignores_non_tool_calls() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert!(detect(line, &cfg(), &dlp()).is_empty());
    }

    #[test]
    fn ignores_malformed_lines() {
        assert!(detect("not json", &cfg(), &dlp()).is_empty());
    }

    #[test]
    fn emits_one_event_per_outbound_host() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil.example.com/x"}}}"#;
        let events = detect(line, &cfg(), &dlp());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["outbound_host"], "evil.example.com");
        assert_eq!(events[0]["decision"], "allow");
        assert_eq!(events[0]["mcp_server_id"], "srv-1");
        assert_eq!(events[0]["server_class"], "filesystem");
    }

    #[test]
    fn flags_sensitive_data_as_block() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send","arguments":{"ssn":"123-45-6789"}}}"#;
        let events = detect(line, &cfg(), &dlp());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["dlp_hit"], true);
        assert_eq!(events[0]["decision"], "block");
    }

    #[test]
    fn no_event_for_clean_local_tool_call() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"path":"/tmp/a.txt"}}}"#;
        assert!(detect(line, &cfg(), &dlp()).is_empty());
    }

    #[test]
    fn command_parsing_splits_on_double_dash() {
        let args = vec![
            "mcpshield-runtime".to_string(),
            "--".to_string(),
            "npx".to_string(),
            "server".to_string(),
        ];
        assert_eq!(parse_command(&args).unwrap(), vec!["npx", "server"]);
    }

    #[test]
    fn command_parsing_without_double_dash() {
        let args = vec!["mcpshield-runtime".to_string(), "npx".to_string()];
        assert_eq!(parse_command(&args).unwrap(), vec!["npx"]);
    }
}
