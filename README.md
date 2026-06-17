# MCPShield runtime

A Rust runtime sandbox for MCP (Model Context Protocol) servers. Drop-in wrapper
that enforces capability allowlists, outgoing proxy filtering, and exports
behavioral telemetry via OpenTelemetry GenAI semconv v1.36+.

Aligned to NSA May-2026 MCP security guidance: sandboxing, DLP, outgoing proxy
filtering, message integrity, and output filtering — all in a single `cargo add`.

**What MCPShield enforces in front of any MCP server:**

- **Capability allowlist** — only the tools and resource URIs you list reach the server; everything else is blocked before the server sees it.
- **Outbound proxy filter** — the wrapped server's outbound network calls are denied unless the destination host is allowlisted.
- **HMAC policy snapshot** — the active policy is cryptographically signed at startup, so you can prove which policy was enforced.
- **OTel GenAI telemetry** — every tool call is exported as a span; blocked calls carry `gen_ai.policy.permitted=false`.

New here? Jump to the [Quickstart](#quickstart) — it wraps a real MCP server and ends with a blocked call surfacing as a span.

[![CI](https://github.com/mcpshieldvow/mcpshield-runtime/actions/workflows/ci.yml/badge.svg)](https://github.com/mcpshieldvow/mcpshield-runtime/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Looking for the managed control plane?** This repository is the open-source
> runtime. The hosted MCPShield Cloud — multi-tenant console, cross-tenant
> threat intel, attestation and retention — lives at
> [mcpshield.shieldvow.com](https://mcpshield.shieldvow.com). The runtime here is
> Apache 2.0 and free to self-host forever.

---

## Quickstart

### Prerequisites

- Rust 1.80+ (`rustup update stable`)
- An MCP server binary you want to sandbox

### Add to your workspace

```toml
# Cargo.toml
[dependencies]
mcpshield-runtime = { git = "https://github.com/mcpshieldvow/mcpshield-runtime" }
mcpshield-policy  = { git = "https://github.com/mcpshieldvow/mcpshield-runtime" }
mcpshield-telemetry = { git = "https://github.com/mcpshieldvow/mcpshield-runtime" }
```

### Wrap a stdio MCP server

```rust
use mcpshield_runtime::{McpRuntime, RuntimeConfig, Transport};
use mcpshield_policy::{CapabilityAllowlist, OutboundFilter};
use mcpshield_telemetry::TelemetryConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = RuntimeConfig {
        // Command that starts your MCP server
        server_command: vec![
            "npx".into(),
            "-y".into(),
            "@modelcontextprotocol/server-filesystem".into(),
            "/tmp".into(),
        ],
        transport: Transport::Stdio,
        allowlist: CapabilityAllowlist::new(
            // Only these tools are permitted
            vec!["read_file".into(), "list_directory".into()],
            // Only these resource URI prefixes are permitted
            vec!["file:///tmp/".into()],
        ),
        outbound_filter: OutboundFilter::new(
            // Outbound network calls are blocked unless the host is listed here
            vec![],
        ),
        policy_signing_key: b"change-me-32-byte-key-in-prod!!!".to_vec(),
        telemetry: TelemetryConfig::default(),
    };

    McpRuntime::new(config)?.run().await?;
    Ok(())
}
```

### Wrap an HTTP MCP server

```rust
use std::net::SocketAddr;
use mcpshield_runtime::{McpRuntime, RuntimeConfig, Transport};
use mcpshield_policy::{CapabilityAllowlist, OutboundFilter};
use mcpshield_telemetry::TelemetryConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = RuntimeConfig {
        server_command: vec![],
        transport: Transport::Http {
            // MCPShield listens here — point your MCP client at this address
            bind_addr: "127.0.0.1:8080".parse::<SocketAddr>()?,
            // Your existing MCP server is already running here
            upstream: "http://127.0.0.1:9000".into(),
        },
        allowlist: CapabilityAllowlist::new(
            vec!["search".into(), "fetch_page".into()],
            vec![],
        ),
        outbound_filter: OutboundFilter::new(
            vec!["api.example.com".into()],
        ),
        policy_signing_key: b"change-me-32-byte-key-in-prod!!!".to_vec(),
        telemetry: TelemetryConfig::default(),
    };

    McpRuntime::new(config)?.run().await?;
    Ok(())
}
```

---

## How it works

```
MCP client
    │
    ▼
MCPShield runtime
    ├── Capability allowlist  ── block tool/resource calls outside the list
    ├── Outbound proxy filter ── block outbound network calls to unlisted hosts
    ├── HMAC policy snapshot  ── cryptographically sign the active policy at startup
    └── OTel GenAI semconv   ── emit spans for every tool call (OTLP export)
    │
    ▼
Wrapped MCP server (stdio or HTTP)
```

Every tool call is checked against the allowlist. Every outbound network request
the wrapped server would make is evaluated against the proxy filter. Blocked
events are logged and surfaced as OTel spans with `gen_ai.policy.permitted=false`.

---

## Build from source

```bash
git clone https://github.com/mcpshieldvow/mcpshield-runtime
cd mcpshield-runtime
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

---

## Workspace crates

| Crate | Description |
|---|---|
| `mcpshield-runtime` | Transport layer: spawns/proxies stdio and HTTP MCP servers |
| `mcpshield-policy` | Capability allowlist + outbound filter + HMAC policy snapshots |
| `mcpshield-telemetry` | OTel GenAI semconv v1.36+ span export via OTLP |

---

## Telemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export spans to your collector:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 ./my-sandboxed-server
```

Spans follow [OTel GenAI semantic conventions v1.36+](https://opentelemetry.io/docs/specs/semconv/gen-ai/):
- `gen_ai.operation.name`: `"mcp.tool_call"`
- `gen_ai.tool.name`: name of the tool invoked
- `gen_ai.policy.permitted`: `true` / `false`

---

## Feedback & security

- Bugs, ideas, adoption questions: [open an issue](https://github.com/mcpshieldvow/mcpshield-runtime/issues).
- Suspected a security vulnerability? Please report it privately via a
  [security advisory](https://github.com/mcpshieldvow/mcpshield-runtime/security/advisories/new)
  rather than a public issue.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
