//! Integration tests for the full policy enforcement pipeline.
//!
//! These tests exercise the public API of `mcpshield-policy` end-to-end:
//! snapshot creation → engine construction → enforcement decisions.

use mcpshield_policy::{
    proxy_filter::extract_hosts_from_value, CapabilityAllowlist, DlpRuleset, OutboundFilter,
    PolicyEngine, PolicySnapshot,
};
use serde_json::json;

const SIGNING_KEY: &[u8] = b"integration-test-signing-key";

fn make_engine(tools: Vec<&str>, resources: Vec<&str>, hosts: Vec<&str>) -> PolicyEngine {
    let allowlist = CapabilityAllowlist::new(
        tools.iter().map(|s| s.to_string()).collect(),
        resources.iter().map(|s| s.to_string()).collect(),
    );
    let filter = OutboundFilter::new(hosts.iter().map(|s| s.to_string()).collect());
    let snap =
        PolicySnapshot::new(allowlist, filter, DlpRuleset::default(), 1, SIGNING_KEY).unwrap();
    PolicyEngine::new(snap).unwrap()
}

// --- Snapshot lifecycle ---

#[test]
fn snapshot_version_is_accessible_via_engine() {
    let engine = make_engine(vec!["read_file"], vec![], vec![]);
    assert_eq!(engine.version(), 1);
}

#[test]
fn snapshot_version_survives_round_trip() {
    let allowlist = CapabilityAllowlist::new(vec!["read_file".into()], vec![]);
    let filter = OutboundFilter::new(vec![]);
    let snap =
        PolicySnapshot::new(allowlist, filter, DlpRuleset::default(), 42, SIGNING_KEY).unwrap();
    assert_eq!(snap.version, 42);
    let engine = PolicyEngine::new(snap).unwrap();
    assert_eq!(engine.version(), 42);
}

#[test]
fn snapshot_integrity_holds_after_engine_construction() {
    let allowlist = CapabilityAllowlist::new(vec!["read_file".into()], vec![]);
    let filter = OutboundFilter::new(vec!["api.example.com".into()]);
    let snap =
        PolicySnapshot::new(allowlist, filter, DlpRuleset::default(), 1, SIGNING_KEY).unwrap();
    assert!(snap.verify(SIGNING_KEY).is_ok());
}

#[test]
fn empty_policy_denies_all_tools() {
    let engine = make_engine(vec![], vec![], vec![]);
    assert!(engine.check_tool("read_file").is_err());
    assert!(engine.check_tool("any_tool").is_err());
}

#[test]
fn empty_policy_denies_all_resources() {
    let engine = make_engine(vec![], vec![], vec![]);
    assert!(engine.check_resource("file:///tmp/data.json").is_err());
}

#[test]
fn empty_policy_denies_all_hosts() {
    let engine = make_engine(vec![], vec![], vec![]);
    assert!(engine.check_outbound("safe.example.com").is_err());
}

#[test]
fn policy_with_multiple_tools_permits_each() {
    let engine = make_engine(
        vec!["read_file", "search_web", "list_directory"],
        vec![],
        vec![],
    );
    assert!(engine.check_tool("read_file").is_ok());
    assert!(engine.check_tool("search_web").is_ok());
    assert!(engine.check_tool("list_directory").is_ok());
}

#[test]
fn policy_blocks_tool_not_in_multi_tool_list() {
    let engine = make_engine(vec!["read_file", "search_web"], vec![], vec![]);
    assert!(engine.check_tool("exec_shell").is_err());
}

// --- Allowlist: relative URIs and paths without leading slash ---

#[test]
fn resource_uri_without_scheme_is_blocked_by_file_prefix_allowlist() {
    // A relative path has no "://" — it never matches a `file:///` prefix.
    let engine = make_engine(vec![], vec!["file:///tmp/"], vec![]);
    assert!(engine.check_resource("tmp/data.json").is_err());
}

#[test]
fn resource_uri_relative_without_scheme_allowed_by_relative_prefix() {
    // Covers allowlist.rs:59 (else branch — no "://" in URI).
    // Covers allowlist.rs:91 (normalize_path match arm (false, false)).
    let engine = make_engine(vec![], vec!["tmp/"], vec![]);
    assert!(engine.check_resource("tmp/data.json").is_ok());
    assert!(engine.check_resource("other/data.json").is_err());
}

#[test]
fn resource_uri_relative_with_trailing_slash_normalises_correctly() {
    // Covers allowlist.rs:90 (normalize_path match arm (false, true)).
    // The resource URI itself has a trailing slash so normalize_path returns
    // the (false, true) branch: "{joined}/".
    let engine = make_engine(vec![], vec!["workspace/output/"], vec![]);
    assert!(engine.check_resource("workspace/output/").is_ok());
    assert!(engine.check_resource("workspace/input/").is_err());
}

// --- Combined pipeline: extract_hosts → check_outbound ---

#[test]
fn pipeline_allows_tool_call_whose_url_arg_is_on_allowlist() {
    let engine = make_engine(vec!["fetch_url"], vec![], vec!["api.example.com"]);
    let args = json!({"url": "https://api.example.com/data"});
    let hosts = extract_hosts_from_value(&args);
    assert!(engine.check_tool("fetch_url").is_ok());
    for host in &hosts {
        assert!(
            engine.check_outbound(host).is_ok(),
            "host {host} must be allowed"
        );
    }
}

#[test]
fn pipeline_blocks_tool_call_whose_url_arg_is_not_on_allowlist() {
    let engine = make_engine(vec!["fetch_url"], vec![], vec!["api.example.com"]);
    let args = json!({"url": "https://evil.com/steal"});
    let hosts = extract_hosts_from_value(&args);
    assert!(!hosts.is_empty());
    let blocked = hosts.iter().any(|h| engine.check_outbound(h).is_err());
    assert!(blocked, "evil.com must be blocked");
}

#[test]
fn pipeline_blocks_when_one_of_multiple_urls_is_disallowed() {
    let engine = make_engine(vec!["batch_fetch"], vec![], vec!["api.example.com"]);
    let args = json!({
        "requests": [
            {"url": "https://api.example.com/ok"},
            {"url": "https://evil.com/exfil"}
        ]
    });
    let hosts = extract_hosts_from_value(&args);
    let has_blocked = hosts.iter().any(|h| engine.check_outbound(h).is_err());
    assert!(has_blocked, "a single disallowed host must block the batch");
}

// --- Error variant correctness ---

#[test]
fn denied_tool_produces_capability_denied_error() {
    let engine = make_engine(vec![], vec![], vec![]);
    let err = engine.check_tool("exec_shell").unwrap_err();
    assert!(err.to_string().contains("exec_shell"));
}

#[test]
fn denied_outbound_produces_outbound_blocked_error() {
    let engine = make_engine(vec![], vec![], vec![]);
    let err = engine.check_outbound("evil.com").unwrap_err();
    assert!(err.to_string().contains("evil.com"));
}

#[test]
fn denied_resource_produces_capability_denied_error() {
    let engine = make_engine(vec![], vec![], vec![]);
    let err = engine.check_resource("file:///etc/passwd").unwrap_err();
    assert!(err.to_string().contains("file:///etc/passwd"));
}
