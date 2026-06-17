use serde_json::Value;

/// URL schemes that indicate an outbound network connection will be made.
const URL_SCHEMES: &[&str] = &[
    "http://", "https://",
    "ws://", // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
    "wss://", "ftp://", "ftps://",
];

/// Object keys whose string values are treated as plain hostnames even when no
/// URL scheme is present. Widened surface ensures arguments like
/// `{"host": "evil.com"}` or `{"target": "attacker.io"}` are caught in addition
/// to `{"url": "https://evil.com"}`.
const HOST_KEYS: &[&str] = &[
    "host",
    "hostname",
    "server",
    "domain",
    "address",
    "peer",
    "target",
    "remote",
    "origin",
    "authority",
];

/// Recursively extract every distinct outbound host from a JSON value tree.
///
/// Two classes of values are collected:
/// 1. Any string that begins with a recognised URL scheme (`http://`, `https://`,
///    `ws://`, `wss://`, `ftp://`, `ftps://`) — host component is extracted. // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
/// 2. Any string whose parent JSON key is a well-known host-designator
///    (`host`, `hostname`, `target`, …) — value is treated as `hostname[:port]`.
///
/// All other values (non-URL strings, numbers, booleans, null) are ignored.
/// Duplicates are removed; order is stable.
///
/// The caller **must** check every returned host against [`OutboundFilter`](crate::OutboundFilter)
/// before forwarding the request. A single blocked host must deny the entire request.
pub fn extract_hosts_from_value(value: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    collect(value, None, &mut hosts);
    hosts.dedup();
    hosts
}

fn collect(value: &Value, parent_key: Option<&str>, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if let Some(host) = host_from_string(s, parent_key) {
                out.push(host);
            }
        }
        Value::Array(arr) => {
            for item in arr {
                // Array items inherit the parent key context so that
                // `{"urls": ["https://a.com", "https://b.com"]}` is fully scanned.
                collect(item, parent_key, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                collect(v, Some(k.as_str()), out);
            }
        }
        // Numbers, booleans, null — no host reference possible.
        _ => {}
    }
}

fn host_from_string(s: &str, parent_key: Option<&str>) -> Option<String> {
    // URL scheme present — extract authority host.
    for scheme in URL_SCHEMES {
        if s.starts_with(scheme) {
            return parse_authority_host(s, scheme.len());
        }
    }

    // Well-known host key — treat value as plain `hostname[:port]`.
    if let Some(key) = parent_key {
        if HOST_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
            let host = s.split(':').next()?.trim();
            if !host.is_empty() {
                return Some(host.to_owned());
            }
        }
    }

    None
}

/// Extract the hostname from a URL, given the byte length of the scheme prefix.
/// Handles optional `user:password@` userinfo and strips any port number.
fn parse_authority_host(url: &str, scheme_len: usize) -> Option<String> {
    let after_scheme = &url[scheme_len..];
    // Authority ends at the first '/' (or end of string if no path).
    let authority = after_scheme.split('/').next()?;
    // Strip optional userinfo (`user:pass@`).
    let host_port = authority.rsplit('@').next()?;
    // Strip optional port.
    let host = host_port.split(':').next()?.trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- parse_authority_host ---

    #[test]
    fn extracts_host_from_https_url() {
        assert_eq!(
            parse_authority_host("https://api.example.com/path", "https://".len()),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn extracts_host_strips_port() {
        assert_eq!(
            parse_authority_host("http://evil.com:8080/data", "http://".len()),
            Some("evil.com".into())
        );
    }

    #[test]
    fn extracts_host_strips_userinfo() {
        assert_eq!(
            parse_authority_host("https://user:pass@api.example.com/", "https://".len()),
            Some("api.example.com".into())
        );
    }

    #[test]
    fn returns_none_for_empty_host() {
        assert_eq!(
            parse_authority_host("https:///path", "https://".len()),
            None
        );
    }

    // --- extract_hosts_from_value: URL-scheme strings ---

    #[test]
    fn extracts_top_level_url_string() {
        let v = json!("https://evil.com/exfil");
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    #[test]
    fn extracts_https_url_from_url_key() {
        let v = json!({"url": "https://evil.com/exfil"});
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    #[test]
    fn extracts_http_url() {
        let v = json!({"endpoint": "http://api.example.com/data"});
        assert_eq!(extract_hosts_from_value(&v), vec!["api.example.com"]);
    }

    #[test]
    fn extracts_ws_url() {
        let v = json!({"stream": "ws://realtime.example.com/socket"}); // nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket
        assert_eq!(extract_hosts_from_value(&v), vec!["realtime.example.com"]);
    }

    #[test]
    fn extracts_wss_url() {
        let v = json!("wss://secure.example.com/ws");
        assert_eq!(extract_hosts_from_value(&v), vec!["secure.example.com"]);
    }

    #[test]
    fn extracts_ftp_url() {
        let v = json!({"file": "ftp://files.example.com/data.zip"});
        assert_eq!(extract_hosts_from_value(&v), vec!["files.example.com"]);
    }

    // --- extract_hosts_from_value: host-key strings ---

    #[test]
    fn extracts_plain_hostname_from_host_key() {
        let v = json!({"host": "evil.com"});
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    #[test]
    fn extracts_hostname_with_port_from_hostname_key() {
        let v = json!({"hostname": "evil.com:443"});
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    #[test]
    fn extracts_from_target_key() {
        let v = json!({"target": "attacker.io"});
        assert_eq!(extract_hosts_from_value(&v), vec!["attacker.io"]);
    }

    #[test]
    fn extracts_from_remote_key() {
        let v = json!({"remote": "exfil.attacker.io"});
        assert_eq!(extract_hosts_from_value(&v), vec!["exfil.attacker.io"]);
    }

    #[test]
    fn extracts_from_server_key() {
        let v = json!({"server": "data.evil.com"});
        assert_eq!(extract_hosts_from_value(&v), vec!["data.evil.com"]);
    }

    // --- extract_hosts_from_value: nested structures ---

    #[test]
    fn extracts_from_nested_object() {
        let v = json!({"outer": {"inner": {"url": "https://evil.com/x"}}});
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    #[test]
    fn extracts_from_array() {
        let v = json!({"urls": ["https://a.com/p", "https://b.com/q"]});
        let hosts = extract_hosts_from_value(&v);
        assert!(
            hosts.contains(&"a.com".to_owned()),
            "a.com must be extracted"
        );
        assert!(
            hosts.contains(&"b.com".to_owned()),
            "b.com must be extracted"
        );
    }

    #[test]
    fn extracts_multiple_hosts_from_different_keys() {
        let v = json!({
            "endpoint": "https://api.example.com/x",
            "callback": "https://evil.com/y"
        });
        let hosts = extract_hosts_from_value(&v);
        assert_eq!(hosts.len(), 2);
        assert!(hosts.contains(&"api.example.com".to_owned()));
        assert!(hosts.contains(&"evil.com".to_owned()));
    }

    #[test]
    fn extracts_from_deeply_nested_array_in_object() {
        let v = json!({"data": {"items": [{"link": "https://evil.com"}]}});
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    // --- deduplication ---

    #[test]
    fn deduplicates_same_host_across_keys() {
        let v = json!({
            "url": "https://api.example.com/a",
            "mirror": "https://api.example.com/b"
        });
        let hosts = extract_hosts_from_value(&v);
        assert_eq!(hosts, vec!["api.example.com"]);
    }

    // --- negative cases ---

    #[test]
    fn ignores_arbitrary_key_non_url_string() {
        let v = json!({"description": "some plain text with no URL"});
        assert!(extract_hosts_from_value(&v).is_empty());
    }

    #[test]
    fn ignores_number_and_bool_values() {
        let v = json!({"count": 42, "active": true, "ratio": 0.5});
        assert!(extract_hosts_from_value(&v).is_empty());
    }

    #[test]
    fn handles_null_value() {
        assert!(extract_hosts_from_value(&Value::Null).is_empty());
    }

    #[test]
    fn handles_empty_object() {
        assert!(extract_hosts_from_value(&json!({})).is_empty());
    }

    #[test]
    fn handles_empty_array() {
        assert!(extract_hosts_from_value(&json!([])).is_empty());
    }

    // --- Red-team: evasion attempts ---

    #[test]
    fn redteam_arbitrary_key_with_url_scheme_is_caught() {
        // Key "x_custom_cb" is not in HOST_KEYS, but the value begins with
        // https:// so the host is extracted via the URL-scheme path.
        let v = json!({"x_custom_cb": "https://evil.com/steal"});
        assert_eq!(extract_hosts_from_value(&v), vec!["evil.com"]);
    }

    #[test]
    fn redteam_ftp_exfil_is_caught() {
        let v = json!({"archive": "ftp://exfil.attacker.io/stolen.tar.gz"});
        assert_eq!(extract_hosts_from_value(&v), vec!["exfil.attacker.io"]);
    }

    #[test]
    fn redteam_url_inside_nested_batch() {
        let v = json!({
            "batch": [
                {"url": "https://evil.com/1"},
                {"url": "https://safe.example.com/2"}
            ]
        });
        let hosts = extract_hosts_from_value(&v);
        assert!(
            hosts.contains(&"evil.com".to_owned()),
            "evil.com must be detected"
        );
        assert!(hosts.contains(&"safe.example.com".to_owned()));
    }

    #[test]
    fn redteam_mixed_host_and_url_keys() {
        // Tool call combines a "host" key and a URL-valued "endpoint" key.
        let v = json!({"host": "exfil.evil.com", "endpoint": "https://api.example.com/"});
        let hosts = extract_hosts_from_value(&v);
        assert!(hosts.contains(&"exfil.evil.com".to_owned()));
        assert!(hosts.contains(&"api.example.com".to_owned()));
    }
}
