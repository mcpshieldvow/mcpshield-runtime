use serde::{Deserialize, Serialize};

/// Defines which MCP tools and resources a sandboxed server is permitted to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAllowlist {
    /// Exact tool names permitted (e.g. `"read_file"`, `"search_web"`).
    pub tools: Vec<String>,
    /// URI prefixes for permitted resources (e.g. `"file:///tmp/"`).
    pub resources: Vec<String>,
}

impl CapabilityAllowlist {
    pub fn new(tools: Vec<String>, resources: Vec<String>) -> Self {
        Self { tools, resources }
    }

    pub fn allows_tool(&self, tool_name: &str) -> bool {
        self.tools.iter().any(|t| t == tool_name)
    }

    /// Check whether a resource URI falls within an allowed prefix.
    ///
    /// The URI path is normalised before the prefix check so that `..` segments
    /// cannot be used to escape an allowed prefix (e.g. `file:///tmp/../etc/passwd`).
    pub fn allows_resource(&self, resource_uri: &str) -> bool {
        let normalized = normalize_uri_path(resource_uri);
        self.resources
            .iter()
            .any(|prefix| normalized.starts_with(prefix.as_str()))
    }
}

/// Defines which outbound network hosts a sandboxed server may contact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundFilter {
    /// Allowed hostnames (exact match, no wildcards in this initial version).
    pub allowed_hosts: Vec<String>,
}

impl OutboundFilter {
    pub fn new(allowed_hosts: Vec<String>) -> Self {
        Self { allowed_hosts }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|h| h == host)
    }
}

/// Normalise the path component of a URI to eliminate `..` traversal segments.
/// Scheme, authority, query string, and fragment are preserved unchanged.
fn normalize_uri_path(uri: &str) -> String {
    let (before_query, suffix) = split_query(uri);

    let path_start = if let Some(scheme_end) = before_query.find("://") {
        let after_auth = &before_query[scheme_end + 3..];
        scheme_end + 3 + after_auth.find('/').unwrap_or(after_auth.len())
    } else {
        0
    };

    let authority = &before_query[..path_start];
    let raw_path = &before_query[path_start..];
    format!("{authority}{}{suffix}", normalize_path(raw_path))
}

fn split_query(s: &str) -> (&str, &str) {
    s.find(['?', '#'])
        .map(|i| (&s[..i], &s[i..]))
        .unwrap_or((s, ""))
}

fn normalize_path(path: &str) -> String {
    let leading_slash = path.starts_with('/');
    let trailing_slash = path.len() > 1 && path.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    match (leading_slash, trailing_slash && !joined.is_empty()) {
        (true, true) => format!("/{joined}/"),
        (true, false) => format!("/{joined}"),
        (false, true) => format!("{joined}/"),
        (false, false) => joined,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_permits_known_tool() {
        let list = CapabilityAllowlist::new(vec!["read_file".into()], vec![]);
        assert!(list.allows_tool("read_file"));
        assert!(!list.allows_tool("exec_shell"));
    }

    #[test]
    fn allowlist_permits_resource_by_prefix() {
        let list = CapabilityAllowlist::new(vec![], vec!["file:///tmp/".into()]);
        assert!(list.allows_resource("file:///tmp/data.json"));
        assert!(!list.allows_resource("file:///etc/passwd"));
    }

    #[test]
    fn outbound_filter_blocks_unknown_host() {
        let filter = OutboundFilter::new(vec!["api.example.com".into()]);
        assert!(filter.allows_host("api.example.com"));
        assert!(!filter.allows_host("evil.example.com"));
    }

    #[test]
    fn blocks_path_traversal_to_etc_passwd() {
        let list = CapabilityAllowlist::new(vec![], vec!["file:///tmp/".into()]);
        // /tmp/../etc/passwd normalises to /etc/passwd — must be blocked
        assert!(!list.allows_resource("file:///tmp/../etc/passwd"));
    }

    #[test]
    fn blocks_path_traversal_to_etc_shadow() {
        let list = CapabilityAllowlist::new(vec![], vec!["file:///tmp/".into()]);
        assert!(!list.allows_resource("file:///tmp/../etc/shadow"));
    }

    #[test]
    fn permits_benign_subpath_with_dotdot() {
        let list = CapabilityAllowlist::new(vec![], vec!["file:///tmp/".into()]);
        // /tmp/sub/../data.json normalises to /tmp/data.json — still under the prefix
        assert!(list.allows_resource("file:///tmp/sub/../data.json"));
    }

    #[test]
    fn normalize_path_clamps_dotdot_at_root() {
        // `..` from root stays at root; subsequent segments are still appended.
        assert_eq!(normalize_path("/../etc/passwd"), "/etc/passwd");
    }

    #[test]
    fn normalize_path_preserves_trailing_slash() {
        assert_eq!(normalize_path("/tmp/"), "/tmp/");
    }

    #[test]
    fn normalize_path_removes_dot_segments() {
        assert_eq!(normalize_path("/a/./b"), "/a/b");
    }
}
