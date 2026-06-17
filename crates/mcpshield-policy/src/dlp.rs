//! Regex-based Data Loss Prevention (DLP) engine.
//!
//! The DLP layer scans outbound payloads for sensitive content (PII, secrets,
//! credentials) and is the third stage of the outbound evaluation pipeline
//! defined by PLAN-RULE-01: capability allowlist → proxy rules → **DLP scan** →
//! IOC match. Like every stage it is fail-closed — a payload that matches any
//! rule denies the entire request.
//!
//! Rules are plain regular expressions carried as strings inside the signed
//! [`PolicySnapshot`](crate::PolicySnapshot) so they share the snapshot's HMAC
//! integrity guarantee and cannot be swapped without detection. They are
//! compiled once when the [`PolicyEngine`](crate::PolicyEngine) is built; an
//! invalid pattern fails construction rather than silently disabling a rule.
//!
//! Pattern matching uses the `regex` crate, whose finite-automata engine runs in
//! linear time and has no backtracking, so an adversarial rule or payload cannot
//! trigger catastrophic-backtracking (ReDoS) stalls in the runtime.
//!
//! ML-based DLP (semantic/contextual detection) is intentionally out of scope
//! for this phase — see ADR-0005.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::PolicyError;

/// A single named DLP detection rule.
///
/// `pattern` is stored as source text so the rule can travel inside the signed,
/// serialisable policy snapshot; it is compiled into a [`Regex`] when the engine
/// is built.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpRule {
    /// Stable identifier reported in detection events and deny reasons
    /// (e.g. `"credit_card"`). Never contains the matched value.
    pub name: String,
    /// Regular-expression source matched against payload strings.
    pub pattern: String,
}

impl DlpRule {
    pub fn new(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pattern: pattern.into(),
        }
    }
}

/// An ordered set of DLP rules, signed as part of the policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DlpRuleset {
    pub rules: Vec<DlpRule>,
}

impl DlpRuleset {
    pub fn new(rules: Vec<DlpRule>) -> Self {
        Self { rules }
    }

    /// Built-in ruleset covering the most common classes of sensitive data that
    /// must not leave the sandbox: PII (email, US SSN, credit-card numbers) and
    /// credentials (AWS access-key IDs, private-key blocks, bearer tokens).
    ///
    /// Tenants extend or replace this set through their signed policy; it exists
    /// so a server is protected by sensible defaults out of the box.
    pub fn with_defaults() -> Self {
        Self::new(vec![
            DlpRule::new("email", r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
            DlpRule::new("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
            DlpRule::new(
                "credit_card",
                r"\b\d{4}[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{1,4}\b",
            ),
            DlpRule::new("aws_access_key_id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            DlpRule::new(
                "private_key",
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            ),
            DlpRule::new("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
        ])
    }
}

/// A DLP match. Carries only the rule identifier — never the matched value —
/// so findings can be logged and returned without leaking sensitive data
/// (CONST-LOG-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlpFinding {
    pub rule: String,
}

/// A compiled, ready-to-run DLP ruleset.
#[derive(Debug)]
pub struct DlpEngine {
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
    regex: Regex,
}

impl DlpEngine {
    /// Compile a ruleset. Fails with [`PolicyError::InvalidDlpRule`] if any
    /// pattern is not a valid regular expression, naming the offending rule.
    pub fn compile(ruleset: &DlpRuleset) -> Result<Self, PolicyError> {
        let mut rules = Vec::with_capacity(ruleset.rules.len());
        for rule in &ruleset.rules {
            let regex = Regex::new(&rule.pattern)
                .map_err(|e| PolicyError::InvalidDlpRule(format!("{}: {e}", rule.name)))?;
            rules.push(CompiledRule {
                name: rule.name.clone(),
                regex,
            });
        }
        Ok(Self { rules })
    }

    /// Number of active rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a single string, returning one finding per rule that matched.
    ///
    /// Each rule contributes at most one finding regardless of how many times it
    /// matches; the matched text is deliberately not retained.
    pub fn scan_text(&self, text: &str) -> Vec<DlpFinding> {
        self.rules
            .iter()
            .filter(|rule| rule.regex.is_match(text))
            .map(|rule| DlpFinding {
                rule: rule.name.clone(),
            })
            .collect()
    }

    /// Recursively scan every string in a JSON value tree (object values, array
    /// items, nested at any depth). Findings are de-duplicated by rule name so a
    /// rule that matches in several places is reported once.
    pub fn scan_value(&self, value: &Value) -> Vec<DlpFinding> {
        let mut matched = vec![false; self.rules.len()];
        self.collect(value, &mut matched);
        self.rules
            .iter()
            .zip(matched)
            .filter(|(_, hit)| *hit)
            .map(|(rule, _)| DlpFinding {
                rule: rule.name.clone(),
            })
            .collect()
    }

    fn collect(&self, value: &Value, matched: &mut [bool]) {
        match value {
            Value::String(s) => {
                for (i, rule) in self.rules.iter().enumerate() {
                    if !matched[i] && rule.regex.is_match(s) {
                        matched[i] = true;
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr {
                    self.collect(item, matched);
                }
            }
            Value::Object(map) => {
                for v in map.values() {
                    self.collect(v, matched);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine() -> DlpEngine {
        DlpEngine::compile(&DlpRuleset::with_defaults()).unwrap()
    }

    // --- compilation ---

    #[test]
    fn compiles_default_ruleset() {
        let engine = engine();
        assert_eq!(engine.rule_count(), 6);
    }

    #[test]
    fn compiles_empty_ruleset() {
        let engine = DlpEngine::compile(&DlpRuleset::default()).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn rejects_invalid_pattern_naming_the_rule() {
        let bad = DlpRuleset::new(vec![DlpRule::new("broken", "(unclosed")]);
        let err = DlpEngine::compile(&bad).unwrap_err();
        assert!(err.to_string().contains("broken"));
    }

    // --- detection: each default rule matches its sensitive class ---

    #[test]
    fn detects_email_address() {
        let hits = engine().scan_text("contact alice@example.com please");
        assert!(hits.iter().any(|f| f.rule == "email"));
    }

    #[test]
    fn detects_us_ssn() {
        let hits = engine().scan_text("ssn 123-45-6789");
        assert!(hits.iter().any(|f| f.rule == "us_ssn"));
    }

    #[test]
    fn detects_credit_card_number() {
        let hits = engine().scan_text("card 4111 1111 1111 1111");
        assert!(hits.iter().any(|f| f.rule == "credit_card"));
    }

    #[test]
    fn detects_credit_card_without_separators() {
        let hits = engine().scan_text("4111111111111111");
        assert!(hits.iter().any(|f| f.rule == "credit_card"));
    }

    #[test]
    fn detects_aws_access_key_id() {
        let hits = engine().scan_text("key=AKIAIOSFODNN7EXAMPLE end");
        assert!(hits.iter().any(|f| f.rule == "aws_access_key_id"));
    }

    #[test]
    fn detects_private_key_block() {
        let hits = engine().scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE");
        assert!(hits.iter().any(|f| f.rule == "private_key"));
    }

    #[test]
    fn detects_bearer_token_case_insensitively() {
        let hits = engine().scan_text("Authorization: Bearer abcdef0123456789ABCDEF");
        assert!(hits.iter().any(|f| f.rule == "bearer_token"));
    }

    // --- clean payloads produce no findings ---

    #[test]
    fn clean_text_yields_no_findings() {
        assert!(engine()
            .scan_text("the quick brown fox jumps over 7 lazy dogs")
            .is_empty());
    }

    #[test]
    fn empty_text_yields_no_findings() {
        assert!(engine().scan_text("").is_empty());
    }

    // --- finding never carries the matched value (CONST-LOG-03) ---

    #[test]
    fn finding_contains_rule_name_not_matched_value() {
        let hits = engine().scan_text("alice@example.com");
        let finding = hits.iter().find(|f| f.rule == "email").unwrap();
        assert_eq!(finding.rule, "email");
        assert!(!finding.rule.contains("alice@example.com"));
    }

    // --- JSON tree scanning ---

    #[test]
    fn scans_string_value_in_object() {
        let v = json!({"note": "reach me at bob@corp.io"});
        let hits = engine().scan_value(&v);
        assert!(hits.iter().any(|f| f.rule == "email"));
    }

    #[test]
    fn scans_deeply_nested_value() {
        let v = json!({"a": {"b": {"c": "123-45-6789"}}});
        let hits = engine().scan_value(&v);
        assert!(hits.iter().any(|f| f.rule == "us_ssn"));
    }

    #[test]
    fn scans_array_items() {
        let v = json!({"lines": ["nothing here", "AKIAIOSFODNN7EXAMPLE"]});
        let hits = engine().scan_value(&v);
        assert!(hits.iter().any(|f| f.rule == "aws_access_key_id"));
    }

    #[test]
    fn deduplicates_findings_across_multiple_matches() {
        let v = json!({"to": "a@x.com", "cc": "b@y.com"});
        let hits = engine().scan_value(&v);
        let email_hits = hits.iter().filter(|f| f.rule == "email").count();
        assert_eq!(email_hits, 1, "one email rule must report exactly once");
    }

    #[test]
    fn reports_multiple_distinct_rules() {
        let v = json!({"pii": "ssn 123-45-6789", "secret": "AKIAIOSFODNN7EXAMPLE"});
        let hits = engine().scan_value(&v);
        assert!(hits.iter().any(|f| f.rule == "us_ssn"));
        assert!(hits.iter().any(|f| f.rule == "aws_access_key_id"));
    }

    #[test]
    fn ignores_non_string_scalars() {
        let v = json!({"count": 123456789, "active": true, "ratio": 0.5});
        assert!(engine().scan_value(&v).is_empty());
    }

    #[test]
    fn clean_json_tree_yields_no_findings() {
        let v = json!({"name": "read_file", "path": "/tmp/data.json"});
        assert!(engine().scan_value(&v).is_empty());
    }

    #[test]
    fn empty_engine_never_matches() {
        let engine = DlpEngine::compile(&DlpRuleset::default()).unwrap();
        assert!(engine.scan_value(&json!({"ssn": "123-45-6789"})).is_empty());
    }
}
