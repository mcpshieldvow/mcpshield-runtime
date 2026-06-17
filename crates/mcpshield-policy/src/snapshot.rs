use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::{
    allowlist::{CapabilityAllowlist, OutboundFilter},
    dlp::DlpRuleset,
    error::PolicyError,
};

type HmacSha256 = Hmac<Sha256>;

/// Immutable, HMAC-signed snapshot of the active policy.
///
/// The HMAC prevents tampering with policy state between serialization and enforcement.
/// Verification uses the constant-time comparison provided by the `hmac` crate
/// to prevent timing-oracle attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySnapshot {
    pub allowlist: CapabilityAllowlist,
    pub outbound_filter: OutboundFilter,
    /// Regex DLP ruleset applied to outbound payloads. Covered by the HMAC so
    /// rules cannot be swapped or stripped without invalidating the signature.
    pub dlp: DlpRuleset,
    /// Monotonically increasing version; callers must reject snapshots with a lower
    /// version than the one they expect.
    pub version: u64,
    hmac_hex: String,
}

impl PolicySnapshot {
    /// Create a new signed snapshot. Fails only if serialization of the policy data fails.
    pub fn new(
        allowlist: CapabilityAllowlist,
        outbound_filter: OutboundFilter,
        dlp: DlpRuleset,
        version: u64,
        signing_key: &[u8],
    ) -> Result<Self, PolicyError> {
        let hmac_hex = sign_payload(&allowlist, &outbound_filter, &dlp, version, signing_key)?;
        Ok(Self {
            allowlist,
            outbound_filter,
            dlp,
            version,
            hmac_hex,
        })
    }

    /// Verify the snapshot has not been tampered with since it was signed.
    ///
    /// Uses constant-time MAC comparison via [`Hmac::verify_slice`] to prevent
    /// timing-oracle attacks on the stored signature.
    pub fn verify(&self, signing_key: &[u8]) -> Result<(), PolicyError> {
        let payload = serialize_payload(
            &self.allowlist,
            &self.outbound_filter,
            &self.dlp,
            self.version,
        )?;
        let stored = decode_hex(&self.hmac_hex).ok_or(PolicyError::InvalidSignature)?;

        let mut mac = HmacSha256::new_from_slice(signing_key).expect("HMAC accepts any key length");
        mac.update(&payload);
        mac.verify_slice(&stored)
            .map_err(|_| PolicyError::InvalidSignature)
    }
}

/// Compute an HMAC-SHA256 over the policy payload and return the result as a
/// lowercase hex string.
fn sign_payload(
    allowlist: &CapabilityAllowlist,
    outbound_filter: &OutboundFilter,
    dlp: &DlpRuleset,
    version: u64,
    key: &[u8],
) -> Result<String, PolicyError> {
    let payload = serialize_payload(allowlist, outbound_filter, dlp, version)?;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&payload);
    let bytes = mac.finalize().into_bytes();
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Deterministically serialise the fields that are covered by the HMAC.
///
/// Field ordering is fixed by the struct definition so the output is stable
/// across invocations regardless of the runtime environment.
fn serialize_payload(
    allowlist: &CapabilityAllowlist,
    outbound_filter: &OutboundFilter,
    dlp: &DlpRuleset,
    version: u64,
) -> Result<Vec<u8>, PolicyError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        version: u64,
        allowlist: &'a CapabilityAllowlist,
        outbound_filter: &'a OutboundFilter,
        dlp: &'a DlpRuleset,
    }
    Ok(serde_json::to_vec(&Payload {
        version,
        allowlist,
        outbound_filter,
        dlp,
    })?)
}

/// Decode a lowercase or uppercase hex string into bytes.
/// Returns `None` if the string contains non-hex characters or has odd length.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Some((hi << 4) | lo)
        })
        .collect()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"super-secret-signing-key";

    fn sample_allowlist() -> CapabilityAllowlist {
        CapabilityAllowlist::new(vec!["read_file".into()], vec!["file:///tmp/".into()])
    }

    fn sample_filter() -> OutboundFilter {
        OutboundFilter::new(vec!["api.example.com".into()])
    }

    fn sample_dlp() -> DlpRuleset {
        DlpRuleset::with_defaults()
    }

    fn sample_snap() -> PolicySnapshot {
        PolicySnapshot::new(sample_allowlist(), sample_filter(), sample_dlp(), 1, KEY).unwrap()
    }

    // --- Green path ---

    #[test]
    fn snapshot_verify_roundtrip() {
        assert!(sample_snap().verify(KEY).is_ok());
    }

    #[test]
    fn snapshot_with_empty_policy_verifies() {
        let snap = PolicySnapshot::new(
            CapabilityAllowlist::new(vec![], vec![]),
            OutboundFilter::new(vec![]),
            DlpRuleset::default(),
            0,
            KEY,
        )
        .unwrap();
        assert!(snap.verify(KEY).is_ok());
    }

    // --- Wrong key ---

    #[test]
    fn snapshot_rejects_wrong_key() {
        let snap = PolicySnapshot::new(
            sample_allowlist(),
            sample_filter(),
            sample_dlp(),
            1,
            b"correct-key",
        )
        .unwrap();
        assert!(snap.verify(b"wrong-key").is_err());
    }

    // --- Tampered fields (serialise → mutate JSON → deserialise → verify must fail) ---

    #[test]
    fn snapshot_rejects_tampered_allowlist_tools() {
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        json["allowlist"]["tools"] = serde_json::json!(["exec_shell"]);
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_tampered_allowlist_resources() {
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        json["allowlist"]["resources"] = serde_json::json!(["file:///etc/"]);
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_tampered_outbound_filter() {
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        json["outbound_filter"]["allowed_hosts"] = serde_json::json!(["evil.com"]);
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_tampered_dlp_rules() {
        // Stripping a DLP rule must invalidate the signature so an attacker
        // cannot disable detection by editing the serialised snapshot.
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        json["dlp"]["rules"] = serde_json::json!([]);
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_tampered_version() {
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        json["version"] = serde_json::json!(999);
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_tampered_hmac_hex() {
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        let original = json["hmac_hex"].as_str().unwrap().to_owned();
        // Flip the first byte: use "ff" if it starts with "00", else "00".
        let prefix = if original.starts_with("00") {
            "ff"
        } else {
            "00"
        };
        json["hmac_hex"] = serde_json::json!(format!("{prefix}{}", &original[2..]));
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_invalid_hmac_hex() {
        let snap = sample_snap();
        let mut json: serde_json::Value = serde_json::to_value(&snap).unwrap();
        json["hmac_hex"] = serde_json::json!("not-valid-hex!!");
        let tampered: PolicySnapshot = serde_json::from_value(json).unwrap();
        assert!(tampered.verify(KEY).is_err());
    }

    #[test]
    fn snapshot_rejects_cross_version_hmac_replay() {
        // HMAC from version 0 must not validate the version-1 snapshot.
        let snap0 =
            PolicySnapshot::new(sample_allowlist(), sample_filter(), sample_dlp(), 0, KEY).unwrap();
        let snap1 = sample_snap(); // version = 1
        let mut json1 = serde_json::to_value(&snap1).unwrap();
        let json0 = serde_json::to_value(&snap0).unwrap();
        json1["hmac_hex"] = json0["hmac_hex"].clone();
        let mixed: PolicySnapshot = serde_json::from_value(json1).unwrap();
        assert!(mixed.verify(KEY).is_err());
    }

    // --- decode_hex unit tests ---

    #[test]
    fn decode_hex_roundtrips_known_bytes() {
        let bytes = [0x00u8, 0xde, 0xad, 0xbe, 0xef, 0xff];
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(decode_hex(&hex).unwrap(), bytes);
    }

    #[test]
    fn decode_hex_rejects_odd_length() {
        assert!(decode_hex("abc").is_none());
    }

    #[test]
    fn decode_hex_rejects_invalid_chars() {
        assert!(decode_hex("zz").is_none());
    }

    #[test]
    fn decode_hex_accepts_uppercase() {
        assert_eq!(decode_hex("DEADBEEF").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn decode_hex_empty_string_returns_empty_vec() {
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }
}
