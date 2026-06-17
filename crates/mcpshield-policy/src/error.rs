use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("capability '{0}' is not in the allowlist")]
    CapabilityDenied(String),

    #[error("outbound call to host '{0}' blocked by proxy filter")]
    OutboundBlocked(String),

    #[error("outbound payload blocked by DLP rule '{0}'")]
    DlpViolation(String),

    #[error("invalid DLP rule '{0}'")]
    InvalidDlpRule(String),

    #[error("HMAC verification failed: policy snapshot integrity check did not pass")]
    InvalidSignature,

    #[error("failed to serialize policy for signing: {0}")]
    SerializationFailed(#[from] serde_json::Error),
}
