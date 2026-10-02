//! Errors.
//!
//! The split mirrors `packages/core/src/message/rpc.ts` (`MESSAGE_FETCH_CODES`): several
//! different transport failures are **one** thing to a caller — *this exchange did not
//! complete* — while oversized is a fact about the data, not the exchange. A refusal by
//! the peer is **not** an error here; it is a well-formed response carrying `error`, which
//! `message::rpc` returns so the caller can branch on `anp_code`.

use serde_json::Value;

pub type Result<T> = std::result::Result<T, AgentxError>;

#[derive(Debug, thiserror::Error)]
pub enum AgentxError {
    /// The exchange completed but what came back is not something we can read as a
    /// JSON-RPC response (P1 §5.6). Also used for a malformed request we are about to send.
    #[error("message_invalid: {0}")]
    MessageInvalid(String),

    /// Network or policy layer failure, non-2xx, or too many redirects. The five fetch
    /// codes that all collapse to `message_send_failed` in the TS client.
    #[error("message_send_failed: {0}")]
    MessageSendFailed(String),

    /// The peer's answer exceeded the size cap. Separate because it is about the data.
    #[error("response_too_large: {0}")]
    ResponseTooLarge(String),

    /// A DID we were asked to work with cannot be turned into one (`invalid_did` in the TS
    /// client). Not a network failure: nothing was attempted.
    #[error("invalid_did: {0}")]
    DidInvalid(String),

    /// The network policy refused a hop (`did_resolve_blocked` / `message_send_failed`'s
    /// blocked arm in the TS client). Also not a network failure — the fetch never left.
    #[error("did_resolve_blocked: {0}")]
    DidResolveBlocked(String),

    /// A DID document does not expose exactly one ANPMessageService (P2 §7.1).
    #[error("message_service_not_found: {0}")]
    MessageServiceNotFound(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

/// A JSON-RPC error object (P1 §10.2). Not an `AgentxError`: this is a peer's *answer*.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AnpErrorObject {
    pub code: i64,
    pub message: String,
    #[serde(default)]
    pub data: Option<AnpErrorData>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AnpErrorData {
    /// P1 §10.2: present **only** when `code` is in the ANP custom range (1000+).
    #[serde(default)]
    pub anp_code: Option<String>,
    #[serde(default)]
    pub retryable: Option<bool>,
    #[serde(default)]
    pub details: Option<Value>,
}
