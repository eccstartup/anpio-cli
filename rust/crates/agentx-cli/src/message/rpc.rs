//! The HTTP hop: JSON-RPC over HTTP, client half (P1 §5–§6).
//!
//! The port of `packages/core/src/message/rpc.ts`. It does three things and no more: POST
//! the request to the `serviceEndpoint`, read back a body, and decide whether what came
//! back is a well-formed JSON-RPC response (§5.6). No authentication, no signing, no retry
//! — the same omissions, for the same reason: a retry has to reuse the same `operation_id`,
//! and only the caller knows what that is.
//!
//! **A peer's refusal is not an error here.** §5.6 makes a failure response an object with
//! an `error` member arriving under HTTP 200; that is the protocol working. It is returned
//! as [`AnpResponse::Error`] so the caller can branch on `anp_code`. Only four things are
//! real errors: a network/policy failure, a non-2xx status, a body that is not a JSON-RPC
//! response, and an `id` that does not match the request's.
//!
//! **Every POST carries its own hop policy.** The endpoint is read out of a peer's DID
//! document, so the host is chosen by the peer — a caller cannot be trusted to remember
//! that, and a transport that lets one request skip the check is a transport that will
//! eventually carry one. So the policy is a parameter rather than something the caller is
//! expected to have applied first (`packages/core/src/crypto/resolveDid.ts`).

use reqwest::Url;
use serde_json::Value;

use crate::error::{AgentxError, AnpErrorObject, Result};

use super::envelope::{AnpNotification, AnpRequest, JSONRPC_VERSION};
use super::resolve::{assert_allowed_host, ResolvePolicy};

/// A JSON-RPC response (P1 §5.6). Success and failure are the two arms of one type, because
/// exactly one of them is present and which one it is *is* the answer.
#[derive(Debug, Clone)]
pub enum AnpResponse {
    Success { id: String, result: Value },
    Error { id: String, error: AnpErrorObject },
}

impl AnpResponse {
    /// The `id` the peer answered with (§5.6 — equal to the request's, enforced in `post`).
    pub fn id(&self) -> &str {
        match self {
            AnpResponse::Success { id, .. } | AnpResponse::Error { id, .. } => id,
        }
    }

    /// The `anp_code` of a failure (§10.2 — present only in the ANP custom range).
    ///
    /// Standard codes (`-32xxx`) are deliberately **not** translated into an ANP code: they
    /// are told apart by `message`, and inventing a correspondence the spec does not have
    /// would be worse than making the caller read it.
    pub fn anp_code(&self) -> Option<&str> {
        match self {
            AnpResponse::Error { error, .. } => error.data.as_ref()?.anp_code.as_deref(),
            AnpResponse::Success { .. } => None,
        }
    }
}

const JSON_RPC_HEADERS: [(&str, &str); 2] = [
    ("content-type", "application/json"),
    ("accept", "application/json"),
];

/// A response larger than this is refused rather than buffered. Matches the guard the TS
/// client applies through `fetchControlledJson`'s `tooLarge` code.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

fn check_response(endpoint: &str, request_id: &str, text: &str) -> Result<AnpResponse> {
    let raw: Value = serde_json::from_str(text).map_err(|_| {
        AgentxError::MessageInvalid(format!(
            "ANP message service at {endpoint} did not answer with a JSON-RPC response object"
        ))
    })?;
    let object = raw.as_object().ok_or_else(|| {
        AgentxError::MessageInvalid(format!(
            "ANP message service at {endpoint} did not answer with a JSON-RPC response object"
        ))
    })?;

    if object.get("jsonrpc").and_then(Value::as_str) != Some(JSONRPC_VERSION) {
        return Err(AgentxError::MessageInvalid(format!(
            "ANP message service at {endpoint} answered with jsonrpc {}; it MUST be exactly \"2.0\" (P1 §4.1)",
            object.get("jsonrpc").map_or("nothing".to_string(), Value::to_string),
        )));
    }
    // §5.6: the response id MUST equal the request id exactly — otherwise a cache or a
    // crossed answer could hand us someone else's result as ours.
    let id = object.get("id").and_then(Value::as_str);
    if id != Some(request_id) {
        return Err(AgentxError::MessageInvalid(format!(
            "ANP message service at {endpoint} answered id {} for request id {request_id:?}; they MUST match (P1 §5.6)",
            object.get("id").map_or("nothing".to_string(), Value::to_string),
        )));
    }
    let id = id.unwrap_or_default().to_string();

    let has_error = object.contains_key("error");
    let has_result = object.contains_key("result");
    // §5.6: success MUST have `result` and MUST NOT have `error`; failure the reverse.
    if has_error == has_result {
        return Err(AgentxError::MessageInvalid(format!(
            "ANP message service at {endpoint} answered with {} of result and error (P1 §5.6)",
            if has_error { "both" } else { "neither" }
        )));
    }

    if !has_error {
        return Ok(AnpResponse::Success {
            id,
            result: object.get("result").cloned().unwrap_or(Value::Null),
        });
    }

    let error = object.get("error").cloned().unwrap_or(Value::Null);
    let error: AnpErrorObject = serde_json::from_value(error)
        .map_err(|err| AgentxError::MessageInvalid(format!("ANP message service at {endpoint} answered with an error object missing code or message (P1 §10.2): {err}")))?;
    Ok(AnpResponse::Error { id, error })
}

/// POST a Request to an ANP endpoint and return its response object.
///
/// `policy` is the hop policy for this POST, and `context` names who chose the endpoint,
/// for the refusal message. The check runs here rather than at the call site on purpose:
/// the endpoint comes out of a peer's DID document, so "remember to check it" is the one
/// thing this hop must not rely on.
pub async fn post_message(
    client: &reqwest::Client,
    endpoint: &str,
    request: &AnpRequest,
    policy: &ResolvePolicy,
    context: &str,
) -> Result<AnpResponse> {
    let url = Url::parse(endpoint)
        .map_err(|err| AgentxError::MessageInvalid(format!("endpoint is not a URL: {err}")))?;
    assert_allowed_host(&url, policy, context)?;

    let body = serde_json::to_string(request)?;
    // §14.1: no redirects. A redirect would carry the signed request to a host the policy
    // never saw, which is the one thing this hop is arranged to prevent; the client that
    // makes these requests is built with `redirect::Policy::none()` (see `message::client`).
    let response = client
        .post(url.clone())
        .headers(reqwest::header::HeaderMap::from_iter(
            JSON_RPC_HEADERS.iter().map(|(name, value)| {
                (
                    reqwest::header::HeaderName::from_bytes(name.as_bytes())
                        .expect("static header name"),
                    reqwest::header::HeaderValue::from_str(value).expect("static header value"),
                )
            }),
        ))
        .body(body)
        .send()
        .await
        .map_err(|err| AgentxError::MessageSendFailed(err.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(AgentxError::MessageSendFailed(format!(
            "ANP message service at {endpoint} answered HTTP {status}"
        )));
    }
    let text = response
        .text()
        .await
        .map_err(|err| AgentxError::MessageSendFailed(err.to_string()))?;
    if text.len() > MAX_RESPONSE_BYTES {
        return Err(AgentxError::ResponseTooLarge(format!(
            "ANP message service at {endpoint} answered {} bytes",
            text.len()
        )));
    }
    check_response(endpoint, &request.id, &text)
}

/// POST a Notification. Only "did it arrive" is known — §5.3 gives it no response to match,
/// so a 200 with an empty body is success, and reading it as JSON would turn a delivered
/// notification into a failure and resend it.
pub async fn post_notification(
    client: &reqwest::Client,
    endpoint: &str,
    notification: &AnpNotification,
    policy: &ResolvePolicy,
    context: &str,
) -> Result<()> {
    let url = Url::parse(endpoint)
        .map_err(|err| AgentxError::MessageInvalid(format!("endpoint is not a URL: {err}")))?;
    assert_allowed_host(&url, policy, context)?;

    let body = serde_json::to_string(notification)?;
    let response = client
        .post(url)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|err| AgentxError::MessageSendFailed(err.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(AgentxError::MessageSendFailed(format!(
            "ANP message service at {endpoint} answered HTTP {status}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn service_error_arm(text: &str) -> AnpResponse {
        check_response("https://svc.example/rpc", "id-1", text).unwrap()
    }

    #[test]
    fn success_response_is_read() {
        let response = service_error_arm(r#"{"jsonrpc":"2.0","id":"id-1","result":{"ok":true}}"#);
        match response {
            AnpResponse::Success { result, .. } => assert_eq!(result, json!({"ok": true})),
            other => panic!("expected success, got {other:?}"),
        }
    }

    #[test]
    fn failure_response_is_an_answer_not_an_error() {
        let response = service_error_arm(
            r#"{"jsonrpc":"2.0","id":"id-1","error":{"code":5002,"message":"no","data":{"anp_code":"anp.group.e2ee.did_binding_invalid"}}}"#,
        );
        assert_eq!(response.anp_code(), Some("anp.group.e2ee.did_binding_invalid"));
    }

    #[test]
    fn standard_codes_have_no_anp_code() {
        let response =
            service_error_arm(r#"{"jsonrpc":"2.0","id":"id-1","error":{"code":-32600,"message":"bad"}}"#);
        assert_eq!(response.anp_code(), None);
    }

    #[test]
    fn mismatched_id_is_refused() {
        let err = check_response("https://svc.example/rpc", "id-1", r#"{"jsonrpc":"2.0","id":"id-2","result":{}}"#)
            .unwrap_err();
        assert!(matches!(err, AgentxError::MessageInvalid(_)));
    }

    #[test]
    fn both_or_neither_of_result_and_error_is_refused() {
        assert!(check_response("e", "i", r#"{"jsonrpc":"2.0","id":"i"}"#).is_err());
        assert!(check_response("e", "i", r#"{"jsonrpc":"2.0","id":"i","result":{},"error":{"code":1,"message":"m"}}"#).is_err());
    }

    #[test]
    fn wrong_jsonrpc_version_is_refused() {
        assert!(check_response("e", "i", r#"{"jsonrpc":"1.0","id":"i","result":{}}"#).is_err());
    }
}
