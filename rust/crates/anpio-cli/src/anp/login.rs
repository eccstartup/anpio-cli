//! `anp login` — the online half of the `anp` pair: prove this identity to an application
//! server and take back the credential it issues.
//!
//! The request is the one [`super::sign`] prints, sent instead of displayed. Everything the
//! protocol obliges is in [`super::request`]; what is here is what the *answer* means — an
//! access token, a refusal, or the conclusion that the DID this client signed with is no
//! longer the current one.
//!
//! The last of those is the reason this returns a typed error rather than an `anyhow`. A 409
//! `did_superseded` is a statement about the identity, not a rejection of a proof (ANP-03
//! §3.2), and the caller has to do something with it that a string cannot express: walk the
//! chain and tell the user their DID moved. Folding it into "the login failed" would hide the
//! one answer here that is a conclusion.

use serde_json::Value;

use crate::anp::request::{self as anp_request, SignedPost};
use crate::identity::{subject_of, Identity};
use crate::message::client::client_for_url;
use crate::message::resolve::ResolvePolicy;

/// What a successful login amounts to.
///
/// Both names are reported on purpose. `did` is what the site saw — the wire credential, which
/// a key update replaces. `subject` is derived from it and survives that update, so a session
/// keyed on the subject outlives the key; the TS client returns both for the same reason.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub subject: String,
    pub did: String,
    /// The access token, from `Authentication-Info` or the body (ANP-02 §3.2.3).
    pub token: Option<String>,
    /// The `token_type` the server named for it, verbatim. `None` means the spec's default
    /// (`Bearer`) applies.
    pub token_type: Option<String>,
    pub doc_url: Option<String>,
}

/// A login that did not produce a token.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    /// The peer refused, and said so — a status, a body, or a local refusal before anything
    /// was sent. Nothing about the identity is in question.
    #[error("{0:#}")]
    Refused(anyhow::Error),
    /// 409 `did_superseded`: the DID this client signed with is no longer the current one.
    /// The peer's claim is a **hint** and is reported as such; ANP-03 §3.2 is explicit that
    /// re-signing from the DID it names would hand the peer the choice of credential.
    #[error("did_superseded: {0}")]
    Superseded(Superseded),
}

/// The peer's 409, kept separate from this client's own conclusion.
///
/// Both DIDs are the peer's words, not verified facts, which is why neither is named
/// `current_did`: the walk that establishes the real one is the caller's next move, and
/// labelling the hint as the answer is how it stops being treated as one.
#[derive(Debug, Clone)]
pub struct Superseded {
    pub requested_did: String,
    pub claimed_current_did: Option<String>,
}

impl std::fmt::Display for Superseded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} is no longer current", self.requested_did)
    }
}

/// Log in to `target` as `identity`, and take back the token it issues.
///
/// `document` travels with `signer` rather than being read off the identity because an
/// `anpio-key` identity's document is fetched from the daemon on the way in: it is the
/// document the peer will compare the signature against, so it must be the one the key
/// belongs to.
pub async fn login(
    _client: &reqwest::Client,
    target: &str,
    policy: &ResolvePolicy,
    identity: &Identity,
    signer: &crate::anp::request::Signer,
    document: &Value,
    nonce: &str,
) -> std::result::Result<LoginOutcome, LoginError> {
    let url = reqwest::Url::parse(target)
        .map_err(|err| LoginError::Refused(anyhow::anyhow!("--target must be a URL: {err}")))?;
    // The target is the application server, and the policy is the caller's: a login is a
    // signed request carrying the DID document, so it goes to the same hosts everything else
    // this client sends to may go to, and no others.
    let client = client_for_url(&url, policy, "the login endpoint").map_err(|err| LoginError::Refused(err.into()))?;

    let posted = anp_request::post_signed(
        &client,
        &SignedPost {
            did: &identity.did,
            document,
            signer,
            keyid: &format!("{}#key-1", identity.did),
            target,
            nonce,
            // A login carries no application payload: what is being proved is the identity,
            // and the three names the protocol owns are the whole of it.
            extra: None,
        },
    )
    .await
    .map_err(|err| LoginError::Refused(err.into_error()))?;

    let status = posted.response.status();
    if status == reqwest::StatusCode::CONFLICT {
        let body = read_body(posted.response).await;
        if server_code(&body).as_deref() == Some("did_superseded") {
            // The peer's report is about OUR credential; if it names a different DID it is
            // not about what we signed with, so it is not the answer to this request.
            let claimed = body.get("requestedDid").and_then(Value::as_str);
            if claimed.is_none() || claimed == Some(identity.did.as_str()) {
                return Err(LoginError::Superseded(Superseded {
                    requested_did: identity.did.clone(),
                    claimed_current_did: body
                        .get("currentDid")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                }));
            }
        }
        return Err(LoginError::Refused(anyhow::anyhow!(
            "login_failed: {target} answered HTTP {status}{}",
            describe(&body)
        )));
    }

    if !status.is_success() {
        // 403 is worth naming apart: the DID authenticated and is not permitted, which is a
        // different thing for the caller to do something about than "your proof was rejected"
        // (ANP-02 §3.2.4.2).
        let body = read_body(posted.response).await;
        let code = if status == reqwest::StatusCode::FORBIDDEN {
            "authorization_denied"
        } else {
            "login_failed"
        };
        return Err(LoginError::Refused(anyhow::anyhow!(
            "{code}: {target} answered HTTP {status}{}",
            describe(&body)
        )));
    }

    // Before the 2xx is taken as a login: a web page answers 200 too, and every field of the
    // outcome is optional, so a page would be reported as a successful sign-in (assert_not_web_page).
    anp_request::assert_not_web_page(&posted.response, target).map_err(LoginError::Refused)?;

    // The header first, and the body only if the header carried nothing: `text()` consumes
    // the body, so the one read has to happen after every header question is answered.
    let (header_token, header_type) = header_access_token(&posted.response);
    let body = read_body(posted.response).await;
    let (token, token_type) = match header_token {
        Some(token) => (Some(token), header_type),
        None => body_access_token(&body),
    };

    Ok(LoginOutcome {
        subject: subject_of(&identity.did),
        did: identity.did.clone(),
        token,
        token_type,
        doc_url: body.get("docUrl").and_then(Value::as_str).map(str::to_string),
    })
}

/// The access token from `Authentication-Info` (ANP-02 §3.2.3), with the `token_type` the
/// server named beside it.
///
/// The two are read from the same carrier on purpose: a `token_type` from the header describes
/// the header's token, and pairing it with a body token would attach one source's typing rules
/// to another source's credential.
pub fn header_access_token(response: &reqwest::Response) -> (Option<String>, Option<String>) {
    let Some(header) = response
        .headers()
        .get("authentication-info")
        .and_then(|value| value.to_str().ok())
    else {
        return (None, None);
    };
    match auth_info_param(header, "access_token") {
        Some(token) => (Some(token), auth_info_param(header, "token_type")),
        None => (None, None),
    }
}

/// The access token from the body — the non-normative convenience this client accepts because
/// §4.2 leaves the header-less case to the implementation.
pub fn body_access_token(body: &Value) -> (Option<String>, Option<String>) {
    match body.get("token").and_then(Value::as_str) {
        // An empty `token` is absent, not a token of zero length.
        Some(token) if !token.is_empty() => (
            Some(token.to_string()),
            body.get("token_type").and_then(Value::as_str).map(str::to_string),
        ),
        _ => (None, None),
    }
}

/// One `param=value` out of an `Authentication-Info` header, quoted or bare.
///
/// Quoted first: a quoted value may contain the commas and spaces the bare form cannot, and a
/// token is base64url precisely so it needs no quoting — but a `token_type` never does either,
/// so both spellings are accepted rather than one being assumed.
fn auth_info_param(header: &str, name: &str) -> Option<String> {
    let quoted = format!("{name}=\"");
    if let Some(rest) = header.split(&quoted).nth(1) {
        if let Some(value) = rest.split('"').next() {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    let bare = format!("{name}=");
    if let Some(rest) = header.split(&bare).nth(1) {
        let value = rest.split([',', ' ', ';']).next().unwrap_or_default();
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// The peer's own `code`, from wherever it put it: the body's `code`, or the `error` an
/// ANP-02 server names in the same vocabulary (§3.2.4.1).
fn server_code(body: &Value) -> Option<String> {
    body.get("code")
        .and_then(Value::as_str)
        .or_else(|| body.get("error").and_then(Value::as_str))
        .map(str::to_string)
}

/// The peer's message, if it sent one. Only for the human line — never branched on: a peer
/// that answers in another language, or not at all, must not change what this client does.
fn describe(body: &Value) -> String {
    match body.get("message").and_then(Value::as_str) {
        Some(message) if !message.is_empty() => format!(": {message}"),
        _ => String::new(),
    }
}

/// A response body as JSON. An unparsable or absent body is an empty object, not an error:
/// the token may ride in a header, so a peer that sends nothing is still a valid answer.
async fn read_body(response: reqwest::Response) -> Value {
    let text = response.text().await.unwrap_or_default();
    serde_json::from_str(&text).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_token_is_read_quoted_or_bare_and_with_its_own_type() {
        assert_eq!(
            auth_info_param(r#"sig1=("x"); access_token="abc.def", token_type="Bearer""#, "access_token")
                .as_deref(),
            Some("abc.def")
        );
        assert_eq!(
            auth_info_param("access_token=abc, token_type=DPoP", "token_type").as_deref(),
            Some("DPoP")
        );
        // A listed parameter stops at the delimiter rather than swallowing the rest.
        assert_eq!(
            auth_info_param("access_token=abc; other=1", "access_token").as_deref(),
            Some("abc")
        );
        assert_eq!(auth_info_param("realm=\"x\"", "access_token"), None);
    }

    #[test]
    fn the_body_form_needs_a_token_and_keeps_the_type_with_it() {
        // The peer's `error` is in the same place a `code` would be, so both are read.
        assert_eq!(server_code(&json!({"error": "did_superseded"})).as_deref(), Some("did_superseded"));
        assert_eq!(server_code(&json!({"code": "handle_taken"})).as_deref(), Some("handle_taken"));
        assert_eq!(server_code(&json!({})), None);
    }

    #[test]
    fn a_superseded_hint_is_reported_but_never_promoted_to_the_answer() {
        let superseded = Superseded {
            requested_did: "did:wba:h:user:a:e1_old".to_string(),
            claimed_current_did: Some("did:wba:h:user:a:e1_new".to_string()),
        };
        // The message names the DID we signed with; the peer's claim stays a field, because
        // the walk is what makes a DID current, not the peer's word.
        assert!(superseded.to_string().contains("e1_old"));
        assert!(!superseded.to_string().contains("e1_new"));
    }
}
