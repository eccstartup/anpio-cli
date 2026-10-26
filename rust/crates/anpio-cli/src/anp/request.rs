//! One ANP-02 request: the flat body, and the RFC 9421 headers that sign it.
//!
//! This is the half of ANP-02 that does not depend on *why* a request is being sent. A
//! login, a DID registration and an update hop all put `nonce` / `did` / `didDocument` in
//! the body and sign the bytes with the identity's binding key; what differs is the
//! endpoint, the extra fields, and what the answer is taken to mean. Those stay with their
//! senders; this module owns the part that must not drift between them.
//!
//! It is one module rather than a helper per caller because the signing bytes are the
//! security property: the digest covers the exact vector that is sent, so building the
//! body anywhere other than where it is signed — or signing anything other than what is
//! put on the wire — is how a proxy gets to edit a request.

use std::collections::BTreeMap;

use anp::authentication::http_signatures::{generate_http_signature_headers, HttpSignatureOptions};
use anp::PrivateKeyMaterial;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

use crate::custody::AnpioKey;

/// Where the private half of a signature comes from.
///
/// Two shapes because the protocol has two senders: a key this process read from the store,
/// and a key `anpio-key` holds and will not hand over. The signed request is the same in
/// both cases — the daemon rebuilds the signature base from the same method, target and
/// body — so the difference stops at this enum rather than leaking into every caller.
pub enum Signer {
    /// Key material in this process.
    Local(PrivateKeyMaterial),
    /// A key the daemon signs with, reached through its command interface.
    AnpioKey(AnpioKey),
}

impl Signer {
    /// Sign one request, dispatching to the holder of the key.
    ///
    /// `keyid` is the credential to make the signature under, and only the local arm uses
    /// it: `anpio-key` resolves the key itself, refuses to sign with one the document does
    /// not authorize, and reports which one it used in `Signature-Input`.
    ///
    /// `nonce` is the request body's nonce, passed to the daemon so both places carry the
    /// same value (`anpio-key`'s own recommendation). The local arm keeps the crate's
    /// established behavior — a random signature parameter — because nothing this client
    /// has verified depends on the two being equal.
    // One argument per thing a signature names. Grouping them would only move the same
    // seven values into a struct at each of the two call sites, and the two arms already
    // disagree about which they need (`keyid` is local-only, `nonce` daemon-only).
    #[allow(clippy::too_many_arguments)]
    pub fn sign_headers(
        &self,
        did: &str,
        document: &Value,
        url: &str,
        method: &str,
        keyid: &str,
        body: Option<&[u8]>,
        nonce: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        match self {
            Signer::Local(key) => sign_headers(document, url, method, key, keyid, body),
            Signer::AnpioKey(key) => key.sign_headers(did, method, url, body, nonce),
        }
    }
}

/// The body of an ANP-02 request: the three names the protocol owns, plus whatever the
/// endpoint adds.
///
/// `extra` is spread FIRST, so the protocol's own names always win — an endpoint field
/// called `did` cannot displace the DID being proved. That ordering is the whole reason
/// this takes a `Value` rather than letting each caller assemble its own object.
pub fn body(did: &str, did_document: &Value, nonce: &str, extra: Option<Value>) -> Result<Vec<u8>> {
    let mut fields = match extra {
        Some(Value::Object(map)) => map,
        Some(other) => return Err(anyhow!("the endpoint's extra fields are not an object: {other}")),
        None => serde_json::Map::new(),
    };
    fields.insert("nonce".to_string(), Value::String(nonce.to_string()));
    fields.insert("did".to_string(), Value::String(did.to_string()));
    fields.insert("didDocument".to_string(), did_document.clone());
    Ok(serde_json::to_vec(&Value::Object(fields))?)
}

/// Sign one request over the exact body bytes, with the identity's binding key.
///
/// `document` is what the peer will verify against, and it is also what names the
/// credential: the DID document keeps key-1 in its `authentication`, so a signature made
/// under `{did}#key-1` is one the document authorizes.
///
/// `body` is `None` for a request that carries no body at all — then no `content-digest`
/// is signed, and a peer that requires one will refuse. Every ANP-02 body here is a JSON
/// object, so in practice it is always `Some`.
pub fn sign_headers(
    document: &Value,
    url: &str,
    method: &str,
    key: &PrivateKeyMaterial,
    keyid: &str,
    body: Option<&[u8]>,
) -> Result<BTreeMap<String, String>> {
    generate_http_signature_headers(
        document,
        url,
        method,
        key,
        None,
        body,
        HttpSignatureOptions {
            keyid: Some(keyid.to_string()),
            ..Default::default()
        },
    )
    .map_err(|err| anyhow!("signing the ANP-02 request: {err}"))
}

/// The whole request as a JSON object, in the shape `anp sign` prints it.
pub fn signed_request_json(
    did: &str,
    keyid: &str,
    document: &Value,
    body: &[u8],
    headers: &BTreeMap<String, String>,
) -> Result<Value> {
    Ok(json!({
        "did": did,
        "keyid": keyid,
        "didDocument": document,
        "body": String::from_utf8(body.to_vec()).context("the signed body is not UTF-8")?,
        "headers": headers,
    }))
}

/// The headers as a `HeaderMap`, plus the JSON content type the body obliges.
pub fn header_map(headers: &BTreeMap<String, String>) -> Result<reqwest::header::HeaderMap> {
    let mut map = reqwest::header::HeaderMap::new();
    map.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    for (name, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("{name} is not a header name"))?;
        let value =
            reqwest::header::HeaderValue::from_str(value).with_context(|| format!("{name} has a value that cannot go on the wire"))?;
        map.insert(name, value);
    }
    Ok(map)
}

/// How many times one request is signed: the first attempt, and one answer to a 401 challenge.
///
/// A challenge exists so a server can hand out its own nonce first, and it is answered once — a
/// peer that challenges a second time is not asking for a nonce, it is refusing.
pub const MAX_ATTEMPTS: usize = 2;

/// One signed ANP-02 request: the identity that signs it, and where it goes.
///
/// A struct rather than the seven parameters it carries, because those seven are one thing — the
/// body and the signature are made from exactly these — and a call site that could transpose the
/// document and the key would be a call site that signs as somebody else.
pub struct SignedPost<'a> {
    /// The DID the request proves. It goes in the body, and `keyid` names a key of it.
    pub did: &'a str,
    /// The document the peer verifies against — and the one whose `authentication` makes
    /// `keyid` a key this identity is allowed to sign with.
    pub document: &'a Value,
    /// Who signs it: a key in this process, or `anpio-key` holding one.
    pub signer: &'a Signer,
    /// `{did}#key-1`, the credential the signature is made under. A hint for the local
    /// signer; `anpio-key` picks the key and reports it in `Signature-Input`.
    pub keyid: &'a str,
    /// The full target URL. It is what the signature covers (`@target-uri`, `@authority`), so
    /// it is not decoration: a request signed for one target is not valid at another.
    pub target: &'a str,
    /// The server's one-time nonce, or empty to accept a 401 challenge.
    pub nonce: &'a str,
    /// The endpoint's own body fields, spread beneath the protocol's three names.
    pub extra: Option<Value>,
}

/// A request that went out, and the answer to it.
#[derive(Debug)]
pub struct Posted {
    pub response: reqwest::Response,
    /// The nonce the accepted attempt was signed with — the challenge's, when one was answered.
    /// Reported because the nonce is what the peer will remember; a caller logging the request
    /// should log the one that was actually signed.
    pub nonce: String,
}

/// Why no answer came back.
///
/// The two arms exist because one of them settles a question and the other does not. Nothing
/// sent means the peer cannot have acted on the request — the staged key of an update hop has
/// no identity to belong to. Anything else leaves open that the peer accepted it and only the
/// answer was lost, which is the case where a key must be kept. A single `anyhow::Error` could
/// not carry that difference, and [`crate::identity::update`] decides with it.
#[derive(Debug, thiserror::Error)]
pub enum PostError {
    /// Nothing left the process: the target was not a URL, the body or the signature could not
    /// be built, the headers could not go on the wire.
    #[error("{0:#}")]
    NotSent(anyhow::Error),
    /// The request was sent and the answer never arrived: a dropped connection, a timeout.
    #[error("{0:#}")]
    Unanswered(anyhow::Error),
}

impl PostError {
    pub fn into_error(self) -> anyhow::Error {
        match self {
            PostError::NotSent(err) | PostError::Unanswered(err) => err,
        }
    }
}

/// Sign one ANP-02 request, POST it, and answer a 401 challenge once.
///
/// The one place a signed request goes on the wire. A login and an update hop differ in what
/// they put in the body and in what they make of the answer; they do not differ in how the
/// request is signed, sent, or challenged — and the version of this that was copied per caller
/// is how one of them ends up signing a body the other would refuse.
///
/// The response comes back whatever its status: only the callers know what `409` or `403` means
/// for the request they made. The 401 is the exception, because retrying it is part of sending
/// rather than of interpreting — and it is answered only when the challenge names a nonce we
/// are not already using, since a server that challenges with the nonce we sent is refusing.
pub async fn post_signed(
    client: &reqwest::Client,
    post: &SignedPost<'_>,
) -> std::result::Result<Posted, PostError> {
    let url = reqwest::Url::parse(post.target)
        .map_err(|err| PostError::NotSent(anyhow!("{0} is not a URL: {err}", post.target)))?;
    let mut nonce = post.nonce.to_string();

    for attempt in 0..MAX_ATTEMPTS {
        // The bytes that are signed ARE the bytes that are sent: the digest covers this exact
        // vector, so building a second one for the transport would be a chance to sign one body
        // and deliver another.
        let body = body(post.did, post.document, &nonce, post.extra.clone()).map_err(PostError::NotSent)?;
        let headers = post
            .signer
            .sign_headers(
                post.did,
                post.document,
                post.target,
                "POST",
                post.keyid,
                Some(&body),
                (!nonce.is_empty()).then_some(nonce.as_str()),
            )
            .map_err(PostError::NotSent)?;

        let response = client
            .post(url.clone())
            .headers(header_map(&headers).map_err(PostError::NotSent)?)
            .body(body)
            .send()
            .await
            .map_err(|err| PostError::Unanswered(anyhow!("POST {}: {err}", post.target)))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED && attempt + 1 < MAX_ATTEMPTS {
            let challenged = nonce_from_challenge(
                response
                    .headers()
                    .get("www-authenticate")
                    .and_then(|value| value.to_str().ok()),
            );
            match challenged {
                Some(next) if next != nonce => {
                    nonce = next;
                    continue;
                }
                _ => {}
            }
        }
        return Ok(Posted { response, nonce });
    }

    // Unreachable while `MAX_ATTEMPTS` is 2 and the only `continue` above is guarded by
    // `attempt + 1 < MAX_ATTEMPTS`; kept as a definite answer rather than a panic.
    Err(PostError::NotSent(anyhow!(
        "the peer at {} refused every attempt",
        post.target
    )))
}

/// Refuse a 2xx that came back as a web page.
///
/// A 2xx is not by itself an answer from an ANP server, and nothing about the acceptance is
/// read back from one — so a page that answers 200 would be reported as a delivered
/// request. The likely cause is a target aimed at a site origin instead of at the
/// endpoint, which is the mistake a caller cannot detect afterwards. Only HTML is refused:
/// a real peer's body is genuinely optional or opaque, so requiring a shape would break
/// servers that omit it.
pub fn assert_not_web_page(response: &reqwest::Response, target: &str) -> Result<()> {
    let mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if mime != "text/html" && mime != "application/xhtml+xml" {
        return Ok(());
    }
    Err(anyhow!(
        "invalid_argument: {target} answered {} {mime}: that is a web page, not an ANP endpoint",
        response.status()
    ))
}

/// The `nonce` out of a `WWW-Authenticate` challenge, if it names one.
///
/// A deliberate subset of RFC 9110's `param=value` list: the scheme is skipped, and the
/// parameters are split on commas outside quotes. That is the whole contract here — the
/// nonce is the only parameter this client acts on, so parsing the rest would be inventing
/// work.
pub fn nonce_from_challenge(header: Option<&str>) -> Option<String> {
    let text = header?.trim();
    let space = text.find(char::is_whitespace)?;
    let params = &text[space + 1..];
    for param in split_params(params) {
        let (name, value) = param.split_once('=')?;
        if name.trim().eq_ignore_ascii_case("nonce") {
            let value = unquote(value.trim());
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Split `a="1,2", b=3` on the commas that are not inside quotes.
fn split_params(params: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in params.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            ',' if !quoted => {
                parts.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    parts.push(current);
    parts
}

fn unquote(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_protocol_names_win_over_the_endpoints_own_fields() {
        let document = json!({"id": "did:wba:h:user:alice:e1_x"});
        // An endpoint that ships a field called `did` must not be able to displace the DID
        // being proved — that would sign one identity and claim another.
        let bytes = body(
            "did:wba:h:user:alice:e1_x",
            &document,
            "n-1",
            Some(json!({"did": "did:wba:h:user:mallory:e1_y", "handle": "alice"})),
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["did"], "did:wba:h:user:alice:e1_x");
        assert_eq!(parsed["nonce"], "n-1");
        assert_eq!(parsed["handle"], "alice");
        assert_eq!(parsed["didDocument"], document);
    }

    #[test]
    fn extra_fields_have_to_be_an_object() {
        let document = json!({});
        assert!(body("did:wba:h:u:a:e1_x", &document, "n", Some(json!([1]))).is_err());
    }

    #[test]
    fn a_challenge_nonce_is_read_quoted_or_bare() {
        assert_eq!(
            nonce_from_challenge(Some("ANP realm=\"did\", nonce=\"abc123\"")).as_deref(),
            Some("abc123")
        );
        assert_eq!(nonce_from_challenge(Some("ANP nonce=abc123")).as_deref(), Some("abc123"));
        // A quoted value may contain a comma; splitting on every comma would truncate it.
        assert_eq!(
            nonce_from_challenge(Some("ANP realm=\"a,b\", nonce=\"x,y\"")).as_deref(),
            Some("x,y")
        );
    }

    #[test]
    fn a_challenge_with_no_nonce_is_not_one() {
        assert_eq!(nonce_from_challenge(None), None);
        assert_eq!(nonce_from_challenge(Some("")), None);
        assert_eq!(nonce_from_challenge(Some("ANP realm=\"did\"")), None);
        assert_eq!(nonce_from_challenge(Some("ANP nonce=\"\"")), None);
        // A scheme with no parameters at all: there is no space to split on.
        assert_eq!(nonce_from_challenge(Some("ANP")), None);
    }

    /// The classifier `did update` decides a staged key's fate with. A target that is not a URL
    /// is refused before anything is signed, and that is the difference between "the server
    /// said no" (nothing was sent) and "we do not know what the server did".
    #[tokio::test]
    async fn a_target_that_is_not_a_url_never_leaves_the_process() {
        let identity = crate::identity::test_support::mint("alice");
        let key = crate::identity::load_stored_key(&identity.keys["key-1"]).unwrap();
        let signer = Signer::Local(key);
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let err = post_signed(
            &client,
            &SignedPost {
                did: &identity.did,
                document: &identity.did_document,
                signer: &signer,
                keyid: &format!("{}#key-1", identity.did),
                target: "not a url",
                nonce: "",
                extra: None,
            },
        )
        .await
        .expect_err("a target that is not a URL must be refused");
        assert!(matches!(err, PostError::NotSent(_)), "got {err:?}");
    }
}
