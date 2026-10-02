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
}
