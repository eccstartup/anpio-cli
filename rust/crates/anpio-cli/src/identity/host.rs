//! Talking to the DID host.
//!
//! The identity is published to a real awiki host (TODO5 §0.1 #7 / §8-J) — the same route
//! the TS CLI takes, with the host on this machine. Three things live here: read the host's
//! own service DID document (so the identity's document can advertise the service the host
//! will accept), publish a document (`register` the first time, `update_document` after),
//! and read/write the host's user profile (the nickname and blurb a chat client shows).
//!
//! **Two kinds of request go out from this module and they authenticate differently.**
//! `register` carries the signed document itself and needs no credential. Everything else —
//! `update_document`, and the whole profile surface — is the host's *own* control plane,
//! which authenticates with the bearer token `register` handed back (`current_did(request)`
//! on the host side). That is the one place in this client where a stored token is read
//! back, and it is not a substitute for the ANP origin proof anywhere else: the message and
//! group families still sign, because that is what those methods accept.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Url;
use serde_json::{json, Value};

use super::store::Identity;

/// The awiki JSON-RPC paths. The first is what its own client uses; the second is an
/// alias the server keeps. The profile surface is a separate path with its own method set
/// (`get_me` / `update_me`), which is why the nickname lives there and not under `did-auth`.
const DID_AUTH_PATH: &str = "/user-service/v1/did-auth/rpc";

/// The client version every user-service call carries. awiki.ai answers
/// `-32004 client.upgrade_required` when the header is missing, and its grammar only
/// knows three product names — `awiki-me`, `awiki-cli`, `awiki-daemon` — so a client
/// that is not one of them presents itself as the CLI-shaped one. The value is the
/// minimum awiki.ai currently accepts (the same one `anpio-extension` sends); bump it
/// when the service raises the bar, or every call starts being refused again.
const CLIENT_VERSION: &str = "awiki-cli/0815/1.0.58";
const PROFILE_PATH: &str = "/user-service/v1/did/profile/rpc";
/// The credential-free view of a profile, by DID. See [`fetch_public_profile`].
const PUBLIC_PROFILE_PATH: &str = "/user-service/v1/users";
/// The handle precheck: JSON-RPC `registration_check`, which says whether a handle is free
/// before a key is minted for it.
const HANDLE_RPC_PATH: &str = "/user-service/v1/handle/rpc";
/// The registration email round trip. Both are unauthenticated: the address is the
/// evidence, and no DID exists yet.
const EMAIL_STATUS_PATH: &str = "/user-service/v1/auth/email-status";
const EMAIL_SEND_PATH: &str = "/user-service/v1/auth/email-send";

/// What the host's precheck said about a candidate handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleDecision {
    /// Free: register it.
    Register,
    /// Already registered to someone (possibly to the caller, which the host cannot see).
    Existing,
    /// Reserved or otherwise not registrable.
    Unavailable,
}

/// A precheck answer, plus the host's own spelling of the full handle.
#[derive(Debug, Clone)]
pub struct HandleCheck {
    pub decision: HandleDecision,
    /// The handle as the host spells it (`mybot.awiki.me`) — what the email calls use.
    pub full_handle: Option<String>,
    /// Whatever the host said about why, when it said anything.
    pub reason: Option<String>,
}

/// Ask the host whether a handle can be registered.
///
/// `Ok(None)` means the host has no `registration_check` endpoint — it predates the
/// precheck, and the caller says so and goes on to register rather than pretending the
/// name was checked. Anything else that is not a well-formed answer is an error: a
/// precheck whose reply cannot be understood must not silently pass.
pub async fn check_handle(
    client: &reqwest::Client,
    base: &Url,
    handle: &str,
    domain: &str,
) -> Result<Option<HandleCheck>> {
    let url = base
        .join(HANDLE_RPC_PATH)
        .with_context(|| format!("{base} cannot serve {HANDLE_RPC_PATH}"))?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": "registration-check",
        "method": "registration_check",
        "params": {"handle": handle, "domain": domain, "check_invite": false},
    });
    let response = client
        .post(url.clone())
        .header("x-awiki-client-version", CLIENT_VERSION)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;

    // 404/405 is the whole story for a host that never had this route.
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED
    {
        return Ok(None);
    }
    let envelope: Value = match serde_json::from_str(&text) {
        Ok(envelope) => envelope,
        Err(_) => {
            bail!("POST {url} failed: HTTP {status}: {}", snippet(&text));
        }
    };
    if let Some(error) = error_object(&envelope) {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        // -32601 is JSON-RPC's "method not found"; a host that kept the route but not the
        // method is in the same place as one that never had it.
        if code == -32601 || named_error(error) == Some("method_not_found") {
            return Ok(None);
        }
        bail!("registration_check refused: {}", describe_error(error));
    }
    let result = envelope.get("result").ok_or_else(|| {
        anyhow!(
            "POST {url} answered neither result nor error: {}",
            snippet(&text)
        )
    })?;
    let decision = match result.get("decision").and_then(Value::as_str) {
        Some("register") => HandleDecision::Register,
        Some("existing") => HandleDecision::Existing,
        Some("unavailable") => HandleDecision::Unavailable,
        other => bail!(
            "registration_check answered with an unknown decision {:?}: {}",
            other,
            snippet(&text)
        ),
    };
    Ok(Some(HandleCheck {
        decision,
        full_handle: result
            .get("full_handle")
            .and_then(Value::as_str)
            .map(str::to_string),
        reason: result
            .get("reason")
            .or_else(|| result.get("message"))
            .and_then(Value::as_str)
            .map(str::to_string),
    }))
}

/// Whether the address is already verified for this handle.
pub async fn email_verified(
    client: &reqwest::Client,
    base: &Url,
    email: &str,
    handle: &str,
) -> Result<bool> {
    let url = base
        .join(EMAIL_STATUS_PATH)
        .with_context(|| format!("{base} cannot serve {EMAIL_STATUS_PATH}"))?;
    let response = client
        .get(url.clone())
        .header("x-awiki-client-version", CLIENT_VERSION)
        .query(&[("email", normalize_email(email)), ("handle", handle.to_string())])
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;
    if !status.is_success() {
        bail!("GET {url} failed: HTTP {status}: {}", snippet(&text));
    }
    let value: Value =
        serde_json::from_str(&text).with_context(|| format!("{url} did not return JSON"))?;
    // The version gate answers HTTP 200 with an error body, so a plain status check would
    // read the refusal as "not verified" and poll until the deadline.
    if let Some(error) = error_object(&value) {
        bail!("email-status refused: {}", describe_error(error));
    }
    // No `verified` field is a reply this client does not understand — reporting it as
    // `false` is what turned a protocol error into a silent five-minute timeout.
    match value.get("verified").and_then(Value::as_bool) {
        Some(verified) => Ok(verified),
        None => bail!("{url} answered without a `verified` field: {}", snippet(&text)),
    }
}

/// Ask the host to send the verification email.
pub async fn send_verification_email(
    client: &reqwest::Client,
    base: &Url,
    email: &str,
    handle: &str,
) -> Result<()> {
    let url = base
        .join(EMAIL_SEND_PATH)
        .with_context(|| format!("{base} cannot serve {EMAIL_SEND_PATH}"))?;
    let response = client
        .post(url.clone())
        .header("x-awiki-client-version", CLIENT_VERSION)
        .json(&json!({"email": normalize_email(email), "handle": handle}))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;
    if !status.is_success() {
        bail!("POST {url} failed: HTTP {status}: {}", snippet(&text));
    }
    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        if let Some(error) = error_object(&value) {
            bail!("email-send refused: {}", describe_error(error));
        }
    }
    Ok(())
}

/// Poll the verification status until it flips or the deadline passes.
///
/// `Ok(false)` is a timeout, not an error: the address may be verified after this command
/// has returned, and the caller says how to resume.
pub async fn wait_for_email(
    client: &reqwest::Client,
    base: &Url,
    email: &str,
    handle: &str,
    timeout: std::time::Duration,
    interval: std::time::Duration,
) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if email_verified(client, base, email, handle).await? {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(interval).await;
    }
}

fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}


/// What the host says about itself, read from its `/.well-known/did.json`.
pub struct HostService {
    /// The host's own DID — the `serviceDid` an identity's document must name.
    pub service_did: String,
    /// The DID authority an identity's DID hangs under: the segment after `did:wba:` in
    /// the host's own DID (`localhost%3A8000`).
    pub authority: String,
    /// The ANP message endpoint an identity's document must advertise.
    pub service_endpoint: String,
}

/// Read the host's service DID document.
///
/// The identity's document must advertise the host's *own* message service: the awiki
/// host checks the endpoint and `serviceDid` against its configuration and refuses a
/// peer-declared one unless a switch that is off by default is turned on (TODO5 §8-J).
/// Reading them off the host beats re-deriving its settings here.
pub async fn fetch_host_service(client: &reqwest::Client, base: &Url) -> Result<HostService> {
    let url = base
        .join("/.well-known/did.json")
        .with_context(|| format!("{base} cannot serve /.well-known/did.json"))?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;
    if !status.is_success() {
        bail!("GET {url} failed: HTTP {status}: {}", snippet(&text));
    }
    let document: Value =
        serde_json::from_str(&text).with_context(|| format!("{url} did not return JSON"))?;

    let service_did = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the host's DID document has no id"))?
        .to_string();
    let authority = service_did
        .strip_prefix("did:wba:")
        .ok_or_else(|| anyhow!("the host's DID is not a did:wba DID: {service_did}"))?
        .to_string();
    let service_endpoint = document
        .get("service")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("type").and_then(Value::as_str) == Some("ANPMessageService"))
        })
        .and_then(|service| service.get("serviceEndpoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the host's DID document names no ANPMessageService endpoint"))?
        .to_string();

    Ok(HostService {
        service_did,
        authority,
        service_endpoint,
    })
}

/// One JSON-RPC call to the host's own surface: post it, unwrap the envelope, hand back
/// the `result`.
///
/// `token`, when given, becomes the `Authorization` header. It is a **bearer** credential
/// and not an ANP origin proof — see the module header for why both exist and which calls
/// want which.
///
/// The error branch is here rather than in each caller because it is the same envelope
/// every time, and a refusal from this host is a well-formed answer whose `message` is the
/// only useful part; dropping it would leave "the host refused" and nothing to act on.
async fn call(
    client: &reqwest::Client,
    base: &Url,
    path: &str,
    method: &str,
    params: Value,
    token: Option<&str>,
) -> Result<Value> {
    let url = base
        .join(path)
        .with_context(|| format!("{base} cannot serve {path}"))?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": format!("anpio-cli-{method}-{}", std::process::id()),
        "method": method,
        "params": params,
    });
    let mut request = client
        .post(url.clone())
        .header("x-awiki-client-version", CLIENT_VERSION)
        .json(&body);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;

    // A non-2xx is not always a bare HTTP error: the host raises its typed errors as status
    // codes *and* a JSON-RPC body, so the body is worth reading before falling back to the
    // status. Only when it is not JSON does the status stand alone.
    if let Ok(envelope) = serde_json::from_str::<Value>(&text) {
        if let Some(error) = error_object(&envelope) {
            return Err(anyhow!("{method} refused: {}", describe_error(error)));
        }
        if let Some(result) = envelope.get("result") {
            return Ok(result.clone());
        }
    }
    if !status.is_success() {
        bail!("POST {url} failed: HTTP {status}: {}", snippet(&text));
    }
    bail!("{method}: the host's reply carried neither result nor error: {}", snippet(&text))
}

/// What the host said when it accepted a document, and the credential that came with it.
pub struct Issued {
    /// The bearer token `register` returned. `update_document` does not issue a new one, so
    /// this is `None` there and a caller keeps whatever it already had.
    pub token: Option<String>,
    pub token_type: Option<String>,
    /// The `result` object as it came, for a caller that wants a field this struct does not
    /// name (`document_version`, `state`, …).
    pub result: Value,
}

impl Issued {
    fn from_result(result: Value) -> Self {
        // `register` answers with `access_token` on one shape and `token` on another (the
        // did-auth alias returns a narrower nine-field object) — the same credential under
        // two names, so both are read and neither is preferred for a reason a caller can see.
        let token = result
            .get("access_token")
            .or_else(|| result.get("token"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let token_type = result.get("token_type").and_then(Value::as_str).map(str::to_string);
        Self {
            token,
            token_type,
            result,
        }
    }
}

/// Publish the identity's document for the first time.
///
/// `register` is idempotent for a DID already on file only in the sense that it is refused
/// as a conflict — a re-register after a lost response needs `update_document`, which is
/// what `did publish` is for.
///
/// `email` is the address the handle is registered under. awiki.ai's production
/// registration is "one self-signed document + an email" (`anpio-extension`'s
/// `registerDidDocument` sends exactly these three fields), and a host that wants one
/// refuses the call without it; a host that does not care ignores the field. Sending it
/// is not verification — the `auth/email-status` / `auth/email-send` round trip is what
/// proves the address, and this client does not run it.
pub async fn register_identity(
    client: &reqwest::Client,
    base: &Url,
    identity: &Identity,
    email: Option<&str>,
) -> Result<Issued> {
    let mut params = json!({
        "handle": identity.handle,
        "did_document": identity.did_document,
    });
    if let Some(email) = email {
        params["email"] = Value::String(email.to_string());
    }
    let result = call(client, base, DID_AUTH_PATH, "register", params, None).await?;
    Ok(Issued::from_result(result))
}

/// Re-publish a document that changed, under the host's control plane.
///
/// `expected_document_hash` is the CAS: the host compares it against the SHA-256 of the
/// document it is **currently** serving and refuses with `did_document_changed` rather than
/// overwrite a change this client never saw. Passing the hash of what we last read is what
/// makes "publish my local document" safe to run twice.
pub async fn update_document(
    client: &reqwest::Client,
    base: &Url,
    token: &str,
    document: &Value,
    expected_document_hash: &str,
) -> Result<Issued> {
    let result = call(
        client,
        base,
        DID_AUTH_PATH,
        "update_document",
        json!({
            "document": document,
            "expected_document_hash": expected_document_hash,
        }),
        Some(token),
    )
    .await?;
    Ok(Issued::from_result(result))
}

/// The host's profile for the bearer token's DID — the nickname and blurb a chat client
/// shows, alongside the document and its version.
pub async fn fetch_profile(client: &reqwest::Client, base: &Url, token: &str) -> Result<Value> {
    call(client, base, PROFILE_PATH, "get_me", json!({}), Some(token)).await
}

/// Write profile fields and hand back the profile as the host now holds it.
///
/// The field set is the host's, not this client's, so the caller passes the names the host
/// knows (`display_name`, `avatar_uri`, `description`, `profile_uri`). Note that these are
/// **per DID**, not per group: the protocol has no per-membership nickname at all.
pub async fn update_profile(
    client: &reqwest::Client,
    base: &Url,
    token: &str,
    fields: Value,
) -> Result<Value> {
    call(client, base, PROFILE_PATH, "update_me", fields, Some(token)).await
}

/// The profile **anyone** can read, for a DID that is not ours — the escape hatch behind
/// `group members --names` (TODO6 §4.2 ①).
///
/// [`fetch_profile`] above is the host's control plane: it wants the bearer token `register`
/// handed out, and only the owner of the identity has one. Asking for a *peer's* name is not
/// an owner's request, so this is a different route with no credential at all: the DID in the
/// path, and the public view of the same profile — the name, avatar and blurb the peer chose
/// for itself.
///
/// Like `get_me`, this is **awiki's own surface, not ANP** (rust/README.md, `me show | set`):
/// the protocol has no nickname anywhere. A peer hosted elsewhere may well answer 404 or
/// nothing here, and that is a "no name for this member", not a failure of the caller.
pub async fn fetch_public_profile(client: &reqwest::Client, base: &Url, did: &str) -> Result<Value> {
    // The DID is **one** path segment, and it carries a percent-encoded port in its first
    // segment (`localhost%3A8765`). The server decodes what it receives, so sending `%3A`
    // through would hand it `localhost:8765` — a string that is not this DID, and one no row
    // is keyed by. Escaping the percent sign is what keeps the DID byte-identical end to end.
    let encoded = did.replace('%', "%25");
    let url = base
        .join(&format!("{PUBLIC_PROFILE_PATH}/{encoded}/profile"))
        .with_context(|| format!("{base} cannot serve {PUBLIC_PROFILE_PATH}"))?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;
    if !status.is_success() {
        bail!("GET {url} failed: HTTP {status}: {}", snippet(&text));
    }
    serde_json::from_str(&text).with_context(|| format!("{url} did not return JSON"))
}

/// The `sha256:<base64url>` digest the host computes over a stored document (RFC 8785 JSON
/// canonicalization, then SHA-256, base64url with no padding).
///
/// This is the CAS value `update_document` compares, so it has to be computed exactly the
/// way the host computes it — a hash that is merely "a hash of the document" would never
/// match and every publish would look like someone else's change.
pub fn document_hash(document: &Value) -> Result<String> {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha256};

    let canonical = serde_json_canonicalizer::to_vec(document)
        .map_err(|err| anyhow!("the document is not representable as canonical JSON: {err}"))?;
    let digest = Sha256::digest(&canonical);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    Ok(format!("sha256:{encoded}"))
}

/// The refusal in a JSON-RPC reply, when it carries one.
///
/// awiki's user-service writes the `error` key on **every** reply — `"error": null` when the
/// call succeeded. Presence alone therefore says nothing; only a non-null object is a
/// refusal, and treating the null as one failed every `did-auth` and handle call.
fn error_object(envelope: &Value) -> Option<&Value> {
    envelope.get("error").filter(|error| !error.is_null())
}

/// The host's typed name for a refusal: `did_document_changed`, `client.upgrade_required`,
/// …. That string, not the numeric code, is what a caller branches on and what a person
/// recognises; `awiki_code` is how the user-service names its upgrade gate.
fn named_error(error: &Value) -> Option<&str> {
    error
        .get("data")
        .and_then(|data| {
            data.get("type")
                .or_else(|| data.get("code"))
                .or_else(|| data.get("awiki_code"))
        })
        .and_then(Value::as_str)
}

/// One line for a refusal: the typed name when the host gave one, the JSON-RPC code, and
/// the message. The code is `0` only when the host omitted it, which is a fact worth seeing.
fn describe_error(error: &Value) -> String {
    let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the host gave no message");
    match named_error(error) {
        Some(named) => format!("{named} ({code}: {message})"),
        None => format!("{code}: {message}"),
    }
}

fn snippet(text: &str) -> String {
    let trimmed = text.trim();
    trimmed.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digests are computed by hand (Python `hashlib.sha256` + `urlsafe_b64encode`, no
    /// padding) over the canonical strings, which is the point: this test is a cross-check
    /// against a different implementation of both halves, not a restatement of the Rust.
    #[test]
    fn the_document_hash_is_sha256_of_the_canonical_form_base64url_unpadded() {
        assert_eq!(
            document_hash(&json!({})).unwrap(),
            "sha256:RBNvo1WzZ4oRRq0W9-hknpT7T8If536DEMBg9hyq_4o"
        );
        assert_eq!(
            document_hash(&json!({"id": "did:wba:x"})).unwrap(),
            "sha256:3Fb9G0G4yi5F5zaQX7SUlRrWxKJVzZavi1g8oEITC3Q"
        );
    }

    /// Canonicalization is not `to_string`: key order must not change the digest, or the CAS
    /// would fail on a document the host considers unchanged — which is exactly the bug this
    /// whole hash exists to avoid.
    #[test]
    fn key_order_does_not_change_the_digest_because_jcs_sorts_keys() {
        let sorted = serde_json::from_str::<Value>(r#"{"a":1,"b":2}"#).unwrap();
        let shuffled = serde_json::from_str::<Value>(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(
            document_hash(&sorted).unwrap(),
            "sha256:QyWM_3g_5wNtikMDP4MK38YOwDc4JHNUisdCuIgpJ3c"
        );
        assert_eq!(document_hash(&sorted).unwrap(), document_hash(&shuffled).unwrap());
    }
}
