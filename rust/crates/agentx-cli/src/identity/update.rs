//! `did update` — the write half of the `did` pair: moving a DID to a successor key.
//!
//! What a hop **is** — that the retiring document is the one on file plus `deactivated` and
//! `successorDid`, that key-1 signs it, that the successor keeps the stable subject path —
//! is `anp`'s and [`super::did`]'s business. Where to deliver it is not: ANP-03 §2.5.3
//! defines no management interface, so `--target` names the DID server's own endpoint and
//! this module only speaks to it.
//!
//! The delivery is a plain ANP-02 request — `nonce` / `did` / `didDocument` — plus
//! `successorDid` / `successorDocument`, signed with the HTTP message signature machinery a
//! login uses, so a server can check it with what it already has. The two documents go
//! **inside** the body, under the content digest: a hop editable in flight would let a proxy
//! point the retirement at a successor of its own choosing, which is the one thing the proof
//! must not allow.
//!
//! No 409 retry, unlike `login`: this request is signed with the very DID it retires, so "that
//! DID is superseded" means the caller's premise is wrong. Resolve the chain first rather than
//! have this client guess at a predecessor whose key it may not even hold.
//!
//! The **keep-or-drop** question is why [`UpdateError`] has two arms. A failure that proves
//! the hop was never delivered says the staged key has no identity to belong to; anything
//! else leaves open the possibility that the server accepted the hop and only the answer was
//! lost — and then that staged file is the sole copy of the key the DID has moved to.

use std::collections::BTreeMap;

use anp::PrivateKeyMaterial;
use anyhow::{anyhow, Result};
use reqwest::Url;
use serde_json::{json, Value};

use crate::anp::request as anp_request;
use crate::message::resolve::{assert_allowed_host, ResolvePolicy};

/// What the DID server's acceptance amounts to.
///
/// `successor_did` is what was **asked for**, not something read back: §2.5.3 defines no
/// response body, so anything parsed out of one would be invention. The server is the
/// authority on whether the successor is now current, and `did update` says so and points at
/// `did resolve --chain` rather than implying a confirmation it never got.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub retiring_did: String,
    pub successor_did: String,
    pub accepted_by: String,
}

/// A delivery failure, split by what it says about the world.
///
/// The split is the whole reason this is a type and not an `anyhow::Error`: the caller's next
/// move — keep the staged successor key, or drop it — is decided by which arm it gets, and a
/// string could not carry that.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// Nothing was sent (a local refusal) or the server answered with an error status. The
    /// hop is settled as NOT delivered, so a staged key has nothing to belong to.
    #[error("{0:#}")]
    Settled(anyhow::Error),
    /// The delivery did not complete, and whether the server accepted it is not knowable
    /// from here: a connection that dropped, a timeout, a body that could not be read. The
    /// server may well have accepted the hop.
    #[error("{0:#}")]
    Ambiguous(anyhow::Error),
}

impl UpdateError {
    /// The failure, as an ordinary command failure.
    pub fn into_error(self) -> anyhow::Error {
        match self {
            UpdateError::Settled(err) | UpdateError::Ambiguous(err) => err,
        }
    }
}

/// How many times one hop is signed: the first attempt, and one answer to a 401 challenge.
///
/// A challenge exists so a server can hand out its own nonce first, and it is answered once
/// — a peer that challenges a second time is not asking for a nonce, it is refusing.
const MAX_ATTEMPTS: usize = 2;

/// One update hop: the two documents and the key that signs them.
///
/// A struct rather than five parameters because the five are one thing — a hop is only
/// meaningful whole, and a call site that could transpose the retirement and successor
/// documents would be a call site that could retire the wrong document.
pub struct Hop<'a> {
    pub retiring_did: &'a str,
    pub retirement_document: &'a Value,
    pub successor_did: &'a str,
    pub successor_document: &'a Value,
    /// The retiring DID's key-1 — the only key that can deliver this hop, and the one whose
    /// fingerprint the DID embeds (§2.5.3 L413).
    pub key1: &'a PrivateKeyMaterial,
}

/// Deliver one update hop to `target`.
pub async fn deliver(
    client: &reqwest::Client,
    target: &str,
    policy: &ResolvePolicy,
    hop: &Hop<'_>,
) -> std::result::Result<Accepted, UpdateError> {
    let url = Url::parse(target)
        .map_err(|err| UpdateError::Settled(anyhow!("--target must be a URL: {err}")))?;
    // Before anything is signed: a hop is not sent to a host the policy has not seen, and a
    // hop is the one request whose body a proxy must not be free to rewrite.
    assert_allowed_host(&url, policy, "the DID server's update endpoint")
        .map_err(|err| UpdateError::Settled(err.into()))?;

    let keyid = format!("{}#key-1", hop.retiring_did);
    let mut nonce = String::new();

    for attempt in 0..MAX_ATTEMPTS {
        // The bytes that are signed ARE the bytes that are sent — the digest covers this
        // exact vector, so building a second one for the transport would be a chance to
        // sign one body and deliver another.
        let body = request_body(
            hop.retiring_did,
            hop.retirement_document,
            hop.successor_did,
            hop.successor_document,
            &nonce,
        )
        .map_err(UpdateError::Settled)?;
        let headers = signature_headers(hop.retirement_document, url.as_str(), &body, hop.key1, &keyid)
            .map_err(UpdateError::Settled)?;

        let response = client
            .post(url.clone())
            .headers(anp_request::header_map(&headers).map_err(UpdateError::Settled)?)
            .body(body)
            .send()
            .await
            .map_err(|err| UpdateError::Ambiguous(anyhow!("POST {target}: {err}")))?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED && attempt + 1 < MAX_ATTEMPTS {
            // A challenge is worth exactly one answer, and only when it names a nonce we are
            // not already using: a server that challenges with the nonce we sent is refusing,
            // not asking.
            let challenged = anp_request::nonce_from_challenge(
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

        if status.is_success() {
            anp_request::assert_not_web_page(&response, target).map_err(UpdateError::Settled)?;
            return Ok(Accepted {
                retiring_did: hop.retiring_did.to_string(),
                successor_did: hop.successor_did.to_string(),
                accepted_by: target.to_string(),
            });
        }
        // The server answered, and its answer was no. Settled by definition — this is the
        // `update_failed` of the TS client, and the arm that lets a staged key be dropped.
        return Err(UpdateError::Settled(anyhow!(
            "update_failed: the DID server at {target} answered HTTP {status}"
        )));
    }

    // Unreachable while `MAX_ATTEMPTS` is 2 and the only `continue` above is guarded by
    // `attempt + 1 < MAX_ATTEMPTS`; kept as a definite answer rather than a panic.
    Err(UpdateError::Settled(anyhow!(
        "update_failed: the DID server at {target} refused every attempt"
    )))
}

/// The delivery body: a plain ANP-02 request, plus the two documents the hop is about.
///
/// The two documents are the hop's own fields — they are what makes this request an update
/// rather than a login — while the protocol's three names come from
/// [`anp_request::body`], which is the one place that builds an ANP-02 body.
pub fn request_body(
    retiring_did: &str,
    retirement_document: &Value,
    successor_did: &str,
    successor_document: &Value,
    nonce: &str,
) -> Result<Vec<u8>> {
    anp_request::body(
        retiring_did,
        retirement_document,
        nonce,
        Some(json!({
            "successorDid": successor_did,
            "successorDocument": successor_document,
        })),
    )
}

/// Sign one request over the exact body bytes, with the retiring DID's key-1.
///
/// `retirement_document` is what the peer will verify against — it is in the body, and it
/// keeps key-1 in its `authentication` (a deactivated predecessor MUST retain its binding
/// key, or the hop is unverifiable), so it is also what names the credential.
pub fn signature_headers(
    retirement_document: &Value,
    url: &str,
    body: &[u8],
    key1: &PrivateKeyMaterial,
    keyid: &str,
) -> Result<BTreeMap<String, String>> {
    anp_request::sign_headers(retirement_document, url, "POST", key1, keyid, Some(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_carries_the_two_documents_inside_it() {
        let retirement = json!({"id": "did:wba:h:user:alice:e1_old", "deactivated": true});
        let successor = json!({"id": "did:wba:h:user:alice:e1_new"});
        let body = request_body(
            "did:wba:h:user:alice:e1_old",
            &retirement,
            "did:wba:h:user:alice:e1_new",
            &successor,
            "n-1",
        )
        .unwrap();
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        // Both documents inside the body, under the content digest — a hop a proxy could
        // edit would be a hop a proxy could point somewhere else.
        assert_eq!(parsed["didDocument"]["deactivated"], true);
        assert_eq!(parsed["successorDocument"]["id"], successor["id"]);
        assert_eq!(parsed["did"], "did:wba:h:user:alice:e1_old");
        assert_eq!(parsed["successorDid"], "did:wba:h:user:alice:e1_new");
        assert_eq!(parsed["nonce"], "n-1");
    }

    #[test]
    fn the_two_failure_arms_are_told_apart_by_their_type() {
        let settled = UpdateError::Settled(anyhow!("update_failed: HTTP 400"));
        let ambiguous = UpdateError::Ambiguous(anyhow!("connection reset"));
        assert!(matches!(settled, UpdateError::Settled(_)));
        assert!(matches!(ambiguous, UpdateError::Ambiguous(_)));
        assert!(settled.into_error().to_string().contains("update_failed"));
        assert!(ambiguous.into_error().to_string().contains("connection reset"));
    }
}
