//! The ANP application layer: what an identity signs with, and what it is called.
//!
//! `did` is the pair of commands that talk to the server that *hosts* the DID. This module
//! is the other end of the same identity: the credential a relying party is asked to
//! accept (`anp sign`), and the view from there (`anp show`) — where the stable subject and
//! the current wire credential are two different names, which is exactly what a `did
//! update` hop moves between.
//!
//! [`request`] is the shared half: one ANP-02 body and one RFC 9421 signature over it,
//! used here and by `identity::update`'s hop delivery, so the bytes that are signed are
//! built in exactly one place.

pub mod request;

use anp::PrivateKeyMaterial;
use anyhow::Result;
use serde_json::Value;

use crate::identity::Identity;

pub use request::{
    assert_not_web_page, body, header_map, nonce_from_challenge, sign_headers, signed_request_json,
};

/// Sign one ANP-02 request for `identity`, and return it in the shape `anp sign` prints.
///
/// No network: this is what a login *would* put on the wire, which is what makes it the
/// tool for checking a target's contract (or a peer's) without sending anything. The body
/// is ANP-02's own three fields and nothing else — a login carries no application payload,
/// because what is being proved is the identity, not a message.
pub fn sign(
    identity: &Identity,
    key: &PrivateKeyMaterial,
    target: &str,
    method: &str,
    nonce: &str,
) -> Result<Value> {
    let keyid = format!("{}#key-1", identity.did);
    let body = body(&identity.did, &identity.did_document, nonce, None)?;
    let headers = sign_headers(&identity.did_document, target, method, key, &keyid, Some(&body))?;
    signed_request_json(&identity.did, &keyid, &identity.did_document, &body, &headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_support::mint;

    #[test]
    fn a_signed_request_carries_the_body_its_signature_covers() {
        let identity = mint("alice");
        let key = crate::identity::load_stored_key(&identity.keys["key-1"]).unwrap();
        let signed = sign(&identity, &key, "https://site.example/api/anp/verify", "POST", "n-7").unwrap();

        let body: Value = serde_json::from_str(signed["body"].as_str().unwrap()).unwrap();
        assert_eq!(body["did"], identity.did);
        assert_eq!(body["nonce"], "n-7");
        assert_eq!(body["didDocument"]["id"], identity.did);

        let headers = signed["headers"].as_object().unwrap();
        assert_eq!(signed["did"], identity.did);
        assert_eq!(signed["keyid"], format!("{}#key-1", identity.did));
        // The crate spells these in their RFC 9421 title case; the names are what a peer
        // matches on, so a rename here would be a rename on the wire.
        for name in ["Signature-Input", "Signature", "Content-Digest"] {
            assert!(headers.contains_key(name), "missing {name}");
        }
        // The keyid the credential is made under, and the authority the signature covers:
        // both are read off the signature-input line, so a mismatch with the target would
        // be visible here rather than only at the peer.
        let input = headers["Signature-Input"].as_str().unwrap();
        assert!(input.contains(&format!("keyid=\"{}\"", signed["keyid"].as_str().unwrap())));
        assert!(input.contains("@authority"));
        assert!(input.contains("content-digest"));
    }

    /// The command's output is only a credential if a verifier accepts it, so the test
    /// checks it the way a peer would: hand the printed body and headers to the crate's own
    /// verifier and require a pass. A signature that round-trips through `sign` alone would
    /// prove nothing — both ends would be mine.
    #[test]
    fn what_the_command_signs_the_crate_itself_verifies() {
        use anp::authentication::http_signatures::verify_http_message_signature;
        use std::collections::BTreeMap;

        let identity = mint("alice");
        let key = crate::identity::load_stored_key(&identity.keys["key-1"]).unwrap();
        let target = "https://site.example/api/anp/verify";
        let signed = sign(&identity, &key, target, "POST", "n-7").unwrap();

        let headers: BTreeMap<String, String> = signed["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_string()))
            .collect();
        let body = signed["body"].as_str().unwrap().as_bytes();

        verify_http_message_signature(&identity.did_document, "POST", target, &headers, Some(body))
            .expect("the crate refuses the signature this command printed");
    }
}
