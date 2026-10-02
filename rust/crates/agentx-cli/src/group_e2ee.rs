//! The wire half of P6: what a `group.e2ee.*` request body looks like.
//!
//! [`crate::mls`] makes and reads MLS objects; this module decides which of them goes into
//! which body. The split is the one `docs/design/cli.md` §1 draws and the service already
//! keeps (`packages/service/src/rpc/groupE2ee.ts` vs `groupControl.ts`): the thing that is
//! hard to get right is the *shape a service will accept*, and it is easier to check when it
//! is not interleaved with the crypto that produced the payload.
//!
//! Method names and Profiles are in [`crate::message`] with the rest of the wire vocabulary;
//! what is here is the policy that goes in the bodies.

use anp::group_e2ee::v2_models::V2GroupKeyPackage;
use serde_json::{Map, Value};

use crate::error::{AgentxError, Result};

/// The body of `group.e2ee.publish_key_package` (P6 §8.1.2).
///
/// Exactly one field, and it is the object itself — §8.1.2 names no others, and there is no
/// "batch" shape here the way P5's prekey bundle has one: a KeyPackage is published one
/// `key_package_id` at a time. The whole object goes, `did_wba_binding` and its proof
/// included, because §8.2.3 hands this same object to whoever later runs `group.e2ee.add`
/// (§9.3.3) and their MLS runtime verifies that binding. Anything normalised here would
/// change every downstream verifier's input.
pub fn publish_body(key_package: &V2GroupKeyPackage) -> Result<Map<String, Value>> {
    let mut body = Map::new();
    body.insert(
        "group_key_package".to_string(),
        serde_json::to_value(key_package)
            .map_err(|err| AgentxError::MessageInvalid(format!("serialising a KeyPackage: {err}")))?,
    );
    Ok(body)
}

/// The body of `group.e2ee.get_key_package` (P6 §8.2.2).
///
/// The two fields the lookup is by, plus the two MAYs when the caller asked for them. Both
/// MAYs are **absent** rather than present-and-empty when they do not apply: §8.2.2 makes
/// `preferred_suite` a non-empty string when it appears at all, so an empty one is a shape
/// problem at the service, not a "no preference". An empty `preferred_suite` is therefore
/// refused here, where the caller can still be told which flag was wrong.
pub fn get_key_package_body(
    target_did: &str,
    target_device_id: &str,
    preferred_suite: Option<&str>,
    require_fresh: bool,
) -> Result<Map<String, Value>> {
    let mut body = Map::new();
    body.insert(
        "target_did".to_string(),
        Value::String(target_did.to_string()),
    );
    body.insert(
        "target_device_id".to_string(),
        Value::String(target_device_id.to_string()),
    );
    if let Some(suite) = preferred_suite {
        if suite.is_empty() {
            return Err(AgentxError::MessageInvalid(
                "--suite must be a non-empty string when given (P6 §8.2.2)".to_string(),
            ));
        }
        body.insert(
            "preferred_suite".to_string(),
            Value::String(suite.to_string()),
        );
    }
    if require_fresh {
        body.insert("require_fresh".to_string(), Value::Bool(true));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anp::group_e2ee::v2_models::{V2DidWbaBinding, V2ObjectProof};

    /// The one field §8.1.2 names, carrying the object unchanged.
    ///
    /// The package is built field by field rather than parsed from a JSON literal: the crate's
    /// models are what the service has to accept, so if one of their fields moves this stops
    /// compiling instead of quietly testing a shape nobody uses.
    #[test]
    fn a_publish_body_carries_the_object_under_the_field_the_service_reads() {
        let package = V2GroupKeyPackage {
            key_package_id: "kp-1".to_string(),
            owner_did: "did:wba:example.com:user:test:e1_abc".to_string(),
            owner_device_id: "test/default".to_string(),
            suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_string(),
            mls_key_package_b64u: "AA".to_string(),
            did_wba_binding: V2DidWbaBinding {
                agent_did: "did:wba:example.com:user:test:e1_abc".to_string(),
                device_id: "test/default".to_string(),
                verification_method: "did:wba:example.com:user:test:e1_abc#test/default-sign"
                    .to_string(),
                leaf_signature_key_b64u: "AA".to_string(),
                issued_at: "2026-10-02T00:00:00Z".to_string(),
                expires_at: "2026-10-09T00:00:00Z".to_string(),
                proof: V2ObjectProof {
                    proof_type: "DataIntegrityProof".to_string(),
                    cryptosuite: "eddsa-jcs-2022".to_string(),
                    created: "2026-10-02T00:00:00Z".to_string(),
                    proof_purpose: "assertionMethod".to_string(),
                    verification_method: "did:wba:example.com:user:test:e1_abc#test/default-sign"
                        .to_string(),
                    proof_value: "AA".to_string(),
                },
            },
            expires_at: Some("2026-10-09T00:00:00Z".to_string()),
        };

        let body = publish_body(&package).unwrap();
        assert_eq!(body.len(), 1, "§8.1.2 names one field and nothing else");
        assert_eq!(
            body["group_key_package"]["key_package_id"],
            Value::String("kp-1".to_string())
        );
        assert_eq!(
            body["group_key_package"]["did_wba_binding"]["device_id"],
            Value::String("test/default".to_string()),
            "the binding travels with the object, proof and all (§8.2.3)"
        );
    }

    /// §8.2.2's MAYs are absent when they do not apply — not present and empty.
    ///
    /// The distinction is load-bearing at the service: it refuses `preferred_suite: ""` as a
    /// shape problem, so a caller who passed nothing must not look like a caller who passed
    /// an empty suite.
    #[test]
    fn the_get_body_names_the_pair_and_omits_the_mays_it_has_nothing_to_say_with() {
        let body =
            get_key_package_body("did:wba:example.com:user:peer:e1_x", "peer/default", None, false)
                .unwrap();
        assert_eq!(body.len(), 2, "only the two fields the lookup is by");
        assert_eq!(
            body["target_device_id"],
            Value::String("peer/default".to_string())
        );

        let body = get_key_package_body(
            "did:wba:example.com:user:peer:e1_x",
            "peer/default",
            Some("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"),
            true,
        )
        .unwrap();
        assert_eq!(body.len(), 4);
        assert_eq!(body["require_fresh"], Value::Bool(true));
    }

    #[test]
    fn an_empty_suite_is_refused_before_it_is_sent() {
        let err =
            get_key_package_body("did:wba:example.com:user:peer:e1_x", "peer/default", Some(""), false)
                .unwrap_err();
        assert!(err.to_string().contains("--suite"), "{err}");
    }
}
