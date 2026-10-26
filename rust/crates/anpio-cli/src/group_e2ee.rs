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

use anp::group_e2ee::v2_models::{
    V2E2eeNotice, V2GroupAddBody, V2GroupCipherObject, V2GroupCreateBody, V2GroupKeyPackage,
    V2GroupNoticeMetadata, V2GroupRemoveBody, V2GroupSendMetadata, V2Target,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::error::{AnpioError, Result};
use crate::message::{GROUP_E2EE_INCOMING, GROUP_E2EE_NOTICE};

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
        value_of(key_package, "a KeyPackage")?,
    );
    Ok(body)
}

/// The body of `group.e2ee.create` (P6 §9.2.3) — the crate's own six fields, unchanged.
///
/// There is nothing for this module to decide: §9.2.3 names `group_did`, `group_state_ref`,
/// `suite`, `creator_key_package`, `crypto_group_id_b64u` and `epoch`, and the crate builds
/// all six (the last two are its own MLS values, and `epoch` is the `"0"` §9.2.3 SHOULD).
/// Re-serialising the crate's struct rather than assembling a `Map` field by field is what
/// keeps this in step with `validate()` — the two are the same struct, so a field that moves
/// moves in both, where a hand-written body would drift silently.
pub fn create_body(body: &V2GroupCreateBody) -> Result<Map<String, Value>> {
    object_of(body, "a group.e2ee.create body")
}

/// The body of `group.e2ee.add` (P6 §9.3.3) — likewise the crate's own fields, unchanged.
///
/// Nine here rather than `create`'s six: §9.3.3 adds the member pair, the package being
/// covered, and the three MLS objects a commit to an existing group needs (`commit_b64u`,
/// `welcome_b64u`, `ratchet_tree_b64u`). Every one of them is the crate's, including
/// `crypto_group_id_b64u` and `epoch` — the latter is the epoch *after* this add, which only
/// the crate can know.
pub fn add_body(body: &V2GroupAddBody) -> Result<Map<String, Value>> {
    object_of(body, "a group.e2ee.add body")
}

/// The body of `group.e2ee.remove` (P6 §9.4.3) — the crate's own six fields, unchanged.
///
/// Six rather than `add`'s nine because a removal invites nobody: §9.4.3 names the pair, the
/// state ref, the crypto group id, the epoch and one MLS object (`commit_b64u`). The
/// `welcome_b64u` / `ratchet_tree_b64u` / `group_key_package` of `add` have no counterpart,
/// and the crate refuses a removal that produced a Welcome at all.
pub fn remove_body(body: &V2GroupRemoveBody) -> Result<Map<String, Value>> {
    object_of(body, "a group.e2ee.remove body")
}

/// The body of `group.e2ee.send` (P6 §9.5.3) — one field, the cipher object, unchanged.
///
/// The point of §9.5.3 is that the object is *the sender's to make*: the service has no way to
/// check a `PrivateMessage` and no key material to try (§12.6), so anything this module did to
/// the object beyond serialising it would be unverifiable by the receiver who has to decrypt
/// it. It travels byte-for-byte, `epoch_authenticator` included.
pub fn send_body(cipher: &V2GroupCipherObject) -> Result<Map<String, Value>> {
    let mut body = Map::new();
    body.insert(
        "group_cipher_object".to_string(),
        value_of(cipher, "a group cipher object")?,
    );
    Ok(body)
}

/// A crate model as a request body: the object form, or an error naming what could not be
/// serialised. Serialising is the only way these cross from the crate's typed world into
/// [`crate::message`]'s `Map<String, Value>` one, and every failure of it is the same kind —
/// a model that cannot be written as JSON cannot be signed either.
fn object_of<T: Serialize>(value: &T, what: &str) -> Result<Map<String, Value>> {
    match value_of(value, what)? {
        Value::Object(fields) => Ok(fields),
        other => Err(AnpioError::MessageInvalid(format!(
            "serialising {what}: expected an object, got {other}"
        ))),
    }
}

fn value_of<T: Serialize>(value: &T, what: &str) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|err| AnpioError::MessageInvalid(format!("serialising {what}: {err}")))
}

// ---- reading the two pushed frames (P6 §12) ------------------------------------
//
// The other direction of the six request bodies above: a service pushes a bare Notification
// `{jsonrpc, method, params}`, with no `id` and no signature — §13.6 is explicit that a notice
// MUST NOT carry an `origin_proof`, and §12.5 keeps an `incoming`'s accepted proof inside
// `params.auth`, which is not what either parser reads.
//
// Neither frame deserialises straight into the crate's model, and for the same reason: the
// crate's metas `deny_unknown_fields`, while §12's envelopes deliberately carry a bit more
// than the model has slots for (`message_id` on a notice, `recipient_device_id` on an
// `incoming`). So each is read field by field, into exactly the struct the crate's `validate()`
// was written against — a superset would be refused, and a dropped field is one the crate
// never looks at.

/// A pushed frame's `params`, or an error naming the method that was expected.
fn params_of<'a>(frame: &'a Value, method: &str) -> Result<&'a Map<String, Value>> {
    let row = frame.as_object().ok_or_else(|| {
        AnpioError::MessageInvalid(format!("a pushed {method} frame must be a JSON object"))
    })?;
    let seen = row.get("method").and_then(Value::as_str).unwrap_or("");
    if seen != method {
        return Err(AnpioError::MessageInvalid(format!(
            "expected a {method} frame, got {}",
            if seen.is_empty() { "(no method)" } else { seen }
        )));
    }
    row.get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| AnpioError::MessageInvalid(format!("a {method} frame must carry params")))
}

fn object_field<'a>(fields: &'a Map<String, Value>, key: &str, method: &str) -> Result<&'a Map<String, Value>> {
    fields
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| AnpioError::MessageInvalid(format!("a {method} frame has no {key}")))
}

/// A field the crate's `validate()` requires, so its absence is reported here rather than
/// surfacing later as a generic state error.
fn required(fields: &Map<String, Value>, key: &str, method: &str) -> Result<String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AnpioError::MessageInvalid(format!("a {method} frame has no {key}"))
        })
}

/// A field the crate's model carries as `Option`. A JSON `null` and an absent key are the same
/// thing here, and both mean "not present" — the crate's own `deserialize_present` is why an
/// explicit `null` must not be passed through as `Some(null)`.
fn optional(fields: &Map<String, Value>, key: &str) -> Option<String> {
    fields.get(key).and_then(Value::as_str).map(str::to_string)
}

fn target_of(fields: &Map<String, Value>, method: &str) -> Result<V2Target> {
    let target = object_field(fields, "target", method)?;
    Ok(V2Target {
        kind: required(target, "kind", method)?,
        did: required(target, "did", method)?,
    })
}

/// One `group.e2ee.notice`: the metadata and the notice body (P6 §12.2).
///
/// `meta.target` is the **recipient** agent here and stays that way — the crate's
/// `validate_notice_outer` wants `meta.target.did == recipient_did`, and §12.2.2 builds the
/// notice's target exactly so.
pub fn notice_of_frame(frame: &Value) -> Result<(V2GroupNoticeMetadata, V2E2eeNotice)> {
    let params = params_of(frame, GROUP_E2EE_NOTICE)?;
    let meta = object_field(params, "meta", GROUP_E2EE_NOTICE)?;
    let body = object_field(params, "body", GROUP_E2EE_NOTICE)?;

    let metadata = V2GroupNoticeMetadata {
        anp_version: optional(meta, "anp_version"),
        profile: required(meta, "profile", GROUP_E2EE_NOTICE)?,
        security_profile: required(meta, "security_profile", GROUP_E2EE_NOTICE)?,
        sender_did: required(meta, "sender_did", GROUP_E2EE_NOTICE)?,
        target: target_of(meta, GROUP_E2EE_NOTICE)?,
        recipient_device_id: required(meta, "recipient_device_id", GROUP_E2EE_NOTICE)?,
        operation_id: required(meta, "operation_id", GROUP_E2EE_NOTICE)?,
        created_at: optional(meta, "created_at"),
    };

    let notice: V2E2eeNotice = serde_json::from_value(Value::Object(body.clone())).map_err(|err| {
        AnpioError::MessageInvalid(format!("a {GROUP_E2EE_NOTICE} body is not a P6 notice: {err}"))
    })?;
    Ok((metadata, notice))
}

/// One `group.incoming` carrying P6 ciphertext: what [`crate::mls::decrypt_received`] needs,
/// plus the two ordering fields a rendered line shows (P6 §12.5).
pub struct IncomingFrame {
    pub meta: V2GroupSendMetadata,
    pub cipher: V2GroupCipherObject,
    /// §12.5: the same value in every leaf's copy of one accepted `send` — it is how a member
    /// lines this message up with what the others saw, the same way `group.send`'s response
    /// does for the sender.
    pub group_event_seq: Option<String>,
    pub accepted_at: Option<String>,
}

/// One P6 `group.incoming`: reconstruct the sender's metadata, and take the cipher object
/// (P6 §12.5).
///
/// The reconstruction is the whole point of this function, because the envelope's `meta` is
/// **not** the metadata the ciphertext was authenticated under. §12.5 re-targets each leaf's
/// copy at the receiving agent, so `meta.target` names the *recipient* — while `target.did` is
/// part of the `send`'s authenticated data (§7.5's `group_send_authenticated_data_v2`, which
/// the receiver re-derives and compares). The original target was the **group**, and the one
/// place §12.5 leaves that value is `body.group_did`. Reading the envelope's target here would
/// decrypt against the wrong bytes and be reported as a cipher failure.
///
/// Everything else is preserved rather than invented: `sender_did` / `sender_device_id` /
/// `message_id` / `operation_id` / `content_type` are the accepted `send`'s own (L1486–1487),
/// and `created_at` is the one field §13.6 moves aside into `origin_context` — it is not in the
/// authenticated data, so the delivery timestamp the envelope carries is fine.
pub fn incoming_of_frame(frame: &Value) -> Result<IncomingFrame> {
    let params = params_of(frame, GROUP_E2EE_INCOMING)?;
    let meta = object_field(params, "meta", GROUP_E2EE_INCOMING)?;
    let body = object_field(params, "body", GROUP_E2EE_INCOMING)?;

    let group_did = required(body, "group_did", GROUP_E2EE_INCOMING)?;
    let cipher: V2GroupCipherObject = serde_json::from_value(
        body.get("group_cipher_object")
            .cloned()
            .ok_or_else(|| {
                AnpioError::MessageInvalid(format!(
                    "a {GROUP_E2EE_INCOMING} frame has no group_cipher_object"
                ))
            })?,
    )
    .map_err(|err| {
        AnpioError::MessageInvalid(format!(
            "a {GROUP_E2EE_INCOMING} frame's cipher object is not a V2GroupCipherObject: {err}"
        ))
    })?;

    Ok(IncomingFrame {
        meta: V2GroupSendMetadata {
            anp_version: optional(meta, "anp_version"),
            profile: required(meta, "profile", GROUP_E2EE_INCOMING)?,
            security_profile: required(meta, "security_profile", GROUP_E2EE_INCOMING)?,
            sender_did: required(meta, "sender_did", GROUP_E2EE_INCOMING)?,
            sender_device_id: required(meta, "sender_device_id", GROUP_E2EE_INCOMING)?,
            target: V2Target {
                kind: "group".to_string(),
                did: group_did,
            },
            operation_id: required(meta, "operation_id", GROUP_E2EE_INCOMING)?,
            message_id: required(meta, "message_id", GROUP_E2EE_INCOMING)?,
            content_type: required(meta, "content_type", GROUP_E2EE_INCOMING)?,
            created_at: optional(meta, "created_at"),
        },
        cipher,
        group_event_seq: optional(body, "group_event_seq"),
        accepted_at: optional(body, "accepted_at"),
    })
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
            return Err(AnpioError::MessageInvalid(
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
    use anp::group_e2ee::v2_models::{
        V2DidWbaBinding, V2GroupStateRef, V2ObjectProof, GROUP_E2EE_MTI_SUITE_V2,
    };
    use serde_json::json;

    fn package() -> V2GroupKeyPackage {
        V2GroupKeyPackage {
            key_package_id: "kp-1".to_string(),
            owner_did: "did:wba:example.com:user:test:e1_abc".to_string(),
            owner_device_id: "test/default".to_string(),
            suite: GROUP_E2EE_MTI_SUITE_V2.to_string(),
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
        }
    }

    /// The one field §8.1.2 names, carrying the object unchanged.
    ///
    /// The package is built field by field rather than parsed from a JSON literal: the crate's
    /// models are what the service has to accept, so if one of their fields moves this stops
    /// compiling instead of quietly testing a shape nobody uses.
    #[test]
    fn a_publish_body_carries_the_object_under_the_field_the_service_reads() {
        let package = package();

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

    /// §9.2.3's six fields, exactly as the crate built them.
    ///
    /// The point of the test is that nothing is added and nothing is dropped: the service
    /// refuses an unknown shape, and the two fields this client never chooses
    /// (`crypto_group_id_b64u`, `epoch`) are here because the crate put them there.
    #[test]
    fn a_create_body_is_the_crates_six_fields_unchanged() {
        let body = create_body(&V2GroupCreateBody {
            group_did: "did:web:svc.example:g:team".to_string(),
            group_state_ref: V2GroupStateRef {
                group_did: "did:web:svc.example:g:team".to_string(),
                group_state_version: "7".to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            suite: GROUP_E2EE_MTI_SUITE_V2.to_string(),
            creator_key_package: package(),
            crypto_group_id_b64u: "Z3JvdXA".to_string(),
            epoch: "0".to_string(),
        })
        .unwrap();

        let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "creator_key_package",
                "crypto_group_id_b64u",
                "epoch",
                "group_did",
                "group_state_ref",
                "suite",
            ]
        );
        assert_eq!(
            body["group_state_ref"]["group_state_version"],
            Value::String("7".to_string()),
            "the P4 version travels in the ref, which is where §7.2 puts it"
        );
        assert_eq!(
            body["epoch"],
            Value::String("0".to_string()),
            "§9.2.3's SHOULD for the initial epoch is the crate's value, not this client's"
        );
    }

    /// §9.3.3's nine fields, again exactly as the crate built them.
    ///
    /// The three MLS objects and the two coordinate fields are all the crate's, and the member
    /// pair is the *package's* owner rather than anything this client chose — so the assertion
    /// that matters is the one tying `member_did` to `group_key_package.owner_did`: the service
    /// refuses a body where those two disagree (its `didBindingInvalid`), and a client that
    /// took the pair from anywhere but the package could produce that split.
    #[test]
    fn an_add_body_is_the_crates_nine_fields_unchanged() {
        let package = package();
        let body = add_body(&V2GroupAddBody {
            member_did: package.owner_did.clone(),
            member_device_id: package.owner_device_id.clone(),
            group_state_ref: V2GroupStateRef {
                group_did: "did:web:svc.example:g:team".to_string(),
                group_state_version: "7".to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            group_key_package: package.clone(),
            crypto_group_id_b64u: "Z3JvdXA".to_string(),
            epoch: "1".to_string(),
            commit_b64u: "Y29tbWl0".to_string(),
            welcome_b64u: "d2VsY29tZQ".to_string(),
            ratchet_tree_b64u: "dHJlZQ".to_string(),
        })
        .unwrap();

        let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "commit_b64u",
                "crypto_group_id_b64u",
                "epoch",
                "group_key_package",
                "group_state_ref",
                "member_device_id",
                "member_did",
                "ratchet_tree_b64u",
                "welcome_b64u",
            ]
        );
        assert_eq!(
            body["member_did"],
            body["group_key_package"]["owner_did"],
            "§9.3.3 keys the add on the package's own owner (§9.3.3's didBindingInvalid otherwise)"
        );
        assert_eq!(
            body["epoch"],
            Value::String("1".to_string()),
            "§9.3.3's `epoch` is the one *after* the add, so it is the crate's value"
        );
    }

    /// §9.4.3's six fields, again exactly as the crate built them.
    ///
    /// The point of the assertion is the count: `add`'s nine carries three objects a removal
    /// has no use for, and the service refuses an unknown shape — so a body that still held
    /// `welcome_b64u` from a copied `add` would be caught here rather than there.
    #[test]
    fn a_remove_body_is_the_crates_six_fields_unchanged() {
        let body = remove_body(&V2GroupRemoveBody {
            member_did: "did:wba:example.com:user:peer:e1_x".to_string(),
            member_device_id: "peer/default".to_string(),
            group_state_ref: V2GroupStateRef {
                group_did: "did:web:svc.example:g:team".to_string(),
                group_state_version: "7".to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            crypto_group_id_b64u: "Z3JvdXA".to_string(),
            epoch: "2".to_string(),
            commit_b64u: "Y29tbWl0".to_string(),
        })
        .unwrap();

        let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "commit_b64u",
                "crypto_group_id_b64u",
                "epoch",
                "group_state_ref",
                "member_device_id",
                "member_did",
            ],
            "§9.4.3 has no welcome, no ratchet tree and no package"
        );
        assert_eq!(
            body["epoch"],
            Value::String("2".to_string()),
            "§9.4.3's `epoch` is the one *after* the remove, so it is the crate's value"
        );
    }

    /// §9.5.3's single field, carrying the cipher object unchanged.
    ///
    /// The object is built field by field rather than parsed from a literal, for the same
    /// reason as the KeyPackage above: it is the crate's model the receiver will decrypt, so a
    /// field that moves must stop this compiling rather than quietly testing a shape nobody
    /// sends. The assertion that matters is that nothing is renamed on the way out —
    /// `epoch_authenticator` included, which the receiver's `decrypt_v2` checks against the
    /// epoch it actually reached.
    #[test]
    fn a_send_body_carries_the_object_under_the_field_the_service_reads() {
        let cipher = V2GroupCipherObject {
            crypto_group_id_b64u: "Z3JvdXA".to_string(),
            epoch: "2".to_string(),
            private_message_b64u: "AA".to_string(),
            group_state_ref: V2GroupStateRef {
                group_did: "did:web:svc.example:g:team".to_string(),
                group_state_version: "7".to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            epoch_authenticator: Some("BB".to_string()),
        };

        let body = send_body(&cipher).unwrap();
        assert_eq!(body.len(), 1, "§9.5.3 names one field and nothing else");
        let sent = &body["group_cipher_object"];
        assert_eq!(sent["epoch"], Value::String("2".to_string()));
        assert_eq!(
            sent["group_state_ref"]["group_state_version"],
            Value::String("7".to_string()),
            "the P4 version travels inside the object, where §7.4 puts it"
        );
        assert_eq!(
            sent["epoch_authenticator"],
            Value::String("BB".to_string()),
            "§12.6 forbids re-encoding the object, so the authenticator goes as it was made"
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

    // ---- the pushed frames -----------------------------------------------------
    //
    // The literals below are the envelopes `packages/service/src/rpc/groupEnvelopes.ts`
    // builds, field for field — a fixture invented here would only prove this file agrees
    // with itself.

    const GROUP: &str = "did:web:svc.example:g:team";
    const CAROL: &str = "did:wba:example.com:user:carol:e1_carol";

    fn state_ref() -> Value {
        json!({ "group_did": GROUP, "group_state_version": "7" })
    }

    /// The commit half of an `add`: §12.2.2's envelope, `subject_status: active`.
    #[test]
    fn a_commit_notice_frame_reads_into_the_crates_notice() {
        let frame = json!({
            "jsonrpc": "2.0",
            "method": "group.e2ee.notice",
            "params": {
                "meta": {
                    "profile": "anp.group.e2ee.v2",
                    "security_profile": "transport-protected",
                    "sender_did": GROUP,
                    "target": { "kind": "agent", "did": CAROL },
                    "recipient_device_id": "carol/default",
                    // The one field the crate's notice metadata has no slot for; it must be
                    // dropped rather than refused (the crate's metas deny unknown fields).
                    "message_id": "bXNn",
                    "operation_id": "b3A",
                    "created_at": "2026-10-02T00:00:00Z"
                },
                "body": {
                    "notice_id": "bnQ",
                    "notice_type": "commit-delivery",
                    "group_did": GROUP,
                    "group_state_ref": state_ref(),
                    "crypto_group_id_b64u": "Z3JvdXA",
                    "epoch": "1",
                    "subject_did": CAROL,
                    "subject_device_id": "carol/default",
                    "subject_status": "active",
                    "commit_b64u": "Y29tbWl0"
                }
            }
        });

        let (meta, notice) = notice_of_frame(&frame).unwrap();
        assert_eq!(meta.sender_did, GROUP, "§12.2.2: the group is the sender");
        assert_eq!(meta.target.did, CAROL, "…and the recipient is the target");
        assert_eq!(meta.operation_id, "b3A");
        assert_eq!(notice.notice_type, "commit-delivery");
        assert_eq!(notice.subject_status, "active");
        assert_eq!(notice.commit_b64u.as_deref(), Some("Y29tbWl0"));
        assert!(notice.welcome_b64u.is_none(), "a commit carries no Welcome");
    }

    /// The welcome half: the same envelope with the two Welcome objects and no commit.
    #[test]
    fn a_welcome_notice_frame_reads_both_welcome_objects() {
        let frame = json!({
            "jsonrpc": "2.0",
            "method": "group.e2ee.notice",
            "params": {
                "meta": {
                    "profile": "anp.group.e2ee.v2",
                    "security_profile": "transport-protected",
                    "sender_did": GROUP,
                    "target": { "kind": "agent", "did": CAROL },
                    "recipient_device_id": "carol/default",
                    "message_id": "bXNn",
                    "operation_id": "b3A",
                    "created_at": "2026-10-02T00:00:00Z"
                },
                "body": {
                    "notice_id": "bnQ",
                    "notice_type": "welcome-delivery",
                    "group_did": GROUP,
                    "group_state_ref": state_ref(),
                    "crypto_group_id_b64u": "Z3JvdXA",
                    "epoch": "1",
                    "subject_did": CAROL,
                    "subject_device_id": "carol/default",
                    // Both welcome objects §12.4 sends, and the status the crate's own
                    // `validate_notice_outer` insists on for a welcome.
                    "subject_status": "active",
                    "welcome_b64u": "d2VsY29tZQ",
                    "ratchet_tree_b64u": "dHJlZQ"
                }
            }
        });

        let (_, notice) = notice_of_frame(&frame).unwrap();
        assert_eq!(notice.notice_type, "welcome-delivery");
        assert_eq!(notice.welcome_b64u.as_deref(), Some("d2VsY29tZQ"));
        assert_eq!(notice.ratchet_tree_b64u.as_deref(), Some("dHJlZQ"));
        assert_eq!(
            notice.subject_did, CAROL,
            "§12.4: the Welcome's subject must be the recipient (the crate checks it)"
        );
    }

    /// An `incoming` frame's meta is re-targeted at the group, and the crate accepts it.
    ///
    /// The assertion that matters is the last one: the crate's own AAD builder both validates
    /// the reconstructed metadata and insists `group_state_ref.group_did == meta.target.did`.
    /// If the envelope's own target (the recipient agent, per §12.5) were passed through, that
    /// check would fail here rather than as an unexplained decrypt failure at the service.
    #[test]
    fn an_incoming_frame_is_retargeted_at_the_group_for_the_aad() {
        let cipher = V2GroupCipherObject {
            crypto_group_id_b64u: "Z3JvdXA".to_string(),
            epoch: "2".to_string(),
            private_message_b64u: "AA".to_string(),
            group_state_ref: V2GroupStateRef {
                group_did: GROUP.to_string(),
                group_state_version: "7".to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            // Base64url, because the AAD builder below validates the object it is handed —
            // the values are the wire vector's, so this fixture also proves those parse.
            epoch_authenticator: Some("ZXBvY2gtYXV0aA".to_string()),
        };
        let frame = json!({
            "jsonrpc": "2.0",
            "method": "group.incoming",
            "params": {
                "meta": {
                    "profile": "anp.group.e2ee.v2",
                    "security_profile": "group-e2ee",
                    "sender_did": "did:wba:example.com:user:bob:e1_bob",
                    "sender_device_id": "bob/default",
                    "target": { "kind": "agent", "did": CAROL },
                    "recipient_device_id": "carol/default",
                    "message_id": "bXNn",
                    "operation_id": "b3A",
                    "content_type": "application/anp-group-cipher+json",
                    "created_at": "2026-10-02T00:00:00Z"
                },
                "auth": { "scheme": "anp", "origin_proof": {}, "origin_context": {} },
                "body": {
                    "group_did": GROUP,
                    "group_state_version": "7",
                    "group_event_seq": "4",
                    "accepted_at": "2026-10-02T00:00:00Z",
                    "group_receipt": {},
                    "group_cipher_object": serde_json::to_value(&cipher).unwrap()
                }
            }
        });

        let incoming = incoming_of_frame(&frame).unwrap();
        assert_eq!(
            incoming.meta.sender_did,
            "did:wba:example.com:user:bob:e1_bob",
            "§12.5 L1486: the sender's pair is preserved as the sender's"
        );
        assert_eq!(
            incoming.meta.target.kind, "group",
            "the envelope's target names the recipient; the send's named the group"
        );
        assert_eq!(incoming.meta.target.did, GROUP);
        assert_eq!(incoming.group_event_seq.as_deref(), Some("4"));
        assert_eq!(incoming.cipher.epoch, "2");

        anp::group_e2ee::group_send_authenticated_data_v2(&incoming.meta, &incoming.cipher)
            .expect("the reconstructed metadata is what the ciphertext was authenticated under");
    }

    /// A frame for a method this parser is not for is refused, and says which it saw.
    #[test]
    fn a_frame_for_another_method_is_refused() {
        let frame = json!({
            "jsonrpc": "2.0",
            "method": "direct.incoming",
            "params": { "meta": {}, "body": {} }
        });
        let err = notice_of_frame(&frame).unwrap_err();
        assert!(err.to_string().contains("direct.incoming"), "{err}");
        assert!(err.to_string().contains("group.e2ee.notice"), "{err}");
    }

    /// A notice with no `operation_id` is refused here rather than deeper in.
    ///
    /// The crate receipts notices on that id, so a missing one is not a body it can take —
    /// and the error should name the field, not the state machine that tripped over it.
    #[test]
    fn a_notice_without_the_fields_the_crate_needs_is_refused() {
        let frame = json!({
            "jsonrpc": "2.0",
            "method": "group.e2ee.notice",
            "params": {
                "meta": {
                    "profile": "anp.group.e2ee.v2",
                    "security_profile": "transport-protected",
                    "sender_did": GROUP,
                    "target": { "kind": "agent", "did": CAROL },
                    "recipient_device_id": "carol/default"
                },
                "body": {}
            }
        });
        let err = notice_of_frame(&frame).unwrap_err();
        assert!(err.to_string().contains("operation_id"), "{err}");
    }
}
