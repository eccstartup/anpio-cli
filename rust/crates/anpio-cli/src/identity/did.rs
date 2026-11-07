//! Minting an identity: keys, a DID document that publishes them, and the device
//! manifest the P6 gate reads.
//!
//! The document is the `e1_` shape the awiki host accepts (TODO5 §8-J): `did:wba:<host>
//! <path…>:e1_<fingerprint>`, an Ed25519 `key-1` in `Multikey` form, and a Data Integrity
//! proof in `eddsa-jcs-2022`. The `anp` crate builds all of that; three things are ours.
//!
//! 1. **The device keys.** P6 wants a device whose signing key is Ed25519 and whose
//!    agreement key is X25519, and the host refuses a device that reuses the DID root
//!    (`awiki-open-server/protocol/anp_adapter.py`: "root cannot authorize a device
//!    token"). The crate's own `enable_e2ee` pair is the older single-device layout
//!    (`#key-2` is P-256), so this client mints its own two keys and drops that pair.
//! 2. **The document assembly.** `build_vnext_did_document` puts the root and device keys
//!    into exactly the relationships P6 demands; the awiki host rebuilds the document
//!    from the same builder and rejects a document whose relationships differ, so
//!    assembling by hand is not an option (TODO5 §8-J).
//! 3. **The `proofValue` encoding and signing input.** `anp::proof::complete_w3c_proof`
//!    writes bare base64url over a signing input that leaves the document's `@context` out
//!    of the proof configuration. W3C `vc-di-eddsa` — and so both the awiki host and
//!    `anpio-key` — wants base58-btc multibase (`z…`) over
//!    `sha256(jcs(proofConfig))‖sha256(jcs(document minus proof))`, with the document's
//!    `@context` folded into the configuration. That is [`super::proof`]'s job; there is no
//!    re-encoding step, because the signing input differs, not just the alphabet.

use std::collections::BTreeMap;

use anp::authentication::device_manifest::{
    build_vnext_did_document, DeviceManifestEntry, PROFILE_CORE_BINDING_V1,
    PROFILE_DIRECT_BASE_V1, PROFILE_DIRECT_E2EE_V2, PROFILE_GROUP_BASE_V2, PROFILE_GROUP_E2EE_V2,
    PROFILE_IDENTITY_DISCOVERY_V1,
};
use anp::authentication::did_transition::parse_did_wba_e1;
use anp::authentication::did_wba::{
    build_anp_message_service, compute_multikey_fingerprint, AnpMessageServiceOptions,
    ANP_MESSAGE_SERVICE_TYPE,
};
use anp::{PrivateKeyMaterial, PublicKeyMaterial};
use anyhow::{anyhow, bail, Result};
use chrono::Utc;
use serde_json::{json, Value};

use super::proof;
use super::store::{Identity, StoredKeyPair};

pub struct CreateIdentityInput {
    /// The host's DID authority — the segment after `did:wba:` in the host's own service
    /// DID, e.g. `localhost%3A8000`. Taken from the host rather than re-derived here:
    /// an identity's DID hangs under the host's, so the host decides what its authority
    /// is (its `AWIKI_SERVICE_DID`; see `awiki-open-server/app/settings.py`).
    pub authority: String,
    /// The bare hostname the identity claims, e.g. `awiki.me`. The root proof names it as
    /// its `domain`, and the host refuses a document whose proof omits it.
    pub domain: String,
    pub agent: String,
    pub profile: String,
    /// The device name the document publishes (`{device}-sign`, `{device}-agreement`).
    /// Absent means `{agent}/{profile}`; a protected identity can name its own device.
    pub device: Option<String>,
    pub handle: String,
    /// The user's spelling of the host, kept for display and for `did register`.
    pub did_host_url: String,
    /// The ANP message service the document advertises. The awiki host requires its
    /// *own* endpoint and DID here unless its peer-declared-service switch is on
    /// (TODO5 §8-J) — which is why these are read off its `/.well-known/did.json`
    /// rather than chosen by this client.
    pub service_endpoint: String,
    pub service_did: String,
}

/// Mint a fresh identity. Nothing is written; the caller saves it.
pub fn create_identity(input: CreateIdentityInput) -> Result<Identity> {
    let keys = mint_keys(&input.agent, &input.profile);
    rebuild_identity(input, &keys)
}

/// The private material a new identity starts with: the root and the device pair.
///
/// Separate from the document because the document embeds the handle (through the DID) and
/// a handle is a candidate until the host accepts it. A retry changes the path, not these.
pub fn mint_keys(agent: &str, profile: &str) -> BTreeMap<String, StoredKeyPair> {
    let device_id = format!("{agent}/{profile}");
    let root = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(
        &mut rand::rngs::OsRng,
    ));
    // A fresh device key, not the root: a device that reuses the root makes the host refuse
    // the document (the root would authorize itself as a token holder).
    let signing = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(
        &mut rand::rngs::OsRng,
    ));
    // Same construction the crate uses for its own X25519 agreement key.
    let agreement = PrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::from(
        rand::random::<[u8; 32]>(),
    ));
    let mut keys = BTreeMap::new();
    keys.insert("key-1".to_string(), pair(&root));
    keys.insert(format!("{device_id}-sign"), pair(&signing));
    keys.insert(format!("{device_id}-agreement"), pair(&agreement));
    keys
}

/// Rebuild an identity for a **new handle** from key material that already exists.
///
/// A taken handle costs a name, not a key: the fingerprint is the key's, and the handle is
/// only the path above it. Everything the document says about the DID embeds that path —
/// the id, every verification-method id, every relationship entry — so the document is
/// rebuilt from the stored public keys and re-proven with key-1 rather than patched.
///
/// The device fragments are the one thing that may change: they carry the agent/profile
/// name, and a retry can name a different agent.
pub fn rebuild_identity(
    input: CreateIdentityInput,
    keys: &std::collections::BTreeMap<String, StoredKeyPair>,
) -> Result<Identity> {
    let root_pair = keys.get("key-1").ok_or_else(|| {
        anyhow!("the pending identity has no key-1; there is no key to reuse")
    })?;
    let root = load_stored_key(root_pair)?;
    let root_public = root.public_key();

    // The stored fragments carry the old device name; find the pair by role, not by the
    // exact fragment, so a retry under another agent renames rather than re-mints.
    let signing_pair = keys
        .iter()
        .find(|(fragment, _)| fragment.ends_with("-sign"))
        .map(|(_, pair)| pair)
        .ok_or_else(|| anyhow!("the pending identity has no device signing key"))?;
    let agreement_pair = keys
        .iter()
        .find(|(fragment, _)| fragment.ends_with("-agreement"))
        .map(|(_, pair)| pair)
        .ok_or_else(|| anyhow!("the pending identity has no device agreement key"))?;
    let signing_public = public_of_pem(&signing_pair.public_key_pem)?;
    let agreement_public = public_of_pem(&agreement_pair.public_key_pem)?;

    let (did, device_id, document) =
        vnext_document(&input, &root_public, &signing_public, &agreement_public)?;
    let root_key_id = format!("{did}#key-1");
    let signed_document = proof::sign_document(
        &document,
        &root,
        &root_key_id,
        Some(&input.domain),
        Some(&fresh_challenge()),
    )?;

    let mut stored = std::collections::BTreeMap::new();
    stored.insert("key-1".to_string(), root_pair.clone());
    stored.insert(format!("{device_id}-sign"), signing_pair.clone());
    stored.insert(format!("{device_id}-agreement"), agreement_pair.clone());

    Ok(Identity {
        did,
        device_id,
        agent: input.agent,
        profile: input.profile,
        handle: input.handle,
        did_host: input.did_host_url,
        created_at: Utc::now().to_rfc3339(),
        keys: stored,
        did_document: signed_document,
        custody: None,
    })
}

/// The document both lines agree on: an Ed25519 root, an Ed25519 device signing key and an
/// X25519 device agreement key, assembled by `build_vnext_did_document`.
///
/// The private halves come from very different places — this store on one line, `anpio-key`
/// on the other — but the public halves and the roles they claim are the same, and the host
/// rebuilds exactly this shape before accepting it. So both lines build it here, and a
/// difference between them is a bug rather than a variation.
fn vnext_document(
    input: &CreateIdentityInput,
    root_public: &PublicKeyMaterial,
    signing_public: &PublicKeyMaterial,
    agreement_public: &PublicKeyMaterial,
) -> Result<(String, String, Value)> {
    if !matches!(root_public, PublicKeyMaterial::Ed25519(_))
        || !matches!(signing_public, PublicKeyMaterial::Ed25519(_))
    {
        bail!("the DID root and device signing keys must be Ed25519");
    }
    if !matches!(agreement_public, PublicKeyMaterial::X25519(_)) {
        bail!("the device agreement key must be X25519");
    }
    let fingerprint = compute_multikey_fingerprint(root_public)
        .map_err(|err| anyhow!("computing the identity key's fingerprint: {err}"))?;
    let did = format!(
        "did:wba:{}:user:{}:e1_{}",
        input.authority, input.agent, fingerprint
    );

    let device_id = input
        .device
        .clone()
        .unwrap_or_else(|| format!("{}/{}", input.agent, input.profile));
    let signing_fragment = format!("{device_id}-sign");
    let agreement_fragment = format!("{device_id}-agreement");
    let signing_id = format!("{did}#{signing_fragment}");
    let agreement_id = format!("{did}#{agreement_fragment}");
    let signing_method = json!({
        "id": signing_id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": multibase(0xed, &public_bytes(signing_public)),
    });
    let agreement_method = json!({
        "id": agreement_id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": multibase(0xec, &public_bytes(agreement_public)),
    });
    let entry = DeviceManifestEntry {
        device_id: device_id.clone(),
        signing_key_id: signing_id,
        e2ee_key_id: agreement_id,
        profiles: device_profiles(),
    };

    let root_key_id = format!("{did}#key-1");
    let root_method = json!({
        "id": root_key_id,
        "type": "Multikey",
        "controller": did,
        "publicKeyMultibase": multibase(0xed, &public_bytes(root_public)),
    });
    let base = json!({
        "id": did,
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/data-integrity/v2",
            "https://w3id.org/security/multikey/v1",
        ],
        "service": [message_service_value(input)],
    });
    let document = build_vnext_did_document(
        &base,
        &root_key_id,
        &root_method,
        &entry,
        &signing_method,
        &agreement_method,
    )
    .map_err(|err| anyhow!("assembling the device DID document: {err}"))?;
    Ok((did, device_id, document))
}

/// A document built from public keys that live **elsewhere** — the `anpio-key` line.
///
/// This function has no private material to sign with and returns the document unsigned:
/// only the key's holder can prove it, and that proof is a daemon call. The daemon holds
/// three named keys for the identity — the root, the device signing key and the X25519
/// agreement key — so the document carries the same one-device manifest the local line does,
/// and the store still keeps no private bytes.
pub struct ExternalIdentity {
    pub did: String,
    pub device_id: String,
    pub unsigned_document: Value,
}

pub fn build_external_identity(
    input: &CreateIdentityInput,
    root_public: PublicKeyMaterial,
    signing_public: PublicKeyMaterial,
    agreement_public: PublicKeyMaterial,
) -> Result<ExternalIdentity> {
    let (did, device_id, unsigned_document) =
        vnext_document(input, &root_public, &signing_public, &agreement_public)?;
    Ok(ExternalIdentity {
        did,
        device_id,
        unsigned_document,
    })
}

fn message_service_value(input: &CreateIdentityInput) -> Value {
    build_anp_message_service(
        "#anp-message",
        input.service_endpoint.clone(),
        AnpMessageServiceOptions::default()
            .with_service_did(input.service_did.clone())
            .with_profiles(["anp.direct.base.v1"])
            .with_security_profiles(["transport-protected"]),
    )
}

fn device_profiles() -> Vec<String> {
    [
        PROFILE_CORE_BINDING_V1,
        PROFILE_IDENTITY_DISCOVERY_V1,
        PROFILE_DIRECT_BASE_V1,
        PROFILE_DIRECT_E2EE_V2,
        PROFILE_GROUP_BASE_V2,
        PROFILE_GROUP_E2EE_V2,
    ]
    .iter()
    .map(|profile| profile.to_string())
    .collect()
}

/// The public half of a stored pair, read from the PEM the store keeps beside the private key.
fn public_of_pem(pem: &str) -> Result<PublicKeyMaterial> {
    PublicKeyMaterial::from_pem(pem)
        .map_err(|err| anyhow!("the stored public key is not readable: {err}"))
}

/// The **stable subject** of a DID: the identity that survives a key update.
///
/// A `did:wba` E1 DID embeds key-1's fingerprint (`e1_…`), which moves with every hop — so
/// the subject is that identifier with the fingerprint segment taken off, and the DID is the
/// wire credential that changes underneath it. A session keyed on the subject therefore
/// survives a key update, and one keyed on the DID does not (this is why `login` reports
/// both).
///
/// A DID with no fingerprint is already stable and is returned unchanged. That is `did:web`'s
/// definition, not a fallback: its identifier carries nothing about the key — the tie is the
/// domain's TLS certificate plus the document it serves — so demanding a WBA fingerprint of
/// it is a MUST NOT (ANP-05 App. B B.1 L477).
pub fn subject_of(did: &str) -> String {
    match parse_did_wba_e1(did) {
        // `stable_subject_path` already includes the authority (`localhost%3A9001:user:carol`),
        // so the prefix is the whole of what is added back.
        Ok(profile) => format!("did:wba:{}", profile.stable_subject_path),
        Err(_) => did.to_string(),
    }
}

/// Mint the successor half of an update hop: a fresh key for the **same** subject.
///
/// Everything that makes the identity *this* identity is carried over — the host, the path,
/// the handle, the device name, the creation date — and only the key material is new. The
/// DID changes because it embeds key-1's fingerprint (ANP-03 §2.5.3 L413); the stable
/// subject path does not, because nothing above the fingerprint moved. That is the property
/// the crate's `verify_transition_hop` re-checks on delivery (`StablePathMismatch`), so it is
/// arranged here by construction rather than asserted afterwards: one function reads the
/// retiring identity's own fields, so the two cannot drift apart.
///
/// The authority is taken from the retiring DID rather than from the host again: it is
/// `did:wba:<authority>:…`, so re-deriving it is a string operation, and asking the host
/// would make a local step depend on the network.
pub fn successor_of(identity: &Identity) -> Result<Identity> {
    let profile = parse_did_wba_e1(&identity.did).map_err(|err| {
        anyhow!(
            "{} is not a did:wba E1 DID, so it has no successor ({})",
            identity.did,
            err.message
        )
    })?;
    let (service_endpoint, service_did) = message_service(&identity.did_document, &identity.did)?;

    let mut successor = create_identity(CreateIdentityInput {
        authority: profile.origin.clone(),
        domain: domain_from_did(&identity.did).unwrap_or(profile.origin),
        agent: identity.agent.clone(),
        profile: identity.profile.clone(),
        device: Some(identity.device_id.clone()),
        handle: identity.handle.clone(),
        did_host_url: identity.did_host.clone(),
        service_endpoint,
        service_did,
    })?;
    // The update moves the key, not the account: an identity that has been renewed is not
    // a new account, and `did show` must not report it as one born today.
    successor.created_at = identity.created_at.clone();
    Ok(successor)
}

/// The endpoint and service DID an identity's document advertises, read back off it.
///
/// `create_identity` wrote these from the host's own `/.well-known/did.json`; reading them
/// back is what lets [`successor_of`] rebuild the same document without a second round trip
/// to a host that may not be up. The document is the store's own, so a missing entry means
/// the file was hand-edited — worth naming rather than composing a document with no service.
fn message_service(document: &Value, did: &str) -> Result<(String, String)> {
    let service = document
        .get("service")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.get("type").and_then(Value::as_str) == Some(ANP_MESSAGE_SERVICE_TYPE)
            })
        })
        .ok_or_else(|| {
            anyhow!("{did}'s document advertises no {ANP_MESSAGE_SERVICE_TYPE} service to carry over")
        })?;
    let endpoint = service
        .get("serviceEndpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{did}'s message service has no serviceEndpoint"))?;
    let service_did = service
        .get("serviceDid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{did}'s message service has no serviceDid"))?;
    Ok((endpoint.to_string(), service_did.to_string()))
}

/// Build the retirement half of an update hop: the document that was on file, marked retired.
///
/// ANP-03 §2.5.3 L417: the predecessor's document gets `deactivated` and `successorDid`, and
/// L419: the proof it is re-made with covers the properties it carries. So this is the
/// **same** document — the base is the one the DID server holds, not one composed here, or
/// the hop retires a document that was never published (any `service` entry the host added
/// out of band would be missing) — with exactly those two fields added and one fresh proof.
///
/// Signed by key-1, the key whose fingerprint *is* the DID: `verify_transition_hop` looks
/// for a binding method that matches the DID's fingerprint, finds key-1, and requires the
/// proof to be key-1's. Re-signing is not optional — the old proof covered a document
/// without `deactivated`, so leaving it would be asserting something that is no longer true.
pub fn retirement_document(
    base: &Value,
    did: &str,
    successor_did: &str,
    key1: &PrivateKeyMaterial,
) -> Result<Value> {
    let mut retired = base
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("the document on file is not a JSON object"))?;
    if retired.get("id").and_then(Value::as_str) != Some(did) {
        // Not a formality: a base from before a key change describes the DID that was
        // current then, and retiring it would deliver a hop about the wrong identifier.
        bail!(
            "the document on file is for {}, not {did} — it cannot be the base of a hop retiring {did}",
            retired.get("id").and_then(Value::as_str).unwrap_or("<no id>")
        );
    }
    retired.insert("deactivated".to_string(), Value::Bool(true));
    retired.insert("successorDid".to_string(), Value::String(successor_did.to_string()));

    let domain = domain_from_did(did);
    proof::sign_document(
        &Value::Object(retired),
        key1,
        &format!("{did}#key-1"),
        domain.as_deref(),
        Some(&fresh_challenge()),
    )
    .map_err(|err| anyhow!("signing the retirement document: {err}"))
}

/// Load a stored key pair as signing material — `key-1`, for the two documents `did update`
/// signs.
pub fn load_stored_key(pair: &StoredKeyPair) -> Result<PrivateKeyMaterial> {
    PrivateKeyMaterial::from_pem(&pair.private_key_pem)
        .map_err(|err| anyhow!("the stored private key is not readable: {err}"))
}

/// Re-make a document's proof over the document as it now stands.
///
/// A DID document's proof covers the document's own bytes, so **any** edit invalidates it:
/// the host re-verifies and refuses with `did_document_proof_invalid`, which is exactly what
/// a locally edited document is. Re-proving is therefore part of publishing an edit rather
/// than a step beside it, and it is what `retirement_document` does too — the difference is
/// only that that one adds two fields first.
///
/// Signed by key-1, and it has to be: the host refuses a document whose proof names any
/// other root (`root_change_not_supported`), and key-1 is the key whose fingerprint *is* the
/// DID. [`proof::sign_document`] drops whatever `proof` the document carried out of the
/// signing input, so re-proving an already-proven document is what it is for.
pub fn resign_document(document: &Value, did: &str, key1: &PrivateKeyMaterial) -> Result<Value> {
    let domain = domain_from_did(did);
    proof::sign_document(
        document,
        key1,
        &format!("{did}#key-1"),
        domain.as_deref(),
        Some(&fresh_challenge()),
    )
    .map_err(|err| anyhow!("signing the DID document: {err}"))
}

/// The authority a DID hangs under, in the form a proof's `domain` takes: the first
/// `did:wba:` segment, with a `%3Aport` suffix removed. `None` for a DID this client cannot
/// place, and the proof then carries no domain rather than a wrong one.
fn domain_from_did(did: &str) -> Option<String> {
    let authority = did.strip_prefix("did:wba:")?.split(':').next()?;
    let authority = authority.replace("%3A", ":").replace("%3a", ":");
    let host = authority.split(':').next().filter(|host| !host.is_empty())?;
    Some(host.to_ascii_lowercase())
}

/// A 16-byte nonce as 32 hex characters — the challenge shape awiki's registration requires.
pub fn fresh_challenge() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The document with its `proof` removed, for comparing two documents without comparing
/// their proofs.
///
/// There is no such thing as two equal proofs: every one carries a `created` timestamp, so a
/// byte comparison of two whole documents says "changed" even when the only thing that moved
/// is the clock. Comparing what the proof *covers* is the question a publisher actually has —
/// is there anything here the host does not already serve.
pub fn without_proof(document: &Value) -> Value {
    let mut bare = document.clone();
    if let Some(object) = bare.as_object_mut() {
        object.remove("proof");
    }
    bare
}

fn pair(key: &PrivateKeyMaterial) -> StoredKeyPair {
    StoredKeyPair {
        private_key_pem: key.to_pem(),
        public_key_pem: key.public_key().to_pem(),
    }
}

fn public_bytes(key: &PublicKeyMaterial) -> Vec<u8> {
    match key {
        anp::PublicKeyMaterial::Ed25519(verifying) => verifying.to_bytes().to_vec(),
        anp::PublicKeyMaterial::X25519(bytes) => bytes.to_vec(),
        other => unreachable!("a device key is Ed25519 or X25519, got {other:?}"),
    }
}

/// `Multikey`: the multicodec prefix for the algorithm, then the raw key, in base58-btc
/// multibase (ANP-03; `z` is the base58-btc multibase marker).
fn multibase(prefix: u8, key: &[u8]) -> String {
    let mut bytes = vec![prefix, 0x01];
    bytes.extend_from_slice(key);
    format!("z{}", bs58::encode(bytes).into_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use anp::authentication::did_transition::{
        resolve_current_did, InMemoryTransitionCache, TransitionAssurance, TransitionStatus,
        DEFAULT_MAX_TRANSITION_HOPS,
    };

    use super::*;
    use crate::message::resolve::document_in_crate_form;
    use crate::identity::did::test_support::mint;

    #[test]
    fn a_successor_moves_the_fingerprint_and_nothing_else() {
        let older = mint("alice");
        let next = successor_of(&older).unwrap();

        assert_ne!(next.did, older.did);
        // The stable subject path is what makes the server treat this as the same account
        // (§2.5.3) — and what `verify_transition_hop` refuses the hop over if it moved.
        let before = parse_did_wba_e1(&older.did).unwrap();
        let after = parse_did_wba_e1(&next.did).unwrap();
        assert_eq!(before.stable_subject_path, after.stable_subject_path);
        assert_ne!(before.fingerprint, after.fingerprint);
        assert!(next.did.starts_with("did:wba:did.example.com:user:alice:e1_"));

        // Everything an update carries over: the account, not a new one.
        assert_eq!(next.agent, older.agent);
        assert_eq!(next.profile, older.profile);
        assert_eq!(next.handle, older.handle);
        assert_eq!(next.did_host, older.did_host);
        assert_eq!(next.created_at, older.created_at);
        assert_eq!(next.device_id, older.device_id);
        // The service entry is rebuilt from the retiring document, not from the host.
        let (_, service_did) = message_service(&next.did_document, &next.did).unwrap();
        assert_eq!(service_did, "did:wba:svc.example.com");
    }

    #[test]
    fn a_retirement_document_is_the_one_on_file_marked_retired() {
        let older = mint("alice");
        let next = successor_of(&older).unwrap();
        let key1 = load_stored_key(&older.keys["key-1"]).unwrap();

        let retired = retirement_document(&older.did_document, &older.did, &next.did, &key1).unwrap();

        assert_eq!(retired["id"], older.did_document["id"]);
        assert_eq!(retired["deactivated"], true);
        assert_eq!(retired["successorDid"], next.did);
        // Not a document composed here: the same verification methods, so the DID server is
        // asked to retire what it published.
        assert_eq!(retired["verificationMethod"], older.did_document["verificationMethod"]);
        assert_eq!(retired["service"], older.did_document["service"]);
        // One proof, over the retired document — the old one covered a document without
        // `deactivated`, so keeping it would assert something no longer true.
        assert!(retired["proof"].is_object());
        assert_ne!(retired["proof"]["proofValue"], older.did_document["proof"]["proofValue"]);
    }

    #[test]
    fn a_retirement_document_for_another_did_is_refused() {
        let older = mint("alice");
        let next = successor_of(&older).unwrap();
        let key1 = load_stored_key(&older.keys["key-1"]).unwrap();

        let err = retirement_document(&older.did_document, &next.did, &next.did, &key1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot be the base"), "{err}");
    }

    /// The shape `awiki` and `anpio-key` verify: base58-btc `proofValue`, the document's
    /// `@context` folded into the signing input **and kept in the proof object**, plus the
    /// `domain` and `challenge` the host's registration asks for.
    ///
    /// The verdict is `anp` 1.0.6's own binding check — the code path both of them run — not
    /// a string match on the prefix.
    #[test]
    fn a_minted_document_binds_under_the_crate_verifier() {
        let identity = mint("alice");
        let document = &identity.did_document;
        // The fold only happens when the document has one, so the fixture has to have it for
        // this test to be about the case that used to fail.
        let context = document
            .get("@context")
            .expect("the e1 document carries @context");

        assert!(anp::authentication::validate_did_document_binding(document, true));
        // Accepted as it stands: the canonical form is the first form the crate tries, so the
        // fetch path never reaches its legacy re-encoding.
        assert_eq!(document_in_crate_form(document), Some(document.clone()));

        let proof = document["proof"].as_object().expect("the document carries a proof");
        // The host reads the proof options as stored, so dropping this field here would sign
        // one input and publish another.
        assert_eq!(proof.get("@context"), Some(context), "the proof must keep @context");
        assert_eq!(proof.get("domain"), Some(&json!("did.example.com")));
        let challenge = proof["challenge"].as_str().expect("a challenge");
        assert_eq!(challenge.len(), 32);
        assert!(challenge.chars().all(|c| c.is_ascii_hexdigit()));
        let proof_value = proof["proofValue"].as_str().expect("a proofValue");
        let signature = bs58::decode(proof_value.strip_prefix('z').expect("base58-btc multibase"))
            .into_vec()
            .expect("decodable base58-btc");
        assert_eq!(signature.len(), 64);
        assert_eq!(document["@context"], *context);
    }

    /// The same on a document with no `@context` — the branch where there is nothing to fold.
    #[test]
    fn a_document_without_a_context_binds_too() {
        let identity = mint("alice");
        let mut bare = without_proof(&identity.did_document);
        bare.as_object_mut().unwrap().remove("@context");
        let key1 = load_stored_key(&identity.keys["key-1"]).unwrap();

        let signed = resign_document(&bare, &identity.did, &key1).unwrap();

        assert!(anp::authentication::validate_did_document_binding(&signed, true));
        assert!(!signed["proof"].as_object().unwrap().contains_key("@context"));
    }

    /// Re-proving does not touch the document's own `@context`: it is folded into the signing
    /// input and read back by the verifier, never moved or rewritten.
    #[test]
    fn re_proving_keeps_the_documents_context() {
        let identity = mint("alice");
        let key1 = load_stored_key(&identity.keys["key-1"]).unwrap();
        let context = identity.did_document["@context"].clone();

        let resigned = resign_document(&identity.did_document, &identity.did, &key1).unwrap();

        assert_eq!(resigned["@context"], context);
        assert!(anp::authentication::validate_did_document_binding(&resigned, true));
    }

    /// The test that matters: the hop this client builds is one the crate can **verify**.
    ///
    /// The daemon's chain walk is `anp`'s, so "our documents are self-consistent" is not the
    /// question — "does the verifier accept them" is. Run the real walk over the pair, with
    /// the same re-encoding the fetch path applies (TODO5 §8-J, third pit).
    #[test]
    fn the_crate_walks_the_hop_these_two_documents_make() {
        let older = mint("alice");
        let next = successor_of(&older).unwrap();
        let key1 = load_stored_key(&older.keys["key-1"]).unwrap();
        let retired = retirement_document(&older.did_document, &older.did, &next.did, &key1).unwrap();

        let old_did = older.did.clone();
        let new_did = next.did.clone();
        let fetcher = |target: &str| -> std::result::Result<Value, String> {
            let document = if target == old_did {
                retired.clone()
            } else {
                next.did_document.clone()
            };
            document_in_crate_form(&document).ok_or_else(|| format!("{target} does not bind under either convention"))
        };
        let mut cache = InMemoryTransitionCache::default();
        let result = resolve_current_did(
            &old_did,
            &fetcher,
            &HashMap::new(),
            &mut cache,
            DEFAULT_MAX_TRANSITION_HOPS,
        )
        .expect("the hop must verify");

        assert_eq!(result.current_did, new_did);
        assert_eq!(result.status, TransitionStatus::Superseded);
        assert_eq!(result.hops.len(), 1);
        // Signed by key-1, the key whose fingerprint is the DID: `verified`, not the
        // `provider_asserted` a proof-less retirement would fall back to.
        assert_eq!(result.hops[0].assurance, TransitionAssurance::Verified);
    }
}

/// Test-only fixtures other modules' tests need.
///
/// An identity with no host and no network behind it: every input `create_identity` wants is
/// a string, so a successor/retirement pair — or a signed ANP-02 request — can be exercised
/// offline. Shared rather than copied, because a second `mint` would be a second idea of
/// what a well-formed identity looks like.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn mint(agent: &str) -> Identity {
        create_identity(CreateIdentityInput {
            authority: "did.example.com".to_string(),
            domain: "did.example.com".to_string(),
            agent: agent.to_string(),
            profile: "default".to_string(),
            device: None,
            handle: agent.to_string(),
            did_host_url: "https://did.example.com".to_string(),
            service_endpoint: "https://svc.example.com/anp".to_string(),
            service_did: "did:wba:svc.example.com".to_string(),
        })
        .unwrap()
    }
}
