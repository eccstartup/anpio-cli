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
//! 3. **The `proofValue` encoding.** `anp::proof::complete_w3c_proof` writes base64url;
//!    ANP-03 §2.5.5 and the awiki host both require base58-btc multibase (`z…`). The
//!    signing input is identical on both sides (`sha256(jcs(proof))‖sha256(jcs(unsigned
//!    document))`), so only the encoding has to be redone.

use std::collections::BTreeMap;

use anp::authentication::device_manifest::{
    build_vnext_did_document, DeviceManifestEntry, PROFILE_CORE_BINDING_V1, PROFILE_GROUP_BASE_V2,
    PROFILE_GROUP_E2EE_V2, PROFILE_IDENTITY_DISCOVERY_V1,
};
use anp::authentication::did_wba::{
    build_anp_message_service, create_did_wba_document, AnpMessageServiceOptions, DidDocumentOptions,
    DidProfile,
};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use serde_json::{json, Map, Value};

use super::store::{Identity, StoredKeyPair};

pub struct CreateIdentityInput {
    /// The host's DID authority — the segment after `did:wba:` in the host's own service
    /// DID, e.g. `localhost%3A8000`. Taken from the host rather than re-derived here:
    /// an identity's DID hangs under the host's, so the host decides what its authority
    /// is (its `AWIKI_SERVICE_DID`; see `awiki-open-server/app/settings.py`).
    pub authority: String,
    pub agent: String,
    pub profile: String,
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

/// Split a DID authority into the hostname and port `create_did_wba_document` wants,
/// undoing ANP-03 §2.1's `%3A` encoding.
fn split_authority(authority: &str) -> Result<(String, Option<u16>)> {
    match authority.split_once("%3A") {
        None => Ok((authority.to_string(), None)),
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .with_context(|| format!("{authority} does not end in a port"))?;
            Ok((host.to_string(), Some(port)))
        }
    }
}

/// Mint a fresh identity. Nothing is written; the caller saves it.
pub fn create_identity(input: CreateIdentityInput) -> Result<Identity> {
    let device_id = format!("{}/{}", input.agent, input.profile);

    let service = build_anp_message_service(
        "#anp-message",
        input.service_endpoint.clone(),
        AnpMessageServiceOptions::default()
            .with_service_did(input.service_did.clone())
            .with_profiles(["anp.direct.base.v1"])
            .with_security_profiles(["transport-protected"]),
    );

    let (host, port) = split_authority(&input.authority)?;

    let options = DidDocumentOptions {
        port,
        path_segments: vec!["user".to_string(), input.agent.clone()],
        services: vec![service],
        // P6's device pair is minted below; the crate's `#key-2`/`#key-3` pair is the
        // older single-device layout and does not survive `build_vnext_did_document`.
        enable_e2ee: false,
        did_profile: DidProfile::E1,
        ..Default::default()
    };
    let bundle = create_did_wba_document(&host, options)
        .map_err(|err| anyhow!("building the DID document: {err}"))?;
    let did = bundle
        .did()
        .ok_or_else(|| anyhow!("the created document has no id"))?
        .to_string();

    let root_key_id = format!("{did}#key-1");
    let root_method = bundle
        .did_document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find(|method| method.get("id").and_then(Value::as_str) == Some(&root_key_id))
        })
        .ok_or_else(|| anyhow!("the created document has no {root_key_id}"))?;

    let device = DeviceKeys::generate(&did, &device_id);
    let document = build_vnext_did_document(
        &base_document(&did, &bundle.did_document),
        &root_key_id,
        root_method,
        &device.entry,
        &device.signing_method,
        &device.agreement_method,
    )
    .map_err(|err| anyhow!("assembling the device DID document: {err}"))?;

    let key1 = bundle
        .load_private_key("key-1")
        .map_err(|err| anyhow!("loading #key-1: {err}"))?;
    let signed = generate_w3c_proof(
        &document,
        &key1,
        &root_key_id,
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            created: Some(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            domain: None,
            challenge: None,
        },
    )
    .map_err(|err| anyhow!("signing the DID document: {err}"))?;
    let signed_document = to_multibase_proof_value(signed)?;

    let mut keys = bundle
        .keys
        .iter()
        .map(|(fragment, pair)| {
            (
                fragment.clone(),
                StoredKeyPair {
                    private_key_pem: pair.private_key_pem.clone(),
                    public_key_pem: pair.public_key_pem.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    keys.insert(device.signing_fragment.clone(), device.signing_pair());
    keys.insert(device.agreement_fragment.clone(), device.agreement_pair());

    Ok(Identity {
        did,
        device_id,
        agent: input.agent,
        profile: input.profile,
        handle: input.handle,
        did_host: input.did_host_url,
        created_at: Utc::now().to_rfc3339(),
        keys,
        did_document: signed_document,
    })
}

/// The fields `build_vnext_did_document` does not manage: the id, the JSON-LD contexts of
/// the profile, and the service entries the host made the document advertise.
fn base_document(did: &str, built: &Value) -> Value {
    let mut base = Map::new();
    base.insert("id".to_string(), Value::String(did.to_string()));
    for field in ["@context", "service"] {
        if let Some(value) = built.get(field) {
            base.insert(field.to_string(), value.clone());
        }
    }
    Value::Object(base)
}

/// The device's own key pair, and the two verification methods P6 binds it through.
///
/// Distinct from the DID root by construction, which is the whole point: a device that
/// reuses the root makes the DID host refuse the document, because then the root would be
/// authorizing itself as a token holder.
struct DeviceKeys {
    signing: PrivateKeyMaterial,
    agreement: PrivateKeyMaterial,
    signing_fragment: String,
    agreement_fragment: String,
    signing_method: Value,
    agreement_method: Value,
    entry: DeviceManifestEntry,
}

impl DeviceKeys {
    fn generate(did: &str, device_id: &str) -> Self {
        let signing = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(
            &mut rand::rngs::OsRng,
        ));
        // Same construction the crate uses for its own X25519 agreement key.
        let agreement = PrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::from(
            rand::random::<[u8; 32]>(),
        ));

        let signing_fragment = format!("{device_id}-sign");
        let agreement_fragment = format!("{device_id}-agreement");
        let signing_id = format!("{did}#{signing_fragment}");
        let agreement_id = format!("{did}#{agreement_fragment}");

        // Both validators (`anp`'s and the host's) read the algorithm off the multicodec
        // prefix — `0xed01` Ed25519, `0xec01` X25519 — so the `Multikey` type says
        // nothing on its own and is right for both.
        let signing_method = json!({
            "id": signing_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase(0xed, &public_bytes(&signing)),
        });
        let agreement_method = json!({
            "id": agreement_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": multibase(0xec, &public_bytes(&agreement)),
        });

        let entry = DeviceManifestEntry {
            device_id: device_id.to_string(),
            signing_key_id: signing_id,
            e2ee_key_id: agreement_id,
            // The **whole** dependency closure: P6's `require_dependencies` rejects a bare
            // `anp.group.e2ee.v2`, because a device claiming group E2EE claims everything
            // it builds on (TODO5 §6, Phase 0 result 3a).
            profiles: [
                PROFILE_CORE_BINDING_V1,
                PROFILE_IDENTITY_DISCOVERY_V1,
                PROFILE_GROUP_BASE_V2,
                PROFILE_GROUP_E2EE_V2,
            ]
            .iter()
            .map(|profile| profile.to_string())
            .collect(),
        };

        Self {
            signing,
            agreement,
            signing_fragment,
            agreement_fragment,
            signing_method,
            agreement_method,
            entry,
        }
    }

    fn signing_pair(&self) -> StoredKeyPair {
        pair(&self.signing)
    }

    fn agreement_pair(&self) -> StoredKeyPair {
        pair(&self.agreement)
    }
}

fn pair(key: &PrivateKeyMaterial) -> StoredKeyPair {
    StoredKeyPair {
        private_key_pem: key.to_pem(),
        public_key_pem: key.public_key().to_pem(),
    }
}

fn public_bytes(key: &PrivateKeyMaterial) -> Vec<u8> {
    match key.public_key() {
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

/// Re-encode the proof's `proofValue` from base64url to base58-btc multibase.
///
/// Only the encoding changes: the signature bytes and the signing input are untouched, so
/// the proof still verifies — against the awiki host's verifier, which base58-decodes.
fn to_multibase_proof_value(mut document: Value) -> Result<Value> {
    let proof = document
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("the signed document has no proof"))?;
    let encoded = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the proof has no proofValue"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("decoding the proof's base64url signature")?;
    if signature.len() != 64 {
        bail!("an Ed25519 signature is 64 bytes; got {}", signature.len());
    }
    proof.insert(
        "proofValue".to_string(),
        Value::String(format!("z{}", bs58::encode(signature).into_string())),
    );
    Ok(document)
}
