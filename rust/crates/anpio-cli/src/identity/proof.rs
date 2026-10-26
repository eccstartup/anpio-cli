//! The DID document's `DataIntegrityProof`: the proof configuration, the signing input, and
//! the `proofValue` encoding, in one place.
//!
//! The `anp` crate can do the same thing (`prepare_w3c_proof` / `complete_w3c_proof`), but
//! what it writes is the older dialect: a bare base64url `proofValue`, and proof options
//! that do not carry the document's `@context`. W3C `vc-di-eddsa` (`eddsa-jcs-2022`) asks
//! for something else, and it is what both `awiki` (via `anp` 1.0.6's verifier) and
//! `anpio-key` check:
//!
//! 1. `proofValue` is base58-btc multibase — the `z` prefix;
//! 2. the Create Proof step: *If unsecuredDocument.@context is present, set
//!    proof.@context to unsecuredDocument.@context*, and the signing input is
//!    `SHA256(JCS(proofConfig)) ‖ SHA256(JCS(document minus proof))`.
//!
//! `anp` 1.0.6's `verify_w3c_proof` reads a `z` proofValue through exactly that branch, so
//! re-encoding the legacy dialect's bytes would be a valid alphabet over an invalid signing
//! input — which is what a real document with `@context` used to come back as: rejected.
//!
//! The artifact carries **no** proof-level `@context`: the spec wants it in the signing
//! input, and a verifier restores it from the document. Carrying it would give one document
//! two spellings.

use anp::proof::{CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY};
use anp::{PrivateKeyMaterial, PublicKeyMaterial};
use anyhow::{anyhow, Result};
use chrono::Utc;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The public facts of one document proof. `type` and `cryptosuite` are not here — they are
/// fixed by the shape this client publishes.
pub(crate) struct Facts<'a> {
    pub verification_method: &'a str,
    pub purpose: &'a str,
    pub created: &'a str,
    pub domain: Option<&'a str>,
    pub challenge: Option<&'a str>,
}

/// Everything needed before the signature exists: the document, the proof object, and the
/// exact bytes to sign. No private key material.
pub(crate) struct Prepared {
    document: Value,
    proof_object: Map<String, Value>,
    signing_input: Vec<u8>,
    public: PublicKeyMaterial,
}

impl Prepared {
    /// The bytes the signer is given: the proof configuration's digest, then the document's.
    pub(crate) fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }
}

/// Assemble the proof configuration and the signing input for `document`.
pub(crate) fn prepare(
    document: &Value,
    public: &PublicKeyMaterial,
    facts: Facts<'_>,
) -> Result<Prepared> {
    let mut config = Map::new();
    config.insert("type".into(), json!(PROOF_TYPE_DATA_INTEGRITY));
    config.insert("created".into(), json!(facts.created));
    config.insert("verificationMethod".into(), json!(facts.verification_method));
    config.insert("proofPurpose".into(), json!(facts.purpose));
    config.insert("cryptosuite".into(), json!(CRYPTOSUITE_EDDSA_JCS_2022));
    for (name, value) in [("domain", facts.domain), ("challenge", facts.challenge)] {
        if let Some(value) = value {
            config.insert(name.into(), json!(value));
        }
    }

    let mut signing_document = document.clone();
    let object = signing_document
        .as_object_mut()
        .ok_or_else(|| unusable("the document to prove is not a JSON object"))?;
    // A re-proof covers the document as it now stands, so the old proof is not part of what
    // is signed.
    object.remove("proof");
    if let Some(context) = object.get("@context").cloned() {
        config.insert("@context".into(), context);
    }

    let mut signing_input = Vec::with_capacity(64);
    signing_input.extend_from_slice(&digest(&Value::Object(config.clone()))?);
    signing_input.extend_from_slice(&digest(&signing_document)?);

    Ok(Prepared {
        document: document.clone(),
        proof_object: config,
        signing_input,
        public: public.clone(),
    })
}

/// Attach `signature` to a prepared proof, after checking it is the key's own.
///
/// The self-check is not ceremony: a signature that does not verify here would be published
/// as a document no host accepts, and the failure would surface as a DID that silently stops
/// resolving.
pub(crate) fn complete(prepared: Prepared, signature: &[u8]) -> Result<Value> {
    if signature.len() != 64 {
        return Err(unusable(&format!(
            "an Ed25519 signature is 64 bytes; the signer produced {}",
            signature.len()
        )));
    }
    prepared
        .public
        .verify_message(&prepared.signing_input, signature)
        .map_err(|_| unusable("the signature does not match the key that was asked to make it"))?;

    let mut proof_object = prepared.proof_object;
    proof_object.remove("@context");
    proof_object.insert(
        "proofValue".into(),
        json!(format!("z{}", bs58::encode(signature).into_string())),
    );

    let mut document = prepared.document;
    let object = document
        .as_object_mut()
        .ok_or_else(|| unusable("the proven document stopped being a JSON object"))?;
    object.insert("proof".into(), Value::Object(proof_object));
    Ok(document)
}

/// Sign `document` with `key` and return it carrying the canonical proof.
///
/// Every document this client publishes is proved for `assertionMethod` at the moment it is
/// published, so those are not parameters.
pub(crate) fn sign_document(
    document: &Value,
    key: &PrivateKeyMaterial,
    verification_method: &str,
) -> Result<Value> {
    let prepared = prepare(
        document,
        &key.public_key(),
        Facts {
            verification_method,
            purpose: "assertionMethod",
            created: &timestamp(),
            domain: None,
            challenge: None,
        },
    )?;
    let signature = key
        .sign_message(prepared.signing_input())
        .map_err(|err| anyhow!("signing the DID document: {err}"))?;
    complete(prepared, &signature)
}

/// The `created` shape, the same one `anp` writes: `%Y-%m-%dT%H:%M:%SZ`.
pub(crate) fn timestamp() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn digest(value: &Value) -> Result<Vec<u8>> {
    let canonical = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| unusable(&format!("canonicalizing the proof input failed: {error}")))?;
    Ok(Sha256::digest(&canonical).to_vec())
}

fn unusable(why: &str) -> anyhow::Error {
    anyhow!("{why}")
}
