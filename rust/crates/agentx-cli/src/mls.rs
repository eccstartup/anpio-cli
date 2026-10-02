//! The device half of P6: the MLS state this client keeps, and the artefacts it makes with it.
//!
//! Everything here is the official `anp` crate's `group_e2ee`. That is the whole reason this
//! client is Rust (TODO5 §0): MLS exists only in that crate, and calling it from here removes
//! the napi layer [client-mls.md](../../../../docs/design/client-mls.md) §3 had planned for
//! the TS CLI — TODO5 §1 cancels that whole shell rather than writing it twice.
//!
//! **The store is key material**, under the same rule as the identity file (TODO4 §E): it
//! holds this device's MLS private state, which is what the group's plaintext decrypts to.
//! Backups, debugging and sharing are governed by that one rule, and it is why this lives
//! inside the identity's own directory instead of anywhere a cache would go.
//!
//! Nothing in here talks to a service. What the service accepts is `group.e2ee.*`, which is
//! [`crate::group_e2ee`]'s half; this file only produces and consumes the objects that go in
//! and come out of those bodies.

use std::path::PathBuf;

use anp::group_e2ee::operations::v2::{generate_key_package_v2, V2GenerateKeyPackageInput};
use anp::group_e2ee::storage::ImCoreSqliteGroupMlsStore;
use anp::group_e2ee::v2_models::V2GroupKeyPackage;
use anp::PrivateKeyMaterial;
use chrono::{Duration, Utc};

use crate::error::{AgentxError, Result};
use crate::identity::{Identity, IdentityLocation};
use crate::message::{document_in_crate_form, uuid_v4};

/// How long a KeyPackage this client mints claims to be good for.
///
/// P6 §7.3 makes `expires_at` a SHOULD, and §8.2.4 lets the service hand out an expired one
/// when the cabinet has nothing fresher — so this is not a hard gate on anything. It is the
/// window in which "somebody may still use this to add me" is true, and a week is long enough
/// that publishing is not a chore while short enough that a device that stopped publishing
/// stops being addable.
pub const KEY_PACKAGE_VALID_DAYS: i64 = 7;

/// `<root>/<agent>/<profile>/mls/` — where this identity's MLS state goes.
///
/// Beside the identity file rather than under a second naming scheme: client-mls.md §4 asks
/// for one answer to "where does an identity's state live", and the identity's DID is what
/// every object in here is scoped by. `messages.db` (TODO5 §4, Phase 2) is its sibling.
pub fn mls_dir(location: &IdentityLocation) -> PathBuf {
    location.dir().join("mls")
}

/// The MLS store for one identity, opened lazily (nothing is written until an operation runs).
///
/// The crate scopes everything it keeps by `(owner_identity_id, device_id)`, and hashes those
/// two to name the directory under the path given here. `owner_identity_id` is the **local
/// slot** (`agent/profile`), not the DID: it is what identifies this identity across a key
/// rotation or a DID migration, and the DID is recorded in the rows either way.
///
/// The file name in the path is the crate's own convention and only its **parent directory**
/// is used — the database it opens is `<mls dir>/group_mls/<scope>/mls_state.sqlite`.
pub fn store_for(
    location: &IdentityLocation,
    identity: &Identity,
) -> Result<ImCoreSqliteGroupMlsStore> {
    ImCoreSqliteGroupMlsStore::from_local_state_sqlite_path(
        mls_dir(location).join("local_state.sqlite"),
        format!("{}/{}", location.agent, location.profile),
        &identity.did,
        &identity.device_id,
    )
    .map_err(|err| AgentxError::MessageInvalid(format!("opening the MLS store: {err}")))
}

/// This device's signing key, and the verification method id it is published as.
///
/// P6 §6.4 item 3 wants the KeyPackage's `did_wba_binding.verification_method` to be *this
/// device's* `signing_key_id`, and item 5 wants the binding signed by that key. So the key
/// has to be the device signing key, not `key-1`: the document puts the device key in
/// `assertionMethod` and the roots in `authentication`, and §6.4 is pointing at the device
/// half. It is Ed25519 by construction ([`crate::identity::did`]), which is the algorithm the
/// MLS binding verifies with.
///
/// `generate_key_package_v2` is the one operation in this module that takes a private key at
/// all — every other MLS operation keeps its keys inside the store (client-mls.md §5 #4).
pub fn device_signing_key(identity: &Identity) -> Result<(String, PrivateKeyMaterial)> {
    let fragment = format!("{}-sign", identity.device_id);
    let key = identity.keys.get(&fragment).ok_or_else(|| {
        AgentxError::MessageInvalid(format!(
            "{} has no {fragment}; re-run: agentx-cli did create",
            identity.did
        ))
    })?;
    let material = PrivateKeyMaterial::from_pem(&key.private_key_pem).map_err(|err| {
        AgentxError::MessageInvalid(format!("cannot read {fragment} from the store: {err}"))
    })?;
    Ok((format!("{}#{fragment}", identity.did), material))
}

/// One KeyPackage for this device, ready to publish (P6 §7.3).
///
/// `key_package_id` is the name this package will be filed under, here and in the service's
/// cabinet, and the store refuses a **second** generation under an id it already holds
/// (`group.e2ee.key_package_consumed` — verified against the service, not read off the
/// crate). So it is not a retry knob: a publish that has to be sent again after the package
/// was minted is a `group.e2ee.get_key_package` read or a fresh id, not a re-mint. Passing
/// one at all is for naming — a script that has to refer to the package it just made.
pub fn generate_key_package(
    location: &IdentityLocation,
    identity: &Identity,
    key_package_id: &str,
    valid_for: Duration,
) -> Result<V2GroupKeyPackage> {
    let store = store_for(location, identity)?;
    let (verification_method, device_key) = device_signing_key(identity)?;
    // The crate verifies the issuer's binding itself, with no fallback for the proof
    // encoding its own `z…` branch assumes ([`crate::message::document_in_crate_form`]). So
    // the document goes in already in the form that check accepts; the alternative is a
    // document this client just resolved successfully coming back as
    // `Issuer DID document binding validation failed`.
    let document = document_in_crate_form(&identity.did_document).ok_or_else(|| {
        AgentxError::MessageInvalid(format!(
            "{}'s stored DID document is not bound to its own DID",
            identity.did
        ))
    })?;
    let now = Utc::now();

    let input = V2GenerateKeyPackageInput {
        owner_did: identity.did.clone(),
        owner_device_id: identity.device_id.clone(),
        verification_method,
        key_package_id: key_package_id.to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: (now + valid_for).to_rfc3339(),
        now: now.to_rfc3339(),
        // The **code** gate, not the advertising one (client-mls.md §6). The extension's
        // registered code point is a compile-time constant upstream, but every v2 operation
        // takes this flag at runtime — so the Profile is usable today and merely cannot be
        // advertised. `anp.get_capabilities` still withholds `anp.group.e2ee.v2`; that is
        // `capabilities.ts`'s `WITHHELD_PROFILES`, a different switch.
        draft_extension_negotiated: true,
        request_id: uuid_v4(),
    };

    generate_key_package_v2(&store, input, &document, &device_key)
        .map_err(|err| AgentxError::MessageInvalid(format!("generating a KeyPackage: {err}")))
}

/// A fresh `key_package_id` for a publish that was not given one.
///
/// Opaque and unique, with no meaning to anyone but the two stores that file it: §7.3 only
/// asks that it name one package, and the point of a fresh id per run is that a device may
/// hold several live packages at once — §8.2.4 hands out the freshest, so an older one
/// never blocks a newer.
pub fn new_key_package_id() -> String {
    format!("kp-{}", uuid_v4())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::StoredKeyPair;
    use std::collections::BTreeMap;

    fn identity(device_id: &str) -> Identity {
        let material = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(
            &mut rand::rngs::OsRng,
        ));
        let mut keys = BTreeMap::new();
        keys.insert(
            "key-1".to_string(),
            StoredKeyPair {
                private_key_pem: material.to_pem(),
                public_key_pem: material.public_key().to_pem(),
            },
        );
        Identity {
            did: "did:wba:example.com:user:test:e1_abc".to_string(),
            device_id: device_id.to_string(),
            agent: "test".to_string(),
            profile: "default".to_string(),
            handle: "test".to_string(),
            did_host: "https://example.com".to_string(),
            created_at: "2026-10-02T00:00:00Z".to_string(),
            keys,
            did_document: serde_json::json!({}),
        }
    }

    #[test]
    fn the_mls_directory_sits_beside_the_identity_file() {
        let location = IdentityLocation::new("test", "default");
        assert_eq!(mls_dir(&location), location.dir().join("mls"));
    }

    /// The device's key, not `key-1`: a document may only bind what it publishes as that
    /// device's `signing_key_id` (P6 §6.4 item 3).
    #[test]
    fn the_binding_key_is_the_devices_signing_key() {
        let identity = identity("test/default");
        let err = device_signing_key(&identity).unwrap_err();
        assert!(
            err.to_string().contains("test/default-sign"),
            "an identity with no device key must name the fragment it is missing: {err}"
        );
    }
}
