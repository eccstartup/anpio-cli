//! Phase 0 spike, kept runnable ([TODO5.md](../../../../TODO5.md) §6).
//!
//! One question, answered by running: **can the official `anp` crate (1.0.5) drive the P6
//! device half?** So this mints a device identity, builds a DID document carrying a
//! `deviceManifest` that names that device, opens the MLS store, and generates a KeyPackage
//! — the artefact `group.e2ee.publish_key_package` takes.
//!
//! It deliberately does **not** talk to the service; that needs the transport in
//! `src/message`, which is Phase 1. The result is recorded in TODO5 §6, and the pieces
//! worth keeping (which key signs the binding, the full dependency closure) are the two
//! things this file pins down.
//!
//! ```text
//! cargo run --example phase0_key_package -- /tmp/anpiocli-spike
//! ```

use std::path::PathBuf;

use anp::authentication::device_manifest::{
    DeviceManifest, DeviceManifestEntry, DEVICE_MANIFEST_TYPE, PROFILE_CORE_BINDING_V1,
    PROFILE_GROUP_BASE_V2, PROFILE_GROUP_E2EE_V2, PROFILE_IDENTITY_DISCOVERY_V1,
};
use anp::authentication::did_wba::{create_did_wba_document, DidDocumentOptions};
use anp::group_e2ee::operations::v2::{generate_key_package_v2, V2GenerateKeyPackageInput};
use anp::group_e2ee::storage::ImCoreSqliteGroupMlsStore;
use anp::PrivateKeyMaterial;
use serde_json::Value;

const DEVICE_ID: &str = "device-1";

fn main() -> anyhow::Result<()> {
    let base = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "./.anpiocli-spike".to_string()),
    );

    // 1. A device identity. `enable_e2ee` (on by default) is what makes the document carry
    //    a `key-2` signing VM and a `key-3` agreement VM.
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())?;
    let did = bundle
        .did()
        .ok_or_else(|| anyhow::anyhow!("created document has no id"))?
        .to_string();
    println!("did = {did}");
    println!("key fragments = {:?}", bundle.keys.keys().collect::<Vec<_>>());

    // `key-1` is the Ed25519 identity key; the P6 `did_wba_binding` verifies against it.
    // (`key-2` is a Secp256r1 E2EE-signing key and `key-3` an X25519 agreement key —
    // neither can verify an MLS Ed25519 binding.)
    let signing_vm = vm_id(&bundle.did_document, "key-1")
        .ok_or_else(|| anyhow::anyhow!("document has no #key-1 verification method"))?;
    let e2ee_vm = vm_id(&bundle.did_document, "key-3")
        .ok_or_else(|| anyhow::anyhow!("document has no #key-3 verification method"))?;
    println!("device signing vm = {signing_vm}");

    // 2. The deviceManifest entry naming this device — the writer side the TS repo does not
    //    have (TODO5 §2). A P6 entry must carry the whole dependency closure, not just
    //    `anp.group.e2ee.v2`: `require_dependencies` rejects a bare profile list.
    let entry = DeviceManifestEntry {
        device_id: DEVICE_ID.to_string(),
        signing_key_id: signing_vm.clone(),
        e2ee_key_id: e2ee_vm,
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
    let mut document = bundle.did_document.clone();
    document
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("document is not an object"))?
        .insert(
            "deviceManifest".to_string(),
            serde_json::to_value(DeviceManifest {
                manifest_type: DEVICE_MANIFEST_TYPE.to_string(),
                devices: vec![entry],
            })?,
        );

    // 3. The device signing key the KeyPackage's `did_wba_binding` is signed with.
    //    `generate_key_package_v2` is the one operation that takes a private key —
    //    everything else keeps its keys inside the store.
    let signing_pem = bundle
        .private_key_pem("key-1")
        .ok_or_else(|| anyhow::anyhow!("no private key for #key-1"))?;
    let device_key = PrivateKeyMaterial::from_pem(signing_pem)?;

    // 4. The MLS store: one sqlite path + an fs2 lock, scoped by (owner, device).
    let store = ImCoreSqliteGroupMlsStore::from_local_state_sqlite_path(
        base.join("local_state.sqlite"),
        "spike-identity",
        &did,
        DEVICE_ID,
    )?;
    println!("mls state db = {}", store.state_db_path().display());

    // 5. Generate the KeyPackage. Its shape was checked field by field against the
    //    service's `keyPackageShapeProblem` (see TODO5 §6): this is publishable as-is.
    let now = chrono::Utc::now();
    let input = V2GenerateKeyPackageInput {
        owner_did: did.clone(),
        owner_device_id: DEVICE_ID.to_string(),
        verification_method: signing_vm,
        key_package_id: format!("kp-{}", now.timestamp_millis()),
        issued_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::days(7)).to_rfc3339(),
        now: now.to_rfc3339(),
        draft_extension_negotiated: true,
        request_id: format!("req-{}", now.timestamp_millis()),
    };
    let key_package = generate_key_package_v2(&store, input, &document, &device_key)?;

    println!("key_package_id = {}", key_package.key_package_id);
    println!("suite          = {}", key_package.suite);
    println!(
        "mls_key_package_b64u len = {}",
        key_package.mls_key_package_b64u.len()
    );
    println!("{}", serde_json::to_string_pretty(&key_package)?);

    Ok(())
}

/// The full id of the verification method whose id ends with `#{fragment}`.
fn vm_id(document: &Value, fragment: &str) -> Option<String> {
    document
        .get("verificationMethod")?
        .as_array()?
        .iter()
        .filter_map(|vm| vm.get("id").and_then(Value::as_str))
        .find(|id| id.ends_with(&format!("#{fragment}")))
        .map(str::to_string)
}
