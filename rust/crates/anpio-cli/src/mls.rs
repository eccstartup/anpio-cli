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

use anp::group_e2ee::operations::v2::{
    abort_commit_v2, add_member_prepare_v2, create_group_prepare_v2, decrypt_received_v2,
    encrypt_v2, finalize_commit_v2, generate_key_package_v2, process_notice_v2,
    remove_member_prepare_v2, V2AddMemberInput, V2CreateGroupInput, V2DecryptInput,
    V2DecryptOutput, V2DidDocument, V2EncryptInput, V2FinalizeInput, V2GenerateKeyPackageInput,
    V2PreparedAdd, V2PreparedCreate, V2PreparedRemove, V2ProcessNoticeInput,
    V2ProcessNoticeOutput, V2RemoveMemberInput,
};
use anp::group_e2ee::storage::ImCoreSqliteGroupMlsStore;
use anp::group_e2ee::v2_models::{
    V2E2eeNotice, V2GroupAddBody, V2GroupApplicationPlaintext, V2GroupCipherObject,
    V2GroupControlMetadata, V2GroupCreateBody, V2GroupKeyPackage, V2GroupNoticeMetadata,
    V2GroupRemoveBody, V2GroupSendMetadata, V2GroupStateRef, V2ServiceMetadata, V2Target,
    GROUP_CIPHER_CONTENT_TYPE_V2, GROUP_E2EE_PROFILE_V2, GROUP_E2EE_SECURITY_PROFILE_V2,
};
use anp::PrivateKeyMaterial;
use chrono::{Duration, Utc};
use serde_json::Value;

use crate::custody::Operation;
use crate::error::{AnpioError, Result};
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
    .map_err(|err| AnpioError::MessageInvalid(format!("opening the MLS store: {err}")))
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
    // The MLS device key is minted by `did create` and lives in this store; an `anpio-key`
    // identity never has one. Delegating the device assertion is a `SIGN_PURPOSE` operation
    // (stage 2), so refuse through the capability table rather than a missing-key error.
    if let Some(custody) = &identity.custody {
        custody
            .require(Operation::Purpose, "group e2ee")
            .map_err(|err| AnpioError::MessageInvalid(format!("{err:#}")))?;
    }
    let fragment = format!("{}-sign", identity.device_id);
    let key = identity.keys.get(&fragment).ok_or_else(|| {
        AnpioError::MessageInvalid(format!(
            "{} has no {fragment}; re-run: anpio-cli did create",
            identity.did
        ))
    })?;
    let material = PrivateKeyMaterial::from_pem(&key.private_key_pem).map_err(|err| {
        AnpioError::MessageInvalid(format!("cannot read {fragment} from the store: {err}"))
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
    let document = did_document_in_crate_form(identity)?;
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
        .map_err(|err| AnpioError::MessageInvalid(format!("generating a KeyPackage: {err}")))
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

/// A fresh `pending_commit_id` for a control operation (P6 §13.6).
///
/// The crate's name for the **local** half of a state-changing P6 call: `create` / `add` /
/// `remove` are three-phase — prepare (write-ahead, here), send (the service decides), then
/// finalize or abort. The id is what ties the third phase back to the first, so it exists
/// before anything is sent and is this client's to mint. `pc-` only distinguishes it by eye
/// from a `kp-…` package id in the store's rows.
pub fn new_pending_commit_id() -> String {
    format!("pc-{}", uuid_v4())
}

/// Every `create` this client sends is initial: §9.2.1's creator is the caller, and the
/// epoch §9.2.3 asks for starts at `0`.
///
/// The crate owns those two, so what is left for the caller is the group being initialised,
/// where its P4 state stands, who signs as the creator device, and which service is being
/// asked. `group_state_version` comes from P4 [`crate::group`]'s `group.get_info`; the
/// service re-checks only that it is a decimal string (§9.2.3), while §14.1 L1707 is why
/// `create` MUST NOT advance it — so the value sent is the group's current one, not one
/// this client computes.
pub struct CreateInput<'a> {
    pub group_did: &'a str,
    pub group_state_version: &'a str,
    /// The creator's own KeyPackage — §9.2.3 requires `owner_did` / `owner_device_id` to be
    /// this device, and `create_group_prepare_v2` refuses anything else, so it is minted here
    /// ([`generate_key_package`]) rather than fetched: §8.2's cabinet is for adding *others*.
    pub creator_key_package: &'a V2GroupKeyPackage,
    /// The servicing host's `serviceDid`. §4.4.1 L292–293 keeps `create` service-scoped even
    /// though the group now exists, so this — not `group_did` — is what goes in `meta.target`.
    pub service_did: &'a str,
    pub operation_id: &'a str,
}

/// A prepared `group.e2ee.create`: the wire body, plus the local handle that finishes it.
pub struct PreparedCreate {
    pub pending_commit_id: String,
    pub body: V2GroupCreateBody,
}

/// Phase one of `create`: all of the MLS work, nothing on the wire.
///
/// The order matters — this writes to the store before the service has heard anything, which
/// is the point (the client must not be the one to lose a commit the service accepted), and
/// it is why a failure here costs nothing remote and a failure *after* it has to be answered
/// by [`finalize_commit`] or [`abort_commit`].
pub fn prepare_create(
    location: &IdentityLocation,
    identity: &Identity,
    input: CreateInput<'_>,
) -> Result<PreparedCreate> {
    let store = store_for(location, identity)?;
    let document = did_document_in_crate_form(identity)?;
    let pending_commit_id = new_pending_commit_id();
    let now = Utc::now().to_rfc3339();

    let prepared: V2PreparedCreate = create_group_prepare_v2(
        &store,
        V2CreateGroupInput {
            meta: V2ServiceMetadata {
                anp_version: None,
                profile: GROUP_E2EE_PROFILE_V2.to_string(),
                // §4.3 L273: `create` is one of the four `group-e2ee` control methods.
                security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_string(),
                sender_did: identity.did.clone(),
                sender_device_id: identity.device_id.clone(),
                target: V2Target {
                    kind: "service".to_string(),
                    did: input.service_did.to_string(),
                },
                operation_id: input.operation_id.to_string(),
                created_at: Some(now.clone()),
            },
            group_state_ref: V2GroupStateRef {
                group_did: input.group_did.to_string(),
                group_state_version: input.group_state_version.to_string(),
                // §7.2 L499 makes this a condition ("if the policy has been hashed"); this
                // service does not hash P4 policies, so there is nothing to put here and the
                // field stays absent rather than carrying an invented digest.
                policy_hash: None,
                roster_hash: None,
            },
            creator_key_package: input.creator_key_package.clone(),
            creator_did_document: document,
            now,
            // The code gate, as in [`generate_key_package`].
            draft_extension_negotiated: true,
            pending_commit_id: pending_commit_id.clone(),
            request_id: uuid_v4(),
        },
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("preparing group.e2ee.create: {err}")))?;

    Ok(PreparedCreate {
        pending_commit_id,
        body: prepared.body,
    })
}

/// What `add` needs from the caller (P6 §9.3).
///
/// The pair §9.3.3 keys on — `member_did` together with `member_device_id` — is **not** here:
/// the crate takes it from the KeyPackage itself (`V2GroupAddBody.member_did` is
/// `group_key_package.owner_did`), so passing it twice would be two answers to one question.
/// The command face still names the device, because that is what it fetches the package with.
pub struct AddInput<'a> {
    pub group_did: &'a str,
    /// The group's current P4 version, read the same way `create` reads it.
    pub group_state_version: &'a str,
    /// The member's **published** package, §8.2.3 — this is what the commit covers, so it is
    /// the member's own device's package and not one of this client's.
    pub group_key_package: &'a V2GroupKeyPackage,
    /// The member's DID document. Evidence, not context: the crate re-runs the package's
    /// `did_wba_binding` against it, with no fallback for the proof encoding its own `z…`
    /// branch assumes ([`crate::message::document_in_crate_form`]).
    pub member_did_document: Value,
    pub operation_id: &'a str,
}

/// A prepared `group.e2ee.add`: the wire body, plus the local handle that finishes it.
pub struct PreparedAdd {
    pub pending_commit_id: String,
    pub body: V2GroupAddBody,
}

/// Phase one of `add`, the same shape as [`prepare_create`] — and the same order.
///
/// The one thing that differs is the target: §4.4.2 makes `add`/`remove`/`send`
/// **group-addressed**, so `meta.target.did` is the group's DID rather than a service DID.
/// That is not a stylistic choice — the crate enforces it (`validate_control_meta` refuses a
/// target that is not `group_state_ref.group_did`), and the service splits the two families
/// on it too (`targetMode` in its method table).
pub fn prepare_add(
    location: &IdentityLocation,
    identity: &Identity,
    input: AddInput<'_>,
) -> Result<PreparedAdd> {
    let store = store_for(location, identity)?;
    let pending_commit_id = new_pending_commit_id();
    let now = Utc::now().to_rfc3339();

    let prepared: V2PreparedAdd = add_member_prepare_v2(
        &store,
        V2AddMemberInput {
            meta: V2GroupControlMetadata {
                anp_version: None,
                profile: GROUP_E2EE_PROFILE_V2.to_string(),
                security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_string(),
                sender_did: identity.did.clone(),
                sender_device_id: identity.device_id.clone(),
                target: V2Target {
                    kind: "group".to_string(),
                    did: input.group_did.to_string(),
                },
                operation_id: input.operation_id.to_string(),
                created_at: Some(now.clone()),
            },
            group_state_ref: V2GroupStateRef {
                group_did: input.group_did.to_string(),
                group_state_version: input.group_state_version.to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            group_key_package: input.group_key_package.clone(),
            member_did_document: input.member_did_document,
            now,
            draft_extension_negotiated: true,
            pending_commit_id: pending_commit_id.clone(),
            request_id: uuid_v4(),
        },
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("preparing group.e2ee.add: {err}")))?;

    Ok(PreparedAdd {
        pending_commit_id,
        body: prepared.body,
    })
}

/// What `remove` needs from the caller (P6 §9.4).
///
/// Unlike [`AddInput`], the pair is here: §9.4.3 keys the removal on the exact
/// `(member_did, member_device_id)` leaf, and there is no package to read it off — the target
/// is named rather than invited. `member_did_document` is still evidence, but of a weaker kind
/// than on `add`: the crate's leaf lookup uses it today only to check the document's `id`
/// equals `member_did` (`find_exact_accepted_leaf`), so it is handed over in the same verified
/// form anyway, because a document going into the crate travels in one shape regardless of
/// which of its checks reads it ([`crate::message::document_in_crate_form`]).
pub struct RemoveInput<'a> {
    pub group_did: &'a str,
    /// The group's current P4 version, read the same way `create` and `add` read it.
    pub group_state_version: &'a str,
    pub member_did: &'a str,
    pub member_device_id: &'a str,
    pub member_did_document: Value,
    pub operation_id: &'a str,
}

/// A prepared `group.e2ee.remove`: the wire body, plus the local handle that finishes it.
pub struct PreparedRemove {
    pub pending_commit_id: String,
    pub body: V2GroupRemoveBody,
}

/// Phase one of `remove`, the same shape and order as [`prepare_create`] and [`prepare_add`].
///
/// Group-addressed for the same reason as `add` (§4.4.2), and it commits to the *retained*
/// leaves exactly as `add` does — the crate asserts the commit produced no Welcome, because a
/// removal adds nobody. The one check worth knowing before the network is asked: the crate
/// refuses a controller removing its own exact leaf (`group.e2ee.controller_required`), so
/// this device cannot kick *this device*; leaving is `group leave`, a different family.
pub fn prepare_remove(
    location: &IdentityLocation,
    identity: &Identity,
    input: RemoveInput<'_>,
) -> Result<PreparedRemove> {
    let store = store_for(location, identity)?;
    let pending_commit_id = new_pending_commit_id();
    let now = Utc::now().to_rfc3339();

    let prepared: V2PreparedRemove = remove_member_prepare_v2(
        &store,
        V2RemoveMemberInput {
            meta: V2GroupControlMetadata {
                anp_version: None,
                profile: GROUP_E2EE_PROFILE_V2.to_string(),
                security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_string(),
                sender_did: identity.did.clone(),
                sender_device_id: identity.device_id.clone(),
                target: V2Target {
                    kind: "group".to_string(),
                    did: input.group_did.to_string(),
                },
                operation_id: input.operation_id.to_string(),
                created_at: Some(now.clone()),
            },
            group_state_ref: V2GroupStateRef {
                group_did: input.group_did.to_string(),
                group_state_version: input.group_state_version.to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            member_did: input.member_did.to_string(),
            member_device_id: input.member_device_id.to_string(),
            member_did_document: input.member_did_document,
            now,
            draft_extension_negotiated: true,
            pending_commit_id: pending_commit_id.clone(),
            request_id: uuid_v4(),
        },
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("preparing group.e2ee.remove: {err}")))?;

    Ok(PreparedRemove {
        pending_commit_id,
        body: prepared.body,
    })
}

/// The plaintext `group.e2ee.send` encrypts (P6 §7.4).
///
/// §7.4 requires **exactly one** of `text` / `payload` / `payload_b64u`, so the two spellings
/// a caller has map onto the first two: `--text` becomes `text` (content type `text/plain`),
/// `--body` becomes `payload` (a JSON object, content type `application/json`). This client
/// never produces `payload_b64u` — it would be a second way to carry bytes that `payload`
/// already carries as JSON, and §6.2.5 of the message profiles does not ask a text client for
/// it.
///
/// `application_content_type` is the type of what was *encrypted*, and is free-form unlike the
/// outer `meta.content_type`, which §9.5.3 pins to one value. Refusing `--text` under
/// `application/json` is the same call `message::payload_of` makes: `text` is not a shape
/// `application/json` has, so sending one under the other would be two claims about the body.
pub fn application_plaintext(
    text: Option<&str>,
    body: Option<&str>,
    content_type: Option<&str>,
) -> Result<V2GroupApplicationPlaintext> {
    match (text, body) {
        (Some(_), Some(_)) => {
            return Err(AnpioError::MessageInvalid(
                "--text and --body are two spellings of the same thing; pass one".to_string(),
            ))
        }
        (None, None) => {
            return Err(AnpioError::MessageInvalid(
                "missing required option --text or --body".to_string(),
            ))
        }
        _ => {}
    }

    if let Some(text) = text {
        let content_type = content_type.unwrap_or("text/plain").to_string();
        if content_type == "application/json" {
            return Err(AnpioError::MessageInvalid(
                "--text is sent as `text`, which application/json has no body shape for \
                 (P6 §7.4); pass --body instead"
                    .to_string(),
            ));
        }
        return Ok(V2GroupApplicationPlaintext {
            application_content_type: content_type,
            thread_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some(text.to_string()),
            payload: None,
            payload_b64u: None,
        });
    }

    let raw = body.unwrap_or_default();
    let parsed: Value = serde_json::from_str(raw).map_err(|_| {
        AnpioError::MessageInvalid(format!(
            "--body must be JSON (got {})",
            serde_json::to_string(raw).unwrap_or_else(|_| format!("{raw:?}"))
        ))
    })?;
    if !parsed.is_object() {
        return Err(AnpioError::MessageInvalid(
            "--body must be a JSON object, which is the only shape `payload` has (P6 §7.4); \
             use --text for a plain string"
                .to_string(),
        ));
    }
    Ok(V2GroupApplicationPlaintext {
        application_content_type: content_type.unwrap_or("application/json").to_string(),
        thread_id: None,
        reply_to_message_id: None,
        annotations: None,
        text: None,
        payload: Some(parsed),
        payload_b64u: None,
    })
}

/// What `send` needs from the caller (P6 §9.5).
///
/// The plaintext is built and parsed by [`application_plaintext`]; this carries it together
/// with the two names §9.5.3 requires in `meta` rather than in the body — `message_id` and
/// `operation_id` — because they identify the *request*, not the ciphertext. The outer
/// `content_type` is not here: §9.5.3 fixes it to one value, so letting a caller pass one
/// would only be a way to get it wrong.
pub struct SendInput<'a> {
    pub group_did: &'a str,
    /// The group's current P4 version, read the same way the three control methods read it —
    /// §9.5 carries it inside the cipher object's `group_state_ref`.
    pub group_state_version: &'a str,
    pub message_id: &'a str,
    pub operation_id: &'a str,
    pub plaintext: V2GroupApplicationPlaintext,
}

/// Encrypt one application message into a `group_cipher_object` (P6 §9.5).
///
/// **Not** the three-phase shape the control methods have. There is nothing for the service to
/// accept or refuse in the local state: this is one `PrivateMessage` made against the current
/// epoch, and the service's answer says only "taken and ordered" (§9.5's success semantics).
/// So there is no pending commit, no finalize and no abort — the encrypt either produces a
/// cipher object or fails, and the caller sends that object.
///
/// The document here is the **sender's own**, not a peer's: the crate re-validates this
/// device's own leaf binding against it before encrypting, the same way it does when minting a
/// KeyPackage — hence the same crate-form handling ([`did_document_in_crate_form`]).
pub fn send_message(
    location: &IdentityLocation,
    identity: &Identity,
    input: SendInput<'_>,
) -> Result<V2GroupCipherObject> {
    let store = store_for(location, identity)?;
    let document = did_document_in_crate_form(identity)?;
    let now = Utc::now().to_rfc3339();

    encrypt_v2(
        &store,
        V2EncryptInput {
            meta: V2GroupSendMetadata {
                anp_version: None,
                profile: GROUP_E2EE_PROFILE_V2.to_string(),
                security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_string(),
                sender_did: identity.did.clone(),
                sender_device_id: identity.device_id.clone(),
                target: V2Target {
                    kind: "group".to_string(),
                    did: input.group_did.to_string(),
                },
                operation_id: input.operation_id.to_string(),
                message_id: input.message_id.to_string(),
                // §9.5.3: not a caller's choice. The crate enforces it too
                // (`V2GroupSendMetadata::validate`).
                content_type: GROUP_CIPHER_CONTENT_TYPE_V2.to_string(),
                created_at: Some(now.clone()),
            },
            group_state_ref: V2GroupStateRef {
                group_did: input.group_did.to_string(),
                group_state_version: input.group_state_version.to_string(),
                policy_hash: None,
                roster_hash: None,
            },
            application_plaintext: input.plaintext,
            sender_did_document: document,
            now,
            draft_extension_negotiated: true,
            request_id: uuid_v4(),
        },
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("encrypting a group message: {err}")))
}

/// Apply one `group.e2ee.notice` to this device's MLS state (P6 §12.2).
///
/// The single entry point for both notice kinds: the crate branches on
/// `notice.notice_type` itself — `welcome-delivery` joins the group (and validates **every**
/// leaf in the tree, which is why `member_documents` has to cover all of them, not just the
/// sender), `commit-delivery` advances an existing one. A device the notice names as its
/// subject with `subject_status: removed` comes out with `self_removed: true`, which is how
/// the caller learns to stop listening for that group.
///
/// The crate makes this **idempotent per `meta.operation_id`**: it files a receipt before
/// applying and returns the stored output for a repeat. That is what makes the push-only,
/// no-ack delivery safe to redeliver — the service deletes its queue row after a successful
/// socket write (`groupEnvelopes.ts` §6.1), so at-least-once is the guarantee, and the
/// deduplication has to live here.
///
/// `member_documents` is [`V2DidDocument`] pairs — the agent DID and its whole document,
/// fetched by the caller with [`crate::message::resolve_did_document`] and converted with
/// [`crate::message::document_in_crate_form`]. It is a parameter rather than fetched here for
/// the same reason as everywhere else (client-mls.md §5 #4): this module owns the store, not
/// the network.
pub fn process_notice(
    location: &IdentityLocation,
    identity: &Identity,
    meta: V2GroupNoticeMetadata,
    notice: V2E2eeNotice,
    member_documents: Vec<V2DidDocument>,
) -> Result<V2ProcessNoticeOutput> {
    let store = store_for(location, identity)?;
    process_notice_v2(
        &store,
        V2ProcessNoticeInput {
            recipient_did: identity.did.clone(),
            recipient_device_id: identity.device_id.clone(),
            meta,
            notice,
            member_documents,
            now: Utc::now().to_rfc3339(),
            draft_extension_negotiated: true,
            request_id: uuid_v4(),
        },
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("processing a group notice: {err}")))
}

/// What decrypting one `group.incoming` needs beyond the identity (P6 §12.5).
///
/// The `originating_meta` is the **sender's** `V2GroupSendMetadata`, not the envelope's
/// `V2GroupNoticeMetadata`-shaped one: §12.5 keeps `sender_did` / `sender_device_id` /
/// `message_id` / `operation_id` / `content_type` from the accepted `send` precisely so the
/// receiver can rebuild this. The `group_cipher_object` is the accepted body's object
/// byte-for-byte (§12.6 forbids re-encoding), and `sender_did_document` is that sender's
/// document — needed to check the leaf binding the ciphertext was signed under.
pub struct DecryptInput {
    pub originating_meta: V2GroupSendMetadata,
    pub group_cipher_object: V2GroupCipherObject,
    pub sender_did_document: Value,
}

/// Decrypt one delivered `group.incoming` (P6 §12.5).
///
/// `decrypt_received_…` rather than the plain `decrypt_v2`: the received variant admits an
/// exact-input recovery result, which is the shape a **durably received** input has — one
/// that came off a queue the service may deliver twice. The strict variant is for a caller
/// that has not stored the input and can afford to treat a repeat as a failure; a listener
/// cannot, because the redelivery is the service's normal behaviour, not an error.
pub fn decrypt_received(
    location: &IdentityLocation,
    identity: &Identity,
    input: DecryptInput,
) -> Result<V2DecryptOutput> {
    let store = store_for(location, identity)?;
    let DecryptInput {
        originating_meta,
        group_cipher_object,
        sender_did_document,
    } = input;
    decrypt_received_v2(
        &store,
        V2DecryptInput {
            recipient_did: identity.did.clone(),
            recipient_device_id: identity.device_id.clone(),
            originating_meta,
            group_cipher_object,
            sender_did_document,
            now: Utc::now().to_rfc3339(),
            draft_extension_negotiated: true,
            request_id: uuid_v4(),
        },
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("decrypting a group message: {err}")))
}

/// Phase three, accepted: the service took the commit, so the local pending one becomes the
/// device's state.
///
/// Only ever called after a success response. `finalize_commit_v2` refuses a pending commit
/// that was aborted, and `abort_commit_v2` refuses one that was finalized — the pair is a
/// partition, not two spellings of "clean up", which is what makes the choice structural
/// rather than a comment. What the crate reports back (`epoch`, `crypto_group_id_b64u`) is
/// deliberately not returned: the service's own response is the record of what it accepted,
/// and two copies of it would be two things to disagree.
pub fn finalize_commit(
    location: &IdentityLocation,
    identity: &Identity,
    pending_commit_id: &str,
) -> Result<()> {
    let store = store_for(location, identity)?;
    finalize_commit_v2(
        &store,
        V2FinalizeInput {
            pending_commit_id: pending_commit_id.to_string(),
            request_id: uuid_v4(),
        },
    )
    .map(|_| ())
    .map_err(|err| AnpioError::MessageInvalid(format!("finalising a commit: {err}")))
}

/// Phase three, refused: the service said no, so nothing of this commit survives here.
///
/// The caller decides when this is safe. A service *refusal* is the clear case — it never
/// accepted anything — while a request that failed in transport may well have been accepted,
/// and rolling back then would leave this device with no state for a group the service
/// believes it has. The crate keeps `reconcile_pending_v2` for that ambiguity; this function
/// is not it.
pub fn abort_commit(
    location: &IdentityLocation,
    identity: &Identity,
    pending_commit_id: &str,
) -> Result<()> {
    let store = store_for(location, identity)?;
    abort_commit_v2(
        &store,
        V2FinalizeInput {
            pending_commit_id: pending_commit_id.to_string(),
            request_id: uuid_v4(),
        },
    )
    .map(|_| ())
    .map_err(|err| AnpioError::MessageInvalid(format!("aborting a commit: {err}")))
}

/// This device's DID document, in the one form the crate's own checks accept — the same
/// conversion [`generate_key_package`] needs, for the same reason, done once here so both
/// callers cannot drift apart on it.
fn did_document_in_crate_form(identity: &Identity) -> Result<Value> {
    document_in_crate_form(&identity.did_document).ok_or_else(|| {
        AnpioError::MessageInvalid(format!(
            "{}'s stored DID document is not bound to its own DID",
            identity.did
        ))
    })
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
            custody: None,
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

    /// `--text` is §7.4's `text`, and the default content type is the one that goes with it.
    ///
    /// The freed-up field that matters is the negative half: `payload` and `payload_b64u` must
    /// be *absent*, not present-and-null, because §7.4 makes the three spellings a one-of — a
    /// plaintext carrying two would be refused by the receiver before it ever decrypted.
    #[test]
    fn a_text_plaintext_is_the_text_field_under_text_plain() {
        let plaintext = application_plaintext(Some("hello"), None, None).unwrap();
        assert_eq!(plaintext.text.as_deref(), Some("hello"));
        assert_eq!(plaintext.application_content_type, "text/plain");
        assert!(plaintext.payload.is_none(), "only one of the three spellings");
        assert!(plaintext.payload_b64u.is_none(), "this client never makes this one");

        let named = application_plaintext(Some("hello"), None, Some("text/markdown")).unwrap();
        assert_eq!(
            named.application_content_type, "text/markdown",
            "an explicit type is the caller's, not overridden back to text/plain"
        );
    }

    /// `--body` is §7.4's `payload`, which only has an object shape.
    #[test]
    fn a_body_plaintext_is_the_payload_field_under_application_json() {
        let plaintext = application_plaintext(None, Some(r#"{"kind":"ping","n":1}"#), None).unwrap();
        assert_eq!(plaintext.application_content_type, "application/json");
        assert_eq!(
            plaintext.payload.as_ref().and_then(|value| value.get("kind")),
            Some(&Value::String("ping".to_string()))
        );
        assert!(plaintext.text.is_none(), "only one of the three spellings");
    }

    /// Passing both spellings is refused here, not at the receiver.
    ///
    /// The same reason `message::payload_of` refuses it: two claims about one body cannot both
    /// be true, and a client that guessed which one the caller meant would silently drop the
    /// other. Neither is a default.
    #[test]
    fn both_spellings_or_neither_is_refused_before_it_is_encrypted() {
        let err = application_plaintext(Some("hello"), Some("{}"), None).unwrap_err();
        assert!(err.to_string().contains("--text and --body"), "{err}");

        let err = application_plaintext(None, None, None).unwrap_err();
        assert!(err.to_string().contains("--text or --body"), "{err}");
    }

    /// `--text` under `application/json` is two claims about one body, so it is refused.
    ///
    /// This mirrors `message::payload_of`'s call rather than inventing a rule: `text` is not a
    /// shape `application/json` has, so the pair could only be sent by contradicting the
    /// content type the receiver will parse it under.
    #[test]
    fn a_text_under_application_json_is_refused() {
        let err = application_plaintext(Some("hello"), None, Some("application/json")).unwrap_err();
        assert!(err.to_string().contains("--body"), "{err}");
    }

    /// `--body` that is not a JSON object is refused, and the message says why.
    ///
    /// §7.4's `payload` is a JSON *object*; `"5"` and `[1,2]` parse as JSON but are not one, so
    /// both fall out here rather than at a receiver that would have to decide what they meant.
    #[test]
    fn a_body_that_is_not_a_json_object_is_refused() {
        let err = application_plaintext(None, Some("[1,2]"), None).unwrap_err();
        assert!(err.to_string().contains("JSON object"), "{err}");

        let err = application_plaintext(None, Some("not json"), None).unwrap_err();
        assert!(err.to_string().contains("must be JSON"), "{err}");
    }
}
