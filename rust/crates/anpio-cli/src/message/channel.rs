//! The client half of ANP-09, shared by `msg` (and later `group`): who this run signs as,
//! which message service answers for a given DID, and one signed call placed on it.
//!
//! The port of `packages/cli/src/commands/channel.ts`. It exists as its own module for the
//! same reason it does there: the parts that must happen **exactly once** are the parts that
//! break in the hardest way when they are copied. Three laws hold here.
//!
//! 1. [`crate::message::envelope::build_message_request`] assembles the envelope.
//! 2. The `anp` crate's `generate_rfc9421_origin_proof` canonicalises for the proof.
//! 3. The **same** `meta` goes to the signer and to the envelope builder, so neither can
//!    sign one thing and send another.

use anp::proof::{generate_rfc9421_origin_proof, Rfc9421OriginProofGenerationOptions};
use anp::PrivateKeyMaterial;
use chrono::{SecondsFormat, Utc};
use reqwest::Url;
use serde_json::{Map, Value};

use crate::error::{AnpioError, Result};
use crate::custody::Operation;
use crate::identity::Identity;

use super::discovery::{discover_message_service, AnpCapabilities, MessageServiceTarget};
use super::envelope::{
    build_message_request, AnpAuth, AnpMeta, AnpOriginProof, AnpRequest, AnpTarget, TargetKind,
    ORIGIN_PROOF_SCHEME,
};
use super::resolve::{did_host, is_loopback_host_name, ResolvePolicy};
use super::rpc::{post_message, AnpResponse};

pub const TRANSPORT_PROTECTED: &str = "transport-protected";

/// JSON-RPC "no such method".
pub const METHOD_NOT_FOUND: i64 = -32601;
/// P1 §10.3: 1001 `anp.unsupported_profile`. On an `x_anpiocli.*` profile this says the same
/// thing `-32601` does — the peer does not implement this extension.
pub const UNSUPPORTED_PROFILE: &str = "anp.unsupported_profile";
/// P1 §10.3: the peer refuses a DID that has a successor, and MUST NOT retarget on its own.
/// The sender is the one that has to verify the migration and retry (P3 §5.5).
pub const DID_SUPERSEDED: &str = "anp.did_superseded";

/// P3 §7.1.2: the three fixed values of a `direct.send`.
pub const DIRECT_SEND: &str = "direct.send";
pub const DIRECT_PROFILE: &str = "anp.direct.base.v1";

/// P4 §5.1: the group family's Profile, and its methods. The one thing P4 does not let
/// this be a constant is `meta.target` — `group.create` names the service, every other
/// method names the group (`CallRequest.target`).
pub const GROUP_PROFILE: &str = "anp.group.base.v2";
pub const GROUP_CREATE: &str = "group.create";
pub const GROUP_GET_INFO: &str = "group.get_info";
pub const GROUP_JOIN: &str = "group.join";
pub const GROUP_LEAVE: &str = "group.leave";
pub const GROUP_SEND: &str = "group.send";
/// The group's own name lives in `group_profile.display_name` (§7.4), and this is the only
/// method that writes it. Its body is `group_profile_patch` under RFC 7386 merge semantics
/// (§8.7.2), so a field left out is a field left unchanged.
pub const GROUP_UPDATE_PROFILE: &str = "group.update_profile";

/// P6 §4.1: the group E2EE family's Profile and its six methods.
///
/// The six do not split the way P4's do. Three are addressed to the *service* — the two
/// KeyPackage methods, whose cabinet lives there, and `group.e2ee.create`, which asks for a
/// group that has no DID yet to address — and three (`add` / `remove` / `send`) are addressed
/// to the *group*, so `meta.target` is a parameter here exactly as it is in P4, and for the
/// same reason: it is inside the signature.
///
/// The method names and the Profile live here with the rest of the wire vocabulary; the
/// policy that goes *in* them is `crate::group_e2ee`.
pub const GROUP_E2EE_PROFILE: &str = "anp.group.e2ee.v2";
/// P6 §4.3 L273: the four control methods are read at `group-e2ee`, one notch above the
/// transport-only default the two KeyPackage methods keep (L272).
pub const GROUP_E2EE_SECURITY_PROFILE: &str = "group-e2ee";
pub const PUBLISH_KEY_PACKAGE: &str = "group.e2ee.publish_key_package";
pub const GET_KEY_PACKAGE: &str = "group.e2ee.get_key_package";
pub const GROUP_E2EE_CREATE: &str = "group.e2ee.create";
pub const GROUP_E2EE_ADD: &str = "group.e2ee.add";
pub const GROUP_E2EE_REMOVE: &str = "group.e2ee.remove";
pub const GROUP_E2EE_SEND: &str = "group.e2ee.send";

/// P6 §12: the two methods a **service pushes**, which no `group.e2ee.*` call above has.
///
/// They are the receive half of the family: `notice` carries a Commit or a Welcome (§12.2),
/// `incoming` carries application ciphertext (§12.5). Neither is ever *sent* by a client, so
/// they are not in the six above — §12.6 says this Profile defines no P6 history pull at all,
/// which is what makes a live socket the only way to get either.
///
/// `GROUP_E2EE_INCOMING` shares its string with P4's own `group.incoming` (the TS service
/// keeps the two apart by module, `groupEnvelopes.ts` vs `groups.ts`). A client therefore
/// cannot tell them apart by method alone: the discriminator is the security profile P6
/// §12.5 pins to `group-e2ee`, which is why the receive path checks it.
pub const GROUP_E2EE_NOTICE: &str = "group.e2ee.notice";
pub const GROUP_E2EE_INCOMING: &str = "group.incoming";

/// P1 §8.2.1: a capabilities probe explains itself under the core binding.
pub const GET_CAPABILITIES: &str = "anp.get_capabilities";
pub const CORE_BINDING: &str = "anp.core.binding.v1";

/// message-service.md §9.3: the three extension methods the read commands call.
pub const INBOX_GET: &str = "inbox.get";
pub const INBOX_MARK_READ: &str = "inbox.mark_read";
pub const MESSAGE_GET_BATCH: &str = "message.get_batch";

/// TODO6 §3: the address book's three methods, on the same self-addressed shape as the three
/// above. They live here rather than in `contacts.rs` so that every method name this client
/// sends over the extension transport is in one place, next to the Profile each is read under.
pub const CONTACTS_LIST: &str = "contacts.list";
pub const CONTACTS_PUT: &str = "contacts.put";
pub const CONTACTS_REMOVE: &str = "contacts.remove";

/// TODO6 §4.2: the same address book's other half — the name this identity gives a *group*.
/// A separate family with a separate Profile (§9.5), because a group is `group`-addressed
/// and not something `msg send --to` can reach: folding the two books together would let a
/// name resolve to a group DID and a message be sent to a mailbox no group can read.
pub const GROUP_REMARKS_LIST: &str = "group_remarks.list";
pub const GROUP_REMARKS_PUT: &str = "group_remarks.put";
pub const GROUP_REMARKS_REMOVE: &str = "group_remarks.remove";

/// The pick-up surface's Profile. P1 §6.2.2 makes `meta.profile` MUST and calls it "the
/// single Profile this request is to be read under", so a read request has to name one —
/// and no normative Profile interprets `inbox.get`. The `x_` prefix is the namespace P1
/// §12 leaves for extensions, and it is what keeps these values out of the `profiles[]` a
/// service advertises as its specification conformance.
///
/// One Profile per family, not one for all extensions: the service advertises them separately
/// (`x_anpiocli.inbox.v1`, `x_anpiocli.contacts.v1` and `x_anpiocli.group_remarks.v1` are three
/// entries in `capabilities.extensionProfiles`), and a client that named the wrong one would
/// be asking to be read under a Profile that does not define the method.
pub const INBOX_PROFILE: &str = "x_anpiocli.inbox.v1";
pub const CONTACTS_PROFILE: &str = "x_anpiocli.contacts.v1";
pub const GROUP_REMARKS_PROFILE: &str = "x_anpiocli.group_remarks.v1";

// ---- the outbound network policy ---------------------------------------------

/// The hosts a run may treat as its own machine: those named in `--allow-private-host`,
/// plus every **loopback** name among `hosts`.
///
/// A loopback spelling needs no second flag. `--allow-private-host` stays for a host that
/// is local *without* being spelled that way (a LAN address, a name resolving inward).
///
/// The two relaxations travel together because a host declared local is a development
/// server: ANP-02's TLS requirement is about real deployments, and plain `http` on this
/// machine is the case `allowInsecureTransport` exists for.
pub fn relaxed_hosts(hosts: &[String], allow_private_hosts: &[String]) -> Vec<String> {
    let mut relaxed = allow_private_hosts.to_vec();
    for host in hosts {
        if is_loopback_host_name(host) && !relaxed.iter().any(|listed| listed == host) {
            relaxed.push(host.clone());
        }
    }
    relaxed
}

/// The policy for a fetch whose host is DERIVED rather than typed.
///
/// `did resolve` makes the caller name `--allow-host`, because there the host *is* the
/// thing being asked about. Here it comes from a DID: it *is* the peer, and a second flag
/// repeating it would only be one more way to get it wrong. What the caller still controls
/// is the private-address gate, because a message service on this machine is a development
/// setup (`--allow-private-host`).
pub fn policy_for(hosts: &[String], allow_private_hosts: &[String]) -> ResolvePolicy {
    let mut allowed_hosts: Vec<String> = Vec::new();
    for host in hosts {
        if !allowed_hosts.iter().any(|listed| listed == host) {
            allowed_hosts.push(host.clone());
        }
    }
    let relaxed = relaxed_hosts(&allowed_hosts, allow_private_hosts);
    ResolvePolicy {
        allowed_hosts,
        allow_private_hosts: relaxed.clone(),
        allow_insecure_transport: relaxed,
    }
}

fn endpoint_host(endpoint: &str) -> Option<String> {
    Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
}

/// One discovered ingress, plus the policy its POST hop must satisfy.
pub struct Endpoint {
    pub target: MessageServiceTarget,
    pub policy: ResolvePolicy,
}

/// P2 §9.1 for an agent and for a group are the same two steps: resolve the target's
/// document, take its one ANPMessageService. A group DID's document carries its own entry
/// exactly as an agent's does, so there is no group-specific lookup to write.
///
/// Two policies come out of this, not one. The document fetch may reach only the host the
/// DID itself names; the message POST may additionally reach the endpoint host, which the
/// **peer** chose by writing it into the document.
pub async fn discover(
    client: &reqwest::Client,
    identity: &str,
    allow_private_hosts: &[String],
) -> Result<Endpoint> {
    let document_host = did_host(identity)?;
    let document_policy = policy_for(std::slice::from_ref(&document_host), allow_private_hosts);
    let target = discover_message_service(client, identity, &document_policy).await?;

    let mut hosts = vec![document_host];
    if let Some(host) = endpoint_host(&target.endpoint) {
        hosts.push(host);
    }
    let policy = policy_for(&hosts, allow_private_hosts);
    Ok(Endpoint { target, policy })
}

// ---- the sender --------------------------------------------------------------

/// The identity this run signs as.
///
/// `agent` / `profile` travel with it rather than being looked up again, because they are
/// what `msg listen` derives its default `device_id` from (realtime.md §5.4).
pub struct Sender {
    pub did: String,
    pub keyid: String,
    pub agent: String,
    pub profile: String,
    /// Which device of that identity this run is. P1 §6.2.4.1 requires it inside P5/P6 and
    /// forbids it everywhere else, so it rides along and only [`call_device`] puts it on the
    /// wire — a `Sender` is not a device until a Profile says the caller is one.
    pub device_id: String,
    signing_key: PrivateKeyMaterial,
}

impl Sender {
    /// The signing half of an already-loaded identity.
    ///
    /// A message carries `meta.sender_did` (P3 §7.1.2) and the recipient resolves that DID
    /// back to an ingress to answer on. An identity that only exists on this machine has no
    /// ingress, so a send signed by one could not be answered — which is why `did create`
    /// publishes as part of creating, and why a keyless identity is refused here rather than
    /// surfacing later as a network problem.
    ///
    /// The identity is passed in rather than loaded here on purpose: reading the store is
    /// the command face's job, and it reports its failures with its own error type. This
    /// layer only ever sees a value that already exists.
    pub fn from_identity(identity: &Identity) -> Result<Self> {
        // Every message this client sends carries an origin proof over bytes it assembles
        // itself. Whether the daemon can make one is negotiated, not assumed: the refusal
        // names the missing operation and what the daemon does announce.
        if let Some(custody) = &identity.custody {
            custody
                .require(Operation::OriginProof, "msg send")
                .map_err(|err| AnpioError::MessageInvalid(format!("{err:#}")))?;
        }
        let fragment = "key-1";
        let key = identity.keys.get(fragment).ok_or_else(|| {
            AnpioError::MessageInvalid(format!(
                "{} has no {fragment}; re-run: anpio-cli did create",
                identity.did
            ))
        })?;
        let signing_key = PrivateKeyMaterial::from_pem(&key.private_key_pem).map_err(|err| {
            AnpioError::MessageInvalid(format!("cannot read {fragment} from the store: {err}"))
        })?;
        Ok(Self {
            did: identity.did.clone(),
            keyid: format!("{}#key-1", identity.did),
            agent: identity.agent.clone(),
            profile: identity.profile.clone(),
            device_id: identity.device_id.clone(),
            signing_key,
        })
    }

    /// The same run, proved by **this device's** key instead of the DID's root key.
    ///
    /// P6 §13.3 item 6 asks `group.e2ee.send`'s origin proof to be made with the sending
    /// device's current signing key: the service compares the proof's `keyid` against the
    /// DID document's `signing_key_id` for `meta.sender_device_id`, so a proof made with
    /// `key-1` — the root key every other call signs with — is refused (`anp.unauthorized`,
    /// verified against the service). The DID on the wire does not change; only which
    /// verification method proves it does.
    ///
    /// The key arrives already read rather than being looked up here: which fragment holds a
    /// device key is `crate::mls`'s fact (`{device_id}-sign`), and a second copy of that
    /// convention in this layer is exactly the kind of drift the split is meant to prevent.
    pub fn signing_as_device(&self, keyid: String, signing_key: PrivateKeyMaterial) -> Self {
        Self {
            did: self.did.clone(),
            keyid,
            agent: self.agent.clone(),
            profile: self.profile.clone(),
            device_id: self.device_id.clone(),
            signing_key,
        }
    }
}

/// A read is addressed to the caller's OWN message service. There is no `--to`: the owner
/// of the inbox is `meta.sender_did`, so the DID whose document has to be fetched for the
/// service entry is the one we sign as.
pub struct Channel {
    pub sender: Sender,
    pub endpoint: Endpoint,
}

/// One channel resolution and one signer. Exported for `msg listen`, which authenticates
/// the same way over a socket instead of a POST (realtime.md §3).
pub async fn open_channel(
    client: &reqwest::Client,
    identity: &Identity,
    allow_private_hosts: &[String],
) -> Result<Channel> {
    let sender = Sender::from_identity(identity)?;
    let did = sender.did.clone();
    open_channel_for(client, sender, &did, allow_private_hosts).await
}

/// The same resolution against a DID that is *not* the signer's own.
///
/// The `group` family needs this: every method but `create` is addressed to the **group's**
/// `group_did`, whose document is what names the service to POST to (P4 §8.2.2). The two DIDs
/// are meant to differ, so the signer is an argument rather than something read off the target
/// — passing the target's DID here as the signer would sign as the group.
pub async fn open_channel_for(
    client: &reqwest::Client,
    sender: Sender,
    target_did: &str,
    allow_private_hosts: &[String],
) -> Result<Channel> {
    let endpoint = discover(client, target_did, allow_private_hosts).await?;
    Ok(Channel { sender, endpoint })
}

// ---- one signed call ---------------------------------------------------------

/// What one call puts on the wire, minus the envelope and the signature.
///
/// `target` is a parameter rather than a constant because P4 gives two answers within one
/// family: `group.create` names the SERVICE it is asking to make a group, every other group
/// method names the GROUP. `meta.target` is part of the Signed Request Object, so this is a
/// signed decision, not a routing hint.
pub struct CallRequest {
    pub method: String,
    pub profile: String,
    pub target: AnpTarget,
    /// The `group_policy`/`group_key_package`-shaped object this call carries.
    pub body: Map<String, Value>,
    /// P1 §6.2.4.1: MUST inside P5/P6, MUST NOT appear outside them. Only [`call_device`]
    /// sets it, from the sender's own device.
    pub sender_device_id: Option<String>,
    /// P1 §6.2.3. `None` is `transport-protected`, which is every family but P6's four
    /// control methods (P6 §4.3 L272–273 draws that line).
    pub security_profile: Option<String>,
    /// P1 §6.2.7: a message-bearing operation MUST carry it. Set by `direct.send` and
    /// `group.send`, absent on a state change.
    pub message_id: Option<String>,
    /// P1 §6.2.10 / P4 §7.6: likewise.
    pub content_type: Option<String>,
    /// P1 §6.2.6: MUST for every state-changing operation. Caller-supplied when a retry has
    /// to reuse it, otherwise fresh.
    pub operation_id: Option<String>,
}

/// Assemble and sign one Request, ready to place on any transport.
///
/// This is [`call`]'s first half, split out so the socket path (`message::listen`) signs
/// **exactly** as the HTTP path does. The handshake is where a connection learns who is on
/// it (realtime.md §4.1), so it is the last place to accept a second signing routine: two
/// of them would be two chances to canonicalise `meta` differently from the envelope.
///
/// `id` pairs one request with one response (P1 §5.2). The HTTP path has no use for it and
/// generates a fresh one; the stream does, because it has to recognise its own reply in a
/// frame stream that also carries unsolicited Notifications.
pub fn sign_request(sender: &Sender, id: &str, request: CallRequest) -> Result<AnpRequest> {
    let CallRequest {
        method,
        profile,
        target,
        body,
        sender_device_id,
        security_profile,
        message_id,
        content_type,
        operation_id,
    } = request;

    let meta = AnpMeta {
        profile,
        security_profile: security_profile.unwrap_or_else(|| TRANSPORT_PROTECTED.to_string()),
        sender_did: Some(sender.did.clone()),
        sender_device_id,
        target: Some(target),
        operation_id: Some(operation_id.unwrap_or_else(uuid_v4)),
        created_at: Some(now_rfc3339()),
        message_id,
        content_type,
        ..Default::default()
    };

    // P1 appendix A.3: the Signed Request Object is `{method, meta, body}`, so the SAME two
    // values go to the signer and to the envelope builder. The signer takes `meta` as JSON,
    // exactly as the builder will serialise it, so neither can sign one thing and send
    // another. (`request_meta_is_what_gets_signed` pins that down.)
    let meta_value = serde_json::to_value(&meta)?;
    let body_value = Value::Object(body);
    let proof = generate_rfc9421_origin_proof(
        &method,
        &meta_value,
        &body_value,
        &sender.signing_key,
        &sender.keyid,
        Rfc9421OriginProofGenerationOptions::default(),
    )
    .map_err(|err| AnpioError::MessageInvalid(format!("signing {method}: {err}")))?;

    let auth = AnpAuth {
        scheme: ORIGIN_PROOF_SCHEME.to_string(),
        origin_proof: AnpOriginProof {
            content_digest: proof.content_digest,
            signature_input: proof.signature_input,
            signature: proof.signature,
        },
    };

    build_message_request(id, &method, meta, Some(body_value), Some(auth))
}

/// POST one signed request. The response is returned as it arrived — success and refusal
/// are both answers, and only the caller knows which of them it can act on.
///
/// `sender` and `endpoint` come in separately rather than as a [`Channel`] because the two
/// halves are chosen independently: `msg send` signs with the identity in use and posts to
/// the **recipient's** ingress, while `msg inbox` posts to its own. A type that assumed they
/// belonged together would have to be taken apart again for the send case.
pub async fn call(
    client: &reqwest::Client,
    sender: &Sender,
    endpoint: &Endpoint,
    request: CallRequest,
) -> Result<AnpResponse> {
    // A fresh `id` per exchange: `id` pairs one request with one response, while
    // `operation_id` is what makes the business operation idempotent.
    let envelope = sign_request(sender, &uuid_v4(), request)?;

    // The endpoint is the peer's, so `post_message` applies the hop policy itself rather
    // than trusting this call site to have done it.
    post_message(
        client,
        &endpoint.target.endpoint,
        &envelope,
        &endpoint.policy,
        &endpoint.target.identity,
    )
    .await
}

/// One extension call. Authenticated exactly like `direct.send` — an `origin_proof` over
/// `{method, meta, body}`, no bearer token — because this client does not hold one and the
/// proof is the stronger answer anyway.
///
/// `meta.target` is the mailbox owner, i.e. the identity in use. That is not a formality:
/// P1 appendix A.4 requires `meta.target` whenever a method carries an `origin_proof`, and
/// the same appendix requires an endpoint-local method to have its target modelling written
/// down by its Profile — which is message-service.md §9.1.1. Reading one's own inbox is
/// addressed to oneself, so `target.did` and `sender_did` are the same DID.
///
/// `profile` is passed in rather than fixed here because each extension family is read under
/// its own Profile (`INBOX_PROFILE`, `CONTACTS_PROFILE`); the service keys its method table by
/// the pair, so a call that named the other family's Profile would be refused as an
/// unsupported profile rather than silently honoured.
pub async fn call_extension(
    client: &reqwest::Client,
    channel: &Channel,
    method: &str,
    profile: &str,
    body: Map<String, Value>,
) -> Result<Value> {
    let response = call(
        client,
        &channel.sender,
        &channel.endpoint,
        CallRequest {
            method: method.to_string(),
            profile: profile.to_string(),
            target: AnpTarget {
                kind: TargetKind::Agent,
                did: channel.sender.did.clone(),
            },
            body,
            sender_device_id: None,
            security_profile: None,
            message_id: None,
            content_type: None,
            operation_id: None,
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => Ok(result),
        AnpResponse::Error { error, .. } => Err(extension_rejection(
            method,
            &channel.sender.did,
            error.code,
            error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
            &error.message,
        )),
    }
}

/// A state-changing group call of P4 `anp.group.base.v2`. [`call_extension`] is fixed to the
/// caller's own DID because a read is addressed to the reader's own inbox; a group call is
/// addressed to something else — and `group.create` addresses a *service* rather than a group
/// (P4 §8.1.2) — so the target has to be a parameter. It is inside the Signed Request Object,
/// which is why it is a parameter rather than a routing hint.
///
/// `subject` is the party a refusal is attributed to on the error line. It follows the TS
/// client: a group method is answered by the group (`did:…:group:…` rejected `group.info`),
/// while `group.create` is answered by the service, against the caller whose request it is.
///
/// `group.send` does not come through here: it carries a message, and therefore
/// `message_id` and `content_type` as well (P4 §7.6).
pub async fn call_group(
    client: &reqwest::Client,
    channel: &Channel,
    method: &str,
    target: AnpTarget,
    body: Map<String, Value>,
    subject: &str,
) -> Result<Value> {
    let response = call(
        client,
        &channel.sender,
        &channel.endpoint,
        CallRequest {
            method: method.to_string(),
            profile: GROUP_PROFILE.to_string(),
            target,
            body,
            sender_device_id: None,
            security_profile: None,
            message_id: None,
            content_type: None,
            operation_id: None,
        },
    )
    .await?;

    result_of(method, subject, response)
}

/// A `group.e2ee.*` call of P6 `anp.group.e2ee.v2`.
///
/// The two reasons this is not [`call_group`] with more arguments are both in `meta`, and
/// both are things the caller must not choose: the Profile is `anp.group.e2ee.v2` (§4.3
/// L264), and `sender_device_id` is present because §4.3 L266 makes it mandatory — every P6
/// request is from a *device*, which is why the sender's own device is the only value that
/// can go there.
///
/// The Profile's security mode is the one thing that does vary by method, and P6 §4.3
/// L272–273 states the split itself, so [`group_e2ee_security_profile`] reads it rather than
/// leaving the choice to each call site.
pub async fn call_device(
    client: &reqwest::Client,
    channel: &Channel,
    method: &str,
    target: AnpTarget,
    body: Map<String, Value>,
    subject: &str,
) -> Result<Value> {
    let response = call(
        client,
        &channel.sender,
        &channel.endpoint,
        CallRequest {
            method: method.to_string(),
            profile: GROUP_E2EE_PROFILE.to_string(),
            target,
            body,
            sender_device_id: Some(channel.sender.device_id.clone()),
            security_profile: Some(group_e2ee_security_profile(method).to_string()),
            message_id: None,
            content_type: None,
            operation_id: None,
        },
    )
    .await?;

    result_of(method, subject, response)
}

/// P6 §4.3 L272–273: the two KeyPackage methods (and `notice`) are read at
/// `transport-protected`, the four control methods at `group-e2ee`.
///
/// The spec's first group also names `group.e2ee.notice`, which this client never *calls* —
/// it is agent-addressed and arrives as a `group.incoming` delivery — so the match below is
/// the two KeyPackage methods or the four control ones, and nothing falls between them.
///
/// Written as the spec's own split rather than as a flag on each call site: which of the two
/// a method belongs to is a fact about the method, and a call site that got it wrong would
/// produce a request the receiver refuses for a reason that reads like an auth failure.
pub fn group_e2ee_security_profile(method: &str) -> &'static str {
    match method {
        PUBLISH_KEY_PACKAGE | GET_KEY_PACKAGE => TRANSPORT_PROTECTED,
        _ => GROUP_E2EE_SECURITY_PROFILE,
    }
}

/// Success and refusal are both answers, and only the caller knows which it can act on — so
/// a refusal becomes an error here, attributed to `subject`.
fn result_of(method: &str, subject: &str, response: AnpResponse) -> Result<Value> {
    match response {
        AnpResponse::Success { result, .. } => Ok(result),
        AnpResponse::Error { error, .. } => Err(rejection(
            method,
            subject,
            error.code,
            error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
            &error.message,
        )),
    }
}

// ---- the payload -------------------------------------------------------------

/// A `direct.send` / `group.send` payload, already paired with the content type that
/// describes it.
pub struct Payload {
    pub body: Map<String, Value>,
    pub content_type: String,
}

/// Of `text` / `payload` / `payload_b64u` **exactly one** MUST be present, and the two
/// fixed content types each pin which one. So the command takes a payload as text or as a
/// JSON object, and refuses the two combinations the Profiles have no body shape for.
///
/// Written once because P3 §6.2.4 / §6.2.5 and P4 §7.6 state the same three-way rule for
/// `direct.send` and `group.send`: the citations differ, the constraint does not, and two
/// copies of it would be two chances to drift.
pub fn payload_of(
    text: Option<&str>,
    raw_json: Option<&str>,
    content_type: Option<&str>,
) -> Result<Payload> {
    match (text, raw_json) {
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
                "--text is sent as `text`, which content_type application/json does not have a \
                 body shape for (P3 §6.2.5 / P4 §7.6); pass --body instead"
                    .to_string(),
            ));
        }
        let mut body = Map::new();
        body.insert("text".to_string(), Value::String(text.to_string()));
        return Ok(Payload { body, content_type });
    }

    let raw = raw_json.unwrap_or_default();
    let parsed: Value = serde_json::from_str(raw).map_err(|_| {
        AnpioError::MessageInvalid(format!(
            "--body must be JSON (got {})",
            serde_json::to_string(raw).unwrap_or_else(|_| format!("{raw:?}"))
        ))
    })?;
    if !parsed.is_object() {
        return Err(AnpioError::MessageInvalid(
            "--body must be a JSON object, which is the only shape `payload` has (P3 §6.2.5 / \
             P4 §7.6); use --text for a plain string"
                .to_string(),
        ));
    }
    let content_type = content_type.unwrap_or("application/json").to_string();
    if content_type == "text/plain" {
        return Err(AnpioError::MessageInvalid(
            "--body is sent as `payload`, which content_type text/plain does not have a body \
             shape for (P3 §6.2.4 / P4 §7.6); pass --text instead"
                .to_string(),
        ));
    }
    let mut body = Map::new();
    body.insert("payload".to_string(), parsed);
    Ok(Payload { body, content_type })
}

/// The inverse of [`payload_of`]: a body this client built, read back into §7.4's two arms.
///
/// The local record (`crate::messages`) keeps "the text was this string" and "the payload was
/// this object" apart instead of storing the wire shape, so a send path that wants to write a
/// row has to read its own request back. Anything that is **neither** shape — a body from some
/// other implementation — comes back as neither arm: that is what exactly-one-of says, and
/// guessing which arm was meant would put a claim in the record the wire never made.
pub fn payload_from(body: &Map<String, Value>) -> (Option<String>, Option<Value>) {
    match (body.get("text"), body.get("payload")) {
        (Some(Value::String(text)), None) => (Some(text.clone()), None),
        (None, Some(payload)) => (None, Some(payload.clone())),
        _ => (None, None),
    }
}

// ---- reporting ---------------------------------------------------------------

pub fn is_error(response: &AnpResponse) -> bool {
    matches!(response, AnpResponse::Error { .. })
}

/// A peer's refusal. The peer's own `anp_code` goes on the message line so a script can
/// branch on it without `--json`.
pub fn rejection(
    method: &str,
    identity: &str,
    code: i64,
    anp_code: Option<&str>,
    message: &str,
) -> AnpioError {
    let named = anp_code.map(str::to_string).unwrap_or_else(|| format!("JSON-RPC error {code}"));
    AnpioError::MessageSendFailed(format!(
        "{identity} rejected {method}: {named}: {message}"
    ))
}

/// A peer that has no extension surface is not a failure — it is an answer, and a specific
/// one. Both codes say "I do not have this": `-32601` is what a JSON-RPC service returns for
/// a method it does not implement, and `1001` is what a service returns for a Profile it
/// does not know.
///
/// No capabilities probe is made first: an extension Profile is not supposed to be in
/// `profiles[]` (message-service.md §13), so the probe could only ever confirm the absence,
/// at the price of a second round trip.
pub fn extension_rejection(
    method: &str,
    identity: &str,
    code: i64,
    anp_code: Option<&str>,
    message: &str,
) -> AnpioError {
    if code != METHOD_NOT_FOUND && anp_code != Some(UNSUPPORTED_PROFILE) {
        return rejection(method, identity, code, anp_code, message);
    }
    let named = anp_code.map(str::to_string).unwrap_or_else(|| format!("JSON-RPC error {code}"));
    AnpioError::UnsupportedExtension(format!(
        "{identity} does not implement {method} ({named}): the inbox / history / read-state / \
         address-book methods are an implementation extension, not defined by the ANP message \
         specification"
    ))
}

/// The capabilities this run negotiated, or the static hint when the service answered
/// nothing usable. Kept as one call so the "runtime beats hint" rule is applied in one
/// place.
pub fn negotiated(
    target: &MessageServiceTarget,
    runtime: Option<&AnpCapabilities>,
) -> (Vec<String>, Vec<String>, &'static str) {
    super::discovery::negotiate_profiles(
        &target.hinted_profiles,
        &target.hinted_security_profiles,
        runtime,
    )
}

/// Now, spelled the way the TS client spells it (`new Date().toISOString()`): millisecond
/// precision and a `Z` offset. §6.2.8 asks for RFC 3339 and both spellings satisfy it, but a
/// peer that already logs the TS client's timestamps does not need a second format.
pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// A UUID v4, so `operation_id` and request `id` read like the TS client's `randomUUID()`.
/// The spec fixes no format (P1 §6.2.6 only says it must be a string), but interop with a
/// peer that logs them is easier when both clients spell them the same way.
pub fn uuid_v4() -> String {
    let mut bytes = rand::random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_and_body_are_two_spellings_of_one_payload() {
        assert!(payload_of(Some("hi"), Some("{}"), None).is_err());
        assert!(payload_of(None, None, None).is_err());
    }

    /// The record reads a body back so it can keep §7.4's two arms apart. If this inverse ever
    /// drifts from `payload_of`, the local record starts storing the wire shape instead.
    #[test]
    fn a_body_reads_back_into_the_arm_it_was_built_from() {
        let text = payload_of(Some("hi"), None, None).unwrap();
        assert_eq!(payload_from(&text.body), (Some("hi".to_string()), None));

        let object = payload_of(None, Some(r#"{"k":1}"#), None).unwrap();
        assert_eq!(
            payload_from(&object.body),
            (None, Some(json!({"k": 1})))
        );
    }

    /// A body this client did not build is neither arm rather than a guess at which was meant.
    #[test]
    fn a_foreign_body_reads_back_as_neither_arm() {
        let mut body = Map::new();
        body.insert("text".to_string(), json!("hi"));
        body.insert("payload".to_string(), json!({"k": 1}));
        assert_eq!(payload_from(&body), (None, None));

        assert_eq!(
            payload_from(&Map::new()),
            (None, None),
            "and neither does an empty one"
        );
    }

    #[test]
    fn text_pins_text_plain_and_body_pins_json() {
        let payload = payload_of(Some("hello"), None, None).unwrap();
        assert_eq!(payload.content_type, "text/plain");
        assert_eq!(Value::Object(payload.body), json!({"text": "hello"}));

        let payload = payload_of(None, Some(r#"{"k":1}"#), None).unwrap();
        assert_eq!(payload.content_type, "application/json");
        assert_eq!(Value::Object(payload.body), json!({"payload": {"k": 1}}));
    }

    #[test]
    fn the_two_combinations_without_a_body_shape_are_refused() {
        assert!(payload_of(Some("hi"), None, Some("application/json")).is_err());
        assert!(payload_of(None, Some("{}"), Some("text/plain")).is_err());
    }

    #[test]
    fn body_must_be_a_json_object() {
        assert!(payload_of(None, Some("[1,2]"), None).is_err());
        assert!(payload_of(None, Some("null"), None).is_err());
        assert!(payload_of(None, Some("not json"), None).is_err());
        assert!(payload_of(None, Some(r#""s""#), None).is_err());
    }

    #[test]
    fn a_loopback_host_relaxes_both_gates_without_a_flag() {
        let policy = policy_for(&["localhost".to_string()], &[]);
        assert_eq!(policy.allowed_hosts, ["localhost"]);
        assert_eq!(policy.allow_private_hosts, ["localhost"]);
        assert_eq!(policy.allow_insecure_transport, ["localhost"]);

        let policy = policy_for(&["example.com".to_string()], &[]);
        assert!(policy.allow_private_hosts.is_empty());
        assert!(policy.allow_insecure_transport.is_empty());
    }

    #[test]
    fn the_flag_is_what_extends_the_relaxation_to_a_lan_host() {
        let policy = policy_for(&["192.168.1.5".to_string()], &["192.168.1.5".to_string()]);
        assert_eq!(policy.allow_private_hosts, ["192.168.1.5"]);
        assert_eq!(policy.allow_insecure_transport, ["192.168.1.5"]);
        // The allowlist is still exactly the hosts derived from the DID.
        assert_eq!(policy.allowed_hosts, ["192.168.1.5"]);
    }

    #[test]
    fn duplicates_are_collapsed_and_a_second_host_widens_the_allowlist() {
        let policy = policy_for(
            &["example.com".to_string(), "example.com".to_string(), "svc.example.com".to_string()],
            &[],
        );
        assert_eq!(policy.allowed_hosts, ["example.com", "svc.example.com"]);
    }

    #[test]
    fn a_uuid_looks_like_one() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
        assert_eq!(&id[14..15], "4");
        assert_ne!(id, uuid_v4());
    }

    /// The law this module exists to keep: what the signer canonicalised is exactly what
    /// the envelope carries. `call` serialises `meta` once and signs that value; this is
    /// the same struct going through both paths.
    #[test]
    fn request_meta_is_what_gets_signed() {
        let meta = AnpMeta {
            profile: "anp.direct.base.v1".to_string(),
            security_profile: TRANSPORT_PROTECTED.to_string(),
            sender_did: Some("did:wba:example.com:user:a".to_string()),
            target: Some(AnpTarget {
                kind: TargetKind::Agent,
                did: "did:wba:example.com:user:b".to_string(),
            }),
            operation_id: Some("op".to_string()),
            created_at: Some("2026-10-02T00:00:00Z".to_string()),
            ..Default::default()
        };
        let as_signed = serde_json::to_value(&meta).unwrap();
        let request = build_message_request("id", "direct.send", meta, None, None).unwrap();
        assert_eq!(serde_json::to_value(&request.params.meta).unwrap(), as_signed);
    }

    /// The device cut swaps the verification method and nothing else.
    ///
    /// P6 §13.3 item 6 is the reason [`Sender::signing_as_device`] exists, and the DID it
    /// leaves alone is the half that matters most: the service authenticates the proof's
    /// `keyid` *against* `meta.sender_did`, so a cut that moved the DID would not be a
    /// retargeting of the proof but a different sender entirely.
    #[test]
    fn cutting_the_sender_as_a_device_keeps_the_did_and_swaps_the_proof_key() {
        let material = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(
            &mut rand::rngs::OsRng,
        ));
        let mut keys = std::collections::BTreeMap::new();
        keys.insert(
            "key-1".to_string(),
            crate::identity::StoredKeyPair {
                private_key_pem: material.to_pem(),
                public_key_pem: material.public_key().to_pem(),
            },
        );
        let identity = Identity {
            did: "did:wba:example.com:user:test:e1_abc".to_string(),
            device_id: "test/default".to_string(),
            agent: "test".to_string(),
            profile: "default".to_string(),
            handle: "test".to_string(),
            did_host: "https://example.com".to_string(),
            created_at: "2026-10-02T00:00:00Z".to_string(),
            keys,
            did_document: serde_json::json!({}),
            custody: None,
        };

        let root = Sender::from_identity(&identity).unwrap();
        assert_eq!(root.keyid, "did:wba:example.com:user:test:e1_abc#key-1");
        let device = root.signing_as_device(
            "did:wba:example.com:user:test:e1_abc#test/default-sign".to_string(),
            material,
        );
        assert_eq!(device.did, root.did, "the DID on the wire does not move");
        assert_eq!(device.device_id, root.device_id);
        assert_eq!(
            device.keyid,
            "did:wba:example.com:user:test:e1_abc#test/default-sign",
            "only the verification method changes"
        );
    }

    // ---- the negative results (TODO6 §5.3) -----------------------------------
    //
    // "The peer does not implement this" is the *right* answer from a peer that only
    // implements the specification, and `cli.md` §5 says so. It is also the answer a
    // refactor is most likely to quietly turn into something else — an empty list, a
    // warning, a generic failure — so each shape of it is pinned here by the code a
    // script branches on, not just by the prose.

    /// `-32601` is awiki's answer for any method outside its surface, and it means the peer
    /// is conformant, not broken.
    #[test]
    fn a_peer_without_the_extension_says_so_and_is_not_a_failure() {
        let error = extension_rejection(INBOX_GET, "did:wba:x:user:alice:e1_a", METHOD_NOT_FOUND, None, "no such method");
        assert_eq!(
            error.code(),
            "unsupported_extension",
            "a peer that lacks the surface answered; that is not an exchange failure"
        );
        let text = error.to_string();
        assert!(text.contains(INBOX_GET), "{text}");
        assert!(text.contains("does not implement"), "{text}");
        assert!(
            text.contains("implementation extension, not defined by the ANP message specification"),
            "the message has to say the surface is an extension, not a spec capability: {text}"
        );
    }

    /// `1001 anp.unsupported_profile` is the other spelling of the same answer, and it is the
    /// profile — not the method — that is absent. The peer's own code goes on the line.
    #[test]
    fn an_unsupported_extension_profile_reads_the_same_way() {
        let error = extension_rejection(
            INBOX_GET,
            "did:wba:x:user:alice:e1_a",
            1001,
            Some(UNSUPPORTED_PROFILE),
            "unknown profile",
        );
        assert_eq!(error.code(), "unsupported_extension");
        assert!(error.to_string().contains(UNSUPPORTED_PROFILE), "{error}");
    }

    /// The direction that matters most: a peer that *did* read the method and refused it must
    /// not be reported as "this peer has no such extension". Reading a real refusal as an
    /// absent surface would tell a caller to stop asking a service that is in fact reachable
    /// and, here, would misattribute the refusal to the wrong party.
    #[test]
    fn a_real_refusal_is_not_downgraded_to_an_absent_extension() {
        for (code, named) in [(-32602, None), (1014, Some("anp.invalid_target_binding"))] {
            let error = extension_rejection(INBOX_GET, "did:wba:x:user:alice:e1_a", code, named, "no");
            assert_eq!(error.code(), "message_send_failed", "code {code} was answered, not missing");
            let text = error.to_string();
            assert!(text.contains("rejected"), "{text}");
            assert!(!text.contains("does not implement"), "{text}");
        }
    }

    /// A refusal outside the extension surface keeps the peer's own `anp_code` on the line, so
    /// a script can branch on it without `--json`.
    #[test]
    fn a_refusal_names_the_peer_code() {
        let error = rejection(DIRECT_SEND, "did:wba:x:user:alice:e1_a", 409, Some(DID_SUPERSEDED), "moved");
        assert_eq!(error.code(), "message_send_failed");
        assert!(error.to_string().contains(DID_SUPERSEDED), "{error}");
    }
}
