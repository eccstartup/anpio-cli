//! The receive half of P6: what this device does with the two frames a service pushes.
//!
//! §12.6 L1523 says the queue a service pushes from is a delivery mechanism, not group
//! history, and that this Profile defines **no** P6 pull method at all — so these frames only
//! ever arrive on the live socket `msg listen` holds open, never as an answer to a request.
//! That is why this is a module of its own rather than more of [`crate::group_e2ee`]: the
//! request half is a body shape, and this half is a *session* — it resolves the group, reads
//! the roster, fetches documents, and keeps the MLS store moving.
//!
//! It also cannot live in [`crate::message::listen`]. That state machine is the transport and
//! the cursor, deliberately knowing nothing about MLS (realtime.md §7); the one thing it does
//! here is hand a frame over and take an event back.
//!
//! ## What each frame costs
//!
//! Two network round trips can hide behind one pushed frame: the group's roster
//! (`group.get_info`, to learn every member DID) and each DID document. A notice needs the
//! roster because the crate validates the **whole leaf set** on a Welcome; an application
//! message needs only the sender's document. Both are fetched fresh rather than cached — see
//! the note on [`GroupReceiver::document_of`].

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex;

use anp::group_e2ee::operations::v2::V2DidDocument;
use anp::group_e2ee::v2_models::V2GroupApplicationPlaintext;

use crate::error::{AgentxError, Result};
use crate::group::group_target;
use crate::identity::{Identity, IdentityLocation};
use crate::message::channel::{
    call_group, open_channel_for, policy_for, Channel, Sender, GROUP_E2EE_INCOMING,
    GROUP_E2EE_NOTICE, GROUP_E2EE_SECURITY_PROFILE, GROUP_GET_INFO,
};
use crate::message::resolve::{did_host, document_in_crate_form, resolve_did_document};
use crate::mls::{decrypt_received, process_notice, DecryptInput};
use crate::group_e2ee::{incoming_of_frame, notice_of_frame};

/// What one pushed frame amounted to, once it has been applied to this device's state.
///
/// Owned values rather than the crate's structs: the renderer draws a line, and a crate type
/// would make it depend on the crate for a field it can already see. `Serialize` because
/// `msg listen --json` prints this object directly.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GroupEvent {
    /// A `group.e2ee.notice` — a Commit or a Welcome (§12.2), now applied.
    Notice {
        group_did: String,
        notice_type: String,
        from_epoch: String,
        epoch: String,
        /// §12.3: this device was the subject of a removal, so the notice just applied is the
        /// last one it will ever get for this group. It is why a listener says so loudly.
        self_removed: bool,
    },
    /// A P6 `group.incoming` — application ciphertext (§12.5), now decrypted.
    Message {
        group_did: String,
        from: String,
        message_id: String,
        /// §12.5: the same value in every leaf's copy of one accepted `send`. The ordering
        /// field, exactly as `group.send`'s response reports it for the sender (§8.9.4).
        group_event_seq: Option<String>,
        accepted_at: Option<String>,
        content_type: String,
        /// §7.4's exactly-one-of, as it came out of the ciphertext. A JSON `payload` is shown
        /// as JSON; this is the receiver's own key material at work, not the service's.
        text: Option<String>,
        payload: Option<Value>,
    },
}

impl GroupEvent {
    /// Whether this is something a peer said, rather than a change in the group itself. The
    /// renderer sends the first to stdout and the second to stderr, so that
    /// `msg listen > messages.txt` holds messages.
    pub fn is_message(&self) -> bool {
        matches!(self, GroupEvent::Message { .. })
    }
}

/// Where a §12 frame goes, as the transport sees it.
///
/// [`GroupReceiver`] is the only implementation that ships. The trait exists for the same
/// reason [`crate::message::listen::ListenView`] does: the dispatch decision lives in the
/// listener's loop, and a test that wants to drive that decision should not need a service, a
/// roster and a DID resolver behind it.
pub trait GroupSink: Send + Sync {
    fn handle<'a>(
        &'a self,
        method: &'a str,
        frame: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Option<GroupEvent>>> + Send + 'a>>;
}

impl GroupSink for GroupReceiver {
    fn handle<'a>(
        &'a self,
        method: &'a str,
        frame: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<Option<GroupEvent>>> + Send + 'a>> {
        Box::pin(self.apply(method, frame))
    }
}

/// The P6 receive path for one run of `msg listen`: this device, and the groups it hears from.
pub struct GroupReceiver {
    client: reqwest::Client,
    location: IdentityLocation,
    identity: Identity,
    allow_private: Vec<String>,
    /// One entry per group this run has already resolved. See [`Self::channel_for`].
    channels: Mutex<HashMap<String, Arc<Channel>>>,
}

impl GroupReceiver {
    pub fn new(
        client: reqwest::Client,
        location: IdentityLocation,
        identity: Identity,
        allow_private: Vec<String>,
    ) -> Self {
        Self {
            client,
            location,
            identity,
            allow_private,
            channels: Mutex::new(HashMap::new()),
        }
    }

    /// Apply one pushed frame, or report that it is not one this half takes.
    ///
    /// `Ok(None)` is not a failure: it is the answer for every frame that is not P6 — including
    /// P4's own `group.incoming` notification, which shares its method name (the service keeps
    /// the two apart by module, `groupEnvelopes.ts` vs `groups.ts`). §12.5 pins the P6 one's
    /// security profile to `group-e2ee`, and that is the only thing on the wire that tells them
    /// apart, so it is what this checks.
    pub async fn apply(&self, method: &str, frame: &Value) -> Result<Option<GroupEvent>> {
        if method == GROUP_E2EE_NOTICE {
            return self.notice(frame).await.map(Some);
        }
        if method == GROUP_E2EE_INCOMING && self.is_group_e2ee(frame) {
            return self.message(frame).await.map(Some);
        }
        Ok(None)
    }

    /// §12.5 L1484: the application-ciphertext arm is read at `group-e2ee`, one notch above the
    /// transport default P4's same-named notification keeps.
    fn is_group_e2ee(&self, frame: &Value) -> bool {
        frame
            .get("params")
            .and_then(|params| params.get("meta"))
            .and_then(|meta| meta.get("security_profile"))
            .and_then(Value::as_str)
            == Some(GROUP_E2EE_SECURITY_PROFILE)
    }

    /// Apply a Commit or a Welcome (P6 §12.2).
    ///
    /// The crate wants the **whole** leaf set's documents on this path, not just the sender's:
    /// a Welcome validates every binding in the ratchet tree it carries. So the roster is read
    /// from P4 (`group.get_info`'s `member_list`, §8.2.2) rather than from the local MLS state —
    /// which on a first Welcome does not hold the group yet, and could not answer at all.
    async fn notice(&self, frame: &Value) -> Result<GroupEvent> {
        let (meta, notice) = notice_of_frame(frame)?;
        let group_did = notice.group_did.clone();
        let member_documents = self.member_documents(&group_did).await?;

        let applied =
            process_notice(&self.location, &self.identity, meta, notice, member_documents)?;
        Ok(GroupEvent::Notice {
            group_did,
            notice_type: applied.notice_type,
            from_epoch: applied.from_epoch,
            epoch: applied.epoch,
            self_removed: applied.self_removed,
        })
    }

    /// Decrypt one application message (P6 §12.5).
    ///
    /// `decrypt_received` is the variant that admits a redelivery of an input it already holds:
    /// the service deletes a queue row only after the socket write succeeds (§12.6), so a
    /// reconnect can hand this device a message it has already decrypted. The strict variant
    /// would report that as a failure.
    async fn message(&self, frame: &Value) -> Result<GroupEvent> {
        let incoming = incoming_of_frame(frame)?;
        let group_did = incoming.cipher.group_state_ref.group_did.clone();
        let sender_did_document = self.document_of(&incoming.meta.sender_did).await?;

        let plaintext: V2GroupApplicationPlaintext = decrypt_received(
            &self.location,
            &self.identity,
            DecryptInput {
                originating_meta: incoming.meta.clone(),
                group_cipher_object: incoming.cipher,
                sender_did_document,
            },
        )?
        .application_plaintext;

        Ok(GroupEvent::Message {
            group_did,
            from: incoming.meta.sender_did,
            message_id: incoming.meta.message_id,
            group_event_seq: incoming.group_event_seq,
            accepted_at: incoming.accepted_at,
            content_type: plaintext.application_content_type.clone(),
            text: plaintext.text,
            payload: plaintext.payload,
        })
    }

    /// The channel to a group — resolved once per run, then reused.
    ///
    /// A channel is *where the service is*: an endpoint and the host's DID, both of which this
    /// run would otherwise re-resolve on every pushed frame. Unlike a DID document (below), a
    /// stale copy does not change what a signature is checked against, so holding one is not a
    /// second answer to a cryptographic question.
    async fn channel_for(&self, group_did: &str) -> Result<Arc<Channel>> {
        let mut channels = self.channels.lock().await;
        if let Some(channel) = channels.get(group_did) {
            return Ok(channel.clone());
        }
        let sender = Sender::from_identity(&self.identity)?;
        let channel = Arc::new(
            open_channel_for(&self.client, sender, group_did, &self.allow_private).await?,
        );
        channels.insert(group_did.to_string(), channel.clone());
        Ok(channel)
    }

    /// Every active member's DID document, in the crate's `V2DidDocument` pair form.
    ///
    /// One document per **DID**, not per device: the crate's `exact_did_document` refuses a set
    /// where one DID appears twice, and a second device of the same agent is the same document.
    async fn member_documents(&self, group_did: &str) -> Result<Vec<V2DidDocument>> {
        let channel = self.channel_for(group_did).await?;
        let mut body = Map::new();
        // §8.2.2: the roster is a projection of `group.get_info`, asked for by name.
        body.insert("include_member_list".to_string(), json!(true));
        let info = call_group(
            &self.client,
            &channel,
            GROUP_GET_INFO,
            group_target(group_did),
            body,
            group_did,
        )
        .await?;

        let mut documents = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for member in info
            .get("member_list")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(did) = member.get("agent_did").and_then(Value::as_str) else {
                continue;
            };
            if seen.iter().any(|known| known == did) {
                continue;
            }
            seen.push(did.to_string());
            documents.push(V2DidDocument {
                did: did.to_string(),
                document: self.document_of(did).await?,
            });
        }
        if documents.is_empty() {
            return Err(AgentxError::MessageInvalid(format!(
                "{group_did} answered group.get_info without a member_list, and a notice cannot \
                 be applied without every member's document (P6 §12.2)"
            )));
        }
        Ok(documents)
    }

    /// One DID's document, in the form the crate's checks accept.
    ///
    /// Fetched through the one host the DID names, exactly as `discover` fetches one — and
    /// **not** cached. A document is the authority on which keys a device signs with right now;
    /// a copy held from earlier in a long-running listener would be a second answer to that,
    /// and the failure it produces (a signature that no longer verifies) would look like a
    /// broken peer rather than a stale cache.
    async fn document_of(&self, did: &str) -> Result<Value> {
        let policy = policy_for(&[did_host(did)?], &self.allow_private);
        let document = resolve_did_document(&self.client, did, &policy).await?;
        document_in_crate_form(&document).ok_or_else(|| {
            AgentxError::MessageInvalid(format!(
                "{did}'s document does not bind in a form this crate accepts"
            ))
        })
    }
}
