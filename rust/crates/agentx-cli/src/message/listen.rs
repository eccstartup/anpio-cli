//! `msg listen` — the state machine behind the CLI's only long-running process.
//!
//! The contract is docs/design/realtime.md §7, and the shape of the code follows one
//! decision from it: **the transport is injected** ([`super::stream::ConnectFn`]). Nothing
//! below opens a socket; it is handed something that does. That is not testability for its
//! own sake — a state machine that could only be exercised by a live service would ship
//! unexercised. What is injected is only the connection; the handshake, the cursor
//! arithmetic, the backoff and the decoding are all real code under test, and the tests at
//! the bottom of this file drive them over an in-memory duplex.
//!
//! Rendering is the [`ListenView`] at the bottom. This file decides; that one draws.

use std::collections::VecDeque;
use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Local};
use serde::Serialize;
use serde_json::{json, Map, Value};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;

use crate::error::{AgentxError, AnpErrorObject, Result};
use crate::group_receive::{GroupEvent, GroupSink};

use super::channel::{
    sign_request, CallRequest, Channel, Sender, METHOD_NOT_FOUND, UNSUPPORTED_PROFILE,
};
use super::envelope::{AnpTarget, TargetKind};
use super::stream::{
    stream_url, ConnectFn, Frame, StreamSide, DELTA_PAGE, INCOMING_METHODS, STREAM_ACK,
    STREAM_AUTH, STREAM_HELLO, STREAM_PROFILE, SYNC_DELTA,
};

/// realtime.md §9: the read surface's Profile — `sync.delta` is a business extension method,
/// not a transport one, so it is interpreted under this.
const INBOX_PROFILE: &str = "x_agentx.inbox.v1";

/// realtime.md §7.2: exponential backoff, bounded. The base is 2s so attempt 2 lands on the
/// 4s the design document's own example shows.
const BACKOFF_BASE_MS: u64 = 2000;
const BACKOFF_MAX_MS: u64 = 30_000;
/// ±20%. A fixed schedule makes every client of a restarted service reconnect together.
const BACKOFF_JITTER: f64 = 0.2;

// ---- one event ----------------------------------------------------------------

/// One message as it arrives. The fields are the ones a renderer needs and no more:
/// re-stating the whole envelope here would make this a second implementation of it.
#[derive(Debug, Clone, Serialize)]
pub struct ListenMessage {
    #[serde(rename = "type")]
    pub kind: &'static str,
    /// The delivery cursor this message came with. Monotonic per device, which is what makes
    /// it the right key to deduplicate on across a reconnect (realtime.md §5.2).
    pub seq: u64,
    pub message_id: String,
    /// The sender, as a DID. There is no address book, and a display name invented here would
    /// be one more thing to disagree with the peer's own view of who sent it.
    pub from: String,
    /// `agent` for a direct message, `group` for one addressed to a group.
    pub target_kind: &'static str,
    /// Set when `target_kind` is `group`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_did: Option<String>,
    pub content_type: String,
    /// Set when the body was text. A P5/P6 payload stays opaque — this client holds no key
    /// and never will (message-service.md §11), so the line says what it is instead of
    /// nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// When the body carried a JSON `payload`, that object — **not serialized**, because the
    /// line a consumer reads already has it: `text` above is the same value pretty-printed,
    /// which is what a renderer wants. This field exists for the local record
    /// (client-messages.md §3), which keeps §7.4's distinction between "the text was this
    /// string" and "the payload was this object" instead of flattening it. So when this is
    /// set, `text` is a rendering of it and not a second body.
    #[serde(skip_serializing)]
    pub payload: Option<Value>,
    /// When the service accepted it, as the service reported it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_at: Option<String>,
}

/// The three non-message states are the login's vocabulary plus `reconnecting`, so a consumer
/// that already reads `anp login --json` reads this too.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ListenState {
    Connecting { service: String },
    Connected { device: String, head: u64 },
    Reconnecting { attempt: u32, after_ms: u64 },
    Error { code: String, message: String },
}

/// One line of the stream.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ListenEvent {
    State(ListenState),
    Message(ListenMessage),
    /// A group-e2ee frame this device decrypted or applied itself. Not a [`ListenMessage`]:
    /// that one is a service-visible delivery, and §12's envelope never is — a listener that
    /// drew the two alike would be claiming the service can read a message it cannot.
    Group(GroupEvent),
}

// ---- reading frames -----------------------------------------------------------

/// A server-initiated frame. Only Notifications are read this way: a Response carries an `id`
/// and belongs to the request that is waiting for it.
fn notification_of(frame: &Value) -> Option<(String, &Map<String, Value>)> {
    let row = frame.as_object()?;
    if row.contains_key("id") {
        return None;
    }
    let method = string_at(Some(row), "method")?;
    let params = row.get("params")?.as_object()?;
    Some((method, params))
}

/// A non-empty string at `key`, or nothing. Peers are narrowed rather than trusted: every
/// field read here may be missing from a different implementation.
fn string_at(row: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    row.and_then(|row| row.get(key))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn number_at(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

/// A delivered message, or `None` for a frame that is not one.
///
/// The decoding is message-service.md §8.2 read backwards: the payload a service pushes is the
/// original message's `meta` and `body`, unchanged, with `origin_proof` copied rather than
/// re-signed. Nothing here verifies that proof — this client holds no key of the sender's, and
/// the service is the party that checked it on the way in; what this does is take the service
/// at the field names it promised.
pub fn decode_message(frame: &Value, seq: u64) -> Option<ListenMessage> {
    let (method, params) = notification_of(frame)?;
    if !INCOMING_METHODS.contains(&method.as_str()) {
        return None;
    }

    let meta = params.get("meta").and_then(Value::as_object);
    let body = params.get("body").and_then(Value::as_object);
    let target = meta.and_then(|meta| meta.get("target")).and_then(Value::as_object);
    let group = string_at(target, "kind").as_deref() == Some("group");
    let group_did = if group { string_at(target, "did") } else { None };

    Some(ListenMessage {
        kind: "message",
        seq,
        message_id: string_at(meta, "message_id")
            .or_else(|| string_at(meta, "operation_id"))
            .unwrap_or_else(|| format!("seq-{seq}")),
        from: string_at(meta, "sender_did").unwrap_or_else(|| "(unknown sender)".to_string()),
        target_kind: if group { "group" } else { "agent" },
        group_did,
        content_type: string_at(meta, "content_type")
            .unwrap_or_else(|| "application/octet-stream".to_string()),
        text: body_text(body),
        // §7.4's second arm, kept as the object it was so the local record can tell the two
        // arms apart (`body_text` above renders it into a line).
        payload: body.and_then(|body| body.get("payload")).cloned(),
        accepted_at: string_at(meta, "created_at"),
    })
}

/// P3 §6.2: exactly one of `text` / `payload` / `payload_b64u` is present. Text is passed
/// through; a JSON payload is shown as JSON; an encrypted or binary one is left opaque, which
/// leaves `text` unset so the renderer says what the body is instead of printing a blob.
fn body_text(body: Option<&Map<String, Value>>) -> Option<String> {
    let body = body?;
    if let Some(text) = body.get("text").and_then(Value::as_str) {
        return Some(text.to_string());
    }
    if let Some(payload) = body.get("payload") {
        return Some(
            serde_json::to_string_pretty(payload).unwrap_or_else(|_| payload.to_string()),
        );
    }
    None
}

// ---- backoff ------------------------------------------------------------------

/// realtime.md §7.2: exponential with jitter, bounded. `random` is a parameter so a test can
/// pin the schedule instead of asserting against a moving target.
pub fn backoff_ms(attempt: u32, random: f64) -> u64 {
    let growth =
        (BACKOFF_BASE_MS as f64 * 2f64.powi(attempt.saturating_sub(1) as i32)).min(BACKOFF_MAX_MS as f64);
    let swing = growth * BACKOFF_JITTER * (random * 2.0 - 1.0);
    // The floor matters: the jitter's lower half can pull the first attempt below the base,
    // and a reconnect that is faster than the base is a hot loop with extra steps.
    ((growth + swing).round() as i64).max(BACKOFF_BASE_MS as i64) as u64
}

// ---- frames as a queue ---------------------------------------------------------

/// One arrival from the stream, as the reader sees it.
enum Arrival {
    Frame(Value),
    Closed,
}

/// The socket's frames, held for a consumer that reads them one at a time. The transport
/// delivers into a channel and the state machine reads with `await`; the only thing this adds
/// is the **put-back** — a Notification that arrives while a Response is awaited was not
/// consumed by that wait, and dropping it would lose a message.
struct Arrivals {
    inbound: UnboundedReceiver<Frame>,
    held: VecDeque<Value>,
    closed: bool,
    abort: watch::Receiver<bool>,
}

impl Arrivals {
    fn new(inbound: UnboundedReceiver<Frame>, abort: watch::Receiver<bool>) -> Self {
        Self {
            inbound,
            held: VecDeque::new(),
            closed: false,
            abort,
        }
    }

    /// The next frame, or `Closed`. A Ctrl-C ends the wait immediately rather than after the
    /// next frame, which is the difference between a listener that exits and one that hangs.
    async fn next(&mut self) -> Arrival {
        if let Some(frame) = self.held.pop_front() {
            return Arrival::Frame(frame);
        }
        if self.closed {
            return Arrival::Closed;
        }
        if *self.abort.borrow() {
            self.closed = true;
            return Arrival::Closed;
        }

        // The two futures borrow different fields, and the arms only produce a value — the
        // `self.closed` write happens after the borrows are gone, which is why this is written
        // as a `select!` that yields rather than one that handles in place.
        let arrival = tokio::select! {
            biased;
            // The only value ever sent is `true`, and a dropped sender is the same news, so
            // any change here is an interrupt.
            _ = self.abort.changed() => Arrival::Closed,
            received = self.inbound.recv() => match received {
                Some(Frame::Raw(frame)) => Arrival::Frame(frame),
                Some(Frame::Closed(_)) | None => Arrival::Closed,
            },
        };
        if matches!(arrival, Arrival::Closed) {
            self.closed = true;
        }
        arrival
    }

    /// Put frames back at the front, in the order they came.
    fn hold_back(&mut self, frames: Vec<Value>) {
        for frame in frames.into_iter().rev() {
            self.held.push_front(frame);
        }
    }
}

// ---- the session ---------------------------------------------------------------

/// The command's options, resolved by the command face.
pub struct ListenArgs {
    pub device: String,
    /// §5.4: a debugging override of the service-side cursor. **Nothing local is stored** —
    /// storing it here would be a second source of truth, and the two would disagree.
    pub since: Option<u64>,
    /// §6: **off by default.** Forgetting to ack replays a message; acking one nobody read
    /// loses it forever, and this is the only one of the two that is recoverable.
    pub ack: bool,
    /// §7.2: backfill, then exit 0. The escape hatch that makes this command usable from a
    /// script without touching the long-running contract.
    pub once: bool,
}

/// Where an event goes. A trait rather than a function so a test can record instead of print.
pub trait ListenView: Send + Sync {
    fn event(&self, event: &ListenEvent);
}

/// The real dependencies. `connect` is what a test replaces.
pub struct ListenDeps {
    pub connect: ConnectFn,
    pub view: Arc<dyn ListenView>,
    pub abort: watch::Receiver<bool>,
    /// Jitter source, `[0, 1)`. Injected so a test's reconnect schedule is deterministic.
    pub random: Arc<dyn Fn() -> f64 + Send + Sync>,
    /// The P6 receive path (group-e2ee.md §12). `None` on a run that was not given one — the
    /// transport then treats §12's frames as it always did, by not knowing them.
    pub receiver: Option<Arc<dyn GroupSink>>,
}

/// How one connection ended. `Frame` is what continuing looks like.
enum Step {
    Frame(Value),
    Ended,
    Dropped,
    Fatal(AgentxError),
}

struct SessionCtx<'a> {
    url: &'a str,
    args: &'a ListenArgs,
    view: &'a dyn ListenView,
    channel: &'a Channel,
    receiver: Option<&'a dyn GroupSink>,
}

/// The device this stream is (§5.4). Defaults to the local `agent/profile` — the same two
/// names the store already keeps everything else under, so "the same machine, a different
/// profile" is two devices, as it should be.
pub fn device_of(sender: &Sender, named: Option<&str>) -> Result<String> {
    match named {
        Some(named) => {
            if named.trim().is_empty() {
                return Err(AgentxError::MessageInvalid(
                    "--device must not be empty".to_string(),
                ));
            }
            Ok(named.to_string())
        }
        None => Ok(format!("{}/{}", sender.agent, sender.profile)),
    }
}

/// Connect, and stay connected, until something ends the run.
///
/// realtime.md §7.2: a drop reconnects, an interrupted run exits 0, and a refusal that will
/// not change on retry exits 1. Nothing here resets the attempt counter — a service that
/// accepts a connection and immediately drops it is exactly the case the backoff exists for.
pub async fn run_listen(channel: &Channel, args: ListenArgs, deps: ListenDeps) -> Result<()> {
    let url = stream_url(&channel.endpoint.target.endpoint)?;
    let ctx = SessionCtx {
        url: &url,
        args: &args,
        view: deps.view.as_ref(),
        channel,
        receiver: deps.receiver.as_deref(),
    };

    let mut attempt: u32 = 0;
    loop {
        if attempt == 0 {
            deps.view.event(&ListenEvent::State(ListenState::Connecting {
                service: url.clone(),
            }));
        }

        let step = match (deps.connect)(url.clone()).await {
            Ok(side) => session(side, &ctx, deps.abort.clone()).await,
            // A transport that cannot open is a dropped connection, not a verdict: the
            // backoff above is the answer to it.
            Err(_) => Step::Dropped,
        };

        match step {
            Step::Fatal(error) => {
                deps.view.event(&ListenEvent::State(ListenState::Error {
                    code: error.code().to_string(),
                    message: error.to_string(),
                }));
                return Err(error);
            }
            // `Step::Frame` cannot reach here: `session` only yields one from inside itself.
            Step::Ended | Step::Frame(_) => return Ok(()),
            Step::Dropped => {}
        }
        if *deps.abort.borrow() {
            return Ok(());
        }

        attempt += 1;
        let delay = backoff_ms(attempt, (deps.random)());
        deps.view.event(&ListenEvent::State(ListenState::Reconnecting {
            attempt,
            after_ms: delay,
        }));
        sleep_until(delay, &mut deps.abort.clone()).await;
        if *deps.abort.borrow() {
            return Ok(());
        }
    }
}

/// One connection, from upgrade to close. Everything that ends a stream ends it here: a
/// refusal, an interrupt, `--once` finishing, or the socket going away.
async fn session(side: StreamSide, ctx: &SessionCtx<'_>, abort: watch::Receiver<bool>) -> Step {
    let StreamSide { outbound, inbound } = side;
    let mut arrivals = Arrivals::new(inbound, abort);

    // realtime.md §4.2: the server says who it is before anything is signed, and the stream is
    // a plaintext upgrade until then — so this is the first man-in-the-middle check.
    let hello = match expect_notification(&mut arrivals, STREAM_HELLO).await {
        Step::Frame(params) => params,
        _ => return Step::Dropped,
    };
    if let Some(expected) = &ctx.channel.endpoint.target.service_did {
        let introduced = string_at(hello.as_object(), "server_did");
        if introduced.as_deref() != Some(expected.as_str()) {
            return Step::Fatal(AgentxError::MessageInvalid(format!(
                "{} introduced itself as {}, but the DID document names {expected} (realtime.md §4.2)",
                ctx.url,
                introduced.as_deref().unwrap_or("(nothing)")
            )));
        }
    }

    let ready = match authenticate(&outbound, &mut arrivals, ctx).await {
        Step::Frame(ready) => ready,
        other => return other,
    };
    let head_seq = number_at(&ready, "head_seq").unwrap_or(0);
    let cursor_accepted = number_at(&ready, "cursor_accepted").unwrap_or(ctx.args.since.unwrap_or(0));
    ctx.view.event(&ListenEvent::State(ListenState::Connected {
        device: ctx.args.device.clone(),
        head: head_seq,
    }));

    match delta(&outbound, &mut arrivals, ctx, cursor_accepted).await {
        Step::Frame(_) => {}
        other => return other,
    }
    if ctx.args.once {
        return Step::Ended;
    }

    live(&outbound, &mut arrivals, ctx, head_seq).await
}

/// The handshake (§4): one authenticated Request, whose result is the ready payload. Signed
/// over `{method, meta, body}` exactly as every other call is — the handshake is where the
/// connection learns who is on it, so it is the last place to accept something unsigned.
async fn authenticate(
    outbound: &UnboundedSender<Value>,
    arrivals: &mut Arrivals,
    ctx: &SessionCtx<'_>,
) -> Step {
    let mut body = Map::new();
    body.insert("device_id".to_string(), json!(ctx.args.device));
    if let Some(since) = ctx.args.since {
        body.insert("cursor".to_string(), json!(since));
    }
    request(outbound, arrivals, ctx, STREAM_AUTH, body).await
}

/// The backfill (§5.2): everything this device missed, from the accepted cursor up to the head
/// the server took when it registered the connection. The server holds live frames until this
/// exchange finishes, so there is no gap for one to fall into.
async fn delta(
    outbound: &UnboundedSender<Value>,
    arrivals: &mut Arrivals,
    ctx: &SessionCtx<'_>,
    since: u64,
) -> Step {
    let mut cursor = since;
    loop {
        let mut body = Map::new();
        body.insert("since".to_string(), json!(cursor));
        body.insert("limit".to_string(), json!(DELTA_PAGE));
        // 补的是**这台设备**错过的东西。服务端按 `device_id` 筛交付行，不声明就只看得到
        // 账号级的那批——而同一台信箱的实时那一半是按设备推的，两边必须用同一个名字，
        // 否则补课会把别的设备的密文也拖进来，或者把自己那条漏掉。
        body.insert("device_id".to_string(), json!(ctx.args.device));
        let page = match request(outbound, arrivals, ctx, SYNC_DELTA, body).await {
            Step::Frame(page) => page,
            other => return other,
        };

        for entry in page.get("messages").and_then(Value::as_array).into_iter().flatten() {
            // message-service.md §9.3: each entry IS the notification the stream would have
            // pushed, with the delivery number the stream would have given it. One decoder
            // therefore serves both halves of the connection.
            let Some(row) = entry.as_object() else { continue };
            let seq = number_at(entry, "seq").unwrap_or(cursor);
            let frame = json!({
                "jsonrpc": "2.0",
                "method": row.get("method"),
                "params": row.get("params"),
            });
            if let Some(message) = decode_message(&frame, seq) {
                ctx.view.event(&ListenEvent::Message(message));
            }
        }

        if page.get("has_more").and_then(Value::as_bool) != Some(true) {
            return Step::Frame(page);
        }
        // A page that does not move the cursor would repeat forever, and an empty page that
        // claims more would too, which is what the second half guards.
        match number_at(&page, "next_since") {
            Some(next) if next > cursor => cursor = next,
            _ => return Step::Frame(page),
        }
    }
}

/// Offer one frame to the group-e2ee receive path, if this run has one.
///
/// `None` means "not mine, read it as an ordinary delivery": either no receiver was given, or
/// the frame is not one of §12's two — including P4's own `group.incoming`, which shares a
/// method name and is told apart by its security profile inside the receiver.
///
/// `Some(Err(_))` is the receiver's verdict on a frame it *did* claim, and it is deliberately
/// not a fall-through: a frame that reached the e2ee path must never also be drawn as a
/// service-visible delivery, which is what [`decode_message`] would make of it.
async fn dispatch_group(
    ctx: &SessionCtx<'_>,
    method: &str,
    frame: &Value,
) -> Option<Result<GroupEvent>> {
    let receiver = ctx.receiver?;
    match receiver.handle(method, frame).await {
        Ok(Some(event)) => Some(Ok(event)),
        Ok(None) => None,
        Err(error) => Some(Err(error)),
    }
}

/// After the backfill the cursor is the head the server took at registration, and every frame
/// from here on is one message further (§5.5). Non-message notifications do not advance it —
/// they are not queue entries.
async fn live(
    outbound: &UnboundedSender<Value>,
    arrivals: &mut Arrivals,
    ctx: &SessionCtx<'_>,
    head_seq: u64,
) -> Step {
    let mut cursor = head_seq;
    loop {
        let frame = match arrivals.next().await {
            Arrival::Closed => return Step::Dropped,
            Arrival::Frame(frame) => frame,
        };
        let Some((method, _)) = notification_of(&frame) else {
            continue; // a Response nobody is waiting for
        };

        // group-e2ee.md §12's two frames are answered before the delivery filter, and
        // `continue` here is load-bearing: §12.6 gives them no `deliveries` row, so they are
        // not queue entries and must not move the cursor — moving it would claim this device
        // has been delivered a message it was never sent, and the next reconnect would skip
        // whatever sits at that number.
        if let Some(outcome) = dispatch_group(ctx, &method, &frame).await {
            match outcome {
                Ok(event) => ctx.view.event(&ListenEvent::Group(event)),
                // Not fatal: a notice that arrived before one it depends on applies on a
                // later frame, so exiting would throw away a session that is about to work.
                // The listener reports it the way it reports any other state change.
                Err(error) => ctx.view.event(&ListenEvent::State(ListenState::Error {
                    code: error.code().to_string(),
                    message: error.to_string(),
                })),
            }
            continue;
        }

        if !INCOMING_METHODS.contains(&method.as_str()) {
            continue;
        }
        cursor += 1;
        let Some(message) = decode_message(&frame, cursor) else {
            continue;
        };
        ctx.view.event(&ListenEvent::Message(message));

        if ctx.args.ack {
            // §6: what is left of the two calls is the one that has to be online. `stream.ack`
            // moves this device's delivery cursor, and is therefore what keeps a reconnect
            // from replaying. The *read* state used to be a second call here
            // (`inbox.mark_read`); after the 2026-10-03 ruling it lives in `messages.db`, and
            // `RecordingView` marks the row it just wrote (design §4) — so this side stays
            // unaware of it. Neither is a read receipt for the sender: the spec defines none
            // (§6's ⚠).
            //
            // The backfill is deliberately not acked: the cursor only ever moves forwards, so
            // the first live ack carries it past everything the backfill showed, and `--once`
            // has to stay the read-only one-shot §7.2 calls it.
            let mut ack = Map::new();
            ack.insert("seq".to_string(), json!(cursor));
            match request(outbound, arrivals, ctx, STREAM_ACK, ack).await {
                Step::Frame(_) => {}
                other => return other,
            }
        }
    }
}

/// Which Profile each method belongs to (realtime.md §9).
///
/// Per method, not one constant for the connection: `meta.profile` is "the single
/// interpretation of this request" (P1 §6.2.2), and a method's own Profile is what says which
/// interpretation this request is. Sending the wrong one is a 1001
/// `anp.unsupported_profile`, which only a real service answers.
fn profile_for(method: &str) -> &'static str {
    match method {
        STREAM_AUTH | STREAM_ACK => STREAM_PROFILE,
        _ => INBOX_PROFILE,
    }
}

/// One extension call over the stream, signed exactly as the HTTP path signs one. The refusal
/// rules are the read surface's (message-service.md §9): a peer that does not have this method
/// has **answered**, and the caller gets to say so rather than reporting a generic failure.
async fn request(
    outbound: &UnboundedSender<Value>,
    arrivals: &mut Arrivals,
    ctx: &SessionCtx<'_>,
    method: &str,
    body: Map<String, Value>,
) -> Step {
    let id = super::channel::uuid_v4();
    let envelope = match sign_request(
        &ctx.channel.sender,
        &id,
        CallRequest {
            method: method.to_string(),
            profile: profile_for(method).to_string(),
            // P1 附录 A.4: a method carrying an `origin_proof` MUST have `meta.target`, and the
            // same appendix leaves an endpoint-local method's target modelling to its Profile
            // (realtime.md §9). The queue being subscribed to belongs to the identity in use.
            target: AnpTarget {
                kind: TargetKind::Agent,
                did: ctx.channel.sender.did.clone(),
            },
            body,
            sender_device_id: None,
            security_profile: None,
            message_id: None,
            content_type: None,
            operation_id: None,
        },
    ) {
        Ok(envelope) => envelope,
        Err(error) => return Step::Fatal(error),
    };
    let frame = match serde_json::to_value(&envelope) {
        Ok(frame) => frame,
        Err(error) => return Step::Fatal(error.into()),
    };
    if outbound.send(frame).is_err() {
        return Step::Dropped;
    }

    let Some(reply) = read_response(arrivals, &id).await else {
        return Step::Dropped;
    };
    let Some(error) = reply.get("error").cloned() else {
        // §5.6: a success carries `result`. A result that is not an object is not something
        // any caller here can read, and `{}` is the shape `asRow(x) ?? {}` gives it.
        let result = reply.get("result").cloned().unwrap_or(Value::Null);
        return Step::Frame(if result.is_object() { result } else { json!({}) });
    };
    let error: AnpErrorObject = match serde_json::from_value(error) {
        Ok(error) => error,
        Err(err) => {
            return Step::Fatal(AgentxError::MessageInvalid(format!(
                "{method} answered with an error object missing code or message (P1 §10.2): {err}"
            )))
        }
    };

    let anp_code = error.data.as_ref().and_then(|data| data.anp_code.clone());
    let named = anp_code
        .clone()
        .unwrap_or_else(|| format!("JSON-RPC error {}", error.code));
    // §7.2: a refusal is not retried. Reconnecting with the same key gets the same answer, and
    // a loop of them would look like a working listener.
    if error.code == METHOD_NOT_FOUND || anp_code.as_deref() == Some(UNSUPPORTED_PROFILE) {
        return Step::Fatal(AgentxError::UnsupportedExtension(format!(
            "{} does not implement {method} ({named}): the stream is an implementation extension, \
             not defined by the ANP message specification",
            ctx.url
        )));
    }
    Step::Fatal(AgentxError::MessageSendFailed(format!(
        "{} rejected {method}: {named}: {}",
        ctx.channel.sender.did, error.message
    )))
}

// ---- small readers ------------------------------------------------------------

/// Read until the next Notification with this method. A Response here belongs to a request
/// that is no longer waiting, and is skipped.
async fn expect_notification(arrivals: &mut Arrivals, method: &str) -> Step {
    loop {
        let frame = match arrivals.next().await {
            Arrival::Closed => return Step::Dropped,
            Arrival::Frame(frame) => frame,
        };
        if let Some((found, params)) = notification_of(&frame) {
            if found == method {
                return Step::Frame(Value::Object(params.clone()));
            }
        }
    }
}

/// Read until the Response to `id`. A Notification that arrives first is not consumed by this
/// wait, so it is put back once the response is in hand — a message that arrived while a
/// `sync.delta` page was in flight is still a message.
async fn read_response(arrivals: &mut Arrivals, id: &str) -> Option<Value> {
    let mut held = Vec::new();
    let found = loop {
        match arrivals.next().await {
            Arrival::Closed => break None,
            Arrival::Frame(frame) => {
                if frame.get("id").and_then(Value::as_str) == Some(id) {
                    break Some(frame);
                }
                held.push(frame);
            }
        }
    };
    arrivals.hold_back(held);
    found
}

/// A sleep a Ctrl-C ends immediately, so the backoff never delays an exit.
async fn sleep_until(ms: u64, abort: &mut watch::Receiver<bool>) {
    if *abort.borrow() {
        return;
    }
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(ms)) => {}
        _ = abort.changed() => {}
    }
}

// ---- the two renderers ---------------------------------------------------------

/// One event, one line, on stdout. Not pretty-printed: this is a wire, and a wire does not
/// pretty-print.
pub struct MachineView;

impl ListenView for MachineView {
    fn event(&self, event: &ListenEvent) {
        if let Ok(line) = serde_json::to_string(event) {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{line}");
        }
    }
}

/// The IM rendering of realtime.md §7.1: a header line naming who sent it and when, then the
/// body hanging under it.
///
/// Messages go to stdout and state changes to stderr, so `agentx-cli msg listen > messages.txt`
/// leaves the file holding messages. No colour: the rendering is a contract, and a terminal
/// capability is not part of one.
pub struct HumanView;

impl ListenView for HumanView {
    fn event(&self, event: &ListenEvent) {
        match event {
            ListenEvent::Message(message) => {
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{}", render_message(message));
            }
            ListenEvent::State(state) => {
                let mut err = std::io::stderr().lock();
                let _ = writeln!(err, "{}", render_state(state));
            }
            // A decrypted application message is a message, and a notice is bookkeeping — the
            // same split the two lines above make, for the same reason.
            ListenEvent::Group(group) => {
                let line = render_group(group);
                if group.is_message() {
                    let mut out = std::io::stdout().lock();
                    let _ = writeln!(out, "{line}");
                } else {
                    let mut err = std::io::stderr().lock();
                    let _ = writeln!(err, "{line}");
                }
            }
        }
    }
}

/// `--json`, or a stdout nobody is looking at. A pipe is a machine even when nobody asked for
/// `--json`: `agentx-cli msg listen | tee log` is a thing people do, and the NDJSON form is the
/// one a file should hold.
pub fn view_for(json: bool) -> Arc<dyn ListenView> {
    if json || !std::io::stdout().is_terminal() {
        Arc::new(MachineView)
    } else {
        Arc::new(HumanView)
    }
}

/// A `group-e2ee.md` §12 event. A decrypted message is drawn like any other — the group heads
/// it and the sender is prefixed — while a notice gets one terser, markered line, because it
/// is not something anyone said.
fn render_group(event: &GroupEvent) -> String {
    match event {
        GroupEvent::Message {
            group_did,
            from,
            content_type,
            text,
            payload,
            accepted_at,
            ..
        } => {
            let when = accepted_at
                .as_deref()
                .map(|at| format!("  {}", format_time(at)))
                .unwrap_or_default();
            let body = text.clone().or_else(|| {
                payload
                    .as_ref()
                    .map(|value| {
                        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
                    })
            });
            // The body is ciphertext the service never saw, so a type this renderer cannot
            // draw is named rather than dropped — the fact that something arrived is the news.
            let body = body.unwrap_or_else(|| format!("[{content_type}]"));
            let mut lines = body.lines();
            let first = lines.next().unwrap_or_default().to_string();
            let mut out = vec![
                format!("● {group_did} (group, e2ee){when}"),
                format!("  {from}: {first}"),
            ];
            out.extend(lines.map(|line| format!("  {line}")));
            out.join("\n")
        }
        GroupEvent::Notice {
            group_did,
            notice_type,
            from_epoch,
            epoch,
            self_removed,
        } => {
            let removed = if *self_removed { " — this device was removed" } else { "" };
            format!("· {group_did}: {notice_type} {from_epoch}→{epoch}{removed}")
        }
    }
}

/// What a person sees, one line per state change. Kept apart from the message rendering
/// because it is not a message: a reconnect notice between two messages reads as one if it is
/// drawn like one.
fn render_state(state: &ListenState) -> String {
    match state {
        ListenState::Connecting { service } => format!("connecting to {service}"),
        ListenState::Connected { device, head } => {
            format!("connected as {device}, at cursor {head}")
        }
        ListenState::Reconnecting { attempt, after_ms } => {
            format!("reconnecting: attempt {attempt} in {}", format_delay(*after_ms))
        }
        ListenState::Error { code, message } => format!("error: {code}: {message}"),
    }
}

/// A group message is headed by the GROUP, with the sender prefixed to the body. The other way
/// round would make two groups look like two private conversations with the same person.
fn render_message(event: &ListenMessage) -> String {
    let group = event.target_kind == "group";
    let where_ = match (group, &event.group_did) {
        (true, Some(did)) => did.as_str(),
        _ => event.from.as_str(),
    };
    let when = event
        .accepted_at
        .as_deref()
        .map(|at| format!("  {}", format_time(at)))
        .unwrap_or_default();
    let head = format!("● {where_}{}{when}", if group { " (group)" } else { "" });

    let lines = body_lines(event);
    let first = match (group, lines.first()) {
        (true, Some(first)) => format!("{}: {first}", event.from),
        (_, Some(first)) => first.clone(),
        (_, None) => String::new(),
    };
    let mut out = vec![head, format!("  {first}")];
    out.extend(lines.into_iter().skip(1).map(|line| format!("  {line}")));
    out.join("\n")
}

/// The body, as lines. Text arrives as it was sent, including its newlines; anything else is
/// described rather than dumped — a reader needs to know a message arrived and what it is, and
/// a base64 blob tells them neither.
fn body_lines(event: &ListenMessage) -> Vec<String> {
    match &event.text {
        Some(text) => text.split('\n').map(str::to_string).collect(),
        None => vec![format!("({} body, not rendered)", event.content_type)],
    }
}

/// `<YYYY-MM-DD HH:MM>` in local time. Hand-formatted rather than through a locale: the output
/// of this command is a contract, and a locale that shifts with the environment would make the
/// same stream render differently on two machines.
fn format_time(iso: &str) -> String {
    match DateTime::parse_from_rfc3339(iso) {
        Ok(at) => at.with_timezone(&Local).format("%Y-%m-%d %H:%M").to_string(),
        Err(_) => iso.to_string(),
    }
}

/// A backoff, said the way a person waiting reads it.
fn format_delay(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        let seconds = (ms as f64 / 100.0).round() / 10.0;
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{create_identity, CreateIdentityInput};
    use crate::message::channel::{
        GROUP_E2EE_INCOMING, GROUP_E2EE_NOTICE, TRANSPORT_PROTECTED,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use tokio::sync::mpsc::unbounded_channel;

    #[test]
    fn backoff_grows_from_the_base_and_stops_at_the_ceiling() {
        // A midpoint draw is the plain schedule: 2s, 4s, 8s, 16s, then the 30s ceiling.
        assert_eq!(backoff_ms(1, 0.5), 2000);
        assert_eq!(backoff_ms(2, 0.5), 4000);
        assert_eq!(backoff_ms(3, 0.5), 8000);
        assert_eq!(backoff_ms(4, 0.5), 16000);
        assert_eq!(backoff_ms(5, 0.5), 30000);
        assert_eq!(backoff_ms(40, 0.5), 30000);
    }

    #[test]
    fn jitter_stays_within_the_band_and_never_undercuts_the_base() {
        assert_eq!(backoff_ms(2, 1.0), 4800); // 4000 + 20%
        assert_eq!(backoff_ms(2, 0.0), 3200); // 4000 - 20%
        // The first attempt's lower half would be 1600; the floor is what stops it.
        assert_eq!(backoff_ms(1, 0.0), 2000);
    }

    #[test]
    fn a_direct_message_decodes_to_the_fields_the_renderer_needs() {
        let frame = json!({
            "jsonrpc": "2.0",
            "method": "direct.incoming",
            "params": {
                "meta": {
                    "message_id": "msg-1",
                    "sender_did": "did:wba:example.com:user:bob",
                    "content_type": "text/plain",
                    "created_at": "2026-10-02T00:00:00Z"
                },
                "body": { "text": "hello" }
            }
        });
        let message = decode_message(&frame, 7).unwrap();
        assert_eq!(message.seq, 7);
        assert_eq!(message.kind, "message");
        assert_eq!(message.message_id, "msg-1");
        assert_eq!(message.from, "did:wba:example.com:user:bob");
        assert_eq!(message.target_kind, "agent");
        assert_eq!(message.group_did, None);
        assert_eq!(message.text.as_deref(), Some("hello"));
    }

    #[test]
    fn a_group_message_carries_the_group_and_its_sender_separately() {
        let frame = json!({
            "method": "group.incoming",
            "params": {
                "meta": {
                    "sender_did": "did:wba:example.com:user:bob",
                    "target": { "kind": "group", "did": "did:wba:example.com:group:team" },
                    "content_type": "text/plain"
                },
                "body": { "text": "attachment sent" }
            }
        });
        let message = decode_message(&frame, 1).unwrap();
        assert_eq!(message.target_kind, "group");
        assert_eq!(message.group_did.as_deref(), Some("did:wba:example.com:group:team"));
        assert_eq!(message.from, "did:wba:example.com:user:bob");
    }

    /// An encrypted payload has no `text`, so the renderer says what the body is instead of
    /// printing a blob. A missing message id falls back to the sequence, which is still a
    /// usable key for `msg show`.
    #[test]
    fn an_opaque_body_and_a_missing_id_still_produce_a_renderable_line() {
        let frame = json!({
            "method": "direct.incoming",
            "params": { "meta": {}, "body": { "payload_b64u": "AAAA" } }
        });
        let message = decode_message(&frame, 3).unwrap();
        assert_eq!(message.text, None);
        assert_eq!(message.message_id, "seq-3");
        assert_eq!(message.from, "(unknown sender)");
        assert_eq!(message.content_type, "application/octet-stream");
    }

    #[test]
    fn responses_and_other_notifications_are_not_messages() {
        // A Response is not a push, even under the same method name.
        assert!(decode_message(
            &json!({"jsonrpc": "2.0", "id": "1", "method": "direct.incoming", "params": {}}),
            1
        )
        .is_none());
        // A group state change is on the same socket but is not a queue entry (§5.5).
        assert!(decode_message(
            &json!({"method": "group.state_changed", "params": {"meta": {}, "body": {}}}),
            1
        )
        .is_none());
    }

    #[test]
    fn the_two_profiles_are_chosen_per_method() {
        assert_eq!(profile_for(STREAM_AUTH), STREAM_PROFILE);
        assert_eq!(profile_for(STREAM_ACK), STREAM_PROFILE);
        // `sync.delta` is the one extension method `msg listen` still calls, and the only
        // member of `x_agentx.inbox.v1` the client has left (design §4, 2026-10-03).
        assert_eq!(profile_for(SYNC_DELTA), INBOX_PROFILE);
    }

    #[test]
    fn the_device_defaults_to_the_local_agent_and_profile() {
        let sender = test_sender();
        assert_eq!(device_of(&sender, None).unwrap(), "carol/default");
        assert_eq!(device_of(&sender, Some("phone")).unwrap(), "phone");
        assert!(device_of(&sender, Some("  ")).is_err());
    }

    /// A sender with a real key, minted locally: the handshake in the session tests is signed
    /// for real, which is the point of exercising it at all.
    fn test_sender() -> Sender {
        let identity = create_identity(CreateIdentityInput {
            authority: "localhost%3A8765".to_string(),
            agent: "carol".to_string(),
            profile: "default".to_string(),
            handle: "carol".to_string(),
            did_host_url: "http://localhost:8765".to_string(),
            service_endpoint: "http://localhost:8765/anp-im/rpc".to_string(),
            service_did: "did:wba:localhost%3A8765:service:anp-message".to_string(),
        })
        .unwrap();
        Sender::from_identity(&identity).unwrap()
    }

    fn test_channel() -> Channel {
        Channel {
            sender: test_sender(),
            endpoint: crate::message::Endpoint {
                target: crate::message::MessageServiceTarget {
                    identity: "did:wba:localhost%3A8765:user:carol".to_string(),
                    service_id: "#anp-message".to_string(),
                    endpoint: "http://localhost:8765/anp-im/rpc".to_string(),
                    service_did: Some("did:wba:localhost%3A8765:service:anp-message".to_string()),
                    hinted_profiles: vec![],
                    hinted_security_profiles: vec![],
                },
                policy: crate::message::ResolvePolicy::default(),
            },
        }
    }

    #[derive(Default)]
    struct RecordingView {
        events: Mutex<Vec<ListenEvent>>,
    }

    impl RecordingView {
        fn events(&self) -> Vec<ListenEvent> {
            self.events.lock().unwrap().clone()
        }

        fn messages(&self) -> Vec<ListenMessage> {
            self.events()
                .into_iter()
                .filter_map(|event| match event {
                    ListenEvent::Message(message) => Some(message),
                    _ => None,
                })
                .collect()
        }
    }

    impl ListenView for RecordingView {
        fn event(&self, event: &ListenEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    /// One client side, plus the server's two ends of the same pair.
    fn duplex() -> (
        StreamSide,
        UnboundedReceiver<Value>,
        UnboundedSender<Frame>,
    ) {
        let (outbound, client_to_server) = unbounded_channel::<Value>();
        let (server_to_client, inbound) = unbounded_channel::<Frame>();
        (
            StreamSide { outbound, inbound },
            client_to_server,
            server_to_client,
        )
    }

    fn hello() -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": STREAM_HELLO,
            "params": {
                "server_did": "did:wba:localhost%3A8765:service:anp-message",
                "head_seq": 0,
                "profiles": []
            }
        })
    }

    fn backfill_entry() -> Value {
        json!({
            "seq": 1,
            "method": "direct.incoming",
            "params": {
                "meta": {
                    "message_id": "msg-1",
                    "sender_did": "did:wba:localhost%3A8765:user:bob",
                    "content_type": "text/plain",
                    "created_at": "2026-10-02T00:00:00Z"
                },
                "body": { "text": "hello" }
            }
        })
    }

    fn live_notification(method: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": {
                "meta": {
                    "message_id": "msg-2",
                    "sender_did": "did:wba:localhost%3A8765:user:bob",
                    "content_type": "text/plain",
                    "created_at": "2026-10-02T00:01:00Z"
                },
                "body": { "text": "live" }
            }
        })
    }

    /// Hand a reply back for the request the client is waiting on: read its `id`, answer it.
    async fn answer(
        server_in: &mut UnboundedReceiver<Value>,
        server_out: &UnboundedSender<Frame>,
        expected_method: &str,
        result: Value,
    ) -> Value {
        let request = server_in.recv().await.unwrap();
        assert_eq!(request.get("method").and_then(Value::as_str), Some(expected_method));
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        server_out
            .send(Frame::Raw(json!({"jsonrpc": "2.0", "id": id, "result": result})))
            .unwrap();
        request
    }

    /// `--once`: the backfill is delivered and the run ends, with no live half to interrupt.
    /// This is realtime.md §5.2's first half, and it needs no signal to be deterministic.
    #[tokio::test]
    async fn a_once_session_backfills_and_ends() {
        let channel = test_channel();
        let (side, mut server_in, server_out) = duplex();
        let view = Arc::new(RecordingView::default());

        server_out.send(Frame::Raw(hello())).unwrap();
        let server = tokio::spawn(async move {
            answer(
                &mut server_in,
                &server_out,
                STREAM_AUTH,
                json!({"device_id": "carol/default", "cursor_accepted": 0, "head_seq": 1}),
            )
            .await;
            answer(
                &mut server_in,
                &server_out,
                SYNC_DELTA,
                json!({"messages": [backfill_entry()], "next_since": 1, "has_more": false}),
            )
            .await;
        });

        let args = ListenArgs {
            device: "carol/default".to_string(),
            since: None,
            ack: false,
            once: true,
        };
        let ctx = SessionCtx {
            url: "ws://localhost:8765/anp-im/stream",
            args: &args,
            view: view.as_ref(),
            channel: &channel,
            receiver: None,
        };
        let (_tx, abort) = watch::channel(false);

        let step = session(side, &ctx, abort).await;
        assert!(matches!(step, Step::Ended));
        server.await.unwrap();

        let events = view.events();
        assert!(matches!(
            events.first(),
            Some(ListenEvent::State(ListenState::Connected { head: 1, .. }))
        ));
        let messages = view.messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].seq, 1);
        assert_eq!(messages[0].text.as_deref(), Some("hello"));
    }

    /// The live half (§5.5): after the backfill the client counts from the head it was given,
    /// so the first pushed frame is `head + 1` even though the frame carries no sequence.
    #[tokio::test]
    async fn live_frames_are_counted_from_the_head_the_server_reported() {
        let channel = test_channel();
        let (side, mut server_in, server_out) = duplex();
        let view = Arc::new(RecordingView::default());

        server_out.send(Frame::Raw(hello())).unwrap();
        tokio::spawn(async move {
            answer(
                &mut server_in,
                &server_out,
                STREAM_AUTH,
                json!({"device_id": "carol/default", "cursor_accepted": 0, "head_seq": 1}),
            )
            .await;
            answer(
                &mut server_in,
                &server_out,
                SYNC_DELTA,
                json!({"messages": [backfill_entry()], "next_since": 1, "has_more": false}),
            )
            .await;
            // Held until the backfill answer was sent, as a real service holds them.
            server_out.send(Frame::Raw(live_notification("direct.incoming"))).unwrap();
            // Dropping the sender ends the stream, which is how this test stops the live loop.
            drop(server_out);
        });

        let args = ListenArgs {
            device: "carol/default".to_string(),
            since: None,
            ack: false,
            once: false,
        };
        let ctx = SessionCtx {
            url: "ws://localhost:8765/anp-im/stream",
            args: &args,
            view: view.as_ref(),
            channel: &channel,
            receiver: None,
        };
        let (_tx, abort) = watch::channel(false);

        assert!(matches!(session(side, &ctx, abort).await, Step::Dropped));
        let messages = view.messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].seq, 1);
        assert_eq!(messages[1].seq, 2);
        assert_eq!(messages[1].text.as_deref(), Some("live"));
    }

    /// §12's frames are answered by the receive path and then dropped, so they must not be
    /// counted as deliveries. The counting is the assertion: the `direct.incoming` that follows
    /// takes `head + 1`, which it could only do if the group frame before it took no number.
    /// A cursor that moved for a frame §12.6 gives no `deliveries` row would skip a real
    /// message on the next reconnect.
    #[tokio::test]
    async fn group_e2ee_frames_are_answered_and_not_counted_as_deliveries() {
        let channel = test_channel();
        let (side, mut server_in, server_out) = duplex();
        let view = Arc::new(RecordingView::default());
        let sink = Arc::new(RecordingSink::default());

        server_out.send(Frame::Raw(hello())).unwrap();
        tokio::spawn(async move {
            answer(
                &mut server_in,
                &server_out,
                STREAM_AUTH,
                json!({"device_id": "carol/default", "cursor_accepted": 0, "head_seq": 1}),
            )
            .await;
            answer(
                &mut server_in,
                &server_out,
                SYNC_DELTA,
                json!({"messages": [backfill_entry()], "next_since": 1, "has_more": false}),
            )
            .await;
            server_out
                .send(Frame::Raw(group_frame(GROUP_E2EE_NOTICE, "group-e2ee")))
                .unwrap();
            server_out
                .send(Frame::Raw(group_frame(GROUP_E2EE_INCOMING, "group-e2ee")))
                .unwrap();
            // P4's `group.incoming`: the same method name, a different profile. The sink must
            // refuse it and the transport must read it as an ordinary delivery.
            server_out
                .send(Frame::Raw(group_frame(GROUP_E2EE_INCOMING, TRANSPORT_PROTECTED)))
                .unwrap();
            drop(server_out);
        });

        let args = ListenArgs {
            device: "carol/default".to_string(),
            since: None,
            ack: false,
            once: false,
        };
        let ctx = SessionCtx {
            url: "ws://localhost:8765/anp-im/stream",
            args: &args,
            view: view.as_ref(),
            channel: &channel,
            receiver: Some(sink.as_ref()),
        };
        let (_tx, abort) = watch::channel(false);

        assert!(matches!(session(side, &ctx, abort).await, Step::Dropped));

        assert_eq!(
            sink.methods(),
            vec![
                GROUP_E2EE_NOTICE.to_string(),
                GROUP_E2EE_INCOMING.to_string(),
                GROUP_E2EE_INCOMING.to_string()
            ],
            "every frame is offered, and the sink is what decides"
        );
        let messages = view.messages();
        assert_eq!(messages.len(), 2, "the two group-e2ee frames are not deliveries");
        assert_eq!(messages[1].seq, 2, "the P4 frame took the first number after the head");
    }

    /// A sink that claims `group.incoming` at the e2ee profile and refuses everything else,
    /// with the same discrimination the real one makes. Only the method list is asserted on.
    #[derive(Default)]
    struct RecordingSink {
        methods: Mutex<Vec<String>>,
    }

    impl RecordingSink {
        fn methods(&self) -> Vec<String> {
            self.methods.lock().unwrap().clone()
        }
    }

    impl GroupSink for RecordingSink {
        fn handle<'a>(
            &'a self,
            method: &'a str,
            frame: &'a Value,
        ) -> Pin<Box<dyn Future<Output = Result<Option<GroupEvent>>> + Send + 'a>> {
            self.methods.lock().unwrap().push(method.to_string());
            let profile = notification_of(frame)
                .and_then(|(_, params)| params.get("meta").cloned())
                .and_then(|meta| meta.get("security_profile").cloned());
            let claimed = method == GROUP_E2EE_NOTICE
                || (method == GROUP_E2EE_INCOMING
                    && profile.as_ref().and_then(Value::as_str) == Some("group-e2ee"));
            Box::pin(async move {
                Ok(claimed.then(|| GroupEvent::Message {
                    group_did: "did:wba:localhost%3A8765:group:g1".to_string(),
                    from: "did:wba:localhost%3A8765:user:alice".to_string(),
                    message_id: "m-1".to_string(),
                    group_event_seq: None,
                    group_state_version: "3".to_string(),
                    accepted_at: None,
                    content_type: "text/plain".to_string(),
                    text: Some("group hello".to_string()),
                    payload: None,
                }))
            })
        }
    }

    fn group_frame(method: &str, security_profile: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": {
                "meta": {
                    "sender_did": "did:wba:localhost%3A8765:user:alice",
                    "content_type": "application/anp-group-cipher+json",
                    "security_profile": security_profile,
                    "created_at": "2026-10-02T00:02:00Z"
                },
                "body": { "group_did": "did:wba:localhost%3A8765:group:g1" }
            }
        })
    }

    /// `--ack` (§6): two calls per live frame — the read state and the delivery cursor. The
    /// backfill is not acked, so the first ack carries `head + 1`.
    #[tokio::test]
    async fn acking_sends_mark_read_and_the_cursor_for_each_live_frame() {
        let channel = test_channel();
        let (side, mut server_in, server_out) = duplex();
        let view = Arc::new(RecordingView::default());

        server_out.send(Frame::Raw(hello())).unwrap();
        let server = tokio::spawn(async move {
            answer(
                &mut server_in,
                &server_out,
                STREAM_AUTH,
                json!({"device_id": "carol/default", "cursor_accepted": 0, "head_seq": 1}),
            )
            .await;
            answer(
                &mut server_in,
                &server_out,
                SYNC_DELTA,
                json!({"messages": [backfill_entry()], "next_since": 1, "has_more": false}),
            )
            .await;
            server_out.send(Frame::Raw(live_notification("direct.incoming"))).unwrap();

            let ack = answer(&mut server_in, &server_out, STREAM_ACK, json!({"cursor": 2})).await;
            assert_eq!(ack["params"]["body"]["seq"], 2);
            assert_eq!(ack["params"]["meta"]["profile"], STREAM_PROFILE);
            drop(server_out);
        });

        let args = ListenArgs {
            device: "carol/default".to_string(),
            since: None,
            ack: true,
            once: false,
        };
        let ctx = SessionCtx {
            url: "ws://localhost:8765/anp-im/stream",
            args: &args,
            view: view.as_ref(),
            channel: &channel,
            receiver: None,
        };
        let (_tx, abort) = watch::channel(false);

        assert!(matches!(session(side, &ctx, abort).await, Step::Dropped));
        server.await.unwrap();
        assert_eq!(view.messages().len(), 2);
    }

    /// §4.2: the upgrade is plaintext, so `stream.hello` is the first man-in-the-middle check.
    /// A server that introduces itself as someone else ends the run — it is not a drop, because
    /// reconnecting would ask the same impostor the same question.
    #[tokio::test]
    async fn a_hello_from_the_wrong_did_is_fatal() {
        let channel = test_channel();
        let (side, _server_in, server_out) = duplex();
        let view = Arc::new(RecordingView::default());

        let mut impostor = hello();
        impostor["params"]["server_did"] = json!("did:wba:elsewhere:service:anp-message");
        server_out.send(Frame::Raw(impostor)).unwrap();

        let args = ListenArgs {
            device: "carol/default".to_string(),
            since: None,
            ack: false,
            once: false,
        };
        let ctx = SessionCtx {
            url: "ws://localhost:8765/anp-im/stream",
            args: &args,
            view: view.as_ref(),
            channel: &channel,
            receiver: None,
        };
        let (_tx, abort) = watch::channel(false);

        assert!(matches!(session(side, &ctx, abort).await, Step::Fatal(_)));
    }

    /// §7.2: a peer that does not implement the stream has **answered**. Reconnecting would get
    /// the same answer, so the run ends with a code a script can branch on.
    #[tokio::test]
    async fn an_unsupported_handshake_is_fatal_not_a_reconnect() {
        let channel = test_channel();
        let (side, mut server_in, server_out) = duplex();
        let view = Arc::new(RecordingView::default());

        server_out.send(Frame::Raw(hello())).unwrap();
        tokio::spawn(async move {
            let request = server_in.recv().await.unwrap();
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            server_out
                .send(Frame::Raw(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": "no such method"}
                })))
                .unwrap();
        });

        let args = ListenArgs {
            device: "carol/default".to_string(),
            since: None,
            ack: false,
            once: false,
        };
        let ctx = SessionCtx {
            url: "ws://localhost:8765/anp-im/stream",
            args: &args,
            view: view.as_ref(),
            channel: &channel,
            receiver: None,
        };
        let (_tx, abort) = watch::channel(false);

        match session(side, &ctx, abort).await {
            // `unsupported_extension`, not `message_invalid`: the peer answered, and the
            // answer was "I do not have this". The stable code on the NDJSON line is how a
            // supervisor tells this from a peer that refused (realtime.md §7.1).
            Step::Fatal(error) => assert_eq!(error.code(), "unsupported_extension"),
            _ => panic!("expected a fatal refusal"),
        }
    }

    /// §5.2: a Notification that arrives while a Response is awaited is put back, not dropped.
    #[tokio::test]
    async fn a_notification_arriving_before_its_response_is_not_lost() {
        let (side, server_in, server_out) = duplex();
        let (_tx, abort) = watch::channel(false);
        let mut arrivals = Arrivals::new(side.inbound, abort);

        // The push lands first, the answer to the request second.
        server_out.send(Frame::Raw(live_notification("direct.incoming"))).unwrap();
        server_out
            .send(Frame::Raw(json!({"jsonrpc": "2.0", "id": "req-1", "result": {}})))
            .unwrap();

        let reply = read_response(&mut arrivals, "req-1").await.unwrap();
        assert_eq!(reply["id"], "req-1");
        match arrivals.next().await {
            Arrival::Frame(frame) => {
                assert_eq!(frame["method"], "direct.incoming");
            }
            Arrival::Closed => panic!("the put-back frame was lost"),
        }
        drop(server_in);
    }

    #[test]
    fn the_renderer_shows_a_group_message_under_the_group() {
        let message = ListenMessage {
            kind: "message",
            seq: 4,
            message_id: "m".to_string(),
            from: "did:wba:example.com:user:bob".to_string(),
            target_kind: "group",
            group_did: Some("did:wba:example.com:group:team".to_string()),
            content_type: "text/plain".to_string(),
            text: Some("attachment sent".to_string()),
            payload: None,
            accepted_at: None,
        };
        let rendered = render_message(&message);
        assert!(rendered.starts_with("● did:wba:example.com:group:team (group)"));
        assert!(rendered.contains("  did:wba:example.com:user:bob: attachment sent"));
    }

    #[test]
    fn an_unrendered_body_says_what_it_is() {
        let message = ListenMessage {
            kind: "message",
            seq: 5,
            message_id: "m".to_string(),
            from: "did:wba:example.com:user:bob".to_string(),
            target_kind: "agent",
            group_did: None,
            content_type: "application/octet-stream".to_string(),
            text: None,
            payload: None,
            accepted_at: None,
        };
        assert!(render_message(&message).contains("(application/octet-stream body, not rendered)"));
    }

    /// A decrypted group message is headed by the group and the sender is prefixed, exactly as
    /// an unencrypted one is — the difference is only who did the decrypting.
    #[test]
    fn the_renderer_shows_a_decrypted_group_message_under_the_group() {
        let event = GroupEvent::Message {
            group_did: "did:wba:example.com:group:team".to_string(),
            from: "did:wba:example.com:user:bob".to_string(),
            message_id: "m".to_string(),
            group_event_seq: Some("7".to_string()),
            group_state_version: "3".to_string(),
            accepted_at: None,
            content_type: "text/plain".to_string(),
            text: Some("secret".to_string()),
            payload: None,
        };
        let rendered = render_group(&event);
        assert!(rendered.starts_with("● did:wba:example.com:group:team (group, e2ee)"));
        assert!(rendered.contains("  did:wba:example.com:user:bob: secret"));
    }

    /// A notice is one line, and a removal says so: §12.3 makes it the last frame this device
    /// will ever get for that group, and a reader who sees only "commit 1→2" would not know.
    #[test]
    fn a_removal_notice_says_this_device_was_removed() {
        let event = GroupEvent::Notice {
            group_did: "did:wba:example.com:group:team".to_string(),
            notice_type: "commit-delivery".to_string(),
            from_epoch: "1".to_string(),
            epoch: "2".to_string(),
            self_removed: true,
        };
        let rendered = render_group(&event);
        assert!(rendered.contains("commit-delivery 1→2"));
        assert!(rendered.contains("this device was removed"));

        let kept = GroupEvent::Notice {
            group_did: "did:wba:example.com:group:team".to_string(),
            notice_type: "commit-delivery".to_string(),
            from_epoch: "1".to_string(),
            epoch: "2".to_string(),
            self_removed: false,
        };
        assert!(!render_group(&kept).contains("removed"));
    }

    #[test]
    fn a_delay_reads_the_way_a_person_waiting_reads_it() {
        assert_eq!(format_delay(500), "500ms");
        assert_eq!(format_delay(2000), "2s");
        assert_eq!(format_delay(4800), "4.8s");
    }

    #[test]
    fn an_unparseable_timestamp_is_passed_through_rather_than_invented() {
        assert_eq!(format_time("not a time"), "not a time");
    }

    /// The machine contract of §7.1: one JSON object per line, and the field names exactly as
    /// the design document spells them.
    #[test]
    fn the_ndjson_shape_matches_the_contract() {
        let connecting = ListenEvent::State(ListenState::Connecting {
            service: "wss://host/anp-im/stream".to_string(),
        });
        assert_eq!(
            serde_json::to_value(&connecting).unwrap(),
            json!({"state": "connecting", "service": "wss://host/anp-im/stream"})
        );

        let reconnecting = ListenEvent::State(ListenState::Reconnecting {
            attempt: 2,
            after_ms: 4000,
        });
        assert_eq!(
            serde_json::to_value(&reconnecting).unwrap(),
            json!({"state": "reconnecting", "attempt": 2, "after_ms": 4000})
        );

        let message = ListenEvent::Message(ListenMessage {
            kind: "message",
            seq: 43,
            message_id: "msg-1".to_string(),
            from: "did:wba:example.com:user:bob".to_string(),
            target_kind: "agent",
            group_did: None,
            content_type: "text/plain".to_string(),
            text: Some("hello".to_string()),
            payload: None,
            accepted_at: Some("2026-10-02T00:00:00Z".to_string()),
        });
        assert_eq!(
            serde_json::to_value(&message).unwrap(),
            json!({
                "type": "message",
                "seq": 43,
                "message_id": "msg-1",
                "from": "did:wba:example.com:user:bob",
                "target_kind": "agent",
                "content_type": "text/plain",
                "text": "hello",
                "accepted_at": "2026-10-02T00:00:00Z"
            })
        );
    }
}
