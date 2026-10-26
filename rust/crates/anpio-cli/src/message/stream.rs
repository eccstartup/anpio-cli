//! The WebSocket half of `msg listen`: the stream address, the frames, and the socket.
//!
//! The port of the transport section of `packages/cli/src/commands/listen.ts`. It is split
//! out from the state machine ([`super::listen`]) for the reason realtime.md §3 gives about
//! the server: **the frames are the control plane's envelopes, the transport is the only
//! thing that differs.** So nothing here knows what a message is — it moves JSON-RPC frames
//! and says when the socket ends.
//!
//! The socket is handed to the state machine as a pair of channels rather than as a socket,
//! which is what makes the machine testable without a server (realtime.md §5.2's note about
//! `--once` covers the backfill half; the live half needs a duplex the test owns).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_tungstenite::tungstenite::Message;

use crate::error::{AnpioError, Result};

/// realtime.md §9: the transport's own Profile. `stream.auth` / `stream.ack` are not
/// normative operations, so they name an extension Profile the way the read surface does —
/// but a *different* one, because `meta.profile` is "the single interpretation of this
/// request" (P1 §6.2.2) and the handshake is not a read.
pub const STREAM_PROFILE: &str = "x_anpiocli.stream.v1";

/// The two methods this connection sends that are the transport's own (realtime.md §4, §6).
/// They exist nowhere else: `stream.auth` has no mailbox to subscribe to over HTTP, and
/// `stream.ack` cannot name a device there (the cursor is per `(owner_did, device_id)`).
pub const STREAM_AUTH: &str = "stream.auth";
pub const STREAM_ACK: &str = "stream.ack";

/// What the server opens with (§4.2). A Notification, never sent by this client.
pub const STREAM_HELLO: &str = "stream.hello";

/// The backfill (message-service.md §9.3) — an extension method, over the same socket.
pub const SYNC_DELTA: &str = "sync.delta";

/// §3: the notifications that carry a delivered message. The other two a service pushes
/// (`group.state_changed` / `group.e2ee.notice`) are not queue entries, so they are neither
/// rendered nor counted towards the cursor (§5.5).
pub const INCOMING_METHODS: [&str; 2] = ["direct.incoming", "group.incoming"];

/// How many missed messages one `sync.delta` asks for.
pub const DELTA_PAGE: u64 = 100;

// ---- the address ---------------------------------------------------------------

/// realtime.md §3: the stream is the control plane's endpoint with its last path segment
/// replaced by `stream` — `https://host/anp-im/rpc` → `wss://host/anp-im/stream`.
///
/// Derived rather than configured: a second flag naming the same host is one more way to
/// point a signed connection at the wrong place. The assumption is stated on the command's
/// help page, since a service that mounts its stream elsewhere cannot be reached by this
/// command.
pub fn stream_url(endpoint: &str) -> Result<String> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| {
        AnpioError::MessageServiceNotFound(format!(
            "the service endpoint {endpoint:?} is not a URL"
        ))
    })?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        other => {
            return Err(AnpioError::MessageServiceNotFound(format!(
                "the service endpoint {endpoint:?} is {other}, not http(s), so no stream address \
                 can be derived from it"
            )))
        }
    };
    let host = url.host_str().ok_or_else(|| {
        AnpioError::MessageServiceNotFound(format!(
            "the service endpoint {endpoint:?} names no host"
        ))
    })?;

    // `.pop()` on the last segment is what turns `/anp-im/rpc` into `/anp-im`; an endpoint
    // that is a bare origin has no segment to drop, so `stream` lands at the root.
    let mut segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
    segments.pop();
    segments.push("stream");
    // `host_str` strips the port, so it has to come back from `port()` — `wss://host:9/...`
    // and `wss://host/...` are different addresses.
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Ok(format!("{scheme}://{authority}/{}", segments.join("/")))
}

// ---- the frames ----------------------------------------------------------------

/// What arrives from the socket. `Closed` fires once, for any reason, so the state machine
/// has exactly one place where a stream ends.
#[derive(Debug)]
pub enum Frame {
    Raw(Value),
    Closed(Option<String>),
}

/// One open stream, as the state machine sees it: frames in, envelopes out.
///
/// The two halves travel separately because they are consumed by different things — the
/// machine writes on its own schedule and reads one frame at a time — and because a socket
/// that is only half-alive is a state worth being able to represent.
pub struct StreamSide {
    pub outbound: UnboundedSender<Value>,
    pub inbound: UnboundedReceiver<Frame>,
}

/// What opening a connection means. A `Fn` rather than a trait so a test can hand in a
/// closure over a channel pair, and `Arc` so the dependency can be shared as the real one
/// is (`deps.connect` is used for every reconnect).
pub type ConnectFn = Arc<dyn Fn(String) -> ConnectFuture + Send + Sync>;
pub type ConnectFuture = Pin<Box<dyn Future<Output = Result<StreamSide>> + Send>>;

/// The real transport: one WebSocket, split into a writer task and a reader task.
///
/// Two tasks rather than one `select!` because the two directions have no reason to share a
/// poll: the writer waits on its own queue, the reader on the socket. Dropping the outbound
/// sender ends the writer, which closes the socket, which ends the reader — so a state
/// machine that stops reading also stops the connection.
pub async fn websocket_connect(url: &str) -> Result<StreamSide> {
    // Parsed here only to reject a malformed address before a socket is attempted; tungstenite
    // takes the textual form (its `Url` is a different type from reqwest's).
    let url = reqwest::Url::parse(url).map_err(|err| {
        AnpioError::MessageServiceNotFound(format!("the stream address is not a URL: {err}"))
    })?;
    let (socket, _response) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .map_err(|err| AnpioError::MessageSendFailed(format!("could not open the stream: {err}")))?;
    let (mut sink, mut source) = socket.split();

    let (outbound, mut queue) = unbounded_channel::<Value>();
    let (arrivals, inbound) = unbounded_channel::<Frame>();

    tokio::spawn(async move {
        while let Some(frame) = queue.recv().await {
            if sink.send(Message::Text(frame.to_string().into())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    tokio::spawn(async move {
        while let Some(message) = source.next().await {
            match message {
                Ok(Message::Text(text)) => match serde_json::from_str::<Value>(&text) {
                    Ok(value) => {
                        if arrivals.send(Frame::Raw(value)).is_err() {
                            break;
                        }
                    }
                    // A frame that is not JSON is not a frame (§3). Dropping it keeps one bad
                    // frame from ending a stream that is otherwise delivering.
                    Err(_) => continue,
                },
                Ok(Message::Binary(bytes)) => {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        if let Ok(value) = serde_json::from_str::<Value>(text) {
                            if arrivals.send(Frame::Raw(value)).is_err() {
                                break;
                            }
                        }
                    }
                }
                Ok(Message::Close(frame)) => {
                    let _ = arrivals.send(Frame::Closed(
                        frame.map(|frame| frame.reason.to_string()).filter(|r| !r.is_empty()),
                    ));
                    return;
                }
                Ok(_) => {}
                Err(err) => {
                    let _ = arrivals.send(Frame::Closed(Some(err.to_string())));
                    return;
                }
            }
        }
        let _ = arrivals.send(Frame::Closed(None));
    });

    Ok(StreamSide {
        outbound,
        inbound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_segment_becomes_stream() {
        assert_eq!(
            stream_url("https://anpio.example/anp-im/rpc").unwrap(),
            "wss://anpio.example/anp-im/stream"
        );
        assert_eq!(
            stream_url("http://127.0.0.1:8080/anp-im/rpc").unwrap(),
            "ws://127.0.0.1:8080/anp-im/stream"
        );
        assert_eq!(stream_url("https://host/stream").unwrap(), "wss://host/stream");
    }

    /// The port is part of the address: a service on `:8443` is not the one on `:443`.
    #[test]
    fn a_non_default_port_survives_the_derivation() {
        assert_eq!(
            stream_url("https://host:8443/a/b/rpc").unwrap(),
            "wss://host:8443/a/b/stream"
        );
    }

    #[test]
    fn a_path_without_a_last_segment_still_lands_on_stream() {
        assert_eq!(stream_url("https://host").unwrap(), "wss://host/stream");
        assert_eq!(stream_url("https://host/").unwrap(), "wss://host/stream");
    }

    #[test]
    fn only_http_and_https_have_a_stream_address() {
        assert!(stream_url("ftp://host/rpc").is_err());
        assert!(stream_url("not a url").is_err());
        assert!(stream_url("wss://host/rpc").is_err());
    }
}
