//! The message layer: what an ANP envelope looks like, and how it gets to the service.
//!
//! `envelope` knows the shape, `rpc` knows how it travels. The split is the same one
//! `packages/core` makes, and for the same reason: the service has no use for the travel
//! half, and a client has no use for the service's parsing half.
//!
//! Above those two sit the pieces a *client* needs and the service does not: `resolve` turns
//! a DID into a verified document, `discovery` takes that document's one ANPMessageService,
//! and `channel` signs a call and places it. `client` is the one HTTP client all of them use.

pub mod channel;
pub mod client;
pub mod discovery;
pub mod envelope;
pub mod listen;
pub mod resolve;
pub mod rpc;
pub mod stream;

pub use channel::{
    call, call_device, call_extension, call_group, discover, extension_rejection,
    group_e2ee_security_profile, is_error, now_rfc3339, open_channel, open_channel_for, payload_of,
    policy_for, rejection, relaxed_hosts, sign_request, uuid_v4, CallRequest, Channel, Endpoint,
    Payload, Sender, CORE_BINDING, DID_SUPERSEDED, DIRECT_PROFILE, DIRECT_SEND, EXTENSION_PROFILE,
    GET_CAPABILITIES, GET_KEY_PACKAGE, GROUP_CREATE, GROUP_E2EE_ADD, GROUP_E2EE_CREATE,
    GROUP_E2EE_PROFILE, GROUP_E2EE_REMOVE, GROUP_E2EE_SECURITY_PROFILE, GROUP_E2EE_SEND,
    GROUP_GET_INFO, GROUP_JOIN, GROUP_LEAVE, GROUP_PROFILE, GROUP_SEND, INBOX_GET, INBOX_MARK_READ,
    MESSAGE_GET_BATCH, METHOD_NOT_FOUND, PUBLISH_KEY_PACKAGE, TRANSPORT_PROTECTED,
    UNSUPPORTED_PROFILE,
};
pub use client::http_client;
pub use discovery::{
    discover_message_service, negotiate_profiles, parse_capabilities, AnpCapabilities,
    MessageServiceTarget, ANP_MESSAGE_SERVICE_TYPE,
};
pub use envelope::{
    build_message_notification, build_message_request, AnpAuth, AnpMeta, AnpNotification,
    AnpOriginProof, AnpParams, AnpRequest, AnpTarget, TargetKind, JSONRPC_VERSION,
    ORIGIN_PROOF_SCHEME,
};
pub use listen::{
    backoff_ms, decode_message, device_of, run_listen, view_for, ListenArgs, ListenDeps,
    ListenEvent, ListenMessage, ListenState, ListenView,
};
pub use resolve::{
    assert_allowed_host, did_host, did_to_url, document_in_crate_form, document_is_bound,
    document_url, is_loopback_host_name, resolve_did_document, ResolvePolicy,
};
pub use rpc::{post_message, post_notification, AnpResponse};
pub use stream::{
    stream_url, websocket_connect, ConnectFn, Frame, StreamSide, DELTA_PAGE, INCOMING_METHODS,
    STREAM_ACK, STREAM_AUTH, STREAM_HELLO, STREAM_PROFILE, SYNC_DELTA,
};
