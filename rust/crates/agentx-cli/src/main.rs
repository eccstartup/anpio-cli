//! `agentx-cli` — the command face.
//!
//! A shell over the `agentx` library ([TODO5.md](../../../../TODO5.md)). `docs/design/cli.md`
//! §1 draws the line this binary is built to respect: **no protocol logic in the command
//! face**. Anything with ongoing state — the identity store, the MLS store, the message
//! store — lives in the library; what is here parses arguments, calls in, and renders.

use clap::{Args, Parser, Subcommand};
use reqwest::Url;
use serde_json::{json, Map, Value};
use std::sync::Arc;

use agentx::group::{group_target, policy_of, service_target};
use agentx::group_receive::GroupReceiver;
use agentx::group_e2ee::{
    add_body, create_body, get_key_package_body, publish_body, remove_body, send_body,
};
use agentx::identity::{
    create_identity, current_agent_path, describe_status, document_is_superseded, fetch_host_service, list_identities,
    read_current_agent, register_identity, resolve_agent_id, resolve_agent_id_with_source, resolve_chain,
    select_current_agent, snake_case_name, ChainError, ChainResolution, CreateIdentityInput, Identity, IdentityLocation,
};
use agentx::message::{
    build_message_request, call, call_device, call_extension, call_group, device_of, did_host, did_to_url,
    discover, document_in_crate_form, group_e2ee_security_profile, http_client, now_rfc3339,
    open_channel, open_channel_for, parse_capabilities, payload_of, policy_for, post_message,
    resolve_did_document, rejection, run_listen, uuid_v4, view_for, websocket_connect, AnpMeta,
    AnpResponse, AnpTarget, CallRequest, Channel, ConnectFn, ListenArgs, ListenDeps, ResolvePolicy,
    Sender, TargetKind, CORE_BINDING, DIRECT_PROFILE, DIRECT_SEND, DID_SUPERSEDED,
    GET_CAPABILITIES, GET_KEY_PACKAGE, GROUP_CREATE, GROUP_E2EE_ADD, GROUP_E2EE_CREATE,
    GROUP_E2EE_PROFILE, GROUP_E2EE_REMOVE, GROUP_E2EE_SEND, GROUP_GET_INFO, GROUP_JOIN,
    GROUP_LEAVE, GROUP_PROFILE, GROUP_SEND, INBOX_GET, INBOX_MARK_READ, MESSAGE_GET_BATCH,
    PUBLISH_KEY_PACKAGE, TRANSPORT_PROTECTED,
};
use agentx::mls::{
    abort_commit, application_plaintext, device_signing_key, finalize_commit, generate_key_package,
    new_key_package_id, prepare_add, prepare_create, prepare_remove, send_message, AddInput,
    CreateInput, KEY_PACKAGE_VALID_DAYS, RemoveInput, SendInput,
};
use anp::group_e2ee::v2_models::V2GroupKeyPackage;
use anp::group_e2ee::GROUP_CIPHER_CONTENT_TYPE;

#[derive(Parser)]
#[command(
    name = "agentx-cli",
    version,
    about = "An ANP client: identity, messaging, and group E2EE.",
    long_about = "A client for the Agent Network Protocol. Separate from the TS service and \
                  from the TS `connectx` CLI: it keeps its own store root and its own \
                  identity (TODO5 §0.1)."
)]
struct Cli {
    /// Treat this host as local: permit a private address and plain `http`.
    ///
    /// A loopback spelling (`localhost`, `127.0.0.1`, `::1`) is already treated as local.
    /// This flag is for a host that is local *without* being spelled that way.
    #[arg(long = "allow-private-host", global = true, value_name = "HOST")]
    allow_private_host: Vec<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Ask an ANP message service what it can do (P1 §8.2).
    ///
    /// This is the only method that MUST work with no authentication — a caller with no
    /// trust relationship yet has to be able to ask "what do you support". So it needs no
    /// identity, which also makes it the cheapest way to check that an endpoint is alive
    /// and speaks the protocol.
    Discover {
        /// The service endpoint. A bare host gets the conventional RPC path appended.
        endpoint: String,
    },
    /// Identity: create it, look at it, publish it.
    Did {
        #[command(subcommand)]
        command: DidCommand,
    },
    /// Which local agent every later command acts as.
    ///
    /// The selection is one file at the store root (`<store root>/current-agent`), so it is
    /// machine-wide rather than per-process — including for another agent's commands. That
    /// is the point: naming the agent on every invocation was the alternative. `--agent`
    /// and `$AGENTXCLI_AGENT` stay ABOVE it, so a script that names an agent cannot be
    /// redirected by a selection left lying in the store.
    ///
    /// There is no `unset`: overwriting the selection with another `agent use` is how it
    /// moves, and deleting that one file is how it is dropped.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Messages: send one, and read the ones that arrived.
    Msg {
        #[command(subcommand)]
        command: MsgCommand,
    },
    /// Groups: make one, look at it, and join or leave (P4 `anp.group.base.v2`).
    ///
    /// A group is addressed by its `group_did`, which is a DID document like any other: the
    /// host that answers for it is found by resolving that DID (P2 §9.2), so there is no
    /// group-specific discovery to configure. The one exception is `create`, which asks a
    /// service to make a group and therefore names that service.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
}

#[derive(Subcommand)]
enum DidCommand {
    /// Mint an identity and publish its DID document to a DID host.
    ///
    /// A DID document is only worth anything where the service can reach it, so this
    /// registers with the host as well — and says so if the registration fails after the
    /// keys were already written.
    Create {
        /// The DID host, e.g. `http://localhost:8000` (TODO5 §8-J: a local
        /// `awiki-open-server`).
        #[arg(long)]
        host: String,
        /// The handle to register under on that host.
        #[arg(long)]
        handle: String,
        /// The local agent name — the DID path segment and the store directory.
        ///
        /// Unlike the other subcommands this one does NOT consult `$AGENTXCLI_AGENT` or
        /// the current agent: `create` names a NEW identity, and who happens to be
        /// selected must not decide where a second one is written. Left out, the handle
        /// is used.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Show the identity on file.
    Show {
        /// `--agent` > `$AGENTXCLI_AGENT` > the current agent > `default`.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        /// Print the whole thing, DID document included.
        #[arg(long)]
        json: bool,
    },
    /// Publish (or re-publish) an identity's DID document to its host.
    Register {
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Resolution: read what any DID publishes, and walk its update links.
    ///
    /// Exit codes are scoped to this subcommand (cli.md §7): `0` the DID is current, `2`
    /// it is superseded (a **conclusion**, not a failure), `3` the update chain does not
    /// verify, `1` anything else.
    Resolve {
        /// The DID to resolve. Not necessarily this store's own.
        did: String,
        /// Follow the update links to the DID that is current, and say how strongly each
        /// hop was proven. Only `did:wba` DIDs with an `e1_` fingerprint carry them.
        #[arg(long)]
        chain: bool,
        /// Print the resolution as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Reserved: recovery of a DID whose key is lost.
    ///
    /// `anp` has no recovery path — the update chain moves a key forward, it cannot bring
    /// one back — so this refuses rather than pretending. It exists so the gap is a
    /// definite answer instead of an "Unknown subcommand".
    Restore,
}

/// The store's CURRENT agent — the id a command acts as when neither `--agent` nor
/// `$AGENTXCLI_AGENT` names one.
#[derive(Subcommand)]
enum AgentCommand {
    /// Which agent is in force, and which step of the chain said so.
    ///
    /// The chain itself is `resolve_agent_id`; what this reports is WHICH step spoke,
    /// because that is the question the command exists to answer — "why is it acting as
    /// that one" is otherwise a guess about the shell.
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Make this agent the current one.
    ///
    /// An id with no identity is accepted on purpose — selecting an agent and then creating
    /// its key is the order a new agent is born in — but it is said out loud, because every
    /// later command would otherwise fail with "no identity" and no explanation.
    Use {
        /// The agent id to select.
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// The agents this machine can act as, with the current one marked.
    ///
    /// Reads the store; contacts nothing. Answers both "which exist" and "which one is in
    /// force".
    List {
        #[arg(long)]
        json: bool,
    },
}

/// The identity a command acts as. Its `--agent`/`--profile` also name the store directory
/// and the default device (`realtime.md` §5.4), so the two are always asked for together.
///
/// Both are optional: leaving one out falls through the resolution chain in
/// `identity::store` rather than pinning the literal `default`, which is what makes the
/// current agent (`agentx-cli agent use`) mean anything.
#[derive(Args)]
struct OwnIdentity {
    #[arg(long)]
    agent: Option<String>,
    #[arg(long)]
    profile: Option<String>,
}

impl OwnIdentity {
    /// The store location these two flags name, after the chain that fills in what was
    /// left out.
    fn location(&self) -> anyhow::Result<IdentityLocation> {
        IdentityLocation::resolve(self.agent.as_deref(), self.profile.as_deref())
    }
}

#[derive(Subcommand)]
enum MsgCommand {
    /// Send one direct message to a DID (P3 `direct.send`).
    Send {
        /// The recipient's DID. Its own document names the service it is delivered to.
        #[arg(long, value_name = "DID")]
        to: String,
        /// A plain-text body. Sent as `text` under `text/plain` unless --content-type says
        /// otherwise.
        #[arg(long)]
        text: Option<String>,
        /// A JSON-object body. Sent as `payload` under `application/json` unless
        /// --content-type says otherwise.
        #[arg(long)]
        body: Option<String>,
        /// Override the content type. The two fixed types each pin which body shape is
        /// legal (P3 §6.2.4/§6.2.5), and the illegal pairings are refused.
        #[arg(long = "content-type", value_name = "MEDIA_TYPE")]
        content_type: Option<String>,
        /// Reuse an operation id. A retry MUST keep it unchanged (P3 §5.5), and
        /// `message_id` follows it (P1 §6.2.6).
        #[arg(long = "operation-id", value_name = "UUID")]
        operation_id: Option<String>,
        /// Print the peer's response as JSON instead of the summary lines.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Ask a DID's message service what it supports (P1 §8.2).
    ///
    /// Anonymous: §8.2.1 lets `sender_did` be omitted, and requiring an identity would make
    /// the one question "can this DID be talked to at all" depend on already having one on
    /// that DID's terms.
    Caps {
        #[arg(value_name = "DID")]
        did: String,
        #[arg(long)]
        json: bool,
    },
    /// Show this identity's inbox (extension `inbox.get`).
    Inbox {
        /// How many rows to ask for (default 20).
        #[arg(long, value_name = "N")]
        limit: Option<String>,
        /// Include the messages that have already been read.
        #[arg(long = "include-read")]
        include_read: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Show one message by id (extension `message.get_batch`).
    Show {
        #[arg(value_name = "MESSAGE_ID")]
        message_id: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Mark messages as read (extension `inbox.mark_read`).
    Read {
        #[arg(value_name = "MESSAGE_ID")]
        message_ids: Vec<String>,
        /// Mark everything currently unread. The ids are the ones *listed*, so a message
        /// arriving between the listing and the write stays unread.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Stay connected and print messages as they arrive (realtime.md).
    ///
    /// This is the only long-running command. The stream address is derived from the
    /// identity's own message service by replacing its last path segment with `stream`
    /// (`/anp-im/rpc` → `/anp-im/stream`), so a service that mounts its stream elsewhere
    /// cannot be reached by this command.
    ///
    /// Nothing is stored locally: the delivery cursor lives on the service, per
    /// `(identity, device)`, and a reconnect resumes from it. Ctrl-C exits 0.
    Listen {
        /// Which device this stream is. Defaults to the local `agent/profile`, so the same
        /// machine under a different profile is a different device with its own cursor.
        #[arg(long, value_name = "DEVICE_ID")]
        device: Option<String>,
        /// Start the backfill from this sequence instead of the stored cursor. A debugging
        /// override for this run only; it is not written back.
        #[arg(long, value_name = "SEQ")]
        since: Option<u64>,
        /// Confirm each message as it is printed: `inbox.mark_read` (read state) and
        /// `stream.ack` (this device's cursor). Off by default — an unconfirmed message is
        /// replayed on reconnect, an over-confirmed one is gone.
        #[arg(long)]
        ack: bool,
        /// Backfill, print, and exit 0 — the read-only one-shot for scripts.
        #[arg(long)]
        once: bool,
        /// Force NDJSON even on a terminal. Without it, a pipe is a machine too.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
}

#[derive(Subcommand)]
enum GroupCommand {
    /// Make a group on this identity's own message service (P4 `group.create`).
    ///
    /// The service is asked to create the group, so the caller must be reachable on it:
    /// the group's creator is whoever signed the request (P4 §7.3), not a field.
    Create {
        /// The group's display name (`group_profile.display_name`, P4 §7.4). Left out
        /// entirely when absent — a group with no name is better described by an absent
        /// object than by an empty one.
        #[arg(long)]
        name: Option<String>,
        /// The `group_policy` as JSON, shallow-merged over the recommended structure in
        /// P4 §7.1 and checked against its closed sets before anything is sent.
        #[arg(long)]
        policy: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Show a group's state and policy (P4 `group.get_info`).
    Info {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Show a group's member list (P4 `group.get_info`, `include_member_list: true`).
    ///
    /// Not a separate method on the wire: P4 §7.5 makes the list an option on `get_info`, so
    /// this is a spelling of the same call with a longer, more expensive answer.
    Members {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Join a group (P4 `group.join`).
    ///
    /// The joiner is `meta.sender_did`, so there is no `--member`: the request is signed by
    /// the identity that joins, and an identity that names someone else would be claiming an
    /// action it cannot authorise.
    Join {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Leave a group (P4 `group.leave`). Same reasoning as `join` about the subject.
    ///
    /// The last owner leaving is a decision the group has to answer, not this CLI: whether
    /// that dissolves the group, hands it on, or is refused is §7.7's business.
    Leave {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Send one message to a group (P4 `group.send`).
    Send {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// A plain-text body. Sent as `text` under `text/plain` unless --content-type says
        /// otherwise.
        #[arg(long)]
        text: Option<String>,
        /// A JSON-object body. Sent as `payload` under `application/json` unless
        /// --content-type says otherwise.
        #[arg(long)]
        body: Option<String>,
        #[arg(long = "content-type", value_name = "MEDIA_TYPE")]
        content_type: Option<String>,
        /// Reuse an operation id. A retry MUST keep it unchanged (P4 §5.4), and
        /// `message_id` follows it (P1 §6.2.6).
        #[arg(long = "operation-id", value_name = "UUID")]
        operation_id: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// End-to-end encryption for groups (P6 `anp.group.e2ee.v2`).
    ///
    /// A subfamily rather than six more `group` verbs: P6 is a different Profile with its own
    /// security modes (§4.3) and its own state — an MLS store this device owns, which no other
    /// command touches. It also cannot be discovered from a group's document alone: the
    /// Profile is deliberately not advertised yet (client-mls.md §6), so a caller has to know
    /// which groups run it.
    E2ee {
        #[command(subcommand)]
        command: GroupE2eeCommand,
    },
}

#[derive(Subcommand)]
enum GroupE2eeCommand {
    /// Publish this device's KeyPackage so others can add it (P6 `group.e2ee.publish_key_package`).
    ///
    /// This is the one thing every device must do before it can be added to any encrypted
    /// group: §8.2 has the group's owner fetch a *published* package for the member it is
    /// adding (§9.3.3), so a device that never ran this cannot be invited. It is also the only
    /// P6 call with no group involved — the service being asked is this identity's own.
    Publish {
        /// Name this package instead of letting the client mint an id. The id is filed both
        /// here and in the service's cabinet, and the local store refuses a second package
        /// under one it already holds — so this is for naming, not for retrying a publish.
        #[arg(long = "key-package-id", value_name = "ID")]
        key_package_id: Option<String>,
        /// How long the published package claims to be valid. §7.3 makes `expires_at` a
        /// SHOULD, so this is a hint rather than a gate.
        #[arg(
            long = "valid-days",
            value_name = "DAYS",
            default_value_t = agentx::mls::KEY_PACKAGE_VALID_DAYS
        )]
        valid_days: i64,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Fetch a peer device's published KeyPackage (P6 `group.e2ee.get_key_package`).
    ///
    /// The read side of [`GroupE2eeCommand::Publish`]: §9.3.3 has whoever adds a member run
    /// this to get the package the commit will cover. §8.2.4 lets the service **claim** the
    /// package as it hands it out, so asking twice does not print the same package twice —
    /// the second answer is the next one, or a refusal when the cabinet is empty.
    GetKeyPackage {
        /// The DID whose device to ask about.
        #[arg(long = "target-did", value_name = "DID")]
        target_did: String,
        /// That DID's device id — the other half of what names one KeyPackage.
        #[arg(long = "target-device", value_name = "ID")]
        target_device: String,
        /// A suite the caller would rather have. §8.2.2 puts this in a MAY and gives it no
        /// meaning; the service checks only that it is a non-empty string.
        #[arg(long = "suite", value_name = "SUITE")]
        suite: Option<String>,
        /// Refuse an expired package rather than falling back to one (P6 §8.2.4 L763).
        #[arg(long = "require-fresh")]
        require_fresh: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Initialise a group's MLS state, with this device as its creator (P6 `group.e2ee.create`).
    ///
    /// The group itself is a P4 object — §9.2.1's premise is that `group.create` already made
    /// it — so this is the second step, not another way to make one. It is also the one P6
    /// control method addressed to the **service** rather than the group (§4.4.1 L292–293),
    /// even though the group now exists; `docs/design/e2ee-group.md` §3 says to copy that
    /// rather than "fix" it.
    ///
    /// The device must be the group's owner: the service checks that against the P4 state
    /// before anything is initialised, so a refusal here is about membership, not encryption.
    Create {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// Name this run's creator KeyPackage instead of letting the client mint an id. As
        /// with `publish`, this is for naming; the local store refuses a second package under
        /// an id it already holds.
        #[arg(long = "key-package-id", value_name = "ID")]
        key_package_id: Option<String>,
        /// Reuse an operation id. §13.6's fresh-request rule makes a retry reuse it, and the
        /// local pending commit is filed under the same value.
        #[arg(long = "operation-id", value_name = "UUID")]
        operation_id: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Add one device of an existing member to the encrypted group (P6 `group.e2ee.add`).
    ///
    /// §9.3.3's two preconditions are P4's, not this client's: the member must already be
    /// `active` in the group, and the device must be an eligible one — so a caller runs
    /// `group join` (or `group add`) first, and the member runs `group e2ee publish`. A second
    /// device of the same DID is another Add, not a second member (§9.3.1).
    ///
    /// Where the two things this needs come from is the part worth stating: the member's
    /// KeyPackage comes from **the member's own service** (§8.2's cabinet, which §8.2.3 lets
    /// be cross-domain), while the `add` itself is group-addressed like `remove`/`send`
    /// (§4.4.2) and so goes to the group's service.
    Add {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// The member's DID — half of the exact pair §9.3.3 keys the leaf on.
        #[arg(long = "member-did", value_name = "DID")]
        member_did: String,
        /// That DID's device to add. §9.3.3 makes the pair exact, so a second device is a
        /// separate Add rather than a wider one.
        #[arg(long = "member-device", value_name = "ID")]
        member_device: String,
        /// Reuse an operation id, as on `create`.
        #[arg(long = "operation-id", value_name = "UUID")]
        operation_id: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Remove one device's leaf from the encrypted group (P6 `group.e2ee.remove`).
    ///
    /// §9.4.3 keys the removal on the exact `(member_did, member_device_id)` leaf, so the
    /// target is named rather than invited — there is no package to read it off, which is why
    /// this names both halves where `add` names only the DID. The removed device need not be
    /// eligible (losing eligibility is one reason to remove it), so the target's own service
    /// is never contacted; only its DID document is read, and only to prove the leaf's
    /// identity.
    ///
    /// Like `add`, this is group-addressed (§4.4.2) and so goes to the group's service. This
    /// device cannot remove itself: the crate refuses that leaf (`controller_required`) —
    /// that is `group leave`.
    Remove {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// The DID whose device to remove.
        #[arg(long = "member-did", value_name = "DID")]
        member_did: String,
        /// That DID's device to remove — the other half of the exact pair §9.4.3 keys on.
        #[arg(long = "member-device", value_name = "ID")]
        member_device: String,
        /// Reuse an operation id, as on `create` and `add`.
        #[arg(long = "operation-id", value_name = "UUID")]
        operation_id: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Encrypt one message to the group and have the service order it (P6 `group.e2ee.send`).
    ///
    /// The one P6 control method that is **not** a three-phase commit: it makes one MLS
    /// `PrivateMessage` against the current epoch, so there is no local pending state to
    /// finalize or roll back — the service's answer says only "taken and ordered" (§9.5). The
    /// ciphertext is opaque to the service; only the members' runtimes can read it.
    ///
    /// The body is what this device encrypted, so the message is one the sender can also be
    /// expected to read back through its own `group.incoming` — `msg listen` is where that
    /// arrives.
    Send {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// The message as plain text. Sent as §7.4's `text`, content type `text/plain`.
        #[arg(long, value_name = "TEXT", conflicts_with = "body")]
        text: Option<String>,
        /// The message as a JSON object. Sent as §7.4's `payload`, content type
        /// `application/json`.
        #[arg(long, value_name = "JSON", conflicts_with = "text")]
        body: Option<String>,
        /// The content type of what is encrypted (P6 §7.4 `application_content_type`). Free,
        /// unlike the outer `meta.content_type`, which §9.5.3 pins to one value.
        #[arg(long = "content-type", value_name = "TYPE")]
        content_type: Option<String>,
        /// Reuse an operation id. As on `group send`, one flag names both `operation_id` and
        /// `message_id` (P1 §6.2.6), so a retry reuses the whole triple.
        #[arg(long = "operation-id", value_name = "UUID")]
        operation_id: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
}

/// How many unread ids `msg read --all` asks for at a time.
const ALL_PAGE: u64 = 100;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let allow_private = cli.allow_private_host;
    match cli.command {
        Command::Discover { endpoint } => cmd_discover(&endpoint, &allow_private).await,
        Command::Did { command } => match command {
            DidCommand::Create {
                host,
                handle,
                agent,
                profile,
            } => cmd_did_create(&host, &handle, agent, profile.as_deref()).await,
            DidCommand::Show {
                agent,
                profile,
                json,
            } => cmd_did_show(agent.as_deref(), profile.as_deref(), json),
            DidCommand::Register { agent, profile } => cmd_did_register(agent.as_deref(), profile.as_deref()).await,
            DidCommand::Resolve { did, chain, json } => cmd_did_resolve(&did, chain, json, &allow_private).await,
            DidCommand::Restore => cmd_did_restore(),
        },
        Command::Agent { command } => match command {
            AgentCommand::Show { json } => cmd_agent_show(json),
            AgentCommand::Use { id, json } => cmd_agent_use(&id, json),
            AgentCommand::List { json } => cmd_agent_list(json),
        },
        Command::Msg { command } => match command {
            MsgCommand::Send {
                to,
                text,
                body,
                content_type,
                operation_id,
                json,
                own,
            } => {
                cmd_msg_send(
                    &own,
                    &to,
                    SendPayload {
                        text,
                        body,
                        content_type,
                        operation_id,
                        json,
                    },
                    &allow_private,
                )
                .await
            }
            MsgCommand::Caps { did, json } => cmd_msg_caps(&did, json, &allow_private).await,
            MsgCommand::Inbox {
                limit,
                include_read,
                json,
                own,
            } => cmd_msg_inbox(&own, limit, include_read, json, &allow_private).await,
            MsgCommand::Show {
                message_id,
                json,
                own,
            } => cmd_msg_show(&own, &message_id, json, &allow_private).await,
            MsgCommand::Read {
                message_ids,
                all,
                json,
                own,
            } => cmd_msg_read(&own, message_ids, all, json, &allow_private).await,
            MsgCommand::Listen {
                device,
                since,
                ack,
                once,
                json,
                own,
            } => {
                cmd_msg_listen(
                    &own,
                    ListenOptions {
                        device,
                        since,
                        ack,
                        once,
                        json,
                    },
                    &allow_private,
                )
                .await
            }
        },
        Command::Group { command } => match command {
            GroupCommand::Create {
                name,
                policy,
                json,
                own,
            } => cmd_group_create(&own, name, policy, json, &allow_private).await,
            GroupCommand::Info {
                group_did,
                json,
                own,
            } => cmd_group_info(&own, &group_did, false, json, &allow_private).await,
            GroupCommand::Members {
                group_did,
                json,
                own,
            } => cmd_group_info(&own, &group_did, true, json, &allow_private).await,
            GroupCommand::Join {
                group_did,
                json,
                own,
            } => cmd_group_membership(&own, &group_did, GROUP_JOIN, json, &allow_private).await,
            GroupCommand::Leave {
                group_did,
                json,
                own,
            } => cmd_group_membership(&own, &group_did, GROUP_LEAVE, json, &allow_private).await,
            GroupCommand::Send {
                group_did,
                text,
                body,
                content_type,
                operation_id,
                json,
                own,
            } => {
                cmd_group_send(
                    &own,
                    &group_did,
                    SendPayload {
                        text,
                        body,
                        content_type,
                        operation_id,
                        json,
                    },
                    &allow_private,
                )
                .await
            }
            GroupCommand::E2ee { command } => match command {
                GroupE2eeCommand::Publish {
                    key_package_id,
                    valid_days,
                    json,
                    own,
                } => {
                    cmd_group_e2ee_publish(
                        &own,
                        key_package_id,
                        valid_days,
                        json,
                        &allow_private,
                    )
                    .await
                }
                GroupE2eeCommand::GetKeyPackage {
                    target_did,
                    target_device,
                    suite,
                    require_fresh,
                    json,
                    own,
                } => {
                    cmd_group_e2ee_get_key_package(
                        &own,
                        target_did,
                        target_device,
                        suite,
                        require_fresh,
                        json,
                        &allow_private,
                    )
                    .await
                }
                GroupE2eeCommand::Create {
                    group_did,
                    key_package_id,
                    operation_id,
                    json,
                    own,
                } => {
                    cmd_group_e2ee_create(
                        &own,
                        &group_did,
                        key_package_id,
                        operation_id,
                        json,
                        &allow_private,
                    )
                    .await
                }
                GroupE2eeCommand::Add {
                    group_did,
                    member_did,
                    member_device,
                    operation_id,
                    json,
                    own,
                } => {
                    cmd_group_e2ee_add(
                        &own,
                        &group_did,
                        &member_did,
                        &member_device,
                        operation_id,
                        json,
                        &allow_private,
                    )
                    .await
                }
                GroupE2eeCommand::Remove {
                    group_did,
                    member_did,
                    member_device,
                    operation_id,
                    json,
                    own,
                } => {
                    cmd_group_e2ee_remove(
                        &own,
                        &group_did,
                        &member_did,
                        &member_device,
                        operation_id,
                        json,
                        &allow_private,
                    )
                    .await
                }
                GroupE2eeCommand::Send {
                    group_did,
                    text,
                    body,
                    content_type,
                    operation_id,
                    json,
                    own,
                } => {
                    cmd_group_e2ee_send(
                        &own,
                        &group_did,
                        SendPayload {
                            text,
                            body,
                            content_type,
                            operation_id,
                            json,
                        },
                        &allow_private,
                    )
                    .await
                }
            },
        },
    }
}

/// `POST /anp-im/rpc` is the conventional control-plane path
/// (`packages/service/src/http/server.ts`). A bare host is the common case to type, so fill
/// it in rather than making the caller remember it.
fn with_rpc_path(endpoint: &str) -> String {
    let Ok(mut url) = Url::parse(endpoint) else {
        return endpoint.to_string();
    };
    let bare = url.path().is_empty() || url.path() == "/";
    if bare {
        url.set_path("/anp-im/rpc");
    }
    url.to_string()
}

/// The hop policy for a **typed** endpoint. Here the host really is the thing being asked
/// about, and it came from the command line rather than from a peer, so there is no DID to
/// derive an allowlist from — the typed host is the allowlist. Loopback is relaxed without a
/// flag; anything else local needs `--allow-private-host` (`docs/design/cli.md` §3.2).
fn typed_endpoint_policy(endpoint: &str, allow_private: &[String]) -> ResolvePolicy {
    match Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
    {
        Some(host) => policy_for(&[host], allow_private),
        None => ResolvePolicy::default(),
    }
}

async fn cmd_discover(endpoint: &str, allow_private: &[String]) -> anyhow::Result<()> {
    let endpoint = with_rpc_path(endpoint);

    let meta = AnpMeta {
        // §8.2.1: `anp_version` is deprecated and the receiver MUST NOT use it to pick a
        // Profile, so it is left out rather than sent for company.
        profile: CORE_BINDING.to_string(),
        security_profile: TRANSPORT_PROTECTED.to_string(),
        // §8.2.1 permits omitting `sender_did`, and this command has no identity.
        ..Default::default()
    };
    let request = build_message_request(
        &format!("agentx-discover-{}", std::process::id()),
        GET_CAPABILITIES,
        meta,
        None,
        None,
    )?;

    let client = http_client()?;
    let policy = typed_endpoint_policy(&endpoint, allow_private);
    let response = post_message(&client, &endpoint, &request, &policy, &endpoint).await?;

    match response {
        AnpResponse::Success { result, .. } => {
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        // A refusal is a well-formed answer, not a transport failure — report it and fail
        // the command, so a script can branch on the exit code.
        AnpResponse::Error { error, .. } => Err(rejection(
            GET_CAPABILITIES,
            &endpoint,
            error.code,
            error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
            &error.message,
        )
        .into()),
    }
}

async fn cmd_did_create(
    host: &str,
    handle: &str,
    agent: Option<String>,
    profile: Option<&str>,
) -> anyhow::Result<()> {
    // The agent is NOT run through `resolve_agent_id`: `create` names a new identity, and
    // the current selection must not decide where a second one lands. No `--agent` means
    // the handle, which is what the DID path segment will be. The profile still resolves
    // through `$AGENTXCLI_PROFILE`, because a profile is not part of the address.
    let agent = agent.unwrap_or_else(|| handle.to_string());
    let location = IdentityLocation::resolve(Some(&agent), profile)?;
    let base = Url::parse(host).map_err(|err| anyhow::anyhow!("--host must be a URL: {err}"))?;
    let client = http_client()?;

    let service = fetch_host_service(&client, &base).await?;
    let identity = create_identity(CreateIdentityInput {
        authority: service.authority,
        agent: location.agent.clone(),
        profile: location.profile.clone(),
        handle: handle.to_string(),
        did_host_url: host.to_string(),
        service_endpoint: service.service_endpoint,
        service_did: service.service_did,
    })?;
    identity.save(&location)?;
    println!("did:     {}", identity.did);
    println!("device:  {}", identity.device_id);
    println!("stored:  {}", location.identity_path().display());

    match register_identity(&client, &base, &identity).await {
        Ok(_) => println!("registered with {host} as {handle}"),
        Err(err) => {
            // The keys are already on disk; a failed publish is retryable and must not
            // look like a failed create.
            eprintln!("the identity was saved, but publishing it failed: {err:#}");
            eprintln!("retry with: agentx-cli did register --agent {}", location.agent);
            return Err(err);
        }
    }
    println!("next:    agentx-cli did show --agent {}", location.agent);
    Ok(())
}

fn cmd_did_show(agent: Option<&str>, profile: Option<&str>, json: bool) -> anyhow::Result<()> {
    let location = IdentityLocation::resolve(agent, profile)?;
    let identity = Identity::load(&location)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&identity)?);
    } else {
        println!("did:        {}", identity.did);
        println!("device:     {}", identity.device_id);
        println!("handle:     {}", identity.handle);
        println!("host:       {}", identity.did_host);
        println!("created:    {}", identity.created_at);
        println!(
            "keys:       {}",
            identity.keys.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        println!("document:   {} characters signed", serde_json::to_string(&identity.did_document)?.len());
        if !Identity::permissions_are_private(&location) {
            eprintln!(
                "warning: {} is readable by others; it holds private keys (chmod 600)",
                location.identity_path().display()
            );
        }
    }
    Ok(())
}

async fn cmd_did_register(agent: Option<&str>, profile: Option<&str>) -> anyhow::Result<()> {
    let location = IdentityLocation::resolve(agent, profile)?;
    let identity = Identity::load(&location)?;
    let base = Url::parse(&identity.did_host)
        .map_err(|err| anyhow::anyhow!("the stored host is not a URL: {err}"))?;
    let client = http_client()?;
    register_identity(&client, &base, &identity).await?;
    println!("registered {} with {}", identity.did, identity.did_host);
    Ok(())
}

/// Exit with a code, after flushing what was printed.
///
/// `std::process::exit` runs no destructors, and a **piped** stdout is block-buffered (a
/// terminal's is line-buffered) — so without the flush a `did resolve --json | jq …` would
/// lose its output on exactly the paths that use this. Only `did resolve`'s two
/// "conclusion" codes need it; every other command keeps the ordinary 0/1 (cli.md §7).
fn exit_with(code: i32) -> ! {
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

/// `did resolve <did> [--chain] [--json]`.
///
/// The DID need not be this store's own: this is the only way to look at what anyone
/// publishes. Exit codes ride on the ANSWER, not on success (`docs/design/cli.md` §7):
/// `2` means the DID is superseded — a conclusion — and `3` that the chain does not verify.
async fn cmd_did_resolve(
    did: &str,
    chain: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let policy = policy_for(&[did_host(did)?], allow_private);
    let client = http_client()?;

    if chain {
        match resolve_chain(&client, did, &policy).await {
            Ok(resolution) => {
                print_chain(&resolution, json)?;
                if resolution.is_superseded() {
                    exit_with(2)
                }
                Ok(())
            }
            // A verdict on the chain, which is what exit 3 is for — distinct from
            // "could not fetch", which is an ordinary failure.
            Err(ChainError::Broken(err)) => {
                eprintln!("agentx-cli: did_chain_broken: {}: {}", snake_case_name(&err.kind), err.message);
                exit_with(3)
            }
            Err(ChainError::Unavailable(err)) => Err(err),
        }
    } else {
        let document = resolve_did_document(&client, did, &policy).await?;
        // Resolving DOES serve a superseded document on purpose — it is evidence, and the
        // document-level call has no successor to offer. Saying so is this command's job.
        let superseded = document_is_superseded(&document);
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "did": did,
                    "docUrl": did_to_url(did)?.as_str(),
                    "superseded": superseded,
                    "document": document,
                }))?
            );
        } else {
            println!("did:      {did}");
            println!("superseded: {}", if superseded { "yes" } else { "no" });
            if superseded {
                println!(
                    "          the document is not current — pass --chain to follow the link to \
                     the DID that is"
                );
            }
            println!();
            println!("{}", serde_json::to_string_pretty(&document)?);
        }
        if superseded {
            exit_with(2)
        }
        Ok(())
    }
}

fn print_chain(resolution: &ChainResolution, json: bool) -> anyhow::Result<()> {
    let result = &resolution.result;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "result": result,
                "docUrl": resolution.doc_url,
                "documents": resolution.documents,
            }))?
        );
        return Ok(());
    }
    println!("did:        {}", result.requested_did);
    println!("currentDid: {}", result.current_did);
    println!("status:     {}", describe_status(result));
    // No hops means there was no chain to weigh, and the crate says exactly that with
    // `None`. Naming the crate's own absence beats inventing a word for it: what *was*
    // verified is the document the DID resolves to, which is what `status` reports.
    println!(
        "assurance:  {}",
        result
            .assurance
            .map(|assurance| snake_case_name(&assurance))
            .unwrap_or_else(|| "none (no hops)".to_string())
    );
    println!("docUrl:     {}", resolution.doc_url);
    println!("hops:       {}", result.hops.len());
    for (index, hop) in result.hops.iter().enumerate() {
        println!("  [{}] {} → {}", index + 1, hop.predecessor_did, hop.successor_did);
        println!("      assurance={}", snake_case_name(&hop.assurance));
    }
    Ok(())
}

/// `did restore` — reserved, and it says so.
///
/// The SDK has no recovery path: the update chain moves a key forward and cannot bring one
/// back, so a DID whose key is gone has no protocol-level restoration. Exiting non-zero
/// with this message is the honest answer, and having the subcommand at all means the gap
/// is a definite one rather than an "Unknown subcommand" that reads like a typo.
fn cmd_did_restore() -> anyhow::Result<()> {
    anyhow::bail!(
        "did restore is not implemented: nothing was read and nothing was restored. \
         `anp` defines no recovery path — the update chain moves a key forward, it cannot \
         bring one back."
    )
}

// ---- agent show / use / list ----------------------------------------------------
/// `agentx-cli agent show` — which agent is in force, and which step said so.
///
/// Reported through `resolve_agent_id_with_source` rather than by re-walking the chain
/// here: two copies of the order would drift, and the one that drifted would be the one
/// that explains the other.
fn cmd_agent_show(json: bool) -> anyhow::Result<()> {
    let (agent, source) = resolve_agent_id_with_source(None)?;
    let file = current_agent_path();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "agent": agent,
                "source": source,
                "file": file,
            }))?
        );
        return Ok(());
    }
    println!("{:<8} {}", "agent:", agent);
    println!("{:<8} {}", "source:", source.describe());
    Ok(())
}

/// `agentx-cli agent use <id>` — make this agent the current one.
fn cmd_agent_use(id: &str, json: bool) -> anyhow::Result<()> {
    let path = select_current_agent(id)?;
    let agent = resolve_agent_id(None)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "agent": agent, "file": path }))?
        );
    } else {
        println!("current agent: {agent}");
    }
    // Said out loud rather than refused: selecting an agent and then creating its identity
    // is the order a new agent is born in — and without this line, every later command
    // would fail with "no identity" and no hint about which agent it meant.
    let stored = list_identities()?;
    if !stored.iter().any(|entry| entry.agent == agent) {
        eprintln!(
            "warning: no identity is stored for agent \"{agent}\" yet; `agentx-cli agent list` \
             shows what is here. Run: agentx-cli did create"
        );
    }
    Ok(())
}

/// `agentx-cli agent list` — the identities this machine can act as, current one marked.
fn cmd_agent_list(json: bool) -> anyhow::Result<()> {
    let identities = list_identities()?;
    let current = read_current_agent()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "current": current,
                "identities": identities,
            }))?
        );
        return Ok(());
    }
    if identities.is_empty() && current.is_none() {
        println!("No agents are stored. Run: agentx-cli did create");
        return Ok(());
    }
    let mark = |agent: &str| if Some(agent) == current.as_deref() { "current " } else { "        " };
    for entry in &identities {
        println!(
            "{}{}/{}  {}  {}",
            mark(&entry.agent),
            entry.agent,
            entry.profile,
            entry.handle.as_deref().unwrap_or("-"),
            entry.dir.display()
        );
    }
    // A selection with nothing stored belongs here too: it is the agent every later command
    // acts as, and "no identity stored" is the whole explanation for the failure that
    // follows. Without this row the list would look like it had forgotten the selection.
    if let Some(current) = current.as_deref() {
        if !identities.iter().any(|entry| entry.agent == current) {
            println!("{}{}  no identity stored", mark(current), current);
        }
    }
    Ok(())
}

// ---- msg send ------------------------------------------------------------------

/// The flags the two `send` commands carry, gathered so their handlers take one argument
/// instead of five.
///
/// `msg send` and `group e2ee send` ask for the same five things but put them in different
/// bodies (`payload_of` vs `application_plaintext`), so the grouping is about the *command
/// face*, not about the wire: the same `--text`/`--body` one-of, the same retry id.
struct SendPayload {
    text: Option<String>,
    body: Option<String>,
    content_type: Option<String>,
    operation_id: Option<String>,
    json: bool,
}

async fn cmd_msg_send(
    own: &OwnIdentity,
    to: &str,
    payload: SendPayload,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let json = payload.json;
    let requested_operation_id = payload.operation_id;
    let payload = payload_of(
        payload.text.as_deref(),
        payload.body.as_deref(),
        payload.content_type.as_deref(),
    )?;
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let sender = Sender::from_identity(&identity)?;
    let client = http_client()?;

    // The recipient's own document names the service that accepts its mail, so discovery is
    // per attempt and the policy is the target's, not ours.
    let endpoint = discover(&client, to, allow_private).await?;

    // P1 §6.2.6: for a message operation the sender SHOULD make `operation_id` the
    // `message_id`, and P3 §5.5 requires a retry to keep that pair unchanged. One flag
    // therefore pins both, which is the entire reason `--operation-id` exists.
    let operation_id = requested_operation_id.unwrap_or_else(uuid_v4);
    let content_type = payload.content_type;

    let response = call(
        &client,
        &sender,
        &endpoint,
        CallRequest {
            method: DIRECT_SEND.to_string(),
            profile: DIRECT_PROFILE.to_string(),
            target: AnpTarget {
                kind: TargetKind::Agent,
                did: to.to_string(),
            },
            body: payload.body,
            sender_device_id: None,
            security_profile: None,
            message_id: Some(operation_id.clone()),
            content_type: Some(content_type),
            operation_id: Some(operation_id),
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => report_accepted(&result, json),
        AnpResponse::Error { error, .. } => {
            let anp_code = error.data.as_ref().and_then(|data| data.anp_code.as_deref());
            if anp_code == Some(DID_SUPERSEDED) {
                // P1 §10.3 / P3 §5.5: the peer MUST refuse rather than retarget silently, and
                // the sender MUST verify the migration from the DID it actually asked about
                // and rebuild everything bound to that DID before retrying. That walk is
                // `did/chain`, which this client does not carry yet (TODO5 §6 Phase 3).
                anyhow::bail!(
                    "{to} was refused as superseded (anp.did_superseded). Verifying the migration \
                     and retrying is not implemented in agentx-cli yet: the peer's claim is not \
                     verified, so re-sending to the same DID would only get the same answer. \
                     Resolve the successor's DID first and send to that, or use the TS client."
                )
            }
            Err(rejection(DIRECT_SEND, to, error.code, anp_code, &error.message).into())
        }
    }
}

/// P3 §7.1.3. Only `accepted` is checked: it MUST be `true` in a success response, and a run
/// that printed "sent" for `accepted: false` would be reporting the opposite of what the
/// peer said. The rest is printed as it arrived — this is a shell, not a second
/// implementation of the receiving side.
fn report_accepted(result: &Value, json: bool) -> anyhow::Result<()> {
    if result.get("accepted").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("direct.send answered without accepted:true (P3 §7.1.3)")
    }
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    field("message id:", result.get("message_id"));
    field("operation id:", result.get("operation_id"));
    field("target:", result.get("target_did"));
    field("accepted at:", result.get("accepted_at"));
    field("conversation:", result.get("conversation_id"));
    Ok(())
}

// ---- msg caps ------------------------------------------------------------------

async fn cmd_msg_caps(did: &str, json: bool, allow_private: &[String]) -> anyhow::Result<()> {
    let client = http_client()?;
    let endpoint = discover(&client, did, allow_private).await?;

    let meta = AnpMeta {
        profile: CORE_BINDING.to_string(),
        security_profile: TRANSPORT_PROTECTED.to_string(),
        operation_id: Some(uuid_v4()),
        created_at: Some(now_rfc3339()),
        ..Default::default()
    };
    let request = build_message_request(&uuid_v4(), GET_CAPABILITIES, meta, None, None)?;
    let response = post_message(
        &client,
        &endpoint.target.endpoint,
        &request,
        &endpoint.policy,
        &endpoint.target.identity,
    )
    .await?;

    let result = match response {
        AnpResponse::Success { result, .. } => result,
        AnpResponse::Error { error, .. } => {
            return Err(rejection(
                GET_CAPABILITIES,
                did,
                error.code,
                error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
                &error.message,
            )
            .into())
        }
    };

    let capabilities = parse_capabilities(&result)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    // The static hint and the runtime answer are both worth seeing here: `msg caps` is where
    // a human finds out they disagree, and §8.3 says the runtime one is the one that counts.
    field(
        "service did:",
        Some(&Value::String(
            capabilities
                .service_did
                .clone()
                .unwrap_or_else(|| "(not stated)".to_string()),
        )),
    );
    field("profiles:", Some(&Value::String(joined(&capabilities.supported_profiles))));
    field(
        "security profiles:",
        Some(&Value::String(joined(&capabilities.supported_security_profiles))),
    );
    // §8.2.2: recommended, not required, so an empty list is stated rather than rendered as
    // a blank where a reader expects an answer.
    field(
        "content types:",
        Some(&Value::String(joined(&capabilities.supported_content_types))),
    );
    if !capabilities.limits.is_empty() {
        let limits = capabilities
            .limits
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(", ");
        field("limits:", Some(&Value::String(limits)));
    }
    Ok(())
}

// ---- msg inbox / show / read ---------------------------------------------------

/// Open the identity in use and resolve its own message service, in one place: all three
/// read commands need exactly this pair, and none of them should be able to disagree about
/// which identity they read.
async fn own_channel(
    own: &OwnIdentity,
    allow_private: &[String],
) -> anyhow::Result<(reqwest::Client, Channel)> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;
    let channel = open_channel(&client, &identity, allow_private).await?;
    Ok((client, channel))
}

/// message-service.md §9.3: `inbox.get` takes `limit` (default 20), `skip`, `include_read`.
fn limit_of(raw: Option<&str>) -> anyhow::Result<u64> {
    let Some(raw) = raw else { return Ok(20) };
    match raw.parse::<u64>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => anyhow::bail!("--limit must be a positive integer (got {raw:?})"),
    }
}

async fn cmd_msg_inbox(
    own: &OwnIdentity,
    limit: Option<String>,
    include_read: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = own_channel(own, allow_private).await?;

    let mut body = Map::new();
    body.insert("limit".to_string(), json!(limit_of(limit.as_deref())?));
    if include_read {
        body.insert("include_read".to_string(), json!(true));
    }
    let result = call_extension(&client, &channel, INBOX_GET, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    let rows = rows_of(&result, "messages");
    if rows.is_empty() {
        println!(
            "{}",
            if include_read {
                "no messages"
            } else {
                "no unread messages; pass --include-read to see the rest"
            }
        );
        return Ok(());
    }
    println!("{}", summary_of(&rows, &result));
    for row in rows {
        println!("{}", render_message(row).join("\n"));
    }
    Ok(())
}

async fn cmd_msg_show(
    own: &OwnIdentity,
    id: &str,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = own_channel(own, allow_private).await?;

    let mut body = Map::new();
    body.insert("message_ids".to_string(), json!([id]));
    let result = call_extension(&client, &channel, MESSAGE_GET_BATCH, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    let rows: Vec<&Map<String, Value>> = rows_of(&result, "items")
        .into_iter()
        .filter_map(|item| item.get("message").and_then(as_row))
        .collect();
    // `unavailable` is the peer's list of ids it could not resolve, and it is why this is
    // reported rather than rendered as an empty inbox — a message that does not exist and one
    // that was asked for under the wrong id look identical otherwise.
    if rows.is_empty() {
        anyhow::bail!("no message {id} in this inbox")
    }
    for row in rows {
        println!("{}", render_message(row).join("\n"));
    }
    Ok(())
}

async fn cmd_msg_read(
    own: &OwnIdentity,
    ids: Vec<String>,
    all: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    if all && !ids.is_empty() {
        anyhow::bail!("--all and <message_id> are two spellings of the same thing; pass one")
    }
    if !all && ids.is_empty() {
        anyhow::bail!("missing required argument <message_id>, or --all")
    }
    let (client, channel) = own_channel(own, allow_private).await?;

    let message_ids = if all {
        unread_ids(&client, &channel).await?
    } else {
        ids
    };
    if message_ids.is_empty() {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "updated_count": 0,
                    "message_ids": [],
                    "read_at": Value::Null,
                }))?
            );
        } else {
            println!("nothing unread");
        }
        return Ok(());
    }

    let mut body = Map::new();
    let count = message_ids.len();
    body.insert("message_ids".to_string(), json!(message_ids));
    let result = call_extension(&client, &channel, INBOX_MARK_READ, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    let updated = result
        .get("updated_count")
        .and_then(Value::as_u64)
        .unwrap_or(count as u64);
    field("marked read:", Some(&json!(updated)));
    field("read at:", result.get("read_at"));
    Ok(())
}

/// Every unread id, paged. `--all` marks the ids that were LISTED, not "whatever is unread
/// when the write lands": a message arriving between the two calls is left unread, which is
/// the only reading of the flag that does not silently swallow one (message-service.md §9.3).
async fn unread_ids(client: &reqwest::Client, channel: &Channel) -> anyhow::Result<Vec<String>> {
    let mut ids = Vec::new();
    let mut skip: u64 = 0;
    loop {
        let mut body = Map::new();
        body.insert("limit".to_string(), json!(ALL_PAGE));
        body.insert("skip".to_string(), json!(skip));
        body.insert("include_read".to_string(), json!(false));
        let page = call_extension(client, channel, INBOX_GET, body).await?;

        let rows = rows_of(&page, "messages");
        for row in &rows {
            if let Some(id) = id_of(row) {
                ids.push(id.to_string());
            }
        }
        // A page that contributes nothing under `has_more` would repeat forever, so an empty
        // page ends the walk whatever the flag says.
        if page.get("has_more").and_then(Value::as_bool) != Some(true) || rows.is_empty() {
            return Ok(ids);
        }
        skip += rows.len() as u64;
    }
}

// ---- msg listen -----------------------------------------------------------------

/// `--since` is parsed by clap into a `u64`, so a value that is not a sequence number never
/// gets past the argument parser — before an identity is opened or a document is fetched.
struct ListenOptions {
    device: Option<String>,
    since: Option<u64>,
    ack: bool,
    once: bool,
    json: bool,
}

async fn cmd_msg_listen(
    own: &OwnIdentity,
    options: ListenOptions,
    allow_private: &[String],
) -> anyhow::Result<()> {
    // The identity is opened and its own service resolved before anything long-running
    // starts, so a missing identity or an unreachable DID document fails like any other
    // command rather than as a stream that never connects.
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;
    let channel = open_channel(&client, &identity, allow_private).await?;
    let device = device_of(&channel.sender, options.device.as_deref())?;

    // A listener is exactly the place where §12's pushes arrive, so it is the place that
    // carries the P6 receive path. The same `client` is shared: a notice costs a roster read
    // and one DID document per member, and each of those should reuse the connection pool the
    // stream's requests already warm.
    let receiver = Arc::new(GroupReceiver::new(
        client.clone(),
        location,
        identity,
        allow_private.to_vec(),
    ));

    let deps = ListenDeps {
        connect: websocket_connect_fn(),
        view: view_for(options.json),
        abort: interrupt_signal(),
        // `rand::random::<f64>()` is `[0, 1)`, which is the range the jitter expects.
        random: Arc::new(rand::random::<f64>),
        receiver: Some(receiver),
    };
    run_listen(
        &channel,
        ListenArgs {
            device,
            since: options.since,
            ack: options.ack,
            once: options.once,
        },
        deps,
    )
    .await?;
    Ok(())
}

/// The real connect: `websocket_connect` takes `&str`, while a [`ConnectFn`] owns its `url`.
fn websocket_connect_fn() -> ConnectFn {
    Arc::new(|url: String| Box::pin(async move { websocket_connect(&url).await }))
}

/// An interrupt that the stream's waits observe (realtime.md §7.2).
///
/// SIGINT and SIGTERM both mean "stop", and both exit 0: the messages already printed are not
/// unprinted, and a Ctrl-C is how a person ends a listener. The watch channel is what makes
/// the exit immediate — the state machine's waits select on it, so a backoff sleep does not
/// delay the exit by up to 30 seconds.
fn interrupt_signal() -> tokio::sync::watch::Receiver<bool> {
    let (fire, observe) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            match signal(SignalKind::terminate()) {
                Ok(mut terminate) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = terminate.recv() => {}
                    }
                }
                // Without SIGTERM, Ctrl-C is still handled rather than both being lost.
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = fire.send(true);
    });
    observe
}

// ---- group ---------------------------------------------------------------------

/// A call addressed to the group itself.
///
/// The group's own DID document names the host that answers for it, exactly as an agent's
/// does (P2 §9.2), so there is no group-specific discovery to write — only the signer differs
/// from the target, which is why this is not [`own_channel`].
async fn group_channel(
    own: &OwnIdentity,
    group_did: &str,
    allow_private: &[String],
) -> anyhow::Result<(reqwest::Client, Channel)> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let sender = Sender::from_identity(&identity)?;
    let client = http_client()?;
    let channel = open_channel_for(&client, sender, group_did, allow_private).await?;
    Ok((client, channel))
}

async fn cmd_group_create(
    own: &OwnIdentity,
    name: Option<String>,
    policy: Option<String>,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    // Checked before an identity is opened or a document fetched: a policy the service would
    // refuse should cost nothing to hear about, and this is the one group argument that has
    // rules of its own.
    let policy = policy_of(policy.as_deref())?;
    let (client, channel) = own_channel(own, allow_private).await?;
    // The target is the service, not a group: there is no group DID until this call answers.
    let target = service_target(&channel.endpoint.target)?;

    let mut body = Map::new();
    body.insert("group_policy".to_string(), policy);
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        body.insert("group_profile".to_string(), json!({ "display_name": name }));
    }

    let result = call_group(
        &client,
        &channel,
        GROUP_CREATE,
        target,
        body,
        // The service is the one answering, and the caller is who it answers about.
        &channel.sender.did,
    )
    .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_group_created(&result)
}

/// `group members` IS `group.get_info` with a projection (§8.2.2), so one function serves
/// both: asking for the roster is not a different operation, and a second call path would be
/// a second place to get the visibility rules wrong.
async fn cmd_group_info(
    own: &OwnIdentity,
    group_did: &str,
    members: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = group_channel(own, group_did, allow_private).await?;

    let mut body = Map::new();
    if members {
        body.insert("include_member_list".to_string(), json!(true));
    }
    let result = call_group(
        &client,
        &channel,
        GROUP_GET_INFO,
        group_target(group_did),
        body,
        group_did,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    if members {
        report_roster(&result)?;
    } else {
        report_group_info(&result);
    }
    Ok(())
}

/// `join` and `leave` differ only in the method and in which field names the subject of the
/// change (§8.3.3 / §8.6.4), so they share a body: the subject is `meta.sender_did` by
/// construction in both (§8.3.2 / §8.6.2) — the body MUST NOT name a member, so there is
/// nothing to pass — and the rest is the same call.
async fn cmd_group_membership(
    own: &OwnIdentity,
    group_did: &str,
    method: &str,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = group_channel(own, group_did, allow_private).await?;
    let result = call_group(
        &client,
        &channel,
        method,
        group_target(group_did),
        Map::new(),
        group_did,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_membership(&result, if method == GROUP_JOIN { "member" } else { "leaver" })
}

async fn cmd_group_send(
    own: &OwnIdentity,
    group_did: &str,
    payload: SendPayload,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let json = payload.json;
    let requested_operation_id = payload.operation_id;
    let payload = payload_of(
        payload.text.as_deref(),
        payload.body.as_deref(),
        payload.content_type.as_deref(),
    )?;
    let (client, channel) = group_channel(own, group_did, allow_private).await?;

    // P1 §6.2.6: one flag pins `operation_id` and `message_id` together, so a retry keeps
    // the pair unchanged (P4 §5.4).
    let operation_id = requested_operation_id.unwrap_or_else(uuid_v4);
    let content_type = payload.content_type;

    let response = call(
        &client,
        &channel.sender,
        &channel.endpoint,
        CallRequest {
            method: GROUP_SEND.to_string(),
            profile: GROUP_PROFILE.to_string(),
            target: group_target(group_did),
            body: payload.body,
            sender_device_id: None,
            security_profile: None,
            message_id: Some(operation_id.clone()),
            content_type: Some(content_type),
            operation_id: Some(operation_id),
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => report_group_sent(&result, json),
        // No `anp.did_superseded` retry here, unlike `msg send` (cli.md §3.4): DID continuity
        // inside a group is member-level and host-driven — P4 §8.12 says
        // `group.member_did_update` is not even a JSON-RPC method — and P4 defines no client
        // path for a group DID itself, so there is nothing to verify and retry.
        AnpResponse::Error { error, .. } => Err(rejection(
            GROUP_SEND,
            group_did,
            error.code,
            error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
            &error.message,
        )
        .into()),
    }
}

// ---- group e2ee ------------------------------------------------------------------

/// Publish this device's KeyPackage (§8.1).
///
/// The order is the one the pieces have to come in: mint the package (which needs the
/// identity and writes to the MLS store), then open the channel, then send. A mint that
/// fails costs nothing on the network, and a channel that fails leaves a package in the
/// store that a retry with the same `--key-package-id` will hand back unchanged.
async fn cmd_group_e2ee_publish(
    own: &OwnIdentity,
    key_package_id: Option<String>,
    valid_days: i64,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let key_package_id = key_package_id.unwrap_or_else(new_key_package_id);

    let package = generate_key_package(
        &location,
        &identity,
        &key_package_id,
        chrono::Duration::days(valid_days),
    )?;
    let body = publish_body(&package)?;

    let client = http_client()?;
    let channel = open_channel(&client, &identity, allow_private).await?;
    // The target is the service, as with `group.create`: §8.1.2 L697 spells out that
    // `meta.target.did` is the servicing host's DID, and the device being published is
    // `meta.sender_device_id` — the caller's own, which `call_device` fills in.
    let target = service_target(&channel.endpoint.target)?;

    let result = call_device(
        &client,
        &channel,
        PUBLISH_KEY_PACKAGE,
        target,
        body,
        &channel.sender.did,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_key_package_published(&result)?;
    Ok(())
}

/// §8.1.3: the service's own record of what it filed, echoed back.
///
/// `published: false` is not a failure the caller should paper over — §8.1.2 says the cabinet
/// ignores a re-publish under an id it already holds, so a false here means the service did
/// not store *this* object, and printing the rest of the fields as if it had would be
/// reporting a state the service does not have.
fn report_key_package_published(result: &Value) -> anyhow::Result<()> {
    if result.get("published").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("group.e2ee.publish_key_package did not report `published: true` (P6 §8.1.3)")
    }
    field("owner:", result.get("owner_did"));
    field("device:", result.get("owner_device_id"));
    field("key package:", result.get("key_package_id"));
    field("published at:", result.get("published_at"));
    Ok(())
}

/// Fetch a peer device's published KeyPackage (§8.2).
///
/// The body names the *peer* while the target names the service, which is the shape §8.2.2
/// asks for: the cabinet belongs to the servicing host, and the package is looked up inside
/// it by `(did, device)`. Nothing is written locally — the package is evidence of what the
/// peer published, and §9.3.3's `add` is where one gets used.
async fn cmd_group_e2ee_get_key_package(
    own: &OwnIdentity,
    target_did: String,
    target_device: String,
    suite: Option<String>,
    require_fresh: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;

    let client = http_client()?;
    let channel = open_channel(&client, &identity, allow_private).await?;
    let target = service_target(&channel.endpoint.target)?;

    let result = call_device(
        &client,
        &channel,
        GET_KEY_PACKAGE,
        target,
        get_key_package_body(&target_did, &target_device, suite.as_deref(), require_fresh)?,
        &target_did,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_key_package_fetched(&result)
}

/// §8.2.3: the package as published, plus the two fields the caller asked with.
///
/// The package's own id and expiry are what the caller can act on; its MLS bytes are not
/// something a terminal should print, so they stay behind `--json`. A response whose
/// `group_key_package` is missing is a service lying about §8.2.3, not an empty cabinet —
/// an empty cabinet is a refusal (`keyPackageNotFound`), which never reaches here.
fn report_key_package_fetched(result: &Value) -> anyhow::Result<()> {
    let package = result.get("group_key_package").ok_or_else(|| {
        anyhow::anyhow!("group.e2ee.get_key_package answered without a group_key_package (P6 §8.2.3)")
    })?;
    field("target:", result.get("target_did"));
    field("device:", result.get("target_device_id"));
    field("key package:", package.get("key_package_id"));
    field("suite:", package.get("suite"));
    field("expires:", package.get("expires_at"));
    Ok(())
}

/// Initialise the group's MLS state, with this device as its creator (§9.2).
///
/// Three phases, in the crate's order: prepare (local MLS state and a write-ahead record),
/// send (the service decides), then finalize or abort. Reading P4's state first is a
/// precondition rather than a phase — §9.2.3's `group_state_ref` carries the group's current
/// `group_state_version`, and asking P4 for it is also the plainest way to hear that the
/// group is not this identity's to initialise.
///
/// Nothing here sends a KeyPackage to the cabinet: §9.2.3 wants the *creator's* package in
/// the body, and §8.2's publish/get pair exists for adding people who are not in the room.
async fn cmd_group_e2ee_create(
    own: &OwnIdentity,
    group_did: &str,
    key_package_id: Option<String>,
    operation_id: Option<String>,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;
    let sender = Sender::from_identity(&identity)?;
    // Resolved against the **group's** DID document, unlike `group.create`: the group exists,
    // and its document is what names the Host this call has to be addressed to (P2 §9.1).
    let channel = open_channel_for(&client, sender, group_did, allow_private).await?;

    let info = call_group(
        &client,
        &channel,
        GROUP_GET_INFO,
        group_target(group_did),
        Map::new(),
        group_did,
    )
    .await?;
    let group_state_version = text_of(info.get("group_state_version")).ok_or_else(|| {
        anyhow::anyhow!("group.get_info answered without a group_state_version (P4 §8.2.3)")
    })?;

    // §4.4.1 L292–293: the target is the **service**, and it must be the one that named
    // itself in the group's document — the service refuses a `meta.target.did` that is not
    // its own `serviceDid`.
    let target = service_target(&channel.endpoint.target)?;
    let operation_id = operation_id.unwrap_or_else(uuid_v4);
    let key_package_id = key_package_id.unwrap_or_else(new_key_package_id);
    let creator_key_package = generate_key_package(
        &location,
        &identity,
        &key_package_id,
        chrono::Duration::days(KEY_PACKAGE_VALID_DAYS),
    )?;
    let prepared = prepare_create(
        &location,
        &identity,
        CreateInput {
            group_did,
            group_state_version,
            creator_key_package: &creator_key_package,
            service_did: &target.did,
            operation_id: &operation_id,
        },
    )?;

    let response = call(
        &client,
        &channel.sender,
        &channel.endpoint,
        CallRequest {
            method: GROUP_E2EE_CREATE.to_string(),
            profile: GROUP_E2EE_PROFILE.to_string(),
            target,
            body: create_body(&prepared.body)?,
            sender_device_id: Some(channel.sender.device_id.clone()),
            security_profile: Some(group_e2ee_security_profile(GROUP_E2EE_CREATE).to_string()),
            message_id: None,
            content_type: None,
            operation_id: Some(operation_id),
        },
    )
    .await?;

    // The response is matched rather than run through `call_device`, because which half of
    // §13.6's third phase applies depends on *why* it failed. A refusal means the service
    // never took this commit, so it is rolled back here; a request that failed in transport
    // may well have been accepted with only the answer lost, and rolling back then would
    // leave this device with no state for a group the service believes it has. That case is
    // the crate's `reconcile_pending_v2` to sort out, not a guess made here.
    let result = match response {
        AnpResponse::Success { result, .. } => {
            finalize_commit(&location, &identity, &prepared.pending_commit_id)?;
            result
        }
        AnpResponse::Error { error, .. } => {
            if let Err(err) = abort_commit(&location, &identity, &prepared.pending_commit_id) {
                // The refusal is what the caller needs; a rollback that failed is worth
                // saying out loud but not worth replacing that with a worse description of
                // the same event.
                eprintln!("warning: rolling back the local commit failed: {err}");
            }
            return Err(rejection(
                GROUP_E2EE_CREATE,
                group_did,
                error.code,
                error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
                &error.message,
            )
            .into());
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_group_e2ee_created(&result)
}

/// §9.2.4's success fields.
///
/// `created: true` is checked before anything is printed, as on the publish path: a service
/// that answered without it did not report state this client can go on to add members to,
/// and printing the rest as if it had would be reporting a group that does not exist.
fn report_group_e2ee_created(result: &Value) -> anyhow::Result<()> {
    if result.get("created").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("group.e2ee.create did not report `created: true` (P6 §9.2.4)")
    }
    field("group:", result.get("group_did"));
    field("crypto group:", result.get("crypto_group_id_b64u"));
    field("epoch:", result.get("epoch"));
    field("accepted at:", result.get("accepted_at"));
    Ok(())
}

/// Add one device of an existing member to the group's MLS state (§9.3).
///
/// The same three phases as [`cmd_group_e2ee_create`], and the same rule for the third one: a
/// service refusal aborts the local commit, a transport failure is left to
/// `reconcile_pending_v2`. What differs is where the inputs come from. Two network reads
/// happen first, and they are deliberately to *different* places:
///
///   - `group.get_info` goes to the **group**, because §9.3.3's `group_state_ref` carries the
///     group's P4 version and only the group's own service can say what that is;
///   - the member's KeyPackage is fetched from the **member's** service. §8.2's cabinet
///     belongs to the servicing host — the one the member's own document names — and §8.2.3
///     lets that be a different domain from the group's, so asking the group's service would
///     work only where the two happen to coincide.
///
/// The `add` itself is group-addressed (§4.4.2), so it goes back to the group's service, with
/// the member's document already resolved and re-checked against the package the crate will
/// build the commit from.
async fn cmd_group_e2ee_add(
    own: &OwnIdentity,
    group_did: &str,
    member_did: &str,
    member_device: &str,
    operation_id: Option<String>,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;

    // The group's document is what names the service holding this group (P2 §9.1) — the same
    // resolution `create` needs, for the same reason.
    let group_channel = open_channel_for(
        &client,
        Sender::from_identity(&identity)?,
        group_did,
        allow_private,
    )
    .await?;
    let info = call_group(
        &client,
        &group_channel,
        GROUP_GET_INFO,
        group_target(group_did),
        Map::new(),
        group_did,
    )
    .await?;
    let group_state_version = text_of(info.get("group_state_version")).ok_or_else(|| {
        anyhow::anyhow!("group.get_info answered without a group_state_version (P4 §8.2.3)")
    })?;

    // The member's document, read for two reasons at once: its ANPMessageService entry is
    // where the package was filed, and the document is what the crate re-validates that
    // package's `did_wba_binding` against. Resolved through the policy the member's own
    // channel produced, so the hop is checked the same way every other peer hop is.
    let member_channel = open_channel_for(
        &client,
        Sender::from_identity(&identity)?,
        member_did,
        allow_private,
    )
    .await?;
    let member_document =
        resolve_did_document(&client, member_did, &member_channel.endpoint.policy).await?;

    let fetched = call_device(
        &client,
        &member_channel,
        GET_KEY_PACKAGE,
        service_target(&member_channel.endpoint.target)?,
        get_key_package_body(member_did, member_device, None, false)?,
        member_did,
    )
    .await?;
    let package = fetched.get("group_key_package").cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "group.e2ee.get_key_package answered without a group_key_package (P6 §8.2.3)"
        )
    })?;
    // The crate's own model, so a package this service hands out is parsed by the same types
    // the commit will be built from. A service answering with a field the crate does not have
    // is a shape problem here rather than a mystery at prepare time.
    let group_key_package: V2GroupKeyPackage = serde_json::from_value(package).map_err(|err| {
        anyhow::anyhow!("the service's group_key_package is not one this crate can read: {err}")
    })?;
    // As in `generate_key_package`: the crate re-checks the issuer's binding with no fallback
    // of its own, so the document goes in already in the encoding that check accepts.
    let member_did_document = document_in_crate_form(&member_document).ok_or_else(|| {
        anyhow::anyhow!("{member_did}'s document does not bind in a form this crate accepts")
    })?;

    let operation_id = operation_id.unwrap_or_else(uuid_v4);
    let prepared = prepare_add(
        &location,
        &identity,
        AddInput {
            group_did,
            group_state_version,
            group_key_package: &group_key_package,
            member_did_document,
            operation_id: &operation_id,
        },
    )?;

    let response = call(
        &client,
        &group_channel.sender,
        &group_channel.endpoint,
        CallRequest {
            method: GROUP_E2EE_ADD.to_string(),
            profile: GROUP_E2EE_PROFILE.to_string(),
            // §4.4.2: group-addressed, unlike `create`.
            target: group_target(group_did),
            body: add_body(&prepared.body)?,
            sender_device_id: Some(group_channel.sender.device_id.clone()),
            security_profile: Some(group_e2ee_security_profile(GROUP_E2EE_ADD).to_string()),
            // §9.3.3 names neither: this call carries no application message.
            message_id: None,
            content_type: None,
            operation_id: Some(operation_id),
        },
    )
    .await?;

    // Matched rather than run through `call_device`, for the reason spelled out in
    // `cmd_group_e2ee_create`: only a *refusal* proves the service did not take the commit.
    let result = match response {
        AnpResponse::Success { result, .. } => {
            finalize_commit(&location, &identity, &prepared.pending_commit_id)?;
            result
        }
        AnpResponse::Error { error, .. } => {
            if let Err(err) = abort_commit(&location, &identity, &prepared.pending_commit_id) {
                eprintln!("warning: rolling back the local commit failed: {err}");
            }
            return Err(rejection(
                GROUP_E2EE_ADD,
                group_did,
                error.code,
                error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
                &error.message,
            )
            .into());
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_group_e2ee_added(&result)
}

/// §9.3.4's success fields.
///
/// `accepted: true` is checked before anything is printed, as on the other two paths — and
/// here it matters more, because the local pending commit was just finalized on the strength
/// of this response. A service that answered without it did not report state this device can
/// go on to send in.
fn report_group_e2ee_added(result: &Value) -> anyhow::Result<()> {
    if result.get("accepted").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("group.e2ee.add did not report `accepted: true` (P6 §9.3.4)")
    }
    field("group:", result.get("group_did"));
    field("member:", result.get("member_did"));
    field("device:", result.get("member_device_id"));
    field("epoch:", result.get("epoch"));
    field("accepted at:", result.get("accepted_at"));
    Ok(())
}

/// `group e2ee remove` (P6 §9.4) — `add`'s mirror, with one channel instead of two.
///
/// Where `add` reads the member's document *and* fetches from the member's service, this
/// reads only the document: the removal names the exact leaf (§9.4.3), so there is no package
/// to fetch, and the target device is deliberately not required to be eligible — losing
/// eligibility is one reason to remove it (the service's `deviceAddressed` names only the
/// sender for the same reason). The document is still read, because the crate's leaf lookup
/// takes it as evidence that the pair names the leaf being removed.
///
/// The policy for that one fetch is built straight from the member's DID host rather than by
/// opening a channel: `channel::discover`'s document half is exactly this, and removing a
/// device should not require its owner to still expose a live ANPMessageService entry.
async fn cmd_group_e2ee_remove(
    own: &OwnIdentity,
    group_did: &str,
    member_did: &str,
    member_device: &str,
    operation_id: Option<String>,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;

    // The group's document names the service holding this group, as on `add` and `create`.
    let group_channel = open_channel_for(
        &client,
        Sender::from_identity(&identity)?,
        group_did,
        allow_private,
    )
    .await?;
    let info = call_group(
        &client,
        &group_channel,
        GROUP_GET_INFO,
        group_target(group_did),
        Map::new(),
        group_did,
    )
    .await?;
    let group_state_version = text_of(info.get("group_state_version")).ok_or_else(|| {
        anyhow::anyhow!("group.get_info answered without a group_state_version (P4 §8.2.3)")
    })?;

    // The target's document, fetched through the one host its DID names — the same policy
    // `discover` uses for its document half, because that is all this needs. No service entry
    // is read, so a member whose Host is gone can still be removed as long as its document
    // still answers; and if even that is unreachable, the removal cannot prove which leaf it
    // means, so failing here is the honest outcome.
    let member_policy = policy_for(&[did_host(member_did)?], allow_private);
    let member_document = resolve_did_document(&client, member_did, &member_policy).await?;
    let member_did_document = document_in_crate_form(&member_document).ok_or_else(|| {
        anyhow::anyhow!("{member_did}'s document does not bind in a form this crate accepts")
    })?;

    let operation_id = operation_id.unwrap_or_else(uuid_v4);
    let prepared = prepare_remove(
        &location,
        &identity,
        RemoveInput {
            group_did,
            group_state_version,
            member_did,
            member_device_id: member_device,
            member_did_document,
            operation_id: &operation_id,
        },
    )?;

    let response = call(
        &client,
        &group_channel.sender,
        &group_channel.endpoint,
        CallRequest {
            method: GROUP_E2EE_REMOVE.to_string(),
            profile: GROUP_E2EE_PROFILE.to_string(),
            // §4.4.2: group-addressed, as on `add`.
            target: group_target(group_did),
            body: remove_body(&prepared.body)?,
            sender_device_id: Some(group_channel.sender.device_id.clone()),
            security_profile: Some(group_e2ee_security_profile(GROUP_E2EE_REMOVE).to_string()),
            // §9.4.3 names neither: a removal carries no application message.
            message_id: None,
            content_type: None,
            operation_id: Some(operation_id),
        },
    )
    .await?;

    // Matched rather than run through `call_device`, for the reason spelled out in
    // `cmd_group_e2ee_create`: only a *refusal* proves the service did not take the commit.
    let result = match response {
        AnpResponse::Success { result, .. } => {
            finalize_commit(&location, &identity, &prepared.pending_commit_id)?;
            result
        }
        AnpResponse::Error { error, .. } => {
            if let Err(err) = abort_commit(&location, &identity, &prepared.pending_commit_id) {
                eprintln!("warning: rolling back the local commit failed: {err}");
            }
            return Err(rejection(
                GROUP_E2EE_REMOVE,
                group_did,
                error.code,
                error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
                &error.message,
            )
            .into());
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_group_e2ee_removed(&result)
}

/// §9.4.4's success fields — the same shape as `add`'s, minus nothing.
///
/// `accepted: true` is checked first for the same reason: the local commit was just finalized
/// on the strength of this response, so a service that omitted it did not report state this
/// device can go on to send in.
fn report_group_e2ee_removed(result: &Value) -> anyhow::Result<()> {
    if result.get("accepted").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("group.e2ee.remove did not report `accepted: true` (P6 §9.4.4)")
    }
    field("group:", result.get("group_did"));
    field("member:", result.get("member_did"));
    field("device:", result.get("member_device_id"));
    field("epoch:", result.get("epoch"));
    field("accepted at:", result.get("accepted_at"));
    Ok(())
}

/// `group e2ee send` (P6 §9.5) — the one control method with no local commit to finish.
///
/// The shape is `group send`'s, minus the three-phase machinery: encrypt against the current
/// epoch, put the one cipher object in the body, and let the service order it. There is no
/// pending commit, so a service refusal needs no rollback — the local MLS state was only ever
/// *read* (§9.5 sends the current epoch; it does not advance it).
async fn cmd_group_e2ee_send(
    own: &OwnIdentity,
    group_did: &str,
    payload: SendPayload,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let SendPayload {
        text,
        body,
        content_type,
        operation_id,
        json,
    } = payload;
    let plaintext = application_plaintext(text.as_deref(), body.as_deref(), content_type.as_deref())?;
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;

    // The group's document names the service holding this group, as on the other methods.
    let group_channel = open_channel_for(
        &client,
        Sender::from_identity(&identity)?,
        group_did,
        allow_private,
    )
    .await?;
    let info = call_group(
        &client,
        &group_channel,
        GROUP_GET_INFO,
        group_target(group_did),
        Map::new(),
        group_did,
    )
    .await?;
    let group_state_version = text_of(info.get("group_state_version")).ok_or_else(|| {
        anyhow::anyhow!("group.get_info answered without a group_state_version (P4 §8.2.3)")
    })?;

    // One flag names both halves of the triple `group send` also pins together (P1 §6.2.6):
    // the request's `operation_id` and the message's `message_id` are the same value here, so
    // a retry that reuses `--operation-id` reuses the whole identity of the message.
    let operation_id = operation_id.unwrap_or_else(uuid_v4);
    let cipher = send_message(
        &location,
        &identity,
        SendInput {
            group_did,
            group_state_version,
            message_id: &operation_id,
            operation_id: &operation_id,
            plaintext,
        },
    )?;

    // §13.3 item 6: this is the one P6 call whose origin proof has to be made with the
    // sending *device's* key rather than the DID root's. The service compares the proof's
    // `keyid` against the DID document's `signing_key_id` for `meta.sender_device_id`, and
    // `key-1` loses that comparison — so the sender is re-cut here, same DID, device key.
    let (device_keyid, device_key) = device_signing_key(&identity)?;
    let sender = group_channel
        .sender
        .signing_as_device(device_keyid, device_key);

    let response = call(
        &client,
        &sender,
        &group_channel.endpoint,
        CallRequest {
            method: GROUP_E2EE_SEND.to_string(),
            profile: GROUP_E2EE_PROFILE.to_string(),
            // §4.4.2: group-addressed, like `add` and `remove`.
            target: group_target(group_did),
            body: send_body(&cipher)?,
            sender_device_id: Some(group_channel.sender.device_id.clone()),
            security_profile: Some(group_e2ee_security_profile(GROUP_E2EE_SEND).to_string()),
            // §9.5.3 makes both mandatory on this method — this is the one P6 call that
            // carries an application message.
            message_id: Some(operation_id.clone()),
            content_type: Some(GROUP_CIPHER_CONTENT_TYPE.to_string()),
            operation_id: Some(operation_id),
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => report_group_e2ee_sent(&result, json),
        AnpResponse::Error { error, .. } => Err(rejection(
            GROUP_E2EE_SEND,
            group_did,
            error.code,
            error.data.as_ref().and_then(|data| data.anp_code.as_deref()),
            &error.message,
        )
        .into()),
    }
}

/// §9.5.4's success fields.
///
/// Two of them are worth reading rather than skipping. `epoch` is the epoch of **the accepted
/// ciphertext**, not the group's current one — §9.5.3 says the two may differ under reordered
/// delivery, so a caller comparing them would be comparing two different things. And
/// `accepted: true` says only that the service took and ordered the message; it never says a
/// member could decrypt it (§9.5's own success semantics).
fn report_group_e2ee_sent(result: &Value, json: bool) -> anyhow::Result<()> {
    if result.get("accepted").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("group.e2ee.send did not report `accepted: true` (P6 §9.5.4)")
    }
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    field("group:", result.get("group_did"));
    field("message id:", result.get("message_id"));
    field("epoch:", result.get("epoch"));
    field("event seq:", result.get("group_event_seq"));
    field("state version:", result.get("group_state_version"));
    field("accepted at:", result.get("accepted_at"));
    Ok(())
}

/// §8.1.3: `group_did` at minimum, and the pair a caller has to keep for the next call — the
/// group it just made, and where that group's state stands.
fn report_group_created(result: &Value) -> anyhow::Result<()> {
    let group_did = text_of(result.get("group_did"));
    let Some(group_did) = group_did else {
        anyhow::bail!("group.create answered without a group_did (P4 §8.1.3)")
    };
    field("group:", Some(&Value::String(group_did.to_string())));
    field("state version:", result.get("group_state_version"));
    field("created at:", result.get("created_at"));
    field("creator:", result.get("creator_did"));
    if let Some(profile) = result.get("group_profile").and_then(as_row) {
        field("name:", profile.get("display_name"));
    }
    Ok(())
}

/// §8.2.3. `member_count` is a decimal string there and is printed as it arrived rather than
/// parsed — it is the peer's number, and rounding it would be this CLI inventing a fact.
fn report_group_info(result: &Value) {
    field("group:", result.get("group_did"));
    field("state version:", result.get("group_state_version"));
    if let Some(profile) = result.get("group_profile").and_then(as_row) {
        field("name:", profile.get("display_name"));
        field("description:", profile.get("description"));
        field("discoverability:", profile.get("discoverability"));
    }
    field("members:", result.get("member_count"));
    match result.get("group_policy").and_then(as_row) {
        Some(policy) => {
            field("admission:", policy.get("admission_mode"));
            if let Some(permissions) = policy.get("permissions").and_then(as_row) {
                let rendered = permissions
                    .iter()
                    .map(|(key, value)| format!("{key}={}", value.as_str().unwrap_or(&value.to_string())))
                    .collect::<Vec<_>>()
                    .join(", ");
                field("permissions:", Some(&Value::String(rendered)));
            }
        }
        // §8.2.3: the policy comes back only when the caller asked AND is entitled to see it,
        // so its absence is the service's answer and not a missing field.
        None => field(
            "policy:",
            Some(&Value::String(
                "(not returned; the service decides what this caller may see)".to_string(),
            )),
        ),
    }
}

/// §7.2: `agent_did` / `role` / `status` are the minimum; `joined_at` and `added_by` are
/// optional and printed when present.
fn report_roster(result: &Value) -> anyhow::Result<()> {
    let rows = rows_of(result, "member_list");
    if rows.is_empty() {
        println!("no members listed (the service returns a roster only to callers entitled to it)");
        return Ok(());
    }
    println!("{} member{}", rows.len(), if rows.len() == 1 { "" } else { "s" });
    for row in rows {
        let role = text_of(row.get("role")).unwrap_or("member");
        let status = text_of(row.get("status")).unwrap_or("unknown");
        let agent = text_of(row.get("agent_did")).unwrap_or("(unnamed)");
        let joined = match text_of(row.get("joined_at")) {
            Some(joined) => format!("  joined {joined}"),
            None => String::new(),
        };
        println!("  {status:<8} {role:<6} {agent}{joined}");
    }
    Ok(())
}

/// §8.3.3 / §8.6.4: the two answers differ in which field names the subject of the change,
/// and reporting the wrong one would be reporting someone else.
fn report_membership(result: &Value, subject: &str) -> anyhow::Result<()> {
    field("group:", result.get("group_did"));
    let named = if subject == "member" {
        result.get("member_did")
    } else {
        result.get("leaver_did")
    };
    field(&format!("{subject}:"), named);
    field("status:", result.get("membership_status"));
    field("state version:", result.get("group_state_version"));
    Ok(())
}

/// §8.9.4: `accepted` MUST be `true` — checked before the JSON is printed, because `--json`
/// is not a reason to report a send that the group declined — and the event position is what
/// lines this message up with what the other members saw.
fn report_group_sent(result: &Value, json: bool) -> anyhow::Result<()> {
    if result.get("accepted").and_then(Value::as_bool) != Some(true) {
        anyhow::bail!("group.send answered without accepted:true (P4 §8.9.4)")
    }
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    field("group:", result.get("group_did"));
    field("message id:", result.get("message_id"));
    field("event seq:", result.get("group_event_seq"));
    field("state version:", result.get("group_state_version"));
    field("accepted at:", result.get("accepted_at"));
    Ok(())
}

// ---- reading what came back ----------------------------------------------------

/// A peer's string field. An empty string is treated as absent, for the same reason the TS
/// client's `textOf` does: a service that sends `""` for an unset name is saying it has no
/// name, and printing a blank after a label says nothing at all.
fn text_of(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|text| !text.is_empty())
}

fn field(label: &str, value: Option<&Value>) {
    let Some(value) = value else { return };
    let rendered = match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    println!("{label:<20} {rendered}");
}

fn joined(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".to_string()
    } else {
        values.join(", ")
    }
}

/// A peer's JSON, narrowed rather than trusted: everything that reads it may meet a
/// different implementation, and a value with a field missing is still worth printing.
fn as_row(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

fn rows_of<'a>(result: &'a Value, key: &str) -> Vec<&'a Map<String, Value>> {
    result
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(as_row).collect())
        .unwrap_or_default()
}

/// The identifier `msg show` takes. `id` is the same value under the name
/// `_direct_message_result` also publishes, so either spelling resolves.
fn id_of(row: &Map<String, Value>) -> Option<&str> {
    row.get("message_id")
        .or_else(|| row.get("id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
}

fn summary_of(rows: &[&Map<String, Value>], result: &Value) -> String {
    let unread = rows.iter().filter(|row| is_unread(row)).count();
    let more = if result.get("has_more").and_then(Value::as_bool) == Some(true) {
        " (more available)"
    } else {
        ""
    };
    format!(
        "{} message{}, {} unread{}",
        rows.len(),
        if rows.len() == 1 { "" } else { "s" },
        unread,
        more
    )
}

/// Unread means "the owner has not read it". An outgoing row is the owner's own copy of
/// something they sent, and the service leaves its `read_at` null because the field has no
/// meaning there (message-service.md §9.3) — reading that null as "unread" would count every
/// message the user ever sent into the unread tally.
fn is_unread(row: &Map<String, Value>) -> bool {
    if row.get("direction").and_then(Value::as_str) == Some("outgoing") {
        return false;
    }
    matches!(row.get("read_at"), None | Some(Value::Null))
}

/// One message, as an IM client shows one: who and when on the opening line, the body under
/// it, the id last. Three lines rather than one because the id is the argument to `msg show`
/// and has to survive a copy — a truncated one is a broken command.
fn render_message(row: &Map<String, Value>) -> Vec<String> {
    let direction = row
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let counterpart = if direction == "outgoing" {
        row.get("recipient_did")
    } else {
        row.get("sender_did")
    };
    let peer = counterpart
        .and_then(Value::as_str)
        .filter(|peer| !peer.is_empty())
        .unwrap_or("(unknown peer)");
    let at = row.get("created_at").and_then(Value::as_str).unwrap_or("");

    let mut out = vec![format!(
        "  {}  {}  {}  {}",
        if is_unread(row) { "unread" } else { "read  " },
        at,
        direction,
        peer
    )];
    out.extend(content_of(row).into_iter().map(|line| format!("    {line}")));
    if let Some(id) = id_of(row) {
        out.push(format!("    id {id}"));
    }
    out
}

/// The body as it arrived. `text` and `payload` are the two shapes P3 §6.2 defines and are
/// printed as they were sent; a P5/P6 payload stays opaque, because decrypting is the
/// client's job and this service never holds the key (message-service.md §11).
fn content_of(row: &Map<String, Value>) -> Vec<String> {
    let lines = |text: &str| text.split('\n').map(str::to_string).collect::<Vec<_>>();
    if let Some(body) = row.get("body").and_then(Value::as_object) {
        if let Some(text) = body.get("text").and_then(Value::as_str) {
            return lines(text);
        }
        if let Some(payload) = body.get("payload") {
            let pretty = serde_json::to_string_pretty(payload).unwrap_or_default();
            return lines(&pretty);
        }
        if let Some(encoded) = body.get("payload_b64u").and_then(Value::as_str) {
            return vec![format!(
                "(encrypted or binary payload, {} base64url characters)",
                encoded.len()
            )];
        }
    }
    if let Some(content) = row.get("content").and_then(Value::as_str) {
        return lines(content);
    }
    vec!["(no content)".to_string()]
}
