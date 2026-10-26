//! `anpio-cli` — the command face.
//!
//! A shell over the `anpio_cli` library ([TODO5.md](../../../../TODO5.md)). `docs/design/cli.md`
//! §1 draws the line this binary is built to respect: **no protocol logic in the command
//! face**. Anything with ongoing state — the identity store, the MLS store, the message
//! store — lives in the library; what is here parses arguments, calls in, and renders.

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use reqwest::Url;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::Arc;

use anpio_cli::contacts::{
    ambiguous_name_error, book_from_json, looks_like_a_did, lookup, not_a_did_error,
    unknown_name_error, Contact, Lookup, RosterNames,
};
use anpio_cli::AnpioError;
use anpio_cli::group::{group_target, policy_of, service_target};
use anpio_cli::group_remarks::{book_from_json as group_remarks_from_json, GroupRemark};
use anpio_cli::group_receive::GroupReceiver;
use anpio_cli::group_e2ee::{
    add_body, create_body, get_key_package_body, publish_body, remove_body, send_body,
};
use anpio_cli::anp::login::login;
use anpio_cli::anp::{LoginError, Superseded};
use anpio_cli::custody::{document_has_key, document_keyids, split_did, AnpioKey, Operation};
use anpio_cli::identity::{
    create_identity, current_agent_path, deliver, describe_status, document_hash, document_is_superseded,
    fetch_host_service, fetch_profile, fetch_public_profile, list_identities, load_session, load_stored_key,
    parse_ttl_seconds,
    read_current_agent, register_identity, resign_document, resolve_agent_id, resolve_agent_id_with_source,
    resolve_chain, retirement_document, save_session, select_current_agent, session_host, snake_case_name, subject_of,
    successor_of, superseded_refusal_text, update_document, update_profile, without_proof, Accepted, ChainError,
    ChainResolution, Custody, Supersession,
    CreateIdentityInput, Hop, Identity, IdentityLocation, Issued, SessionWrite, UpdateError,
    DEFAULT_SESSION_TTL_SECONDS,
};
use anpio_cli::message::{
    build_message_request, call, call_device, call_extension, call_group, decode_message, device_of,
    did_host, did_to_url,
    discover, document_in_crate_form, document_url, group_e2ee_security_profile, http_client, now_rfc3339,
    open_channel, open_channel_for, parse_capabilities, payload_from, payload_of, policy_for, post_message,
    resolve_did_document, rejection, run_listen, uuid_v4, view_for, websocket_connect, AnpMeta,
    AnpResponse, AnpTarget, CallRequest, Channel, ConnectFn, ListenArgs, ListenDeps, ListenEvent,
    ResolvePolicy,
    Sender, TargetKind, CONTACTS_LIST, CONTACTS_PROFILE, CONTACTS_PUT, CONTACTS_REMOVE,
    CORE_BINDING, DELTA_PAGE, DIRECT_PROFILE, DIRECT_SEND, DID_SUPERSEDED,
    GET_CAPABILITIES, GET_KEY_PACKAGE, GROUP_CREATE, GROUP_E2EE_ADD, GROUP_E2EE_CREATE,
    GROUP_E2EE_PROFILE, GROUP_E2EE_REMOVE, GROUP_E2EE_SECURITY_PROFILE, GROUP_E2EE_SEND,
    GROUP_GET_INFO, GROUP_JOIN,
    GROUP_LEAVE, GROUP_PROFILE, GROUP_REMARKS_LIST, GROUP_REMARKS_PROFILE, GROUP_REMARKS_PUT,
    GROUP_REMARKS_REMOVE, GROUP_SEND, GROUP_UPDATE_PROFILE, INBOX_PROFILE,
    PUBLISH_KEY_PACKAGE, SYNC_DELTA, TRANSPORT_PROTECTED,
};
use anpio_cli::mls::{
    abort_commit, application_plaintext, device_signer, finalize_commit, generate_key_package,
    new_key_package_id, prepare_add, prepare_create, prepare_remove, send_message, AddInput,
    CreateInput, DeviceSigner, KEY_PACKAGE_VALID_DAYS, RemoveInput, SendInput,
};
use anpio_cli::messages::{
    records_from, Conversation, Direction, MessageStore, Record as MessageRecord, RecordingView,
    StoredMessage,
};
use anp::group_e2ee::v2_models::V2GroupKeyPackage;
use anp::group_e2ee::GROUP_CIPHER_CONTENT_TYPE;

#[derive(Parser)]
#[command(
    name = "anpio-cli",
    version,
    about = "An ANP client: identity, messaging, and group E2EE.",
    long_about = "A client for the Agent Network Protocol. It keeps its own store root and its \
                  own identity, separate from the service that hosts mailboxes for it \
                  (`docs/design/cli.md` §2, §3)."
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
    /// and `$ANPIOCLI_AGENT` stay ABOVE it, so a script that names an agent cannot be
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
    /// The application layer: the credential a peer is asked to accept.
    ///
    /// `did` is the pair of commands that talk to the server hosting the DID; this is the
    /// identity as a relying party sees it, which is a different question with a different
    /// answer — the stable *subject* outlives the *DID* that a key update replaces.
    Anp {
        #[command(subcommand)]
        command: AnpCommand,
    },
    /// Names for DIDs, so a message can be addressed to a person rather than a string
    /// (TODO6 §3).
    ///
    /// ANP addresses by DID; people, and the agents relaying for them, address by name. This
    /// family is the layer between the two, and `resolve` is the one to reach for from a
    /// script: name in, DID out.
    ///
    /// The book lives in the message service's own store, not in this machine's, so the rows
    /// follow the identity rather than the installation — and every row is keyed to the
    /// identity that wrote it, so no other identity's `contacts list` can see it.
    Contacts {
        #[command(subcommand)]
        command: ContactsCommand,
    },
    /// The host's profile for this identity: nickname, blurb, avatar.
    ///
    /// Not part of ANP — the protocol has no display name — so this family is the host's
    /// own surface, and it is the only thing the cached bearer token is read back for
    /// besides `did publish`.
    Me {
        #[command(subcommand)]
        command: MeCommand,
    },
    /// The version of this binary.
    ///
    /// The word form, next to `--version` / `-V`: a script that runs `anpio-cli version`
    /// should not have to know which of the two this client spells.
    Version {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AnpCommand {
    /// Show this identity as the application layer sees it.
    ///
    /// Contacts nothing: this is the store's own record. What it adds over `did show` is the
    /// pair of names a key update separates — the stable `subject` and the current `did` —
    /// plus the keyid a signature would be made under, which is what a peer will look for.
    Show {
        /// Print the whole record, DID document included.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Sign one ANP-02 request and print it, without sending anything.
    ///
    /// The output is the whole request: the flat ANP-02 body, the RFC 9421 headers that sign
    /// it, and the DID document the peer will verify against. It is the offline answer to
    /// "what would this identity put on the wire" — the body is what the signature covers,
    /// so anything a target adds to it is a target-specific field, not this client's.
    Sign {
        /// The full URL of the endpoint being signed for, e.g.
        /// `https://site.example/api/anp/verify`.
        #[arg(long, value_name = "URI")]
        target: String,
        /// The HTTP method the signature covers.
        #[arg(long, value_name = "VERB", default_value = "POST")]
        method: String,
        /// A server-issued one-time nonce. Empty asks the target to challenge instead.
        #[arg(long, default_value = "")]
        nonce: String,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Log in to an application server: sign one ANP-02 request, POST it, and take back the
    /// credential the server issues.
    ///
    /// The request is the one `anp sign` prints, sent instead of displayed, so what goes out is
    /// the same object either way. A 401 challenge is answered once, with the nonce the server
    /// names. A 409 `did_superseded` is a **conclusion** about this identity rather than a
    /// rejected proof, so it is reported as one and the chain is walked to say which DID is
    /// current — the peer's own hint is never acted on (ANP-03 §3.2).
    Login {
        /// The full URL of the login endpoint, e.g. `https://site.example/api/anp/login`.
        #[arg(long, value_name = "URI")]
        target: String,
        /// A server-issued one-time nonce. Empty asks the target to challenge instead.
        #[arg(long, default_value = "")]
        nonce: String,
        /// Keep the token for at most this long: `7d`, `24h`, `30m`, or bare seconds. The
        /// server's own expiry wins whenever it is shorter.
        #[arg(long, value_name = "SPEC")]
        session_ttl: Option<String>,
        /// Print the token but do not cache it.
        #[arg(long)]
        no_save_session: bool,
        /// Print the whole outcome as JSON, token included.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
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
        /// Unlike the other subcommands this one does NOT consult `$ANPIOCLI_AGENT` or
        /// the current agent: `create` names a NEW identity, and who happens to be
        /// selected must not decide where a second one is written. Left out, the handle
        /// is used.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        profile: Option<String>,
    },
    /// Attach an identity whose key is held by an `anpio-key` daemon.
    ///
    /// The DID document comes from the daemon, not from a local key: this store keeps no
    /// private bytes for such an identity. The ANP-02 commands (`anp sign`, `anp login`)
    /// and the host's document surface work; message, group and DID-update commands need
    /// signatures `anpio-key` does not make, and refuse by name.
    AttachAnpioKey {
        /// The DID whose key anpio-key holds (`did:wba:…:e1_…`).
        #[arg(long)]
        did: String,
        /// anpio-key's key directory (`--root`), when it is not `~/.anpio-key`.
        #[arg(long, value_name = "DIR")]
        key_root: Option<PathBuf>,
        /// anpio-key's socket, when it is not the one derived from the key directory.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// The key fragment (`key-1`, `recovery-1`, …); the daemon's default key if omitted.
        #[arg(long)]
        kid: Option<String>,
        /// anpio-key's protected v2 surface (`data --config`), an administrator-owned file.
        ///
        /// Mutually exclusive with `--key-root` / `--socket`: one identity points at one
        /// surface, so a command can never choose between them at signing time.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["key_root", "socket"])]
        config: Option<PathBuf>,
        /// The grant this identity signs under, issued by the anpio-key administrator.
        #[arg(long, requires = "config")]
        grant: Option<String>,
        /// This machine's device name in the DID document (`{device}-sign`,
        /// `{device}-agreement`), for the paths that sign as a device (group E2EE).
        ///
        /// Left out, those paths refuse and say so: the local `{agent}/{profile}` is not a
        /// device name, and mapping one to the other would point at a key the document may
        /// not publish.
        #[arg(long, value_name = "ID")]
        device: Option<String>,
        /// The DID host's URL, when the DID's authority is not the host to publish to.
        #[arg(long)]
        host: Option<String>,
        /// The local agent name; the DID's handle if omitted.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        /// Replace an identity already stored under this agent/profile.
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show the identity on file.
    Show {
        /// `--agent` > `$ANPIOCLI_AGENT` > the current agent > `default`.
        #[arg(long)]
        agent: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        /// Print the whole thing, DID document included.
        #[arg(long)]
        json: bool,
    },
    /// Every identity this machine holds, and what each one is bound to.
    ///
    /// Not `agent list`, although both read the same directories. `agent list` answers the
    /// *selection* question — which agent is in force, and how that was decided — while this
    /// answers the *identity* question: which DIDs exist here, and which of them never got
    /// one. `cli.md` §3.1 keeps both, and the difference is the third column below.
    List {
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
    /// Re-publish a document that changed, over the host's authenticated control plane.
    ///
    /// The difference from `register` is not cosmetic. `register` is unauthenticated and
    /// one-shot: it carries the signed document and, on a DID already on file, is refused
    /// as `did_already_registered`. So the two cases that actually happen in practice — a
    /// `register` whose *response* was lost (the host has the DID, the client does not know
    /// it succeeded) and a local document that changed after it was published — have no
    /// path through `register` at all. They have this one.
    ///
    /// It authenticates with the **bearer token** `register` (or `anp login`) left in
    /// `session.json`, because that is what the host's `update_document` accepts; and it
    /// passes the host the hash of the document it is currently serving as a CAS, so a
    /// document that moved under us is refused as `did_document_changed` rather than
    /// silently overwritten.
    Publish {
        /// Print the served document and its new version as JSON.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Retire this identity's DID in favour of a successor key (ANP-03 §2.5.3).
    ///
    /// Three steps, in this order: the successor key is minted and **staged** before anything
    /// is sent; the hop is delivered to the DID server's own update endpoint; and only once
    /// that server accepts does the store move. Staging is what makes a crash survivable —
    /// between "the server accepted" and "the store moved", that file is the only copy of the
    /// key the DID has been moved to.
    ///
    /// A delivery whose outcome cannot be known (a dropped connection, a timeout) keeps the
    /// staged key and says so; `--resume` settles that case by asking the server which DID it
    /// serves as current.
    Update {
        /// The DID server's own update endpoint.
        ///
        /// Required unless `--resume`: ANP-03 §2.5.3 defines no management interface, so where
        /// a hop goes is the server's contract and cannot be derived here.
        #[arg(long, value_name = "URI")]
        target: Option<String>,
        /// Settle an update whose delivery outcome is unknown.
        ///
        /// Resolves this identity's chain and asks which DID the server now serves: the
        /// staged successor means the hop landed, the old DID means it never did, and a third
        /// DID means something else moved this identity on — in which case nothing is touched.
        #[arg(long)]
        resume: bool,
        /// Print the two DIDs and what accepted the hop, as JSON
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
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

/// The host's user profile: the nickname and blurb a chat client puts next to a DID.
///
/// This is **the host's** surface, not the protocol's. ANP defines identity (a DID, a
/// stable subject, the keys that prove them) and leaves display names to the application —
/// `docs/design/groups.md` has no per-member nickname anywhere, and the only name a group
/// itself carries is `group_profile.display_name`, which is a *group's* name and is changed
/// through `group.update_profile`. So this family is where "昵称 / 备注" actually live, and
/// they live per DID, on the service that hosts it.
///
/// Every method here authenticates with the cached bearer token rather than an ANP
/// signature: it is the host's own control plane, and `get_me` / `update_me` are what it
/// accepts.
#[derive(Subcommand)]
enum MeCommand {
    /// The profile the host holds for this identity, plus the document it serves.
    Show {
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Change one or more profile fields and print the profile as the host now holds it.
    Set {
        /// The display name — the nickname a chat client shows. `display_name` on the host.
        #[arg(long, value_name = "TEXT")]
        name: Option<String>,
        /// A short blurb. The host calls this `description`.
        #[arg(long, value_name = "TEXT")]
        bio: Option<String>,
        /// An avatar URI. The host calls this `avatar_uri`.
        #[arg(long, value_name = "URI")]
        avatar: Option<String>,
        /// A profile page URI. The host calls this `profile_uri`.
        #[arg(long = "profile-url", value_name = "URI")]
        profile_url: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
}

/// The store's CURRENT agent — the id a command acts as when neither `--agent` nor
/// `$ANPIOCLI_AGENT` names one.
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
/// current agent (`anpio-cli agent use`) mean anything.
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
    /// Send one direct message to a DID or a contact name (P3 `direct.send`).
    Send {
        /// The recipient's DID, or a name from the address book (TODO6 §3). A DID-shaped
        /// argument is used as given; anything else is looked up, and a name that two
        /// contacts answer to is refused rather than guessed.
        #[arg(long, value_name = "DID|NAME")]
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
    /// Show what this identity has, newest first — read from the local store.
    ///
    /// Reads `messages.db`, **not the service**: this answers with the network down
    /// (client-messages.md §8.1). It is the same question `msg inbox` has always asked, with
    /// the subject changed from "what does the service hold" to "what do I have" — what the
    /// service still holds and this device does not is what `msg fetch` is for.
    Inbox {
        /// How many rows to show (default 20).
        #[arg(long, value_name = "N")]
        limit: Option<String>,
        /// Only the ones not read yet. Read state is local (client-messages.md §4), so this
        /// needs no network either.
        #[arg(long)]
        unread: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Show one conversation, oldest first — read from the local store.
    ///
    /// A conversation and an inbox are two questions: `msg inbox` is every conversation on one
    /// timeline, this is a single thread in the order it was said. Neither goes online.
    History {
        /// The other end: a DID, never a name. Names live in the service's address book, and
        /// resolving one here would make a read go online (client-messages.md §8.2) — use
        /// `contacts resolve` first if you have a name.
        #[arg(value_name = "PEER_DID")]
        peer_did: String,
        /// How many of the newest rows to show (default 20).
        #[arg(long, value_name = "N")]
        limit: Option<String>,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Show one message by id — read from the local store.
    Show {
        #[arg(value_name = "MESSAGE_ID")]
        message_id: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Mark messages as read — a local write.
    ///
    /// Read state has one home, this device's `messages.db` (client-messages.md §4,
    /// 2026-10-03), so this is not a service call and works offline.
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
    /// Bring what the service still holds into the local store.
    ///
    /// **The one read command that goes online**, and it is a *write*: it lands the delivery
    /// frames this device has not applied and moves the local cursor with them, through the
    /// same `MessageStore::record` the listener uses (client-messages.md §8.3). Called twice it
    /// changes nothing the second time, and with no `--since` it resumes where this device
    /// stopped. What it cannot bring back — a delivery the service has dropped, or a P6 frame
    /// whose device-queue entry expired — it cannot bring back, and says so.
    Fetch {
        /// Start from this delivery number instead of the stored cursor. A debugging
        /// override; the ordinary call resumes where this device stopped.
        #[arg(long, value_name = "SEQ")]
        since: Option<u64>,
        /// How many to ask for per page (default 100).
        #[arg(long, value_name = "N")]
        limit: Option<String>,
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
    /// Every message it consumes is also written to the local store (`messages.db`,
    /// client-messages.md), because the plaintext of an E2EE group message has no other
    /// home. The *delivery cursor* is not local: it lives on the service, per
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
        /// Confirm each message as it is printed: `stream.ack` (this device's cursor) here,
        /// and the local row is marked read. Off by default — an unconfirmed message is
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
enum ContactsCommand {
    /// Every contact this identity has, ordered by subject.
    List {
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Put a DID in the book, or change the name it is already filed under.
    ///
    /// Adding and renaming are one operation because they are one row: the key is the peer's
    /// stable subject, derived from the DID, so a second `add` for the same person lands on
    /// the existing entry instead of creating a duplicate.
    ///
    /// Without `--remark`, an entry that already has a name keeps it. The wire's own rule is
    /// "absent means clear", so the client has to be the one to decide otherwise — and
    /// `add <did>` run twice must not quietly erase the name the first run gave.
    Add {
        /// The peer's DID. Not a name — the name is what `--remark` is for.
        #[arg(value_name = "DID")]
        did: String,
        /// What to call them. Left out, a new entry has no name: usable by DID, and waiting
        /// for one.
        #[arg(long, value_name = "NAME")]
        remark: Option<String>,
        /// Drop the name and keep the entry. The explicit form of what an absent `--remark`
        /// deliberately does not do.
        #[arg(long = "clear-remark", conflicts_with = "remark")]
        clear_remark: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Rename a contact: the same row, a new remark.
    ///
    /// Takes a name or a DID, resolving a name the same way `msg send --to` does — so a name
    /// that two contacts answer to is refused here too, rather than renaming the wrong one.
    SetRemark {
        /// The name to rename, or the DID.
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(value_name = "REMARK")]
        remark: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Take a contact out of the book. A name or a DID, as in `set-remark`.
    Remove {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Turn a name into a DID. Name in, DID out, and nothing else on stdout.
    ///
    /// This is the one to call from an agent: the answer is a single line a script can use as
    /// `msg send --to`, and a name that does not resolve is an error rather than an empty
    /// result. A DID passed in comes back unchanged — the text form is its own answer, and
    /// `--json` says so with `"source": "argument"`.
    Resolve {
        #[arg(value_name = "NAME")]
        name: String,
        /// The whole row instead of the bare DID, for a caller that wants the subject too.
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
    ///
    /// Names come from the address book (`contacts.list`, TODO6 §3), so a member already in
    /// the book prints as the remark you gave them — that costs one extra round trip and no
    /// per-member fetch. `--names` additionally asks each of the remaining members' own DID
    /// host for the name they chose for themselves (TODO6 §4.2 ①), which is one request per
    /// unnamed member. A host that does not answer leaves that member printed as their DID:
    /// the route is awiki's own and not ANP's, so "no name" is a normal answer here.
    ///
    /// `--json` prints the service's roster verbatim — names belong to the human rendering,
    /// the same rule `msg send --json` follows for its `named:` line.
    Members {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        #[arg(long)]
        names: bool,
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
    /// Rename a group (P4 `group.update_profile`, §7.4 / §8.7.2).
    ///
    /// The name a group carries is `group_profile.display_name`, and this is the only method
    /// that writes it. The patch is RFC 7386 (merge, not replace), so fields left out stay
    /// as they are — there is no way to blank a name with this command, which is deliberate:
    /// a group with no name is a group a chat client cannot label.
    UpdateProfile {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// The new `display_name`. Required: this command exists to change the name, and a
        /// call that changed nothing would still consume a state version on the service.
        #[arg(long, value_name = "NAME")]
        name: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        own: OwnIdentity,
    },
    /// Name a group, as you call it — or drop the name.
    ///
    /// Not the group's own name: that is `group_profile.display_name`, set by
    /// `group update-profile`, and every member sees it. This is the opposite — the name only
    /// you see, which the protocol has no place for and ought not, since it is your memory
    /// rather than a fact about the group (TODO6 §4.2).
    ///
    /// It lives beside the address book, in the service's own store, partitioned by the
    /// verified signer, so one identity's names are invisible to another's — and it is a
    /// different book from the address book, because a contact is something `msg send --to`
    /// can reach and a group is not.
    ///
    /// `group info` prints it back as `remark:`. `--clear` forgets it: a name is the only
    /// thing this stores, so there is no row left behind to keep.
    SetRemark {
        #[arg(value_name = "GROUP_DID")]
        group_did: String,
        /// What to call the group.
        #[arg(value_name = "REMARK", required_unless_present = "clear")]
        remark: Option<String>,
        /// Forget the name. The explicit form of the other half of this command.
        #[arg(long, conflicts_with = "remark")]
        clear: bool,
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
            default_value_t = anpio_cli::mls::KEY_PACKAGE_VALID_DAYS
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
            DidCommand::AttachAnpioKey {
                did,
                key_root,
                socket,
                kid,
                config,
                grant,
                device,
                host,
                agent,
                profile,
                force,
                json,
            } => cmd_did_attach_anpio_key(
                &did,
                key_root,
                socket,
                kid.as_deref(),
                config,
                grant,
                device.as_deref(),
                host.as_deref(),
                agent.as_deref(),
                profile.as_deref(),
                force,
                json,
            ),
            DidCommand::Show {
                agent,
                profile,
                json,
            } => cmd_did_show(agent.as_deref(), profile.as_deref(), json),
            DidCommand::List { json } => cmd_did_list(json),
            DidCommand::Register { agent, profile } => cmd_did_register(agent.as_deref(), profile.as_deref()).await,
            DidCommand::Publish { json, own } => cmd_did_publish(json, &own).await,
            DidCommand::Resolve { did, chain, json } => cmd_did_resolve(&did, chain, json, &allow_private).await,
            DidCommand::Update {
                target,
                resume,
                json,
                own,
            } => {
                cmd_did_update(
                    target.as_deref(),
                    resume,
                    json,
                    own.agent.as_deref(),
                    own.profile.as_deref(),
                    &allow_private,
                )
                .await
            }
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
                unread,
                json,
                own,
            } => cmd_msg_inbox(&own, limit, unread, json),
            MsgCommand::History {
                peer_did,
                limit,
                json,
                own,
            } => cmd_msg_history(&own, &peer_did, limit, json),
            MsgCommand::Show {
                message_id,
                json,
                own,
            } => cmd_msg_show(&own, &message_id, json),
            MsgCommand::Read {
                message_ids,
                all,
                json,
                own,
            } => cmd_msg_read(&own, message_ids, all, json),
            MsgCommand::Fetch {
                since,
                limit,
                json,
                own,
            } => cmd_msg_fetch(&own, since, limit, json, &allow_private).await,
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
        Command::Contacts { command } => match command {
            ContactsCommand::List { json, own } => cmd_contacts_list(&own, json, &allow_private).await,
            ContactsCommand::Add { did, remark, clear_remark, json, own } => {
                cmd_contacts_add(&own, &did, remark, clear_remark, json, &allow_private).await
            }
            ContactsCommand::SetRemark { name, remark, json, own } => {
                cmd_contacts_set_remark(&own, &name, &remark, json, &allow_private).await
            }
            ContactsCommand::Remove { name, json, own } => {
                cmd_contacts_remove(&own, &name, json, &allow_private).await
            }
            ContactsCommand::Resolve { name, json, own } => {
                cmd_contacts_resolve(&own, &name, json, &allow_private).await
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
            } => cmd_group_info(&own, &group_did, false, false, json, &allow_private).await,
            GroupCommand::Members {
                group_did,
                names,
                json,
                own,
            } => cmd_group_info(&own, &group_did, true, names, json, &allow_private).await,
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
            GroupCommand::UpdateProfile {
                group_did,
                name,
                json,
                own,
            } => cmd_group_update_profile(&own, &group_did, &name, json, &allow_private).await,
            GroupCommand::SetRemark {
                group_did,
                remark,
                clear,
                json,
                own,
            } => cmd_group_set_remark(&own, &group_did, remark, clear, json, &allow_private).await,
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
        Command::Anp { command } => match command {
            AnpCommand::Show { json, own } => cmd_anp_show(&own, json),
            AnpCommand::Sign {
                target,
                method,
                nonce,
                own,
            } => cmd_anp_sign(&own, &target, &method, &nonce),
            AnpCommand::Login {
                target,
                nonce,
                session_ttl,
                no_save_session,
                json,
                own,
            } => {
                cmd_anp_login(
                    &own,
                    &target,
                    &nonce,
                    session_ttl.as_deref(),
                    no_save_session,
                    json,
                    &allow_private,
                )
                .await
            }
        },
        Command::Me { command } => match command {
            MeCommand::Show { json, own } => cmd_me_show(json, &own).await,
            MeCommand::Set {
                name,
                bio,
                avatar,
                profile_url,
                json,
                own,
            } => {
                cmd_me_set(
                    name.as_deref(),
                    bio.as_deref(),
                    avatar.as_deref(),
                    profile_url.as_deref(),
                    json,
                    &own,
                )
                .await
            }
        },
        // `--version` is answered by clap before dispatch, so reaching here means the word
        // was typed. Same string either way: the two spellings are one fact.
        Command::Version { json } => {
            println!(
                "{}",
                if json {
                    json!({ "version": env!("CARGO_PKG_VERSION") }).to_string()
                } else {
                    env!("CARGO_PKG_VERSION").to_string()
                }
            );
            Ok(())
        }
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
        &format!("anpiocli-discover-{}", std::process::id()),
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
    // through `$ANPIOCLI_PROFILE`, because a profile is not part of the address.
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
        Ok(issued) => {
            // The host hands back a bearer token with the acceptance, and that is the only
            // credential its own control plane (`update_document`, `me`) accepts — the ANP
            // request path signs instead. The reply that carries it is this one, so it is
            // cached here, next to where `anp login` caches the one it gets.
            match cache_issued_token(&location, &identity, &issued) {
                Ok(true) => println!("token:   cached in {}", location.session_path().display()),
                Ok(false) => {}
                Err(err) => eprintln!("warning: could not cache the access token: {err:#}"),
            }
            println!("registered with {host} as {handle}");
        }
        Err(err) => {
            // The keys are already on disk; a failed publish is retryable and must not
            // look like a failed create.
            eprintln!("the identity was saved, but publishing it failed: {err:#}");
            eprintln!("retry with: anpio-cli did register --agent {}", location.agent);
            return Err(err);
        }
    }
    println!("next:    anpio-cli did show --agent {}", location.agent);
    Ok(())
}

/// `did attach-anpio-key` — adopt a DID whose key lives in an `anpio-key` daemon.
///
/// This is the only way an identity enters the store without private bytes: the daemon
/// holds the key, publishes the document, and signs ANP-02 requests on request. Everything
/// that needs the key *here* — an origin proof, an MLS device key, a DID-document proof —
/// is refused by [`Custody::refuse`] at the command that would have needed it.
///
/// The identity is created only after the daemon answers with a document naming this DID
/// and carrying the key to be used, so a half-attached identity cannot be written: either
/// the daemon holds the key, or the store is untouched.
fn cmd_did_attach_anpio_key(
    did: &str,
    key_root: Option<PathBuf>,
    socket: Option<PathBuf>,
    kid: Option<&str>,
    config: Option<PathBuf>,
    grant: Option<String>,
    device: Option<&str>,
    host: Option<&str>,
    agent: Option<&str>,
    profile: Option<&str>,
    force: bool,
    json: bool,
) -> anyhow::Result<()> {
    let parts = split_did(did).ok_or_else(|| {
        anyhow::anyhow!(
            "{did} is not a did:wba E1 DID (did:wba:<authority>:user:<handle>:e1_<fingerprint>); \
             anpio-key holds Ed25519 keys under that profile"
        )
    })?;

    // The flag names a fragment; a caller who pasted a whole `did#key-1` is understood
    // rather than refused, because that is what anpio-key's own `list` prints.
    let kid = kid.map(|value| value.rsplit('#').next().unwrap_or(value).to_string());
    let mut key = AnpioKey {
        root: key_root,
        socket,
        kid,
        config,
        grant,
        device: device.map(str::to_string),
        ..AnpioKey::default()
    };

    // Fetching the document is the check that the daemon is reachable and actually holds
    // this DID. No key bytes are fetched, because there are none to fetch. Which entry
    // answers depends on the surface: the development socket publishes `document`, while
    // the protected one reaches it through LIST_AUTHORIZED_KEYS + GET_DOCUMENT.
    let (document, keyid) = if key.config.is_some() {
        let (document, keyid) = key.authorized_document(did)?;
        if key.grant.is_some() {
            let status = key.grant_status()?;
            if !status.usable() {
                anyhow::bail!(
                    "anpio-key reports grant {} as {} with {} of {} uses left; attaching it \
                     would produce an identity that cannot sign. Ask the administrator for a \
                     fresh grant",
                    status.grant_id,
                    status.state,
                    status.remaining_uses(),
                    status.max_uses
                );
            }
        }
        // Cache the negotiated set here so an ordinary command answers "can this identity
        // sign?" without spawning a daemon. An empty announcement (a daemon too old to have
        // the field) is cached as what it actually is: the baseline six operations. The
        // purposes are cached beside them for the paths that need a *purpose* switch
        // (`device_assertion`); an absent list stays absent, so the daemon's own refusal
        // decides rather than this client assuming the switch is off.
        let capabilities = key.capabilities()?;
        key.operations = Some(capabilities.announced_names());
        key.signing_purposes = capabilities
            .signing_purposes()
            .map(|purposes| purposes.into_iter().map(str::to_string).collect());
        (document, keyid)
    } else {
        let document = key.document(did)?;
        let keyid = key.resolved_keyid(&document, did);
        (document, keyid)
    };
    if !document_has_key(&document, &keyid) {
        let available = document_keyids(&document);
        anyhow::bail!(
            "anpio-key has no key {keyid} for {did}; the document publishes {}",
            if available.is_empty() {
                "no verification methods".to_string()
            } else {
                available.join(", ")
            }
        );
    }

    // A device binding is only stored once the document shows the key it names. Two
    // spellings are accepted because both are things a person pastes — the device name and
    // the whole fragment — and the document decides which one it is, so neither is a guess.
    if let Some(given) = key.device.clone() {
        let bare = given.rsplit('#').next().unwrap_or(&given).to_string();
        let candidates = [
            bare.clone(),
            bare.trim_end_matches("-sign").to_string(),
            given.clone(),
        ];
        let matched = candidates
            .into_iter()
            .find(|device| document_has_key(&document, &format!("{did}#{device}-sign")));
        let Some(device) = matched else {
            anyhow::bail!(
                "{did} publishes no {}; the document publishes {}",
                format!("{did}#{bare}-sign"),
                if document_keyids(&document).is_empty() {
                    "no verification methods".to_string()
                } else {
                    document_keyids(&document).join(", ")
                }
            );
        };
        key.device = Some(device);
    }

    // `did create` defaults the agent to the handle; so does this, and for the same reason:
    // a new identity should land under its own name, not under whatever is selected.
    let agent = agent
        .map(str::to_string)
        .unwrap_or_else(|| parts.handle.clone());
    let location = IdentityLocation::resolve(Some(&agent), profile)?;
    if location.identity_path().is_file() && !force {
        anyhow::bail!(
            "{} already holds an identity ({}). Attaching over it would discard the keys it \
             stores; pass --force if that is what you want, or --agent to attach alongside it",
            location.identity_path().display(),
            Identity::load(&location)
                .map(|identity| identity.did)
                .unwrap_or_else(|_| "unreadable".to_string())
        );
    }

    let identity = Identity {
        did: did.to_string(),
        device_id: format!("{}/{}", location.agent, location.profile),
        agent: location.agent.clone(),
        profile: location.profile.clone(),
        handle: parts.handle.clone(),
        // The host URL is only for the host's own control plane (`register`, `publish`,
        // `me`); signing never uses it. A DID carries an authority, not a scheme, so a
        // default is derivable and `--host` overrides it.
        did_host: host
            .map(str::to_string)
            .unwrap_or_else(|| parts.default_host()),
        created_at: chrono::Utc::now().to_rfc3339(),
        keys: std::collections::BTreeMap::new(),
        did_document: document.clone(),
        custody: Some(Custody::AnpioKey(key)),
    };
    identity.save(&location)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "agent": location.agent,
                "profile": location.profile,
                "did": identity.did,
                "keyid": keyid,
                "handle": identity.handle,
                "didHost": identity.did_host,
                "custody": identity.custody,
                "identityFile": location.identity_path(),
                "document": document,
            }))?
        );
        return Ok(());
    }

    println!("did:     {}", identity.did);
    println!("key:     held by anpio-key ({keyid})");
    println!("document: from anpio-key");
    println!("stored:  {}", location.identity_path().display());
    println!();
    println!("signs with: anpio-cli anp sign --nonce <nonce> --target <url>");
    println!("logs in as: anpio-cli anp login --target <url> --nonce <nonce>");
    if let Some(custody) = &identity.custody {
        let capabilities = custody.known_capabilities();
        println!("signs:      {}", capabilities.effective().join(", "));
        if capabilities.contains(Operation::OriginProof) {
            println!("msg/group:  on — origin proofs are delegated to anpio-key");
        } else {
            println!(
                "refused:    msg/group/update — this surface does not announce \
                 SIGN_ORIGIN_PROOF"
            );
        }
    }
    Ok(())
}

/// `anp show` — this identity as the application layer sees it.
///
/// The one fact this page exists for is the pair `subject` / `did`: a key update moves the
/// DID and leaves the subject where it was, so a relying party that keyed a session on the
/// former would lose the account and one that keyed it on the latter would not.
fn cmd_anp_show(own: &OwnIdentity, json: bool) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let subject = subject_of(&identity.did);
    // Which credential this identity signs under. A daemon-held key is resolved against the
    // stored document, so the answer comes from the same binding rule the daemon enforces —
    // without needing the daemon to be running just to read the field.
    let keyid = match &identity.custody {
        Some(Custody::AnpioKey(key)) => key.resolved_keyid(&identity.did_document, &identity.did),
        None => format!("{}#key-1", identity.did),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "agent": location.agent,
                "profile": location.profile,
                "subject": subject,
                "did": identity.did,
                "keyid": keyid,
                "handle": identity.handle,
                "didHost": identity.did_host,
                "deviceId": identity.device_id,
                "createdAt": identity.created_at,
                "identityFile": location.identity_path(),
                "keys": identity.keys.keys().cloned().collect::<Vec<_>>(),
                "custody": identity.custody,
                "didDocument": identity.did_document,
            }))?
        );
        return Ok(());
    }

    let line = |label: &str, value: &str| field(label, Some(&Value::String(value.to_string())));

    line("agent:", &format!("{}/{}", location.agent, location.profile));
    line("subject:", &subject);
    line("did:", &identity.did);
    line("keyid:", &keyid);
    line("handle:", &identity.handle);
    line("device:", &identity.device_id);
    match &identity.custody {
        Some(Custody::AnpioKey(key)) => line("keys:", &format!("held by {}", key.describe())),
        None => line(
            "keys:",
            &identity.keys.keys().cloned().collect::<Vec<_>>().join(", "),
        ),
    }
    line(
        "store:",
        &format!(
            "{} ({})",
            location.identity_path().display(),
            if identity.custody.is_some() || Identity::permissions_are_private(&location) {
                "mode 600"
            } else {
                "readable by others — it holds private keys; chmod 600"
            }
        ),
    );
    println!();
    println!("subject is the stable identity and survives a key update; did is the");
    println!("current wire credential and changes with the key.");
    println!();
    println!("{}", serde_json::to_string_pretty(&identity.did_document)?);
    Ok(())
}

/// `anp sign` — sign one ANP-02 request and print it. Nothing is sent.
///
/// The target is a URL and the signature covers it, so where the request is aimed is part
/// of the proof: `--target` is not decoration, and a signature made here is only usable
/// against that exact URL and method.
fn cmd_anp_sign(own: &OwnIdentity, target: &str, method: &str, nonce: &str) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let signed = anpio_cli::anp::sign(&identity, target, method, nonce)?;
    println!("{}", serde_json::to_string_pretty(&signed)?);
    Ok(())
}

/// `anp login` — the same request `anp sign` prints, sent, and the credential it comes back with.
///
/// The token is the outcome; the cache is a convenience beside it. A failed cache write is a
/// warning and never a failed login, because the token is already in hand and re-running the
/// login to fix a file would be a worse outcome than a stale file (ADR-0001 §2.5).
async fn cmd_anp_login(
    own: &OwnIdentity,
    target: &str,
    nonce: &str,
    session_ttl: Option<&str>,
    no_save_session: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    // Before the network round trip, so a typo in `--session-ttl` fails fast.
    let ttl = parse_ttl_seconds(session_ttl)?;
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    // The document and the signer come out of the identity together, so a daemon-held key
    // signs through the same call as a stored one — and the document the peer compares
    // against is the one the key belongs to, not a copy in the store.
    let signing = identity.signing()?;

    // The allowlist is the bare host, but the token is cached — and named — under the authority
    // that issued it, port included: two servers on one machine are two different issuers.
    let policy_host = target_host(target)?;
    let host = session_host(target)?;
    // Only the login endpoint's host is allowlisted: this request carries the DID document and
    // a signature over the target URL, so it goes exactly where the caller aimed it.
    let policy = policy_for(std::slice::from_ref(&policy_host), allow_private);
    let client = http_client()?;

    let outcome = match login(
        &client,
        target,
        &policy,
        &identity,
        &signing.signer,
        &signing.document,
        nonce,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(LoginError::Superseded(hint)) => {
            return report_superseded(&client, &location, &identity, &hint, allow_private).await
        }
        Err(LoginError::Refused(err)) => return Err(err),
    };

    let written = match (outcome.token.as_deref(), no_save_session) {
        (Some(token), false) => {
            match save_session(
                &location,
                &host,
                token,
                &outcome.did,
                Some(&outcome.subject),
                outcome.token_type.as_deref(),
                ttl,
            ) {
                Ok(()) => SessionWrite::Saved,
                Err(err) => {
                    eprintln!(
                        "anpio-cli: warning: could not save the session ({err:#}). The token below is the only copy."
                    );
                    SessionWrite::Failed
                }
            }
        }
        _ => SessionWrite::Skipped,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "host": host,
                "subject": outcome.subject,
                "did": outcome.did,
                "token": outcome.token,
                "tokenType": outcome.token_type,
                "docUrl": outcome.doc_url,
                "session": session_word(written),
                "sessionFile": location.session_path(),
            }))?
        );
        return Ok(());
    }

    let line = |label: &str, value: &str| field(label, Some(&Value::String(value.to_string())));
    println!("signed in to {host}");
    line("did:", &outcome.did);
    line("subject:", &outcome.subject);
    match outcome.token.as_deref() {
        Some(token) => line("token:", token),
        None => println!("no token: the server accepted the proof and issued no credential"),
    }
    match written {
        SessionWrite::Saved => line("saved:", &location.session_path().display().to_string()),
        SessionWrite::Failed => println!("session not saved — the token above is the only copy"),
        SessionWrite::Skipped => println!("session not saved (--no-save-session)"),
    }
    // The type is the one field that says how the token must be presented, so a non-default one
    // is worth saying out loud rather than leaving for the caller to notice.
    if let Some(token_type) = outcome.token_type.as_deref() {
        if !token_type.eq_ignore_ascii_case("bearer") {
            println!(
                "note: the server named token_type \"{token_type}\" — present this token the way that \
                 profile requires, not as a Bearer token (ANP-02 §3.2.3)"
            );
        }
    }
    Ok(())
}

/// Report a 409 `did_superseded`, with this client's own conclusion attached.
///
/// The peer's two DIDs are a hint (§3.2), so the walk is what decides: it is the same chain
/// resolution `did resolve --chain` does, and it answers the one question this login cannot —
/// whether the DID really moved, and to what. Nothing is retried: a retry would have to sign as
/// the successor, and this store holds that key only if the update was run here.
///
/// The exit code stays `1`: `docs/design/cli.md` §7 reserves `2` / `3` for `did resolve`, and
/// widening that contract is a decision about the whole command face rather than one login.
async fn report_superseded(
    client: &reqwest::Client,
    location: &IdentityLocation,
    identity: &Identity,
    hint: &Superseded,
    allow_private: &[String],
) -> anyhow::Result<()> {
    println!("did_superseded: the server refused {} as no longer current", hint.requested_did);
    if let Some(claimed) = hint.claimed_current_did.as_deref() {
        println!("the server says: {claimed} (a hint, not a verified fact — ANP-03 §3.2)");
    }

    let policy = policy_for(&[did_host(&identity.did)?], allow_private);
    match resolve_chain(client, &identity.did, &policy).await {
        Ok(chain) => {
            println!("current did:    {}", chain.result.current_did);
            println!(
                "assurance:      {}",
                chain
                    .result
                    .assurance
                    .map(|value| snake_case_name(&value))
                    .unwrap_or_else(|| "none (no hops)".to_string())
            );
            println!(
                "detail:         anpio-cli did resolve {} --chain",
                identity.did
            );
        }
        Err(ChainError::Broken(err)) => {
            eprintln!(
                "anpio-cli: did_chain_broken: {}: {}",
                snake_case_name(&err.kind),
                err.message
            );
            eprintln!(
                "anpio-cli: the DID is reported as superseded AND its chain does not verify; \
                 the staged key, if any, is at {}",
                location.successor_path().display()
            );
        }
        Err(ChainError::Unavailable(err)) => {
            eprintln!("anpio-cli: warning: could not walk the chain to check: {err:#}");
        }
    }
    anyhow::bail!("login_failed: the DID this store signs with is superseded")
}

/// What happened to the token cache, as one word — the same three the TS client's stream uses,
/// so a machine reading either client's `--json` sees the same vocabulary.
fn session_word(written: SessionWrite) -> &'static str {
    match written {
        SessionWrite::Saved => "saved",
        SessionWrite::Skipped => "skipped",
        SessionWrite::Failed => "failed",
    }
}

fn cmd_did_show(agent: Option<&str>, profile: Option<&str>, json: bool) -> anyhow::Result<()> {
    let location = IdentityLocation::resolve(agent, profile)?;
    let identity = Identity::load(&location)?;
    if json {
        let mut value = serde_json::to_value(&identity)?;
        if let Some(custody) = &identity.custody {
            value["capabilities"] = capability_view(custody);
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("did:        {}", identity.did);
        println!("device:     {}", identity.device_id);
        println!("handle:     {}", identity.handle);
        println!("host:       {}", identity.did_host);
        println!("created:    {}", identity.created_at);
        match &identity.custody {
            // No key names to list: the point of custody is that there are no key bytes here
            // to name. What the line can say is which daemon holds the key, and which proofs
            // this build can actually ask it for.
            Some(Custody::AnpioKey(key)) => {
                println!("key:        held by {}", key.describe());
                match key.capabilities() {
                    Ok(capabilities) => {
                        let effective = capabilities.effective();
                        println!(
                            "signs:      {}",
                            if effective.is_empty() {
                                "nothing this build delegates".to_string()
                            } else {
                                effective.join(", ")
                            }
                        );
                        let announced = capabilities.announced_not_effective();
                        if !announced.is_empty() {
                            println!(
                                "daemon:     also announces {} (this build does not use it yet)",
                                announced.join(", ")
                            );
                        }
                    }
                    Err(err) => println!("signs:      unknown ({err:#})"),
                }
            }
            None => println!(
                "keys:       {}",
                identity.keys.keys().cloned().collect::<Vec<_>>().join(", ")
            ),
        }
        println!("document:   {} characters signed", serde_json::to_string(&identity.did_document)?.len());
        if identity.custody.is_none() && !Identity::permissions_are_private(&location) {
            eprintln!(
                "warning: {} is readable by others; it holds private keys (chmod 600)",
                location.identity_path().display()
            );
        }
    }
    Ok(())
}

/// What a custody can delegate, for `did show --json`.
///
/// Negotiation can fail (daemon stopped, config unreadable); the answer then reports the
/// cached view with an `error` rather than turning a read-only command into a failure.
fn capability_view(custody: &Custody) -> Value {
    match custody.capabilities() {
        Ok(capabilities) => json!({
            "operations": capabilities.effective(),
            "announced": capabilities.announced_operations(),
            "source": capabilities.source().name(),
        }),
        Err(err) => {
            let known = custody.known_capabilities();
            json!({
                "operations": known.effective(),
                "announced": known.announced_operations(),
                "source": known.source().name(),
                "error": format!("{err:#}"),
            })
        }
    }
}

/// `anpio-cli did list` — every identity this machine holds, and what it is bound to.
///
/// The third column is the whole reason this is not `agent list`: an identity whose `did
/// create` wrote keys and whose registration then failed has a directory and no DID, and
/// that row is precisely the one worth seeing. Printing it as an empty column, or skipping
/// it, would hide the thing the caller came here to find.
///
/// No curve column, unlike the TS client's `did list`: `curve` is a choice there (`--curve
/// ed25519|secp256k1`) and a constant here — the Rust client's binding key is always the
/// Ed25519 one a `did:wba` `e1_` fingerprint names. A column that is the same on every row
/// is noise, not information.
fn cmd_did_list(json: bool) -> anyhow::Result<()> {
    let identities = list_identities()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&identities)?);
        return Ok(());
    }
    if identities.is_empty() {
        println!("No identities are stored. Run: anpio-cli did create");
        return Ok(());
    }
    for entry in &identities {
        // `did` is absent both for the never-registered identity and for one whose file
        // could not be read, and the two want different fixes — but neither is a DID, so
        // the column says "not registered" and the path beside it is what disambiguates.
        let named = entry.did.as_deref().unwrap_or("not registered");
        println!("{}/{}  {}  {}", entry.agent, entry.profile, named, entry.dir.display());
    }
    Ok(())
}

async fn cmd_did_register(agent: Option<&str>, profile: Option<&str>) -> anyhow::Result<()> {
    let location = IdentityLocation::resolve(agent, profile)?;
    let identity = Identity::load(&location)?;
    // Registration publishes the document. For an `anpio-key` identity that document lives in
    // the daemon, so it is read on the way in rather than from the snapshot `did attach-anpio-key`
    // wrote — a key rotated since then would otherwise be registered as somebody else's.
    let identity = match &identity.custody {
        Some(Custody::AnpioKey(key)) => Identity {
            did_document: key.document(&identity.did)?,
            ..identity
        },
        _ => identity,
    };
    let base = Url::parse(&identity.did_host)
        .map_err(|err| anyhow::anyhow!("the stored host is not a URL: {err}"))?;
    let client = http_client()?;
    let issued = register_identity(&client, &base, &identity).await?;
    // Same credential, same place as `did create`: a re-register is one of the two ways the
    // token ever gets into the cache in the first place.
    match cache_issued_token(&location, &identity, &issued) {
        Ok(true) => println!("token:   cached in {}", location.session_path().display()),
        Ok(false) => {}
        Err(err) => eprintln!("warning: could not cache the access token: {err:#}"),
    }
    println!("registered {} with {}", identity.did, identity.did_host);
    Ok(())
}

/// Put the bearer token a host issued into the session cache.
///
/// Returns whether there was one to cache: `register` issues a token, `update_document` does
/// not, and a caller that already holds one keeps it. A failure here is returned rather than
/// swallowed so the caller can warn — but it is never fatal, because the token is in hand
/// either way and the cache is only a place to keep it.
fn cache_issued_token(
    location: &IdentityLocation,
    identity: &Identity,
    issued: &Issued,
) -> anyhow::Result<bool> {
    let Some(token) = issued.token.as_deref() else {
        return Ok(false);
    };
    let host = session_host(&identity.did_host)?;
    let subject = subject_of(&identity.did);
    save_session(
        location,
        &host,
        token,
        &identity.did,
        Some(&subject),
        issued.token_type.as_deref(),
        DEFAULT_SESSION_TTL_SECONDS,
    )?;
    Ok(true)
}

/// This identity's host, and the bearer token the host issued for it.
///
/// Both ends of the check live here rather than at each call site because both are ways a
/// cached token is *the wrong token*: it is keyed by the authority that issued it (two
/// servers on one machine are two issuers), and it was issued to one DID (a key update moves
/// the DID, and the host keys its tokens by DID). Either mismatch is a refusal from the host
/// after a round trip; catching it here turns that into a sentence saying what to run.
fn host_and_token(location: &IdentityLocation, identity: &Identity) -> anyhow::Result<(Url, String)> {
    let base = Url::parse(&identity.did_host)
        .map_err(|err| anyhow::anyhow!("the stored host is not a URL: {err}"))?;
    let host = session_host(&identity.did_host)?;
    let entry = load_session(location, &host).ok_or_else(|| {
        anyhow::anyhow!(
            "no usable access token for {host} — run `anpio-cli did register --agent {agent}` \
             or `anpio-cli anp login --target {target}`",
            agent = location.agent,
            target = identity.did_host,
        )
    })?;
    if entry.did != identity.did {
        anyhow::bail!(
            "the cached token for {host} was issued to {} but this identity is {} — a key update \
             moved the DID, so that token is for the old one; log in again",
            entry.did,
            identity.did
        );
    }
    Ok((base, entry.token))
}

/// `did publish` — make the host serve what this store holds, over its authenticated plane.
///
/// Three steps, and the middle one is the point: read what the host serves (`get_me`, which
/// hands back the document and its version), hash **that** as the compare-and-swap value,
/// then `update_document` with it. Hashing the local document instead would be the easy
/// mistake and it fails every time — the host compares the CAS against what it stores, so a
/// digest of anything else can only ever be a mismatch, and every publish would come back
/// `did_document_changed`.
///
/// The document that goes out is **re-proved** with key-1 first, because an edit to a DID
/// document invalidates its proof and the host re-verifies (`did_document_proof_invalid`).
/// So the two cases this command exists for — a `register` whose response was lost, and a
/// document that changed here after it was published — are one operation.
///
/// Whether anything was published is read off the host's answer rather than guessed by
/// comparing documents locally: the version it reports moves only when the document it now
/// holds differs from the one it held. The local comparison that decides whether to send at
/// all ignores `proof` on both sides, since no two proofs are ever byte-equal.
async fn cmd_did_publish(json: bool, own: &OwnIdentity) -> anyhow::Result<()> {
    let location = own.location()?;
    let mut identity = Identity::load(&location)?;
    let (base, token) = host_and_token(&location, &identity)?;
    let client = http_client()?;

    let before = fetch_profile(&client, &base, &token).await?;
    let served = before
        .get("did_document")
        .ok_or_else(|| anyhow::anyhow!("the host's profile carried no did_document"))?;
    let version_before = before.get("document_version").and_then(Value::as_u64);
    let expected = document_hash(served)?;

    // Where the document to publish comes from depends on where the key is: a stored key
    // re-proves the local copy, and an `anpio-key` identity asks the daemon for the document
    // it publishes — that one is already proved, and it is the only copy the daemon's key
    // belongs to.
    let document = match &identity.custody {
        Some(Custody::AnpioKey(key)) => key.document(&identity.did)?,
        _ => {
            let key1 = load_stored_key(identity.keys.get("key-1").ok_or_else(|| {
                anyhow::anyhow!("{} has no key-1, so its document cannot be re-proved", location.identity_path().display())
            })?)?;
            resign_document(&identity.did_document, &identity.did, &key1)?
        }
    };

    // Nothing to say to the host when the only difference is the proof we just replaced. The
    // token was still worth reading back: this call is also how a lost `register` response
    // gets resolved, and getting here at all means the host has the identity.
    if without_proof(served) == without_proof(&document) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "agent": location.agent,
                    "profile": location.profile,
                    "did": identity.did,
                    "host": identity.did_host,
                    "changed": false,
                    "documentVersion": version_before,
                }))?
            );
            return Ok(());
        }
        println!("{} already serves this document", identity.did_host);
        if let Some(version) = version_before {
            println!("version: {version}");
        }
        return Ok(());
    }

    let issued = update_document(&client, &base, &token, &document, &expected).await?;
    let version_after = issued.result.get("document_version").and_then(Value::as_u64);

    // The store now holds a document whose proof no longer covers it — that is what an edit
    // does — so the re-proved document that the host just accepted is what goes back. Keeping
    // the edited one would leave the store describing something that was never published, and
    // the next signature over it would fail for a reason nothing on disk explains.
    //
    // The host's reply is the version to write, not the local `document`: the host is
    // authoritative about what it stores, and its own normalization (adding the message
    // service, say) happens before it does. When the document it was sent already carried
    // that, the two are the same object.
    if let Some(accepted) = issued.result.get("document") {
        identity.did_document = accepted.clone();
        identity.save(&location)?;
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "agent": location.agent,
                "profile": location.profile,
                "did": identity.did,
                "host": identity.did_host,
                "changed": true,
                "documentVersion": version_after,
                "document": issued.result.get("document"),
            }))?
        );
        return Ok(());
    }

    println!("published {} to {}", identity.did, identity.did_host);
    if version_after != version_before {
        match (version_before, version_after) {
            (Some(before), Some(after)) => println!("version: {before} -> {after}"),
            (_, Some(after)) => println!("version: {after}"),
            _ => println!("version: (the host did not say)"),
        }
    }
    println!("store:   {}", location.identity_path().display());
    Ok(())
}

/// `me show` — the profile the host holds for this identity.
///
/// Read with the bearer token rather than by signing, which is the whole reason the token is
/// cached: `get_me` is the host's method, and an ANP signature is not what it takes.
async fn cmd_me_show(json: bool, own: &OwnIdentity) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let (base, token) = host_and_token(&location, &identity)?;
    let client = http_client()?;
    let profile = fetch_profile(&client, &base, &token).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&profile)?);
        return Ok(());
    }
    let field = |label: &str, name: &str| {
        let value = profile.get(name).and_then(Value::as_str).unwrap_or("—");
        println!("{label:<9}{value}");
    };
    println!("{:<9}{}", "did", identity.did);
    field("handle", "handle");
    field("name", "display_name");
    field("bio", "description");
    field("avatar", "avatar_uri");
    field("profile", "profile_uri");
    Ok(())
}

/// `me set` — change profile fields and print what the host now holds.
///
/// The host's own field names are the ones sent (`display_name`, `description`, …); the flags
/// are named after what a person calls them. Only the flags given are sent, so setting the
/// nickname cannot blank the avatar — that is the host's `update_me`, which writes exactly
/// the keys it is handed.
async fn cmd_me_set(
    name: Option<&str>,
    bio: Option<&str>,
    avatar: Option<&str>,
    profile_url: Option<&str>,
    json: bool,
    own: &OwnIdentity,
) -> anyhow::Result<()> {
    let mut fields = serde_json::Map::new();
    if let Some(name) = name {
        fields.insert("display_name".to_string(), Value::String(name.to_string()));
    }
    if let Some(bio) = bio {
        fields.insert("description".to_string(), Value::String(bio.to_string()));
    }
    if let Some(avatar) = avatar {
        fields.insert("avatar_uri".to_string(), Value::String(avatar.to_string()));
    }
    if let Some(url) = profile_url {
        fields.insert("profile_uri".to_string(), Value::String(url.to_string()));
    }
    if fields.is_empty() {
        // Refused rather than sent as an empty PATCH: a call that changes nothing is
        // indistinguishable from one that failed to name the right fields.
        anyhow::bail!("nothing to set — pass at least one of --name, --bio, --avatar, --profile-url");
    }

    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let (base, token) = host_and_token(&location, &identity)?;
    let client = http_client()?;
    let profile = update_profile(&client, &base, &token, Value::Object(fields)).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&profile)?);
        return Ok(());
    }
    let display = profile
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or("(unnamed)");
    println!("updated {}: {display}", identity.did);
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
                eprintln!("anpio-cli: did_chain_broken: {}: {}", snake_case_name(&err.kind), err.message);
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

/// The host a `--target` URL names, for the allowlist. The bare host: the gate is about which
/// host may be reached, and the port picks a service on it, not a different host.
fn target_host(target: &str) -> anyhow::Result<String> {
    let url = Url::parse(target).map_err(|err| anyhow::anyhow!("--target must be a URL: {err}"))?;
    url.host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("--target {target} names no host"))
}

/// The document this hop's retirement half is built on.
///
/// Fetched rather than taken from the store, because §2.5.3 L417 retires **the document on
/// file** and the store's copy is only what this client published — a server that added a
/// `service` entry out of band would be asked to retire a document it never served. A fetch
/// that fails falls back to the local copy and says so: L411 leaves the document's other
/// content to us, so the hop is still valid, but it may be missing what the server holds.
async fn retirement_base(
    client: &reqwest::Client,
    identity: &Identity,
    policy: &ResolvePolicy,
) -> anyhow::Result<Value> {
    match resolve_did_document(client, &identity.did, policy).await {
        Ok(document) => Ok(document),
        Err(err) => {
            eprintln!(
                "anpio-cli: warning: could not read the document on file for {} ({err:#}).",
                identity.did
            );
            eprintln!(
                "anpio-cli: warning: FALLING BACK to the copy in the store — any field the DID \
                 server holds and this client cannot compose will be MISSING from this hop's \
                 retirement document."
            );
            Ok(identity.did_document.clone())
        }
    }
}

/// `did update [--target <uri>] [--resume]`.
///
/// The successor's whole lifecycle is here: minted and staged before anything leaves the
/// process, delivered, and promoted only on acceptance. What the two failure arms do with the
/// staged key is the one decision that cannot be undone — see [`UpdateError`].
async fn cmd_did_update(
    target: Option<&str>,
    resume: bool,
    json: bool,
    agent: Option<&str>,
    profile: Option<&str>,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = IdentityLocation::resolve(agent, profile)?;
    let identity = Identity::load(&location)?;

    // A hop is signed with the retiring DID's key-1 *and* the successor is minted here, so
    // both halves of it are this process's job. `--resume` is refused with it: a staged
    // successor is a key this client wrote, and an `anpio-key` identity never writes one.
    if let Some(custody) = &identity.custody {
        custody.require(Operation::DocumentProof, "did update")?;
        // Reached only once a daemon delegates document proofs; the successor still has to
        // be minted on its admin plane, and §11 has no such operation (plan §4.4).
        anyhow::bail!(
            "did update on an anpio-key identity also needs a successor key minted inside the \
             daemon; anpio-key's admin plane has no successorship operation yet, so this hop \
             cannot be completed here"
        );
    }

    if resume {
        if target.is_some() {
            anyhow::bail!(
                "--resume settles an update that was already attempted, so it takes no --target. \
                 To deliver a NEW hop, run: anpio-cli did update --target <uri>"
            );
        }
        return resume_update(&location, &identity, json, allow_private).await;
    }

    let target = target.ok_or_else(|| {
        anyhow::anyhow!(
            "missing --target: the DID server's own update endpoint. ANP-03 §2.5.3 defines no \
             management interface, so where a hop goes cannot be derived."
        )
    })?;

    // Refused, not overwritten — and this is stricter than the TS client on purpose. A staged
    // successor means a previous delivery's outcome is unknown, so that file may be the only
    // copy of the key the DID has already moved to. Staging a second one over it would destroy
    // exactly what staging exists to protect.
    if Identity::has_staged_successor(&location) {
        anyhow::bail!(
            "a successor is already staged at {}: a previous delivery's outcome is unknown, so \
             that key is kept — it may be the only copy of the key this DID has moved to. \
             Settle it first:\n  anpio-cli did update --resume",
            location.successor_path().display()
        );
    }

    let client = http_client()?;
    let did = identity.did.clone();
    let policy = policy_for(&[did_host(&did)?, target_host(target)?], allow_private);

    // The successor is minted first and needs no network, which is what lets the retirement
    // document name it.
    let successor = successor_of(&identity)?;
    let key1 = load_stored_key(identity.keys.get("key-1").ok_or_else(|| {
        anyhow::anyhow!(
            "{} has no key-1 in the store; the DID's binding key is what signs a hop",
            location.identity_path().display()
        )
    })?)?;

    let base = retirement_base(&client, &identity, &policy).await?;
    let retirement = retirement_document(&base, &did, &successor.did, &key1)?;

    // Staged BEFORE the delivery. From here on, every exit path either promotes this key or
    // deliberately keeps it.
    successor.stage_successor(&location)?;

    match deliver(
        &client,
        target,
        &policy,
        Hop {
            retiring_did: &did,
            retirement_document: &retirement,
            successor_did: &successor.did,
            successor_document: &successor.did_document,
            key1,
        },
    )
    .await
    {
        Ok(accepted) => {
            let installed = Identity::promote_staged_successor(&location)?;
            print_update(&location, &installed, &accepted, json)?;
            Ok(())
        }
        Err(UpdateError::Settled(err)) => {
            // The hop provably did not land — nothing was sent, or the server answered with an
            // error status — so the staged key has no identity to belong to. Dropping it is
            // what makes the next `--resume` ask a question that is not already settled.
            //
            // A cleanup that fails is reported and then set aside: the reason the command failed
            // is the delivery, and that is what the caller needs to see.
            if let Err(cleanup) = Identity::discard_staged_successor(&location) {
                eprintln!(
                    "anpio-cli: warning: the staged successor at {} could not be cleared \
                     ({cleanup:#}). The hop did not land, so that file is inert and can be \
                     deleted by hand.",
                    location.successor_path().display()
                );
            }
            Err(err)
        }
        Err(UpdateError::Ambiguous(err)) => {
            eprintln!(
                "anpio-cli: warning: the update delivery to {target} did not complete, and \
                 whether the server accepted it is NOT knowable from here."
            );
            eprintln!(
                "anpio-cli: warning: the successor key has been KEPT at {} (the store itself is \
                 unchanged).",
                location.successor_path().display()
            );
            eprintln!(
                "anpio-cli: warning: settle it with `anpio-cli did update --resume` — if the hop \
                 WAS accepted, that file is the only key for {}.",
                successor.did
            );
            Err(err)
        }
    }
}

/// `did update --resume` — settle an update by asking the DID server which DID it serves.
///
/// The answer comes from the server's own documents, never from the store and never from a
/// guess. Three outcomes, three different facts: the staged successor is current (the hop
/// landed), the old DID is still current (it never did), or a third DID is (something else
/// moved this identity on). The last is why an unknown answer touches nothing.
async fn resume_update(
    location: &IdentityLocation,
    identity: &Identity,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    if !Identity::has_staged_successor(location) {
        anyhow::bail!(
            "nothing to resume: there is no staged successor at {}. That file exists only between \
             `did update` starting and its outcome being settled.",
            location.successor_path().display()
        );
    }
    let staged = Identity::load_staged_successor(location)?;

    let client = http_client()?;
    // Only the identity's OWN host is allowlisted, and derived rather than flagged: the DID
    // being asked about is this store's, so nothing else needs to be reachable for the answer.
    let policy = policy_for(&[did_host(&identity.did)?], allow_private);

    let chain = match resolve_chain(&client, &identity.did, &policy).await {
        Ok(chain) => chain,
        // A broken chain is not an answer about which DID is current — it is a verdict on the
        // chain, and acting on it would mean guessing. Nothing is touched.
        Err(ChainError::Broken(err)) => anyhow::bail!(
            "did_chain_broken: {}: {}. Nothing was changed: the staged key is kept at {}.",
            snake_case_name(&err.kind),
            err.message,
            location.successor_path().display()
        ),
        Err(ChainError::Unavailable(err)) => return Err(err),
    };

    if chain.result.current_did == staged.did {
        let installed = Identity::promote_staged_successor(location)?;
        let accepted = Accepted {
            retiring_did: identity.did.clone(),
            successor_did: staged.did.clone(),
            accepted_by: "the DID server's own documents".to_string(),
        };
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "ok": true,
                    "resumed": true,
                    "agent": location.agent,
                    "profile": location.profile,
                    "retiringDid": accepted.retiring_did,
                    "currentDid": installed.did,
                    "assurance": chain.result.assurance.map(|value| snake_case_name(&value)),
                    "identityFile": location.identity_path(),
                }))?
            );
        } else {
            println!("resumed {}", installed.handle);
            println!("superseded did: {}", identity.did);
            println!("current did:    {}", installed.did);
            println!(
                "assurance:      {}",
                chain
                    .result
                    .assurance
                    .map(|value| snake_case_name(&value))
                    .unwrap_or_else(|| "none (no hops)".to_string())
            );
            println!("local:          {}/{} now signs as the successor", location.agent, location.profile);
        }
        return Ok(());
    }

    if !chain.is_superseded() {
        // The server still serves the OLD DID, so the hop was never accepted. The staged key
        // therefore has no identity to belong to, and keeping it would only make the next
        // `--resume` ask the same settled question.
        Identity::discard_staged_successor(location)?;
        anyhow::bail!(
            "update_failed: the DID server still serves {} as current, so the staged successor \
             ({}) was never published. The staged key has been dropped; retry with \
             `anpio-cli did update --target <uri>`.",
            identity.did,
            staged.did
        );
    }

    anyhow::bail!(
        "did_superseded: {} has been superseded to {}, which is NOT the staged successor {}. \
         Something else moved this DID on. Nothing was changed: the staged key is kept at {}, and \
         the store still holds the key it had.",
        identity.did,
        chain.result.current_did,
        staged.did,
        location.successor_path().display()
    )
}

/// Report an accepted hop.
///
/// Deliberately does not claim the successor is current: the server accepted the delivery, and
/// §2.5.3 defines no response body that could confirm more. Saying so — and naming the command
/// that *can* confirm it — is the difference between a report and a guess.
fn print_update(
    location: &IdentityLocation,
    installed: &Identity,
    accepted: &Accepted,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "agent": location.agent,
                "profile": location.profile,
                "retiringDid": accepted.retiring_did,
                "successorDid": accepted.successor_did,
                "acceptedBy": accepted.accepted_by,
                "identityFile": location.identity_path(),
            }))?
        );
        return Ok(());
    }
    println!("updated {}", installed.handle);
    println!("retiring did:  {}", accepted.retiring_did);
    println!("successor did: {}", accepted.successor_did);
    println!("accepted by:   {}", accepted.accepted_by);
    println!(
        "local:         {}/{} now signs as the successor (handle and creation date kept)",
        location.agent, location.profile
    );
    println!();
    println!("The DID server is the authority on whether the successor is now current; confirm with:");
    println!("  anpio-cli did resolve {} --chain", accepted.successor_did);
    Ok(())
}

// ---- agent show / use / list ----------------------------------------------------
/// `anpio-cli agent show` — which agent is in force, and which step said so.
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

/// `anpio-cli agent use <id>` — make this agent the current one.
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
            "warning: no identity is stored for agent \"{agent}\" yet; `anpio-cli agent list` \
             shows what is here. Run: anpio-cli did create"
        );
    }
    Ok(())
}

/// `anpio-cli agent list` — the identities this machine can act as, current one marked.
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
        println!("No agents are stored. Run: anpio-cli did create");
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

    // TODO6 §3.3: `--to` takes a name or a DID, and the shape of the argument decides which.
    // A DID goes straight to discovery — it is already unambiguous, and the common
    // `--to <did>` path should not pay a book round trip to be told so. Anything else is a
    // name, and only the book can turn a name into an address.
    let (to, named) = if looks_like_a_did(to) {
        (to.to_string(), None)
    } else {
        let channel = open_channel(&client, &identity, allow_private).await?;
        let book = fetch_contacts(&client, &channel).await?;
        match lookup(&book, to) {
            Lookup::One(contact) => (contact.did.clone(), Some(contact)),
            // §3.3: refusing is the point. "Send to the wrong Alice" is the most expensive
            // mistake this surface can make, and picking one of two is how it happens.
            Lookup::Ambiguous(candidates) => return Err(ambiguous_name_error(to, &candidates).into()),
            Lookup::None { .. } => return Err(unknown_name_error(to).into()),
        }
    };

    // The recipient's own document names the service that accepts its mail, so discovery is
    // per attempt and the policy is the target's, not ours.
    let endpoint = discover(&client, &to, allow_private).await?;

    // A name that resolved is not visible in the peer's answer beyond `target_did`, so the
    // resolution is printed where a human is reading. `--json` stays the peer's response
    // verbatim; a script that wants to check first runs `contacts resolve`.
    if !json {
        if let Some(contact) = &named {
            field("to:", Some(&json!(to)));
            field("named:", Some(&json!(contact.name())));
        }
    }

    // P1 §6.2.6: for a message operation the sender SHOULD make `operation_id` the
    // `message_id`, and P3 §5.5 requires a retry to keep that pair unchanged. One flag
    // therefore pins both, which is the entire reason `--operation-id` exists.
    let operation_id = requested_operation_id.unwrap_or_else(uuid_v4);
    let content_type = payload.content_type;
    // Before `payload.body` moves into the request: the local row keeps §7.4's arms apart
    // rather than storing the wire shape it sent.
    let (sent_text, sent_payload) = payload_from(&payload.body);

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
            content_type: Some(content_type.clone()),
            operation_id: Some(operation_id.clone()),
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => {
            if result.get("accepted").and_then(Value::as_bool) == Some(true) {
                record_outgoing(
                    &location,
                    &identity,
                    &endpoint.target.endpoint,
                    &device_of(&sender, None)?,
                    text_of(result.get("accepted_at")),
                    MessageRecord::outgoing(
                        Conversation::Direct {
                            peer_did: to.to_string(),
                        },
                        &sender.did,
                        &operation_id,
                        content_type,
                        sent_text,
                        sent_payload,
                    ),
                );
            }
            report_accepted(&result, json)
        }
        AnpResponse::Error { error, .. } => {
            let anp_code = error.data.as_ref().and_then(|data| data.anp_code.as_deref());
            if anp_code == Some(DID_SUPERSEDED) {
                // P1 §10.3 / P3 §5.5: the peer MUST refuse rather than retarget silently, and
                // `details.current_did` is an **unverified hint** — the caller MUST verify the
                // transition from the DID it actually asked about before acting on it, and MUST
                // rebuild every DID-bound signature, digest and encrypted context before
                // retrying. That walk is `identity/chain.rs`, the same one `did resolve --chain`
                // runs. A retry is a *fresh* `msg send --to <successor>`, which rebuilds and
                // re-signs from scratch — so this returns the successor plus the command, and
                // never re-sends on the peer's word.
                let hint = error
                    .data
                    .as_ref()
                    .and_then(|data| data.details.as_ref())
                    .and_then(|details| details.get("current_did"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                return Err(
                    superseded_refusal(&client, &to, hint.as_deref(), allow_private).await.into(),
                );
            }
            Err(rejection(DIRECT_SEND, &to, error.code, anp_code, &error.message).into())
        }
    }
}

/// What to say when a peer refuses a send with `anp.did_superseded` (P1 §10.3, P3 §5.5).
///
/// The walk is the caller's job because the peer's `details.current_did` is only a hint: it may
/// name any successor, and a request bound to the wrong DID is a message to the wrong place.
/// So this walks `to`'s chain itself and hands the verdict to
/// [`superseded_refusal_text`](anpio_cli::identity::superseded_refusal_text), which owns the wording.
async fn superseded_refusal(
    client: &reqwest::Client,
    to: &str,
    hint: Option<&str>,
    allow_private: &[String],
) -> AnpioError {
    // The policy is the *requested* DID's host: the walk starts from the document it serves, and
    // every hop after it is served by that same host.
    let policy = match did_host(to) {
        Ok(host) => policy_for(&[host], allow_private),
        Err(err) => {
            return AnpioError::MessageSendFailed(superseded_refusal_text(
                to,
                hint,
                &Supersession::Unfetched {
                    reason: format!("its host cannot even be named to verify that ({err:#})"),
                },
            ))
        }
    };

    let outcome = match resolve_chain(client, to, &policy).await {
        Ok(resolution) if resolution.is_superseded() => Supersession::Verified {
            successor: resolution.result.current_did.clone(),
        },
        Ok(_) => Supersession::StillCurrent,
        Err(ChainError::Broken(err)) => Supersession::Broken {
            kind: snake_case_name(&err.kind),
            message: err.message.clone(),
        },
        Err(ChainError::Unavailable(err)) => Supersession::Unfetched {
            reason: format!("{err:#}"),
        },
    };
    AnpioError::MessageSendFailed(superseded_refusal_text(to, hint, &outcome))
}

/// Write the row for a message this run has just sent (TODO5 §6 Phase 2, client-messages.md §3).
///
/// Called on the **success arm only**, after `accepted: true` was checked: a row for a message
/// the service refused would be a local claim the conversation does not support. A store that
/// cannot be opened or written is a **warning, not a failure** — the message *was* sent, and
/// turning a full disk into exit 1 would tell a script the opposite of what happened.
fn record_outgoing(
    location: &IdentityLocation,
    identity: &Identity,
    endpoint: &str,
    device: &str,
    accepted_at: Option<&str>,
    mut record: MessageRecord,
) {
    record.accepted_at = accepted_at.map(str::to_string);
    let outcome = MessageStore::open(location, identity, endpoint, device)
        .and_then(|mut store| store.record(&record).map(|_| ()));
    if let Err(err) = outcome {
        eprintln!("anpio-cli: not recorded in messages.db: {err}");
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

// ---- msg inbox / history / show / read: the local read family -------------------

/// Open the identity in use and resolve its own message service.
///
/// The `msg` commands that go online need exactly this pair. The read family
/// (`inbox` / `history` / `show`) deliberately does **not** call it: reading is local
/// (client-messages.md §8.1), so routing a read through here would make the one family that
/// has to answer with the network down the one that cannot.
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

/// The local record for the identity in use, opened **for reading**.
///
/// `open_read_only`, not `open`: a read has no discovered `serviceEndpoint` to key the cursor
/// with, and must not create a file that is not there. "Nothing here" is the right answer for
/// an identity that has never listened, and it is an answer — not an error (design §8.1).
fn local_store(own: &OwnIdentity) -> anyhow::Result<MessageStore> {
    Ok(MessageStore::open_read_only(&own.location()?)?)
}

/// How many rows to show. The default is the one the service-side `inbox.get` took (20), kept
/// so the two readings of this flag do not change under anyone; a local read has no
/// server-side ceiling to respect and no paging to do.
fn limit_of(raw: Option<&str>) -> anyhow::Result<u64> {
    let Some(raw) = raw else { return Ok(20) };
    match raw.parse::<u64>() {
        Ok(parsed) if parsed > 0 => Ok(parsed),
        _ => anyhow::bail!("--limit must be a positive integer (got {raw:?})"),
    }
}

/// A stored row in the shape the renderer already speaks: the service's own `inbox.get` row.
///
/// One renderer for both sources (TODO5 §7.3). A message read out of `messages.db` and the
/// same message read off the service must *look* the same, or the move to a local read would
/// have changed the output as a side effect. The keys are the service's, which is why the
/// outgoing arm has to synthesise `recipient_did` — the file keys a row by the peer it is
/// filed under, and that peer is the recipient when we sent it.
fn row_of_stored(message: &StoredMessage) -> Value {
    let peer = match &message.conversation {
        Conversation::Group { group_did } => group_did,
        Conversation::Direct { peer_did } => peer_did,
    };
    let direction = match message.direction {
        Direction::Incoming => "incoming",
        Direction::Outgoing => "outgoing",
    };
    // §7.4's two arms, kept apart here as they are in the file: a `payload` reads as JSON, a
    // `text` reads as text, and a row with neither says so (`content_of`).
    let mut body = Map::new();
    match (&message.payload, &message.text) {
        (Some(payload), _) => {
            body.insert("payload".to_string(), payload.clone());
        }
        (None, Some(text)) => {
            body.insert("text".to_string(), json!(text));
        }
        (None, None) => {}
    }
    json!({
        "message_id": &message.message_id,
        "sender_did": &message.sender_did,
        "recipient_did": match message.direction {
            Direction::Outgoing => json!(peer),
            Direction::Incoming => Value::Null,
        },
        "content_type": &message.content_type,
        "direction": direction,
        // The service's own time where there is one, and otherwise when *this device* wrote
        // the row down. A message the service never numbered (a §12 group frame) has only the
        // second, and it is a real answer rather than an empty field.
        "created_at": message.accepted_at.as_deref().unwrap_or(&message.received_at),
        "read_at": &message.read_at,
        "body": Value::Object(body),
    })
}

/// Print stored rows the way the read family has always printed them.
///
/// `empty` is the sentence for no rows, and it is a parameter because "nothing here yet" and
/// "nothing unread" are different facts and only the caller knows which it asked for.
fn print_stored(rows: &[StoredMessage], json: bool, empty: &str) -> anyhow::Result<()> {
    let rendered: Vec<Value> = rows.iter().map(row_of_stored).collect();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "messages": rendered }))?
        );
        return Ok(());
    }
    let maps: Vec<&Map<String, Value>> = rendered.iter().filter_map(as_row).collect();
    if maps.is_empty() {
        println!("{empty}");
        return Ok(());
    }
    // `has_more` is a word from the paged service read, and there is no service here: the
    // summary is given a null result so it does not claim there is more than what is shown.
    println!("{}", summary_of(&maps, &Value::Null));
    for row in maps {
        println!("{}", render_message(row).join("\n"));
    }
    Ok(())
}

fn cmd_msg_inbox(
    own: &OwnIdentity,
    limit: Option<String>,
    unread: bool,
    json: bool,
) -> anyhow::Result<()> {
    let rows = local_store(own)?.recent(limit_of(limit.as_deref())?, unread)?;
    print_stored(
        &rows,
        json,
        if unread {
            "nothing unread"
        } else {
            "nothing here yet — `msg fetch` brings in what the service still holds"
        },
    )
}

fn cmd_msg_history(
    own: &OwnIdentity,
    peer_did: &str,
    limit: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    // A DID, never a name. Names live in the **service's** address book, so accepting one
    // would mean resolving it, and this command must answer with the network down
    // (client-messages.md §8.2). `contacts resolve` is the command that goes and looks; this
    // one says which command that is rather than quietly going online.
    if !looks_like_a_did(peer_did) {
        anyhow::bail!(
            "{peer_did:?} is not a DID. The local record is filed by DID, and looking a name \
             up would need the service's address book — run `anpio-cli contacts resolve \
             {peer_did}` and pass the DID it prints"
        )
    }
    let rows = local_store(own)?.conversation_with(peer_did, limit_of(limit.as_deref())?)?;
    print_stored(
        &rows,
        json,
        &format!("nothing with {peer_did} yet"),
    )
}

fn cmd_msg_show(own: &OwnIdentity, id: &str, json: bool) -> anyhow::Result<()> {
    let store = local_store(own)?;
    let rows = store.find(id)?;
    if json {
        let rendered: Vec<Value> = rows.iter().map(row_of_stored).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "messages": rendered }))?
        );
        return Ok(());
    }
    if rows.is_empty() {
        // Two different facts, and the message has to say which: an id this device has never
        // recorded (it was never fetched, or the service has since dropped it) is not the
        // same as an id that does not exist. Only the first is something the caller can fix.
        anyhow::bail!(
            "no message {id} in the local record — `msg fetch` brings in what the service \
             still holds, and never-fetched is not the same as never-sent"
        )
    }
    for message in &rows {
        let row = row_of_stored(message);
        let Some(row) = as_row(&row) else { continue };
        println!("{}", render_message(row).join("\n"));
    }
    Ok(())
}

fn cmd_msg_read(
    own: &OwnIdentity,
    ids: Vec<String>,
    all: bool,
    json: bool,
) -> anyhow::Result<()> {
    if all && !ids.is_empty() {
        anyhow::bail!("--all and <message_id> are two spellings of the same thing; pass one")
    }
    if !all && ids.is_empty() {
        anyhow::bail!("missing required argument <message_id>, or --all")
    }
    let location = own.location()?;
    // Writable, because this is the one read-family command that writes: read state lives
    // here and nowhere else (design §4, 2026-10-03). `open_unsynced` rather than `open`,
    // because marking a row read needs neither a resolved service nor a device — and it must
    // not go online to get them, or the family §8.1 keeps offline would have one member that
    // is not. It creates the file if there is none, which `open_read_only` would not, and
    // that is right: `--all` over an identity with no record is a write of zero rows.
    let mut store = MessageStore::open_unsynced(&location)?;
    let (marked, count) = if all {
        let changed = store.mark_all_read()?;
        (Vec::new(), changed)
    } else {
        let marked = store.mark_read(&ids)?;
        let count = marked.len() as u64;
        (marked, count)
    };

    if json {
        // No `read_at` here. The store stamps each row with its own clock, and echoing a
        // second reading of *this* clock would be a value that is not what was written —
        // `msg show --json` carries the real one, per row.
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "updated_count": count,
                "message_ids": marked,
            }))?
        );
        return Ok(());
    }
    if count == 0 {
        // Not an error: an id that is already read, or was never here, changes nothing, and
        // saying "0" is more useful than a refusal that hides which of the two happened.
        println!(
            "{}",
            if all { "nothing unread" } else { "nothing changed" }
        );
        return Ok(());
    }
    field("marked read:", Some(&json!(count)));
    Ok(())
}

/// Bring in what the service still holds — the one read-family command that goes online.
///
/// It is a **write** (client-messages.md §8.3): each `sync.delta` entry is the notification
/// the stream would have pushed, `decode_message` makes the frame the listener would have
/// seen, and `records_from` → `MessageStore::record` is the listener's own write path. One
/// mapping for one frame is what keeps the two halves from disagreeing about what a delivery
/// is. Calling it twice changes nothing the second time: the dedupe key catches the rows and
/// the cursor only moves forward (`record`).
async fn cmd_msg_fetch(
    own: &OwnIdentity,
    since: Option<u64>,
    limit: Option<String>,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let location = own.location()?;
    let identity = Identity::load(&location)?;
    let client = http_client()?;
    // Every step from here down is one the rest of the read family does not take, so each of
    // the two carries the sentence that says so. Without it, "error sending request" off a
    // dead service reads as if the *record* were broken — and the record is precisely the
    // thing that is still fine and still answerable.
    let channel = open_channel(&client, &identity, allow_private)
        .await
        .with_context(|| {
            format!(
                "`msg fetch` is the one read that goes online: it resolves {} and asks \
                 its service for what is still held. `msg inbox` / `history` / `show` answer \
                 from the local record and need no network",
                identity.did
            )
        })?;
    // The same device `msg listen` uses by default, so a fetch resumes exactly where a listen
    // stopped. A different device is a different slice of the inbox, and this command has no
    // `--device`: the record it writes to belongs to this identity *on this machine*.
    let device = device_of(&channel.sender, None)?;
    let mut store = MessageStore::open(
        &location,
        &identity,
        &channel.endpoint.target.endpoint,
        &device,
    )?;

    // Where to resume. The stored cursor is the answer unless the caller overrode it, and a
    // record that has never applied anything starts at 0 — `sync.delta` is a "since" read, so
    // 0 is "everything this device was ever sent".
    let mut cursor = match since {
        Some(explicit) => explicit,
        None => store.applied_seq()?.unwrap_or(0),
    };
    let start = cursor;
    let page_size = limit_of(limit.as_deref())?.min(DELTA_PAGE);

    let mut applied = 0u64;
    let mut replayed = 0u64;
    let mut offline: Vec<String> = Vec::new();
    // How many rows the service still holds but will not hand out any more, because they are
    // older than its read window and have not been fetched (`sync.delta` 的 `aged_out`). Taken
    // as a max: only the first page can be non-zero, since every later page's `since` has
    // already stepped over that span.
    let mut aged_out = 0u64;
    loop {
        let mut body = Map::new();
        body.insert("since".to_string(), json!(cursor));
        body.insert("limit".to_string(), json!(page_size));
        body.insert("device_id".to_string(), json!(device));
        let page = call_extension(&client, &channel, SYNC_DELTA, INBOX_PROFILE, body)
            .await
            .with_context(|| {
                format!(
                    "`msg fetch` is the one read that goes online: it asks {} for its sync.delta \
                     page. `msg inbox` / `history` / `show` answer from the local record and need \
                     no network",
                    channel.endpoint.target.endpoint
                )
            })?;
        aged_out = aged_out.max(page.get("aged_out").and_then(Value::as_u64).unwrap_or(0));
        for entry in page.get("messages").and_then(Value::as_array).into_iter().flatten() {
            let Some(row) = entry.as_object() else { continue };
            let seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(cursor);
            let frame = json!({
                "jsonrpc": "2.0",
                "method": row.get("method"),
                "params": row.get("params"),
            });
            // A §12 frame whose device-queue entry has expired is not in `deliveries` at all,
            // but one that is still queued can arrive here — and this command has no MLS
            // receiver, so it can neither decrypt it nor record the ciphertext as if it were
            // the message. Named and skipped, not silently dropped: "what fetch cannot bring
            // back it says so about" is the whole of §8.3's second half.
            if is_group_e2ee_frame(&frame) {
                if let Some(did) = group_did_of(&frame) {
                    if !offline.contains(&did) {
                        offline.push(did);
                    }
                }
                continue;
            }
            let Some(message) = decode_message(&frame, seq) else { continue };
            if let Some(record) = records_from(&ListenEvent::Message(message)) {
                if store.record(&record)? {
                    applied += 1;
                } else {
                    replayed += 1;
                }
            }
        }

        if page.get("has_more").and_then(Value::as_bool) != Some(true) {
            break;
        }
        // A page that does not move the cursor would repeat forever, and one that is empty
        // while claiming more would too — the same guard `msg listen`'s backfill carries.
        match page.get("next_since").and_then(Value::as_u64) {
            Some(next) if next > cursor => cursor = next,
            _ => break,
        }
    }

    let held = store.message_count()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "applied": applied,
                "replayed": replayed,
                "since": start,
                "next_since": cursor,
                "held": held,
                "unfetchable": offline,
                "aged_out": aged_out,
            }))?
        );
        return Ok(());
    }
    field("brought in:", Some(&json!(applied)));
    if replayed > 0 {
        // A replay is normal (the same frame pushed and fetched), so it is reported rather
        // than hidden — otherwise "brought in: 0" on a second call would read as a failure.
        field("already had:", Some(&json!(replayed)));
    }
    field("local cursor:", Some(&json!(cursor)));
    field("held locally:", Some(&json!(held)));
    if !offline.is_empty() {
        println!(
            "  {} not fetched: group-e2ee ciphertext needs `msg listen` to decrypt it, and \
             the device queue may already have dropped it",
            joined(&offline)
        );
    }
    if aged_out > 0 {
        // §8.3 的第二半：搬不回来的要**说清搬不回来**。这一句说的是另一种搬不回来——
        // 服务端还留着（保留契约是永不裁剪），但它们已经出了那条「只交出最近这一段」的
        // 窗口，所以再 fetch 多少次也够不着。少了它，上面那句 `brought in: 0` 在这种情形
        // 下就是一句会骗人的真话。
        println!(
            "  {} not fetched: older than the service's read window, so no fetch can bring \
             them back — they are not deleted, just past the point where the service hands \
             them out",
            aged_out
        );
    }
    Ok(())
}

/// Is this notification P6's? The two `group.incoming` methods share a name (P4's plaintext
/// one and §12's ciphertext one) and §12.5's security profile is the only thing on the wire
/// that tells them apart — the same test the receiver makes, made here because this command
/// has no receiver to make it.
fn is_group_e2ee_frame(frame: &Value) -> bool {
    frame
        .get("params")
        .and_then(|params| params.get("meta"))
        .and_then(|meta| meta.get("security_profile"))
        .and_then(Value::as_str)
        == Some(GROUP_E2EE_SECURITY_PROFILE)
}

fn group_did_of(frame: &Value) -> Option<String> {
    frame
        .get("params")
        .and_then(|params| params.get("meta"))
        .and_then(|meta| meta.get("target"))
        .and_then(|target| target.get("did"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

// ---- contacts (TODO6 §3) --------------------------------------------------------


/// The whole book, as the identity in use has it.
///
/// One call and no paging: `contacts.list` takes no body and answers the whole table, which
/// is what makes "two contacts answer to this name" answerable at all — a name can only be
/// ambiguous against the full book, so a paged reader could call one Alice unique by having
/// stopped before the other.
async fn fetch_contacts(client: &reqwest::Client, channel: &Channel) -> anyhow::Result<Vec<Contact>> {
    let result = call_extension(client, channel, CONTACTS_LIST, CONTACTS_PROFILE, Map::new()).await?;
    Ok(book_from_json(&result)?)
}

/// A name or a DID as the DID to act on, over an already-fetched book.
///
/// The book is a parameter rather than fetched here so that a command which resolves and then
/// writes reads it once; two reads would be able to disagree about a row that changed in
/// between, and the disagreement would look like the wrong contact being renamed.
fn resolve_did(book: &[Contact], input: &str) -> anyhow::Result<String> {
    match lookup(book, input) {
        Lookup::One(contact) => Ok(contact.did),
        Lookup::Ambiguous(candidates) => Err(ambiguous_name_error(input, &candidates).into()),
        Lookup::None { did_shaped: true } => Ok(input.to_string()),
        Lookup::None { did_shaped: false } => Err(unknown_name_error(input).into()),
    }
}

/// One row back out as JSON, in the shape the service used. `--json` here and the service's
/// own answer are then the same document rather than two spellings of it.
fn contact_json(contact: &Contact) -> Value {
    json!({
        "subject": contact.subject,
        "did": contact.did,
        "remark": contact.remark,
        "created_at": contact.created_at,
        "updated_at": contact.updated_at,
    })
}

async fn cmd_contacts_list(
    own: &OwnIdentity,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = own_channel(own, allow_private).await?;
    let book = fetch_contacts(&client, &channel).await?;

    if json {
        let rows: Vec<Value> = book.iter().map(contact_json).collect();
        println!("{}", serde_json::to_string_pretty(&json!({ "contacts": rows }))?);
        return Ok(());
    }
    if book.is_empty() {
        println!("no contacts; add one with `anpio-cli contacts add <did> --remark <name>`");
        return Ok(());
    }
    println!("{} contact{}", book.len(), if book.len() == 1 { "" } else { "s" });
    for contact in &book {
        println!("{}\t{}", contact.name(), contact.did);
    }
    Ok(())
}

async fn cmd_contacts_add(
    own: &OwnIdentity,
    did: &str,
    remark: Option<String>,
    clear_remark: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    // Checked before anything is opened: `subject_of` is total, so the service would take a
    // name here and file it under a key no DID will ever match. See `not_a_did_error`.
    if !looks_like_a_did(did) {
        return Err(not_a_did_error(did).into());
    }
    if remark.as_deref() == Some("") {
        anyhow::bail!("--remark cannot be empty; leave it out, or pass --clear-remark to drop one")
    }

    let (client, channel) = own_channel(own, allow_private).await?;
    let book = fetch_contacts(&client, &channel).await?;
    let subject = subject_of(did);
    let existing = book.iter().find(|contact| contact.subject == subject);

    // On the wire an absent `remark` clears it, which would make a second `add <did>` erase
    // the name the first one wrote. So the decision belongs here: with no `--remark` and no
    // `--clear-remark`, an existing remark is sent back unchanged — the update still happens
    // (the DID is refreshed), the name is not touched.
    let requested = match (&remark, clear_remark) {
        (Some(name), _) => Some(name.clone()),
        (None, true) => None,
        (None, false) => existing.and_then(|contact| contact.remark.clone()),
    };
    let kept = remark.is_none() && !clear_remark && requested.is_some();

    let mut body = Map::new();
    body.insert("did".to_string(), json!(did));
    if let Some(name) = &requested {
        body.insert("remark".to_string(), json!(name));
    }
    let result = call_extension(&client, &channel, CONTACTS_PUT, CONTACTS_PROFILE, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    let created = result.get("created").and_then(Value::as_bool).unwrap_or(false);
    let stored = result.get("contact").map(Contact::from_json).transpose()?;
    let name = stored.as_ref().and_then(|contact| contact.remark.clone());
    let verb = if created { "added" } else { "updated" };
    match &name {
        Some(name) if kept => println!("{verb} {did} (remark {name} unchanged)"),
        Some(name) => println!("{verb} {name}\t{did}"),
        None => println!("{verb} {did} (no remark)"),
    }
    Ok(())
}

async fn cmd_contacts_set_remark(
    own: &OwnIdentity,
    name: &str,
    remark: &str,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    if remark.is_empty() {
        anyhow::bail!("a remark cannot be empty; `contacts add <did> --clear-remark` is how one is dropped")
    }
    let (client, channel) = own_channel(own, allow_private).await?;
    let book = fetch_contacts(&client, &channel).await?;
    // Resolved against the same book `--to` uses, so a name two contacts answer to is refused
    // here rather than renaming whichever one came first.
    let did = resolve_did(&book, name)?;

    let mut body = Map::new();
    body.insert("did".to_string(), json!(did));
    body.insert("remark".to_string(), json!(remark));
    let result = call_extension(&client, &channel, CONTACTS_PUT, CONTACTS_PROFILE, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    println!("{remark}\t{did}");
    Ok(())
}

async fn cmd_contacts_remove(
    own: &OwnIdentity,
    name: &str,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = own_channel(own, allow_private).await?;
    let book = fetch_contacts(&client, &channel).await?;
    let did = resolve_did(&book, name)?;

    let mut body = Map::new();
    body.insert("subject".to_string(), json!(subject_of(&did)));
    let result = call_extension(&client, &channel, CONTACTS_REMOVE, CONTACTS_PROFILE, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    if result.get("removed").and_then(Value::as_bool) != Some(true) {
        // Only reachable with a DID that was already gone — a name got this far by resolving
        // to a row. Saying nothing was removed is the honest answer, and it is an error
        // because the command did not do what it was asked to.
        anyhow::bail!("{did} was not in the book; nothing to remove")
    }
    println!("removed\t{did}");
    Ok(())
}

async fn cmd_contacts_resolve(
    own: &OwnIdentity,
    name: &str,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    // A DID needs no book: it is already its own answer, and a caller that holds one is common
    // enough to be worth not opening an identity for. This also makes the command total, which
    // is the point of it — an agent can run `resolve` on whatever string it was handed,
    // without first deciding which of the two it has.
    if looks_like_a_did(name) {
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "did": name,
                    "subject": subject_of(name),
                    "remark": Value::Null,
                    "source": "argument",
                }))?
            );
        } else {
            println!("{name}");
        }
        return Ok(());
    }

    let (client, channel) = own_channel(own, allow_private).await?;
    let book = fetch_contacts(&client, &channel).await?;
    match lookup(&book, name) {
        Lookup::One(contact) => {
            if json {
                let mut row = contact_json(&contact);
                row["source"] = json!("contacts");
                println!("{}", serde_json::to_string_pretty(&row)?);
            } else {
                // The bare DID and nothing else: the answer is what a script feeds to
                // `msg send --to`, and a decoration on stdout would be something to strip.
                println!("{}", contact.did);
            }
            Ok(())
        }
        Lookup::Ambiguous(candidates) => Err(ambiguous_name_error(name, &candidates).into()),
        Lookup::None { .. } => Err(unknown_name_error(name).into()),
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

    // A listener signs on every reconnect, so a grant that runs out mid-run ends the stream
    // hours after the user walked away from it. This is the one moment to notice, and to
    // say what the administrator would have to do if it cannot be renewed.
    if let Some(Custody::AnpioKey(key)) = identity.custody.as_ref() {
        if key.config.is_some() {
            if let Some(renewed) = key.ensure_runway()? {
                let when = chrono::DateTime::from_timestamp(renewed.expiry, 0)
                    .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                    .unwrap_or_else(|| format!("{} (unix seconds)", renewed.expiry));
                eprintln!(
                    "renewed anpio-key grant {} until {when} so the listener keeps signing on \
                     reconnect",
                    renewed.grant_id
                );
            }
        }
    }

    let client = http_client()?;
    let channel = open_channel(&client, &identity, allow_private).await?;
    let device = device_of(&channel.sender, options.device.as_deref())?;

    // The local record (client-messages.md). Opened before the stream starts rather than
    // lazily: a store this build cannot open — a file from a newer one, a directory it cannot
    // write — is then a startup failure like any other, instead of a listener that silently
    // records nothing for as long as it runs.
    let store = MessageStore::open(
        &location,
        &identity,
        &channel.endpoint.target.endpoint,
        &device,
    )?;

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
        // Recording is a decorator, so the terminal still shows every event and the store is
        // never on the path that decides what to print.
        view: Arc::new(RecordingView::new(store, view_for(options.json), options.ack)),
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
    names: bool,
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
        let (roster_names, unfetched) = member_names(own, &client, &result, names, allow_private).await?;
        report_roster(&result, &roster_names, unfetched)?;
    } else {
        let remark = group_remark_for(own, &client, group_did, allow_private).await?;
        report_group_info(&result, remark.as_deref());
    }
    Ok(())
}

/// What I call this group, or `None` (TODO6 §4.2).
///
/// One read of my own book, and only on the way to the human rendering: `--json` stays the
/// service's own answer, the same rule `group members` follows for its names. The lookup is
/// by the group DID, which is the row's key — a group DID carries no key fingerprint, so
/// unlike a peer there is no second spelling for it to drift to (§9.5).
async fn group_remark_for(
    own: &OwnIdentity,
    client: &reqwest::Client,
    group_did: &str,
    allow_private: &[String],
) -> anyhow::Result<Option<String>> {
    // `group_remarks.list` is self-addressed, so this needs a channel to **my** service — the
    // channel `cmd_group_info` already holds is addressed to the group.
    let identity = Identity::load(&own.location()?)?;
    let channel = open_channel(client, &identity, allow_private).await?;
    let result = call_extension(
        client,
        &channel,
        GROUP_REMARKS_LIST,
        GROUP_REMARKS_PROFILE,
        Map::new(),
    )
    .await?;
    let book = group_remarks_from_json(&result)?;
    Ok(book
        .into_iter()
        .find(|row| row.group_did == group_did)
        .map(|row| row.remark))
}

/// Name a group, or drop the name (TODO6 §4.2).
///
/// Two wires, one command: a remark goes to `group_remarks.put`, `--clear` to
/// `group_remarks.remove`. The row holds nothing but the name, so "forget it" is the whole
/// of what removal can mean here — there is no entry left behind to keep, unlike
/// `contacts remove`, which drops a peer the book might otherwise still recognise.
async fn cmd_group_set_remark(
    own: &OwnIdentity,
    group_did: &str,
    remark: Option<String>,
    clear: bool,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = own_channel(own, allow_private).await?;

    if clear {
        let mut body = Map::new();
        body.insert("group_did".to_string(), json!(group_did));
        let result =
            call_extension(&client, &channel, GROUP_REMARKS_REMOVE, GROUP_REMARKS_PROFILE, body).await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }
        if result.get("removed").and_then(Value::as_bool) != Some(true) {
            // Honest rather than silent: nothing was named, so there was nothing to forget.
            println!("{group_did} had no remark");
            return Ok(());
        }
        println!("forgot the remark for {group_did}");
        return Ok(());
    }

    let Some(remark) = remark else {
        // clap makes one of the two required, so this is unreachable through the parser; it
        // exists so the function cannot quietly send a body the service would refuse.
        anyhow::bail!("pass a remark, or --clear to forget one")
    };
    if remark.is_empty() {
        anyhow::bail!("a remark cannot be empty; --clear is how one is dropped")
    }

    let mut body = Map::new();
    body.insert("group_did".to_string(), json!(group_did));
    body.insert("remark".to_string(), json!(remark));
    let result = call_extension(&client, &channel, GROUP_REMARKS_PUT, GROUP_REMARKS_PROFILE, body).await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    let stored = result.get("group_remark").map(GroupRemark::from_json).transpose()?;
    let name = stored.map(|row| row.remark).unwrap_or(remark);
    println!("{name}\t{group_did}");
    Ok(())
}

/// The group's name lives in `group_profile.display_name`, and `group.update_profile` is the
/// only writer (§7.4). The body field is `group_profile_patch` under RFC 7386 merge semantics
/// (§8.7.2), so a field left out is a field left unchanged — there is no other way to change
/// a name, which is why this is a command and not a flag hung off `group info`.
async fn cmd_group_update_profile(
    own: &OwnIdentity,
    group_did: &str,
    name: &str,
    json: bool,
    allow_private: &[String],
) -> anyhow::Result<()> {
    let (client, channel) = group_channel(own, group_did, allow_private).await?;

    let mut body = Map::new();
    body.insert(
        "group_profile_patch".to_string(),
        json!({ "display_name": name }),
    );

    let result = call_group(
        &client,
        &channel,
        GROUP_UPDATE_PROFILE,
        group_target(group_did),
        body,
        group_did,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
        return Ok(());
    }
    report_group_profile(&result)
}

/// §8.7: `group_did`, the new state version, and the merged profile.
fn report_group_profile(result: &Value) -> anyhow::Result<()> {
    field("group:", result.get("group_did"));
    field("state version:", result.get("group_state_version"));
    if let Some(profile) = result.get("group_profile").and_then(as_row) {
        field("name:", profile.get("display_name"));
        field("description:", profile.get("description"));
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
    // Read again rather than threaded out of `group_channel`: the local record wants the
    // identity, and widening that helper's return for one caller would put the store's needs
    // into the channel's signature.
    let location = own.location()?;
    let identity = Identity::load(&location)?;

    // P1 §6.2.6: one flag pins `operation_id` and `message_id` together, so a retry keeps
    // the pair unchanged (P4 §5.4).
    let operation_id = requested_operation_id.unwrap_or_else(uuid_v4);
    let content_type = payload.content_type;
    let (sent_text, sent_payload) = payload_from(&payload.body);

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
            content_type: Some(content_type.clone()),
            operation_id: Some(operation_id.clone()),
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => {
            if result.get("accepted").and_then(Value::as_bool) == Some(true) {
                record_outgoing(
                    &location,
                    &identity,
                    &channel.endpoint.target.endpoint,
                    &device_of(&channel.sender, None)?,
                    text_of(result.get("accepted_at")),
                    MessageRecord::outgoing(
                        Conversation::Group {
                            group_did: group_did.to_string(),
                        },
                        &channel.sender.did,
                        &operation_id,
                        content_type,
                        sent_text,
                        sent_payload,
                    ),
                );
            }
            report_group_sent(&result, json)
        }
        // No `anp.did_superseded` arm here, unlike `msg send` (`superseded_refusal` above): DID
        // continuity inside a group is member-level and host-driven — P4 §8.12 says
        // `group.member_did_update` is not even a JSON-RPC method — and P4 defines no client
        // path for a group DID itself, so there is no chain to walk and nothing to verify.
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
    // Kept for the local row: `plaintext` moves into `SendInput` below, and the row keeps the
    // **plaintext**'s content type rather than the cipher's — the row is what this device knows
    // about the conversation, while `application/…+group-cipher` is a fact about the transport.
    let sent_content_type = plaintext.application_content_type.clone();
    let sent_text = plaintext.text.clone();
    let sent_payload = plaintext.payload.clone();

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
    // Which custody holds that key is [`device_signer`]'s call: a local `{device}-sign`, or
    // `anpio-key` signing the prepared proof under `device_assertion`.
    let signer = device_signer(&identity)?;
    let sender = match signer {
        DeviceSigner::Local { keyid, key } => group_channel.sender.signing_as_device(keyid, key),
        DeviceSigner::Daemon {
            keyid, key, public, ..
        } => group_channel
            .sender
            .signing_as_daemon_device(keyid, key, public),
    };

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
            operation_id: Some(operation_id.clone()),
        },
    )
    .await?;

    match response {
        AnpResponse::Success { result, .. } => {
            if result.get("accepted").and_then(Value::as_bool) == Some(true) {
                // The version is the one the cipher was encrypted against — the same field the
                // receive path reads off `group_state_ref` — so a sender's row and a
                // receiver's row are reconcilable the same way.
                let mut record = MessageRecord::outgoing(
                    Conversation::Group {
                        group_did: group_did.to_string(),
                    },
                    &identity.did,
                    &operation_id,
                    sent_content_type,
                    sent_text,
                    sent_payload,
                );
                record.group_state_version =
                    Some(cipher.group_state_ref.group_state_version.clone());
                record.group_event_seq = text_of(result.get("group_event_seq")).map(str::to_string);
                record_outgoing(
                    &location,
                    &identity,
                    &group_channel.endpoint.target.endpoint,
                    &device_of(&group_channel.sender, None)?,
                    text_of(result.get("accepted_at")),
                    record,
                );
            }
            report_group_e2ee_sent(&result, json)
        }
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
///
/// `remark` is the one line here that did **not** come from the service's answer: it is what
/// this identity calls the group (TODO6 §4.2), read from its own book and passed in. It is
/// printed next to `name:` because the pair is the whole point — `name:` is the group's own
/// name and every member sees it, `remark:` is mine alone, and a reader who confuses them
/// would think the first had no local override.
fn report_group_info(result: &Value, remark: Option<&str>) {
    field("group:", result.get("group_did"));
    field("state version:", result.get("group_state_version"));
    if let Some(profile) = result.get("group_profile").and_then(as_row) {
        field("name:", profile.get("display_name"));
        if let Some(remark) = remark {
            field("remark:", Some(&Value::String(remark.to_string())));
        }
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

/// DID → name for one roster (TODO6 §4.2).
///
/// Two sources, in this order, because they answer different questions. A remark is what *I*
/// call this peer: deliberate, mine, and the one of the two that survives the peer renaming
/// itself. The peer's own display name fills in the members the book does not know — and it is
/// asked **only** for those, so a group whose members are all in the book costs no per-member
/// request at all while `--names` still does what it says for the rest.
///
/// The count that comes back with the names is how many members `--names` asked about and got
/// no answer for. It is reported rather than swallowed: a roster that quietly fell back to DIDs
/// looks the same as one where nobody has a name.
async fn member_names(
    own: &OwnIdentity,
    client: &reqwest::Client,
    roster: &Value,
    fetch: bool,
    allow_private: &[String],
) -> anyhow::Result<(RosterNames, usize)> {
    // One read of the book whether or not `--names` was given: it is the default source, and
    // it also decides which members still need asking. `contacts.list` is self-addressed, so
    // this needs a channel to **our** service — the group's channel is addressed to the group.
    let identity = Identity::load(&own.location()?)?;
    let channel = open_channel(client, &identity, allow_private).await?;
    let book = fetch_contacts(client, &channel).await?;
    let mut names = RosterNames::from_book(&book);
    let mut unfetched = 0usize;

    if fetch {
        for row in rows_of(roster, "member_list") {
            let Some(agent_did) = text_of(row.get("agent_did")) else {
                continue;
            };
            // A member the book already names is not asked about: the remark is the reader's
            // own word for them, and one HTTP round trip per known member is the cost the
            // escape hatch was meant to avoid.
            if names.name_of(agent_did).is_some() {
                continue;
            }
            match peer_display_name(client, agent_did, allow_private).await {
                Some(name) => names.remember(agent_did, name),
                None => unfetched += 1,
            }
        }
    }
    Ok((names, unfetched))
}

/// The name a peer chose for itself, read from its own DID host (TODO6 §4.2 ①).
///
/// `None` for every way of not having one — the host does not answer, it serves no public
/// profile for this DID, or the profile carries no name. They are one answer on purpose: the
/// caller prints the DID either way, and telling "their host is down" apart from "they never
/// set a name" would not change anything it could do about it.
async fn peer_display_name(
    client: &reqwest::Client,
    agent_did: &str,
    allow_private: &[String],
) -> Option<String> {
    let host = did_host(agent_did).ok()?;
    // The scheme gate is the one the document fetch uses, and it is needed for the same
    // reason: a DID spells `https` and cannot say otherwise, so a host reachable over plain
    // HTTP is only reachable where the caller allowed it (`--allow-private`, or loopback).
    let policy = policy_for(std::slice::from_ref(&host), allow_private);
    // The returned URL is the DID's own document address, which is fine as a base: every path
    // here is absolute, and joining one discards the rest — what has to survive is scheme,
    // host and port, and those are exactly what a DID host base is.
    let base = document_url(agent_did, &policy).ok()?;
    let profile = fetch_public_profile(client, &base, agent_did).await.ok()?;
    // `display_name` is what `me set --name` writes; the rest are the host's other spellings
    // of the same thing, tried in that order so a profile that has only a handle still names
    // the member. All three empty is "no name", not an empty name.
    for field in ["display_name", "nick_name", "handle"] {
        if let Some(name) = text_of(profile.get(field)) {
            return Some(name.to_string());
        }
    }
    None
}

/// §7.2: `agent_did` / `role` / `status` are the minimum; `joined_at` and `added_by` are
/// optional and printed when present.
fn report_roster(result: &Value, names: &RosterNames, unfetched: usize) -> anyhow::Result<()> {
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
        // The DID stays on the line even when there is a name for it: it is the address, and
        // it is what the next command takes. The name is an annotation on it, not a
        // replacement.
        match names.name_of(agent) {
            Some(name) => println!("  {status:<8} {role:<6} {agent}  {name}{joined}"),
            None => println!("  {status:<8} {role:<6} {agent}{joined}"),
        }
    }
    if unfetched > 0 {
        println!(
            "note: {} member{} could not be named (no public profile on their host); their DID is printed instead",
            unfetched,
            if unfetched == 1 { "" } else { "s" }
        );
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
