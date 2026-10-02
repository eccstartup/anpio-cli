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

use agentx::identity::{
    create_identity, fetch_host_service, register_identity, CreateIdentityInput, Identity,
    IdentityLocation,
};
use agentx::message::{
    build_message_request, call, call_extension, device_of, discover, http_client, now_rfc3339,
    open_channel, parse_capabilities, payload_of, policy_for, post_message, rejection, run_listen,
    uuid_v4, view_for, websocket_connect, AnpMeta, AnpResponse, AnpTarget, CallRequest, Channel,
    ConnectFn, ListenArgs, ListenDeps, ResolvePolicy, Sender, TargetKind, CORE_BINDING,
    DIRECT_PROFILE, DIRECT_SEND, DID_SUPERSEDED, GET_CAPABILITIES, INBOX_GET, INBOX_MARK_READ,
    MESSAGE_GET_BATCH, TRANSPORT_PROTECTED,
};

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
    /// Messages: send one, and read the ones that arrived.
    Msg {
        #[command(subcommand)]
        command: MsgCommand,
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
        #[arg(long)]
        agent: Option<String>,
        #[arg(long, default_value = "default")]
        profile: String,
    },
    /// Show the identity on file.
    Show {
        #[arg(long, default_value = "default")]
        agent: String,
        #[arg(long, default_value = "default")]
        profile: String,
        /// Print the whole thing, DID document included.
        #[arg(long)]
        json: bool,
    },
    /// Publish (or re-publish) an identity's DID document to its host.
    Register {
        #[arg(long, default_value = "default")]
        agent: String,
        #[arg(long, default_value = "default")]
        profile: String,
    },
}

/// The identity a command acts as. Its `--agent`/`--profile` also name the store directory
/// and the default device (`realtime.md` §5.4), so the two are always asked for together.
#[derive(Args)]
struct OwnIdentity {
    #[arg(long, default_value = "default")]
    agent: String,
    #[arg(long, default_value = "default")]
    profile: String,
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
            } => {
                cmd_did_create(&host, &handle, agent.unwrap_or_else(|| handle.clone()), &profile)
                    .await
            }
            DidCommand::Show {
                agent,
                profile,
                json,
            } => cmd_did_show(&agent, &profile, json),
            DidCommand::Register { agent, profile } => cmd_did_register(&agent, &profile).await,
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

async fn cmd_did_create(host: &str, handle: &str, agent: String, profile: &str) -> anyhow::Result<()> {
    let location = IdentityLocation::new(agent, profile);
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

fn cmd_did_show(agent: &str, profile: &str, json: bool) -> anyhow::Result<()> {
    let location = IdentityLocation::new(agent, profile);
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

async fn cmd_did_register(agent: &str, profile: &str) -> anyhow::Result<()> {
    let location = IdentityLocation::new(agent, profile);
    let identity = Identity::load(&location)?;
    let base = Url::parse(&identity.did_host)
        .map_err(|err| anyhow::anyhow!("the stored host is not a URL: {err}"))?;
    let client = http_client()?;
    register_identity(&client, &base, &identity).await?;
    println!("registered {} with {}", identity.did, identity.did_host);
    Ok(())
}

// ---- msg send ------------------------------------------------------------------

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
    let location = IdentityLocation::new(&own.agent, &own.profile);
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
    let location = IdentityLocation::new(&own.agent, &own.profile);
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
    let (_client, channel) = own_channel(own, allow_private).await?;
    let device = device_of(&channel.sender, options.device.as_deref())?;

    let deps = ListenDeps {
        connect: websocket_connect_fn(),
        view: view_for(options.json),
        abort: interrupt_signal(),
        // `rand::random::<f64>()` is `[0, 1)`, which is the range the jitter expects.
        random: Arc::new(rand::random::<f64>),
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

// ---- reading what came back ----------------------------------------------------

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
