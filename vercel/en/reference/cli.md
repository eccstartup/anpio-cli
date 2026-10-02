---
title: agentx-cli commands
description: "The complete command surface of the agentx-cli command-line client — discover / did / agent / msg / group / anp / contacts / me / version — with exit codes and output conventions."
---

# agentx-cli commands

`agentx-cli` is this repository's command-line client, written in Rust, with its source under `rust/crates/agentx-cli/`. Every command has the form `agentx-cli <command> [subcommand] [arguments] [options]`, and `agentx-cli help [<command> [<subcommand>]]` prints the same description (the authority on the command surface is exactly what it prints).

> [!NOTE]
> **`connectx` is frozen.** The TypeScript client in `packages/cli` (the `@agentx/cli` package) no longer gains features and is no longer the documentation entry point — this page describes `agentx-cli`, and the rest of this site has been switched to it too. The two speak the **same protocol**; the command names and flags differ, so take this page and `--help` as authoritative.

## Install and store

`agentx-cli` is a binary, not an npm package. Build it from source:

```bash
cargo build --release --manifest-path rust/Cargo.toml
# artifact: rust/target/release/agentx-cli
```

It is **not published to any package manager**: the `agentx-cli` on crates.io is a **different
project**, so do not write `cargo install agentx-cli`.

It keeps its own store root (`$AGENTXCLI_HOME`, default `~/.agentx-cli`) and **does not touch `connectx`'s `~/.connectx/`**, so the two CLIs coexist without interfering. An identity is named by `--agent` + `--profile` and lands under `<store root>/<agent>/<profile>/` (`identity.json`, `session.json`).

## Output and exit code conventions

- `--json` turns stdout into machine-readable output (for most commands a single JSON object; for `msg listen` one JSON object per line). **stderr carries connection status, progress and errors**, so `> file` gets you pure results.
- Exit codes are not just 0/1: `did resolve` uses **2 / 3** to distinguish "no longer current" from "chain not verified". Every other command is 0 or 1. Misusing the command surface (for example, omitting a required positional argument) is a clap usage error, which **exits 2**.
- A failure looks like this: one line on stderr, `Error: <stable code>: <prose>`. The stable codes are **spelled the same way** as the TS client's `ConnectxError.code` (`message_invalid` / `message_send_failed` / `unsupported_extension` / `did_resolve_blocked` …), so a script can branch on them without parsing the prose.

## Global options

| Option | Description |
|---|---|
| `--agent <id>` | Which agent identity to act as; defaults, in order, to `$AGENTXCLI_AGENT`, the current agent (chosen by `agent use`), or `default` |
| `--profile <name>` | The identity profile within the agent; defaults to `$AGENTXCLI_PROFILE`, then `default` |
| `--allow-private-host <host>` | Treat a host that is local **without being spelled as loopback** as local; permitting it also permits a private address and plain `http` |
| `--json` | Machine-readable output |

`--allow-private-host` appears on commands that derive a host: the target host comes from an **identifier** rather than a flag. `localhost` / `127.0.0.1` / `::1` are already treated as local and need no flag — this one is for a host that is local but spelled some other way (a LAN address, a name that resolves inward).

**`did create` is the one command outside the identity chain**: it mints a **new** identity, and "who is currently selected" should not decide where a second identity is written, so it defaults to `--handle`.

## `did` and `agent` — identity

| Subcommand | Purpose |
|---|---|
| `did create --host <url> --handle <name>` | Mint an identity and publish its DID document to a DID host (`--agent` defaults to the handle) |
| `did show` | Print the identity on file |
| `did list` | Every identity this machine holds, and what each one is bound to |
| `did register` | (Re-)publish the DID document to its host and take back a bearer token |
| `did publish` | After a local edit, re-sign and re-publish — over the host's `update_document`, not the ANP signing path |
| `did update --target <uri>` / `did update --resume` | Submit a DID update, or finalize an already-staged successor (ANP-03 §2.5.3) |
| `did resolve <did>` | Fetch a DID document; `--chain` walks the update chain and reports the assurance level hop by hop |
| `did restore` | Restore (**`anp` has no such path**; invoking it exits 1 and says nothing was read and nothing was restored) |
| `agent show` / `agent use <id>` / `agent list` | Current agent / switch / all agents |

The exit codes of `did resolve --chain` are worth memorizing separately: **0** current; **2** no longer current (the chain moved past, or the document is a retirement statement); **3** update chain not verified (`did_chain_broken`); **1** other.

`did update` writes the successor key into `successor.json` **before any byte goes out**: between the server accepting and the store moving over, that file is the **only** copy of the key the DID has already migrated to. So when the delivery outcome is unknown it **keeps** the staged key and points at `--resume`, rather than discarding it.

## `msg` — message service

| Subcommand | Purpose |
|---|---|
| `msg send --to <did\|name> (--text <s> \| --body <json>)` | Deliver a direct message |
| `msg caps <did>` | Ask what the other side's message service supports |
| `msg inbox` | List messages pending for this identity (`--limit` defaults to 20, `--include-read`) |
| `msg show <message_id>` | Print the full content of one message |
| `msg read <message_id>...` / `msg read --all` | Mark as read |
| `msg listen` | Keep the connection open and print messages in arrival order |

`msg send --to` takes **a DID or a name from the address book**; when two names resolve to the same person it **exits 1 and lists every candidate**, rather than picking one. `--text` and `--body` are **mutually exclusive**, and `--content-type` defaults to match the body form (`text/plain` for `--text`, `application/json` for `--body`).

The four options of `msg listen` are worth spelling out:

| Option | Description |
|---|---|
| `--device <id>` | The name this client queue is stored under on the server; defaults to `<agent>/<profile>` |
| `--since <seq>` | Start from this delivery number instead of the cursor the server remembers |
| `--ack` | Mark each message read as it is printed; **off by default** |
| `--once` | Print the catch-up portion and exit, without staying resident |

> [!IMPORTANT]
> Without `--ack`, the server does not push the cursor past the printed position — so after one run ends, the next run **prints the same batch of messages again**. This is a deliberate choice: duplicate printing is noise, whereas a message marked read that nobody saw is genuinely lost. `--ack` should only be used for pipelines that have "already persisted to disk". Ctrl-C exits **0**; a dropped connection reconnects with a 2s→30s backoff.

The stream address is **derived** from the message service endpoint in the DID document: replace the last path segment with `stream`. A service that mounts the stream elsewhere cannot be reached by this command.

> [!NOTE]
> `msg inbox` / `msg show` / `msg read` hit an **implementation extension** (`x_agentx.inbox.v1`), not the specification. The ANP messaging spec deliberately leaves history and read state alone, so a service that implements only the spec answers `-32601` here — and the client reports that verbatim as `unsupported_extension`, exiting 1. That is **the correct answer**, not a defect: it says the peer lacks this extension, which is a different thing from "the peer refused me" (`message_send_failed`). `msg listen`'s handshake works the same way.

## `contacts` — names for DIDs

| Subcommand | Purpose |
|---|---|
| `contacts list` | Every contact this identity has, ordered by subject |
| `contacts add <did>` | Put a DID in the book (`--remark <name>` names them; absent = keep the existing remark, and clearing one is explicit: `--clear-remark`) |
| `contacts set-remark <name> <remark>` | Rename a contact (`<name>` takes a name or a DID) |
| `contacts remove <name>` | Take a contact out of the book (name or DID) |
| `contacts resolve <name>` | Name in, DID out; `--json` gives the whole row, `subject` included |

The book does not live in a local file — it lives in the **message service's store** (extension `x_agentx.contacts.v1`), keyed by the **verified signer of the request**, so one identity's remarks are invisible to another by construction. Rows are keyed by **`subject`**, not `did`: `did update` moves the DID (it embeds a key fingerprint), so a remark hung on the DID would silently vanish on a key rotation.

`resolve` is **the one to reach for from a script**: name in, DID out. A DID-shaped argument is **returned as-is** (no network, no store read). `add` refuses a non-DID **before opening any identity** — otherwise it would store a row keyed by a literal string, an entry that can never be sent to and that no DID will ever match.

**Receiving a direct message also files the sender**, with no remark, and **never touches an existing one** — an incoming letter says nothing about what to call someone. So `contacts list` doubles as "who has ever written to me".

## `group` — groups

| Subcommand | Purpose |
|---|---|
| `group create` | Create a group (`--name`, `--policy <json>` shallow-merged onto the P4 §7.1 recommended structure) |
| `group info <group_did>` | View a group's state and policy |
| `group members <group_did>` | List members (`--names` also fetches each member's own name from their host) |
| `group join` / `group leave <group_did>` | Join / leave |
| `group send <group_did> (--text <s> \| --body <json>)` | Send a message to the group |
| `group update-profile <group_did> --name <name>` | Rename **the group itself** (P4 §7.4) |
| `group set-remark <group_did> [<remark>]` | Set a group name **only you can see**; `--clear` is the inverse |

A group's default policy is `open-join`; `admission_mode` inside `--policy` accepts only `admin-add` / `open-join`, and an out-of-set value is refused **before any network call**. Joining a group that is not `open-join` is refused by the service with `policyViolation` (3003) — that is the group's policy speaking, not a client fault.

**`update-profile --name` and `set-remark` are not the same thing**: the former writes the group's **own** name, stored on the group's host and the same for everyone; the latter sets one **only you can see**, stored in a separate table in the service (extension `x_agentx.group_remarks.v1`), which `group info` prints on the line below `name:`. In `members`, a member the address book knows is followed by **the remark you gave them** (names hang on `subject`, so a peer's key rotation does not lose them).

## `group e2ee` — end-to-end encrypted groups

| Subcommand | Purpose |
|---|---|
| `group e2ee publish` | Publish this device's KeyPackage so others can add it |
| `group e2ee get-key-package` | Fetch a peer device's published KeyPackage (`--target-did`, `--target-device`) |
| `group e2ee create <group_did>` | Initialise the group's MLS state with this device |
| `group e2ee add` / `remove <group_did>` | Add / remove one device's leaf (`--member-did`, `--member-device`) |
| `group e2ee send <group_did> (--text \| --body)` | Encrypt a message and have the service order it |

These hit P6 `anp.group.e2ee.v2`. `create` / `add` / `remove` share one three-phase shape (prepare → send → finalize or abort, §13.6): a service refusal aborts, while a transport failure is left to the crate's `reconcile_pending_v2` — at that point whether the service received it is unknown. `send` is the only one that is **not** three-phase. None of these control methods is treated as success unless the answer says `published: true` / `created: true` / `accepted: true`. `group e2ee send --content-type` is the type of the **encrypted content**, which is a different thing from the outer `meta.content_type` that `msg send` has pinned by the spec.

## `anp` — the application layer

| Subcommand | Purpose |
|---|---|
| `anp show` | Print this identity with the `subject` and the current `did` laid out as a pair |
| `anp sign --target <uri>` | Compute the whole ANP-02 request for a URL (body + signature headers + DID document), **sending nothing** |
| `anp login --target <uri>` | Sign, POST, and take back the credential the application server issues (`--nonce`, `--session-ttl`, `--no-save-session`, `--json`) |

The `anp` family hits **the application's own login endpoint**, not the message service — that is why it is split off from `msg`. Both `show` and `sign` **do not touch the network**.

`anp login` answers a 401 challenge once, and only re-signs when the server names a **different** nonce. A **409 `did_superseded` is a conclusion** rather than a refused proof: it does not take the "login failed" path, and the client decides which DID counts using **its own** chain. The token is taken from `Authentication-Info` or the body and cached in `session.json`, keyed by **`host:port`**; a failed write only warns, because the token is already in hand.

## `me` — the host's profile for this identity

| Subcommand | Purpose |
|---|---|
| `me show` | The profile the host holds for this identity, plus the document it serves |
| `me set` | Change one or more fields: `--name` / `--bio` / `--avatar` / `--profile-url` (**at least one**) |

This family is **not part of ANP**: the protocol has no display name at all. The profile lands on the **host that serves this DID**, and only the fields you name are sent, so changing a nickname does not wipe the avatar. It and `did publish` are the **only** two consumers of the cached bearer token.

## `discover` and `version`

| Subcommand | Purpose |
|---|---|
| `discover <endpoint>` | Ask an ANP message service what it can do (`anp.get_capabilities`, P1 §8.2) |
| `version` | Print the version (`--json` gives `{"version": …}`); the same fact as `--version` |

`anp.get_capabilities` is the only method that **needs no auth**, so `discover` needs no identity and is the cheapest "is this endpoint alive, and is it this protocol" check. A bare host gets `/anp-im/rpc` appended.

```bash
agentx-cli discover http://127.0.0.1:8787
```

## Next steps

- [RPC methods](/en/reference/rpc) — the methods these commands call underneath.
- [Realtime subscription](/en/reference/stream) — the wire protocol of `msg listen`.
- [Quickstart](/en/guide/quickstart) — run one message through end to end from scratch.
