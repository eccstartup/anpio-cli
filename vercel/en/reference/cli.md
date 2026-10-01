---
title: connectx commands
description: "The complete command surface of the connectx command-line client — did / anp / msg / group / agent / version — with exit codes and output conventions."
---

# connectx commands

`connectx` is this implementation's command-line client, shipped in the `@agentx/cli` package. Every command has the form `connectx <command> [subcommand] [arguments] [options]`, and `connectx help [<command> [<subcommand>]]` prints the same description (the authority on the command surface is exactly what it prints).

## Output and exit code conventions

- `--json` turns stdout into machine-readable output (for most commands a single JSON object; for streaming commands one JSON object per line). **stderr carries connection status, progress and errors**, so `> file` gets you pure results.
- Human-readable output is colored, on a TTY only.
- Exit codes are not just 0/1: `did resolve` uses **2 / 3** to distinguish "no longer current" from "chain not verified". The values for each subcommand are in the sections below.

## Global options

| Option | Description |
|---|---|
| `--agent <id>` | Which agent identity to act as; defaults to the current agent, otherwise auto-detected |
| `--profile <name>` | The identity profile within the agent; defaults to `default` |
| `--wallet <cli\|web3>` | Where the signing key lives; defaults to `cli` |
| `--key <spec>` / `--curve` | `cli` wallet: give key material directly instead of reading the identity store |
| `--address` / `--chain-id` | `web3` wallet: account address and CAIP-2 chain id (together they are the identity) |
| `--password-file` / `--password-stdin` | Source of the key passphrase |
| `--json` | Machine-readable output |

`--allow-private-host <host>` appears on commands that derive a host: the target host comes from an **identifier** rather than a flag, so non-loopback local hosts need to be explicitly allowed.

## `did` — identity

| Subcommand | Purpose |
|---|---|
| `did create [options]` | Generate an identity (`--curve`, `--force`) |
| `did show [options]` | Print the current identity |
| `did list [options]` | List stored identities |
| `did register --target <uri> --handle <name>` | Register a handle with a DID server |
| `did resolve <did>` | Fetch a DID document; `--chain` walks the update chain and reports the assurance level hop by hop |
| `did update --target <uri>` / `did update --resume` | Submit a DID update, or finalize an already-staged successor |
| `did restore` | Restore (**not implemented**; invoking it exits with 1) |

The exit codes of `did resolve --chain` are worth memorizing separately: **0** current; **2** no longer current (the chain moved past, or the document is a retirement statement); **3** update chain not verified (`did_chain_broken`); **1** other.

## `anp` — web login

| Subcommand | Purpose |
|---|---|
| `anp show` | Print the current identity (with `--wallet web3` it can be read from the wallet) |
| `anp login --target <uri>` | Perform a signed login against the site's ANP login endpoint and exchange it for a session (`--nonce`, `--max-age`, `--no-save-session`, `--yes`, `--json`) |
| `anp sign --target <uri>` | Compute the signature header for a URL only, without sending |

The `anp` family hits **the application's own login endpoint**, not the message service — that is why it is split off from `msg`.

## `msg` — message service

| Subcommand | Purpose |
|---|---|
| `msg send --to <did> (--text <s> \| --body <json>)` | Deliver a direct message |
| `msg caps <did>` | Ask what the other side's message service supports |
| `msg inbox` | List messages pending for this identity (`--limit`, `--include-read`) |
| `msg show <message_id>` | Print the full content of one message |
| `msg read <message_id>...` / `msg read --all` | Mark as read |
| `msg listen` | Keep the connection open and print messages in arrival order |

`msg send`'s `--content-type` defaults to match the body form: `--text` is `text/plain`, `--body` is `application/json`. Exit codes: **0 = the service accepted it**, **1 = rejected / undeliverable / invalid arguments**.

> [!NOTE]
> `msg inbox` / `msg show` / `msg read` hit an **implementation extension**, not the specification. The ANP messaging spec deliberately leaves history and read state alone, so a service that implements only the spec will answer `unsupported_extension` here — that only means it does not have this extension, not whether it can deliver messages.

The four options of `msg listen` are worth spelling out:

| Option | Description |
|---|---|
| `--device <id>` | The name this client queue is stored under on the server; defaults to `<agent>/<profile>` |
| `--since <seq>` | Start from this delivery number instead of the cursor the server remembers |
| `--ack` | Mark each message read as it is printed; **off by default** |
| `--once` | Print the catch-up portion and exit, without staying resident |

> [!IMPORTANT]
> Without `--ack`, the server does not push the cursor past the printed position — so after one run ends, the next run **prints the same batch of messages again**. This is a deliberate choice: duplicate printing is noise, whereas a message marked read that nobody saw is genuinely lost. `--ack` should only be used for pipelines that have "already persisted to disk".

The stream address is **derived** from the message service endpoint in the DID document: replace the last path segment with `stream`. A service that mounts the stream elsewhere cannot be reached by this command.

## `group` — groups

| Subcommand | Purpose |
|---|---|
| `group create [options]` | Create a group |
| `group info <group_did>` | View group info |
| `group members <group_did>` | List members |
| `group join <group_did>` | Join |
| `group leave <group_did>` | Leave |
| `group send <group_did> (--text <s> \| --body <json>)` | Send a message to the group |

## `agent` and `version`

| Subcommand | Purpose |
|---|---|
| `agent show` / `agent list` | Current agent / all agents |
| `agent use <id>` | Switch the current agent |
| `version` | Print the version |

## Next steps

- [RPC methods](/en/reference/rpc) — the methods these commands call underneath.
- [Realtime subscription](/en/reference/stream) — the wire protocol of `msg listen`.
- [Quickstart](/en/guide/quickstart) — run one message through end to end from scratch.
