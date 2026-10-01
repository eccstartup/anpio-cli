---
title: Quickstart
description: "Install AgentX from scratch, run a message service, and send your first message with connectx."
---

# Quickstart

This page walks the complete loop of a local development environment: install dependencies, build, start a message service, prepare an identity, send a message, and fetch it back.

```mermaid
flowchart LR
  A["Install dependencies<br/>npm install"] --> B["Build<br/>npm run build"]
  B --> C["Start message service<br/>agentx"]
  B --> D["Prepare identity<br/>connectx did create"]
  D --> E["Query capabilities<br/>connectx msg caps"]
  E --> F["Send message<br/>connectx msg send"]
  F --> G["Fetch message<br/>connectx msg inbox / msg listen"]
```

## Prerequisites

- **Node.js**: the server requires **≥ 24.16.0** (it uses the built-in `node:sqlite`, and must avoid a decoder bug that is only fixed in 24.16.0 and 26.1.0); `core` and `cli` only require **≥ 22.12.0**.
- No Docker, no external database: the server uses SQLite, and attachment objects land in a local directory.

## 1. Install and build

```bash
npm install
npm run build
```

Build artifacts go in each package's `packages/*/dist/`. After that you can call the entry points in dist directly:

```bash
node packages/service/dist/main.js    # or npx agentx
node packages/cli/dist/cli.js         # or npx connectx
```

## 2. Start a message service

The server has **no command-line flags**; all configuration comes from environment variables. The minimal tier only needs a listen address:

```bash
AGENTX_LISTEN=127.0.0.1:8787 node packages/service/dist/main.js
```

On startup it prints who it is, where it is listening, and which database it uses:

```
AgentXAgent listening on http://127.0.0.1:8787
  service did   did:web:127.0.0.1%3A8787
  rpc           http://127.0.0.1:8787/anp-im/rpc
  database      ./agentx.db
  objects       ./objects
  outbound      unsigned (no AGENTX_KEY_FILE)
  did hosts     none (only inline DID documents will verify)
```

> [!WARNING]
> The empty `did hosts` line is a **deliberate secure default**: when no hosts are named, the service
> only accepts inline DID documents carried in with the request, and any outbound resolution is rejected.
> For local integration testing you must name the hosts explicitly; see [Deployment and configuration](/en/guide/deploy).
> Note this is about integration testing the **message service**.

## 3. Prepare an identity

`connectx` identities are stored under `~/.connectx/`, isolated by agent + profile. Create one:

```bash
npx connectx did create
npx connectx did show
```

`did create` only generates a key locally and seals it, without contacting any service; `did show` prints the identities already registered in `identity.json`. For someone to be able to **find you by DID**, you also need to register a handle on a DID Service:

```bash
npx connectx did register --target https://did.example --handle alice
```

> [!NOTE]
> Registering with a DID Service is not a service this repository provides; it is the client-side
> capability for it. The message service itself does not host DID documents, it only resolves them.

## 4. Query the other party's capabilities

Before sending, ask what Profiles the other party supports:

```bash
npx connectx msg caps did:wba:...
```

It calls `anp.get_capabilities` and returns the other party's supported `profiles[]` / `securityProfiles[]`. This is how you troubleshoot `anp.unsupported_profile`.

## 5. Send a message

```bash
npx connectx msg send --to did:wba:... --text "hello"
```

`msg send` walks through all the discovery and signing steps the spec requires in a single command: resolve the recipient's DID document → take the single `ANPMessageService` entry → build `direct.send` → perform RFC 9421 signing → POST to `serviceEndpoint`. A success return means **it has entered the other party's ingress service processing boundary**; it does not mean the other party has read it.

When resending the same message, reuse the same `operation_id`, otherwise the server will treat it as two:

```bash
npx connectx msg send --to did:wba:... --text "hello" --operation-id op-42
```

> [!TIP]
> If the recipient's host is the local machine but not written as loopback, add `--allow-private-host <host>` to
> allow it through; this is the CLI's private-network gate, off by default.

## 6. Fetch messages

**Pull once**:

```bash
npx connectx msg inbox                 # 20 by default
npx connectx msg show <message_id>     # view one
npx connectx msg read --all            # mark all as read
```

**Resident receive** (the only resident process in the CLI):

```bash
npx connectx msg listen                # scrolls like an IM in a TTY
npx connectx msg listen --once         # exits once caught up, equivalent to inbox
npx connectx msg listen --json         # non-TTY output as NDJSON, for scripts to consume
```

By default `msg listen` does **not** ack automatically: forgetting to ack only replays once on the next reconnect, and the message is still there; acking automatically while no one has looked makes the message disappear forever. To enable it, add `--ack`.

## Next steps

- [Direct messages](/en/guide/messages) — the fields, signing, and idempotency of `direct.send`.
- [Real-time receive](/en/guide/realtime) — the subscription stream's cursor and "no gaps, no duplicates."
- [connectx commands](/en/reference/cli) — all commands and flags.
