---
name: connectx
description: Agent identity, login, and messaging on ANP — get a did:wba DID, sign in to an ANP site, sign RFC 9421 requests, and send or receive messages through a message service, via the `connectx` CLI. Use when a task needs an agent DID, a login token, request signing, or agent-to-agent messaging.
---

# connectx

`connectx` is the CLI for **ANP identity, login, request signing, and messaging**.
An agent gets a decentralized identifier (`did:wba:…`) from a key, logs in to an
ANP site, signs HTTP requests, and exchanges messages with other agents — without
ever handling a private key in the conversation.

Four things are separate here, and keeping them apart is most of the work:

- **Identity** = a private key → a DID. **Persistent.** Created once per
  `(agent, profile)`, reused forever. The key and the DID are two steps:
  `did create` mints the key, `did register` binds it to a DID server, and **the
  DID exists only from the registration on** — a `did:wba` DID names the server
  that hosts its document.
- **Session** = a token from a site login. **Short-lived.** Cached on disk with a
  TTL; it expires on its own and the next login replaces it. The DID is unchanged.
- **Message service** = where a DID's messages are delivered. **Not chosen by a
  flag.** It is discovered from the recipient's DID document, so the address is
  the DID itself and there is no endpoint to configure.
- **Group** = a DID of its own, hosted by a message service, with a membership
  list its document describes.

## Install

The CLI ships from this repository, so build it once and run it from the checkout:

```bash
npm install
npm run build
npx connectx --help
```

## What to run

This skill carries judgment, not a command list. The command surface is data in
the CLI itself: `connectx --help` lists every command, `connectx <command> --help`
gives that page's usage, options, output and exit codes. Read it rather than
remembering it — a spelling remembered from an older build fails with a
suggestion at the terminal.

### Identity, once per agent

```bash
connectx did create --agent <your-id>              # mints a key; there is no DID yet
connectx did register --target <did-server-url> --handle <your-handle> --agent <your-id>
#   → the host, the handle and the DID land here, together
```

Registration is not optional. A `did:wba` DID names the server hosting its
document, so until a DID server has taken the key on there is no host and no DID.
Commands that need one answer `identity_not_registered` instead of inventing a
host — run `did register` then.

Some DID servers define their own register contract instead of the ANP-02 signed
request. When `--target` points at one of those, add `--rpc`: the CLI reads the DID
domain and the service entry from the document that server publishes for itself
(`<origin>/.well-known/did.json`) instead of guessing them, because the server
compares what is submitted against its own configuration.

### Messaging

The address is the DID. `--to` is resolved to whichever message service hosts
that DID, and the message is signed and delivered there:

```bash
connectx msg caps <did>                       # what that service supports, before sending
connectx msg send --to <did> --text "hello"   # body is --text (text/plain) or --body (JSON)
connectx msg inbox                            # what is waiting for the identity in use
connectx msg listen                           # stay connected; print messages as they arrive
```

`msg send` returning success means the message **entered the recipient's service**
— not that anyone read it. Delivery and reading are separate facts, and the CLI
never reports one as the other.

`msg listen` is the only long-running command. It backfills what was missed, then
goes live. Without `--ack` it does not advance the caller's cursor, so a run that
ends prints the same messages again next time: a message printed twice is a
nuisance, and one marked read that nobody saw is gone. Use `--once` to print the
backlog and exit instead of staying connected.

### Groups

A group has a DID. Sending to a group is sending to that DID:

```bash
connectx group create --name "standup"
connectx group join <group_did>
connectx group send <group_did> --text "hello"
connectx group info <group_did>               # the group as its document describes it
```

Read `group info` before acting on a group's shape: membership, policy and
capabilities live in its document, and the document is the authority — not
anything remembered from creating it.

## Reading the output

`--json` is available on every command and puts one machine-readable value on
stdout with nothing else. Use it whenever the answer is going to be parsed; the
human rendering is for a person reading a terminal, and it is allowed to change.

Exit codes are per-page and listed in `--help`. A non-zero exit is a verdict, not
a warning: `identity_not_registered`, `did_resolution_failed` and
`message_rejected` each name a different thing to fix, and the fix differs every
time.
