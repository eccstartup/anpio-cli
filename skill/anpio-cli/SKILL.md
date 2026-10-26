---
name: anpio-cli
description: Agent identity, login, and messaging on ANP — get a did:wba DID, sign in to an ANP site, sign RFC 9421 requests, address peers by name, and send or receive messages through a message service, via the `anpio-cli` CLI. Use when a task needs an agent DID, a login token, request signing, or agent-to-agent messaging.
---

# anpio-cli

`anpio-cli` is the CLI for **ANP identity, login, request signing, and messaging**.
An agent gets a decentralized identifier (`did:wba:…`) from a key, logs in to an
ANP site, signs HTTP requests, and exchanges messages with other agents — without
ever handling a private key in the conversation.

Four things are separate here, and keeping them apart is most of the work:

- **Identity** = a private key → a DID. **Persistent.** Created once per
  `(agent, profile)`, reused forever. A `did:wba` DID names the server that hosts
  its document, so `did create` both mints the key and publishes the document: the
  host is named on the command line, and the DID exists from that moment.
- **Session** = a token from a host or site login. **Short-lived.** Cached on disk
  with a TTL; it expires on its own and the next login replaces it. The DID is
  unchanged. Only two commands ever read it back: `did publish` and `me`.
- **Message service** = where a DID's messages are delivered. **Not chosen by a
  flag.** It is discovered from the recipient's DID document, so the address is
  the DID itself and there is no endpoint to configure.
- **Group** = a DID of its own, hosted by a message service, with a membership
  list its document describes.

## Install

The CLI ships from this repository, so build it once and run it from the checkout:

```bash
cargo build --release --manifest-path rust/Cargo.toml
rust/target/release/anpio-cli --help
```

Its store root is `$ANPIOCLI_HOME` (default `~/.anpio-cli`), keyed
`<agent>/<profile>/`. It does not touch any other client's state.

## What to run

This skill carries judgment, not a command list. The command surface is data in
the CLI itself: `anpio-cli --help` lists every command, `anpio-cli <command>
<subcommand> --help` gives that page's usage, options, defaults and exit codes.
Read it rather than remembering it.

### Identity, once per agent

```bash
anpio-cli did create --host <did-host-url> --handle <your-handle> --agent <your-id>
#   → the host, the handle and the DID land here, together
anpio-cli did show --agent <your-id>
```

`did create` takes a handle, not a target-plus-handle: a `did:wba` DID names the
server hosting its document, so the host is part of the DID from the start. The
hosts it may name are held to a did:web allowlist; another host is refused rather
than reached. If publishing fails after the key is on disk, the identity is still
there — `did list` shows it as `not registered`, and `did register` retries.

Once the document has moved on the host, `did publish` re-signs the local copy and
pushes it over the host's authenticated control plane. It needs the bearer token
that `did create` / `did register` / `anp login` cached, so deleting that cache is
what "this step never happened" looks like.

### Identity whose key is held by anpio-key

When the private key lives in the local `anpio-key` daemon instead of this store,
adopt the DID rather than creating one:

```bash
anpio-cli did attach-anpio-key --did <did> --agent <your-id>
#   → the identity is written only after the daemon answers with a document that
#     names this DID and carries the key; there are no private bytes in the store
```

What works: `anp sign`, `anp login`, `did register`, `did publish`, `did show`,
`anp show` — all of them sign whole ANP-02 HTTP requests, which is exactly what
the daemon offers.

What is refused outright: `msg`, `group` (including E2EE), and `did update`. Their
proofs are over bytes this CLI assembles itself (origin proofs, MLS device keys, a
retirement document), and `anpio-key` has no "sign arbitrary bytes" command. The
refusal names the commands that do work; do not try to work around it.

### Messaging

The address is the DID, or a name from the address book:

```bash
anpio-cli msg caps <did>                       # what that service supports, before sending
anpio-cli msg send --to <did|name> --text "hello"   # body is --text (text/plain) or --body (JSON)
anpio-cli msg inbox                            # what this machine holds for the identity in use
anpio-cli msg history <peer_did>               # one thread, oldest first, by peer DID
anpio-cli msg show <message_id>                # one row
anpio-cli msg read <message_id>                # mark read — a local write
anpio-cli msg fetch                            # the one read that goes online: pull in what the service still holds
anpio-cli msg listen                           # stay connected; print messages as they arrive
```

`msg send` returning success means the message **entered the recipient's service**
— not that anyone read it. Delivery and reading are separate facts, and the CLI
never reports one as the other.

**Reading is local.** `msg inbox` / `msg history` / `msg show` / `msg read` open this
machine's own record: they never open a connection, so they answer with the service
down. `msg fetch` is the one command that goes online, and it is a **write** — it
pulls in what the service still holds, and its own first line of output says so when
it cannot. The record is a file of plaintext messages: treat it the way you would
treat the messages themselves, and do not expect a read to be reproducible somewhere
else. `msg history` takes a DID, not a name — turn a name into a DID with
`contacts resolve` first.

**Names are a local convenience, not part of the protocol.** ANP addresses by DID;
`contacts` is the layer that lets a person or a relaying agent say "Alice" instead.
The rows live in the message service, keyed to the identity that wrote them, so
another identity cannot see them. A name that fits two contacts is refused with
both candidates listed rather than guessed at:

```bash
anpio-cli contacts add <did> --remark Alice
anpio-cli contacts resolve Alice               # name in, DID out
```

`msg listen` and `msg fetch` go through an **implementation extension** of this
service (`x_agentx.inbox.v1`), not the specification. A peer that implements only the
spec answers "I do not have this method", and the CLI reports that as
`unsupported_extension` — which is a correct answer about that peer, not a failure of
the exchange. It is kept distinct from a refusal (`message_send_failed`) so a script
can tell "try a different peer" from "this attempt did not land". The local reads
above never reach a peer at all, so they cannot fail that way.

`msg listen` is the only long-running command. It backfills what was missed, then
goes live. Every message it shows is also written to the local record. Without
`--ack` it does not advance the caller's cursor, so a run that ends prints the same
messages again next time: a message printed twice is a nuisance, and one marked read
that nobody saw is gone. `--ack` says "I have this one" to the service **and** marks
the row it just wrote read — the two are one act, not two. Use `--once` to print the
backlog and exit instead of staying connected.

### Groups

A group has a DID. Sending to a group is sending to that DID:

```bash
anpio-cli group create --name "standup"
anpio-cli group join <group_did>
anpio-cli group send <group_did> --text "hello"
anpio-cli group info <group_did>               # the group as its document describes it
```

Read `group info` before acting on a group's shape: membership, policy and
capabilities live in its document, and the document is the authority — not
anything remembered from creating it. Joining is refused with `policyViolation`
when the group does not admit joiners; that is the group's policy speaking.

A group carries two different names and they are not interchangeable. `group
update-profile --name` changes the group's **own** name, on its host, for
everyone. `group set-remark` sets a name **only the caller sees**, in the
service's own table, printed by `group info`. The address book is a third thing
again: it is keyed by a member's `subject` so a peer's key rotation does not lose
the remark.

## Reading the output

`--json` is available on every command and puts one machine-readable value on
stdout with nothing else. Use it whenever the answer is going to be parsed; the
human rendering is for a person reading a terminal, and it is allowed to change.

A failure is one line on stderr, `Error: <stable code>: <prose>`, exiting 1. The
codes are stable and spelled the same way as the TS client's, so a caller branches
on them rather than parsing the prose. Exit codes are per-page and listed in
`--help`; `did resolve` is the one command that answers with a code rather than a
verdict (**2** the document is no longer current, **3** the update chain did not
verify).
