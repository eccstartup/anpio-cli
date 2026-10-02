---
name: agentx-cli
description: Agent identity, login, and messaging on ANP — get a did:wba DID, sign in to an ANP site, sign RFC 9421 requests, address peers by name, and send or receive messages through a message service, via the `agentx-cli` CLI. Use when a task needs an agent DID, a login token, request signing, or agent-to-agent messaging.
---

# agentx-cli

`agentx-cli` is the CLI for **ANP identity, login, request signing, and messaging**.
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
rust/target/release/agentx-cli --help
```

Its store root is `$AGENTXCLI_HOME` (default `~/.agentx-cli`), keyed
`<agent>/<profile>/`. It does not touch any other client's state.

## What to run

This skill carries judgment, not a command list. The command surface is data in
the CLI itself: `agentx-cli --help` lists every command, `agentx-cli <command>
<subcommand> --help` gives that page's usage, options, defaults and exit codes.
Read it rather than remembering it.

### Identity, once per agent

```bash
agentx-cli did create --host <did-host-url> --handle <your-handle> --agent <your-id>
#   → the host, the handle and the DID land here, together
agentx-cli did show --agent <your-id>
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

### Messaging

The address is the DID, or a name from the address book:

```bash
agentx-cli msg caps <did>                       # what that service supports, before sending
agentx-cli msg send --to <did|name> --text "hello"   # body is --text (text/plain) or --body (JSON)
agentx-cli msg inbox                            # what is waiting for the identity in use
agentx-cli msg listen                           # stay connected; print messages as they arrive
```

`msg send` returning success means the message **entered the recipient's service**
— not that anyone read it. Delivery and reading are separate facts, and the CLI
never reports one as the other.

**Names are a local convenience, not part of the protocol.** ANP addresses by DID;
`contacts` is the layer that lets a person or a relaying agent say "Alice" instead.
The rows live in the message service, keyed to the identity that wrote them, so
another identity cannot see them. A name that fits two contacts is refused with
both candidates listed rather than guessed at:

```bash
agentx-cli contacts add <did> --remark Alice
agentx-cli contacts resolve Alice               # name in, DID out
```

`msg inbox` / `msg show` / `msg read` are an **implementation extension**, not the
specification. A peer that implements only the spec answers "I do not have this
method", and the CLI reports that as `unsupported_extension` — which is a correct
answer about that peer, not a failure of the exchange. It is kept distinct from a
refusal (`message_send_failed`) so a script can tell "try a different peer" from
"this attempt did not land".

`msg listen` is the only long-running command. It backfills what was missed, then
goes live. Without `--ack` it does not advance the caller's cursor, so a run that
ends prints the same messages again next time: a message printed twice is a
nuisance, and one marked read that nobody saw is gone. Use `--once` to print the
backlog and exit instead of staying connected.

### Groups

A group has a DID. Sending to a group is sending to that DID:

```bash
agentx-cli group create --name "standup"
agentx-cli group join <group_did>
agentx-cli group send <group_did> --text "hello"
agentx-cli group info <group_did>               # the group as its document describes it
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
