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

### Registering on awiki.me

The email round trip is **inside** `did create`, not a second command:

```bash
anpio-cli did create --host awiki.me --handle <handle> --email <address> --agent <id>
```

In order: read the host's service document, precheck the handle, mint keys, build
and sign the document, send the verification email, poll `email-status` every 5 s
for up to 5 minutes, then `register` with the same document. When the person says
the email arrived there is nothing left for you to run — the command is already
polling. Do not start a second `did create` to "continue"; it would look for a new
handle and a new key.

**If it timed out**, the key and signed document are kept together in
`$ANPIOCLI_HOME/pending.json`. After the address is verified, resume with the
command the failure itself prints:

```bash
anpio-cli did register --agent <id> --email <address>
```

That publishes the stored document as it is — correct when the only thing that
failed was the wait. It does **not** re-send the email or wait again, and it does
not re-sign: use it only once the address is verified. `--email` is not stored
with the identity, so a retry has to pass it again.

**If the pending record was written by an older build** — or belongs to
`--key anpio-key`, on a machine without the protected service — do not register
it. Rebuild and re-sign with the same key instead:

```bash
anpio-cli did create --host awiki.me --handle <handle> --email <address> \
  --agent <id> --reuse-key [--key anpio-key]
```

`did register` refuses a pending anpio-key record and names this command. Reuse
is what makes the retry cost a name, not a key; `pending.json` keeps the key
across every failure below.

Two host errors name the **document**, not the handle or the email:

- `-32004 challenge is required` — the root proof carried no `challenge`.
- `-32004 DID document or deviceManifest is invalid` (`data: null`) — the proof
  covered a different input than the one published.

Both are fixed in this build: the root proof now carries the bare hostname as
`domain` and a fresh 32-hex `challenge`, and the proof object **keeps** the
document's `@context` (the host reads proof options as stored; stripping it signs
one input and publishes another). If either error appears, the pending record is
older than the fix — rebuild it with `--reuse-key`, or delete `pending.json` and
run `did create` again. A hand-written client calling the RPC directly has to
send `x-awiki-client-version: awiki-cli/0815/1.0.58` as well, or the host refuses
the email calls.

### Identity whose keys are held by anpio-key

The default line mints a key in this store — a `0600` file any code running as
your user can read. The other line puts the keys behind a **protected
[`anpio-key`](https://github.com/eccstartup/anpio-key) service**: a system-level
daemon under its own account, whose sign socket the operator's account cannot
open. The store then records the key and grant ids, and holds no private bytes
at all. Three keys sit in the service because awiki accepts only a one-device
vNext document: an Ed25519 root (`#key-1`), an Ed25519 device signing key
(`{agent}/{profile}-sign`) and an X25519 device agreement key
(`{agent}/{profile}-agreement`).

**The boundary is a property of the install.** A machine that has the protected
service gets its identity provisioned when an existing identity is adopted into
it; `did create` is not the way in (see below). Adoption is an administrator
action in their own terminal, because the passphrases are typed there and never
appear as an argument or an environment variable:

```bash
sudo ./install.sh --adopt --identity <identity.json> \
  --cli-binary <anpio-cli> --cli-sha256 <sha256> \
  --target https://awiki.me/anp-im/rpc \
  --target https://awiki.me/user-service/v1/did-auth/rpc
#   → the three keys move into the service vault; the DID and its published
#     document are not changed; the roles and policies are confirmed; grants are
#     issued to the agent account; an agent record is written under
#     /Library/ANPIOKey/agent/home
```

A new identity's keys cannot be provisioned into the service yet, so
`did create --key anpio-key` **refuses** on a machine that has the service
installed, and names the adopt command. It never starts a second daemon and
never falls back to a local key.

Keys are used by the **agent account**, not the administrator: the sign socket
is `_anpio:_anpio_sign`, the agent is in the group, and the administrator's
account deliberately is not. Run the CLI as that account:

```bash
sudo -u _anpagent env HOME=/Library/ANPIOKey/agent/home \
  TMPDIR=/Library/ANPIOKey/agent/home/tmp \
  /Library/ANPIOKey/bin/anpio-cli did show --agent <your-id>
```

**Recovery, not creation.** `did attach` writes a new store record for a DID whose
keys the service already holds (another machine, a wiped profile) — and it is how
a freshly adopted identity appears in a different store:

```bash
anpio-cli did attach --did <did> --kid <agent>/<profile>-sign \
  --grant http=<hot-grant-id> --grant document_proof=<root-grant-id> --agent <your-id>
#   → --config defaults to the installed service; --kid must be a fragment the
#     service lists for this DID. The HTTP grant covers the hot key; the root key
#     signs the document and is not used for requests.
```

`--grant` is repeatable, each as `<purpose>=<grant-id>`: `http` covers
`SIGN_HTTP` (the Hot key) and `document_proof` covers `SIGN_DOCUMENT_PROOF` (the
Root key). A bare `--grant <id>` still means the HTTP grant. Attach asks the
service about every named grant and refuses one that has expired or run out of
uses, so it never records an identity that cannot sign. To replace a grant later —
a renewal the administrator issued while the identity already exists — record it
without touching anything else:

```bash
anpio-cli key grant <grant-id> --purpose http --agent <your-id>
anpio-cli key grant <grant-id> --purpose document-proof --agent <your-id>
```

`did show`'s first line says where the key lives:
`key: anpio-key (key <kid>, grant <id>)`. Signing then needs only the target —
`anp sign --target <url>` — or `anp login`.

Records written before keys had names find theirs again by DID fingerprint, and
say so if that lookup fails. `did attach-anpio-key` still parses as the old
spelling of the same command.

For group E2EE, add `--device <id>` naming the `{device}-sign` entry in the DID
document. Without it those commands refuse, and they say so before touching the
network — the local `{agent}/{profile}` is not a device name.

`--config <service.json>` names the protected surface explicitly (the ordinary
value is found automatically). `--key-root`/`--socket` name the legacy named-key
daemon instead, and the two cannot be combined: one identity points at one
surface, so a command can never choose between them at signing time.

`--document <file>` supplies the DID document read out of band instead of
resolving it from the DID's host — for a machine whose DNS answers through a
local proxy, which the fetch policy refuses. The file is held to the same checks
as a fetched document (its `id`, and a proof bound to the key the DID spells).
The named-key surface takes it; the protected service answers `GET_DOCUMENT`
itself.

What the protected surface adds: `anp sign`, `anp login`, `did register`, and
`did publish` sign whole ANP-02 HTTP requests; `did publish` proves the document
with `SIGN_DOCUMENT_PROOF`. When the daemon announces `SIGN_ORIGIN_PROOF`,
`msg` (except the purely local reads, which never signed), `contacts`, and
`group` send their origin proofs to the daemon. With `--device <id>` at attach
time and `SIGN_PURPOSE(device_assertion)` announced, `group e2ee` also works: the
KeyPackage binding and `send`'s device origin proof go to the daemon, which signs
under the document's `{device}-sign` key. `did show` prints `signs:` with what
the identity actually got, and a refusal always says which half is missing — the
daemon's announcement or this build.

What is refused outright: `did update`. It needs a freshly minted successor key,
which `anpio-key` cannot supply from its protected surface yet. The refusal
names the commands that do work; do not try to work around it.

**On a machine with no protected service installed**, `did create --key anpio-key`
still mints the three named keys under your account so an identity can be built
and registered first. That identity is not yet protected: adopt it into a
protected install to move the keys out of your account. Never run
`anpio-key serve --development --allow-named-key-signing` as the way to sign —
a development daemon is not a boundary.

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
service (`x_anpiocli.inbox.v1`), not the specification. A peer that implements only the
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
