---
title: RPC methods
description: "The 27 methods that POST /anp-im/rpc recognizes, grouped by Profile, with target types and the notification list."
---

# RPC methods

The control plane is `POST /anp-im/rpc`, and the payload is a JSON-RPC 2.0 envelope. **Requests**
(those with an `id`) hit this method table; what the server pushes to the client is a
**notification** (with no `id`). The stream has two more transport methods of its own; see
[Realtime subscription](/en/reference/stream).

The envelope's keys are fixed as `{meta, auth, body}`: `meta` holds addressing and signing context,
`auth` holds `origin_proof`, and `body` holds the fields of the method itself. **Not one `body`
field the spec does not define may appear**; one extra is `anp.invalid_params_shape` (1003).

## Target types

The shape of `meta.target` is decided by the method. Getting it wrong is
`anp.invalid_target_binding` (1014), not 1003:

| `targetMode` | `meta.target` | Example |
|---|---|---|
| `endpoint-local` | may be omitted | `anp.get_capabilities` |
| `agent-addressed` | `{kind:"agent", did}` | `direct.send` |
| `group-addressed` | `{kind:"group", did}` | `group.send` |
| `service-scoped` | `{kind:"service", did: <serviceDid>}` | `attachment.*`, the key cabinet |
| `self-addressed` | `{kind:"agent", did: <self>}` | Inbox-surface extension methods |

## Method table (27)

### P1 core binding

| Method | Target | Description |
|---|---|---|
| `anp.get_capabilities` | `endpoint-local` | Capability probe. **The only method that can be called anonymously**: no `target`, no `operation_id`, no body rules |

### P3 direct

| Method | Target | Description |
|---|---|---|
| `direct.send` | `agent-addressed` | Deliver a direct message. Must carry `sender_did`, `operation_id`, `message_id`, `content_type` |

### P4 groups

| Method | Target | Description |
|---|---|---|
| `group.create` | `service-scoped` | Create a group; must carry `body.group_policy` |
| `group.get_info` | `group-addressed` | Group profile; **may be anonymous** (a `private` group is trimmed by identity) |
| `group.join` | `group-addressed` | Join |
| `group.add` | `group-addressed` | Add members (`left` / `removed` are reactivated) |
| `group.remove` | `group-addressed` | Remove |
| `group.leave` | `group-addressed` | Leave |
| `group.update_profile` | `group-addressed` | RFC 7386 merge patch, validated after it is applied |
| `group.update_policy` | `group-addressed` | Same as above |
| `group.send` | `group-addressed` | Group message; only advances `group_event_seq` |

### P5 direct end-to-end encryption

| Method | Target | Description |
|---|---|---|
| `direct.e2ee.publish_prekey_bundle` | `service-scoped` | Publish a device prekey bundle |
| `direct.e2ee.get_prekey_bundle` | `service-scoped` | Fetch one; the target device is in `body.target_device_id`, and each call consumes one OPK |

The two have different idempotency keys: `get` carries `target_did` / `target_device_id` in addition
to what `publish` carries; "idempotency record + OPK allocation" must be atomic, and a retry with
the same key gets back **the same** OPK.

### P6 group end-to-end encryption (candidate)

| Method | Target | Description |
|---|---|---|
| `group.e2ee.publish_key_package` | `service-scoped` | Publish a KeyPackage |
| `group.e2ee.get_key_package` | `service-scoped` | Fetch one; three states `available → reserved → consumed` |
| `group.e2ee.create` | `service-scoped` | Create an encrypted group (the Host only records the public projection) |
| `group.e2ee.add` | `group-addressed` | Membership change; `commit_b64u` / `welcome_b64u` / `ratchet_tree_b64u` forwarded as-is |
| `group.e2ee.remove` | `group-addressed` | Same as above |
| `group.e2ee.send` | `group-addressed` | Encrypted group message; enters the Device Delivery Queue |

> [!NOTE]
> P6 is currently a **candidate**: the whole capability does not appear in the stable Profile list
> of `anp.get_capabilities` until the MLS `ExtensionType` code point registration lands.

### P7 attachments

| Method | Target | Description |
|---|---|---|
| `attachment.create_slot` | `service-scoped` | Open an upload slot, giving `upload_uri` + `commit_token` |
| `attachment.commit_object` | `service-scoped` | Verify size + digest, store `object_uri` |
| `attachment.abort_object` | `service-scoped` | Abandon the slot (terminal state) |
| `attachment.get_download_ticket` | `service-scoped` | Issue a short-lived download ticket, running seven checks |

The first three **do not** grant download rights; a Grant is produced only when the message carrying
the manifest is accepted.

### Inbox surface (implementation extension `x_anpiocli.inbox.v1`)

| Method | Target | Description |
|---|---|---|
| `inbox.get` | `self-addressed` | List messages to receive (`limit`, `skip`, `include_read`, `device_id`) |
| `inbox.mark_read` | `self-addressed` | Mark as read |
| `message.get_batch` | `self-addressed` | Fetch a batch by id, at most 100 at a time |
| `sync.delta` | `self-addressed` | Fill in by device cursor; it is part of the subscription handshake |

This group **is not spec**: the spec deliberately does not manage history or read state, and a
service that implements only the spec answers `unsupported_extension`. It is not a spec capability
either, so it does not go into `anp.get_capabilities`.

## Notifications (server → client, no `id`)

| Notification | When |
|---|---|
| `direct.incoming` | A direct message lands in the recipient's queue |
| `group.incoming` | A group message lands in a member's queue |
| `group.state_changed` | Membership change / profile or policy change; the replayable source is `group_events` |
| `group.e2ee.notice` | P6 cryptographic notices |

`direct.incoming` is **not** cross-domain transport — it is the last hop within the same domain,
from "ingress service → recipient endpoint". What is forwarded across domains is always the original
business method. See [Federation and cross-domain](/en/guide/federation).

## Idempotency

Accounted by `(sender_did, target_scope, method, operation_id)`:

- Replaying the same key returns **the same** result and does not write to the database twice.
- The same key with different content → `anp.idempotency_conflict` (1008).
- A method that does not change state (such as `anp.get_capabilities`) has no `targetScope` and does
  not enter the ledger.

## Next steps

- [Error codes](/en/reference/errors) — the code segments of each Profile.
- [HTTP endpoints](/en/reference/endpoints) — routes, status codes and the capability list.
- [Realtime subscription](/en/reference/stream) — which connection notifications go out on.
