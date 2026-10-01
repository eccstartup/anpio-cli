---
title: Error codes
description: "Shared segments and each Profile's private segments; which codes carry an anp_code and which use the real HTTP status code."
---

# Error codes

A rejection looks like this: a JSON-RPC `error` object with a numeric `code`, and **when `code`
falls in the ANP custom range (1000+)**, `error.data.anp_code` is always present; the client
branches on it, not on the `message` text.

```json
{ "jsonrpc": "2.0", "id": 1,
  "error": { "code": 1003, "message": "…",
             "data": { "anp_code": "anp.invalid_params_shape" } } }
```

Two rules:

- **Once inside the application layer, it is always HTTP 200**, with the error inside the envelope.
  A non-2xx is a **response**, not an exception.
- **An outer HTTP authentication failure** uses the real status code (`401`, with
  `WWW-Authenticate`), because at that layer there is not yet a JSON-RPC envelope. The data plane is
  the other exception; see [HTTP endpoints](/en/reference/endpoints).

## Standard JSON-RPC codes

These do not carry an `anp_code`; they are distinguished by `message`.

| Code | Meaning |
|---|---|
| `-32700` | Parse error |
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |

## Segment table

| Segment | Belongs to |
|---|---|
| 1000–1021 | P1 shared errors |
| 2000–2007 | P3 direct (`direct.*`) |
| 3000–3010 | P4 groups (**no 3004**) |
| 4000–4012 | P5 direct E2EE |
| 5000–5013 | P6 group E2EE |
| 6000–6013 | P7 attachments |

## Segment 1000: shared (P1)

| Code | `anp_code` |
|---|---|
| 1000 | `anp.invalid_request_id` |
| 1001 | `anp.unsupported_profile` |
| 1002 | `anp.unsupported_security_profile` |
| 1003 | `anp.invalid_params_shape` |
| 1004 | `anp.batch_not_supported` |
| 1005 | `anp.unauthorized` |
| 1006 | `anp.forbidden` |
| 1007 | `anp.target_not_found` |
| 1008 | `anp.idempotency_conflict` |
| 1009 | `anp.unsupported_content_type` |
| 1010 | `anp.delivery_rejected` |
| 1011 | `anp.rate_limited` |
| 1012 | `anp.temporarily_unavailable` |
| 1013 | `anp.invalid_security_binding` |
| 1014 | `anp.invalid_target_binding` |
| 1015 | `anp.device_binding_required` |
| 1016 | `anp.device_binding_invalid` |
| 1017 | `anp.device_not_eligible` |
| 1018 | `anp.device_state_changed` |
| 1019 | `anp.did_superseded` |
| 1020 | `anp.did_transition_invalid` |
| 1021 | `anp.did_transition_conflict` |

The three most common:

- **1003**: the body has one field too many or one field too few, or `params` is not an object. The
  group profile/policy merge patch is validated **after it is applied**, and a structural violation
  is also 1003 rather than 3003.
- **1005**: `origin_proof` fails verification, or the DID the `keyid` belongs to is not the anchor of
  this call.
- **1014**: the shape of `meta.target` does not match the method's `targetMode` (**not** 1003).

## Segment 2000: direct (P3)

| Code | `anp_code` |
|---|---|
| 2005 | `direct.invalid_origin_proof` |
| 2006 | `direct.origin_did_mismatch` |

Both are on the attribution check of the application-layer proof: a signature that is itself wrong
is 2005; one signed correctly but by a DID that is not the anchor this call should have is 2006.
Cross-domain outer authentication failures do not go here; they use `401`.

## Segment 3000: groups (P4)

| Code | `anp_code` | Does this service emit it? |
|---|---|---|
| 3000 | `group.not_member` | Yes |
| 3001 | `group.already_member` | Yes |
| 3002 | `group.admission_not_allowed` | **No** (no path produces it) |
| 3003 | `group.policy_violation` | Yes (insufficient permission, a join that is not open-join, exceeding `max_members`) |
| 3005 | `group.member_conflict` | Yes (the conflict path for a member reactivated after having left) |
| 3006 | `group.security_mode_required` | Yes (an operation that should have gone through P6 went through P4) |
| 3008 | `group.invalid_origin_proof` | Yes |
| 3009 | `group.origin_did_mismatch` | Yes |

A group notification's anchor is **`body.group_did`**, not `meta.sender_did` — so 3009 and 2006 do
not test the same thing. See [Federation and cross-domain](/en/guide/federation).

## Segment 4000: direct E2EE (P5)

| Code | `anp_code` |
|---|---|
| 4000 | `anp.direct.e2ee.bundle_not_found` |
| 4001 | `anp.direct.e2ee.bundle_invalid` |
| 4003 | `anp.direct.e2ee.opk_unavailable` |
| 4012 | `anp.direct.e2ee.invalid_security_binding` |

With `require_opk` and an empty pool it is **4003**; if the pool is empty but OPK was not required,
the Bundle is returned normally without an OPK. Rate limiting on the key methods uses the shared
**1011**, because the 4000 segment has no corresponding entry.

## Segment 5000: group E2EE (P6)

| Code | `anp_code` |
|---|---|
| 5000 | `anp.group.e2ee.key_package_not_found` |
| 5001 | `anp.group.e2ee.invalid_key_package` |
| 5002 | `anp.group.e2ee.did_binding_invalid` |
| 5003 | `anp.group.e2ee.controller_required` |
| 5004 | `anp.group.e2ee.state_not_ready` |
| 5005 | `anp.group.e2ee.epoch_conflict` |
| 5006 | `anp.group.e2ee.crypto_group_mismatch` |
| 5007 | `anp.group.e2ee.private_message_invalid` |
| 5008 | `anp.group.e2ee.commit_invalid` |
| 5009 | `anp.group.e2ee.welcome_invalid` |
| 5010 | `anp.group.e2ee.fork_suspected` |
| 5011 | `anp.group.e2ee.notice_type_unsupported` |
| 5012 | `anp.group.e2ee.key_package_consumed` |
| 5013 | `anp.group.e2ee.leaf_not_current` |

## Segment 6000: attachments (P7)

| Code | `anp_code` |
|---|---|
| 6000 | `anp.attachment.slot_not_found` |
| 6001 | `anp.attachment.slot_expired` |
| 6002 | `anp.attachment.commit_token_invalid` |
| 6003 | `anp.attachment.object_too_large` |
| 6005 | `anp.attachment.grant_not_found` |
| 6006 | `anp.attachment.unauthorized_requester` |
| 6007 | `anp.attachment.download_ticket_invalid` |
| 6008 | `anp.attachment.ticket_binding_mismatch` |
| 6009 | `anp.attachment.ticket_expired` |
| 6010 | `anp.attachment.digest_mismatch` |
| 6012 | `anp.attachment.object_unavailable` |
| 6013 | `anp.attachment.encryption_policy_violation` |

The 6007–6009 family **appears only on the data plane**: on the control plane side it is issuance,
and at that point there is no token to judge.

## Errors on the extension surface

The inbox surface (`inbox.*` / `message.get_batch` / `sync.delta`) and the stream (`stream.*`) are
**implementation extensions**. They express "there is no such extension" as `unsupported_extension`:
a service that implements only the spec answers this, and it **does not say** whether it can deliver
messages.

## Next steps

- [HTTP endpoints](/en/reference/endpoints) — where the real status codes are used.
- [RPC methods](/en/reference/rpc) — which codes each method may return.
- [Attachments](/en/guide/attachments) — the authorization chain behind the 6000 segment.
