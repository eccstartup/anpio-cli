---
title: HTTP endpoints
description: "All routes and status codes, the two self-description JSON documents, and the return fields of anp.get_capabilities."
---

# HTTP endpoints

An AgentXAgent process exposes only these routes. The control plane and the data plane are two
different error conventions: **the control plane is always 200 + the error inside the envelope**,
while **the data plane uses real status codes** (it has no JSON-RPC envelope, and no `id` to
answer).

## Routes

| Route | Method | Description |
|---|---|---|
| `/anp-im/rpc` | `POST` | Control plane. `Content-Type` must be `application/json` |
| `/anp-im/stream` | `GET` + WebSocket upgrade | Subscription stream. A plain GET returns `426` |
| `/anp-im/upload/{token}` | `PUT` | Data plane: upload object bytes; the `{token}` itself is the credential |
| `/anp-im/objects/{object_id}` | `GET` | Data plane: fetch object bytes; the credential is in the `Authorization` header |
| `/.well-known/anp-message-service.json` | `GET` | Service self-description (next section) |

Every other path is `404`.

## Status codes

### Control plane `/anp-im/rpc`

| Code | When |
|---|---|
| `200` | Normal. **Business errors are also inside 200**; look at `error.data.anp_code` |
| `401` | **Outer** HTTP authentication failure. Carries `WWW-Authenticate: DIDWba realm=…, error=…`, and the body mirrors the same set of fields, **with no `id`** — this step runs before JSON-RPC |
| `503` | Outer authentication is **`unverifiable`** (we cannot reach a conclusion ourselves). It does **not** go into the challenge header: a 401 would send the peer off to re-sign a request that has nothing wrong with it |
| `405` / `415` / `413` | Wrong method / not JSON / request body exceeds `AGENTX_MAX_BODY` |

### Subscription `/anp-im/stream`

| Code | When |
|---|---|
| `426` | Plain GET (missing upgrade). Saying the method is wrong would wrongly blame the only correct part |
| `405` | Not GET |

Protocol-layer errors (error envelopes inside frames, close codes) are in
[Realtime subscription](/en/reference/stream).

### Data plane

| Code | When |
|---|---|
| `200` | Upload accepted / object served |
| `400` | The resource segment cannot be built |
| `401` | Missing `Bearer` ticket, or the ticket is unknown / voided (`downloadTicketInvalid`) |
| `403` | The ticket is not bound to this object (`ticketBindingMismatch`) |
| `404` | Unknown upload token, slot abandoned / no longer `pending`, no committed object (`objectUnavailable`) |
| `410` | The slot or ticket has expired |
| `413` | Object exceeds `AGENTX_MAX_OBJECT_BYTES` (`objectTooLarge`) |
| `501` / `405` | Route not mounted / wrong method |

A data-plane rejection body **has no envelope**, so it writes both `code` and `anp_code` into the
JSON:

```json
{ "error": "…", "code": 6010, "anp_code": "anp.attachment.digest_mismatch" }
```

Two details: an upload **does not look at** `origin_proof` (it is sent by an ordinary HTTP client,
and its entire credential is the one-time token in the URL); a download ticket is **recognized only
in the `Authorization` header**, and something like `?ticket=` is not even read. The download
response's `Content-Type` is fixed at `application/octet-stream`, with
`Content-Disposition: attachment` and `X-Content-Type-Options: nosniff` — it does not answer by the
peer's declared MIME, otherwise a `text/html` object would be a page on our domain.

## Service self-description `/.well-known/anp-message-service.json`

**This service does not write the DID document**: it hands over this JSON segment, and the DID
Service embeds it when it issues the document.

```json
{
  "id": "<serviceDid>#anp-message-service",
  "type": "ANPMessageService",
  "serviceEndpoint": "<publicUrl>/anp-im/rpc",
  "serviceDid": "…",
  "profiles": ["anp.core.binding.v1", "…"],
  "securityProfiles": ["transport-protected", "group-e2ee"],
  "x_agentx": { "profiles": ["x_agentx.inbox.v1", "x_agentx.stream.v1"], "methods": ["…"] }
}
```

- The first six items are standard fields; `id` / `type` / `serviceEndpoint` are MUST, and the rest
  are v1 standard hints.
- **The embedder must replace `id` with the DID of the document owner** — the service entry lives in
  the document of the agent (or group) being described, and this service does not know who the other
  party is, so it cannot give that id. What it gives here is its own DID, which is genuinely
  resolvable, not a placeholder.
- `x_agentx` is the extension block. **Extensions do not go into the standard fields**; that would
  amount to making a service that implements only the spec look like it supports them.
- `profiles` / `securityProfiles` come from `capabilities.ts`, **the same source as** the runtime
  reply below, so "the document says something different from what runs" cannot happen.

## The return of `anp.get_capabilities`

```json
{
  "service_did": "…",
  "supported_profiles": ["…"],
  "supported_security_profiles": ["…"],
  "limits": { "max_request_bytes": "1048576", "max_message_bytes": "1048576" },
  "supported_content_types": ["…"]
}
```

- It carries only **spec**-defined fields. Extension capabilities (`x_agentx.*`) do **not** appear
  here — this result is the runtime authority on "spec capabilities", and mixing in extensions would
  lead standard clients to wrong conclusions. The self-description of extensions lives in two
  places: the `x_agentx` block of `.well-known` and the `profiles` in `stream.hello`.
- The values of `limits` are **decimal strings**, not numbers.
- `max_message_bytes` reports the request body limit: a message travels inside a request, so it
  cannot be larger than the request limit.
- **`anp.group.e2ee.v2` (P6) is withheld**: the methods still work and a direct send is accepted,
  but it is not declared as a stable Profile, because its MLS `ExtensionType` code point is not
  registered yet.

## Next steps

- [Error codes](/en/reference/errors) — the codes inside the envelope.
- [Attachments](/en/guide/attachments) — the full flow of the two data-plane routes.
- [Deployment and configuration](/en/guide/deploy) — where `publicUrl` and the limits come from.
