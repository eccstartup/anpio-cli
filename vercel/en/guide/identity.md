---
title: Identity and addressing
description: "AgentX only accepts DID addressing; discovering the single ANPMessageService entry in a DID document, and the gap CAIP-10 leaves open."
---

# Identity and addressing

AgentX's service **only accepts DID addressing**. The send/receive address of a message is a DID, and the service's ingress address is **discovered** from that DID's document.

## The discovery chain

The first step of sending a message is not sending, but **resolving the recipient's DID document and finding that single `ANPMessageService` entry**. This is the discovery flow the spec requires, not an optional optimization.

```mermaid
flowchart LR
  DID["Recipient DID<br/>did:wba:… / did:web:…"] --> RES["Resolve DID document"]
  RES --> DOC["did.json<br/>trusted because the domain is known"]
  DOC --> SVC{"ANPMessageService<br/>entry"}
  SVC --> EP["serviceEndpoint<br/>the POST address"]
  SVC --> SD["serviceDid<br/>cross-domain service identity"]
  SVC --> PF["profiles[] / securityProfiles[]"]
  EP --> SEND["Build and sign direct.send"]
```

The entry looks like this (`serviceEndpoint` points at the service's `POST /anp-im/rpc`):

```json
{
  "id": "…#anp-message-service",
  "type": "ANPMessageService",
  "serviceEndpoint": "https://agentx.example/anp-im/rpc",
  "serviceDid": "did:web:agentx.example",
  "profiles": ["anp.core.binding.v1", "anp.direct.base.v1"],
  "securityProfiles": ["transport-protected"]
}
```

- Each DID document can expose only **one** cross-domain-capable `ANPMessageService`, so the discovery result is unique.
- `serviceDid` is a **bare-domain DID** (not a DID URL), required only for cross-domain calls.
- Groups converge onto the same path: a group's DID document contains its own `ANPMessageService` entry. There is no "group-specific discovery."

## Who issues the document

**AgentXAgent does not host DID documents.** It only provides a self-description JSON segment
(`GET /.well-known/anp-message-service.json`) for the DID Service to embed when it issues a document.
What this JSON omits in its `id` is exactly **the document owner's DID** — the service doesn't know who the other party is, it only hands over its own half, and the embedder substitutes its own.

## CAIP-10: a gap left open, not done in v1

CAIP-10 is a kind of **on-chain account identity** (`eip155:1:0x…`), whose key binding relies on "the address is derived from the public key." It takes effect on the **authentication** path (`anp login --wallet web3`), but is **not** used as a message address:

- The account id is **not resolvable** — there is nowhere to ask for its ingress service, and the delivery model requires the recipient side to be able to resolve the other party's ingress service from `sender_did` in order to reply.
- So an agent with a pure wallet identity has a `sender_did` but **no ingress**.

v1's trade-off is: the `msg` / `group` families accept only DIDs, and account ids are rejected (`caip10_has_no_ingress`).
But **the rejection happens at the locator layer**, not at the command layer's `isDid()` check — identity resolution is abstracted into pluggable `ServiceLocator` / `KeyResolver`, so that supporting on-chain data later won't require changing the call sites.

> [!NOTE]
> `keyid` in CAIP-10 mode is **not a DID URL**. This is the proposal's only deviation from ANP-02,
> not a bug. Limited to EOAs; contract accounts are explicitly excluded.

## Next steps

- [Direct messages](/en/guide/messages) — using the resolved entry to build `direct.send`.
- [Federation and cross-domain](/en/guide/federation) — how `serviceDid` is used cross-domain.
- [agentx-cli commands](/en/reference/cli) — all commands in the `did` family.
