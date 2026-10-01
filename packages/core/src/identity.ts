// Identity-format contract for connectx (the "冻结" for DID / CAIP-10 / address).
// This is the single source of truth for how a DID string is formed. If the DID
// shape or normalization changes, it changes HERE and is a breaking change.
//
// A DID is exactly one of two shapes:
//   1. ANP-native    — `did:wba:<host>` or, for an agent/user identity that binds
//      a key, the ANP **path type** `did:wba:<host>:<segment>…:<fingerprint>`.
//      The last path segment MUST be a key fingerprint — `e1_` (Ed25519, default)
//      or `k1_` (secp256k1) — so two keys on one host can never collide. This is
//      the form the SDK/CLI emit. A bare `did:wba:<host>` (no fingerprint) is the
//      ANP **domain-level** service identity: it is still ACCEPTED when parsing /
//      resolving, and `domainServiceDid` builds one — but ONLY for a service that
//      has to name the DID it signs cross-domain calls with. As a user identity it
//      is never produced (see `identityDid` below).
//   2. Chain account — a CAIP-10 account id `<caip2-chain-id>:<address>`
//      (e.g. `eip155:1:0x…`). Used ONLY when BOTH a chain id and an address are
//      present. This is an OPAQUE identifier, not a resolvable DID: its DID
//      document is always inlined in the signed proof, never fetched by DID method.
//
// Wherever the DID appears, the derived fields are:
//   - keyid              = `${did}#key-1`
//   - didDocument.id     = did
//   - verificationMethod  = [{ id: keyid, controller: did, ...key }], where `key` is
//                          the representation the profile publishes (`DidPublicKey`):
//                          `{ type: 'Multikey', publicKeyMultibase }` for Ed25519,
//                          `{ type: 'EcdsaSecp256k1VerificationKey2019', publicKeyJwk }`
//                          for secp256k1 (Appendix A A.4).
//   - authentication / assertionMethod = [keyid]
//   - proof              = eddsa-jcs-2022 DataIntegrityProof for `e1_` documents
//                          (MANDATORY for that profile); omitted for `k1_`.
//
// A host carrying a port is percent-encoded (`localhost:3000` → `localhost%3A3000`)
// so the `:` is not mistaken for the path separator the fingerprint segment needs.
// IPv6 literals are not supported.
//
// EVM (`eip155` namespace) accounts are canonicalized: a chain id in EIP-1193 hex
// (`0x1`) or bare decimal (`1`) becomes `eip155:<decimal>`, and an address becomes
// lowercase `0x` + 40 hex chars (no EIP-55 checksum inside a DID — the account id
// is an exact, case-insensitive string key). Non-EVM chains are left verbatim
// (opaque to the SDK, which stays chain-agnostic).

import { ConnectxError } from './errors'
import { didFingerprint, isFingerprint } from './crypto/fingerprint'
import { didToUrl } from './crypto/resolveDid'

/** Curve of a key that a `did:wba` fingerprint binds. */
export type DidKeyCurve = 'ed25519' | 'secp256k1'

/** Longest accepted raw (non-CAIP-2) chain id. Bounds `BigInt` parsing so a huge
 *  attacker-supplied value cannot cost unbounded parse time; 64 chars comfortably
 *  exceeds any real chain id (the largest known are well under 2^64). */
const MAX_RAW_CHAIN_ID_LENGTH = 64

/** Canonicalize a chain id to CAIP-2 form. Bare hex (`0x1`) or decimal (`1`) are
 *  treated as EVM (`eip155:<decimal>`); an already-namespaced value (`eip155:1`,
 *  `cosmos:cosmoshub-3`) is returned unchanged. The numeric conversion uses
 *  `BigInt` (not `Number`) so values above `Number.MAX_SAFE_INTEGER` keep their
 *  exact value — two distinct chain ids can never collapse onto one CAIP-2
 *  account id. Anything malformed or out of range is rejected so a bad value
 *  never silently becomes a malformed or colliding DID. */
export function normalizeChainId(chainId: string): string {
  const id = chainId.trim()
  // EVM hex (`0x…`) or bare decimal. `BigInt` keeps the exact value where `Number`
  // would silently round 2^53 + 1 into 2^53 (audit 2026-09-08 §3.1).
  if (/^0x[0-9a-fA-F]+$/.test(id) || /^\d+$/.test(id)) {
    if (id.length > MAX_RAW_CHAIN_ID_LENGTH) {
      throw new ConnectxError('invalid_argument', `Chain id "${chainId}" is out of range`)
    }
    return `eip155:${BigInt(id)}`
  }
  if (/^[a-z0-9-]+:[^\s:]+$/i.test(id)) return id // already CAIP-2 (namespace:reference)
  throw new ConnectxError(
    'invalid_argument',
    `Malformed chain id "${chainId}" (expected CAIP-2 like "eip155:1", or EVM hex/decimal)`,
  )
}

/** Canonicalize an address for a (normalized) chain id. EVM addresses are
 *  lowercased and must be `0x` + 40 hex chars; non-EVM addresses are trimmed and
 *  used verbatim (the SDK is chain-agnostic and does not parse them). */
export function normalizeAddress(chainId: string, address: string): string {
  const addr = address.trim()
  if (chainId.startsWith('eip155:')) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
      throw new ConnectxError('invalid_argument', `Malformed EVM address "${address}"`)
    }
    return addr.toLowerCase()
  }
  if (addr === '') throw new ConnectxError('invalid_argument', 'Empty address')
  return addr
}

/** Default `did:wba` path when a caller does not name one. ANP requires at least
 *  one segment before the fingerprint; the CLI overrides the second segment with
 *  the acting agent id (`['user', agentId]`). */
export const DEFAULT_WBA_PATH = ['user', 'default'] as const

/** One path segment in a path-type `did:wba`. The allowlist mirrors the CLI's
 *  agent/profile names and, critically, forbids `:` and `/` so a segment can never
 *  forge another segment or escape the DID (path injection). */
const DID_PATH_SEGMENT = /^[a-zA-Z0-9._-]+$/

/** A key that binds a `did:wba` identity: its curve, its public key bytes, and an
 *  optional DID path (defaults to `['user','default']`). */
export interface WbaDidKey {
  curve: DidKeyCurve
  publicKey: Uint8Array
  path?: string[]
}

/** Percent-encode the `:` in a host:port so it is not read as a DID path
 *  separator. IPv6 literals (which need `[`/`]` and many colons) are rejected. */
export function encodeDidHost(host: string): string {
  const h = host.trim()
  if (h === '') throw new ConnectxError('invalid_argument', 'Empty DID host')
  if (h.includes('[') || h.includes(']')) {
    throw new ConnectxError('invalid_argument', 'IPv6 DID hosts are not supported')
  }
  return h.replace(/:/g, '%3A')
}

function normalizeDidPath(path?: string[]): string[] {
  const segments = path ?? [...DEFAULT_WBA_PATH]
  if (segments.length === 0) {
    throw new ConnectxError('invalid_argument', 'A did:wba identity requires at least one path segment before the fingerprint')
  }
  for (const s of segments) {
    if (!DID_PATH_SEGMENT.test(s)) {
      throw new ConnectxError('invalid_argument', `Invalid DID path segment "${s}" (allowed: letters, digits, ".", "_", "-")`)
    }
  }
  return segments
}

/** Compose the DID from a host plus either a chain account or a signing key.
 *
 *  - BOTH `chainId` and `address` → the CAIP-10 account id (normalized). The key
 *    is ignored (a chain account is its own opaque identity).
 *  - otherwise → the ANP path-type `did:wba:<host>:<path…>:<fingerprint>`, binding
 *    `wbaKey` into the DID. Without a `wbaKey` this throws: the SDK no longer
 *    emits a keyless bare-domain DID (which could not distinguish two keys on one
 *    host). A partial chain descriptor (only one of the two) is ignored, as before.
 */
export function identityDid(
  host: string,
  chainId?: string,
  address?: string,
  wbaKey?: WbaDidKey,
): string {
  if (chainId && address) {
    const cid = normalizeChainId(chainId)
    const addr = normalizeAddress(cid, address)
    return `${cid}:${addr}`
  }
  if (!wbaKey) {
    throw new ConnectxError(
      'invalid_argument',
      'A did:wba identity requires a signing key (pass wbaKey) — connectx no longer emits keyless bare-domain DIDs',
    )
  }
  const path = normalizeDidPath(wbaKey.path)
  const fingerprint = didFingerprint(wbaKey.curve, wbaKey.publicKey)
  return `did:wba:${encodeDidHost(host)}:${[...path, fingerprint].join(':')}`
}

/** The ANP **domain-level** service DID: `did:wba:<host>`, with no key fingerprint.
 *
 *  It names a whole domain rather than one agent, and the `e1_`-style path binding
 *  does not apply to it — a bare-domain DID resolves through
 *  `/.well-known/did.json` and has its `id` checked, nothing more (ANP-03
 *  L95–L104, L402). What it is FOR is one thing: a service that participates in a
 *  cross-domain service-to-service call has to declare which DID signs its outer
 *  HTTP request, and ANP-03 L102 says it SHOULD use the bare-domain form.
 *  `serviceDid` is the field that carries it (see `DidDocumentService.serviceDid`).
 *
 *  This is a SEPARATE function from `identityDid` on purpose, and the separation is
 *  the point: a bare-domain DID carries no key, so it can neither prove possession
 *  nor be updated — `identityDid` therefore keeps refusing to emit one, and the SDK
 *  still produces no bare domain as a user identity (ADR-0001 §2.10). This
 *  constructor exists so the service-identity case can be expressed without
 *  reopening that door.
 *
 *  Takes a host with or without a port (`example.com`, `example.com:8800`, or the
 *  already-encoded `example.com%3A8800`); the DID always carries the encoded form.
 *  Anything that would not resolve as a bare-domain DID — a scheme, a path, a
 *  non-numeric port — is rejected here rather than at the far end of a network call.
 */
export function domainServiceDid(host: string): string {
  const did = `did:wba:${encodeDidHost(host)}`
  // Deriving the URL IS the validation: the resolver runs the same host/path check
  // on this DID, so anything that cannot be resolved must not be buildable either.
  didToUrl(did)
  return did
}

/** A native **`did:web`** identity DID: `did:web:<host>[:<path…>]`.
 *
 *  `did:web` is a first-class identity method here, not a foreign shape that merely
 *  happens to resolve: a holder keeps its `did:web` identity and authenticates under
 *  ANP-02's common flow, with no conversion to `did:wba` (Appendix B B.1 L9).
 *  What that costs is the WBA binding — a `did:web` DID carries **no fingerprint**,
 *  so nothing in the identifier ties it to a key; the tie is the domain's TLS
 *  certificate plus the document the domain serves (B.1 L471), and demanding a WBA
 *  fingerprint or document proof of it is a MUST NOT (B.1 L477). `subjectOf` returns
 *  a `did:web` DID unchanged for the same reason: it is already stable.
 *
 *  The path is **optional** and normally absent — a bare host resolves through
 *  `/.well-known/did.json`, and a path is what a host uses to serve more than one
 *  identity (`did:web:example.com:users:alice` → `https://example.com/users/alice/
 *  did.json`). Segments are validated by the same whitelist the `did:wba` path uses.
 *
 *  A port is percent-encoded (`example.com%3A8443`), because `:` is the segment
 *  separator in a method-specific id — the same encoding rule as `identityDid`.
 *  Anything that would not resolve — a scheme, an empty or traversal-shaped
 *  segment, a non-numeric port — is rejected here rather than at the far end of a
 *  network call.
 */
export function webIdentityDid(host: string, path?: string[]): string {
  // An empty array and an absent path are the same thing (a bare host); only a
  // NON-empty path goes through the validator, which requires at least one segment.
  const segments = path == null || path.length === 0 ? [] : normalizeDidPath(path)
  const suffix = segments.length === 0 ? '' : `:${segments.join(':')}`
  const did = `did:web:${encodeDidHost(host)}${suffix}`
  didToUrl(did)
  return did
}

// ---- Stable subject -----------------------------------------------------------
//
// A DID carries a KEY (so it changes when the key changes); a subject does not.
// The subject is the agent's identity for addressing, storage, sessions and
// attribution, while the concrete DID stays the wire credential that signs
// (see ADR-0002 §2.2). Two forms:
//
//   stableSubjectId(did)  the ANP-03 stable subject PATH, naked and unprefixed —
//                         exactly the string ANP-03 §2.2.3 defines and that a 409
//                         `did_superseded` body reports. Only `did:wba` defines one.
//   subjectOf(did)        the local, showable `SubjectId`: the DID's own method
//                         prefix with only the update-varying parts removed.
//                         Total over every supported method (including CAIP-10).
//
// They differ ON PURPOSE, and both are needed: `stableSubjectId` is a protocol
// field whose spelling the spec fixes, while `subjectOf` is what an agent is
// addressed and displayed by. Keeping the method prefix there means a subject
// reads as the identity it came from — and `did:web:…` / `did:wba:…` still never
// collapse onto each other, despite having DIFFERENT trust roots (a native
// did:web document carries no WBA proof — Appendix B).
//
// Dropping only the fingerprint (never the method) is what makes the subject
// stable: a `did:web` DID carries no fingerprint at all, so its subject IS the
// DID; a `did:wba` DID carries one, so its subject is the DID minus that segment.
// A DID-shaped subject is therefore NOT a resolvable DID — the fingerprint that
// bound it to a key is gone.
//
// IMPORTANT: a subject is a LOCAL account identity. ANP-03 §2.2.3 requires
// that a verifier MUST NOT conclude two DIDs are the same subject merely because
// their stable subject paths match; that conclusion needs the continuity chain.
// Never put a subject on the wire in place of the DID.

/** A stable, showable agent identity. Independent of the current key/DID, and
 *  DID-shaped: the same method prefix, minus whatever changes. */
export type SubjectId =
  /** `did:wba:<host>:<path…>` — the path-type DID minus its binding fingerprint. */
  | `did:wba:${string}`
  /** `did:web:<host>:<path…>` — a native Web identity, whose DID is already stable. */
  | `did:web:${string}`
  /** `did:webvh:<host>:<path…>` — the DID minus its log SCID. */
  | `did:webvh:${string}`
  /** Anything else verbatim — notably a CAIP-10 account id (`eip155:1:0x…`),
   *  which is already a stable namespace-qualified identity of its own. */
  | (string & {})

const DID_WBA_PREFIX = 'did:wba:'
const DID_WEB_PREFIX = 'did:web:'
const DID_WEBVH_PREFIX = 'did:webvh:'

/** Split a DID's method-specific part into `:`-separated segments, or `null` when
 *  the DID does not use `prefix`. Segments keep whatever percent-encoding the DID
 *  used, so the round trip does not re-introduce a `:` (a port in the host stays
 *  `%3A` and cannot be mistaken for a path separator). */
function didSegments(did: string, prefix: string): string[] | null {
  if (!did.startsWith(prefix)) return null
  const rest = did.slice(prefix.length)
  if (rest === '') return null
  return rest.split(':')
}

/** The ANP-03 stable subject path (§2.2.3), in the spec's own **naked** shape —
 *  no method prefix, exactly the string a 409 `did_superseded` body reports:
 *
 *  `did:wba:example.com:user:alice:e1_<fp>` → `example.com:user:alice`
 *  `did:wba:example.com` (bare domain)     → `example.com`
 *
 *  §2.2.3 defines this for **path-type** DIDs ("域名及最后一个绑定指纹 segment 之前的
 *  全部路径 segment"); the bare-domain result is the limit case of that rule, not a
 *  separate definition — §2.2 calls a bare-domain DID the "整个域名主体", and it has
 *  no fingerprint segment to strip. A port stays percent-encoded, because §2.2.3's
 *  域名 includes it (`example.com%3A3000`), so moving a DID between ports is a
 *  stable-subject-path change and MUST NOT be accepted as continuity.
 *
 *  Only `did:wba` defines a stable subject path today, so any other DID throws:
 *  returning a look-alike for `did:web` / CAIP-10 would invent a protocol concept
 *  that upstream has not defined. The showable local identity lives in
 *  {@link subjectOf} — for `did:wba` the two always agree on the path, differing
 *  only by subjectOf's `did:wba:` prefix. */
export function stableSubjectId(did: string): string {
  const segments = didSegments(did, DID_WBA_PREFIX)
  if (!segments) {
    throw new ConnectxError('invalid_did', `No stable subject path is defined for DID "${did}" (only did:wba defines one)`)
  }
  // The fingerprint is only stripped when it actually is one, so a DID whose last
  // segment merely looks like a path segment keeps it (the bare-domain form).
  if (segments.length >= 2 && isFingerprint(segments[segments.length - 1])) segments.pop()
  return segments.join(':')
}

/** The local `SubjectId` for any supported DID — the identity connectx addresses
 *  and displays an agent by. DID-shaped: the method prefix stays, only the parts
 *  that change are removed. Total: an unrecognized method (notably a CAIP-10
 *  account id, which is already stable) is returned verbatim.
 *
 *  `did:wba:example.com:user:alice:e1_<fp>` → `did:wba:example.com:user:alice`
 *  `did:web:identity.example:alice`        → itself (no fingerprint to drop)
 *  `did:webvh:abc123:example.com:alice`    → `did:webvh:example.com:alice`
 *  `eip155:1:0x…`                          → itself
 *
 *  The result is NOT a resolvable DID: the fingerprint that bound it to a key is
 *  gone, so no document exists at it. For the spec's own field — the naked
 *  substring a 409 `did_superseded` reports — use {@link stableSubjectId}. */
export function subjectOf(did: string): SubjectId {
  const webvh = didSegments(did, DID_WEBVH_PREFIX)
  if (webvh) {
    // did:webvh:<scid>:<host>[:<path…>] — the SCID is a self-certifying identifier
    // of the *log*, not of the subject, so it is dropped (it changes when the log
    // is re-created). NOTE: upstream defines no stable subject for did:webvh; this
    // is connectx's local convention (ADR-0002 §2.6) and may change to the official
    // rule once one exists.
    if (webvh.length < 2) {
      throw new ConnectxError('invalid_did', `Malformed did:webvh identifier: "${did}"`)
    }
    return `${DID_WEBVH_PREFIX}${webvh.slice(1).join(':')}`
  }

  const web = didSegments(did, DID_WEB_PREFIX)
  if (web) return `${DID_WEB_PREFIX}${web.join(':')}` as SubjectId

  const wba = didSegments(did, DID_WBA_PREFIX)
  if (wba) {
    // Strip the fingerprint only when it actually is one, so a bare-domain DID
    // (`did:wba:example.com`, no binding key) is its own subject.
    if (wba.length >= 2 && isFingerprint(wba[wba.length - 1])) wba.pop()
    return `${DID_WBA_PREFIX}${wba.join(':')}` as SubjectId
  }

  if (did === '') throw new ConnectxError('invalid_did', 'Cannot derive a subject from an empty DID')
  return did as SubjectId
}
