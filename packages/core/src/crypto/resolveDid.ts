import { decodeMultibaseKey, type Curve } from './multicodec'
import { base64ToBytes } from './encoding'
import { didFingerprint, isFingerprint } from './fingerprint'
import { canonicalDidUrl, documentProofKey, documentProofKeyId, verifyDidDocumentProof } from './dataIntegrity'
import type { DidDocumentService } from './didDocument'
import { getNodeBuiltin } from '../nodeBuiltin'
import { ConnectxError, type ConnectxErrorCode } from '../errors'

export interface ResolvedKey {
  curve: Curve
  bytes: Uint8Array
  docUrl?: string
}

/** A DID document that was resolved and verified, plus where this copy came from.
 *  Returned by `resolveDidDocument`. */
export interface ResolvedDidDocument {
  did: string
  document: Record<string, unknown>
  /** The URL the document is served from (`didToUrl(did)`). */
  docUrl: string
  /** `'network'` when fetched just now, `'store'` when served from `documentStore`. */
  source: 'network' | 'store'
  /** Epoch ms of the network fetch that produced this copy. A `'store'` hit keeps
   *  the ORIGINAL fetch time, so a caller can judge how stale the copy is. */
  fetchedAt: number
}

/**
 * Where a resolved DID document is kept between resolutions. Implement this to
 * persist documents; `createDidDocumentStore` is the in-memory one the SDK ships,
 * and nothing reads from a store unless the caller passes it in
 * `ResolveDidOptions.documentStore`. The SDK never passes one itself: it is a hook
 * for callers that ALREADY hold a document (an example server hands back the one a
 * login request carried, so the description fetch does not re-resolve it).
 *
 * Keys are DIDs, never stable subjects: a document describes ONE DID, while a
 * subject is shared across an update — keying by subject would let a superseded
 * DID's document answer for its successor.
 */
export interface DidDocumentStore {
  get(did: string): Promise<ResolvedDidDocument | undefined> | ResolvedDidDocument | undefined
  set(entry: ResolvedDidDocument): Promise<void> | void
  /** Drop an entry. This is how an update invalidates a stored document — see
   *  Part F's 409 `did_superseded` path. */
  delete?(did: string): Promise<void> | void
}

/** In-memory `DidDocumentStore`. Deliberately NOT a global cache: the SDK resolves
 *  over the network on every call unless a caller passes a store in. */
export function createDidDocumentStore(): DidDocumentStore {
  const entries = new Map<string, ResolvedDidDocument>()
  return {
    get: (did) => entries.get(did),
    set: (entry) => {
      entries.set(entry.did, entry)
    },
    delete: (did) => {
      entries.delete(did)
    },
  }
}

// Has this document stopped being the DID's current one? `deactivated` is DID Core's
// marker, `successorDid` is the ANP-03 continuity pointer. Either way the document is
// historical evidence rather than the DID's current credential, so it must never be
// written to (or served from) a document store — and, since ANP-03 §2.5.5 makes an
// ACTIVE `e1_` document's proof mandatory while a deactivated transition document's
// is optional, it is also what decides which proof policy applies. Exported so the
// continuity chain (did/chain.ts) reads the same two markers.
export function isSuperseded(document: Record<string, unknown>): boolean {
  return document.deactivated === true || typeof document.successorDid === 'string'
}

interface VerificationMethod {
  id?: string
  type?: string
  controller?: string | string[]
  publicKeyMultibase?: string
  publicKeyJwk?: {
    kty?: string
    crv?: string
    x?: string
    y?: string
  }
}

/** An entry in `authentication`. DID Core allows either a reference (the method's
 *  id, absolute or `#relative`) or an EMBEDDED method object. */
type AuthenticationEntry = string | ({ id?: string } & VerificationMethod)

interface DidDocument {
  id?: string
  verificationMethod?: VerificationMethod[]
  authentication?: AuthenticationEntry[]
  /** ANP-03 §service. OPTIONAL — plenty of DIDs publish no service at all, so an
   *  absent or empty array is a legal document, never a malformed one. */
  service?: DidDocumentService[]
  [key: string]: unknown
}

/**
 * Network constraints for remote DID resolution. These turn
 * `resolveVerificationKey`, which otherwise issues an outbound HTTPS request to a
 * caller-controlled host, into a bounded, allowlisted fetch. A server that accepts
 * an untrusted `keyid` MUST set `allowedHosts`; every other field is either a safe
 * default or an explicit OPT-OUT that must name its hosts (`allowPrivateHosts` /
 * `allowInsecureTransport` — a local-development facility, not a production knob).
 */
export interface ResolveDidOptions {
  /**
   * Exact hostname allowlist for the fetch. REQUIRED (non-empty) for remote
   * resolution: the SDK refuses to fetch a DID document over the network unless the
   * caller has whitelisted the exact host. This is the primary defence against SSRF
   * — a caller passing an untrusted `keyid` is otherwise free to reach any host.
   */
  allowedHosts?: string[]
  /**
   * Exact hostnames exempted from the PRIVATE-ADDRESS check: each named host may
   * resolve to a private / loopback / link-local address and still be fetched.
   *
   * Separate from `allowedHosts` on purpose — the two gates answer different
   * questions ("may I talk to this host at all" vs "may it be a private one"), and
   * an allowlisted public host needs neither. Both must pass, so naming a host here
   * never widens the allowlist.
   *
   * This exists because the DID-spec local-development case (`localhost`) is
   * otherwise unreachable: without it the only way to resolve a document from your
   * own machine is the escape hatch below, whose stated semantics ("this caller has
   * no DNS resolver") is a LIE when you do have one — a lie that also disables the
   * private-IP gate wholesale. Name the exact hosts instead; never ship a
   * production config that names one. Hosts are compared as `URL.hostname` reports
   * them (no port).
   */
  allowPrivateHosts?: string[]
  /**
   * Exact hostnames whose DID document is fetched over plain `http` instead of
   * `https`. `didToUrl` always derives an `https` URL (ANP-03 requires TLS), so this
   * is the only way to reach a local dev server that speaks http — the same
   * relaxation the `resolveAddresses: () => null` fixture used to perform by
   * rewriting the URL inside a custom `fetch`.
   *
   * Scoped as narrowly as it can be: it changes the SCHEME only, for exactly these
   * hosts. The host and path still come from the DID, the allowlist still applies,
   * and a redirect that downgrades to `http` on any other host is refused.
   */
  allowInsecureTransport?: string[]
  /** Abort the fetch after this many ms. Default 10_000. */
  timeoutMs?: number
  /** Reject a DID document response larger than this many bytes. Default 1_000_000. */
  maxBytes?: number
  /** Follow HTTP redirects. When false (default) a 3xx response is rejected outright;
   *  when true each hop is followed manually and EVERY host in the chain is re-checked
   *  against the allowlist + resolved-address policy (SSRF / DNS rebinding). */
  allowRedirects?: boolean
  /** Maximum redirect hops to follow before failing. Default 5. */
  maxRedirects?: number
  /**
   * Caller-injected fetcher. This is an ESCAPE HATCH: the SDK cannot pin the connect
   * to the validated address through it, so DNS-TOCTOU/SSRF protection is the caller's
   * responsibility. It is ONLY honored when `allowUncontrolledFetch: true`; without
   * that flag a custom `fetch` is rejected (fail-closed) so an uncontrolled network
   * side-channel can never silently replace the pinned default in a secure path.
   */
  fetch?: (url: string, init: RequestInit) => Promise<Response>
  /**
   * Explicitly opt INTO a caller-managed transport. Set this only when you supply a
   * `fetch` that the caller itself pins/trusts (tests, local dev, a browser that does
   * its own connection control). When `false`/absent, a custom `fetch` is rejected and
   * remote resolution uses the SDK's pinned connection (Node default). Note: with the
   * flag set, the SDK does NOT claim DNS pinning.
   */
  allowUncontrolledFetch?: boolean
  /**
   * Override for resolving a host's A/AAAA addresses, used to validate the actual
   * connection target against private/loopback space. Defaults to Node's DNS
   * resolver; in the browser (no `node:dns`) the check is skipped and the hostname
   * allowlist is the only guard. Inject a fake resolver to test DNS rebinding — or
   * return `null` to simulate a browser that has NO resolver (in which case remote
   * resolution fails closed, because the connection target cannot be pinned).
   */
  resolveAddresses?: (host: string) => Promise<string[] | null>
  /**
   * How strictly to require the document's top-level `proof`.
   *
   * - `'lenient'` (default): the proof is MANDATORY for a path-type `did:wba`
   *   whose last segment is an `e1_` fingerprint (ANP-03 §2.5.5 defines no loose
   *   mode for that profile); for any other DID a present proof is still verified,
   *   but a missing one is accepted.
   * - `'strict'`: additionally require a valid proof on every `did:wba` shape.
   *
   * Native `did:web` is exempt either way: Appendix B forbids demanding
   * another method's WBA document proof. A CAIP-10 account id is exempt too — it
   * carries no fingerprint to bind a self-signed document to, so such a proof
   * would prove nothing.
   */
  documentProof?: 'lenient' | 'strict'
  /**
   * Where a resolved document is kept between calls. ABSENT (the default) means no
   * caching at all: every resolution is a fresh network fetch, exactly as it was
   * before this option existed. Pass `createDidDocumentStore()` — or your own
   * persistent implementation — to stop re-fetching a DID you resolve repeatedly.
   *
   * A store is a cache, so it is a correctness hazard: see `cacheTtlMs` for the
   * freshness and update rules that keep a hit from serving a superseded identity.
   */
  documentStore?: DidDocumentStore
  /**
   * How long a stored document may be served before it is re-fetched. Default
   * 300_000 (5 min). Only consulted when `documentStore` is set.
   *
   * A stored copy is a SNAPSHOT — it cannot observe that the DID has since been
   * deactivated. This bound is what keeps that window finite, and it is paired with
   * two rules that make the window safe rather than merely short: a document marked
   * `deactivated` (or carrying `successorDid`) is never written to the store, and a
   * stored copy that has since become superseded is never served.
   */
  cacheTtlMs?: number
}

const DEFAULT_TIMEOUT_MS = 10_000
const DEFAULT_MAX_BYTES = 1_000_000
const DEFAULT_MAX_REDIRECTS = 5
const DEFAULT_CACHE_TTL_MS = 300_000

// The media types a DID document may be served as (W3C DID Resolution). `+json` is
// accepted generically so a future `application/did+ld+json` variant does not break
// resolution; a bare `application/json` is tolerated because minimal DID servers use it.
const DID_DOCUMENT_MEDIA_TYPES = new Set(['application/did+json', 'application/json'])

// Ask for a DID document rather than "anything you have". Without this a server (or a
// proxy in front of it) is free to answer with an HTML page, which would then reach
// JSON.parse and be reported as a malformed document instead of a wrong content type.
const DID_DOCUMENT_ACCEPT = { accept: 'application/did+json, application/json' }

// The codes and the noun one controlled fetch reports with. Parameterised because the
// SAME transport serves both a DID document and the ANP-07 `ad.json` that document
// points at, and the two failures are not the same event: reporting "DID resolution
// failed" when a description failed to download would send the caller looking at the
// wrong thing.
export interface FetchErrorCodes {
  /** How error messages name the resource, e.g. `"DID document"`. */
  subject: string
  blocked: ConnectxErrorCode
  failed: ConnectxErrorCode
  timeout: ConnectxErrorCode
  tooLarge: ConnectxErrorCode
  tooManyRedirects: ConnectxErrorCode
  invalidDocument: ConnectxErrorCode
}

/**
 * A non-GET request for {@link fetchControlledJson}. Absent = the plain GET the DID
 * document and agent-description callers issue.
 *
 * The point of describing a POST here rather than writing a second fetch is that the
 * policy has to hold for it *more* than for the others: an ANP message goes to a
 * `serviceEndpoint` read out of a PEER's DID document, so the host is chosen by the
 * peer, not by the caller. A second copy of the hop-by-hop validation is exactly where
 * an SSRF hole would eventually appear.
 */
export interface ControlledRequest {
  method: string
  headers: Record<string, string>
  body: string
}

export const DID_DOCUMENT_FETCH_CODES: FetchErrorCodes = {
  subject: 'DID document',
  blocked: 'did_resolve_blocked',
  failed: 'did_resolve_failed',
  timeout: 'did_resolve_timeout',
  tooLarge: 'did_resolve_too_large',
  tooManyRedirects: 'did_resolve_too_many_redirects',
  invalidDocument: 'did_resolve_invalid_document',
}

// A DID server must not answer with a web page. This matters for a soft 404 — a
// proxy's error page, a login redirect, a captive portal — which returns 200 with
// `text/html`; without the check the body would be parsed as a document and
// whatever fell out of it would be trusted as verification material.
//
// An ABSENT Content-Type is tolerated on purpose: plenty of minimal DID servers omit
// it, and the JSON parse downstream is then the guard that matters.
function assertDocumentContentType(res: Response, url: string, codes: FetchErrorCodes): void {
  const header = res.headers.get('content-type')
  if (header == null) return
  const mediaType = header.split(';')[0]!.trim().toLowerCase()
  if (DID_DOCUMENT_MEDIA_TYPES.has(mediaType) || mediaType.endsWith('+json')) return
  throw new ConnectxError(
    codes.invalidDocument,
    `${codes.subject} from ${url} has unsupported Content-Type "${mediaType}"`,
  )
}

// Loopback, link-local, private, CGNAT, multicast and reserved IPv4/IPv6 ranges —
// the addresses an SSRF-driven server fetch must never reach. We validate a host's
// RESOLVED addresses (not its name), so an allowlisted hostname that has been
// rebound to a private address (DNS rebinding) is still rejected.
function isPrivateIpAddress(ip: string): boolean {
  let addr = ip.trim()
  if (addr.startsWith('[') && addr.endsWith(']')) addr = addr.slice(1, -1)
  const v4 = parseIpv4(addr)
  if (v4) return isBlockedIpv4(v4)

  const v6 = parseIpv6(addr)
  if (!v6) return true // DNS output must be a canonical, parseable IP; otherwise fail closed.

  // IPv4-mapped IPv6 (including hexadecimal forms such as ::ffff:7f00:1).
  if (v6.slice(0, 10).every((b) => b === 0) && v6[10] === 0xff && v6[11] === 0xff) {
    return isBlockedIpv4(v6.slice(12))
  }
  const unspecified = v6.every((b) => b === 0)
  const loopback = v6.slice(0, 15).every((b) => b === 0) && v6[15] === 1
  if (unspecified || loopback) return true
  if ((v6[0] & 0xfe) === 0xfc) return true // fc00::/7 ULA
  if (v6[0] === 0xfe && (v6[1] & 0xc0) === 0x80) return true // fe80::/10 link-local
  if (v6[0] === 0xff) return true // ff00::/8 multicast
  return false
}

function parseIpv4(value: string): Uint8Array | null {
  const parts = value.split('.')
  if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/.test(part))) return null
  const bytes = parts.map(Number)
  return bytes.some((byte) => byte > 255) ? null : new Uint8Array(bytes)
}

function isBlockedIpv4(bytes: Uint8Array): boolean {
  const [a, b, c] = bytes
  if (a === 0 || a === 10 || a === 127) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && (b === 0 || b === 168)) return true // protocol assignments + RFC1918
  if (a === 192 && b === 0 && c === 2) return true // TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true // TEST-NET-3
  return a >= 224 // multicast + reserved
}

/** Parse an IPv6 literal into 16 bytes. Supports compressed and IPv4-mapped forms. */
function parseIpv6(value: string): Uint8Array | null {
  if (!value || value.includes('%') || value.split('::').length > 2) return null
  const [leftRaw, rightRaw] = value.split('::')
  const expand = (raw: string): number[] | null => {
    if (!raw) return []
    const items = raw.split(':')
    const words: number[] = []
    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      if (item.includes('.')) {
        if (i !== items.length - 1) return null
        const v4 = parseIpv4(item)
        if (!v4) return null
        words.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3])
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(item)) return null
        words.push(Number.parseInt(item, 16))
      }
    }
    return words
  }
  const left = expand(leftRaw)
  const right = expand(rightRaw ?? '')
  if (!left || !right) return null
  const compressed = value.includes('::')
  const zeros = 8 - left.length - right.length
  if ((!compressed && zeros !== 0) || (compressed && zeros < 1)) return null
  const words = [...left, ...Array(Math.max(0, zeros)).fill(0), ...right]
  if (words.length !== 8) return null
  const bytes = new Uint8Array(16)
  words.forEach((word, index) => {
    bytes[index * 2] = word >> 8
    bytes[index * 2 + 1] = word & 0xff
  })
  return bytes
}

// Exact-host membership for the two opt-out lists. Hosts are compared the way
// `URL.hostname` spells them (lowercase, no port, brackets kept on IPv6), so it must
// be the caller who names the host — a wildcard or suffix match here would turn a
// per-host exemption into a policy change.
function hostIsListed(hosts: string[] | undefined, host: string): boolean {
  if (hosts == null) return false
  const target = host.toLowerCase()
  return hosts.some((h) => h.toLowerCase() === target)
}

// The URL a DID is fetched from. `didToUrl` always yields `https` (ANP-03 requires
// TLS), so this is the ONLY place the scheme can change, and only for a host the
// caller named in `allowInsecureTransport`. Host and path still come from the DID.
function documentUrl(did: string, options: ResolveDidOptions): string {
  const url = didToUrl(did)
  if (!hostIsListed(options.allowInsecureTransport, new URL(url).hostname)) return url
  return url.replace(/^https:/, 'http:')
}

function isIpLiteral(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '')
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(bare) || bare.includes(':')
}

// Resolve a host to its A/AAAA addresses. A literal IP is returned as-is (no DNS);
// otherwise we use Node's resolver. Returns `null` when DNS validation is unavailable
// (browser — no `node:dns`), so the caller falls back to the hostname allowlist only.
// In Node, a lookup failure or empty result is NOT swallowed — it surfaces so
// `assertAllowedHost` fails closed rather than letting an unverifiable host through.
async function resolveHostAddresses(host: string, options: ResolveDidOptions): Promise<string[] | null> {
  if (options.resolveAddresses) return options.resolveAddresses(host)
  const bare = host.replace(/^\[|\]$/g, '')
  if (isIpLiteral(bare)) return [bare]
  const dns = getNodeBuiltin<typeof import('node:dns')>('dns')
  // browser: no `node:dns` — skip DNS validation, rely on the allowlist
  if (!dns) return null
  const records = await dns.promises.lookup(bare, { all: true, verbatim: true })
  return records.map((r) => r.address)
}

// A remote host must be (a) explicitly allowlisted and (b) resolve only to public
// addresses. Both gates apply to every hop, including the redirect target.
// Returns the validated public addresses (or `null` in a browser where there is no
// Node DNS resolver) so the caller can pin the actual connection to them — closing
// the DNS-rebinding TOCTOU between this validation and the outbound request.
async function assertAllowedHost(
  host: string,
  options: ResolveDidOptions,
  codes: FetchErrorCodes,
): Promise<string[] | null> {
  const allowedHosts = (options.allowedHosts ?? []).map((h) => h.toLowerCase())
  if (allowedHosts.length === 0) {
    throw new ConnectxError(
      codes.blocked,
      `Remote resolution requires a non-empty allowedHosts allowlist (host "${host}")`,
      { blockedReason: 'host_not_allowlisted' },
    )
  }
  if (!allowedHosts.includes(host.toLowerCase())) {
    throw new ConnectxError(codes.blocked, `Host "${host}" is not in the allowed hosts list`, {
      blockedReason: 'host_not_allowlisted',
    })
  }
  const addrs = await resolveHostAddresses(host, options)
  if (addrs === null) return null // browser: no DNS resolver — allowlist is the only gate
  if (addrs.length === 0) {
    // Fail closed: a host that resolves to no address cannot be verified as public.
    throw new ConnectxError(codes.blocked, `Host "${host}" did not resolve to any address`, {
      blockedReason: 'unmatched',
    })
  }
  // `allowPrivateHosts` is the one sanctioned way past the address gate, and it is
  // per-host: naming a host here exempts THAT host, never the range. The allowlist
  // above has already matched, so this cannot widen what is reachable, only what
  // kind of address an already-reachable host may be.
  if (!hostIsListed(options.allowPrivateHosts, host)) {
    for (const addr of addrs) {
      if (isPrivateIpAddress(addr)) {
        throw new ConnectxError(codes.blocked, `Host "${host}" resolves to a private/loopback address (${addr})`, {
          blockedReason: 'private_address',
        })
      }
    }
  }
  return addrs
}

// Map a did:web / did:wba identifier to the URL that serves its document.
//   did:web:example.com             → https://example.com/.well-known/did.json
//   did:web:example.com:users:alice → https://example.com/users/alice/did.json
//   did:web:example.com%3A8080      → https://example.com:8080/.well-known/did.json
//
// The method prefix MUST match exactly and in lowercase (`did:web:` / `did:wba:`),
// so a non-DID string like `example.com:user` is rejected instead of being mapped
// to a URL. Note the order: split on `:` FIRST (so a `%3A`-encoded port is not
// mistaken for a path separator), then decode each segment. Every segment is
// validated after decoding, so `..`, `.`, `/`, `\`, a bare `%` (double encoding)
// or a percent-encoded separator (`%2e`, `%2f`) cannot traverse to another path on
// an allowlisted host (audit 2026-09-11 ANP-…-04).
const DID_HOST = /^[A-Za-z0-9-]([A-Za-z0-9._-]*[A-Za-z0-9])?(:[0-9]+)?$/
const DID_PATH_SEGMENT = /^[A-Za-z0-9._-]+$/

function decodeDidSegment(raw: string, did: string): string {
  let out: string
  try {
    out = decodeURIComponent(raw)
  } catch {
    throw new ConnectxError('invalid_did', `Cannot derive URL from DID (bad percent-encoding in "${raw}"): ${did}`)
  }
  // A leftover `%` means double encoding (`%252e` → `%2e`); URL normalisation would
  // decode it a second time and could reintroduce `.`/`..`/`/`. Reject outright.
  if (out.includes('%')) {
    throw new ConnectxError('invalid_did', `Cannot derive URL from DID (double-encoded segment "${raw}"): ${did}`)
  }
  return out
}

export function didToUrl(did: string): string {
  const match = /^(did:web|did:wba):(.+)$/.exec(did)
  if (!match) throw new ConnectxError('invalid_did', `Cannot derive URL from DID: ${did}`)

  const rawSegments = match[2].split(':')
  if (rawSegments.some((s) => s === '')) {
    throw new ConnectxError('invalid_did', `Cannot derive URL from DID (empty segment): ${did}`)
  }

  const host = decodeDidSegment(rawSegments[0], did)
  if (!DID_HOST.test(host)) {
    throw new ConnectxError('invalid_did', `Cannot derive URL from DID (invalid host "${host}"): ${did}`)
  }

  const pathSegs = rawSegments.slice(1).map((raw) => {
    const seg = decodeDidSegment(raw, did)
    if (!DID_PATH_SEGMENT.test(seg) || seg === '.' || seg === '..') {
      throw new ConnectxError('invalid_did', `Cannot derive URL from DID (invalid path segment "${seg}"): ${did}`)
    }
    return seg
  })

  if (pathSegs.length === 0) return `https://${host}/.well-known/did.json`
  return `https://${host}/${pathSegs.join('/')}/did.json`
}

function keyFromJwk(jwk: NonNullable<VerificationMethod['publicKeyJwk']>): ResolvedKey {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.x) {
    const x = base64ToBytes(jwk.x)
    if (x.length !== 32) throw new ConnectxError('key_invalid', 'Invalid Ed25519 JWK public key length')
    return { curve: 'ed25519', bytes: x }
  }
  if (jwk.kty === 'EC' && jwk.crv === 'secp256k1' && jwk.x && jwk.y) {
    const x = base64ToBytes(jwk.x)
    const y = base64ToBytes(jwk.y)
    if (x.length !== 32 || y.length !== 32) throw new ConnectxError('key_invalid', 'Invalid secp256k1 JWK coordinates')
    const pub = new Uint8Array(33)
    pub[0] = (y[31] & 0x01) === 1 ? 0x03 : 0x02
    pub.set(x, 1)
    return { curve: 'secp256k1', bytes: pub }
  }
  throw new ConnectxError('key_unsupported', 'Unsupported publicKeyJwk')
}

// Read a response body into a string while rejecting anything over `maxBytes`.
function readCapped(res: Response, maxBytes: number, codes: FetchErrorCodes): Promise<string> {
  const cl = res.headers.get('content-length')
  if (cl != null) {
    const len = Number(cl)
    if (Number.isFinite(len) && len > maxBytes) {
      return Promise.reject(new ConnectxError(codes.tooLarge, `${codes.subject} too large (${len} bytes)`))
    }
  }
  if (!res.body) return res.text()
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  return (async () => {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maxBytes) {
        await reader.cancel()
        throw new ConnectxError(codes.tooLarge, `${codes.subject} exceeds ${maxBytes} bytes`)
      }
      chunks.push(value)
    }
    const merged = new Uint8Array(total)
    let offset = 0
    for (const c of chunks) {
      merged.set(c, offset)
      offset += c.byteLength
    }
    return new TextDecoder().decode(merged)
  })()
}

// Fetch a URL by connecting to an ALREADY-VALIDATED address, keeping the original
// Host header and TLS SNI set to the hostname. This is what closes the DNS-rebinding
// TOCTOU: the address was validated as public by `assertAllowedHost`, and we pin the
// TCP connect to exactly that address instead of letting the HTTP client perform a
// second, independent DNS resolution (which an attacker could answer with a private
// IP between validation and connection).
//
// Used only on the SDK's default path (no `options.fetch` override) in Node. In a
// browser (`resolveHostAddresses` returns null) the request falls back to
// `globalThis.fetch`, since a browser cannot pin DNS — the hostname allowlist is the
// only guard there. The `node:http(s)` / `node:stream` imports go through
// `getNodeBuiltin`, so the ESM browser entries carry no specifier a bundler would
// try to resolve.
export async function pinnedFetch(
  urlStr: string,
  init: RequestInit,
  address: string,
): Promise<Response> {
  const url = new URL(urlStr)
  const isHttps = url.protocol === 'https:'
  const mod = getNodeBuiltin<typeof import('node:http')>(isHttps ? 'https' : 'http')
  const stream = getNodeBuiltin<typeof import('node:stream')>('stream')
  // Unreachable through the SDK's own path: the caller only pins when a DNS resolver
  // answered, i.e. in Node. Failing is the right move if it ever is — falling back to
  // an unpinned `fetch` here would drop the DNS-rebinding guard this function exists for.
  if (!mod || !stream) {
    throw new ConnectxError('did_resolve_blocked', 'Pinned fetch requires node:http(s) and node:stream')
  }
  const { Readable } = stream

  const headers = new Headers(init.headers)
  if (!headers.has('host')) headers.set('host', url.host)

  const reqOptions = {
    method: init.method ?? 'GET',
    hostname: url.hostname,
    port: url.port ? Number(url.port) : isHttps ? 443 : 80,
    path: url.pathname + url.search,
    headers: Object.fromEntries(headers.entries()),
    ...(isHttps ? { servername: url.hostname } : {}), // TLS SNI = hostname, not the IP
    // Pin the connect to the validated address and never re-resolve the hostname.
    // Node's http client calls this lookup with `all: true`, so we return the
    // array form `[{ address, family }]` (and the single form for `all: false`).
    lookup: (_host: string, opts: { all?: boolean }, cb: (...args: [Error | null, string, number] | [Error | null, { address: string; family: number }[]]) => void) => {
      const family = address.includes(':') ? 6 : 4
      if (opts?.all) (cb as (e: Error | null, a: { address: string; family: number }[]) => void)(null, [{ address, family }])
      else (cb as (e: Error | null, a: string, f: number) => void)(null, address, family)
    },
  }

  return new Promise<Response>((resolve, reject) => {
    const req = mod.request(reqOptions, (res: import('node:http').IncomingMessage) => {
      const resHeaders = new Headers()
      for (const [k, v] of Object.entries(res.headers)) {
        if (typeof v === 'string') resHeaders.set(k, v)
        else if (Array.isArray(v)) for (const item of v) resHeaders.append(k, item)
      }
      const body = Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>
      resolve(new Response(body, { status: res.statusCode ?? 200, headers: resHeaders }))
    })
    req.on('error', reject)
    // Wire the caller's AbortSignal to the socket so the timeout in fetchDidDocument
    // aborts the in-flight request the same way it does for a standard fetch.
    const signal = init.signal
    if (signal) {
      if (signal.aborted) {
        req.destroy()
        return
      }
      signal.addEventListener('abort', () => req.destroy(), { once: true })
    }
    if (init.body != null) req.end(init.body as BodyInit)
    else req.end()
  })
}

/** Try each address in order and return the first response.
 *
 *  Every address here already passed the allowlist and the resolved-address policy for
 *  this host, so falling through from one to the next opens no window that a single
 *  pinned connect would have closed. A host with both families gets more than one
 *  address (`localhost` → `::1`, then `127.0.0.1`), and a server bound to only one of
 *  them is reachable through the hostname — stopping at the first would refuse it.
 *
 *  Only a rejection falls through: an HTTP response, a 404 included, is the server
 *  answering, and switching addresses because of it would turn a real answer into a
 *  retry against a different host. */
async function fetchFromAnyAddress(
  addrs: readonly string[],
  fetchAt: (addr: string) => Promise<Response>,
  codes: FetchErrorCodes,
): Promise<Response> {
  let lastError: unknown
  for (const addr of addrs) {
    try {
      return await fetchAt(addr)
    } catch (err) {
      lastError = err
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new ConnectxError(codes.failed, `No validated address was available for this ${codes.subject}`)
}

/** The path segments of a `did:wba` DID — everything after the method — or null for a DID
 *  of any other method (or an empty host segment). The host, port included, is `[0]`. */
function wbaSegments(did: string): string[] | null {
  if (!did.startsWith('did:wba:')) return null
  const segments = did.slice('did:wba:'.length).split(':')
  return segments[0] === '' ? null : segments
}

/** True when `did` carries no binding fingerprint segment, i.e. it names a stable subject
 *  path (ANP-03 §2.2.3) rather than a DID bound to a key. `identity.ts`'s `stableSubjectId`
 *  is the canonical reading of that rule; this states only the predicate the resolution
 *  path needs, because importing it would close a module cycle (`identity` → this file). */
function isStableSubjectPath(did: string): boolean {
  const segments = wbaSegments(did)
  return segments !== null && !(segments.length >= 2 && isFingerprint(segments[segments.length - 1]))
}

/** The DID a fetched document should be verified against, given what was asked for.
 *
 *  Normally the two are the same string and a mismatch is the drift `verifyDidDocument`
 *  refuses. A query by STABLE SUBJECT PATH is the one case where they legitimately differ:
 *  the path with its binding fingerprint segment removed is not a DID of its own and
 *  cannot be resolved on its own (ANP-03 §2.1 L53) — what a server answers at it is the DID
 *  that subject currently has. So the binding holds when the document's `id` is a full DID
 *  whose segments, minus that fingerprint, are exactly the ones asked for (§2.2.3 L183), and
 *  the proof is verified against that `id`: it is the only DID in play, and the one whose
 *  key signed.
 *
 *  Everything else keeps the strict reading — a document whose `id` carries no fingerprint
 *  itself, a DID of another method, or any other mismatch falls through to the caller's own
 *  `did`, so the drift error is raised where it belongs. */
function subjectQueryTarget(document: Record<string, unknown>, did: string): string {
  if (document.id === did) return did
  const id = document.id
  if (typeof id !== 'string' || !isStableSubjectPath(did) || isStableSubjectPath(id)) return did
  const askedSegments = wbaSegments(did)
  const idSegments = wbaSegments(id)
  if (askedSegments === null || idSegments === null) return did
  idSegments.pop()
  return idSegments.join(':') === askedSegments.join(':') ? id : did
}

/**
 * 一次受控交换里"响应体怎么读"。
 *
 * 读取必须是**这一层**的回调，而不是把 `Response` 交出去让调用方自己读：超时定时器
 * 要活到**读完**为止。返回 `Response` 再清定时器，等于给对端一个慢速 body 就能越过
 * `timeoutMs` 的口子——而这里的对端地址来自对端自己的文档。
 */
type ResponseConsumer = (res: Response, current: string, maxBytes: number) => Promise<unknown>

/**
 * Fetch a JSON document under the `ResolveDidOptions` network policy: allowlist and
 * resolved-address check on EVERY redirect hop, optionally a connect pinned to the
 * validated address (closing the DNS-rebinding TOCTOU), a byte cap, a timeout and a
 * media-type check.
 *
 * Shared by DID resolution and by the ANP-07 agent-description fetch, because the
 * second is a request to a host the DOCUMENT names rather than one the caller named
 * — it needs this policy at least as much, and a second copy of the hop-by-hop
 * validation is exactly where an SSRF hole would eventually appear. `codes` chooses
 * which error codes come out, so neither caller reports the other's failure.
 *
 * `request` turns the GET into whatever the caller describes. A body is not followed
 * across a redirect: RFC 9110 lets a 301/302 rewrite the method to GET, which would
 * silently drop the body and read the peer's answer to a different question as if it
 * answered this one.
 */
async function exchangeControlled(input: {
  url: string
  options: ResolveDidOptions
  codes: FetchErrorCodes
  request?: ControlledRequest
  consume: ResponseConsumer
  /** Which status codes count as an answer. Defaults to `res.ok` — the document
   *  callers read a 4xx/5xx body as a failure of the fetch. A caller that speaks a
   *  protocol where the status IS the answer (ANP-02's 401, P8 §2.4) passes
   *  `() => true` and reads it out of `consume`. */
  accept?: (status: number) => boolean
}): Promise<unknown> {
  const { options, codes, request } = input
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES
  const allowRedirects = options.allowRedirects ?? false
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS

  // Fail closed: a caller-managed fetch bypasses the SDK's pinned connect, so it is
  // only allowed as an explicit opt-in. This prevents an uncontrolled network
  // side-channel from silently replacing the pinned default in a secure path.
  if (options.fetch != null && options.allowUncontrolledFetch !== true) {
    throw new ConnectxError(
      codes.blocked,
      'A custom fetch() requires allowUncontrolledFetch:true; the SDK cannot pin a caller-managed connection to the validated address',
    )
  }

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  // Computed once: every hop of one exchange sends the same thing.
  const init: RequestInit = {
    signal: controller.signal,
    redirect: 'manual',
    headers: request?.headers ?? DID_DOCUMENT_ACCEPT,
    ...(request !== undefined ? { method: request.method, body: request.body } : {}),
  }

  try {
    // Follow redirects MANUALLY, one hop at a time, so every host in the chain — not
    // just the first and last — passes the allowlist + resolved-address policy. A
    // single `redirect: 'follow'` would let an allowlisted host bounce through an
    // internal/private address (SSRF) while only the final URL got re-checked.
    let current = input.url
    for (let hop = 0; ; hop++) {
      const hopUrl = new URL(current)
      const host = hopUrl.hostname
      // A redirect may downgrade https → http. That is the same relaxation
      // `allowInsecureTransport` grants per host, so it needs the same permission:
      // without this, a bare redirect could strip TLS for a host never opted in.
      if (hopUrl.protocol !== 'https:' && !hostIsListed(options.allowInsecureTransport, host)) {
        throw new ConnectxError(
          codes.blocked,
          `URL for host "${host}" is not https (${hopUrl.protocol}//); pass allowInsecureTransport to permit it`,
          { blockedReason: 'insecure_transport' },
        )
      }
      const addrs = await assertAllowedHost(host, options, codes)

      let res: Response
      try {
        if (options.fetch) {
          // Explicit opt-in (allowUncontrolledFetch:true). The caller's connect
          // strategy is the caller's responsibility; the SDK has already run the
          // allowlist + address policy but does NOT pin through this fetcher.
          res = await options.fetch(current, init)
        } else if (addrs == null) {
          // No DNS resolver (browser) and no explicit pinned transport: the SDK
          // cannot pin the connect target, so remote resolution is refused. The
          // inline-didDocument / dev-mode flow uses a local doc and never reaches here.
          throw new ConnectxError(
            codes.blocked,
            'Remote resolution requires a DNS resolver (Node) or an explicit allowUncontrolledFetch transport; this environment cannot pin the connection',
            { blockedReason: 'unmatched' },
          )
        } else {
          // Default Node path: pin the connect to an address validated above, so a DNS
          // rebinding between validation and connection cannot reach a private target.
          // EVERY validated address is tried, not just the first: a hostname that answers
          // for both families reaches a server bound to only one of them — `localhost`
          // gives `::1` before `127.0.0.1` on macOS, so a server on IPv4 alone would be
          // refused by a host that is in fact reachable.
          res = await fetchFromAnyAddress(
            addrs,
            (addr) => pinnedFetch(current, init, addr),
            codes,
          )
        }
      } catch (err) {
        // The timer aborts the controller on timeout; any other rejection is a
        // network failure. Distinguish them so callers know whether to retry the
        // same call or tune the timeout / their network.
        if (controller.signal.aborted) {
          throw new ConnectxError(codes.timeout, `${codes.subject} fetch from ${current} aborted after ${timeoutMs}ms`, {
            cause: err,
          })
        }
        throw new ConnectxError(
          codes.failed,
          `Failed to fetch ${codes.subject} from ${current}: ${err instanceof Error ? err.message : String(err)}`,
          { cause: err },
        )
      }
      const location = res.headers.get('location')

      if (res.status >= 300 && res.status < 400 && location) {
        // A body cannot survive this: RFC 9110 lets a 301/302 rewrite the method to
        // GET, and even a 307/308 — which preserves it — would re-send a signed body to
        // a host that never agreed to it. Refused rather than followed, with the
        // `Location` in the message so the caller can address the endpoint directly.
        if (request !== undefined) {
          throw new ConnectxError(
            codes.failed,
            `Failed to fetch ${codes.subject} from ${current} (${res.status} redirect to ${new URL(location, current).toString()}); a request with a body is not followed`,
          )
        }
        if (!allowRedirects) {
          throw new ConnectxError(codes.failed, `Failed to fetch ${codes.subject} from ${current} (${res.status} redirect)`)
        }
        if (hop >= maxRedirects) {
          throw new ConnectxError(codes.tooManyRedirects, `Too many redirects fetching ${codes.subject} from ${current} (limit ${maxRedirects})`)
        }
        current = new URL(location, current).toString()
        continue
      }

      if (!res.ok && !(input.accept?.(res.status) ?? false)) {
        // Carry the status: it is the one thing about a non-2xx that a caller can act
        // on without parsing the message (a 404 is an answer, a 503 is a retry).
        throw new ConnectxError(codes.failed, `Failed to fetch ${codes.subject} from ${current} (${res.status})`, {
          status: res.status,
        })
      }
      return await input.consume(res, current, maxBytes)
    }
  } finally {
    clearTimeout(timer)
  }
}

/**
 * Fetch a JSON document under {@link exchangeControlled}'s policy.
 */
export function fetchControlledJson(
  url: string,
  options: ResolveDidOptions,
  codes: FetchErrorCodes,
  request?: ControlledRequest,
): Promise<unknown> {
  return exchangeControlled({
    url,
    options,
    codes,
    ...(request !== undefined ? { request } : {}),
    consume: async (res, current, maxBytes) => {
      assertDocumentContentType(res, current, codes)
      const text = await readCapped(res, maxBytes, codes)
      try {
        return JSON.parse(text)
      } catch (err) {
        throw new ConnectxError(codes.invalidDocument, `${codes.subject} from ${current} is not valid JSON`, { cause: err })
      }
    },
  })
}

/**
 * 同一条网络策略下的一次交换，**不看响应体**。
 *
 * 存在的理由是 Notification：P1 §5.6 L199 的"每个 Request 必须回一个 Response"不覆盖
 * 它，对端完全可以只回 200 与一个空 body——按 JSON 去解析就等于把一次成功的投递当失败
 * 重试。注意正文 `consume` 那一层仍然**读**（按 `maxBytes`）：不读的 body 会让连接停在
 * 半开状态，而不设上限地读，就是让一个回 4 GiB 的对端把内存吃掉。
 */
export function fetchControlledDiscardingBody(
  url: string,
  options: ResolveDidOptions,
  codes: FetchErrorCodes,
  request?: ControlledRequest,
): Promise<void> {
  return exchangeControlled({
    url,
    options,
    codes,
    ...(request !== undefined ? { request } : {}),
    consume: async (res, _current, maxBytes) => {
      await readCapped(res, maxBytes, codes)
      return undefined
    },
  }).then(() => undefined)
}

/**
 * 同一条网络策略下的一次交换，**任何状态码都当答复交回来**。
 *
 * 与 {@link fetchControlledJson} 的差别只有一处，而那一处是协议定的：ANP-02 §3.2.4.1
 * 把外层认证的失败放在 **HTTP 状态**与 `WWW-Authenticate` 上，不是放在 JSON-RPC 的
 * `error` 里（P8 §2.4）。对端回 401 是一次**跑通的交换**，它的答复就是那个状态码与头；
 * 按异常抛掉，调用方就只剩"发送失败"这一句话，既分不出"我被拒了"与"网络不通"，也拿不到
 * 挑战头。
 *
 * 仍然受全套策略约束：白名单、逐跳验证、连接钉在已验证地址上、超时、字节上限。**任何
 * 2xx/3xx 之外的跳转也不跟随**——带 body 的请求被 301/302 改写成 GET 之后，重发的是一份
 * 对端从未同意过的、要求签名的东西。
 */
export async function fetchControlledResponse(
  url: string,
  options: ResolveDidOptions,
  codes: FetchErrorCodes,
  request?: ControlledRequest,
): Promise<{ status: number; headers: Headers; text: string }> {
  return (await exchangeControlled({
    url,
    options,
    codes,
    ...(request !== undefined ? { request } : {}),
    accept: () => true,
    consume: async (res, _current, maxBytes) => ({
      status: res.status,
      headers: res.headers,
      text: await readCapped(res, maxBytes, codes),
    }),
  })) as { status: number; headers: Headers; text: string }
}

async function fetchDidDocument(url: string, options: ResolveDidOptions): Promise<DidDocument> {
  return (await fetchControlledJson(url, options, DID_DOCUMENT_FETCH_CODES)) as DidDocument
}

/**
 * Verify a DID document you already hold: that it describes the DID you asked about,
 * and that its top-level `proof` holds under the policy for that DID
 * (ANP-03 §2.5.5). Throws `did_resolve_invalid_document` on failure; returns nothing
 * on success.
 *
 * This is the DOCUMENT-level half of what `resolveVerificationKey` enforces. The other
 * half — that a keyid names a method which `authentication` authorizes — needs a
 * keyid, so it stays there. Call this when you hold a document from somewhere other
 * than `resolveDidDocument` (a store you manage, a peer, a fixture) and want it
 * checked before you trust anything inside it.
 */
export function verifyDidDocument(
  document: Record<string, unknown>,
  did: string,
  options: ResolveDidOptions = {},
): void {
  const doc = document as DidDocument
  // Identity binding: the document MUST describe the DID that was requested, otherwise
  // a keyid for one DID could be satisfied by another DID's document (multi-tenant
  // proxy / stale cache / malicious document service).
  if (typeof doc.id !== 'string' || doc.id !== did) {
    throw new ConnectxError(
      'did_resolve_invalid_document',
      `DID document id "${String(doc.id)}" does not match keyid DID "${did}"`,
    )
  }
  assertDocumentProof(doc, did, options.documentProof ?? 'lenient')
}

/**
 * Resolve a DID to its document: derive the document URL (`didToUrl`), fetch it under
 * the `ResolveDidOptions` network policy, verify it (`verifyDidDocument`), and — when a
 * `documentStore` is configured — keep the verified copy.
 *
 * This is the document-level entry point; `resolveVerificationKey` is the key-level one
 * and shares this exact fetch path, so both honor the same allowlist, DNS pinning and
 * store. Without `documentStore` every call is a fresh network fetch.
 */
export async function resolveDidDocument(
  did: string,
  options: ResolveDidOptions = {},
): Promise<ResolvedDidDocument> {
  const docUrl = documentUrl(did, options)
  const store = options.documentStore
  const ttl = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS

  if (store) {
    const hit = await store.get(did)
    // A stored copy is served only while it is both fresh AND still current. A
    // document that has since become superseded is a miss even inside the TTL: the
    // DID has moved on since we fetched it, and ttl is about staleness, not about
    // an identity that has been superseded away.
    if (hit && hit.did === did && Date.now() - hit.fetchedAt < ttl && !isSuperseded(hit.document)) {
      return { ...hit, source: 'store' }
    }
  }

  const document = (await fetchDidDocument(docUrl, options)) as Record<string, unknown>
  const resolvedDid = subjectQueryTarget(document, did)
  verifyDidDocument(document, resolvedDid, options)

  const entry: ResolvedDidDocument = { did: resolvedDid, document, docUrl, source: 'network', fetchedAt: Date.now() }
  // Never store a superseded document. Caching it would pin an identity that has
  // already moved on, and the read above can never serve it anyway — so writing it
  // would only make the invalidation implicit.
  if (store && !isSuperseded(document)) await store.set(entry)
  return entry
}

// Resolve the signing key referenced by a keyid (a DID URL such as
// `did:web:example.com#key-1`). `didDocument` may be supplied inline — used by
// the browser dev-mode flow where no reachable `.well-known` host exists yet.
// When no inline document is given, the keyid is resolved over the network; pass
// `ResolveDidOptions.allowedHosts` to bound which hosts may be fetched (SSRF).
export async function resolveVerificationKey(
  keyid: string,
  didDocument?: unknown,
  options: ResolveDidOptions = {},
): Promise<ResolvedKey> {
  const hashIdx = keyid.indexOf('#')
  const did = hashIdx === -1 ? keyid : keyid.slice(0, hashIdx)
  const fragment = hashIdx === -1 ? null : keyid.slice(hashIdx + 1)

  let doc: DidDocument
  let docUrl: string | undefined
  if (didDocument && typeof didDocument === 'object') {
    doc = didDocument as DidDocument
    verifyDidDocument(doc as Record<string, unknown>, did, options)
  } else {
    // Goes through the document-level entry point, so the store (when the caller
    // configured one) is shared with `resolveDidDocument` instead of bypassed.
    const resolved = await resolveDidDocument(did, options)
    docUrl = resolved.docUrl
    doc = resolved.document as DidDocument
  }

  const vms = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []
  const vm = vms.find((v) => {
    if (!controllerMatches(v, did)) return false
    if (fragment === null) return true
    const id = v?.id ?? ''
    // Accept only the exact full keyid or the DID-spec relative form `#fragment`.
    // A loose `endsWith(#fragment)` would let a DIFFERENT DID's method satisfy the
    // keyid, so it is intentionally not accepted.
    return id === keyid || id === `#${fragment}`
  })
  if (!vm) throw new ConnectxError('did_resolve_not_found', `No verification method matches keyid ${keyid}`)

  // ANP-02 §3.2.1 step 5: naming a key is not enough — it MUST be authorized for
  // authentication. The SDK writes `authentication` when it BUILDS a document
  // (crypto/didDocument.ts), so it must also check it when it READS one; without
  // this a key listed only under `assertionMethod` is accepted as a login key.
  // (The document's own integrity was already checked by `verifyDidDocument` above.)
  assertAuthenticationAuthorized(doc, vm)

  let key: ResolvedKey
  if (vm.publicKeyMultibase) key = { ...decodeMultibaseKey(vm.publicKeyMultibase), docUrl }
  else if (vm.publicKeyJwk) key = { ...keyFromJwk(vm.publicKeyJwk), docUrl }
  else throw new ConnectxError('did_resolve_not_found', 'Verification method has no usable public key')

  // ANP-2026-09-11-01 ties the document to its identifier through the key that signs
  // the document's OWN proof: that key MUST reproduce the path fingerprint. Applying
  // the same requirement to EVERY resolved keyid is too broad for a multi-device
  // `did:wba` document — a device entry's `#dev-signing` key is deliberately a
  // DIFFERENT key from the root the `e1_` segment commits to, so the broad check
  // rejects every compliant device and makes its origin proof unverifiable (P6 §6.4).
  //
  // What carries the binding instead is the document-level guarantee already in force:
  // for an ACTIVE e1_ document `assertDocumentProof` (run by `verifyDidDocument` above)
  // REQUIRES the proof and verifies it against the fingerprint-bound key. A method
  // reached after that belongs to a now-authenticated document, and
  // `assertAuthenticationAuthorized` confines it to `authentication`. So binding the
  // fingerprint to the PROOF key alone is sound. Every case where that guarantee does
  // NOT hold keeps the strict whole-document binding: a `k1_` or unknown profile whose
  // proof this layer cannot verify, and a deactivated transition document (whose proof
  // may legitimately be absent or a recovery proof).
  if (!fingerprintCarriedByProofKey(doc, did, keyid, options.documentProof ?? 'lenient')) {
    assertFingerprintBinding(did, key)
  }
  return key
}

// Whether the fingerprint check may be waived for this keyid because the DID's binding
// is carried by the document's own proof key instead (see the call site). Only for an
// ACTIVE e1_ document whose proof policy is `required` — the case `assertDocumentProof`
// has just verified — and only for a keyid that NAMES A METHOD other than that proof
// key. A keyid with no fragment selects a method by position, not by identity, so it
// keeps the strict binding; so does the proof key itself.
function fingerprintCarriedByProofKey(
  doc: DidDocument,
  did: string,
  keyid: string,
  mode: 'lenient' | 'strict',
): boolean {
  if (!keyid.includes('#')) return false
  if (documentProofPolicy(doc, did, mode) !== 'required') return false
  const raw = doc as Record<string, unknown>
  const proofKeyId = documentProofKeyId(raw)
  if (proofKeyId === undefined) return false
  const wanted = canonicalDidUrl(raw.id, keyid)
  const proof = canonicalDidUrl(raw.id, proofKeyId)
  return wanted !== undefined && proof !== undefined && wanted !== proof
}

/** The Data Integrity cryptosuites this SDK can verify. `eddsa-jcs-2022` is the
 *  only one it implements; the k1_ profile's secp256k1 suite is out of scope. */
const IMPLEMENTED_PROOF_SUITES = new Set(['eddsa-jcs-2022'])

// Is the document's top-level `proof` required for this DID?
//   skipped    — no proof concept applies (native did:web per Appendix B, or a
//                CAIP-10 account id, which carries no fingerprint to bind to)
//   required   — a missing proof rejects the document
//   transition — a deactivated document that names a successor: proof is optional
//   optional   — a present proof is verified, a missing one accepted
function documentProofPolicy(
  doc: DidDocument,
  did: string,
  mode: 'lenient' | 'strict',
): 'skipped' | 'required' | 'transition' | 'optional' {
  if (!did.startsWith('did:wba:')) return 'skipped'
  const segment = did.slice(did.lastIndexOf(':') + 1)
  // The e1_ profile has no loose mode for an ACTIVE document (ANP-03 §2.5.5): its
  // proof is what ties the document to the fingerprint the DID commits to. A
  // deactivated transition document is the opposite case — §2.5.5 says its proof
  // MAY be absent, because both the old private key and a pre-authorized recovery
  // key can be gone, and when present it may be a RECOVERY proof, which is
  // deliberately not fingerprinted to the DID path.
  if (isFingerprint(segment) && segment.startsWith('e1_')) {
    return isSuperseded(doc as Record<string, unknown>) ? 'transition' : 'required'
  }
  return mode === 'strict' ? 'required' : 'optional'
}

function assertDocumentProof(doc: DidDocument, did: string, mode: 'lenient' | 'strict'): void {
  const policy = documentProofPolicy(doc, did, mode)
  if (policy === 'skipped') return
  const proof = doc.proof
  if (proof === undefined) {
    if (policy === 'required') {
      throw new ConnectxError('did_resolve_invalid_document', `DID document for "${did}" has no proof, which this profile requires`)
    }
    return
  }
  if (policy === 'transition') {
    // A present proof MUST verify (§2.5.5: a malformed, unauthorized or
    // cryptographically failing proof invalidates the transition and may not be
    // downgraded to a provider assertion). Two authorized forms exist — the
    // predecessor's binding key, or a recovery key pre-authorized before
    // deactivation — but this layer can only judge the first, and only when the
    // document also describes the key it names: authorizing a recovery key needs the
    // pre-deactivation trusted document, which the chain layer (did/chain.ts) holds.
    // So this layer rejects everything it CAN see is wrong, and defers the one case
    // it structurally cannot see. That case is not a weakening: a transition
    // document's proof may legitimately be ABSENT (§2.5.5), so a deferred proof is
    // never what makes it trustworthy — the chain's per-hop adjudication is, and it
    // fails closed when neither form holds.
    const keyid = documentProofKeyId(doc as Record<string, unknown>)
    if (keyid === undefined) {
      // Structurally malformed: no proof shape could be read at all.
      throw new ConnectxError('did_resolve_invalid_document', `DID document proof for "${did}" is malformed`)
    }
    if (verifyDidDocumentProof(doc as Record<string, unknown>, { did })) return
    if (verifyDidDocumentProof(doc as Record<string, unknown>)) return
    // The named key is not described here, so this may be a recovery proof whose
    // material lives elsewhere — only the chain layer can say. Anything else (a
    // described key that did not verify) is a failing proof and is refused now.
    if (documentProofKey(doc as Record<string, unknown>, keyid)) {
      throw new ConnectxError('did_resolve_invalid_document', `DID document proof for "${did}" is invalid`)
    }
    return
  }
  // A proof in a cryptosuite this SDK does not implement — the k1_ profile's
  // `didwba-jcs-ecdsa-secp256k1-2025` — cannot be judged here. Under `'required'`
  // that is a rejection; under `'optional'` it is skipped, because the check that
  // actually carries the security for a path-type DID (`assertFingerprintBinding`,
  // run below) is independent of it.
  const cryptosuite = proof !== null && typeof proof === 'object' && !Array.isArray(proof)
    ? (proof as Record<string, unknown>).cryptosuite
    : undefined
  if (policy === 'optional' && (typeof cryptosuite !== 'string' || !IMPLEMENTED_PROOF_SUITES.has(cryptosuite))) return
  if (!verifyDidDocumentProof(doc as Record<string, unknown>, { did })) {
    throw new ConnectxError('did_resolve_invalid_document', `DID document proof for "${did}" is invalid`)
  }
}

/** Is `keyid` listed in the document's `relationship` list? DID Core allows the
 *  absolute method id or the DID-spec relative `#fragment` form, and an embedded
 *  method object counts when its `id` matches. Shared by the authentication check
 *  below, the continuity chain's recovery-key authorization (ANP-03 §2.5.5 rule 2),
 *  and the device-manifest reader (P2 §5.5 rule 4 / §10.2.1), so all of them apply
 *  one matching rule instead of several that can drift.
 *
 *  `keyAgreement` and `capabilityInvocation` are accepted because P2 §10.2.1 asks
 *  WHICH relationships a device entry's key ids fall under, and reports the fact to
 *  the E2EE Profile to judge — a reader that could only ask about two of the four
 *  would be unable to express the answer.
 *
 *  The comparison is on RESOLVED DID URLs (`canonicalDidUrl`), the same rule
 *  `documentProofKey` uses: for a document whose id is `did:X`, `#key-1` and
 *  `did:X#key-1` are one identifier and `did:other#key-1` is not. Matching fragments
 *  alone would let a keyid in another DID's namespace authorize against this
 *  document's relative entry (ANP-2026-09-17-R01). */
export function isMethodAuthorized(
  doc: Record<string, unknown>,
  relationship: 'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation',
  keyid: string,
): boolean {
  const wanted = canonicalDidUrl(doc.id, keyid)
  if (wanted === undefined) return false
  const entries = Array.isArray(doc[relationship]) ? (doc[relationship] as AuthenticationEntry[]) : []
  return entries.some((entry) => {
    const id = typeof entry === 'string' ? entry : entry !== null && typeof entry === 'object' && typeof entry.id === 'string' ? entry.id : undefined
    return id !== undefined && canonicalDidUrl(doc.id, id) === wanted
  })
}

// The resolved method MUST appear in `authentication` — a verification method that
// is merely present in the document (e.g. listed only under `assertionMethod`) is
// not thereby a login key.
function assertAuthenticationAuthorized(doc: DidDocument, vm: VerificationMethod): void {
  const id = typeof vm.id === 'string' ? vm.id : ''
  if (!isMethodAuthorized(doc as Record<string, unknown>, 'authentication', id)) {
    throw new ConnectxError(
      'did_resolve_unauthorized',
      `Verification method "${id}" is not listed in the document's authentication relationship, so it may not authenticate a request`,
    )
  }
}

// A path-type `did:wba:<host>:<path…>:<fingerprint>` commits to its key inside the
// DID: the last segment is the RFC 7638 thumbprint of the public key. When the DID
// carries such a fingerprint, the resolved key MUST reproduce it exactly, so a DID
// document cannot bind an attacker's key to a victim's DID (audit 2026-09-11
// ANP-2026-09-11-01). The method prefix is matched case-sensitively: only lowercase
// `did:wba:` is treated as fingerprint-bound, so a mixed-case spelling cannot skip
// the check.
//
// Not applied to every keyid: when an active e1_ document's own proof already binds
// the fingerprint (see `fingerprintCarriedByProofKey`), a keyid naming a DIFFERENT
// authorized method is exempt.
function assertFingerprintBinding(did: string, key: ResolvedKey): void {
  if (!did.startsWith('did:wba:')) return
  const segment = did.slice(did.lastIndexOf(':') + 1)
  if (!isFingerprint(segment)) return
  const actual = didFingerprint(key.curve, key.bytes)
  if (actual !== segment) {
    throw new ConnectxError(
      'did_resolve_invalid_document',
      `DID "${did}" binds fingerprint "${segment}" but the resolved key's fingerprint is "${actual}"`,
    )
  }
}

// A verification method is controlled by the DID (or one of its controllers).
// When absent we rely on the `doc.id === did` binding already enforced; when
// declared, it must agree or the method is not accepted for this DID.
function controllerMatches(vm: VerificationMethod, did: string): boolean {
  const c = vm.controller
  if (c == null) return true
  if (typeof c === 'string') return c === did
  if (Array.isArray(c)) return c.some((x) => typeof x === 'string' && x === did)
  return false
}
