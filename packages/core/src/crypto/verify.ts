import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { ethPersonalSignHash } from '../wallet/eip1193'
import { ConnectxError } from '../errors'
import {
  parseSignatureInput,
  buildSignatureBase,
  buildContentDigestValue,
} from './signatureBase'
import { jcsCanonicalize } from './fingerprint'
import { base64ToBytes, utf8 } from './encoding'
import type { ParsedSignatureInput } from './signatureBase'
import type { ResolvedKey } from './resolveDid'

export interface VerifyHttpSignatureInput {
  method: string
  path: string
  authority: string
  targetUri?: string
  /**
   * The actual request's query string — INCLUDING the leading `?` (e.g. `?tenant=a`),
   * or `''` when there is none. In strict mode the `@target-uri` query must equal
   * this, so a proof signed over one query cannot be accepted for another. The
   * value should be derived by the verifier from the real request, not from a
   * caller-supplied target URI alone.
   */
  search?: string
  headers: Record<string, string> // lowercase keys
  body: string
  key: ResolvedKey
  /**
   * Anti-replay. When set, the Signature-Input `nonce` AND the body's `nonce`
   * field must both equal this value. This lets a server bind a proof to the
   * challenge it issued. Verification success alone is NOT a replay guard — see
   * {@link nonceStore} and the note on `verifyHttpMessageSignature`.
   */
  expectedNonce?: string
  /**
   * Optional one-time nonce store. Called with the proof's `(keyid, nonce)` AFTER
   * the proof otherwise verifies; returning `false` (the pair was already consumed)
   * rejects the proof. This is the server-side atomic consume the SDK cannot perform
   * for itself — pair it with `expectedNonce` to stop in-window replay. May return a
   * promise: a shared store (Redis, PostgreSQL) cannot answer synchronously, and
   * requiring one would push callers off this helper onto the low-level pieces.
   */
  nonceStore?: NonceStore
  /**
   * Component compatibility mode.
   * - `'strict'` (default): require `@target-uri` (the official covered set uses it)
   *   plus `@method`, and the body's digest whenever a body is present. Legacy
   *   `@path`-only signatures are rejected.
   * - `'legacy'`: also accept the old browser-shim set that covered `@path` in
   *   place of `@target-uri`. Only enable for known old clients; otherwise a
   *   signature that binds only the path (not the full URI scheme) is accepted.
   */
  mode?: 'strict' | 'legacy'
}

/**
 * A one-time (atomic) nonce store used to consume a nonce once a proof verifies.
 * Provide your own for shared/multi-server state (e.g. Redis, PostgreSQL); this is
 * a reference implementation and the injection point `verifyHttpMessageSignature`
 * accepts any object with `consume`.
 *
 * The key is the PAIR `(keyid, nonce)`, not the bare nonce (ANP-02 §3.2.1 step 8).
 * A nonce is only guaranteed unique per signer, so keying on it alone lets one
 * DID's proof burn another DID's challenge — a denial of service on a value the
 * victim never chose. Implementations MUST use the pair as the key.
 *
 * `consume` may return a promise. A shared store (a database row, a Redis call)
 * cannot answer synchronously, and a synchronous-only interface would make the
 * whole point of a shared store — one nonce set across instances — unreachable
 * through the high-level {@link verifyAnpLoginRequest}.
 */
export interface NonceStore {
  consume(keyid: string, nonce: string): boolean | Promise<boolean>
}

export interface NonceStoreOptions {
  /** How long a consumed nonce is remembered (ms) before it is treated as stale
   *  and pruned. Keep this larger than the verifier's maximum signature lifetime
   *  (the create-skew + max-TTL window, ~3900s) so a replayed proof is rejected
   *  for its whole validity window. Must be a positive integer. Default 2h. */
  ttlMs?: number
  /** Maximum number of consumed nonces retained. Once the store is full of
   *  live (non-expired) nonces it fails closed — a new nonce is rejected rather
   *  than evicting a live one. Must be a positive integer. Default 10,000. */
  maxSize?: number
}

/** Bounded reference nonce store: keeps consumed nonces for a TTL and at most
 *  `maxSize` entries, evicting expired entries so a long-running service cannot
 *  grow unbounded. Anti-replay is preserved: once the store is full of live
 *  nonces, a new nonce is rejected (fail-closed) instead of evicting an older
 *  live nonce and letting its still-valid signature be replayed. This is a
 *  single-process, finite-capacity reference implementation — for shared /
 *  multi-server / high-throughput state prefer an external store with a real TTL,
 *  atomic consume and a capacity policy (e.g. Redis). */
export function createNonceStore(opts: NonceStoreOptions = {}): NonceStore {
  const ttlMs = positiveCount(opts.ttlMs, 2 * 60 * 60 * 1000, 'ttlMs') // 2h, > max signature window
  const maxSize = positiveCount(opts.maxSize, 10_000, 'maxSize')
  // `${keyid} ${nonce}` -> expiry timestamp (ms). The pair is the key: one DID's
  // replay must never consume another's challenge (see `NonceStore`).
  const seen = new Map<string, number>()

  return {
    consume(keyid: string, nonce: string): boolean {
      const key = `${keyid} ${nonce}`
      const now = Date.now()
      const expiry = seen.get(key)
      if (expiry !== undefined) {
        if (expiry > now) return false // already consumed and still fresh
        seen.delete(key) // expired: no longer remembered, treat as unused
      }
      // Reclaim space from expired entries before admitting a new nonce.
      if (seen.size >= maxSize) {
        for (const [k, v] of seen) {
          if (seen.size < maxSize) break
          if (v <= now) seen.delete(k)
        }
      }
      // Still at capacity with live nonces: fail closed rather than evict a live
      // nonce, which would let a still-valid signature be replayed (review §3.1).
      if (seen.size >= maxSize) return false
      seen.set(key, now + ttlMs)
      return true
    },
  }
}

/** Validate a nonce store option as a positive integer, or throw. Guards against
 *  NaN / Infinity / fractions / zero / negatives that would otherwise silently
 *  disable the bounds (see review §3.2). */
function positiveCount(value: number | undefined, fallback: number, name: string): number {
  if (value === undefined) return fallback
  if (!Number.isInteger(value) || value <= 0) {
    throw new ConnectxError('invalid_argument', `NonceStore ${name} must be a positive integer`)
  }
  return value
}

const FRESHNESS_SKEW_SECONDS = 300
// A fresh signature is created within the SDK TTL (300s) and expires in a bounded
// window. These caps reject replayed / infinite-lifetime signatures.
const MAX_CREATED_AGE_SECONDS = 600
const MAX_TTL_SECONDS = 3600

// The official client sends `Signature: sig1=:<base64>:` (RFC 9421 labeled binary
// format); the legacy browser shim sent a bare base64 value. Decode both. The label
// is returned so the verifier can correlate it with Signature-Input.
function decodeSignatureHeader(header: string): { label: string | null; bytes: Uint8Array } | null {
  const labeled = /^([A-Za-z0-9_-]+)=:([^:]+):\s*$/.exec(header.trim())
  if (labeled) return { label: labeled[1], bytes: base64ToBytes(labeled[2]) }
  const bare = header.trim()
  if (/^[A-Za-z0-9+/=]+$/.test(bare)) return { label: null, bytes: base64ToBytes(bare) }
  return null
}

// The official client bundles created/expires (Unix seconds) into the
// Signature-Input params; enforce the window. ANP-02 §3.1.1 makes `created` a MUST
// and `expires` a SHOULD, so a proof without `expires` is legal — it is bounded by
// `created` alone (the caps below) rather than rejected outright. `created` itself
// is not optional: without it there is no defined lifetime at all, and `expires`
// alone would still let a captured proof replay for as long as its own window says.
export function freshnessOk(params: Record<string, string | number>): boolean {
  const now = Math.floor(Date.now() / 1000)
  const created = params.created
  if (created == null) return false
  const createdNum = Number(created)
  if (!Number.isFinite(createdNum)) return false
  if (createdNum > now + FRESHNESS_SKEW_SECONDS) return false // not from the future
  if (now - createdNum > MAX_CREATED_AGE_SECONDS) return false // not too old
  const expires = params.expires
  if (expires == null) return true // SHOULD, not MUST: `created` bounds it above
  const expiresNum = Number(expires)
  if (!Number.isFinite(expiresNum)) return false
  if (expiresNum <= createdNum) return false // positive TTL
  if (expiresNum - createdNum > MAX_TTL_SECONDS) return false // bounded TTL
  if (now >= expiresNum) return false // not expired
  return true
}

// Extract the `nonce` the signer embedded in the request body, if any. The SDK's
// login/register bodies are JSON `{ nonce, did, didDocument }`; anything else has
// no replayable nonce and is treated as absent. Exported because the ZK login
// profile (§6.1) reuses this carrier rule verbatim: its body is a different shape
// but puts the challenge in the same place.
export function bodyNonce(body: string): string | undefined {
  try {
    const parsed = JSON.parse(body) as { nonce?: unknown }
    return typeof parsed?.nonce === 'string' ? parsed.nonce : undefined
  } catch {
    return undefined
  }
}

/**
 * Why a signature check failed. Deliberately finer-grained than the wire vocabulary:
 * a server needs to tell "your proof is bad" apart from "I could not check it", and
 * a bare `false` cannot. `serverAuth.ts` collapses these onto the nine ANP-02 error
 * values a server may emit; the public `verifyHttpMessageSignature` keeps returning
 * `boolean` and discards them.
 *
 * NOT exported from the package entry: this is the server-authoritative detail, and
 * a caller that relays it verbatim hands an attacker a per-check oracle. See
 * `AnpLoginFailure` for the wire-safe subset and the rule about `unverifiable`.
 */
export type VerifyFailure =
  /** The request's proof envelope: missing/duplicate params, a covered set below the
   *  ANP-02 minimum, or a signed target that disagrees with the actual request. */
  | 'request_malformed'
  | 'content_digest_mismatch'
  | 'timestamp_invalid'
  | 'nonce_mismatch'
  | 'nonce_consumed'
  | 'signature_invalid'
  /** We could not reach the decision: the caller's nonce store threw. Not the
   *  peer's fault, so it must not be reported as a bad proof (see `unverifiable`). */
  | 'store_failed'

export type VerifyOutcome =
  | { ok: true }
  | {
      ok: false
      reason: VerifyFailure
      /** The underlying throw, when there was one (`store_failed`). For the caller's
       *  OWN log — it names infrastructure the peer must not learn about. */
      cause?: unknown
    }

// Check the `Signature` value against a rebuilt signature base. Shared by both
// carriers of the same ANP-02 proof (the HTTP headers of §3 and the JSON envelope
// of §4): the signature format, the label rule and the curve dispatch are carrier
// -independent — §4 changes where the fields travel, not how the bytes are signed.
//
// `parsed` must be the parse of the Signature-Input that came WITH this signature:
// the label check below is what ties the two together.
async function verifyProofSignature(input: {
  signature: string
  parsed: ParsedSignatureInput
  base: string
  key: ResolvedKey
  /** `'legacy'` only relaxes the label rule (the old browser shim sent an unlabeled
   *  value). It never relaxes freshness, digest or covered-set checks. */
  mode: 'strict' | 'legacy'
}): Promise<VerifyOutcome> {
  const decoded = decodeSignatureHeader(input.signature)
  if (!decoded) return FAIL.signature_invalid
  // RFC 9421: the Signature label MUST match the Signature-Input label, otherwise
  // different middleware cannot agree on which signature was verified.
  if (decoded.label != null && decoded.label !== input.parsed.label) return FAIL.signature_invalid
  // A bare (unlabeled) Signature value is the legacy shim form, not a valid
  // labeled RFC 9421 signature — reject it outside explicit legacy mode.
  if (input.mode === 'strict' && decoded.label == null) return FAIL.signature_invalid
  const sig = decoded.bytes
  const msg = utf8(input.base)

  let ok: boolean
  if (input.key.curve === 'ed25519') {
    ok = ed25519.verify(sig, msg, input.key.bytes)
  } else if (sig.length === 65) {
    // secp256k1. A 65-byte signature carries the trailing recovery id (v) and is
    // the Ethereum `personal_sign` form: the wallet hashes the base as an EIP-191
    // personal message, so the verifier reconstructs that same hash and strips `v`
    // before the ECDSA check. A 64-byte signature is the raw r||s form over the
    // base and verifies directly. Raw ECDSA is always 64 bytes, so the length
    // unambiguously picks the scheme. ed25519 and raw secp256k1 need no transform
    // — the verifier stays chain-agnostic.
    ok = await secp256k1.verify(sig.slice(0, 64), ethPersonalSignHash(msg), input.key.bytes, {
      prehash: false,
    })
  } else {
    ok = await secp256k1.verify(sig, msg, input.key.bytes)
  }

  return ok ? OK : FAIL.signature_invalid
}

// Verify a signed HTTP request (ANP-02 authentication):
//   1. the covered set must bind the method, the target, and the body when present
//   2. content-digest must match the body, so the message is bound to what was sent
//   3. the signature base (from Signature-Input's covered components) must verify
//
// IMPORTANT: a `true` result proves integrity + freshness, NOT one-time use. To
// stop in-window replay, pass `expectedNonce` (bind to the issued challenge) and a
// `nonceStore` that atomically consumes it.
export async function verifyHttpMessageSignature(input: VerifyHttpSignatureInput): Promise<boolean> {
  return (await verifyHttpMessageSignatureDetailed(input)).ok
}

/**
 * Same check as {@link verifyHttpMessageSignature}, reporting WHICH check failed.
 *
 * Fail-closed exactly like the boolean form: it never throws (a rejected proof and an
 * internal exception are both an `ok: false`), and it consumes the nonce only after
 * the proof fully verifies, so a malformed proof still cannot burn a challenge.
 *
 * The reason is a diagnostic for the SERVER OPERATOR. Relaying it to the peer
 * unchanged turns this into an oracle that answers "was this DID authorized", "is
 * that nonce already spent", "did my clock skew" one guess at a time — the caller
 * decides what, if anything, to disclose.
 */
export async function verifyHttpMessageSignatureDetailed(
  input: VerifyHttpSignatureInput,
): Promise<VerifyOutcome> {
  const signatureInput = input.headers['signature-input']
  const signature = input.headers['signature']
  if (!signatureInput || !signature) return FAIL.request_malformed

  // The parser rejects an unrecognized/duplicate/extra param by THROWING, so it needs
  // its own frame: a malformed Signature-Input is a malformed request, not a failed
  // signature (the outer catch below keeps covering the key/curve work).
  let parsed: ReturnType<typeof parseSignatureInput>
  try {
    parsed = parseSignatureInput(signatureInput)
  } catch {
    return FAIL.request_malformed
  }

  try {
    const components = parsed.components
    const params = parsed.params
    const mode = input.mode ?? 'strict'
    const usesTargetUri = components.includes('@target-uri')
    const usesPath = components.includes('@path')

    // Minimum covered set (ANP-02 §3.1.1): the method, the target, and — when a body
    // is present — the body's digest. The last one is not optional: a signature that
    // does not cover `content-digest` leaves the body unbound, so a captured request
    // could be replayed with an attacker-chosen body attached. Covering MORE than
    // the minimum is always allowed (`@authority` is recommended, not required).
    const hasBody = input.body !== ''
    if (!components.includes('@method')) return FAIL.request_malformed
    if (hasBody && !components.includes('content-digest')) return FAIL.request_malformed

    if (mode === 'strict') {
      // The official covered set includes @target-uri; @path is NOT a substitute.
      if (!usesTargetUri) return FAIL.request_malformed
      // `@target-uri` is covered, so the verifier MUST have the full target to
      // reconstruct it. A missing target would silently fall back to the relative
      // path in buildSignatureBase, unbinding scheme/host/port. Require an absolute
      // http(s) URI consistent with the actual request's authority + path.
      const t = input.targetUri
      if (!t) return FAIL.request_malformed
      let target: URL
      try {
        target = new URL(t)
      } catch {
        return FAIL.request_malformed
      }
      if (target.protocol !== 'http:' && target.protocol !== 'https:') return FAIL.request_malformed
      if (target.host !== input.authority) return FAIL.request_malformed
      if (target.pathname !== input.path) return FAIL.request_malformed
      // Bind the query string too: the signature covers the full @target-uri, but
      // `input.path` only carries the pathname. Without this, `?tenant=a` could be
      // swapped for `?tenant=b` while the rest of the request still matches.
      if (target.search !== (input.search ?? '')) return FAIL.request_malformed
    } else {
      if (!usesTargetUri && !usesPath) return FAIL.request_malformed
    }

    // When the covered set names `content-digest`, the header MUST match the body
    // that was actually sent. When it does not, the body is unbound — which is only
    // acceptable for a request that has none.
    if (components.includes('content-digest')) {
      const expected = await buildContentDigestValue(utf8(input.body))
      const actual = input.headers['content-digest'] ?? ''
      if (actual !== expected) return FAIL.content_digest_mismatch
    } else if (hasBody) {
      return FAIL.request_malformed
    }
    if (!freshnessOk(params)) return FAIL.timestamp_invalid

    // A keyid is a DID URL, so anything non-string is malformed. (The parser
    // coerces numeric-looking values to numbers, which must not slip through as a
    // nonce-store key.)
    const keyid = typeof params.keyid === 'string' ? params.keyid : ''
    if (!keyid) return FAIL.request_malformed

    const signatureNonce = typeof params.nonce === 'string' ? params.nonce : undefined

    // Anti-replay: if the caller pinned an expected challenge, the proof's nonce
    // (in both Signature-Input and the body) must match it exactly. This is an
    // integrity check — it proves the signer used the issued nonce, not that the
    // nonce is still unused. One-time use is enforced below / externally.
    if (input.expectedNonce != null) {
      if (signatureNonce !== input.expectedNonce) return FAIL.nonce_mismatch
      // A body, when there is one, must ALSO carry the challenge — that is where the
      // login flow puts it, so the accepted nonce is inside the signed payload
      // rather than only in a header. A bodyless request has nowhere to put it.
      if (hasBody && bodyNonce(input.body) !== input.expectedNonce) return FAIL.nonce_mismatch
    }

    // Official clients cover @target-uri and append the @signature-params line to
    // the base; the legacy browser shim covered @path/@authority without it. The
    // `@signature-params` value is reconstructed VERBATIM from the Signature-Input
    // header (label stripped), so an unrecognized/duplicate/extra param — which the
    // parser already rejects — cannot silently differ from what was signed.
    const signatureParams = usesTargetUri ? parsed.signatureParamsValue : undefined

    const base = buildSignatureBase({
      method: input.method,
      path: input.path,
      authority: input.authority,
      targetUri: input.targetUri,
      headers: input.headers,
      components,
      signatureParams,
    })

    const outcome = await verifyProofSignature({
      signature,
      parsed,
      base,
      key: input.key,
      mode,
    })
    if (!outcome.ok) return outcome

    // One-time use: consume the nonce only after the proof fully verifies, so an
    // invalid signature never burns a challenge. A `false` return means the nonce
    // was already used — reject the replay. The key is the (keyid, nonce) pair.
    if (input.nonceStore && signatureNonce != null) {
      // Its own frame: a store that throws is OUR outage, and reporting it as a bad
      // signature would send the peer off to re-sign something that was fine. The
      // boolean form still collapses this to `false` (fail-closed).
      let spent: boolean
      try {
        spent = await input.nonceStore.consume(keyid, signatureNonce)
      } catch (err) {
        return { ok: false, reason: 'store_failed', cause: err }
      }
      return spent ? OK : FAIL.nonce_consumed
    }
    return OK
  } catch {
    return FAIL.signature_invalid
  }
}

export interface VerifyJsonAuthInput {
  /** The already-`JSON.parse`d envelope (`{ auth: {…}, payload }`). */
  envelope: unknown
  /** The value of the covered `@method` component, derived by the caller from the
   *  actual message — not read out of the proof. */
  method: string
  /** The value of the covered `@target-uri` component, likewise derived by the
   *  caller. Must be an absolute URI. */
  targetUri: string
  /** The value of the covered `@authority` component. **Give it if and only if the
   *  carrier has a second, independent source for it** (the way an HTTP request has
   *  both a request line and a Host header); supplying none while the proof covers
   *  `@authority` is rejected, and so is the reverse. */
  authority?: string
  /** The key the proof must verify under, resolved from the proof's `keyid`. */
  key: ResolvedKey
  /** Anti-replay, as in the HTTP path: the proof's `nonce` param must equal this. */
  expectedNonce?: string
  /** The one-time consume, as in the HTTP path. */
  nonceStore?: NonceStore
}

/**
 * Verify a JSON-carried proof (ANP-02 §4): `true` iff it is intact and fresh.
 *
 * Same caveat as {@link verifyHttpMessageSignature}: `true` proves integrity and
 * freshness, NOT one-time use. Pass `expectedNonce` + `nonceStore` to stop
 * in-window replay.
 */
export async function verifyAnpJsonAuthRequest(input: VerifyJsonAuthInput): Promise<boolean> {
  return (await verifyAnpJsonAuthRequestDetailed(input)).ok
}

/**
 * Same check as {@link verifyAnpJsonAuthRequest}, reporting WHICH check failed.
 *
 * §4.2.1 says the verification process is §3.2.1's, with the three fields taken
 * from `auth` and the digest taken over `payload`. That is literally what this does:
 * it runs the same pipeline as {@link verifyHttpMessageSignatureDetailed}, sharing
 * the freshness window, the covered-set minimum, the label rule and the curve
 * dispatch, and differs in exactly three places, each marked below — where the
 * fields are read from, which bytes the digest names, and whether `@authority` is
 * checkable. Anything else that differs between the two would be a bug.
 *
 * Fail-closed exactly like its HTTP twin: it never throws, and it consumes the
 * nonce only after the proof fully verifies.
 */
export async function verifyAnpJsonAuthRequestDetailed(
  input: VerifyJsonAuthInput,
): Promise<VerifyOutcome> {
  // DIFFERENCE 1: the three fields come out of `auth`, not out of headers. §4.1.1
  // names them `contentDigest` / `signatureInput` / `signature` — the same values
  // under camelCase names, so a missing one is as malformed here as there.
  const envelope = asRecord(input.envelope)
  const auth = envelope ? asRecord(envelope.auth) : null
  if (!auth) return FAIL.request_malformed
  const signatureInput = auth.signatureInput
  const signature = auth.signature
  const contentDigest = auth.contentDigest
  if (typeof signatureInput !== 'string' || !signatureInput) return FAIL.request_malformed
  if (typeof signature !== 'string' || !signature) return FAIL.request_malformed
  if (typeof contentDigest !== 'string' || !contentDigest) return FAIL.request_malformed

  let parsed: ReturnType<typeof parseSignatureInput>
  try {
    parsed = parseSignatureInput(signatureInput)
  } catch {
    return FAIL.request_malformed
  }

  try {
    const components = parsed.components
    const params = parsed.params

    // §3.1.2 step 3's minimum, which §4 does not relax: `@method`, `@target-uri`, and
    // the payload's digest. §4 redefines where these travel and which bytes the
    // digest names — never the covered set (§4 opening: it does not redefine the
    // signed field set).
    if (!components.includes('@method')) return FAIL.request_malformed
    if (!components.includes('@target-uri')) return FAIL.request_malformed
    if (!components.includes('content-digest')) return FAIL.request_malformed

    // A payload must be PRESENT — `payload: null` counts and digests as `null`. An
    // envelope that omits the field while covering `content-digest` is claiming to
    // bind a payload nobody sent.
    if (!envelope || !Object.prototype.hasOwnProperty.call(envelope, 'payload')) {
      return FAIL.request_malformed
    }

    // DIFFERENCE 2: `@authority`, where an HTTP request has two independent sources
    // (the request line and the Host header) and a JSON envelope has at most the one
    // the caller brings. Covered-without-a-source would be a component we could only
    // pretend to check, so the two must agree in both directions.
    if (components.includes('@authority') !== (input.authority != null)) {
      return FAIL.request_malformed
    }

    // DIFFERENCE 3: the digest binds `payload` — NOT the wrapper that carries `auth`
    // (§4.1.1: "`contentDigest` 绑定的是 payload 部分，而不是包含 `auth` 在内的整个
    // 封装对象"). `auth` is outer metadata and must not be hashed, or re-casing a
    // field name would invalidate an otherwise untouched message.
    //
    // Canonicalization is fixed to RFC 8785 JCS, the same rule the signer
    // (`signAnpJsonAuthRequest`) uses, so both sides hash identical bytes. A payload
    // value JCS cannot express is a malformed request, not a bad signature — hence
    // its own frame rather than falling into the outer `signature_invalid`.
    let expected: string
    try {
      expected = await buildContentDigestValue(utf8(jcsCanonicalize(envelope.payload)))
    } catch {
      return FAIL.request_malformed
    }
    if (contentDigest !== expected) return FAIL.content_digest_mismatch

    // `@target-uri` must name an absolute target: a relative value would leave
    // scheme/host/port unbound, exactly as in the HTTP path. Beyond that, no HTTP
    // shape is imposed — §4.1.2 item 3 hands the equivalent components to the
    // carrying protocol, so a `wss:` target is as legitimate as an `https:` one.
    // (The HTTP path additionally compares path + query against the real request;
    // here the caller's `targetUri` IS that source, so there is nothing else to
    // compare it to — a proof signed over a different target simply fails below.)
    let target: URL
    try {
      target = new URL(input.targetUri)
    } catch {
      return FAIL.request_malformed
    }
    if (input.authority != null && target.host !== input.authority) return FAIL.request_malformed

    if (!freshnessOk(params)) return FAIL.timestamp_invalid

    const keyid = typeof params.keyid === 'string' ? params.keyid : ''
    if (!keyid) return FAIL.request_malformed

    const signatureNonce = typeof params.nonce === 'string' ? params.nonce : undefined

    // Anti-replay, as in the HTTP path — with one deliberate omission. There,
    // `expectedNonce` also has to appear in the body, because the §3 login flow puts
    // the issued challenge in the signed payload. §4's payload is business data: the
    // recommended format has no `nonce` in it (§4.1.1's example is
    // `{"orderId":…,"action":…}`), so demanding one would reject conforming traffic.
    // Binding the challenge in the signature params is what makes it unforgeable,
    // and that is checked here.
    if (input.expectedNonce != null && signatureNonce !== input.expectedNonce) {
      return FAIL.nonce_mismatch
    }

    const base = buildSignatureBase({
      method: input.method,
      // `@path` is outside this profile's covered set (§4.1.2 item 3 leaves the
      // equivalent to the carrying protocol, which may have no path at all).
      path: '',
      authority: input.authority ?? '',
      targetUri: input.targetUri,
      // The only header-shaped input is the digest, which is what the
      // `content-digest` component resolves to.
      headers: { 'content-digest': contentDigest },
      components,
      // §4 keeps §3's official form (params appended after the component lines), and
      // `@target-uri` is required above, so the params are always part of the base.
      signatureParams: parsed.signatureParamsValue,
    })

    // No legacy mode: the old browser shim predates §4 and never carried a JSON
    // envelope, so there is no unlabeled-value case to accommodate.
    const outcome = await verifyProofSignature({
      signature,
      parsed,
      base,
      key: input.key,
      mode: 'strict',
    })
    if (!outcome.ok) return outcome

    if (input.nonceStore && signatureNonce != null) {
      let spent: boolean
      try {
        spent = await input.nonceStore.consume(keyid, signatureNonce)
      } catch (err) {
        return { ok: false, reason: 'store_failed', cause: err }
      }
      return spent ? OK : FAIL.nonce_consumed
    }
    return OK
  } catch {
    return FAIL.signature_invalid
  }
}

/** Narrow an unknown to a plain object, or `null`. `JSON.parse` yields only plain
 *  values, but a caller may hand-build the envelope. */
function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  return value as Record<string, unknown>
}

// Shared frozen outcomes: the detailed verifier always returns one of these, so a
// caller can compare by identity instead of allocating a fresh object per call.
const OK: VerifyOutcome = { ok: true }
const FAIL: Record<VerifyFailure, VerifyOutcome> = {
  request_malformed: { ok: false, reason: 'request_malformed' },
  content_digest_mismatch: { ok: false, reason: 'content_digest_mismatch' },
  timestamp_invalid: { ok: false, reason: 'timestamp_invalid' },
  nonce_mismatch: { ok: false, reason: 'nonce_mismatch' },
  nonce_consumed: { ok: false, reason: 'nonce_consumed' },
  signature_invalid: { ok: false, reason: 'signature_invalid' },
  store_failed: { ok: false, reason: 'store_failed' },
}
