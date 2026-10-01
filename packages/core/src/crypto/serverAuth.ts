// High-level server-side ANP login verification.
//
// The lower-level pieces (`parseSignatureInput` / `resolveVerificationKey` /
// `verifyHttpMessageSignature`) are individually correct but easy to MIS-wire: the
// 2026-09-11 audit found three worked examples taking the public key from the
// request's inline DID document while writing a *separate, unbound* `did` field
// into the token — so an attacker could sign with their own key and claim a victim
// DID. This function performs the whole binding in one place:
//
//   keyid (from Signature-Input)  →  DID  →  body.did  →  DID document  →  key
//
// and returns the identity only when every link agrees. It also REQUIRES the
// server's challenge nonce + one-time store, so a success can never be a replayed
// proof (2026-09-11 review R01).

import { parseSignatureInput } from './signatureBase'
import {
  isSuperseded,
  resolveDidDocument,
  resolveVerificationKey,
  type ResolveDidOptions,
  type ResolvedKey,
} from './resolveDid'
import {
  verifyHttpMessageSignatureDetailed,
  type NonceStore,
  type VerifyFailure,
} from './verify'
import { isFingerprint } from './fingerprint'
import { ethAddressFromPublicKey } from '../wallet/eip1193'
import { ConnectxError, isConnectxError } from '../errors'
import type { AnpAuthError } from '../actions'

export interface VerifyAnpLoginInput {
  method: string
  authority: string
  /** Pathname of the actual request, e.g. `/api/login/anp/verify`. */
  path: string
  /** The actual request's query string INCLUDING the leading `?`, or `''`. */
  search?: string
  /** Absolute URL the request was addressed to (must agree with authority/path/search). */
  targetUri: string
  /** Lowercase header map of the actual request. */
  headers: Record<string, string>
  /** The RAW request body text — re-serialising it would break the content-digest. */
  body: string
  /** Server-issued challenge nonce. Binds the proof's nonce (header AND body). */
  expectedNonce: string
  /** One-time nonce store for anti-replay; consumed only after the proof verifies. */
  nonceStore: NonceStore
  /** Component compatibility mode; defaults to `'strict'` inside the verifier. */
  mode?: 'strict' | 'legacy'
  /**
   * Network-resolution constraints (notably `allowedHosts`) used when the request
   * does NOT inline a trusted DID document. See the inline trust model below.
   */
  resolveOptions?: ResolveDidOptions
  /**
   * Refuse to trust an INLINED DID document: ask the DID's own server for the document
   * and verify against that, even when the request carries a fingerprint-bound one.
   *
   * Off by default, because the inline path is the ANP-02 design (the document travels
   * with the proof, and a path-type `did:wba` DID commits to its key by fingerprint, so
   * no network is needed to verify it). On, the site gets what only the DID's own host
   * can answer — that this DID is PUBLISHED, and which key is authorized *there* — which
   * is a strictly stronger statement than "the request is internally consistent".
   *
   * With this on, `resolveOptions.allowedHosts` stops meaning "hosts I may fetch" and
   * becomes the actual trust policy: the list of DID servers this site accepts DIDs
   * from. A lookup failure is a REJECTED login, not a pass: a host outside the list, a
   * DID nobody publishes, or a network fault are all refusals (the last one as
   * `'unverifiable'`, which is honest about the fault being ours).
   *
   * ⚠️ The lookup happens BEFORE the proof is checked (the key is needed to check it),
   * so it is reachable by an unauthenticated caller. Bound it with `allowedHosts` — an
   * attacker must not be able to make this server fetch arbitrary hosts.
   */
  requireResolvedDocument?: boolean
}

export interface AnpLoginIdentity {
  /** The DID bound to the signature — from the `keyid`, confirmed by the document. */
  did: string
  keyid: string
  /**
   * The document the key was verified against, as plain JSON — NOT narrowed to the
   * SDK's internal document shape, because what it PROVES differs by mode. With
   * `requireResolvedDocument` it is the document the DID's own server published, so
   * it may be used as an authority (e.g. to locate a service endpoint); otherwise it
   * is the request's inline copy, which is a CLAIM the fingerprint binding made
   * acceptable to verify against — not a statement from the DID's host. Both are
   * integrity-checked (id + top-level `proof`); neither is a licence to trust the
   * document's contents on their own.
   */
  document: Record<string, unknown>
}

/**
 * Why a login was rejected, in the terms a server can act on.
 *
 * The nine {@link AnpAuthError} values are the ANP-02 §3.2.4.1 vocabulary, so a
 * caller can put one straight into `WWW-Authenticate: error="…"`. This verifier
 * emits seven of them (`invalid_access_token` and `forbidden_did` belong to later
 * stages — token checking and authorization); the type stays the whole vocabulary
 * so a handler assembling one response does not have to switch names.
 *
 * `'unverifiable'` is NOT part of that vocabulary and MUST NOT be written into a
 * challenge: it means the server could not reach a decision (its resolver timed
 * out, the DID's host is not in `allowedHosts`, its nonce store threw). Answering
 * "your proof is bad" would send the peer off to re-sign something that may be
 * perfectly good, while the actual fault — a config or dependency of ours — stays
 * hidden. Report it as a 5xx / retryable failure instead.
 *
 * `'did_deactivated'` is neither an ANP-02 value nor a 401 at all: ANP-03 §3.2
 * defines a separate 409 `did_superseded` response for it. The DID's document is
 * deactivated (or names a successor), so ANP-03 §3.1.2 says the server MUST NOT
 * authenticate it — even if its proof would verify.
 */
export type AnpLoginFailure = AnpAuthError | 'unverifiable' | 'did_deactivated'

/**
 * The outcome of {@link verifyAnpLoginRequest}. A discriminated union rather than
 * `AnpLoginIdentity | null` so the failure branch cannot be used without reading the
 * reason — and so a caller cannot accidentally treat "we could not check" as either
 * success or a bad proof.
 */
export type AnpLoginResult =
  | { ok: true; identity: AnpLoginIdentity }
  | {
      ok: false
      error: AnpLoginFailure
      /**
       * The underlying failure, for the server's OWN log — a `ConnectxError` for a
       * resolve/binding failure. NEVER serialize this into a response: it names
       * hosts, addresses and resolution internals the peer must not learn.
       */
      cause?: unknown
      /**
       * Set only for `'did_deactivated'`: the `successorDid` the old document named.
       * It is the DID that document points AT, which may be a direct successor
       * rather than the active DID when the chain has more hops — ANP-03 §3.2 says a
       * 409 body's `currentDid` is only an unverified hint, so a caller may echo it
       * but must leave the peer to walk the chain itself. Absent when the DID was
       * deactivated with no successor.
       */
      successorDid?: string
    }

// A failed key resolution, expressed in the wire vocabulary. The split matters:
//   - the DID itself is unusable                → invalid_did
//   - the DID is fine, its key is not           → invalid_verification_method
//   - WE could not look (policy, network, size) → unverifiable
// `did_resolve_blocked` lands in the third group on purpose: the usual cause is a
// host missing from `allowedHosts`, which is our configuration, not a bad proof.
function resolveFailureToAnpError(err: unknown): AnpLoginFailure {
  if (!isConnectxError(err)) return 'unverifiable'
  switch (err.code) {
    case 'invalid_did':
      return 'invalid_did'
    case 'did_resolve_not_found':
    case 'did_resolve_unauthorized':
    case 'did_resolve_invalid_document':
    case 'key_invalid':
    case 'key_unsupported':
      return 'invalid_verification_method'
    case 'did_resolve_failed':
      // The fetch carries the HTTP status for exactly this reading: a 404 or a 410 is
      // the DID server's OWN answer that it publishes no such DID, which is a fact
      // about the identity and belongs in the second group. Every other failed fetch —
      // a 5xx, a refused redirect, a connection error — is the third group: we could
      // not look, so the caller may retry. Without this an unpublished DID would be
      // reported to a caller as "try again later", forever.
      return err.status === 404 || err.status === 410 ? 'invalid_verification_method' : 'unverifiable'
    default:
      return 'unverifiable'
  }
}

// The verifier's finer-grained reasons, collapsed onto the wire vocabulary. The two
// that the verifier deliberately keeps apart — a proof that failed versus a check
// that could not run — stay apart here.
const VERIFY_FAILURE_TO_ANP_ERROR: Record<VerifyFailure, AnpLoginFailure> = {
  request_malformed: 'invalid_request',
  content_digest_mismatch: 'invalid_content_digest',
  timestamp_invalid: 'invalid_timestamp',
  nonce_mismatch: 'invalid_nonce',
  nonce_consumed: 'invalid_nonce',
  signature_invalid: 'invalid_signature',
  store_failed: 'unverifiable',
}

// An inline DID document is trusted ONLY for an identifier that COMMITS to a key:
//   - a path-type `did:wba:<host>:<path…>:<fingerprint>` — the last segment is the
//     RFC 7638 thumbprint of the public key, checked by `assertFingerprintBinding`
//     in resolveDid.ts;
//   - an `eip155` CAIP-10 account id — the address IS derived from the key, checked
//     by `assertAccountBinding` below. The identity contract calls an account id an
//     OPAQUE identifier whose document is "always inlined in the signed proof, never
//     fetched by DID method" (identity.ts), and this is the check that makes that
//     inline copy verifiable rather than attacker input.
// For any other shape — a bare `did:wba:<host>`, a `did:web`, or a non-EVM CAIP-10
// account id — an inline document is unauthenticated attacker input, so it is
// ignored and the key must be resolved over the network (which requires an
// `allowedHosts` allowlist).
const EIP155_ACCOUNT_ID = /^eip155:[0-9]+:0x[0-9a-f]{40}$/

function hasTrustedInlineDocument(did: string, doc: unknown): boolean {
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return false
  if (EIP155_ACCOUNT_ID.test(did)) return true
  if (!did.startsWith('did:wba:')) return false
  return isFingerprint(did.slice(did.lastIndexOf(':') + 1))
}

/** The account-id half of what `assertFingerprintBinding` does for path-type DIDs:
 *  the identifier commits to a key, so a document naming any OTHER key is rejected
 *  instead of trusted. Without it nothing about `eip155:1:0x…` names a key, and an
 *  attacker could sign with their own key while inlining a document for a victim's
 *  account id. Only the strict lowercase form is accepted, because that is the form
 *  the identity contract produces for an EVM address — a mixed-case spelling is a
 *  different string that no client emits, and refusing it keeps one account from
 *  being addressable under two DIDs. */
function assertAccountBinding(did: string, key: ResolvedKey): void {
  if (!EIP155_ACCOUNT_ID.test(did)) return
  const committed = did.slice(did.lastIndexOf(':') + 1)
  if (key.curve !== 'secp256k1') {
    throw new ConnectxError(
      'did_resolve_invalid_document',
      `Account id "${did}" commits to a secp256k1 key, but the document names a ${key.curve} key`,
    )
  }
  const actual = ethAddressFromPublicKey(key.bytes)
  if (actual !== committed) {
    throw new ConnectxError(
      'did_resolve_invalid_document',
      `Account id "${did}" commits to address "${committed}" but the document's key derives "${actual}"`,
    )
  }
}

/**
 * Verify a signed ANP login/register request and return the bound identity, or the
 * reason it was rejected. Never throws on a REJECTED login; a missing replay guard
 * throws `invalid_argument` (a caller bug, not a login failure).
 *
 * The returned `identity.did` is the ONLY DID a caller may trust for authorization: it
 * is derived from the signature's `keyid`, required to equal the body's `did`, and
 * required to be consistent with the verification key (document id / controller /
 * method id / path fingerprint).
 *
 * The `error` on the failure branch is what the peer may be told (see
 * {@link AnpLoginFailure}); `cause` is for your log only.
 *
 * Fail-closed on replay: `expectedNonce` and `nonceStore` are required, so a
 * success always means the proof carried the server's challenge AND spent it. A
 * login verifier that skipped the challenge would accept an in-window replay of a
 * captured proof. Callers wanting only a stateless integrity/freshness check must
 * use the low-level `verifyHttpMessageSignature` instead.
 */
export async function verifyAnpLoginRequest(input: VerifyAnpLoginInput): Promise<AnpLoginResult> {
  // Deliberately OUTSIDE the try: this is a misconfiguration the caller must fix, so
  // it must not be swallowed into a rejection that looks like a bad login.
  if (input.expectedNonce == null || input.nonceStore == null) {
    throw new ConnectxError(
      'invalid_argument',
      'verifyAnpLoginRequest requires expectedNonce (server challenge) and nonceStore (one-time consume); use the low-level verifyHttpMessageSignature for a stateless check',
    )
  }

  try {
    const signatureInput = input.headers['signature-input']
    if (!signatureInput) return rejected('invalid_request')
    // The parser throws on an unrecognized/duplicate/extra param, so it needs its own
    // frame: a malformed Signature-Input is a malformed request, not an unverifiable one.
    let keyid: unknown
    try {
      keyid = parseSignatureInput(signatureInput).params.keyid
    } catch {
      return rejected('invalid_request')
    }
    if (typeof keyid !== 'string' || keyid === '') return rejected('invalid_request')

    const hashIdx = keyid.indexOf('#')
    const did = hashIdx === -1 ? keyid : keyid.slice(0, hashIdx)
    if (did === '') return rejected('invalid_request')

    let body: unknown
    try {
      body = JSON.parse(input.body)
    } catch {
      return rejected('invalid_request')
    }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      return rejected('invalid_request')
    }
    // The claimed identity in the body must be the DID the signature is bound to. A
    // mismatch is not a malformed request — the proof is bound to a DID the body
    // does not claim, i.e. the claimed identity is the thing that is wrong.
    if ((body as { did?: unknown }).did !== did) return rejected('invalid_did')

    const inlineDoc = (body as { didDocument?: unknown }).didDocument
    let key
    let document: Record<string, unknown>
    try {
      if (!input.requireResolvedDocument && hasTrustedInlineDocument(did, inlineDoc)) {
        document = inlineDoc as Record<string, unknown>
        key = await resolveVerificationKey(keyid, document)
      } else {
        // Ask the DID's own host (the caller's `allowedHosts` says which hosts are
        // acceptable DID servers). This is the whole point of the option: the answer
        // comes from the identity's own server, not from the request. The key is then
        // taken from THAT document, so a key the DID server does not authorize is a
        // rejection even though the request's own copy may name it.
        const resolved = await resolveDidDocument(did, input.resolveOptions)
        document = resolved.document
        key = await resolveVerificationKey(keyid, document, input.resolveOptions)
      }
      // ANP-03 §3.1.2: a document that sets `deactivated = true` MUST NOT be used
      // for new authentication, and one naming a `successorDid` gets §3.2's 409.
      // `isSuperseded` reads both markers — the same pair the continuity chain in
      // did/chain.ts reads. Resolution has to come first (it yields the document),
      // and the document's own proof is part of it; from here on, though, nothing the
      // document asserts is acted on until this passes. The DID cannot authenticate at
      // all, so a genuine request signature over it would prove nothing about whether
      // it still may.
      if (isSuperseded(document)) return deactivatedRejection(document)
      // Runs on the key the document NAMED, before that key is used to check the
      // proof: for an `eip155` account id the document is only as trustworthy as its
      // agreement with the address in the identifier.
      assertAccountBinding(did, key)
    } catch (err) {
      return rejected(resolveFailureToAnpError(err), err)
    }

    const outcome = await verifyHttpMessageSignatureDetailed({
      method: input.method,
      path: input.path,
      authority: input.authority,
      targetUri: input.targetUri,
      search: input.search,
      headers: input.headers,
      body: input.body,
      key,
      expectedNonce: input.expectedNonce,
      nonceStore: input.nonceStore,
      mode: input.mode,
    })
    if (!outcome.ok) return rejected(VERIFY_FAILURE_TO_ANP_ERROR[outcome.reason], outcome.cause)

    return { ok: true, identity: { did, keyid, document } }
  } catch (err) {
    // Still fail closed: an unexpected throw is a rejection, not a pass. Without a
    // name for it, the honest answer is "we could not verify", not "your proof is bad".
    return rejected('unverifiable', err)
  }
}

function rejected(error: AnpLoginFailure, cause?: unknown): AnpLoginResult {
  return cause === undefined ? { ok: false, error } : { ok: false, error, cause }
}

// The DID's document is historical (deactivated, or pointing at a successor), so the
// login is refused. The successor is echoed as a hint only when the document names a
// well-formed DID string; ANP-03 §3.2 treats whatever it puts in the 409 body as
// unverified input the client must re-derive, so there is nothing to validate beyond
// the shape the resolver already accepted.
function deactivatedRejection(document: Record<string, unknown>): AnpLoginResult {
  const successorDid = document.successorDid
  return typeof successorDid === 'string' && successorDid.startsWith('did:')
    ? { ok: false, error: 'did_deactivated', successorDid }
    : { ok: false, error: 'did_deactivated' }
}
