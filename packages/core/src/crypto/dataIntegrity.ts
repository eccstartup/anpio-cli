// W3C Data Integrity proof for a DID document — the mandatory `proof` on an
// `e1_` (Ed25519) did:wba document, using the `eddsa-jcs-2022` cryptosuite.
//
//   toBeSigned = sha256(jcs(proofOptions)) || sha256(jcs(document-without-proof))
//   proofValue = multibase-base58btc(Ed25519(toBeSigned))   → "z…"
//
// ANP-03 §2.5.5 requires `proofValue` to be multibase base58-btc (a `z` prefix),
// matching W3C Data Integrity. The sibling `agent-on/anp-extension` used to emit
// base64url here; ADR-0002 §2.5 replaced that deviation, so agent-on MUST be
// updated in lockstep (`0.3.0` — see todos/TODO5 Part G1.1).
//
// The signing key is provided as a signer function so this works for both a local
// private key (`createAnpIdentity`) and a wallet that only exposes `signMessage`
// (`buildWalletIdentity`). Only Ed25519 is supported: the k1_ (secp256k1) profile
// uses a different, optional cryptosuite (`didwba-jcs-ecdsa-secp256k1-2025`) that
// the SDK does not implement — so a `k1_` document's proof is neither produced nor
// required here.

import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { jcsCanonicalize, didFingerprint, isFingerprint } from './fingerprint'
import { base58btcDecode, base58btcEncode } from './base58'
import { decodeMultibaseKey } from './multicodec'
import { utf8 } from './encoding'

/** Signs raw bytes with the identity key (Ed25519 for the e1_ profile). Async so
 *  a wallet's `signMessage` can be passed directly. */
export type MessageSigner = (message: Uint8Array) => Uint8Array | Promise<Uint8Array>

export interface DidDocumentProofOptions {
  /** DID authority bound into the proof (some servers whitelist it). */
  domain?: string
  /** Server-issued challenge/nonce, when the server requires one. */
  challenge?: string
  /** Override `created` (ISO-8601). Defaults to now — so a built document is
   *  NOT byte-stable across calls. */
  created?: string
}

/** ISO-8601 UTC without milliseconds (matches the official proof `created`). */
export function isoUtcNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/** Encode a proof value as multibase base58-btc: a `z` marker + the base58btc
 *  digest. This is the ONLY encoding ANP-03 accepts for `proofValue`. */
export function encodeProofValue(bytes: Uint8Array): string {
  return 'z' + base58btcEncode(bytes)
}

/** Decode a multibase base58-btc `proofValue`, or `null` when it is not one (a
 *  missing `z` marker, an unknown multibase, a non-base58 character, or an empty
 *  payload). Returns `null` rather than throwing so the caller reports one uniform
 *  "invalid document proof" failure. */
export function decodeProofValue(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || !value.startsWith('z') || value.length === 1) return null
  try {
    return base58btcDecode(value.slice(1))
  } catch {
    return null
  }
}

/** Build the unsigned proof object for a DID document. Exported so a caller can
 *  compute the signing payload without signing (e.g. to inspect / test). */
export function didDocumentProofOptions(
  keyid: string,
  opts: DidDocumentProofOptions = {},
): Record<string, unknown> {
  const proofOptions: Record<string, unknown> = {
    type: 'DataIntegrityProof',
    created: opts.created ?? isoUtcNow(),
    verificationMethod: keyid,
    proofPurpose: 'assertionMethod',
    cryptosuite: 'eddsa-jcs-2022',
  }
  if (opts.domain) proofOptions.domain = opts.domain
  if (opts.challenge) proofOptions.challenge = opts.challenge
  return proofOptions
}

/** The 64-byte payload signed by eddsa-jcs-2022: sha256(jcs(options)) || sha256(jcs(doc)). */
export function didDocumentProofPayload(
  proofOptions: Record<string, unknown>,
  doc: Record<string, unknown>,
): Uint8Array {
  const withoutProof: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(doc)) if (k !== 'proof') withoutProof[k] = v
  const optionsHash = sha256(utf8(jcsCanonicalize(proofOptions)))
  const docHash = sha256(utf8(jcsCanonicalize(withoutProof)))
  const toBeSigned = new Uint8Array(64)
  toBeSigned.set(optionsHash, 0)
  toBeSigned.set(docHash, 32)
  return toBeSigned
}

/** Produce a signed `eddsa-jcs-2022` proof for `doc`. The returned object is the
 *  proof to attach as `doc.proof` (the document itself is not mutated). */
export async function signDidDocumentProof(
  doc: Record<string, unknown>,
  keyid: string,
  sign: MessageSigner,
  opts: DidDocumentProofOptions = {},
): Promise<Record<string, unknown>> {
  const proofOptions = didDocumentProofOptions(keyid, opts)
  const signature = await sign(didDocumentProofPayload(proofOptions, doc))
  return { ...proofOptions, proofValue: encodeProofValue(signature) }
}

/** Synchronous variant for a local Ed25519 private key (keeps `createAnpIdentity`
 *  sync). Identical bytes to `signDidDocumentProof` with an Ed25519 signer. */
export function signDidDocumentProofSync(
  doc: Record<string, unknown>,
  keyid: string,
  privateKey: Uint8Array,
  opts: DidDocumentProofOptions = {},
): Record<string, unknown> {
  const proofOptions = didDocumentProofOptions(keyid, opts)
  const signature = ed25519.sign(didDocumentProofPayload(proofOptions, doc), privateKey)
  return { ...proofOptions, proofValue: encodeProofValue(signature) }
}

export interface VerifyDidDocumentProofOptions {
  /**
   * The DID the document claims to describe. When it is a path-type `did:wba`
   * whose last segment is a key fingerprint, the proof MUST be made by the key
   * that fingerprint commits to — a self-signed document proves nothing on its
   * own, so without this binding an attacker can serve their own key with a
   * perfectly valid proof under the victim's DID.
   */
  did?: string
}

/** Verify the top-level `proof` of a DID document. Returns `false` — never throws
 *  — on any malformation, so the caller reports one uniform resolution failure.
 *
 *  Checked (ANP-03 §2.5.5): `type` is `DataIntegrityProof`, `cryptosuite` is
 *  `eddsa-jcs-2022`, `proofPurpose` is `assertionMethod`, `verificationMethod`
 *  names a method this document both contains AND controls (see
 *  `documentProofKey`), that method's key is Ed25519, the signature verifies over
 *  the reconstructed payload, and — when `did` carries a fingerprint — the proof
 *  key reproduces it. */
export function verifyDidDocumentProof(
  doc: Record<string, unknown>,
  opts: VerifyDidDocumentProofOptions = {},
): boolean {
  const parts = documentProofParts(doc)
  if (!parts) return false

  const publicKey = documentProofKey(doc, parts.keyid)
  if (!publicKey) return false

  // Bind the proof to the identifier, not just to the document: the DID's last
  // path segment commits to its key, so a document signed by a different key is
  // rejected even though its self-signature is internally consistent.
  if (opts.did != null) {
    const segments = opts.did.split(':')
    const fingerprint = segments[segments.length - 1]
    if (isFingerprint(fingerprint)) {
      // The key must be published under THIS DID, compared as RESOLVED DID URLs — so
      // this document's own `#key-1` spelling counts as this DID, and `did:other#key-1`
      // does not. Comparing the raw spelling (`keyid.split('#')[0]`) would have made
      // the relative form look like a foreign DID.
      const proofKeyUrl = canonicalDidUrl(doc.id, parts.keyid)
      if (proofKeyUrl === undefined || didPartOf(proofKeyUrl) !== opts.did) return false
      if (didFingerprint('ed25519', publicKey) !== fingerprint) return false
    }
  }

  return ed25519.verify(parts.signature, didDocumentProofPayload(parts.proofOptions, doc), publicKey)
}

/**
 * Verify a document's top-level `proof` against an EXPLICITLY supplied Ed25519 key
 * instead of one resolved from the document.
 *
 * This is what the recovery branch of a deactivated `did:wba` document needs
 * (ANP-03 §2.5.5 rule 2): a recovery proof is validated against the key material
 * and `assertionMethod` authorization of the document that was trusted BEFORE the
 * deactivation, not against the transition document's own binding. No fingerprint
 * binding is applied — a recovery key need not match the DID path's `e1_` segment.
 *
 * The proof's shape (type / cryptosuite / proofPurpose / `proofValue` encoding) is
 * still checked, so a malformed proof cannot pass by supplying a key.
 */
export function verifyDidDocumentProofWithKey(
  doc: Record<string, unknown>,
  publicKey: Uint8Array,
): boolean {
  const parts = documentProofParts(doc)
  if (!parts) return false
  return ed25519.verify(parts.signature, didDocumentProofPayload(parts.proofOptions, doc), publicKey)
}

/** The `verificationMethod` keyid of a structurally valid top-level proof, or
 *  `undefined` when the document has no proof or its proof is malformed. Lets a
 *  caller look the proof key up somewhere other than the document itself — see
 *  `verifyDidDocumentProofWithKey`. */
export function documentProofKeyId(doc: Record<string, unknown>): string | undefined {
  return documentProofParts(doc)?.keyid
}

/** The parsed, structurally valid parts of a document's top-level proof, or `null`.
 *  Every proof reader goes through this, so the §2.5.5 shape is enforced once. */
function documentProofParts(
  doc: Record<string, unknown>,
): { proofOptions: Record<string, unknown>; keyid: string; signature: Uint8Array } | null {
  const proof = doc.proof
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) return null
  const { proofValue, ...proofOptions } = proof as Record<string, unknown>

  if (proofOptions.type !== 'DataIntegrityProof') return null
  if (proofOptions.cryptosuite !== 'eddsa-jcs-2022') return null
  if (proofOptions.proofPurpose !== 'assertionMethod') return null
  const keyid = proofOptions.verificationMethod
  if (typeof keyid !== 'string' || keyid === '') return null

  const signature = decodeProofValue(proofValue)
  if (!signature) return null
  return { proofOptions, keyid, signature }
}

/** The DID part of a DID URL (`did:…#fragment` → `did:…`), or the whole string when
 *  it carries no fragment. */
function didPartOf(didUrl: string): string {
  const hash = didUrl.indexOf('#')
  return hash === -1 ? didUrl : didUrl.slice(0, hash)
}

/**
 * Resolve a DID URL written inside the document `docId` describes to its ABSOLUTE
 * form. This is DID Core's rule: a relative `#fragment` names a method of the
 * document's OWN DID, so it resolves to `${docId}#fragment`; anything else is
 * already absolute and is returned unchanged. Returns `undefined` when a relative
 * URL cannot be resolved because the document states no string `id` — so every
 * comparison against it fails closed.
 *
 * This is the ONLY sound way to compare two DID URLs written in different forms, and
 * it is deliberately the single rule for key resolution and relationship
 * authorization. Comparing fragments alone is not sound: it makes
 * `did:wba:evil.example:user:mallory#recovery-1` and a local `#recovery-1` the same
 * identifier, so a proof can name an outsider's DID URL while resolving — and being
 * recorded as — this document's own method (ANP-2026-09-17-R01).
 */
export function canonicalDidUrl(docId: unknown, didUrl: string): string | undefined {
  if (!didUrl.startsWith('#')) return didUrl
  return typeof docId === 'string' ? `${docId}${didUrl}` : undefined
}

/** Resolve the Ed25519 key a proof's `verificationMethod` names, from the document
 *  itself. Accepts the absolute form (`did:…#key-1`) and the DID-spec relative
 *  form (`#key-1`), in any combination with how the document spells the method.
 *
 *  The method must be one the DOCUMENT controls, or its key is not this document's
 *  to lend: both the named keyid and the candidate method id are resolved against
 *  `doc.id` before they are compared, an absolute id must live under that same DID,
 *  and the method's `controller` must BE `doc.id` — a `controller` that is absent, an
 *  array, a non-string or another DID establishes no relationship and yields no key.
 *  This is a `verificationMethod`'s DID Core binding, and it carries the check for
 *  callers that reach here without `verifyDidDocument`'s `doc.id === did` gate — in
 *  particular the exported `verifyDidDocumentProof`, and the continuity chain's
 *  recovery-key lookup, where a laxer reading would let a structurally invalid
 *  method satisfy a proof. */
export function documentProofKey(doc: Record<string, unknown>, keyid: string): Uint8Array | null {
  const docId = doc.id
  const wanted = canonicalDidUrl(docId, keyid)
  if (wanted === undefined) return null
  const methods = Array.isArray(doc.verificationMethod) ? doc.verificationMethod : []
  for (const raw of methods) {
    if (raw === null || typeof raw !== 'object') continue
    const vm = raw as { id?: unknown; controller?: unknown; publicKeyMultibase?: unknown }
    const id = typeof vm.id === 'string' ? vm.id : ''
    // Resolved-URL equality, not spelling equality: `#key-1` and `did:X#key-1` are the
    // same identifier for a document whose id is `did:X`, and `did:other#key-1` is not.
    if (canonicalDidUrl(docId, id) !== wanted) continue
    // An ABSOLUTE id names the DID it belongs to, so it must name THIS one: a document
    // cannot lend a key that lives in another DID's URL space.
    if (id.startsWith('did:') && didPartOf(id) !== docId) return null
    if (vm.controller !== docId) return null
    if (typeof vm.publicKeyMultibase !== 'string') return null
    try {
      const key = decodeMultibaseKey(vm.publicKeyMultibase)
      return key.curve === 'ed25519' ? key.bytes : null
    } catch {
      return null
    }
  }
  return null
}
