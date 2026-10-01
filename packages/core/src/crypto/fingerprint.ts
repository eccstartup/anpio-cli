// ANP (did:wba) fingerprint + JSON canonicalization primitives.
//
// A path-type `did:wba` DID binds a key by putting its fingerprint in the last
// path segment: `did:wba:<host>:<path…>:<fingerprint>`. The fingerprint is an
// RFC 7638 JWK thumbprint — SHA-256 over the canonical JWK, base64url without
// padding — prefixed `e1_` (Ed25519) or `k1_` (secp256k1). The digest is always
// 32 bytes → 43 base64url chars, so the segment length is fixed.
//
// Verified against two ANP spec revisions and byte-for-byte against the sibling
// `agent-on/anp-extension` (`computeMultikeyFingerprint`). Kept sync (noble's
// sha256 is sync) so `identityDid` can stay a pure, synchronous function.

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64UrlNoPad, utf8 } from './encoding'
import { ConnectxError } from '../errors'

const ED25519_PUB_BYTES = 32

/** RFC 8785 JSON Canonicalization Scheme. Object keys are sorted by UTF-16 code
 *  unit; strings/numbers reuse `JSON.stringify`, which already emits RFC 8785
 *  escaping. DID documents and proof options contain no non-finite numbers, so
 *  number edge cases are out of scope here (mirrors the sibling implementation). */
export function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new ConnectxError('invalid_argument', 'JCS: non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + value.map(jcsCanonicalize).join(',') + ']'
  if (typeof value === 'object') {
    const entries = Object.keys(value as Record<string, unknown>).sort()
    return (
      '{' +
      entries
        .map((k) => JSON.stringify(k) + ':' + jcsCanonicalize((value as Record<string, unknown>)[k]))
        .join(',') +
      '}'
    )
  }
  throw new ConnectxError('invalid_argument', `JCS: unsupported type ${typeof value}`)
}

/** `e1_` + RFC 7638 thumbprint of the Ed25519 key (JWK members `crv`, `kty`, `x`,
 *  lexicographic — already the canonical order). */
export function ed25519Fingerprint(publicKey: Uint8Array): string {
  if (publicKey.length !== ED25519_PUB_BYTES) {
    throw new ConnectxError('key_invalid', `Ed25519 public key must be ${ED25519_PUB_BYTES} bytes, got ${publicKey.length}`)
  }
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${base64UrlNoPad(publicKey)}"}`
  const digest = sha256(utf8(canonical))
  return `e1_${base64UrlNoPad(digest)}`
}

/** `k1_` + RFC 7638 thumbprint of the secp256k1 key (JWK members `crv`, `kty`,
 *  `x`, `y`). Accepts compressed (33) or uncompressed (65) SEC1 bytes. */
export function secp256k1Fingerprint(publicKey: Uint8Array): string {
  let raw: Uint8Array
  try {
    raw = secp256k1.Point.fromBytes(publicKey).toBytes(false) // 0x04 || x(32) || y(32)
  } catch (err) {
    throw new ConnectxError('key_invalid', `Invalid secp256k1 public key (${publicKey.length} bytes)`, { cause: err })
  }
  const canonical = `{"crv":"secp256k1","kty":"EC","x":"${base64UrlNoPad(raw.slice(1, 33))}","y":"${base64UrlNoPad(raw.slice(33, 65))}"}`
  const digest = sha256(utf8(canonical))
  return `k1_${base64UrlNoPad(digest)}`
}

/** The DID fingerprint for a key on `curve` (see identityDid). */
export function didFingerprint(curve: 'ed25519' | 'secp256k1', publicKey: Uint8Array): string {
  return curve === 'ed25519' ? ed25519Fingerprint(publicKey) : secp256k1Fingerprint(publicKey)
}

/** Whether a path segment is a well-formed e1_/k1_ fingerprint (2-char prefix +
 *  43-char base64url digest). Used by the resolver and tests. */
export function isFingerprint(segment: string): boolean {
  return /^(e1_|k1_)[A-Za-z0-9_-]{43}$/.test(segment)
}
