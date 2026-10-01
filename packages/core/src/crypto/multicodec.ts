import { secp256k1 } from '@noble/curves/secp256k1.js'
import { base58btcDecode, base58btcEncode } from './base58'
import { base64UrlNoPad } from './encoding'
import { ConnectxError } from '../errors'

export type Curve = 'ed25519' | 'secp256k1'

// Multicodec prefixes for public keys (ANP-03: `e1_` Ed25519, `k1_` secp256k1).
// - ed25519-pub   = 0xed 0x01 (varint) + 32 bytes   ← official ANP SDK encoding
// - ed25519-pub   = 0xed        + 32 bytes          ← legacy in-repo browser shim
// - secp256k1-pub = 0xe7 0x01   + 33 bytes (compressed point)
const ED25519_OFFICIAL: [number, number] = [0xed, 0x01]
const ED25519_LEGACY = 0xed

export function decodeMultibaseKey(multibase: string): { curve: Curve; bytes: Uint8Array } {
  if (!multibase.startsWith('z')) throw new ConnectxError('key_invalid', 'Expected base58btc-prefixed multibase key')
  const decoded = base58btcDecode(multibase.slice(1))

  if (decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01) {
    return { curve: 'ed25519', bytes: decoded.slice(2) }
  }
  if (decoded.length === 33 && decoded[0] === ED25519_LEGACY) {
    return { curve: 'ed25519', bytes: decoded.slice(1) }
  }
  if (decoded.length === 35 && decoded[0] === 0xe7 && decoded[1] === 0x01) {
    return { curve: 'secp256k1', bytes: decoded.slice(2) }
  }
  throw new ConnectxError('key_unsupported', 'Unsupported multicodec key prefix')
}

// The SDK emits the OFFICIAL `0xed 0x01` prefix (34 bytes) for new identities.
export function encodeMultibaseEd25519(pub: Uint8Array): string {
  const prefixed = new Uint8Array(34)
  prefixed[0] = ED25519_OFFICIAL[0]
  prefixed[1] = ED25519_OFFICIAL[1]
  prefixed.set(pub, 2)
  return 'z' + base58btcEncode(prefixed)
}

/** Encode a secp256k1 public key as a multibase string (`0xe7 0x01` + compressed
 *  point).
 *
 *  ⚠️ This is NOT how a `k1_` DID document publishes its binding key. Appendix A
 *  represents it as `publicKeyJwk` (A.3 step 1, **L39**) and defines no secp256k1
 *  `publicKeyMultibase` at all; ANP-03 **L149** reserves that property for Ed25519.
 *  Use {@link secp256k1PublicKeyToJwk} for a document. This encoder stays because the
 *  encoding itself is well-formed and this SDK still READS it: `decodeMultibaseKey`
 *  accepts the same prefix, and `extractEcPublicKey`-style documents from other
 *  implementations may carry one. */
export function encodeMultibaseSecp256k1(pub: Uint8Array): string {
  const prefixed = new Uint8Array(35)
  prefixed[0] = 0xe7
  prefixed[1] = 0x01
  prefixed.set(pub, 2)
  return 'z' + base58btcEncode(prefixed)
}

/** A secp256k1 public key in JWK form, the representation Appendix A publishes a `k1_`
 *  binding key in (A.3 step 2 / A.4 **L76–89**). `x` and `y` are base64url with no
 *  padding, and the RFC 7638 thumbprint the DID's fingerprint is built from uses
 *  exactly these four members.
 *
 *  The spec's *recommended* shape also lists an optional `kid` carrying the
 *  fingerprint. This SDK omits it: JWK `kid` is optional, the RFC 7638 thumbprint
 *  ignores every member but these four, A.4's four constraints do not mention it, and
 *  the reader that exists (the official SDK's `publicKeyFromJwk`) derives nothing from
 *  it — repeating the fingerprint inside the key object would only duplicate a value
 *  the DID already commits to. */
export interface Secp256k1PublicKeyJwk {
  kty: 'EC'
  crv: 'secp256k1'
  x: string
  y: string
}

/** Encode a secp256k1 public key as the JWK a `k1_` DID document carries. Accepts
 *  compressed (33) or uncompressed (65) SEC1 bytes, like `secp256k1Fingerprint` — both
 *  are the same point, and the DID's fingerprint is computed over the same coordinates,
 *  so accepting only one would make the two disagree about which keys are usable. */
export function secp256k1PublicKeyToJwk(pub: Uint8Array): Secp256k1PublicKeyJwk {
  let raw: Uint8Array
  try {
    raw = secp256k1.Point.fromBytes(pub).toBytes(false) // 0x04 || x(32) || y(32)
  } catch (err) {
    throw new ConnectxError('key_invalid', `Invalid secp256k1 public key (${pub.length} bytes)`, { cause: err })
  }
  return {
    kty: 'EC',
    crv: 'secp256k1',
    x: base64UrlNoPad(raw.slice(1, 33)),
    y: base64UrlNoPad(raw.slice(33, 65)),
  }
}

