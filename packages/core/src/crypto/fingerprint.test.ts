// ANP fingerprint + JCS. The fixed vectors are computed independently (node:crypto
// over the canonical JWK) so they catch a drift in our own encoding, and also match
// the sibling `agent-on/anp-extension` implementation byte-for-byte.

import { describe, it, expect } from 'vitest'
import { createHash } from 'node:crypto'
import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { jcsCanonicalize, ed25519Fingerprint, secp256k1Fingerprint, didFingerprint, isFingerprint } from './fingerprint'

const ED_PUB = ed25519.getPublicKey(new Uint8Array(32).fill(1))
const ED_FP = 'e1_UDDReOZl1ipXAfp9wYsm13sDBMK5og--QWdBjzuf6o4'

const SECP_PRIV = new Uint8Array(32).fill(0)
SECP_PRIV[31] = 7
const SECP_PUB = secp256k1.getPublicKey(SECP_PRIV, true)
const SECP_FP = 'k1_Mc-1_VGnYGwusEQCyWevvC6PCzwNbq_JDbNYavdMbco'

// Independent reference: RFC 7638 thumbprint of the JWK → sha256 → base64url.
function refFingerprint(prefix: string, jwkJson: string): string {
  return prefix + createHash('sha256').update(jwkJson, 'utf8').digest('base64url')
}

describe('jcsCanonicalize (RFC 8785)', () => {
  it('sorts object keys and preserves structure', () => {
    expect(jcsCanonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}')
    expect(jcsCanonicalize({ z: [{ y: true, x: null }] })).toBe('{"z":[{"x":null,"y":true}]}')
    expect(jcsCanonicalize('a"b')).toBe('"a\\"b"')
    expect(jcsCanonicalize([3, 1, 2])).toBe('[3,1,2]')
  })

  it('rejects non-finite numbers', () => {
    expect(() => jcsCanonicalize(Number.POSITIVE_INFINITY)).toThrowError()
  })
})

describe('fingerprints', () => {
  it('ed25519 → e1_ vector, matching an independent thumbprint', () => {
    const x = Buffer.from(ED_PUB).toString('base64url')
    expect(ed25519Fingerprint(ED_PUB)).toBe(ED_FP)
    expect(ed25519Fingerprint(ED_PUB)).toBe(refFingerprint('e1_', `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`))
  })

  it('secp256k1 → k1_ vector (compressed input), matching an independent thumbprint', () => {
    const raw = secp256k1.Point.fromBytes(SECP_PUB).toBytes(false)
    const x = Buffer.from(raw.slice(1, 33)).toString('base64url')
    const y = Buffer.from(raw.slice(33, 65)).toString('base64url')
    expect(secp256k1Fingerprint(SECP_PUB)).toBe(SECP_FP)
    expect(secp256k1Fingerprint(SECP_PUB)).toBe(refFingerprint('k1_', `{"crv":"secp256k1","kty":"EC","x":"${x}","y":"${y}"}`))
  })

  it('dispatching by curve, length invariant, and the shape guard', () => {
    expect(didFingerprint('ed25519', ED_PUB)).toBe(ED_FP)
    expect(didFingerprint('secp256k1', SECP_PUB)).toBe(SECP_FP)
    expect(ED_FP).toHaveLength(46) // 'e1_' + 43 base64url chars
    expect(isFingerprint(ED_FP)).toBe(true)
    expect(isFingerprint(SECP_FP)).toBe(true)
    expect(isFingerprint('e1_short')).toBe(false)
    expect(isFingerprint(ED_FP.replace('e1_', 'x1_'))).toBe(false)
  })

  it('rejects a wrong-length ed25519 key', () => {
    expect(() => ed25519Fingerprint(new Uint8Array(31))).toThrowError(/must be 32 bytes/)
  })
})
