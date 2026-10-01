import { describe, it, expect } from 'vitest'
import { base58btcEncode, base58btcDecode } from './base58'
import {
  decodeMultibaseKey,
  encodeMultibaseEd25519,
  encodeMultibaseSecp256k1,
} from './multicodec'

describe('base58btc', () => {
  it('round-trips arbitrary bytes', () => {
    for (const bytes of [new Uint8Array(0), new Uint8Array([1]), new Uint8Array([0, 0, 255]), new Uint8Array([255, 0, 1, 2, 3])]) {
      expect(base58btcDecode(base58btcEncode(bytes))).toEqual(bytes)
    }
  })

  it('encodes leading zero bytes as "1" prefixes', () => {
    expect(base58btcEncode(new Uint8Array([0, 0, 1]))).toBe('112')
  })

  it('matches the Bitcoin reference for "Hello World!"', () => {
    const hello = new TextEncoder().encode('Hello World!')
    expect(base58btcEncode(hello)).toBe('2NEpo7TZRRrLZSi2U')
  })

  it('rejects characters outside the Bitcoin alphabet', () => {
    expect(() => base58btcDecode('0OIl')).toThrow()
  })
})

describe('multicodec', () => {
  const edPub = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1))
  const secpPub = new Uint8Array(Array.from({ length: 33 }, (_, i) => i + 1))

  it('round-trips the official ed25519-pub multicodec (0xed 0x01)', () => {
    const mb = encodeMultibaseEd25519(edPub)
    expect(mb.startsWith('z')).toBe(true)
    const decoded = decodeMultibaseKey(mb)
    expect(decoded.curve).toBe('ed25519')
    expect(decoded.bytes).toEqual(edPub)
  })

  it('decodes the legacy 33-byte ed25519 prefix (0xed)', () => {
    const legacy = new Uint8Array(33)
    legacy[0] = 0xed
    legacy.set(edPub, 1)
    const mb = 'z' + base58btcEncode(legacy)
    const decoded = decodeMultibaseKey(mb)
    expect(decoded.curve).toBe('ed25519')
    expect(decoded.bytes).toEqual(edPub)
  })

  it('round-trips the secp256k1-pub multicodec (0xe7 0x01)', () => {
    const mb = encodeMultibaseSecp256k1(secpPub)
    const decoded = decodeMultibaseKey(mb)
    expect(decoded.curve).toBe('secp256k1')
    expect(decoded.bytes).toEqual(secpPub)
  })

  it('rejects a non-base58btc multibase prefix', () => {
    expect(() => decodeMultibaseKey('mnot-base58')).toThrow()
  })

  it('rejects an unknown multicodec prefix', () => {
    const unknown = new Uint8Array(34)
    unknown[0] = 0x99
    unknown[1] = 0x01
    unknown.set(edPub, 2)
    expect(() => decodeMultibaseKey('z' + base58btcEncode(unknown))).toThrow(/Unsupported multicodec/)
  })
})
