// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { pbkdf2Sync, createCipheriv, randomBytes } from 'node:crypto'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { parsePrivateKey, parseMnemonic, parseKeystore, parsePem } from './parse'

const MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

// Build a valid eth keystore V3 (pbkdf2, fast params) so the round-trip test
// doesn't pay the standard scrypt cost. The parser reads c/dklen from the JSON.
function buildKeystore(privateKeyHex: string, password: string, dklen = 32): string {
  const salt = randomBytes(32)
  const c = 1000
  const derived = new Uint8Array(pbkdf2Sync(password, salt, c, dklen, 'sha256'))
  const iv = randomBytes(16)
  const cipher = createCipheriv('aes-128-ctr', derived.slice(0, 16), iv)
  const ct = Buffer.concat([cipher.update(Buffer.from(privateKeyHex, 'hex')), cipher.final()])
  const macInput = Buffer.concat([Buffer.from(derived.slice(16, 32)), ct])
  const mac = keccak_256(new Uint8Array(macInput))
  return JSON.stringify({
    version: 3,
    crypto: {
      cipher: 'aes-128-ctr',
      ciphertext: ct.toString('hex'),
      cipherparams: { iv: iv.toString('hex') },
      kdf: 'pbkdf2',
      kdfparams: { dklen, salt: salt.toString('hex'), c, prf: 'hmac-sha256' },
      mac: toHex(mac),
    },
  })
}

// A forged scrypt keystore. The KDF params are validated BEFORE any scrypt cost
// or MAC check, so a bad param is rejected regardless of the (fake) mac/ciphertext.
function buildScryptKeystore(kdfparams: Record<string, unknown>): string {
  return JSON.stringify({
    version: 3,
    crypto: {
      cipher: 'aes-128-ctr',
      ciphertext: '00'.repeat(32),
      cipherparams: { iv: '00'.repeat(16) },
      kdf: 'scrypt',
      kdfparams,
      mac: '00'.repeat(32),
    },
  })
}

describe('parsePrivateKey', () => {
  const hex = 'ab'.repeat(32)

  it('parses a 32-byte hex key and defaults the curve to ed25519', () => {
    const key = parsePrivateKey(hex)
    expect(key.curve).toBe('ed25519')
    expect(toHex(key.privateKey)).toBe(hex)
  })

  it('accepts an explicit 0x prefix', () => {
    expect(toHex(parsePrivateKey('0x' + hex).privateKey)).toBe(hex)
  })

  it('honours an explicit curve', () => {
    expect(parsePrivateKey(hex, 'secp256k1').curve).toBe('secp256k1')
  })

  it('rejects a key that is not 32 bytes', () => {
    expect(() => parsePrivateKey('ab'.repeat(31))).toThrow(/32-byte/)
    expect(() => parsePrivateKey('ab'.repeat(33))).toThrow(/32-byte/)
  })

  it('rejects a hex key with non-hex characters (no silent zero bytes)', () => {
    expect(() => parsePrivateKey('zz'.repeat(32))).toThrow(/Invalid hex/)
    expect(() => parsePrivateKey('ab'.repeat(31) + 'gg')).toThrow(/Invalid hex/)
    expect(() => parsePrivateKey('0x' + 'ab'.repeat(32))).not.toThrow()
  })
})

describe('parseMnemonic', () => {
  it('uses the first 32 bytes of the BIP-39 seed for ed25519 (BIP-39 vector)', () => {
    const key = parseMnemonic(MNEMONIC, 'ed25519')
    expect(key.curve).toBe('ed25519')
    // Official BIP-39 test-vector seed begins 5eb00bbddcf06908…
    expect(toHex(key.privateKey.slice(0, 8))).toBe('5eb00bbddcf06908')
  })

  it('derives the BIP-44 secp256k1 key and its EVM address (`0x9858ef…`)', () => {
    const key = parseMnemonic(MNEMONIC, 'secp256k1')
    expect(key.curve).toBe('secp256k1')
    const priv = key.privateKey
    // Deterministic and matches the well-known m/44'/60'/0'/0/0 vector.
    expect(toHex(priv)).toBe('1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727')
  })

  it('is deterministic given the same phrase', () => {
    const a = parseMnemonic(MNEMONIC, 'secp256k1')
    const b = parseMnemonic(MNEMONIC, 'secp256k1')
    expect(toHex(a.privateKey)).toBe(toHex(b.privateKey))
  })

  it('rejects an invalid BIP-39 mnemonic', () => {
    expect(() => parseMnemonic('not a valid mnemonic phrase', 'ed25519')).toThrow(/Invalid BIP-39/)
  })
})

describe('parseKeystore', () => {
  const privHex = 'aa'.repeat(32)

  it('round-trips a keystore V3 file back to the original private key', async () => {
    const json = buildKeystore(privHex, 'test-pass')
    const key = await parseKeystore(json, 'test-pass')
    expect(key.curve).toBe('secp256k1')
    expect(toHex(key.privateKey)).toBe(privHex)
  })

  it('rejects a wrong password with a MAC mismatch', async () => {
    const json = buildKeystore(privHex, 'test-pass')
    await expect(parseKeystore(json, 'wrong-pass')).rejects.toThrow(/MAC mismatch/)
  })

  it('rejects an unsupported keystore version', async () => {
    await expect(parseKeystore(JSON.stringify({ version: 2, crypto: {} }), 'p')).rejects.toThrow(/version/)
  })
})

describe('parsePem', () => {
  const key = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1))
  const keyHex = toHex(key)

  function realPem(label = 'PRIVATE KEY'): string {
    // PKCS#8 wrapper (302e020100300506032b657004220420) + 32-byte key, base64 PEM.
    const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(key)])
    const b64 = der.toString('base64').replace(/(.{64})/g, '$1\n').trim()
    return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`
  }

  it('parses a real base64 PKCS#8 PEM', () => {
    const parsed = parsePem(realPem(), 'ed25519')
    expect(parsed.curve).toBe('ed25519')
    expect(toHex(parsed.privateKey)).toBe(keyHex)
  })

  it('still accepts a hex-framed DER body (back-compat)', () => {
    const hexDer = '00'.repeat(5) + '0420' + keyHex
    const pem = `-----BEGIN PRIVATE KEY-----\n${hexDer}\n-----END PRIVATE KEY-----`
    expect(toHex(parsePem(pem, 'secp256k1').privateKey)).toBe(keyHex)
  })

  it('honours an explicit curve label', () => {
    expect(parsePem(realPem('EC PRIVATE KEY'), 'secp256k1').curve).toBe('secp256k1')
  })

  it('rejects a PEM that is too short', () => {
    expect(() => parsePem('-----BEGIN PRIVATE KEY-----AA==-----END PRIVATE KEY-----')).toThrow(/too short/)
  })
})

describe('parseKeystore — strict boundaries (3.6)', () => {
  it('rejects an oversized scrypt N (CPU/memory DoS)', async () => {
    const json = buildScryptKeystore({ dklen: 32, salt: '00'.repeat(32), n: 2 ** 24, r: 8, p: 1 })
    await expect(parseKeystore(json, 'p')).rejects.toThrow(/out of range|power of two/)
  })

  it('rejects a scrypt N that is not a power of two', async () => {
    const json = buildScryptKeystore({ dklen: 32, salt: '00'.repeat(32), n: 1000, r: 8, p: 1 })
    await expect(parseKeystore(json, 'p')).rejects.toThrow(/power of two/)
  })

  it('rejects a scrypt N*r cost above the memory bound', async () => {
    const json = buildScryptKeystore({ dklen: 32, salt: '00'.repeat(32), n: 2 ** 19, r: 32, p: 1 })
    await expect(parseKeystore(json, 'p')).rejects.toThrow(/cost too high/)
  })

  it('rejects a dklen that is not 32', async () => {
    const json = buildKeystore('aa'.repeat(32), 'test-pass', 16)
    await expect(parseKeystore(json, 'test-pass')).rejects.toThrow(/dklen/)
  })

  it('rejects a decrypted plaintext that is not exactly 32 bytes', async () => {
    const json = buildKeystore('aa'.repeat(16), 'test-pass')
    await expect(parseKeystore(json, 'test-pass')).rejects.toThrow(/32 bytes/)
  })

  it('rejects a zero scalar as an invalid secp256k1 private key', async () => {
    const json = buildKeystore('00'.repeat(32), 'test-pass')
    await expect(parseKeystore(json, 'test-pass')).rejects.toThrow(/valid secp256k1 scalar/)
  })

  it('rejects a scalar at or above the secp256k1 order', async () => {
    const json = buildKeystore('ff'.repeat(32), 'test-pass')
    await expect(parseKeystore(json, 'test-pass')).rejects.toThrow(/valid secp256k1 scalar/)
  })
})
