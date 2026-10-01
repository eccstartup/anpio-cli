// Key loaders — the CLI's input boundary. All formats converge to a raw
// `{ privateKey: Uint8Array, curve }` pair that `keypairWallet` can hold. Curves:
// `'ed25519'` (32-byte seed) or `'secp256k1'` (32-byte scalar).

import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist as english } from '@scure/bip39/wordlists/english.js'
import { HDKey } from '@scure/bip32'
import { sha256 } from '@noble/hashes/sha2.js'
import { scrypt as nobleScrypt } from '@noble/hashes/scrypt.js'
import { pbkdf2 as noblePbkdf2 } from '@noble/hashes/pbkdf2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { base64ToBytes } from '../crypto/encoding'
import { getNodeBuiltin } from '../nodeBuiltin'
import { ConnectxError } from '../errors'

export type ParsedKeyCurve = 'ed25519' | 'secp256k1'

// -- keystore V3 KDF / plaintext bounds --------------------------------------
// The CLI parses untrusted keystore JSON at its input boundary. These caps keep a
// maliciously large N/r/p/c, oversized salt/IV/ciphertext or a wrong-length
// plaintext from causing OOM, a CPU denial of service, or a silently truncated key.
const SCRYPT_MAX_N = 2 ** 20 // must also be a power of two
const SCRYPT_MAX_NR = 2 ** 21 // ~128*N*r ≈ 256 MB scrypt memory bound (geth default is 2^18·8 = 2^21)
const SCRYPT_MAX_R = 32
const SCRYPT_MAX_P = 16
const PBKDF2_MAX_C = 1_000_000
const MAX_SALT_BYTES = 1024
const IV_BYTES = 16
const KDF_DKLEN = 32 // 16 cipher key + 16 MAC key, AES-128-CTR
const MAX_CIPHERTEXT_BYTES = 1024
const PRIVATE_KEY_BYTES = 32

// secp256k1 group order n (0xFFFFFFFF…BAAEDCE6AF48A03BBFD25E8CD0364141). A valid
// private scalar is in [1, n-1]; a zero or ≥ n value would be rejected by the
// curve and must not be accepted from a keystore.
const SECP256K1_N = new Uint8Array([
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbb, 0xfd, 0x25, 0xe8, 0xcd, 0x03, 0x64, 0x41,
])

function isValidSecp256k1Scalar(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false
  let nonzero = false
  for (const b of bytes) if (b !== 0) {
    nonzero = true
    break
  }
  if (!nonzero) return false // scalar 0 is invalid
  for (let i = 0; i < 32; i++) {
    if (bytes[i] < SECP256K1_N[i]) return true
    if (bytes[i] > SECP256K1_N[i]) return false
  }
  return false // bytes === n exactly (zero mod n) is invalid
}

function assertKdfParam(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ConnectxError('key_invalid', `Invalid keystore kdf param: ${name}`)
  }
  if (value < min || value > max) {
    throw new ConnectxError('key_invalid', `Keystore kdf param ${name} out of range [${min}, ${max}]: ${value}`)
  }
  return value
}

export interface ParsedKey {
  privateKey: Uint8Array
  curve: ParsedKeyCurve
}

function stripHexPrefix(hex: string): string {
  return hex.replace(/^0x/i, '')
}

function hexBytes(hex: string): Uint8Array {
  const h = stripHexPrefix(hex)
  if (h.length % 2 !== 0) throw new ConnectxError('key_invalid', 'Odd-length hex')
  // `parseInt` returns NaN for non-hex digits and Uint8Array coerces that to 0, so
  // silently produce a zero byte. Reject invalid characters explicitly instead.
  if (!/^[0-9a-fA-F]+$/.test(h)) throw new ConnectxError('key_invalid', 'Invalid hex characters')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

// --- hex private key ----------------------------------------------------------

/** Parse a raw hex private key (32 bytes). Curve must be given (hex is opaque). */
export function parsePrivateKey(hex: string, curve: ParsedKeyCurve = 'ed25519'): ParsedKey {
  const bytes = hexBytes(hex)
  if (bytes.length !== 32) throw new ConnectxError('key_invalid', `Expected 32-byte private key, got ${bytes.length}`)
  return { privateKey: bytes, curve }
}

// --- mnemonic (BIP-39) --------------------------------------------------------

// EVM / secp256k1 uses BIP-44 path `m/44'/60'/0'/0/0`. ed25519 uses the 32-byte
// seed directly (a BIP-39 seed IS an ed25519 private key seed).
const EVM_PATH = "m/44'/60'/0'/0/0"

/** Parse a BIP-39 mnemonic phrase. For secp256k1, derive the BIP-44 key; for
 *  ed25519, use the first 32 bytes of the seed as the private key. */
export function parseMnemonic(mnemonic: string, curve: ParsedKeyCurve = 'ed25519', path?: string): ParsedKey {
  const phrase = mnemonic.trim().toLowerCase()
  if (!validateMnemonic(phrase, english)) throw new ConnectxError('key_invalid', 'Invalid BIP-39 mnemonic')
  const seed = mnemonicToSeedSync(phrase, '')

  if (curve === 'ed25519') {
    return { privateKey: seed.slice(0, 32), curve }
  }

  const child = HDKey.fromMasterSeed(seed).derive(path ?? EVM_PATH)
  if (!child.privateKey) throw new ConnectxError('key_invalid', 'Failed to derive secp256k1 key from mnemonic')
  return { privateKey: child.privateKey, curve }
}

// --- keystore V3 JSON ---------------------------------------------------------

// A keystore is a CLI/agent-side format (geth/OKX), not a browser-wallet concern, and
// decrypting one needs `node:crypto`. We reach it through `getNodeBuiltin` so the browser
// bundle carries no `crypto` specifier for a bundler to resolve; a runtime that has no
// such module fails loudly here instead of silently.
function cryptoLib(): typeof import('node:crypto') {
  const lib = getNodeBuiltin<typeof import('node:crypto')>('crypto')
  if (!lib) throw new ConnectxError('key_unsupported', 'Keystore decryption requires node:crypto (Node runtime)')
  return lib
}

interface KeystoreV3 {
  version: number
  crypto: {
    cipher: string
    ciphertext: string
    cipherparams: { iv: string }
    kdf: string
    kdfparams: Record<string, unknown>
    mac: string
  }
}

// Derive the decryption key from the keystore's kdf params (scrypt / pbkdf2).
function deriveKeystoreKey(json: KeystoreV3, password: string): Uint8Array {
  const p = json.crypto.kdfparams
  if (typeof p.salt !== 'string') throw new ConnectxError('key_invalid', 'Keystore kdfparams missing salt')
  const salt = hexBytes(p.salt)
  if (salt.length === 0 || salt.length > MAX_SALT_BYTES) {
    throw new ConnectxError('key_invalid', `Keystore salt length out of range [1, ${MAX_SALT_BYTES}]: ${salt.length}`)
  }
  const dklen = (p.dklen as number) ?? 32
  if (dklen !== KDF_DKLEN) throw new ConnectxError('key_invalid', `Keystore dklen must be ${KDF_DKLEN}, got ${dklen}`)

  if (json.crypto.kdf === 'scrypt') {
    const N = assertKdfParam(p.n, 'N', 2, SCRYPT_MAX_N)
    const r = assertKdfParam(p.r, 'r', 1, SCRYPT_MAX_R)
    const pCost = assertKdfParam(p.p, 'p', 1, SCRYPT_MAX_P)
    if ((N & (N - 1)) !== 0) throw new ConnectxError('key_invalid', `Keystore scrypt N must be a power of two, got ${N}`)
    if (N * r > SCRYPT_MAX_NR) throw new ConnectxError('key_invalid', `Keystore scrypt cost too high: N*r=${N * r}`)
    return nobleScrypt(password, salt, { N, r, p: pCost, dkLen: dklen })
  }
  if (json.crypto.kdf === 'pbkdf2') {
    const prf = (p.prf as string) ?? 'hmac-sha256'
    if (prf !== 'hmac-sha256') throw new ConnectxError('key_unsupported', `Unsupported pbkdf2 prf: ${prf}`)
    const c = assertKdfParam(p.c, 'c', 1, PBKDF2_MAX_C)
    return noblePbkdf2(sha256, password, salt, { c, dkLen: dklen })
  }
  throw new ConnectxError('key_unsupported', `Unsupported keystore kdf: ${json.crypto.kdf}`)
}

/** Parse an Ethereum keystore V3 JSON. The encrypted key is secp256k1. */
export async function parseKeystore(json: string, password: string): Promise<ParsedKey> {
  let obj: KeystoreV3
  try {
    obj = JSON.parse(json) as KeystoreV3
  } catch (err) {
    throw new ConnectxError('key_invalid', 'Keystore is not valid JSON', { cause: err })
  }
  if (obj.version !== 3) throw new ConnectxError('key_unsupported', `Unsupported keystore version: ${obj.version}`)
  if (obj.crypto.cipher !== 'aes-128-ctr') throw new ConnectxError('key_unsupported', `Unsupported cipher: ${obj.crypto.cipher}`)

  const key = deriveKeystoreKey(obj, password)
  const iv = hexBytes(obj.crypto.cipherparams.iv)
  if (iv.length !== IV_BYTES) throw new ConnectxError('key_invalid', `Invalid keystore IV length: ${iv.length}`)
  const ct = hexBytes(obj.crypto.ciphertext)
  if (ct.length === 0 || ct.length > MAX_CIPHERTEXT_BYTES) {
    throw new ConnectxError('key_invalid', `Invalid keystore ciphertext length: ${ct.length}`)
  }

  // Verify MAC = keccak256(derivedKey[16..32] || ciphertext)
  const macInput = new Uint8Array(16 + ct.length)
  macInput.set(key.slice(16, 32), 0)
  macInput.set(ct, 16)
  const mac = hexBytes(obj.crypto.mac)
  if (!macEquals(keccak_256(macInput), mac)) throw new ConnectxError('key_wrong_password', 'Keystore MAC mismatch (wrong password?)')

  const { createDecipheriv } = cryptoLib()
  const decipher = createDecipheriv('aes-128-ctr', key.slice(0, 16), iv)
  const plain = new Uint8Array(decipher.update(ct) as Buffer)
  // A secp256k1 private key is exactly 32 bytes; truncating a short/long plaintext
  // would silently yield a different "valid" key, so reject instead of slicing.
  if (plain.length !== PRIVATE_KEY_BYTES) {
    throw new ConnectxError('key_invalid', `Keystore plaintext must be ${PRIVATE_KEY_BYTES} bytes, got ${plain.length}`)
  }
  if (!isValidSecp256k1Scalar(plain)) {
    throw new ConnectxError('key_invalid', 'Keystore private key is not a valid secp256k1 scalar')
  }
  return { privateKey: plain, curve: 'secp256k1' }
}

function macEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

// --- PEM ----------------------------------------------------------------------

// Extract the 32-byte private key from a PEM private key (PKCS#8 `PRIVATE KEY` or
// SEC1 `EC PRIVATE KEY`). The curve is ambiguous from length alone, so the caller
// must pass `--curve` (defaults to ed25519). The PKCS#8 DER payload for ed25519 /
// secp256k1 both end with `0x04 0x20 <32-byte key>`.
export function parsePem(pem: string, curve: ParsedKeyCurve = 'ed25519'): ParsedKey {
  const body = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s+/g, '')
  // PEM bodies are base64-encoded DER. Some tools instead frame the raw DER as a
  // hex string inside the markers, so decode by the body's shape: all-hex/even
  // length → hex, otherwise → base64.
  const isHex = /^[0-9a-fA-F]+$/.test(body) && body.length % 2 === 0
  const der = isHex ? hexBytes(body) : base64ToBytes(body)
  if (der.length < 32) throw new ConnectxError('key_invalid', 'PEM private key too short')
  return { privateKey: der.slice(der.length - 32), curve }
}
