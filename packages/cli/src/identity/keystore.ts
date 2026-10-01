// At-rest key codec for the identity store (`~/.connectx/.../key`).
//
// Emits a standard Ethereum keystore V3 JSON (scrypt + aes-128-ctr + keccak256
// MAC), so a secp256k1 store file is interoperable with geth/OKX tooling. The
// **decrypt** path here is deliberately curve-agnostic: core's `parseKeystore`
// hard-codes secp256k1 (it validates the plaintext as a scalar and reports
// `curve: 'secp256k1'`), which would misread an ed25519 seed — and an ed25519
// seed is not guaranteed to be a valid secp256k1 scalar. The stored curve lives
// in `identity.json`; this module only needs the raw 32 bytes.
//
// SECURITY: KDF params are capped on read too — the store file is attacker-
// writable in the threat model that matters (another co-resident process), so a
// huge N/r/p must not become a CPU/memory DoS on every CLI invocation.

import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto'
import { scrypt as nobleScrypt } from '@noble/hashes/scrypt.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { ConnectxError } from '@agentx/core'

const KEYSTORE_N = 2 ** 16 // 65536 → ~64 MB scrypt memory, ~0.3 s. Dev-store tier.
const SCRYPT_R = 8
const SCRYPT_P = 1
const DKLEN = 32 // 16 cipher key + 16 MAC key (AES-128-CTR)
const PRIVATE_KEY_BYTES = 32
const IV_BYTES = 16
const MAC_BYTES = 32

// Read-side caps — mirrors the core keystore parser so a hostile store file
// cannot force unbounded work.
const MAX_N = 2 ** 20
const MAX_R = 32
const MAX_P = 16
const MAX_SALT_BYTES = 1024
const MAX_CIPHERTEXT_BYTES = 1024

function toHex(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

function fromHex(hex: unknown, name: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new ConnectxError('key_invalid', `Invalid keystore field "${name}" (expected hex)`)
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function assertBytes(bytes: Uint8Array, name: string, min: number, max: number): void {
  if (bytes.length < min || bytes.length > max) {
    throw new ConnectxError('key_invalid', `Keystore field "${name}" length out of range [${min}, ${max}]: ${bytes.length}`)
  }
}

function assertInt(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new ConnectxError('key_invalid', `Keystore kdf param "${name}" out of range [${min}, ${max}]`)
  }
  return value
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

/** Encrypt a 32-byte private key (any curve) into a keystore V3 JSON string. */
export async function encryptPrivateKey(privateKey: Uint8Array, password: string): Promise<string> {
  if (privateKey.length !== PRIVATE_KEY_BYTES) {
    throw new ConnectxError('key_invalid', `Expected a ${PRIVATE_KEY_BYTES}-byte key to encrypt, got ${privateKey.length}`)
  }
  // Allocate as plain Uint8Array (not the Buffer node:crypto returns): under a
  // jsdom test realm the global Uint8Array differs from Buffer, and noble's
  // `isBytes` check would reject it.
  const salt = new Uint8Array(randomBytes(32))
  const iv = new Uint8Array(randomBytes(IV_BYTES))
  const dk = await nobleScrypt(password, salt, { N: KEYSTORE_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: DKLEN })

  const cipher = createCipheriv('aes-128-ctr', dk.slice(0, 16), iv)
  const ciphertext = new Uint8Array(Buffer.concat([cipher.update(privateKey), cipher.final()]))

  const macInput = new Uint8Array(16 + ciphertext.length)
  macInput.set(dk.slice(16, 32), 0)
  macInput.set(ciphertext, 16)
  const mac = keccak_256(macInput)

  return (
    JSON.stringify(
      {
        version: 3,
        id: randomUUID(),
        crypto: {
          cipher: 'aes-128-ctr',
          ciphertext: toHex(ciphertext),
          cipherparams: { iv: toHex(iv) },
          kdf: 'scrypt',
          kdfparams: { dklen: DKLEN, n: KEYSTORE_N, r: SCRYPT_R, p: SCRYPT_P, salt: toHex(salt) },
          mac: toHex(mac),
        },
      },
      null,
      2,
    ) + '\n'
  )
}

/** Decrypt a keystore V3 JSON (as written by `encryptPrivateKey`, or by geth/OKX)
 *  into the raw 32-byte private key. Curve is NOT assumed — the caller reads it
 *  from `identity.json`. */
export async function decryptPrivateKey(json: string, password: string): Promise<Uint8Array> {
  let obj: { version?: unknown; crypto?: Record<string, unknown> }
  try {
    obj = JSON.parse(json) as typeof obj
  } catch (err) {
    throw new ConnectxError('key_invalid', 'Stored key is not valid JSON', { cause: err })
  }
  if (obj.version !== 3) throw new ConnectxError('key_unsupported', `Unsupported keystore version: ${String(obj.version)}`)

  const crypto = obj.crypto as Record<string, unknown> | undefined
  if (!crypto || typeof crypto !== 'object') throw new ConnectxError('key_invalid', 'Keystore missing "crypto" section')
  if (crypto.cipher !== 'aes-128-ctr') throw new ConnectxError('key_unsupported', `Unsupported cipher: ${String(crypto.cipher)}`)
  if (crypto.kdf !== 'scrypt') throw new ConnectxError('key_unsupported', `Unsupported keystore kdf: ${String(crypto.kdf)}`)

  const p = (crypto.kdfparams ?? {}) as Record<string, unknown>
  if ((p.dklen ?? DKLEN) !== DKLEN) throw new ConnectxError('key_unsupported', `Unsupported dklen: ${String(p.dklen)} (expected ${DKLEN})`)
  const N = assertInt(p.n, 'n', 2, MAX_N)
  if ((N & (N - 1)) !== 0) throw new ConnectxError('key_invalid', `Keystore scrypt n must be a power of two, got ${N}`)
  const r = assertInt(p.r, 'r', 1, MAX_R)
  const pCost = assertInt(p.p, 'p', 1, MAX_P)

  const salt = fromHex(p.salt, 'salt')
  assertBytes(salt, 'salt', 1, MAX_SALT_BYTES)
  const iv = fromHex((crypto.cipherparams as Record<string, unknown> | undefined)?.iv, 'iv')
  assertBytes(iv, 'iv', IV_BYTES, IV_BYTES)
  const ct = fromHex(crypto.ciphertext, 'ciphertext')
  assertBytes(ct, 'ciphertext', PRIVATE_KEY_BYTES, MAX_CIPHERTEXT_BYTES)
  const mac = fromHex(crypto.mac, 'mac')
  assertBytes(mac, 'mac', MAC_BYTES, MAC_BYTES)

  const dk = await nobleScrypt(password, salt, { N, r, p: pCost, dkLen: DKLEN })

  const macInput = new Uint8Array(16 + ct.length)
  macInput.set(dk.slice(16, 32), 0)
  macInput.set(ct, 16)
  if (!constantTimeEqual(keccak_256(macInput), mac)) {
    throw new ConnectxError('key_wrong_password', 'Stored key MAC mismatch (wrong CONNECTX_KEY_PASSWORD?)')
  }

  const decipher = createDecipheriv('aes-128-ctr', dk.slice(0, 16), iv)
  const plain = new Uint8Array(Buffer.concat([decipher.update(ct), decipher.final()]))
  if (plain.length !== PRIVATE_KEY_BYTES) {
    throw new ConnectxError('key_invalid', `Stored key plaintext must be ${PRIVATE_KEY_BYTES} bytes, got ${plain.length}`)
  }
  return plain
}
