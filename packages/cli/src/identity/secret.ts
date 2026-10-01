// At-rest codec for arbitrary-length secrets — currently the session store
// (`session.json`). The key store (`keystore.ts`) is an Ethereum keystore V3 and
// is hard-wired to a 32-byte plaintext; a session token is an arbitrary-length
// string (usually a JWT), so it gets its own envelope.
//
// AES-256-GCM with a scrypt-derived key, in the same style as the key store. GCM
// is authenticated: a flipped byte in the ciphertext or tag fails loudly as
// `session_invalid` rather than decrypting to garbage. The password source is
// shared with the key store (see `resolvePassword` in commands/auth.ts).
//
// SECURITY: the same honest boundary as the key store — this protects a file that
// is copied, backed up, or misread, NOT against another process running as the
// same user (which can read the password too). KDF params are capped on read so a
// hostile envelope cannot force unbounded work.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { scrypt as nobleScrypt } from '@noble/hashes/scrypt.js'
import { ConnectxError } from '@agentx/core'

const KDF_N = 2 ** 16 // ~64 MB scrypt memory, ~0.3 s. Dev-store tier (matches keystore).
const SCRYPT_R = 8
const SCRYPT_P = 1
const DKLEN = 32 // AES-256 key
const SALT_BYTES = 32
const IV_BYTES = 12 // GCM standard nonce
const TAG_BYTES = 16

// Read-side caps — an attacker-writable envelope must not become a CPU/memory DoS.
const MAX_N = 2 ** 20
const MAX_R = 32
const MAX_P = 16
const MAX_SALT_BYTES = 1024
const MAX_CIPHERTEXT_BYTES = 64 * 1024

function toHex(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

function fromHex(hex: unknown, name: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new ConnectxError('session_invalid', `Invalid session envelope field "${name}" (expected hex)`)
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function assertBytes(bytes: Uint8Array, name: string, min: number, max: number): void {
  if (bytes.length < min || bytes.length > max) {
    throw new ConnectxError(
      'session_invalid',
      `Session envelope field "${name}" length out of range [${min}, ${max}]: ${bytes.length}`,
    )
  }
}

function assertInt(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    throw new ConnectxError('session_invalid', `Session envelope kdf param "${name}" out of range [${min}, ${max}]`)
  }
  return value
}

/** Seal a UTF-8 secret into an authenticated envelope JSON string. */
export async function sealSecret(plaintext: string, password: string): Promise<string> {
  // Allocate as plain Uint8Array (not the Buffer node:crypto returns): under a
  // jsdom test realm the global Uint8Array differs from Buffer and noble's
  // `isBytes` check would reject it.
  const salt = new Uint8Array(randomBytes(SALT_BYTES))
  const iv = new Uint8Array(randomBytes(IV_BYTES))
  const dk = await nobleScrypt(password, salt, { N: KDF_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: DKLEN })

  const cipher = createCipheriv('aes-256-gcm', dk, iv)
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const sealed = new Uint8Array(Buffer.concat([body, cipher.getAuthTag()]))

  return (
    JSON.stringify(
      {
        version: 1,
        kdf: 'scrypt',
        cipher: 'aes-256-gcm',
        kdfparams: { n: KDF_N, r: SCRYPT_R, p: SCRYPT_P, salt: toHex(salt) },
        cipherparams: { iv: toHex(iv) },
        ciphertext: toHex(sealed),
      },
      null,
      2,
    ) + '\n'
  )
}

/** Open an envelope produced by `sealSecret`. Wrong password or a tampered body
 *  surfaces as `session_invalid` — never a raw crypto error. */
export async function openSecret(envelope: string, password: string): Promise<string> {
  let obj: { version?: unknown; kdf?: unknown; cipher?: unknown; kdfparams?: unknown; cipherparams?: unknown; ciphertext?: unknown }
  try {
    obj = JSON.parse(envelope) as typeof obj
  } catch (err) {
    throw new ConnectxError('session_invalid', 'Stored session is not valid JSON', { cause: err })
  }
  if (obj.version !== 1) throw new ConnectxError('session_invalid', `Unsupported session envelope version: ${String(obj.version)}`)
  if (obj.kdf !== 'scrypt') throw new ConnectxError('session_invalid', `Unsupported session kdf: ${String(obj.kdf)}`)
  if (obj.cipher !== 'aes-256-gcm') throw new ConnectxError('session_invalid', `Unsupported session cipher: ${String(obj.cipher)}`)

  const p = (obj.kdfparams ?? {}) as Record<string, unknown>
  if ((p.dklen ?? DKLEN) !== DKLEN) {
    throw new ConnectxError('session_invalid', `Unsupported session dklen: ${String(p.dklen)} (expected ${DKLEN})`)
  }
  const N = assertInt(p.n, 'n', 2, MAX_N)
  if ((N & (N - 1)) !== 0) throw new ConnectxError('session_invalid', `Session scrypt n must be a power of two, got ${N}`)
  const r = assertInt(p.r, 'r', 1, MAX_R)
  const pCost = assertInt(p.p, 'p', 1, MAX_P)

  const salt = fromHex(p.salt, 'salt')
  assertBytes(salt, 'salt', 1, MAX_SALT_BYTES)
  const iv = fromHex((obj.cipherparams as Record<string, unknown> | undefined)?.iv, 'iv')
  assertBytes(iv, 'iv', IV_BYTES, IV_BYTES)
  const sealed = fromHex(obj.ciphertext, 'ciphertext')
  assertBytes(sealed, 'ciphertext', TAG_BYTES, MAX_CIPHERTEXT_BYTES)

  const dk = await nobleScrypt(password, salt, { N, r, p: pCost, dkLen: DKLEN })

  const decipher = createDecipheriv('aes-256-gcm', dk, iv)
  decipher.setAuthTag(sealed.subarray(sealed.length - TAG_BYTES))
  try {
    const body = Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - TAG_BYTES)), decipher.final()])
    return body.toString('utf8')
  } catch (err) {
    throw new ConnectxError(
      'session_invalid',
      'Stored session failed authentication (wrong CONNECTX_KEY_PASSWORD or tampered file)',
      { cause: err },
    )
  }
}
