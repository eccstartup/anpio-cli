// Isomorphic byte helpers for the ANP-02 SDK. Works in the browser and in Node
// 18+ without depending on platform-specific globals at import time.

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js'

export function utf8(text: string): Uint8Array {
  return new TextEncoder().encode(text)
}

export function utf8From(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

// SHA-256 via @noble/hashes (pure JS) — no `crypto.subtle`, so it needs no Node
// flag and is identical on every runtime. Kept async for API stability (callers
// `await` it); noble's sha256 is synchronous underneath.
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return nobleSha256(bytes)
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64')
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

// URL-safe base64 with no padding — the alphabet JWK members and ANP fingerprints
// use (`-`/`_`, no `=`). `base64ToBytes` accepts it back (see `normalizeBase64`).
export function base64UrlNoPad(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// JWK coordinates and other DID-document fields use the URL-safe base64 alphabet
// (`-` / `_`, possibly unpadded), while RFC 9421 signature labels use standard
// base64. `atob` (browser) and strict decoders reject the URL-safe alphabet, so
// normalize it to the standard form before decoding. Standard base64 has no `-`
// or `_`, so this is a no-op for well-formed standard input.
function normalizeBase64(s: string): string {
  let out = s.replace(/-/g, '+').replace(/_/g, '/')
  const remainder = out.length % 4
  if (remainder > 0) out += '='.repeat(4 - remainder)
  return out
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = normalizeBase64(b64)
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(normalized, 'base64'))
  const bin = atob(normalized)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** The inverse of {@link base64UrlNoPad}: URL-safe, padding optional. */
export function base64UrlToBytes(s: string): Uint8Array {
  return base64ToBytes(s)
}
