// CLI key loading — the agent-side input boundary. `--key <spec>` accepts raw
// material (hex / mnemonic / PEM / keystore V3) or a reference to it:
//   file:<path>   read the file
//   env:<VAR>     read an environment variable
//   <raw>         the key material itself (auto-detected)
//   <path>        a bare path, if it names an existing file
//
// This is the ONLY place the CLI touches a private key. It parses to a
// `{ privateKey, curve }` pair and hands it to `keypairWallet` (via `anpCli`).
// Web3 mode (`--wallet web3`) never routes through here — the private key stays
// in the wallet.

import { readFileSync, existsSync } from 'node:fs'
import {
  parsePrivateKey,
  parseMnemonic,
  parsePem,
  parseKeystore,
} from '@agentx/core'
import type { ParsedKey, ParsedKeyCurve } from '@agentx/core'

export interface LoadKeyOptions {
  /** Password for a keystore V3 JSON. */
  password?: string
  /** BIP-44 derivation path for a secp256k1 mnemonic (default EVM `m/44'/60'/0'/0/0`). */
  bip39Path?: string
  /** Curve for opaque formats (hex / PEM); defaults to ed25519. */
  curve?: ParsedKeyCurve
}

export type KeyFormat = 'hex' | 'mnemonic' | 'pem' | 'keystore'

const HEX_KEY = /^(0x)?[0-9a-fA-F]{64}$/
const MNEMONIC_LENGTHS = new Set([12, 15, 18, 21, 24])

/** Detect the key format from raw material. */
export function detectFormat(raw: string): KeyFormat {
  const s = raw.trim()
  if (s.startsWith('-----BEGIN')) return 'pem'
  if (s.startsWith('{')) {
    try {
      if ((JSON.parse(s) as { crypto?: unknown }).crypto) return 'keystore'
    } catch {
      /* not JSON — fall through */
    }
  }
  if (HEX_KEY.test(s)) return 'hex'
  const words = s.split(/\s+/)
  if (MNEMONIC_LENGTHS.has(words.length) && words.every((w) => /^[a-z]+$/i.test(w))) return 'mnemonic'
  // A mnemonic can also be a single, whitespace-free string we failed to split.
  throw new Error('Unrecognized key format (expected hex, BIP-39 mnemonic, PEM, or keystore V3)')
}

/** Parse raw key material into the SDK's `{ privateKey, curve }` pair. */
export async function loadKeyMaterial(raw: string, opts: LoadKeyOptions = {}): Promise<ParsedKey> {
  switch (detectFormat(raw)) {
    case 'hex':
      return parsePrivateKey(raw, opts.curve ?? 'ed25519')
    case 'mnemonic':
      return parseMnemonic(raw.trim().toLowerCase(), opts.curve ?? 'ed25519', opts.bip39Path)
    case 'pem':
      return parsePem(raw, opts.curve ?? 'ed25519')
    case 'keystore':
      return parseKeystore(raw, opts.password ?? '')
  }
}

/** Resolve `--key` to raw material (handles file:/env:/bare-path/raw). */
export function readKeyArg(spec: string): string {
  if (spec.startsWith('file:')) return readFileSync(spec.slice(5), 'utf8')
  if (spec.startsWith('env:')) {
    const name = spec.slice(4)
    const v = process.env[name]
    if (v === undefined) throw new Error(`Environment variable "${name}" is not set`)
    return v
  }
  // Already raw material (hex / mnemonic / PEM / keystore) → use as-is.
  const trimmed = spec.trim()
  if (
    HEX_KEY.test(trimmed) ||
    trimmed.startsWith('-----BEGIN') ||
    trimmed.startsWith('{') ||
    MNEMONIC_LENGTHS.has(trimmed.split(/\s+/).length)
  ) {
    return trimmed
  }
  // A bare file path.
  if (existsSync(trimmed)) return readFileSync(trimmed, 'utf8')
  throw new Error(`Cannot resolve --key: "${spec}" (not raw material or an existing file)`)
}
