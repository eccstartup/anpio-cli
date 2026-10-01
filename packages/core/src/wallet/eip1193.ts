import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { createEventEmitter } from '../events'
import type { EventEmitter } from '../events'
import { ConnectxError } from '../errors'
import type { IWallet } from './wallet'

// Ethereum provider as a chain-agnostic `IWallet`. Most wallets (MetaMask,
// OKX, Link, ...) expose a `window.ethereum`-style provider with EIP-1193
// `request({ method })`. This adapter translates EIP-191 `personal_sign` into
// the SDK's generic `{ publicKey, privateKey, signature }` world:
//   - `getPublicKey()` recovers the secp256k1 public key from an address-backed
//     signature (the wallet gives us an address, not a raw pubkey).
//   - `signMessage()` calls `personal_sign` and returns the 65-byte recoverable
//     signature `r || s || v` (Ethereum convention).
//
// It exercises the "ANP compatible with arbitrary chain wallets" path: a web3
// signature gets framed into an ANP-verifiable proof by the protocol adapter.

export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] | Record<string, unknown> }): Promise<unknown>
  /** EIP-1193 event subscription (present on MetaMask/OKX-style providers). */
  on?(event: string, listener: (...args: unknown[]) => void): void
  removeListener?(event: string, listener: (...args: unknown[]) => void): void
}

export interface ChainWalletOptions {
  /**
   * The wallet's CURRENT chain, as reported by EIP-1193 `eth_chainId` — hex
   * (`0x1`), decimal (`1`), or CAIP-2 (`eip155:1`) all work; the DID builder
   * normalizes to CAIP-2. It is tracked live: `chainChanged` events update it,
   * and it is authoritative for the CAIP-10 DID. Only used as the initial value.
   */
  chainId?: string
  /**
   * The wallet's address. Required because personal_sign-based providers expose
   * an address, not a raw public key — we recover the pubkey from a signature.
   */
  address: string
}

const PERSONAL_SIGN_PREFIX = '\x19Ethereum Signed Message:\n'

/**
 * Build the exact payload Ethereum's `personal_sign` hashes: prefix + length + message.
 * This matches what a browser wallet signs and returns a signature over.
 */
export function ethPersonalSignHash(message: Uint8Array): Uint8Array {
  const prefix = new TextEncoder().encode(PERSONAL_SIGN_PREFIX + message.length)
  const total = new Uint8Array(prefix.length + message.length)
  total.set(prefix, 0)
  total.set(message, prefix.length)
  return keccak_256(total)
}

/**
 * Recover the secp256k1 public key from a 65-byte Ethereum signature `r||s||v`.
 * Returns the compressed 33-byte point (the form a `k1_` DID's fingerprint is
 * computed over).
 */
export function recoverEthPublicKey(message: Uint8Array, sig65: Uint8Array): Uint8Array {
  if (sig65.length !== 65) throw new ConnectxError('signature_invalid', `Expected 65-byte Ethereum signature, got ${sig65.length}`)
  const hash = ethPersonalSignHash(message)
  const r = sig65.slice(0, 32)
  const s = sig65.slice(32, 64)
  const v = sig65[64]
  const recovery = v >= 27 ? v - 27 : v
  const sig = new Uint8Array(64)
  sig.set(r, 0)
  sig.set(s, 32)
  const point = secp256k1.Signature.fromBytes(sig)
    .addRecoveryBit(recovery)
    .recoverPublicKey(hash)
  return point.toBytes(true) // compressed 33 bytes
}

// Derive the lower-case (no EIP-55 checksum) Ethereum address for a secp256k1
// public key: keccak256(x || y) of the uncompressed point, last 20 bytes. This is
// the address a wallet's account is derived from, so it binds a recovered key to
// the account it actually belongs to.
export function ethAddressFromPublicKey(pub: Uint8Array): string {
  const uncompressed = secp256k1.Point.fromBytes(pub).toBytes(false) // 0x04 || x || y
  const hash = keccak_256(uncompressed.slice(1))
  const addr = hash.slice(-20)
  return '0x' + Array.from(addr).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export function chainWallet(provider: Eip1193Provider, opts: ChainWalletOptions): IWallet {
  // Recover the pubkey once and cache it: personal_sign-based providers expose an
  // address, not a raw pubkey, so the first `getPublicKey()` signs a probe and
  // recovers the key. Caching avoids re-prompting the user on every getIdentity().
  //
  // The address and chain are tracked live, NOT frozen at construction: a browser
  // wallet can switch accounts or chains under us, and reusing the old address (or
  // the cached pubkey recovered for it) would mis-describe the identity. On any
  // account/chain change the cache is invalidated so the next getPublicKey()
  // re-recovers the key for the CURRENT account. If the wallet reports no accounts
  // (locked/disconnected) the address is cleared and signing throws.
  let currentAddress: string | undefined = opts.address
  let currentChainId: string | undefined = opts.chainId
  // Monotonic generation, bumped on EVERY account/chain/disconnect change. An
  // in-flight `personal_sign` snapshots it at start; if the snapshot no longer
  // matches when the signature returns (the wallet switched account/chain while we
  // waited), the result is discarded rather than cached under the wrong account.
  let generation = 0
  let cachedPub: Uint8Array | null = null

  // Bridge the provider's EIP-1193 events into a framework-agnostic emitter.
  const events: EventEmitter = createEventEmitter()
  if (provider.on) {
    const onAccounts = (...args: unknown[]) => {
      const accounts = args[0] as string[] | undefined
      // EIP-1193: the FIRST entry is the currently-selected active account; later
      // entries are the other accounts the wallet holds. Selecting the last entry
      // could attribute a signature to a non-active account (identity mismatch).
      currentAddress = Array.isArray(accounts) && accounts.length > 0 ? accounts[0] : undefined
      cachedPub = null
      generation++
      events.emit({ type: 'accountsChanged', payload: args[0] })
    }
    const onChain = (...args: unknown[]) => {
      const chain = args[0]
      if (typeof chain === 'string') currentChainId = chain
      cachedPub = null
      generation++
      events.emit({ type: 'chainChanged', payload: args[0] })
    }
    const onDisconnect = (...args: unknown[]) => {
      currentAddress = undefined
      cachedPub = null
      generation++
      events.emit({ type: 'disconnect', payload: args[0] })
    }
    provider.on('accountsChanged', onAccounts)
    provider.on('chainChanged', onChain)
    provider.on('disconnect', onDisconnect)
  }

  return {
    curve: () => 'secp256k1',
    events,
    async getAccount() {
      return { address: currentAddress, chainId: currentChainId }
    },
    async getPublicKey(): Promise<Uint8Array> {
      if (cachedPub) return cachedPub
      // Snapshot the account + generation BEFORE the async probe. The provider may
      // switch accounts while `personal_sign` is awaited; if it does, the recovered
      // key belongs to a superseded account and must NOT be cached for the new one.
      const address = requireAddress(currentAddress)
      const gen = generation
      const probe = new TextEncoder().encode('connectx:key-recovery')
      const sig = await provider.request({ method: 'personal_sign', params: [toHex(probe), address] })
      if (gen !== generation || (currentAddress ?? '').toLowerCase() !== address.toLowerCase()) {
        throw new ConnectxError('wallet_account_changed', 'Account changed during signing; retry')
      }
      const pub = recoverEthPublicKey(probe, fromHex(sig as string))
      // Bind the recovered key to the account: the wallet's address is derived from
      // its public key, so a mismatch means the provider signed with a DIFFERENT
      // account (or a tampering proxy) than the one it reported. Reject rather than
      // cache a key that would build a DID for account A whose document key belongs
      // to account B — the server would then see an inconsistent identity binding.
      if (ethAddressFromPublicKey(pub).toLowerCase() !== address.toLowerCase()) {
        throw new ConnectxError('wallet_account_mismatch', 'Recovered public key does not match the wallet address')
      }
      cachedPub = pub
      return cachedPub
    },
    async signMessage(message: Uint8Array): Promise<Uint8Array> {
      const address = requireAddress(currentAddress)
      const gen = generation
      const sig = await provider.request({ method: 'personal_sign', params: [toHex(message), address] })
      // If the account switched while we waited for the signature, the recovered
      // key is for a different account — reject rather than attribute it here.
      if (gen !== generation) {
        throw new ConnectxError('wallet_account_changed', 'Account changed during signing; retry')
      }
      const bytes = fromHex(sig as string)
      // A provider may silently switch the actual signing account after the pubkey
      // was cached, or ignore the `address` in personal_sign. Recover and bind here
      // so a signature produced by a different account is rejected instead of being
      // attributed to the cached identity.
      const recovered = recoverEthPublicKey(message, bytes)
      if (ethAddressFromPublicKey(recovered).toLowerCase() !== address.toLowerCase()) {
        throw new ConnectxError('wallet_account_mismatch', 'Signature was produced by a different account')
      }
      return bytes
    },
  }
}

// The wallet must have a known account to sign with. After a lock/disconnect the
// address is cleared and signing fails loudly rather than silently using a stale
// account.
function requireAddress(address: string | undefined): string {
  if (!address) throw new ConnectxError('connector_unavailable', 'Wallet is not connected (no active account)')
  return address
}

function toHex(bytes: Uint8Array): string {
  return '0x' + Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function fromHex(hex: string): Uint8Array {
  const h = hex.replace(/^0x/i, '')
  if (h.length % 2 !== 0) throw new ConnectxError('signature_invalid', 'Odd-length hex')
  if (!/^[0-9a-fA-F]+$/.test(h)) throw new ConnectxError('signature_invalid', 'Invalid hex characters')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}
