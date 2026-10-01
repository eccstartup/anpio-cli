import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { cryptoWalletProver, buildWalletIdentity } from '../anp'
import type { AnpConnector, AnpIdentity, SignRequest, SignResult } from '../../types'
import type { IWallet } from '../../wallet/wallet'
import type { WalletProver } from '../proof'

// Chain-agnostic proof adapter — the "ANP composes with arbitrary-chain wallets"
// bridge. A web3 / CLI / any-chain wallet exposes `{ publicKey, privateKey,
// signature }`; this module frames that into a normal ANP-02 proof and verifies
// it. The server never needs to know the key belonged to an EVM wallet, a CLI
// key file, or an ANP-native identity.

export interface ChainWalletConnectorOptions {
  /** Host used to derive the path-type `did:wba` identity and the inline DID document. */
  host: string
  /** Optional prover override; defaults to the official ANP-02 prover. */
  prover?: WalletProver
  /**
   * Optional chain label (CAIP-2 `chain_id`, e.g. `eip155:1`) and the wallet's
   * address on that chain. Together they form the CAIP-10 account id used AS the
   * DID. Any chain works — the SDK stays chain-agnostic, only sign+verify matter.
   *
   * These are STATIC fallbacks. When the wrapped wallet implements `getAccount()`
   * (as `chainWallet` does), its LIVE account/chain — refreshed on
   * `accountsChanged`/`chainChanged` — always wins over these values. Supply
   * `chainId`/`address` here only for wallets with a fixed, non-live key (e.g.
   * `keypairWallet`), or to seed a `chainWallet` before its first connect.
   */
  chainId?: string
  address?: string
  /** Path segments for the path-type `did:wba` DID before the key fingerprint
   *  (defaults to `['user','default']`). Ignored in CAIP-10 mode. */
  path?: string[]
  /**
   * Connector id. Defaults to `'chain'`. Override it when you configure two
   * chain wallets (e.g. EVM + Solana) — ids must be unique within a config.
   */
  id?: string
}

// Wrap an `IWallet` (public key + signature) as a uniform `AnpConnector`. The
// connector produces the SAME proof shape as an ANP-native identity, so an agent
// does `login()` identically whether it selected this or the dev shim.
export function chainWalletConnector(
  wallet: IWallet,
  opts: ChainWalletConnectorOptions,
): AnpConnector {
  const prover = opts.prover ?? cryptoWalletProver()
  const identityDescriptor = { chainId: opts.chainId, address: opts.address, path: opts.path }
  return {
    id: opts.id ?? 'chain',
    name: 'Chain wallet',
    type: 'chain',
    isAvailable: () => Promise.resolve(true),
    events: wallet.events,
    async getIdentity(): Promise<AnpIdentity> {
      return prover.buildIdentity(wallet, opts.host, identityDescriptor)
    },
    async signRequest(req: SignRequest): Promise<SignResult> {
      const identity = await prover.buildIdentity(wallet, opts.host, identityDescriptor)
      return prover.signRequest(wallet, identity, req)
    },
  }
}

// ---- Agent-side local key wallet ---------------------------------------------
// Holds a raw keypair (`publicKey + privateKey`) directly — the classic
// "public + private key" combination an agent's CLI key file has. This is what a
// future `anpCli` / anp-key connector wraps. The wallet signs with the curve's
// native scheme; the prover frames it as an ANP-02 proof.

export interface KeypairWalletOptions {
  curve?: 'ed25519' | 'secp256k1'
}

export function keypairWallet(privateKey: Uint8Array, opts: KeypairWalletOptions = {}): IWallet {
  const curve = opts.curve ?? 'ed25519'
  const publicKey =
    curve === 'ed25519'
      ? ed25519.getPublicKey(privateKey)
      : secp256k1.getPublicKey(privateKey, true)

  return {
    curve: () => curve,
    async getPublicKey(): Promise<Uint8Array> {
      return publicKey
    },
    async getKeypair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
      return { publicKey, privateKey }
    },
    async signMessage(message: Uint8Array): Promise<Uint8Array> {
      if (curve === 'ed25519') return ed25519.sign(message, privateKey)
      return secp256k1.sign(message, privateKey)
    },
  }
}

// Convenience: derive the DID document for an `IWallet` without building a full
// connector — useful for previewing an identity or resolving a key.
export { buildWalletIdentity }
export type { AnpIdentity }
