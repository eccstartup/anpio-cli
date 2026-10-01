// Chain-agnostic wallet interface. This is the seam the SDK uses to talk to ANY
// wallet — an ANP-native identity, a browser extension, OKX/Link, or an agent's
// local CLI key. The only requirement is the classic **public key + private key +
// signature** combination; the SDK never cares which chain the key belongs to.
//
// A browser wallet will typically implement `getPublicKey` + `signMessage` and not
// expose its private key. An agent's local CLI wallet implements `getKeypair`
// (and thus can derive the public key itself).

import type { EventEmitter } from '../events'

export interface IWallet {
  /** The wallet's public key (curve-agnostic raw bytes). */
  getPublicKey(): Promise<Uint8Array>
  /** Sign an arbitrary message; returns the raw signature bytes. */
  signMessage(message: Uint8Array): Promise<Uint8Array>
  /**
   * Optional: expose the full keypair for wallets that hold the private key
   * locally (e.g. an agent's CLI key file). Browser wallets that never expose
   * the secret simply omit this.
   */
  getKeypair?(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>
  /**
   * Optional: the curve. Defaults to 'ed25519'. Needed when the SDK must frame
   * the public key into a DID document (e.g. secp256k1 uses a different prefix).
   */
  curve?(): 'ed25519' | 'secp256k1'
  /**
   * Optional event source: `accountsChanged` / `chainChanged` / `disconnect`.
   * Browser wallets bridge their provider's events through this.
   */
  events?: EventEmitter
  /**
   * Optional: the wallet's current account/chain, if it is account-addressable
   * (e.g. a browser wallet that can switch accounts/chains). When present the SDK
   * prefers these live values over any static connector descriptor, so a CAIP-10
   * DID stays consistent with the account that actually signs after a switch.
   * Wallets with a fixed local key (e.g. a CLI keypair) omit this.
   */
  getAccount?(): Promise<{ address?: string; chainId?: string } | undefined>
}
