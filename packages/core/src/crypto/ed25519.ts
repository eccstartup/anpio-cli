// Ed25519 key material derivations.
//
// The SDK's own identities are built by `createAnpIdentity` / `buildWalletIdentity`,
// which mint a key and derive its public half in one step. A caller that has to HOLD a
// private key across restarts — the service's per-group key (B1b-A1) is stored in a
// database column — needs the second half of that on its own: read the key back, derive
// the public key, write it into the document.
//
// Only the derivation lives here. Signing goes through `signDidDocumentProofSync` /
// `ed25519OriginProofSigner`, and parsing through `parsePrivateKey`, so there is exactly
// one place per operation rather than a fourth wrapper around @noble.

import { ed25519 } from '@noble/curves/ed25519.js'
import { ConnectxError } from '../errors'

/** The public key of a 32-byte Ed25519 private key (seed).
 *
 *  The length is checked here rather than left to @noble: a key read back from storage, a
 *  file or a keystore is an input boundary, and "Expected a 32-byte private key, got 0"
 *  is a better failure than whatever the curve library says about a zero-length seed.
 */
export function ed25519PublicKey(privateKey: Uint8Array): Uint8Array {
  if (privateKey.length !== 32) {
    throw new ConnectxError('key_invalid', `Expected a 32-byte Ed25519 private key, got ${privateKey.length}`)
  }
  return ed25519.getPublicKey(privateKey)
}
