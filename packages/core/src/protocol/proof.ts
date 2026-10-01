import type { AnpIdentity, AnpSigningIdentity, SignRequest, SignResult } from '../types'
import type { IWallet } from '../wallet/wallet'
import type { NonceStore } from '../crypto/verify'
import type { DidDocumentServices } from '../crypto/didDocument'

// Proof abstraction — the chain-agnostic core of the SDK.
//
// A wallet (ANP native, browser extension, web3, agent CLI) signs a login
// request; the SIGNED FORM is a `Proof`. The server verifies a `Proof` without
// knowing which wallet produced it. This is how "ANP composes with web3
// wallets": a chain adapter frames any `{ publicKey, privateKey, signature }`
// into a Proof a server can check.
export interface Proof {
  kind: string
  /** The signed HTTP request, reconstructed by the server from the raw request. */
  method: string
  path: string
  targetUri?: string
  authority: string
  /** Lowercase header name → raw value (signature-input, signature, content-digest, ...). */
  headers: Record<string, string>
  body: string
  /** DID document (inlined) so the server can resolve the key without a .well-known host. */
  didDocument?: Record<string, unknown>
}

export interface BuildProofInput {
  method: string
  path: string
  authority: string
  targetUri?: string
  body: string
  /** A signing identity (carries the private key that signs). */
  identity: AnpSigningIdentity
  /** Optional handle to claim. Forwarded into the signed body (registration). */
  handle?: string
  /** Endpoint-specific members to bind under the content-digest (`SignRequest.extraBody`).
   *  An adapter that cannot place them must refuse before sending — the request would
   *  otherwise reach the endpoint without a member its contract requires. */
  extraBody?: Record<string, unknown>
}

// A "prover" turns a signing context into a Proof and can verify it back.
// The ANP implementation signs an RFC 9421 HTTP Message Signature.
export interface ProofAdapter {
  kind: string
  /** Given the signing context, produce the headers the signed request must carry. */
  sign(
    input: BuildProofInput & { nonce: string },
  ): Promise<{ body: string; headers: Record<string, string> }>
  /**
   * Verify a proof against the resolved key.
   *
   * SECURITY: `ProofAdapter.verify` is fail-closed against replay — it REQUIRES
   * `expectedNonce` (the server-issued challenge the proof must be bound to) AND a
   * `nonceStore` that atomically consumes it. Verification success proves integrity
   * + freshness AND one-time use. A call that omits either throws `invalid_argument`:
   * a stateless, replayable check must go through the low-level
   * `verifyHttpMessageSignature` (kept intentionally stateless for that purpose) — it
   * is never the security boundary for a server that authenticates on a success.
   */
  verify(
    input: Proof & {
      key: { curve: 'ed25519' | 'secp256k1'; bytes: Uint8Array }
      /** Bind the proof to the server-issued challenge nonce. REQUIRED. */
      expectedNonce: string
      /** One-time consume, called only after the proof otherwise verifies. REQUIRED. */
      nonceStore: NonceStore
    },
  ): Promise<boolean>
}

// Optional CAIP-10 identity descriptor. When present, the DID is the CAIP-10
// account id `chain_id:address` (e.g. `eip155:1:0x…`, `cosmos:cosmoshub-3:cosmos1…`)
// instead of `did:wba:…`. The host still serves as the DID document's controller.
// Any chain works — the SDK only requires sign+verify.
export interface IdentityDescriptor {
  /** CAIP-2 chain id, e.g. `eip155:1`. Required to build a CAIP-10 account id. */
  chainId?: string
  /** Wallet address on that chain, e.g. `0x…` / `cosmos1…`. */
  address?: string
  /** Path segments for the ANP path-type `did:wba` identity, before the key
   *  fingerprint (defaults to `['user','default']`). Ignored in CAIP-10 mode. The
   *  CLI passes `['user', agentId]` so two agents on one host get distinct DIDs. */
  path?: string[]
  /** Services to publish in the built DID document (ANP-03 §service). Signed into
   *  the document — see `DidDocumentServices`. */
  service?: DidDocumentServices
  /** The DID document to use **as the DID server has it on file**, instead of one
   *  composed from the key. Pass this when the document on file may carry fields the
   *  builder does not produce — a `service` endpoint, extra verification keys, a
   *  revoked key (ANP-03 §2.5.3 L411 allows any of these without changing the DID).
   *
   *  It matters because an update hop's retirement document MUST be **that** document
   *  plus `deactivated` + `successorDid` (§2.5.3 L417), with the proof re-made over
   *  every property it carries (L419). Composing a fresh base instead silently
   *  produces a retirement document that differs from the one on file.
   *
   *  Used verbatim, `proof` included: this is the published document, so the SDK does
   *  not re-author it. Its `id` MUST equal the DID derived from the key + host, else
   *  the build throws `invalid_argument` — the DID embeds the e1_ key fingerprint, so
   *  a document for another key cannot match. Mutually exclusive with `service`.
   *
   *  Only the seam. The SDK has no store, so it neither obtains nor keeps such a
   *  document: where one is read from, when it is refreshed and when it is passed
   *  here are the caller's decisions. A consumer holding this option is not evidence
   *  that anyone records a copy. */
  baseDocument?: Record<string, unknown>
}

// A wallet connector that can produce a Proof — the bridge between `IWallet`
// (chain-agnostic key material) and `ProofAdapter` (protocol framing). This is
// what the connectors use to turn `signRequest()` into an ANP-verifiable proof.
export interface WalletProver {
  /** Build the DID document for a wallet's public key, for a given host.
   *  A CAIP-10 descriptor (chainId + address) makes the DID the account id. */
  buildIdentity(wallet: IWallet, host: string, descriptor?: IdentityDescriptor): Promise<AnpIdentity>
  /** Sign an ANP-02 login request with the wallet's key. */
  signRequest(wallet: IWallet, identity: AnpIdentity, req: SignRequest): Promise<SignResult>
}
