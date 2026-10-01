// Shared types for the ANP SDK. This is the chain-agnostic, agent-first surface:
// a wallet configuration (connector) exposes one uniform operation, so an agent
// (programmatic client) does the same thing whether it selected an ANP-native
// identity, a browser extension, or an EIP-1193 web3 wallet.

import type { EventEmitter } from './events'
import type { SubjectId } from './identity'
import type { DidPublicKey } from './crypto/didDocument'
import type { DidChain, DidChainOptions } from './did/chain'
export { ConnectorUnavailableError } from './errors'

export type WalletType =
  // ANP-native identities
  | 'anp-extension'
  | 'anp-dev-shim'
  | 'anp-cli'
  // Arbitrary chain wallets (via the protocol adapter layer)
  | 'ethereum'
  | 'evm'
  | 'solana'
  | 'chain'

// Connection lifecycle states, plus the signing/error states used during login.
//   idle → connecting → connected → disconnecting → idle
// `signing` is set during `login()`/`signRequest()`; `error` holds a failure.
export type AnpStatus = 'idle' | 'connecting' | 'connected' | 'disconnecting' | 'signing' | 'error'

/**
 * An agent's identity, in TWO layers (ADR-0002 §2.2):
 *
 *   subject  stable — it does NOT change when the key updates. Use it to address,
 *            store and attribute the agent (`subjectOf(did)` derives it).
 *   did      the current credential — it DOES change on update. This is what
 *            signs and what a verifier resolves, so it is never replaced by the
 *            subject on the wire.
 *
 * Dropping `did` in favour of `subject` would break signing; dropping `subject`
 * would lose the agent's identity at the first update. Keep both.
 *
 * The binding key is carried as {@link DidPublicKey} — the identity holds the key in
 * whichever representation its profile PUBLISHES, so what a caller sees here is what
 * the DID document says. A `k1_` identity therefore has `publicKey.publicKeyJwk`, not
 * a secp256k1 `publicKeyMultibase` (a shape the spec does not define; see that type).
 * Consumers that only pass the key along never touch the union; ones that read the
 * representation narrow on which member is present.
 */
export interface AnpIdentity {
  /** Stable agent identity, e.g. `did:wba:example.com:user:alice` (the DID minus
   *  its fingerprint) or a CAIP-10 id like `eip155:1:0x…`. */
  subject: SubjectId
  /** Current DID credential (carries the key fingerprint) — signs and verifies. */
  did: string
  keyid: string
  publicKey: DidPublicKey
  didDocument: Record<string, unknown>
}

// The internal signing identity: holds the private key alongside the public
// `AnpIdentity` fields. Used by ANP-native connectors (shim/dev) that generate
// and hold a key; never exposed to a page.
export interface AnpSigningIdentity extends AnpIdentity {
  priv: Uint8Array
}

export interface SignRequest {
  /** Full target URL the signed request is actually POSTed to (== server-reconstructed req.url). */
  url: string
  method: string
  /** Server-issued one-time nonce (from /nonce or a 401 WWW-Authenticate challenge). */
  nonce: string
  /** Optional handle to claim (registration only). When present it is embedded in
   *  the signed body so the content-digest binds the caller's desired handle. It is a
   *  name on the DID server being registered with — see `RegisterOptions.handle`. */
  handle?: string
  /**
   * Retire THIS DID in favour of `successorDid` — the update delivery (see `update`).
   *
   * When present the prover adds the half of the exchange an ordinary login body
   * cannot carry: it builds the RETIREMENT document (this identity's own document,
   * marked `deactivated: true` with `successorDid`) and re-signs it with the RETIRING
   * key. The proof has to be re-made rather than carried over — ANP-03 §2.5.5 defines
   * the top-level proof as covering the whole document minus the proof itself, so the
   * old proof would say nothing about the two fields that authorise the hop, leaving
   * `deactivated` / `successorDid` the only unauthenticated fields in a document that
   * otherwise proves itself. The successor then travels alongside in the same request,
   * because one hop IS the pair (§2.5.3 L415–420).
   */
  successorDid?: string
  /** The successor's ACTIVE document, signed by the successor's OWN key (§2.5.3 L419:
   *  新 DID Document 由新绑定密钥生成整体 `proof`).
   *  Required with `successorDid`: neither half of the hop means anything alone. */
  successorDocument?: Record<string, unknown>
  /**
   * Additional top-level members for the signed body, under the names the WIRE uses.
   *
   * This is how an endpoint contract that carries MORE than a login gets its fields
   * bound: a connector builds the body itself, so a field the caller merely holds would
   * never be in the bytes the content-digest covers — and a field outside the digest is
   * a field a proxy may edit. The names are the endpoint's, exactly as `handle` is the
   * registration endpoint's.
   *
   * The six members ANP-02 names itself (`nonce` / `did` / `didDocument` / `handle` and
   * the `successorDid` / `successorDocument` pair) are NOT settable here: each is a fact
   * the proof is about, so a request carrying one is refused rather than resolved either
   * way (`RESERVED_BODY_FIELDS`). Use the field that exists for it — `handle`,
   * `successorDid` — and only the ENDPOINT's own names go in `extraBody`.
   *
   * A connector that cannot place caller-supplied members — a browser extension whose
   * wallet builds the body — is not a connector this field works with, and says so:
   * the request is refused before anything is sent, rather than posted with the field
   * quietly missing.
   */
  extraBody?: Record<string, unknown>
}

export interface SignResult {
  did: string
  keyid: string
  didDocument: Record<string, unknown>
  /** The authoritative body to POST — the wallet may have re-signed. */
  body: string
  /** Merge these (plus `content-type: application/json`) into the outgoing POST. */
  headers: Record<string, string>
}

export interface LoginOutcome {
  /** Stable agent identity — unchanged by a key update (see `AnpIdentity`). */
  subject: SubjectId
  did: string
  /** The login protocol method. The SDK implements ANP-02 authentication (with
   *  the `did:wba` method binding), so this is always `'anp'`. */
  method: 'anp'
  /** The wallet type that produced the proof (e.g. `'anp-dev-shim'`, `'chain'`). */
  walletType: WalletType
  address?: string
  chainId?: string
  docUrl?: string
  /** Bearer/access token if the server returned one in Authentication-Info or body. */
  token?: string
  /**
   * The `token_type` the server named for that token, verbatim (ANP-02 §3.2.3).
   *
   * It is NOT decoration. §3.2.3 says a client must send a token whose type is not
   * `Bearer` "按照对应扩展规范" — i.e. the value selects how the token has to be
   * presented (a sender-constrained profile binds it to the key, so replaying it as
   * a plain Bearer token is not the same request). An ABSENT `token_type` may be
   * treated as `Bearer` for compatibility, which is what this SDK has always done;
   * any other value does NOT get that default, because the profile it names is the
   * one that says what to do.
   *
   * Recorded rather than acted on: this SDK never sends an access token, so nothing
   * here needs to branch on it yet. What matters is that the value stops being
   * discarded — a caller that DOES send the token can no longer be ignorant of a
   * type the server stated, and neither can a session record that keeps it.
   */
  tokenType?: string
}

// A wallet configuration. Everything about how a wallet signs is sealed inside a
// connector; the caller only ever sees `getIdentity()` and `signRequest()`.
export interface AnpConnector {
  id: string
  name: string
  type: WalletType
  /** Feature-detect: is this wallet actually present/usable right now? */
  isAvailable(): Promise<boolean>
  /** Read-only identity (DID + inline DID document). Never forces a prompt on its own. */
  getIdentity(): Promise<AnpIdentity>
  /** Sign an ANP-02 login request; returns the RFC 9421 headers to attach. Pure, no network. */
  signRequest(req: SignRequest): Promise<SignResult>
  /**
   * Optional event source: `accountsChanged` / `chainChanged` / `disconnect`.
   * Wallet-backed connectors expose the provider's events through this.
   */
  events?: EventEmitter
}

export interface AnpConfig {
  connectors: AnpConnector[]
  defaultConnectorId?: string
}

/** A signed ANP-02 request, ready to be put on the wire: `body` / `headers` are what
 *  the connector produced (the flat ANP-02 body and the RFC 9421 signature headers),
 *  and `sig` is the proof itself, for an envelope that has to reference it. */
export interface SignedRequest {
  /** The URL the caller named — the endpoint, which is the server's own contract. */
  url: string
  method: string
  body: string
  headers: Record<string, string>
  sig: SignResult
}

/** The request actually sent. Every part of it is the envelope's to decide. */
export interface EnvelopeRequest {
  url: string
  /** Defaults to `POST`. */
  method?: string
  /** Defaults to `{}` — which means an envelope that frames the body itself must
   *  supply its own `content-type`. */
  headers?: Record<string, string>
  body: string
}

/**
 * How a signed ANP-02 request becomes the bytes on the wire.
 *
 * The ANP documents define WHAT a request proves (the signature, the documents, the
 * content-digest) and deliberately leave the ENDPOINT and the ENVELOPE to the
 * implementation: ANP-03 §2.5.1 / §2.5.3 say the programmatic registration and
 * management interface "不由本规范定义", and note that a deployment may manage DID
 * document updates with nothing more exotic than git and CI. So no single wire
 * encoding can be the SDK's contract, and a server that frames ANP-02 in an envelope
 * of its own is not non-conforming — it is using the latitude the spec grants it.
 *
 * Supplying one replaces the default (the flat ANP-02 body, the RFC 9421 headers,
 * POSTed to the URI the caller named). ⚠️ It changes the FRAME, not the PROOF
 * mechanism: the body an envelope receives is already signed, so a server that
 * expects a different signature encoding is NOT reachable this way. That is a bigger
 * adapter than this seam, and pretending otherwise would be worse than saying so.
 */
export type RequestEnvelope = (req: SignedRequest) => EnvelopeRequest

/** The transport-level knobs `login`, `register` and `update` share: how the signed
 *  request gets out. */
export interface SignedRequestTransport {
  /** Optional transport override; defaults to globalThis.fetch. */
  transport?: (url: string, init: RequestInit) => Promise<Response>
  /** Optional wire envelope — see {@link RequestEnvelope}. */
  envelope?: RequestEnvelope
}

export interface LoginOptions extends DidUpdateOptions, SignedRequestTransport {
  connectorId?: string
  /** Server-issued one-time nonce to sign with. */
  nonce: string
  /** Full URL of the verify endpoint, e.g. `https://host/api/login/anp/verify`. */
  targetUri: string
}

/**
 * What a 409 `did_superseded` told us, plus what we then checked ourselves.
 *
 * The two halves are kept apart on purpose. ANP-03 §3.2 defines the 409, and in the
 * same paragraph says its `currentDid` is 只作为未验证提示 — the client 不得依据该字段
 * 重试, and must instead fetch the old DID document, verify `deactivated` /
 * `successorDid` / the top-level `proof`, and walk forward to the DID that is active
 * now. So everything the peer SAID is named `claimed*` and is worth nothing on its
 * own, while `verifiedCurrentDid` is what our own walk produced — the only DID here
 * that is safe to sign with.
 */
export interface DidSupersededInfo {
  /** The DID we signed with, i.e. the credential the peer rejected. */
  requestedDid: string
  /** The peer's `currentDid`. Unverified hint — log it, never sign from it. */
  claimedCurrentDid?: string
  /** The DID that is current now, per our completed chain walk. Absent when no walk
   *  ran (no `didChain`, or the peer's report was not about our credential). */
  verifiedCurrentDid?: string
  /** The walk itself — every hop, each with its own assurance. */
  chain?: DidChain
}

/**
 * Produce a signer for the DID a completed chain walk verified. Returning `null` /
 * `undefined` (or omitting the hook) means "do not retry": the 409 is reported as is.
 *
 * An update means a NEW key, so the connector that signed the rejected request cannot
 * sign as the successor — which is why this is a callback the caller supplies rather
 * than something the SDK can derive, and why the SDK accepts only the DID it verified
 * itself: a connector for any other DID is refused, so the peer's `currentDid` hint can
 * never become the credential in use.
 */
export type DidSupersededResolver = (
  info: DidSupersededInfo,
) => AnpConnector | string | null | undefined | Promise<AnpConnector | string | null | undefined>

/**
 * The options `login()` and `register()` share for answering a 409 `did_superseded`
 * (ANP-03 §3.2). `didChain` alone is enough to get the answer — see `didChain` below.
 */
export interface DidUpdateOptions {
  /**
   * How to walk the update chain the 409 points at. Supplying it is what authorises
   * those outbound DID-document fetches — the same "configured, or not fetched at all"
   * rule the resolver follows — and its `allowedHosts` MUST cover the DID's host.
   *
   * Supplying this alone is the normal case for a caller that just wants to know what
   * happened: the walk runs, its conclusion rides on the thrown error's
   * `didSuperseded`, and no retry is attempted.
   */
  didChain?: DidChainOptions
  /** Optional: how to get a signer for the verified current DID, so the SDK can retry
   *  instead of just reporting. See {@link DidSupersededResolver}. */
  onDidSuperseded?: DidSupersededResolver
}
