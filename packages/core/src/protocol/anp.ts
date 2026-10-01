import { signAnpLoginRequest } from '../crypto/signer'
import type { AnpIdentity } from '../types'
import { verifyHttpMessageSignature } from '../crypto/verify'
import { encodeMultibaseEd25519, secp256k1PublicKeyToJwk } from '../crypto/multicodec'
import { buildBaseDidDocument, type DidPublicKey } from '../crypto/didDocument'
import { signDidDocumentProof } from '../crypto/dataIntegrity'
import type { MessageSigner } from '../crypto/dataIntegrity'
import { ANP_COMPONENTS, buildContentDigestValue } from '../crypto/signatureBase'
import { bytesToBase64, utf8 } from '../crypto/encoding'
import { ConnectxError } from '../errors'
import { identityDid, stableSubjectId, subjectOf } from '../identity'
import type { NonceStore } from '../crypto/verify'
import type { IWallet } from '../wallet/wallet'
import type { SignRequest, SignResult } from '../types'
import type { ProofAdapter, BuildProofInput, Proof, WalletProver, IdentityDescriptor } from './proof'

// ANP-02 native proof adapter: signs an RFC 9421 HTTP Message Signature over a
// login request and verifies it, with the `did:wba` method binding from ANP-03.
// All signatures are verified against the resolved key — ed25519 or secp256k1.

/** The proof adapter id. `'anp'` — method-agnostic authentication (ANP-02); the
 *  `did:wba` specifics live in the method layer (`identity.ts` / `resolveDid.ts`).
 *  Was `'anp-03'` before 0.3.0 (ADR-0002 §2.1). */
export const ANP_PROOF_KIND = 'anp'

const TTL_SECONDS = 300

export const anpProofAdapter: ProofAdapter = {
  kind: ANP_PROOF_KIND,

  async sign(input: BuildProofInput & { nonce: string }) {
    if (!input.targetUri) {
      throw new ConnectxError('invalid_argument', 'anpProofAdapter.sign requires a full targetUri URL (RFC 9421 @target-uri)')
    }
    const { body, headers } = await signAnpLoginRequest({
      identity: input.identity,
      nonce: input.nonce,
      method: input.method,
      url: input.targetUri,
      handle: input.handle,
      extraBody: input.extraBody,
    })
    return { body, headers }
  },

  async verify(input: Proof & { key: { curve: 'ed25519' | 'secp256k1'; bytes: Uint8Array }; expectedNonce: string; nonceStore: NonceStore }) {
    // Fail-closed: the high-level adapter MUST consume the server challenge. Without
    // a challenge + store, a success would only prove integrity/freshness — a server
    // treating `true` as a one-time login would accept an in-window replay. Callers
    // wanting a stateless check must use the low-level verifyHttpMessageSignature.
    if (input.expectedNonce == null || input.nonceStore == null) {
      throw new ConnectxError(
        'invalid_argument',
        'anpProofAdapter.verify requires expectedNonce (server challenge) and nonceStore (one-time consume); use the low-level verifyHttpMessageSignature for a stateless check',
      )
    }
    return verifyHttpMessageSignature({
      method: input.method,
      path: input.path,
      authority: input.authority,
      targetUri: input.targetUri,
      headers: input.headers,
      body: input.body,
      key: input.key,
      expectedNonce: input.expectedNonce,
      nonceStore: input.nonceStore,
    })
  },
}

// Build an inline DID document for a wallet's public key. This frames an
// arbitrary-chain key (ed25519 or secp256k1) as an ANP identity. The DID shape
// follows the identity contract in `../identity`: a CAIP-10 account id when a chain
// id + address are present (chain id normalized to CAIP-2, EVM address lowercased),
// else the ANP path-type `did:wba:<host>:<path…>:<fingerprint>` binding the key
// (`e1_` for ed25519, `k1_` for secp256k1). The host is always the DID document's
// controller. An `e1_` document is self-signed with an eddsa-jcs-2022 proof.
//
// `descriptor.baseDocument` overrides the document half: the caller supplies the
// document as the DID server has it on file and it is used verbatim (proof and all),
// so fields this builder does not produce survive. The DID, keyid and public key
// still come from the key — and must match the supplied document's `id`.
export async function buildWalletIdentity(
  wallet: IWallet,
  host: string,
  descriptor?: IdentityDescriptor,
): Promise<AnpIdentity> {
  // Build the identity from a CONSISTENT snapshot. The wallet's provider can switch
  // account/chain at any point; reading the account, then the key, then the account
  // again lets us detect a change across the async key recovery and fail instead of
  // framing a DID for account B with account A's public key (ANP-2026-09-08-02).
  const live0 = await wallet.getAccount?.()
  const pub = await wallet.getPublicKey() // throws if account/chain changed during the probe
  const curve = await wallet.curve?.() ?? 'ed25519'
  const live1 = await wallet.getAccount?.()

  const addr0 = live0?.address ?? descriptor?.address
  const chain0 = live0?.chainId ?? descriptor?.chainId
  const addr1 = live1?.address ?? descriptor?.address
  const chain1 = live1?.chainId ?? descriptor?.chainId
  if (
    (addr0 ?? '').toLowerCase() !== (addr1 ?? '').toLowerCase() ||
    chain0 !== chain1
  ) {
    throw new ConnectxError('wallet_account_changed', 'Account/chain changed while building identity; retry')
  }

  const chainId = chain1
  const address = addr1
  const did = identityDid(host, chainId, address, { curve, publicKey: pub, path: descriptor?.path })
  const keyid = `${did}#key-1`
  // The binding key in the representation its profile publishes — `Multikey` +
  // `publicKeyMultibase` for Ed25519, `EcdsaSecp256k1VerificationKey2019` +
  // `publicKeyJwk` for secp256k1 (Appendix A A.4). A secp256k1 multibase would be a
  // shape no other implementation reads (see `DidPublicKey`).
  const publicKey: DidPublicKey =
    curve === 'ed25519'
      ? { publicKeyMultibase: encodeMultibaseEd25519(pub) }
      : { publicKeyJwk: secp256k1PublicKeyToJwk(pub) }
  const didDocument = await resolveDidDocumentBase({
    supplied: descriptor?.baseDocument,
    service: descriptor?.service,
    did,
    keyid,
    publicKey,
    curve,
    sign: (message) => wallet.signMessage(message),
  })
  return { subject: subjectOf(did), did, keyid, publicKey, didDocument }
}

/** The DID document half of an identity: either the one the caller says is on file at
 *  the DID server (`baseDocument`), or one composed from the key. */
async function resolveDidDocumentBase(input: {
  supplied: Record<string, unknown> | undefined
  service: IdentityDescriptor['service']
  did: string
  keyid: string
  publicKey: DidPublicKey
  curve: string
  sign: MessageSigner
}): Promise<Record<string, unknown>> {
  const { supplied, service, did, keyid, publicKey, curve, sign } = input
  if (supplied == null) {
    const document = buildBaseDidDocument({ did, keyid, ...publicKey, service })
    // The `e1_` profile requires a self-signed DataIntegrityProof. Sign through the
    // wallet so a browser wallet that only exposes `signMessage` works too; a chain
    // wallet (secp256k1) has no mandatory proof, so it stays unsigned.
    if (curve === 'ed25519') document.proof = await signDidDocumentProof(document, keyid, sign)
    return document
  }
  if (service != null) {
    throw new ConnectxError(
      'invalid_argument',
      `Pass either baseDocument (the DID document as the server has it on file) or service (to compose one), not both: the two describe different documents for "${did}".`,
    )
  }
  // The DID embeds the e1_ key fingerprint, so a copy taken before a key change — or
  // a document belonging to another identity — cannot match. Catching it here is the
  // difference between retiring this DID and retiring the wrong one.
  if (supplied.id !== did) {
    throw new ConnectxError(
      'invalid_argument',
      `baseDocument is the DID document for "${String(supplied.id)}", but this key derives "${did}" — refusing to build an identity whose document describes a different DID.`,
    )
  }
  // Verbatim, proof included: this is the document the DID server has on file, and the
  // whole reason to hand one over is that the SDK cannot recompose it (a `service`
  // endpoint, extra keys). Re-signing would swap a document the server published for
  // one it never saw — and an update hop's proof must cover the properties on file
  // (§2.5.3 L419).
  return { ...supplied }
}

// A `WalletProver` for any `IWallet` — the "ANP compatible with arbitrary-chain
// wallets" bridge. It builds the identity and signs an ANP-02 login request
// with the wallet's key, so the server verifies a normal ANP proof.
export function cryptoWalletProver(): WalletProver {
  return {
    buildIdentity: buildWalletIdentity,

    async signRequest(wallet: IWallet, identity: AnpIdentity, req: SignRequest): Promise<SignResult> {
      // A update request signs a DIFFERENT document than a login does: the retirement
      // document, which is what makes the hop verifiable. Everything else — the signed
      // components, the nonce, the keyid — is the ordinary ANP-02 request, so a DID
      // server can verify the delivery with the machinery it already has.
      const retirement =
        req.successorDid == null
          ? undefined
          : await buildRetirementDocument(identity, req, (message) => wallet.signMessage(message))
      const didDocument = retirement ?? identity.didDocument

      const payload: Record<string, unknown> = {
        // Caller-supplied endpoint fields go in FIRST: the four names below are ANP-02's
        // own and win, so a caller cannot displace the DID, the document or the nonce
        // that the proof is about. `assertSigned` then checks each of these members
        // reached the signed bytes.
        ...(req.extraBody ?? {}),
        nonce: req.nonce,
        did: identity.did,
        didDocument,
      }
      if (req.handle != null) payload.handle = req.handle
      if (retirement != null) {
        payload.successorDid = req.successorDid
        payload.successorDocument = req.successorDocument
      }
      const body = JSON.stringify(payload)
      const digestHeader = await buildContentDigestValue(utf8(body))
      const url = new URL(req.url)
      const now = Math.floor(Date.now() / 1000)
      const signatureParams = `(${ANP_COMPONENTS.map((c) => `"${c}"`).join(' ')});created=${now};expires=${
        now + TTL_SECONDS
      };nonce="${req.nonce}";keyid="${identity.keyid}"`

      const base = [
        `"@method": ${req.method.toUpperCase()}`,
        `"@target-uri": ${req.url}`,
        `"@authority": ${url.host}`,
        `"content-digest": ${digestHeader}`,
        `"@signature-params": ${signatureParams}`,
      ].join('\n')

      // Sign the canonical base with the wallet's key; wrap as labeled RFC 9421.
      const sig = await wallet.signMessage(utf8(base))
      const signature = `sig1=:${bytesToBase64(sig)}:`
      return {
        did: identity.did,
        keyid: identity.keyid,
        didDocument,
        body,
        headers: {
          'content-type': 'application/json',
          'content-digest': digestHeader,
          'signature-input': `sig1=${signatureParams}`,
          signature,
        },
      }
    },
  }
}

export type { AnpIdentity }

// ---- Update: the retirement half of a hop -----------------------------------
//
// An update is two documents produced from two keys — the retiring DID's document
// marked `deactivated` with `successorDid`, and the successor's active document — and
// the delivery carries both (§2.5.3 L415–420). This is the only place the SDK produces the
// first; the second is built by the successor's own key, like any other identity.

/**
 * Refuse a hop this SDK cannot honestly produce, BEFORE anything is signed.
 *
 * Three conditions, each measured on the artifacts rather than promised:
 * the retiring document must carry a proof (only the `e1_` profile does, and only an
 * Ed25519 key can re-make it — a `k1_` document is unsigned and a CAIP-10 account id
 * binds no key at all); the successor document must carry a proof too (§2.5.3 L419 puts the
 * successor's active document under its own binding key); and both DIDs must sit on the same
 * stable subject path (§2.5.3). That last one is what makes this an update rather
 * than a hand-off: the subject is the thing that survives, so a "hop" that moved it
 * would be a chain this SDK's own verifier rejects as `did_chain_broken` — and the SDK
 * must not be the thing that delivered it.
 */
function assertUpdatable(identity: AnpIdentity, req: SignRequest): void {
  const successorDid = req.successorDid as string
  if (req.successorDocument == null) {
    throw new ConnectxError(
      'invalid_argument',
      `Cannot retire "${identity.did}" to "${successorDid}" without successorDocument — a hop is the pair (§2.5.3)`,
    )
  }
  if (identity.didDocument.proof == null) {
    throw new ConnectxError(
      'invalid_argument',
      `Cannot retire "${identity.did}": its DID document carries no proof, so there is nothing to re-sign. Update is defined for the e1_ path-type did:wba profile.`,
    )
  }
  if (req.successorDocument.proof == null) {
    throw new ConnectxError(
      'invalid_argument',
      `Cannot retire "${identity.did}" to "${successorDid}": the successor's ACTIVE document carries no proof (§2.5.3 L419)`,
    )
  }
  let predecessor: string
  let successor: string
  try {
    predecessor = stableSubjectId(identity.did)
    successor = stableSubjectId(successorDid)
  } catch (err) {
    throw new ConnectxError(
      'invalid_argument',
      `Cannot retire "${identity.did}" to "${successorDid}": an update is between two did:wba DIDs`,
      { cause: err },
    )
  }
  if (predecessor !== successor) {
    throw new ConnectxError(
      'invalid_argument',
      `Cannot retire "${identity.did}" to "${successorDid}": an update keeps the stable subject path (§2.5.3), got "${predecessor}" → "${successor}"`,
    )
  }
}

/**
 * The retirement document: the retiring DID's own document, marked `deactivated` and
 * pointing at its immediate successor, signed by the RETIRING key.
 *
 * Nothing else changes — `id`, `controller`, `verificationMethod`, `authentication` all
 * stay the retired DID's own. That is the point: the hop is verified with the key the
 * OLD DID binds (§2.5.5), so the entity authorising the move is the one being moved.
 * The proof is re-made because `deactivated` / `successorDid` were added after the old
 * one was created and the proof covers the whole document.
 */
async function buildRetirementDocument(
  identity: AnpIdentity,
  req: SignRequest,
  sign: MessageSigner,
): Promise<Record<string, unknown>> {
  assertUpdatable(identity, req)
  const { proof: _retired, ...rest } = identity.didDocument
  const document: Record<string, unknown> = { ...rest, deactivated: true, successorDid: req.successorDid }
  document.proof = await signDidDocumentProof(document, identity.keyid, sign)
  return document
}
