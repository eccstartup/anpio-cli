import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultibaseEd25519 } from './multicodec'
import { buildBaseDidDocument, type DidDocumentServices } from './didDocument'
import { signDidDocumentProofSync } from './dataIntegrity'
import { identityDid, subjectOf } from '../identity'
import { ANP_COMPONENTS, buildContentDigestValue, buildSignatureBase, serializeSignatureParams, signatureBaseBytes } from './signatureBase'
import { bytesToBase64, utf8 } from './encoding'
import type { AnpSigningIdentity, AnpIdentity } from '../types'

// Browser/Node-side ANP signer. The SDK signs with the OFFICIAL branch:
// it covers `@method, @target-uri, @authority, content-digest`, appends a
// `@signature-params` line (`created/expires/nonce/keyid`), uses the official
// `0xed 0x01` multibase prefix, and emits a labeled RFC 9421 `sig1=:...:` value.

const DEFAULT_TTL_SECONDS = 300

export interface CreateAnpIdentityOptions {
  /** Path segments for the path-type DID before the fingerprint. Defaults to
   *  `['user','default']` (see `identityDid`). */
  path?: string[]
  /** Services to publish in this identity's DID document (ANP-03 §service). Pass a
   *  function to build one from the DID — `agentDescriptionService`'s endpoint
   *  usually embeds it. Signed into the document, so it cannot be added later. */
  service?: DidDocumentServices
}

// Build a deterministic Ed25519 identity with an inline DID document for a host.
// The DID is the ANP path-type `did:wba:<host>:<path…>:e1_<fingerprint>` and the
// document inlines the public key (so a server without a reachable `.well-known`
// host can still resolve it) plus its mandatory eddsa-jcs-2022 self-proof.
export function createAnpIdentity(host: string, opts: CreateAnpIdentityOptions = {}): AnpSigningIdentity {
  const priv = ed25519.utils.randomSecretKey()
  const pub = ed25519.getPublicKey(priv)
  const did = identityDid(host, undefined, undefined, { curve: 'ed25519', publicKey: pub, path: opts.path })
  const keyid = `${did}#key-1`
  const publicKey = { publicKeyMultibase: encodeMultibaseEd25519(pub) }
  const didDocument = buildBaseDidDocument({ did, keyid, ...publicKey, service: opts.service })
  didDocument.proof = signDidDocumentProofSync(didDocument, keyid, priv)
  return { subject: subjectOf(did), priv, did, keyid, publicKey, didDocument }
}

export interface SignAnpLoginInput {
  /** A signing identity: an `AnpIdentity` plus the `priv` key that signs. */
  identity: AnpSigningIdentity
  nonce: string
  method: string
  /** Full target URL the signed request is actually POSTed to. */
  url: string
  /** Optional handle to claim. When present it is embedded in the signed body so
   *  the content-digest binds the caller's desired handle (registration). It is a name
   *  on the DID server being registered with — see `RegisterOptions.handle`. */
  handle?: string
  /** Endpoint-specific members to bind under the content-digest alongside ANP-02's own
   *  (`SignRequest.extraBody`). Placed FIRST, so the five names this function owns — and
   *  `@signature-params`' nonce — always win over a caller's copy of them. */
  extraBody?: Record<string, unknown>
}

// Sign an ANP-02 login request and return the body + headers to attach to the
// POST. The body embeds the nonce and the DID document; the signature binds to
// the content-digest and the covered components.
export async function signAnpLoginRequest(
  input: SignAnpLoginInput,
): Promise<{ body: string; headers: Record<string, string> }> {
  const url = new URL(input.url)
  const path = url.pathname
  const authority = url.host
  // Endpoint-specific members first: the names below are ANP-02's own, and a caller's
  // copy of one must not displace the fact the proof is about.
  const payload: Record<string, unknown> = {
    ...(input.extraBody ?? {}),
    nonce: input.nonce,
    did: input.identity.did,
  }
  // The inline document is a `did:wba` fast path: a path-type DID commits to its key
  // in the identifier, so a server can check the copy against the DID itself. A native
  // `did:web` commits to nothing — Appendix B B.1 L471 makes resolving the document
  // from the domain a MUST, and L477 forbids leaning on another method's proof — so a
  // copy in the body could only ever be unauthenticated input that every conformant
  // verifier must ignore. Sending one would not add a fact; it would hand a
  // non-conformant reader the one thing it must not trust.
  if (!input.identity.did.startsWith('did:web:')) {
    payload.didDocument = input.identity.didDocument
  }
  if (input.handle != null) payload.handle = input.handle
  const body = JSON.stringify(payload)

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'content-digest': await buildContentDigestValue(utf8(body)),
  }

  const now = Math.floor(Date.now() / 1000)
  const signatureParams = serializeSignatureParams(ANP_COMPONENTS, {
    created: now,
    expires: now + DEFAULT_TTL_SECONDS,
    nonce: input.nonce,
    keyid: input.identity.keyid,
    // NOTE: no `alg` — the server rebuilds @signature-params from exactly
    // created/expires/nonce/keyid; adding alg would change the signed bytes.
  })

  const base = buildSignatureBase({
    method: input.method,
    path,
    authority,
    targetUri: input.url,
    headers,
    components: ANP_COMPONENTS,
    signatureParams,
  })

  const signature = bytesToBase64(ed25519.sign(signatureBaseBytes(base), input.identity.priv))
  return {
    body,
    headers: {
      ...headers,
      'signature-input': `sig1=${signatureParams}`,
      signature: `sig1=:${signature}:`,
    },
  }
}
