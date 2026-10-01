// Native `did:web` as a first-class identity — the PRODUCE half of Appendix B.
//
// The read half already lived elsewhere: `didToUrl` maps a `did:web` to the URL that
// serves its document, `resolveDidDocument` resolves it, and the WBA-only checks step
// aside on their own — no `e1_`/`k1_` fingerprint binding (`assertFingerprintBinding`
// is `did:wba`-gated) and no document proof (`documentProofPolicy` returns `skipped`,
// which is Appendix B B.1 L477's MUST NOT). What was missing was the ability to HAVE
// such an identity: every producer in this SDK emits `did:wba`.
//
// Two consequences of the missing binding to keep in view, because they are what
// makes this file different rather than a parameterized copy of `signer.ts`:
//
//   - There is no proof to attach. A `did:wba` `e1_` document self-signs so a server
//     can tie it to the fingerprint inside the DID; a `did:web` DID contains no key,
//     so a document proof would bind nothing to the identifier. Appendix B B.1 L479
//     lets an implementation verify a proof IF the document carries one, under that
//     proof's own profile — so producing none is the honest default, not an omission.
//   - Nothing is publishable until the caller serves it. The document's only possible
//     location is the one derived from the DID (`didToUrl`), and this SDK produces
//     documents, it does not host them (same split as `buildAgentDescription`).

import { ed25519 } from '@noble/curves/ed25519.js'
import { encodeMultibaseEd25519 } from './multicodec'
import { buildBaseDidDocument, type DidDocumentServices } from './didDocument'
import { subjectOf, webIdentityDid } from '../identity'
import type { AnpSigningIdentity } from '../types'

export interface CreateWebIdentityOptions {
  /** Path segments for the DID, before the host's `did.json`. Absent means a bare
   *  host — `did:web:example.com` → `https://example.com/.well-known/did.json`. */
  path?: string[]
  /** Services to publish in the document — the reason a host would serve a document
   *  at all (an `AgentDescription` endpoint, an `ANPHandleService` declaration). */
  service?: DidDocumentServices
}

/**
 * Build a native `did:web` identity: a fresh Ed25519 key, the DID that names it, and
 * the document to serve for it. Authenticates under ANP-02's common flow — the keyid
 * is an ordinary DID URL and the request signing is unchanged, which is the whole
 * claim of the method-binding split (ADR-0002 §2.1).
 *
 * The document carries **no `proof`** (see the module header) and is **not stored
 * anywhere**: serve it, as-is, at `didToUrl(identity.did)`. A verifier MUST resolve it
 * from there rather than accept a copy from a request (B.1 L471) — there is no
 * fingerprint that would let a caller's own copy be checked against the identifier,
 * so an inline document is unauthenticated input on this method.
 */
export function createWebIdentity(host: string, opts: CreateWebIdentityOptions = {}): AnpSigningIdentity {
  const priv = ed25519.utils.randomSecretKey()
  const pub = ed25519.getPublicKey(priv)
  const did = webIdentityDid(host, opts.path)
  const keyid = `${did}#key-1`
  const publicKey = { publicKeyMultibase: encodeMultibaseEd25519(pub) }
  const didDocument = buildBaseDidDocument({ did, keyid, ...publicKey, service: opts.service })
  return { subject: subjectOf(did), priv, did, keyid, publicKey, didDocument }
}
