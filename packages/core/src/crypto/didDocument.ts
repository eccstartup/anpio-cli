// The shared DID-document skeleton for an ANP identity. Both producers — the
// wallet prover (`protocol/anp.ts`) and the sync dev identity (`crypto/signer.ts`)
// — build the same base document here, so the shape can never drift. The
// `proof` is attached by the caller (sync for a local private key, async for a
// wallet's `signMessage`).

import type { Secp256k1PublicKeyJwk } from './multicodec'

/** The `@context` an `e1_` (Ed25519) document carries: `Multikey` is defined by the
 *  multikey context, `DataIntegrityProof` by data-integrity. */
export const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/data-integrity/v2',
  'https://w3id.org/security/multikey/v1',
]

/** The `@context` a `k1_` (secp256k1) document carries. The suite context defines
 *  `EcdsaSecp256k1VerificationKey2019` **and** the scoped `publicKeyJwk` term the
 *  binding key is published under (Appendix A A.4 L76–89) — which is why nothing
 *  from `DID_CONTEXT` is needed here: a `k1_` binding key is never a `Multikey`, and
 *  this SDK's `k1_` proof is the optional one §A.5 defines, not a
 *  `DataIntegrityProof`. */
export const SECP256K1_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/secp256k1-2019/v1',
]

/** An entry in a DID document's `service` array (DID Core; ANP-03 §service lists the
 *  types ANP gives meaning to). */
export interface DidDocumentService {
  id: string
  type: string
  serviceEndpoint: string
  /** ANP-03: who signs a cross-domain service-to-service call. Only
   *  `ANPMessageService` recommends it; the SDK carries it through untouched. */
  serviceDid?: string
}

/** The service `type` whose `serviceEndpoint` locates a public ANP-07 `ad.json`.
 *  This is the ONLY normative way to find an agent description — ANP defines no
 *  path convention for one (ADR-0001 §6.1.1). */
export const AGENT_DESCRIPTION_SERVICE_TYPE = 'AgentDescription'

/** The service `type` through which a DID holder makes the REVERSE declaration of a
 *  WNS Handle binding (ANP-04 §6.2 L484): a dereferenceable `https` endpoint on its
 *  Handle Provider's domain. It exists because the provider's own forward claim
 *  (Handle → DID) cannot be trusted on its own — see `verifyHandleBinding`. */
export const HANDLE_SERVICE_TYPE = 'ANPHandleService'

/** Service entries, or a function of the DID for endpoints that embed it — a host
 *  that keys published descriptions by DID names them in the URL. */
export type DidDocumentServices = DidDocumentService[] | ((did: string) => DidDocumentService[])

/** An identity's binding public key, in one of the two representations DID Core
 *  defines. They are **mutually exclusive**, and ANP fixes which profile uses which:
 *
 *  - `e1_` (Ed25519)  → `Multikey` + `publicKeyMultibase`. ANP-03 **L149** requires
 *    `publicKeyMultibase` to be a base58-btc `Multikey`, and Ed25519 is the only
 *    curve that clause covers.
 *  - `k1_` (secp256k1) → `EcdsaSecp256k1VerificationKey2019` + `publicKeyJwk`.
 *    Appendix A A.3 step 1 (**L39**) says the binding key is "Represented as
 *    `publicKeyJwk` in DID documents" and A.4 (**L70–89**) gives the shape.
 *
 *  This union is the whole point of the split: a secp256k1 `publicKeyMultibase` is a
 *  shape the spec never defines, and a reader that dispatches on `type` (the official
 *  SDK's `extractPublicKey`) sends every `Multikey` down its Ed25519 path — so a
 *  `k1_` document published that way is readable by nothing but this SDK. The two
 *  encodings are NOT interchangeable and no caller may pick one for the other. */
export type DidPublicKey =
  | { publicKeyMultibase: string }
  | { publicKeyJwk: Secp256k1PublicKeyJwk }

/** The four base fields plus the ANP `@context`. A path-type `e1_` document then
 *  requires a `DataIntegrityProof` (attached by the caller); a `k1_` document's
 *  proof is optional. */
export type BaseDidDocumentInput = DidPublicKey & {
  did: string
  keyid: string
  /** Service entries to publish. They MUST be passed HERE rather than appended to
   *  the returned object: the caller signs the document as built, and `proof`
   *  covers every field present at signing time — a service added afterwards would
   *  not be covered and would fail verification (ANP-03 §2.5.5). */
  service?: DidDocumentServices
}

/** Build the base document for `key` — the verification method, its curve's
 *  `@context`, and the `authentication` / `assertionMethod` authorizations that make
 *  the key usable. Which verification-method `type` and key representation go in is
 *  decided HERE and nowhere else, from which member of {@link DidPublicKey} the
 *  caller passed. */
export function buildBaseDidDocument(input: BaseDidDocumentInput): Record<string, unknown> {
  const { did, keyid, service } = input
  const services = service == null ? undefined : typeof service === 'function' ? service(did) : service
  const secp256k1 = 'publicKeyJwk' in input
  const verificationMethod = secp256k1
    ? {
        id: keyid,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: did,
        publicKeyJwk: input.publicKeyJwk,
      }
    : { id: keyid, type: 'Multikey', controller: did, publicKeyMultibase: input.publicKeyMultibase }
  return {
    '@context': [...(secp256k1 ? SECP256K1_CONTEXT : DID_CONTEXT)],
    id: did,
    verificationMethod: [verificationMethod],
    authentication: [keyid],
    assertionMethod: [keyid],
    ...(services == null ? {} : { service: services }),
  }
}
