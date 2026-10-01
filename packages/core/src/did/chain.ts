// DID continuity — following the update chain a `did:wba` identity leaves behind
// when its binding key changes (ANP-03 §2.2.3, §2.5.2–§2.5.5, §2.6, §7).
//
// An update is a LINKED LIST, not a rewrite: the old DID Document stays fetchable
// with `deactivated: true` + `successorDid → <new DID>`, so a verifier holding only
// the old DID can still walk forward to the one that is current. The new DID is a
// DIFFERENT DID — a key change IS a DID change (§2.5.3) — but it shares the same
// stable subject path, and that shared path is what makes the two "the same
// subject" (§2.2.3) and the walk possible at all.
//
// Three consequences shape this file:
//
//   1. The stable subject path INCLUDES THE DOMAIN, and §2.5.3 rule 1 requires the
//      successor's path to be IDENTICAL. A chain therefore never legitimately
//      leaves its host, so walking one needs no new fetch authority: the caller's
//      existing `allowedHosts` already covers every hop, and a successor on another
//      host is a path mismatch we MUST reject. (This is also why the "derive an
//      allowlist for a cross-host chain" question left open in ADR-0002 §6 has no
//      work to do — see todos/TODO5 Part F.)
//   2. Assurance is per EDGE and is never promoted (§2.5.5). An edge the old
//      binding key signed is `verified`; one a pre-authorized recovery key signed
//      is `recovery_verified`; a structurally complete chain with a signature-less
//      hop is `provider_asserted`, and only when every document was fetched live in
//      this resolution; anything else is `unverified`.
//   3. A proof that IS present but is neither authorized form invalidates the
//      transition — it MUST NOT be quietly downgraded to a provider assertion
//      (§2.5.5). Only an ABSENT proof makes a hop signature-less.
//
// Nothing here trusts a hint. The `currentDid` a 409 `did_superseded` body carries
// is a peer's claim (§3.2); the DID this function returns is the one its own walk
// verified, and it is the only DID a retry may sign with.

import { ConnectxError } from '../errors'
import { stableSubjectId, subjectOf, type SubjectId } from '../identity'
import { isFingerprint } from '../crypto/fingerprint'
import {
  canonicalDidUrl,
  documentProofKey,
  documentProofKeyId,
  verifyDidDocumentProof,
  verifyDidDocumentProofWithKey,
} from '../crypto/dataIntegrity'
import {
  isMethodAuthorized,
  resolveDidDocument,
  type DidDocumentStore,
  type ResolveDidOptions,
  type ResolvedDidDocument,
} from '../crypto/resolveDid'

/**
 * How strongly one predecessor→successor edge was proven (ANP-03 §2.5.5). Ordered
 * strongest to weakest; a chain is only as strong as its weakest edge. These four
 * have ONLY the meanings below — never promote one, and never treat
 * `provider_asserted` as a DID Document property.
 */
export type DidChainAssurance =
  /** The predecessor's original binding key signed the transition document, which
   *  covers the deactivation and the direct successor. */
  | 'verified'
  /** A recovery key that the PRE-deactivation trusted document authorized in
   *  `assertionMethod` signed that relation. */
  | 'recovery_verified'
  /** The chain is structurally complete, reaches a binding-proof-valid active `e1_`
   *  DID, and every document came from a live HTTPS fetch in this resolution — but
   *  at least one hop carries no signature. A provider's assertion, not a document
   *  property, and it MUST NOT be promoted to the two above. */
  | 'provider_asserted'
  /** Nothing established this edge: a lone `successorDid`, `alsoKnownAs`, a 409
   *  hint, a signature-less hop we could not attribute to an authenticated source,
   *  or an incomplete chain. */
  | 'unverified'

/** One predecessor→successor edge of an update chain, with the evidence for it. */
export interface DidChainHop {
  /** The predecessor DID this edge starts from. */
  did: string
  /** The DID it points at. */
  successorDid: string
  /** The predecessor's document — the evidence for the edge. */
  document: Record<string, unknown>
  /** Where that document came from (`didToUrl(did)`). */
  docUrl: string
  /** `'network'` when this resolution fetched it, `'store'` when the caller's
   *  `documentStore` served it. Only a `'network'` edge can be `provider_asserted`:
   *  a stored copy is evidence about the past, not an acquisition now. Necessary, not
   *  sufficient — a network hop is still `unverified` when the chain's TERMINAL came
   *  from the store, because the assertion is about the whole resolution. */
  source: 'network' | 'store'
  /** How this edge was proven. */
  assurance: DidChainAssurance
  /** The `verificationMethod` of the proof that carried the edge, for the two
   *  cryptographic assurances, as a FULL DID URL: a relative spelling is resolved
   *  against the document that named it, so which of the two forms the proof used
   *  never changes the identity recorded here. Absent for a signature-less hop. */
  proofKeyId?: string
}

/** The result of walking an update chain: which DID is current now, how strongly
 *  that was proven, and the hops that got us there. */
export interface DidChain {
  /** The DID the caller asked about (the walk's starting point). */
  did: string
  /** The update-stable identity every hop shares (ANP-03 §2.2.3). */
  subject: SubjectId
  /** The stable subject PATH, naked as §2.2.3 spells it — the field a 409
   *  `did_superseded` body reports. */
  stableSubjectId: string
  /** The DID that is current now: `did` itself when nothing superseded, otherwise the
   *  terminal DID of the walk. */
  currentDid: string
  /** Whether any hop was followed. `false` means the DID asked about is current. */
  superseded: boolean
  /** The WEAKEST edge's assurance. A chain with no hops is `verified`: there is no
   *  migration claim to weaken, and the document's own integrity was whatever the
   *  resolver's `documentProof` policy required (mandatory for an active `e1_`). */
  assurance: DidChainAssurance
  /** The terminal, current DID's document. */
  document: Record<string, unknown>
  docUrl: string
  /** The edges, oldest first. */
  hops: DidChainHop[]
}

/** One verified successor edge, as kept between resolutions (ANP-03 §2.6). */
export interface DidChainEdge {
  did: string
  successorDid: string
  /** Only the two cryptographic assurances may be kept. */
  assurance: 'verified' | 'recovery_verified'
  stableSubjectId: string
  /** Epoch ms of the resolution that established the edge. */
  verifiedAt: number
}

/**
 * Where verified successor edges are kept between resolutions. The store's job here
 * is CONFLICT DETECTION and evidence, not skipping work: a cached edge is never
 * trusted in place of re-verifying it, so a store that has been tampered with
 * cannot weaken a resolution — it can only make the walk refuse (§2.6 requires
 * rejecting a migration whose newly observed `successorDid` differs from the
 * verified edge already cached for that DID).
 */
export interface DidChainEdgeStore {
  get(did: string): Promise<DidChainEdge | undefined> | DidChainEdge | undefined
  set(edge: DidChainEdge): Promise<void> | void
  delete?(did: string): Promise<void> | void
}

/** In-memory `DidChainEdgeStore`. Like `createDidDocumentStore` it is deliberately
 *  not a global cache — nothing is read or written unless the caller passes one in. */
export function createDidChainEdgeStore(): DidChainEdgeStore {
  const edges = new Map<string, DidChainEdge>()
  return {
    get: (did) => edges.get(did),
    set: (edge) => {
      edges.set(edge.did, edge)
    },
    delete: (did) => {
      edges.delete(did)
    },
  }
}

export interface DidChainOptions extends ResolveDidOptions {
  /** Follow at most this many hops before reporting `did_chain_broken`. Default 8.
   *  §7 requires a bound; a longer chain is treated as hostile rather than walked. */
  maxChainLength?: number
  /** Accept a chain whose weakest edge is `provider_asserted`. Default false: that
   *  assurance is a provider's word, not a document property (§2.5.5). */
  acceptProviderAsserted?: boolean
  /** Return a chain that is below the acceptance policy instead of throwing
   *  `did_chain_assurance_too_low`. Use it for a diagnostic query, never to gate an
   *  authentication decision. Default false. */
  reportLowAssurance?: boolean
  /** Where verified successor edges are kept (§2.6). Supplying one is what makes the
   *  "same old DID, two different successors" conflict detectable ACROSS
   *  resolutions; without it only a single walk can catch it. */
  edgeStore?: DidChainEdgeStore
  /** Documents you already trust for a DID, used ONLY to authorize a recovery key in
   *  a deactivated document's proof (§2.5.5 rule 2). Never written to. Without the
   *  pre-deactivation state there is nothing to authorize against, so recovery
   *  proofs cannot be accepted — which is the point: a key that appears only at
   *  deactivation time must not be able to claim continuity. */
  trustedDocuments?: DidDocumentStore
}

const DEFAULT_MAX_CHAIN_LENGTH = 8

/** Strongest to weakest — the order is the ranking. */
const ASSURANCE_ORDER: readonly DidChainAssurance[] = [
  'verified',
  'recovery_verified',
  'provider_asserted',
  'unverified',
]

/** What a caller accepts without opting in (F2.7). `unverified` is never in this
 *  list: it establishes nothing, so there is no policy under which it is an answer. */
const DEFAULT_ACCEPTED: readonly DidChainAssurance[] = ['verified', 'recovery_verified']

/** What one hop's own evidence supports, before the terminal is known. */
type EdgeEvidence =
  | { assurance: 'verified' | 'recovery_verified'; proofKeyId?: string }
  | { assurance: 'signature-less' }

/**
 * Resolve a `did:wba` DID to its current DID by walking the update chain, and
 * report how strongly each hop was proven.
 *
 * This is the query behind both directions of the continuity story: ask it before
 * use to learn whether the DID you hold is still current (or, with a
 * `documentStore`, whether it still is after a TTL), and ask it reactively — the
 * `login()` / `register()` 409 path does exactly that — when a peer says our DID
 * has been superseded away.
 *
 * Every hop is validated against the §2.5.3 migration rules: the successor shares
 * the stable subject path, the predecessor is deactivated, the hop is the direct
 * next generation, and the chain neither cycles nor exceeds `maxChainLength`. Any
 * failure reports `did_chain_broken` rather than returning a shorter chain, so a
 * caller can never mistake a partial walk for a complete one.
 *
 * The returned `currentDid` is the walk's own conclusion. A `currentDid` sent by a
 * peer in a 409 body is an unverified hint (§3.2) and is never consulted here.
 */
export async function resolveDidChain(did: string, options: DidChainOptions = {}): Promise<DidChain> {
  // `stableSubjectId` throws `invalid_did` for anything that is not `did:wba`, which
  // is the right gate: the update chain is a WBA method rule, so there is nothing
  // to walk for `did:web` (whose DID already is its stable identity) or a CAIP-10 id.
  const stable = stableSubjectId(did)
  const maxHops = options.maxChainLength ?? DEFAULT_MAX_CHAIN_LENGTH

  const pending: { did: string; entry: ResolvedDidDocument; successorDid: string; edge: EdgeEvidence }[] = []
  const visited = new Set<string>([did])

  let current = did
  let entry = await resolveDidDocument(current, options)

  for (;;) {
    const successor = readSuccessorDid(entry.document)
    if (successor === undefined) break

    if (entry.document.deactivated !== true) {
      // §2.5.3 rule 3: the old document MUST stay fetchable with `deactivated: true`
      // AND `successorDid`. One without the other is a document claiming to be
      // current and superseded at once — no reading of it is safe.
      throw broken(
        did,
        `Document "${current}" names a successor but does not set deactivated: true, so it neither stands as a credential nor as a transition record`,
      )
    }
    if (pending.length >= maxHops) {
      throw broken(did, `Chain from "${did}" is longer than maxChainLength (${maxHops})`)
    }
    if (!successor.startsWith('did:wba:') || stableSubjectId(successor) !== stable) {
      // §2.5.3 rule 1 — and, because the stable path carries the domain, this is also
      // what keeps a chain on one host (see the file header).
      throw broken(
        did,
        `Successor "${successor}" does not share the stable subject path "${stable}" of "${current}", so it is not a continuation of the same subject`,
      )
    }
    if (visited.has(successor)) throw broken(did, `Chain from "${did}" cycles back to "${successor}"`)

    const cached = await options.edgeStore?.get(current)
    if (cached && cached.successorDid !== successor) {
      // §2.6/§7: the same old DID cannot have two successors.
      throw broken(
        did,
        `"${current}" was already verified as superseding to "${cached.successorDid}", but now names "${successor}" — a DID may have only one direct successor`,
      )
    }

    const next = await resolveDidDocument(successor, options)
    assertDirectSuccessor(next.document, current, stable)
    const edge = await edgeEvidence(current, entry, options)
    pending.push({ did: current, entry, successorDid: successor, edge })

    visited.add(successor)
    current = successor
    entry = next
  }

  // The walk stopped because the document names no successor. A terminal that is
  // still deactivated is a DEAD identity (§2.5.4 — no successor, no longer used for
  // authentication), not a current DID, so there is nothing to hand back.
  if (entry.document.deactivated === true) {
    throw broken(did, `Chain from "${did}" ends at "${current}", which is deactivated and names no successor`)
  }

  // §2.5.5 allows a full-chain resolver to report `provider_asserted` only after
  // reaching an ACTIVE `e1_` DID whose binding proof is valid.
  const terminalIsE1 = isE1PathDid(current)
  // ...and only when EVERY document the walk read was fetched live in this
  // resolution — the TERMINAL included. The terminal is the one that matters most:
  // it is the DID the caller is about to treat as current, and a stored copy of it
  // cannot show an update the provider has since made. Its own `source` is not
  // covered by any hop (a hop's `source` describes its PREDECESSOR), so it has to be
  // checked here. (Predecessors cannot presently be store hits at all —
  // `resolveDidDocument` never serves a superseded document, and a predecessor that
  // names a successor is superseded — but the whole-walk condition is stated
  // explicitly so it does not quietly depend on that staying true.)
  const everyDocumentIsLive =
    entry.source === 'network' && pending.every(({ entry: fromEntry }) => fromEntry.source === 'network')
  const hops: DidChainHop[] = pending.map(({ did: from, entry: fromEntry, successorDid, edge }) => {
    // A signature-less hop is the only one whose strength depends on anything
    // outside itself: §2.5.5 lets the WHOLE chain report `provider_asserted` — never
    // more — and only when every hop was fetched live in this resolution and the walk
    // ended at an active `e1_` DID whose binding proof held.
    const assurance: DidChainAssurance =
      edge.assurance !== 'signature-less'
        ? edge.assurance
        : everyDocumentIsLive && terminalIsE1
          ? 'provider_asserted'
          : 'unverified'
    return {
      did: from,
      successorDid,
      document: fromEntry.document,
      docUrl: fromEntry.docUrl,
      source: fromEntry.source,
      assurance,
      ...(edge.assurance === 'signature-less' ? {} : { proofKeyId: edge.proofKeyId }),
    }
  })

  const assurance = hops.reduce<DidChainAssurance>(
    (weakest, hop) =>
      ASSURANCE_ORDER.indexOf(hop.assurance) > ASSURANCE_ORDER.indexOf(weakest) ? hop.assurance : weakest,
    'verified',
  )

  if (!options.reportLowAssurance && !acceptedAssurances(options).includes(assurance)) {
    throw new ConnectxError(
      'did_chain_assurance_too_low',
      `The continuity chain from "${did}" to "${current}" is proven at assurance "${assurance}", which this call's policy does not accept (accepted: ${acceptedAssurances(options).join(', ')})`,
    )
  }

  // Commit only now that the WHOLE chain succeeded, and only the two cryptographic
  // assurances (§2.6): a failure anywhere — including the terminal's own proof, a
  // cycle, or the hop limit — must not leave the failed chain's prefix edges behind.
  if (options.edgeStore) {
    for (const hop of hops) {
      if (hop.assurance === 'verified' || hop.assurance === 'recovery_verified') {
        await options.edgeStore.set({
          did: hop.did,
          successorDid: hop.successorDid,
          assurance: hop.assurance,
          stableSubjectId: stable,
          verifiedAt: Date.now(),
        })
      }
    }
  }

  return {
    did,
    subject: subjectOf(did),
    stableSubjectId: stable,
    currentDid: current,
    superseded: hops.length > 0,
    assurance,
    document: entry.document,
    docUrl: entry.docUrl,
    hops,
  }
}

function acceptedAssurances(options: DidChainOptions): readonly DidChainAssurance[] {
  return options.acceptProviderAsserted ? [...DEFAULT_ACCEPTED, 'provider_asserted'] : DEFAULT_ACCEPTED
}

function broken(did: string, detail: string): ConnectxError {
  return new ConnectxError('did_chain_broken', `Continuity chain from "${did}" did not verify: ${detail}`)
}

/** The successor a document names, or `undefined` when it names none. A non-string
 *  is a malformed transition record, not a missing one. */
function readSuccessorDid(document: Record<string, unknown>): string | undefined {
  const value = document.successorDid
  if (value === undefined) return undefined
  if (typeof value !== 'string' || value === '') {
    throw new ConnectxError(
      'did_chain_broken',
      `A DID document's successorDid must be a single non-empty DID string, got ${JSON.stringify(value)}`,
    )
  }
  return value
}

/**
 * §2.5.5 requires a full-chain resolver to check the DIRECT-successor relation of
 * each hop. The only evidence a transition document offers is the successor's
 * `alsoKnownAs`, which §2.5.3 rule 2 makes optional — so an absent (or irrelevant)
 * list proves nothing and is accepted, while a list that names a DIFFERENT
 * generation of the same subject contradicts the hop and is refused.
 */
function assertDirectSuccessor(
  successorDoc: Record<string, unknown>,
  predecessorDid: string,
  stable: string,
): void {
  const names = Array.isArray(successorDoc.alsoKnownAs) ? successorDoc.alsoKnownAs : []
  const siblings = names.filter(
    (name): name is string =>
      typeof name === 'string' &&
      name.startsWith('did:wba:') &&
      isFingerprint(name.slice(name.lastIndexOf(':') + 1)) &&
      sameStableSubject(name, stable),
  )
  if (siblings.length === 0) return
  if (!siblings.includes(predecessorDid)) {
    throw new ConnectxError(
      'did_chain_broken',
      `The successor document names ${siblings.join(', ')} as its predecessor instead of "${predecessorDid}", so the chain skipped a generation`,
    )
  }
}

function sameStableSubject(did: string, stable: string): boolean {
  try {
    return stableSubjectId(did) === stable
  } catch {
    return false
  }
}

/** Would a standalone verifier call this a path-type `e1_` DID — a DID whose path
 *  commits to the key? Only those carry the mandatory binding proof §2.5.5 requires
 *  of a chain's terminal document. */
function isE1PathDid(did: string): boolean {
  if (!did.startsWith('did:wba:')) return false
  const segment = did.slice(did.lastIndexOf(':') + 1)
  return segment.startsWith('e1_') && isFingerprint(segment)
}

/** A proof's keyid as the FULL DID URL the hop records: a relative `#recovery-1` is
 *  resolved against the document that named it, so the two spellings of one recovery
 *  method do not become two different pieces of evidence. */
function fullProofKeyId(doc: Record<string, unknown>, keyid: string): string {
  return canonicalDidUrl(doc.id, keyid) ?? keyid
}

/**
 * The evidence for one edge (§2.5.5).
 *
 * The two authorized forms are tried in strength order, and a proof that is present
 * but is neither one THROWS: §2.5.5 requires a malformed, unauthorized or
 * cryptographically failing transition proof to invalidate the transition, and
 * forbids downgrading it to a provider assertion or an unverified hint. That is why
 * "no proof at all" and "a proof that does not hold up" end differently here.
 */
async function edgeEvidence(
  fromDid: string,
  entry: ResolvedDidDocument,
  options: DidChainOptions,
): Promise<EdgeEvidence> {
  if (entry.document.proof === undefined) return { assurance: 'signature-less' }

  // §2.5.5's proof rules are the `e1_` profile's. For any other profile this SDK
  // implements no transition suite (the `k1_` suite is out of scope), so the hop is
  // treated as signature-less rather than guessed at either way.
  if (!isE1PathDid(fromDid)) return { assurance: 'signature-less' }

  // A proof whose own shape does not parse (no `verificationMethod`, a foreign
  // cryptosuite, …) is neither authorized form, so it falls through to the throw.
  const keyid = documentProofKeyId(entry.document)
  if (keyid !== undefined) {
    // Form 1 — the predecessor's ORIGINAL BINDING KEY signed the whole transition
    // document. `verifyDidDocumentProof(doc, { did })` is exactly that: it recomputes
    // the RFC 7638 thumbprint of the proof key and requires it to equal the DID path's
    // last `e1_` segment (§2.5.5 rule 2).
    if (verifyDidDocumentProof(entry.document, { did: fromDid })) {
      return { assurance: 'verified', proofKeyId: fullProofKeyId(entry.document, keyid) }
    }

    // Form 2 — a recovery key the PRE-deactivation trusted document authorized in
    // `assertionMethod`. Both halves are load-bearing: the key material comes from the
    // document trusted BEFORE the update (so a key introduced at deactivation time
    // is not authorized), and the proof is checked against that material. The keyid is
    // resolved against that document and authorized by it, so a keyid spelled under
    // another DID resolves to that other DID and neither lookup finds anything.
    const trusted = await options.trustedDocuments?.get(fromDid)
    if (trusted) {
      const key = documentProofKey(trusted.document, keyid)
      if (
        key &&
        isMethodAuthorized(trusted.document, 'assertionMethod', keyid) &&
        verifyDidDocumentProofWithKey(entry.document, key)
      ) {
        return { assurance: 'recovery_verified', proofKeyId: fullProofKeyId(trusted.document, keyid) }
      }
    }
  }

  throw new ConnectxError(
    'did_chain_broken',
    `The transition document for "${fromDid}" carries a top-level proof that is neither its binding key's proof nor a recovery proof pre-authorized before deactivation, so the transition does not hold`,
  )
}
