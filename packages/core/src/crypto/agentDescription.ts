// ANP-07 Agent Description — the public profile an agent publishes about itself.
//
// Three things this is NOT:
//   - NOT JSON-LD. Upstream rewrote ANP-07 to plain JSON on 2025-07-23; the `@context`
//     / `ad:` namespace / `ad:AgentDescription` type in the repo's older notes and in
//     the spec's own `examples/adp/*.json` are a pre-rewrite draft (ADR-0001 §6.1.1).
//   - NOT the local `identity.json`, which is a private file that merely shares `did`.
//   - NOT located by any path convention. ANP defines no path for `ad.json`; the
//     locator is the DID document's `AgentDescription` service entry (ANP-03 §service,
//     used normatively by ANP-04 §10.2). See `agentDescriptionEndpoint` below.

import { ConnectxError } from '../errors'
import { AGENT_DESCRIPTION_SERVICE_TYPE, type DidDocumentService } from './didDocument'
import {
  fetchControlledJson,
  resolveDidDocument,
  type FetchErrorCodes,
  type ResolveDidOptions,
} from './resolveDid'

/** A well-formed ANP-07 agent description document (ANP-07 1.2). */
export interface AgentDescription {
  /** Fixed value `"ANP"`. */
  protocolType: string
  /** The ANP version this document targets, e.g. `"1.0.0"`. */
  protocolVersion: string
  /** `"AgentDescription"` for this document type. */
  type: string
  name: string
  securityDefinitions: Record<string, unknown>
  /** Names the enabled entry in `securityDefinitions`. */
  security: string
  url?: string
  /** Optional. When present it MUST name the DID this description was fetched for. */
  did?: string
  owner?: Record<string, unknown>
  description?: string
  created?: string
  /** WNS handle (ANP-04 §7.2): `local-part.domain`, a RESOLVED name whose authority is
   *  the WNS resolution result, not this document. ⚠️ Do not confuse it with
   *  `RegisterOptions.handle`, which is the name a DID SERVER binds when it agrees to
   *  host your DID — a name inside that DID, not a WNS name. */
  handle?: string
  /** Spelled exactly as ANP-07 spells it. That is the spec's own typo, which makes it
   *  the wire name — do not "fix" it. */
  Infomations?: unknown[]
  interfaces?: unknown[]
  /** Optional. The SIGNATURE is not verified: ANP-07 1.2 mandates no cryptosuite, and the
   *  document's own example uses `EcdsaSecp256r1Signature2019`, which this SDK does not
   *  implement — so `proofValue` is carried through untouched. What IS checked on a
   *  fetched document is the spec's reader MUST (L647): when `proof.domain` is present it
   *  has to name the host the document was obtained from, and it has to come with a
   *  `challenge` (L648). See `assertProofDomain`. */
  proof?: Record<string, unknown>
  [key: string]: unknown
}

/** An agent description plus where it came from. Returned by `fetchAgentDescription`. */
export interface ResolvedAgentDescription {
  /** The DID that was asked for. */
  did: string
  document: AgentDescription
  /** The `serviceEndpoint` the description was fetched from. */
  url: string
  /** The DID document that named that endpoint. */
  docUrl: string
}

// Everything that can go wrong fetching the SECOND document is `ad_fetch_failed`,
// including a refusal by the network policy, with the reason in the message. Unlike
// `did_resolve_blocked` (which a server must distinguish, because it usually means
// the server's own allowlist is misconfigured), the caller here has one action for
// all of it — retry, or fix the hosts it allowed — so the code stays coarse and the
// message carries the detail. A body that is not JSON is the exception: that is the
// same condition as JSON that parses but is not a description, so both are
// `ad_malformed`.
const AGENT_DESCRIPTION_FETCH_CODES: FetchErrorCodes = {
  subject: 'Agent description',
  blocked: 'ad_fetch_failed',
  failed: 'ad_fetch_failed',
  timeout: 'ad_fetch_failed',
  tooLarge: 'ad_fetch_failed',
  tooManyRedirects: 'ad_fetch_failed',
  invalidDocument: 'ad_malformed',
}

/** Read the `AgentDescription` endpoint out of a DID document. This entry IS the
 *  locator — there is no path convention to fall back on, so a document without one
 *  means the DID publishes no description (not that an expected file is missing). */
function agentDescriptionEndpoint(document: Record<string, unknown>, did: string): string {
  const services = Array.isArray(document.service) ? (document.service as DidDocumentService[]) : []
  const entry = services.find(
    (s) => s !== null && typeof s === 'object' && s.type === AGENT_DESCRIPTION_SERVICE_TYPE,
  )
  const endpoint = entry?.serviceEndpoint
  if (typeof endpoint !== 'string' || endpoint === '') {
    throw new ConnectxError(
      'ad_not_found',
      `DID document for "${did}" has no ${AGENT_DESCRIPTION_SERVICE_TYPE} service entry, so this DID publishes no agent description`,
    )
  }
  try {
    new URL(endpoint)
  } catch {
    throw new ConnectxError(
      'ad_fetch_failed',
      `The ${AGENT_DESCRIPTION_SERVICE_TYPE} service entry of "${did}" is not an absolute URL ("${endpoint}")`,
    )
  }
  return endpoint
}

/** The ANP protocol version a description declares. ANP-07 1.2 names `"1.0.0"` as
 *  current. This is the ANP version, not this SDK's — they move independently. */
export const ANP_PROTOCOL_VERSION = '1.0.0'

/** The security scheme the SDK's own client satisfies: ANP-02's `did:wba` proof,
 *  carried in an `Authorization` header. A server reading this should expect the
 *  same thing `verifyAnpLoginRequest` checks. */
export const ANP_SECURITY_SCHEME = 'didwba_sc'

/** Input for `buildAgentDescription`. Only `name` is required of the caller — the
 *  protocol fields are the SDK's own vocabulary, and the security block defaults to
 *  the did:wba scheme this SDK implements. */
export interface AgentDescriptionInput {
  name: string
  /** The DID that publishes this description. Omit when the description is written
   *  before the identity exists; the field is optional and absence is legal. */
  did?: string
  /** Public address of the agent (ANP-07 `url`), distinct from the ad.json's own URL. */
  url?: string
  description?: string
  owner?: Record<string, unknown>
  /** WNS handle (ANP-04 §7.2), when the agent has one. */
  handle?: string
  interfaces?: unknown[]
  /** Spelled as ANP-07 spells it — see the field's note on `AgentDescription`. */
  Infomations?: unknown[]
  /** Defaults to the did:wba definition ANP-07's own example uses, under the name
   *  `didwba_sc`. Pass your own together with `security` when the agent
   *  authenticates otherwise. */
  securityDefinitions?: Record<string, unknown>
  /** Names the enabled definition in `securityDefinitions`. Defaults to
   *  `didwba_sc`, so it must be set whenever `securityDefinitions` is. */
  security?: string
  /** ANP protocol version to declare. Defaults to `ANP_PROTOCOL_VERSION`. */
  protocolVersion?: string
  /** ISO 8601 creation time. Omit for no `created` field at all — the SDK does not
   *  stamp a clock into a document that may be written to disk. */
  created?: string
}

/** The default `securityDefinitions` entry: ANP-02's `did:wba` proof in an
 *  `Authorization` header, exactly as ANP-07's own example spells it. */
const DIDWBA_SECURITY_DEFINITION = {
  scheme: 'didwba',
  in: 'header',
  name: 'Authorization',
} as const

/**
 * Build a minimal but WELL-FORMED ANP-07 agent description — the inverse of
 * `assertAgentDescription`, and the document a caller hosts so other agents can
 * discover it. A document from here passes the reader's checks by construction.
 *
 * Hosting it is only half the job: the description is reachable solely through a
 * `service` entry in the DID document (see `agentDescriptionService`), and that
 * entry has to be inside the document BEFORE it is signed.
 */
export function buildAgentDescription(input: AgentDescriptionInput): AgentDescription {
  const security = input.security ?? ANP_SECURITY_SCHEME
  const securityDefinitions = input.securityDefinitions ?? { [ANP_SECURITY_SCHEME]: DIDWBA_SECURITY_DEFINITION }
  if (!(security in securityDefinitions)) {
    // A `security` naming nothing would leave every reader with a description that
    // points at an undefined mechanism — cheap to catch here, impossible to un-ship.
    throw new ConnectxError(
      'invalid_argument',
      `security "${security}" is not defined in securityDefinitions (have: ${Object.keys(securityDefinitions).join(', ') || 'none'})`,
    )
  }
  return {
    protocolType: 'ANP',
    protocolVersion: input.protocolVersion ?? ANP_PROTOCOL_VERSION,
    type: 'AgentDescription',
    name: input.name,
    securityDefinitions,
    security,
    ...(input.did == null ? {} : { did: input.did }),
    ...(input.url == null ? {} : { url: input.url }),
    ...(input.description == null ? {} : { description: input.description }),
    ...(input.owner == null ? {} : { owner: input.owner }),
    ...(input.handle == null ? {} : { handle: input.handle }),
    ...(input.interfaces == null ? {} : { interfaces: input.interfaces }),
    ...(input.Infomations == null ? {} : { Infomations: input.Infomations }),
    ...(input.created == null ? {} : { created: input.created }),
  }
}

/**
 * The DID-document `service` entry that publishes `endpoint` as this DID's agent
 * description. This entry IS the locator: ANP defines no path for `ad.json`, so a
 * document without it publishes nothing anyone can find.
 *
 * The result belongs in the DID document BEFORE it is signed — `proof` covers
 * whatever was present at signing time, so an entry appended afterwards verifies
 * as a tampered document. Pass it through `createAnpIdentity` / `buildWalletIdentity`.
 */
export function agentDescriptionService(endpoint: string, did?: string): DidDocumentService {
  return {
    // Relative to the document id when the DID is not at hand — legal in DID Core,
    // and never relied on: readers key off `type` and `serviceEndpoint`.
    id: did == null ? '#agent-description' : `${did}#agent-description`,
    type: AGENT_DESCRIPTION_SERVICE_TYPE,
    serviceEndpoint: endpoint,
  }
}

const REQUIRED_STRING_FIELDS = ['protocolType', 'protocolVersion', 'type', 'name', 'security'] as const

/** Check that a fetched body really is an ANP-07 agent description before anything
 *  inside it is believed. Deliberately shallow: presence and type of the fields the
 *  spec marks Required, the one cross-document binding that matters here, and the
 *  internal consistency `buildAgentDescription` already refuses to write. */
function assertAgentDescription(body: unknown, did: string, url: string): AgentDescription {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConnectxError('ad_malformed', `Agent description from ${url} is not a JSON object`)
  }
  const doc = body as Record<string, unknown>
  for (const field of REQUIRED_STRING_FIELDS) {
    if (typeof doc[field] !== 'string' || doc[field] === '') {
      throw new ConnectxError('ad_malformed', `Agent description from ${url} is missing required field "${field}"`)
    }
  }
  if (doc.protocolType !== 'ANP') {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} declares protocolType "${String(doc.protocolType)}", not "ANP"`,
    )
  }
  if (doc.type !== 'AgentDescription') {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} declares type "${String(doc.type)}", not "AgentDescription"`,
    )
  }
  if (doc.securityDefinitions === null || typeof doc.securityDefinitions !== 'object' || Array.isArray(doc.securityDefinitions)) {
    throw new ConnectxError('ad_malformed', `Agent description from ${url} is missing required field "securityDefinitions"`)
  }
  // `security` names the one enabled definition, so a document whose `security` names
  // nothing in its own `securityDefinitions` contradicts itself. `buildAgentDescription`
  // refuses to write that document, and a reader that accepted it would hand callers a
  // "well-formed" description whose enabled mechanism does not exist — a caller doing
  // capability discovery or picking an auth mechanism would act on it. The check is
  // own-property, because `toString`, `constructor` and the rest of Object.prototype are
  // readable through any object literal in JSON without anyone having written them.
  const security = doc.security as string
  const definitions = doc.securityDefinitions as Record<string, unknown>
  if (!Object.prototype.hasOwnProperty.call(definitions, security)) {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} names security "${security}", which is not defined in securityDefinitions (have: ${Object.keys(definitions).join(', ') || 'none'})`,
    )
  }
  const definition = definitions[security]
  if (definition === null || typeof definition !== 'object' || Array.isArray(definition)) {
    const shape = definition === null ? 'null' : Array.isArray(definition) ? 'an array' : typeof definition
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} defines security "${security}" as ${shape}, not an object`,
    )
  }
  // `did` is OPTIONAL (ANP-07 1.2), so its ABSENCE is legal and must not be treated
  // as a malformed document. When it IS present it must name the DID we asked about:
  // the description is fetched from an endpoint the DID document named, but the body
  // is written by whoever serves that endpoint, so a mismatch means the content
  // belongs to some other identity and nothing in it may be attributed to this DID.
  if (doc.did !== undefined && doc.did !== did) {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} describes DID "${String(doc.did)}", but "${did}" was requested`,
    )
  }
  assertProofDomain(doc.proof, url)
  return doc as AgentDescription
}

/**
 * The host binding ANP-07 L647 makes a reader MUST:
 *
 * > "After obtaining the document, the user must verify that the domain from which the
 * > document was obtained matches the domain defined in `domain`. If they do not match,
 * > the document may be forged."
 *
 * The SIGNATURE is not checked — this SDK implements no ANP-07 cryptosuite (see `proof`
 * on {@link AgentDescription}) — but that is a separate matter from this: the domain is a
 * string the document makes about itself, and comparing it with where the bytes actually
 * came from costs nothing and cannot be skipped by an attacker who did not serve them.
 *
 * STRICTNESS, since there is no reference implementation to match (upstream's crawler
 * parses `interfaces` and does not look at `proof`): a `proof` that is not an object, or a
 * `domain` that is not a string, is REJECTED rather than skipped — a check that a shape
 * can turn off is not a check. `challenge` must be there when `domain` is (L648: "When
 * specifying domain, challenge must also be specified"). And only the HOST is compared:
 * the spec's word is "domain", the scheme and port are not part of it, and the host the
 * fetch is allowed to reach is already the caller's decision (`allowedHosts` in
 * `ResolveDidOptions`) — so a description served from a CDN host has to name that host,
 * which is what the MUST says.
 */
function assertProofDomain(proof: unknown, url: string): void {
  if (proof === undefined) return
  if (proof === null || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} has a "proof" that is ${proof === null ? 'null' : Array.isArray(proof) ? 'an array' : typeof proof}, not an object`,
    )
  }
  const { domain, challenge } = proof as { domain?: unknown; challenge?: unknown }
  if (domain === undefined) return
  if (typeof challenge !== 'string' || challenge === '') {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} names a proof domain without a challenge (ANP-07 L648)`,
    )
  }
  if (typeof domain !== 'string') {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} defines a proof domain as ${typeof domain}, not a string`,
    )
  }
  const named = hostOf(domain)
  const obtained = hostOf(url)
  if (named === undefined) {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} defines a proof domain "${domain}", which is not a host`,
    )
  }
  if (named !== obtained) {
    throw new ConnectxError(
      'ad_malformed',
      `Agent description from ${url} was obtained from "${obtained}", but its proof names domain "${domain}" (ANP-07 L647: they must match)`,
    )
  }
}

/** The host a URL, or a `domain` value that may be a bare host or a whole URL, names —
 *  lowercased, since DNS is case-insensitive and `URL` already lowercases (and
 *  punycodes) what it parses. `undefined` when it names no host at all. */
function hostOf(value: string): string | undefined {
  try {
    const url = value.includes('://') ? new URL(value) : new URL(`https://${value}`)
    return url.hostname === '' ? undefined : url.hostname
  } catch {
    return undefined
  }
}

/**
 * Fetch the public ANP-07 agent description a DID publishes, in two steps: resolve
 * the DID document, read the `service` entry whose `type` is `AgentDescription`, then
 * fetch and parse that `serviceEndpoint`.
 *
 * BOTH requests run under the same `ResolveDidOptions` network policy. That matters:
 * the second host is chosen by the DID document, not by the caller, and ANP-03 sets
 * no same-host requirement on this particular endpoint — so the only thing keeping a
 * hostile document from pointing the fetch at an internal address is that the caller
 * already named that host in `allowedHosts`. A description published on a second host
 * (a CDN, a static bucket) therefore needs that host named too; it is not reachable
 * merely because the DID's host is.
 *
 * Throws `ad_not_found` when the DID publishes no description, `ad_fetch_failed` when
 * the description cannot be retrieved, and `ad_malformed` when the body is not a
 * description. DID resolution failures surface as `did_resolve_*`.
 */
export async function fetchAgentDescription(
  did: string,
  options: ResolveDidOptions = {},
): Promise<ResolvedAgentDescription> {
  const resolved = await resolveDidDocument(did, options)
  const url = agentDescriptionEndpoint(resolved.document, did)
  const body = await fetchControlledJson(url, options, AGENT_DESCRIPTION_FETCH_CODES)
  return { did, document: assertAgentDescription(body, did, url), url, docUrl: resolved.docUrl }
}
