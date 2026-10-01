// ANP-08 Agent Discovery — the domain-wide index a host publishes at a well-known path.
//
// Three things this is NOT:
//   - NOT the ANP-07 `ad.json` itself. Every entry here is a URL that points AT one;
//     discovery answers "what does this host publish", and the caller then runs the
//     ANP-07 reader (`fetchAgentDescription`) on whichever entries it cares about.
//   - NOT JSON-LD as far as this reader is concerned. ANP-08's document IS JSON-LD
//     (`CollectionPage`, L52) and the WRITER emits the spec's own context object, but
//     the READER takes the four keys it needs — `@type`, `items[].@id`, `url`, `next`
//     — as plain JSON. Expanding them would introduce semantics nothing here uses or
//     could check. This is a deliberate split (SDKTODO1 §B0): the two ANP documents
//     are different documents, and the spec's example spells all four keys as plain
//     JSON values anyway.
//   - NOT passive discovery. Registration with a search service is defined by THAT
//     service (ANP-08 L96/L102: "These APIs are defined by the search service agents
//     themselves"), so it is a recipe, not code this SDK can write for someone else.

import { ConnectxError, isConnectxError } from '../errors'
import { fetchControlledJson } from './resolveDid'
import type { FetchErrorCodes, ResolveDidOptions } from './resolveDid'

/** The path ANP-08 L45 fixes for the entry page: `https://{domain}/.well-known/agent-descriptions`. */
export const AGENT_DESCRIPTIONS_PATH = '/.well-known/agent-descriptions'

/** The JSON-LD context ANP-08's own example (L69–73) writes. Emitted verbatim by the
 *  writer so a published page matches the spec's shape; the reader ignores it. */
const COLLECTION_PAGE_CONTEXT = {
  '@vocab': 'https://schema.org/',
  did: 'https://w3id.org/did#',
  ad: 'https://agent-network-protocol.com/ad#',
} as const

/** The `@type` ANP-08 L55 fixes for the collection page. */
const COLLECTION_PAGE_TYPE = 'CollectionPage' as const

/** The `@type` ANP-08 L61 fixes for an item. */
const COLLECTION_ITEM_TYPE = 'ad:AgentDescription' as const

/** The SDK's own bound on the pagination chain. ANP-08 L94 says only "recursively
 *  retrieve all pages until there is no `next` property" — which is unbounded, and an
 *  unbounded walk over a document a remote host controls is not a thing to implement.
 *  20 is generous for a domain's public agents; raise it per call if yours is larger. */
const DEFAULT_MAX_PAGES = 20

// One code per failure kind, mirroring the ANP-07 triple: an ANSWER (this domain
// publishes no index), a transport failure, and a document that is not a usable
// collection page. Everything a page's own content can get wrong lands in the third,
// including a pagination chain that never terminates — a page that names more pages
// than the bound, or names one twice, is not a usable collection page.
const AGENT_INDEX_FETCH_CODES: FetchErrorCodes = {
  subject: 'Agent description index',
  blocked: 'ad_index_fetch_failed',
  failed: 'ad_index_fetch_failed',
  timeout: 'ad_index_fetch_failed',
  tooLarge: 'ad_index_fetch_failed',
  tooManyRedirects: 'ad_index_fetch_failed',
  invalidDocument: 'ad_index_malformed',
}

/** The well-known URL the discovery index lives at for `origin`. `origin` may be a bare
 *  domain (`example.com`) or an origin URL (`https://example.com`); anything carrying a
 *  path, query or fragment is refused rather than silently reinterpreted, because
 *  `example.com/agents` looks like a domain and would otherwise become a valid URL
 *  pointing somewhere the caller never meant to ask. A port survives (`localhost:3000`
 *  stays `localhost:3000`), so a local dev host is reachable the same way it is
 *  everywhere else in this SDK — by naming it in `allowInsecureTransport`. */
export function agentDescriptionIndexUrl(origin: string): string {
  const trimmed = origin.trim()
  if (trimmed === '') throw new ConnectxError('invalid_argument', 'An agent discovery origin cannot be empty')
  let url: URL
  try {
    url = new URL(trimmed.includes('://') ? trimmed : `https://${trimmed}`)
  } catch {
    throw new ConnectxError(
      'invalid_argument',
      `"${origin}" is not a domain or URL an agent discovery index can live under`,
    )
  }
  if (url.hostname === '') {
    throw new ConnectxError('invalid_argument', `"${origin}" names no host`)
  }
  if (url.pathname !== '/' || url.search !== '' || url.hash !== '') {
    throw new ConnectxError(
      'invalid_argument',
      `"${origin}" carries a path, query or fragment; an agent discovery origin is a bare domain (the well-known path is appended)`,
    )
  }
  return `${url.origin}${AGENT_DESCRIPTIONS_PATH}`
}

/** Write-side input for `buildAgentDescriptionIndex`: one public agent description. */
export interface AgentDescriptionIndexInput {
  /** URL of the agent description document (ANP-08 L63). Absolute: every URL in an
   *  ANP-08 document is, and a relative one has no base to resolve against — the page
   *  a reader obtained the document from is not necessarily the page's own `url`. */
  id: string
  /** Agent name (ANP-08 L62). Required here because a WRITER must produce a conforming
   *  document; the reader accepts its absence (see `AgentDescriptionIndexEntry`). */
  name: string
}

/** A published ANP-08 collection page (the writer's output). */
export interface AgentDescriptionIndex {
  '@context': typeof COLLECTION_PAGE_CONTEXT
  '@type': typeof COLLECTION_PAGE_TYPE
  /** URL of the current page (ANP-08 L56). */
  url: string
  items: Array<{ '@type': typeof COLLECTION_ITEM_TYPE; name: string; '@id': string }>
  /** The next page, when the collection is paginated (ANP-08 L58). */
  next?: string
}

/** Read-side: one entry of a fetched collection page. */
export interface AgentDescriptionIndexEntry {
  /** URL of the agent description document (ANP-08 L63) — the one thing a caller needs,
   *  since it is what `fetchAgentDescription` takes. Absolute URL. */
  id: string
  /** Agent name (ANP-08 L62), carried through when the page declares one. The reader
   *  does not require it: the spec's Required fields are the writer's business, and
   *  refusing a page over a display label would cost the caller every entry in it. */
  name?: string
}

/** Read-side: one fetched page, with where it came from. */
export interface AgentDescriptionIndexPage {
  /** The URL this page was actually fetched from — the real hop, whether the entry page
   *  or a `next`. */
  url: string
  /** The page's own `url` field (L56), when it declares one. NOT compared against the
   *  fetch URL: ANP-08 states no MUST for it, and unlike ANP-07's `proof.domain` a lie
   *  here aims nothing — every entry's `@id` is absolute and is fetched under the
   *  caller's own `allowedHosts`, not under whatever the page claims about itself. */
  declaredUrl?: string
  entries: AgentDescriptionIndexEntry[]
  /** The next page this page names (ANP-08 L58), when it names one. Absolute URL. */
  next?: string
}

/** What `fetchAgentDescriptionIndex` returns. */
export interface ResolvedAgentDescriptionIndex {
  /** The domain asked about, as the well-known URL's origin. */
  origin: string
  /** The entry URL the well-known path resolves to (ANP-08 L45). */
  url: string
  /** Every page followed, in order — the pagination provenance, which nothing else in
   *  the result can reconstruct. */
  pages: AgentDescriptionIndexPage[]
  /** All entries across all pages, deduplicated by `@id`, in first-seen order. */
  entries: AgentDescriptionIndexEntry[]
}

/** `ResolveDidOptions` plus the one bound ANP-08 leaves out. */
export interface AgentDescriptionIndexOptions extends ResolveDidOptions {
  /** Maximum pages to follow before failing. Default 20. The walk fails rather than
   *  truncating: a caller that got back a shorter list could not tell a domain with few
   *  agents from one whose chain the SDK stopped walking. */
  maxPages?: number
}

/** ANP-08 says nothing about a URL's shape beyond calling it a URL, so the one rule
 *  this reader enforces is the one it needs: absolute. A relative reference has to be
 *  resolved against something, and the only candidate is the page — whose own `url`
 *  field the document may or may not have got right. Refusing is the honest answer. */
function absoluteUrl(value: unknown, what: string, url: string): string {
  if (typeof value !== 'string' || value === '') {
    throw new ConnectxError('ad_index_malformed', `Agent description index from ${url} has ${what} that is not a URL`)
  }
  try {
    new URL(value)
  } catch {
    throw new ConnectxError(
      'ad_index_malformed',
      `Agent description index from ${url} has ${what} "${value}" that is not an absolute URL`,
    )
  }
  return value
}

/** Check that a fetched body is a usable ANP-08 collection page. Deliberately shallow,
 *  like the ANP-07 reader: the fields a caller acts on, and nothing the SDK would only
 *  be guessing at. `@context` is not inspected — the reader takes plain JSON keys
 *  (§B0), and a page's context object is the writer's concern. */
function assertCollectionPage(body: unknown, url: string): AgentDescriptionIndexPage {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ConnectxError('ad_index_malformed', `Agent description index from ${url} is not a JSON object`)
  }
  const doc = body as Record<string, unknown>
  if (doc['@type'] !== COLLECTION_PAGE_TYPE) {
    throw new ConnectxError(
      'ad_index_malformed',
      `Agent description index from ${url} declares @type "${String(doc['@type'])}", not "${COLLECTION_PAGE_TYPE}"`,
    )
  }
  if (!Array.isArray(doc.items)) {
    throw new ConnectxError('ad_index_malformed', `Agent description index from ${url} has no "items" array`)
  }
  const entries: AgentDescriptionIndexEntry[] = doc.items.map((item, at) => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) {
      throw new ConnectxError('ad_index_malformed', `Agent description index from ${url} has an item at index ${at} that is not an object`)
    }
    const entry = item as Record<string, unknown>
    const id = absoluteUrl(entry['@id'], `an "@id" on the item at index ${at}`, url)
    if (entry.name !== undefined && typeof entry.name !== 'string') {
      throw new ConnectxError(
        'ad_index_malformed',
        `Agent description index from ${url} has a "name" at index ${at} that is ${typeof entry.name}, not a string`,
      )
    }
    return entry.name === undefined ? { id } : { id, name: entry.name as string }
  })
  const declaredUrl =
    doc.url === undefined ? undefined : absoluteUrl(doc.url, 'a "url"', url)
  const next = doc.next === undefined ? undefined : absoluteUrl(doc.next, 'a "next"', url)
  return { url, ...(declaredUrl === undefined ? {} : { declaredUrl }), entries, ...(next === undefined ? {} : { next }) }
}

// The entry page answering 404 / 410 is an ANSWER, not a failure to retry: this domain
// publishes no discovery index. Same distinction, and the same two statuses, as
// `handle_not_found` (§4.8). A LATER page is not rewritten — a 404 midway through a
// pagination chain is a broken chain, which is what `ad_index_fetch_failed` says.
async function fetchEntryPage(url: string, options: AgentDescriptionIndexOptions): Promise<unknown> {
  try {
    return await fetchControlledJson(url, options, AGENT_INDEX_FETCH_CODES)
  } catch (err) {
    if (isConnectxError(err) && (err.status === 404 || err.status === 410)) {
      throw new ConnectxError('ad_index_not_found', `No agent discovery index at ${url} (${err.status})`, {
        cause: err,
        status: err.status,
      })
    }
    throw err
  }
}

/**
 * Read the ANP-08 discovery index a domain publishes, following `next` until there is
 * none (L94) and flattening every page's entries into one deduplicated list.
 *
 * The fetch runs under the same `ResolveDidOptions` policy as every other outbound
 * request in this SDK — allowlist, resolved-address check, byte cap, timeout, media
 * type — and that policy is what bounds `next`: the pages come from the DOCUMENT, not
 * from the caller, so a `next` pointing at a host the caller never allowed is refused
 * there. A paginated index on a second host (a CDN) therefore needs that host named in
 * `allowedHosts`, exactly like an `ad.json` served from one.
 *
 * An entry's `@id` is NOT fetched and NOT checked against the allowlist here: discovery
 * reports what a domain publishes. Fetching a description is `fetchAgentDescription`,
 * which enforces that caller's hosts on the second request.
 *
 * Throws `invalid_argument` for an origin that is not a domain, `ad_index_not_found`
 * when the domain publishes no index, `ad_index_fetch_failed` when a page cannot be
 * fetched (network / timeout / size cap / too many redirects / refused by the policy),
 * and `ad_index_malformed` when a page is not a usable collection page or the
 * pagination chain does not terminate within `maxPages`.
 */
export async function fetchAgentDescriptionIndex(
  origin: string,
  options: AgentDescriptionIndexOptions = {},
): Promise<ResolvedAgentDescriptionIndex> {
  const url = agentDescriptionIndexUrl(origin)
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES
  const pages: AgentDescriptionIndexPage[] = []
  const seen = new Set<string>()
  let current = url

  for (;;) {
    if (seen.has(current)) {
      throw new ConnectxError(
        'ad_index_malformed',
        `Agent description index at ${url} does not terminate: "next" points back to ${current}, which was already followed`,
      )
    }
    if (pages.length >= maxPages) {
      throw new ConnectxError(
        'ad_index_malformed',
        `Agent description index at ${url} has more than ${maxPages} pages; raise maxPages to follow a chain this long`,
      )
    }
    seen.add(current)
    const body = await (pages.length === 0 ? fetchEntryPage(current, options) : fetchControlledJson(current, options, AGENT_INDEX_FETCH_CODES))
    const page = assertCollectionPage(body, current)
    pages.push(page)
    const next = page.next
    if (next === undefined) break
    current = next
  }

  // Deduplicated by `@id`, first-seen wins: the same agent listed on two pages is one
  // agent, and the caller asked what this domain publishes, not how it paginates.
  const entries: AgentDescriptionIndexEntry[] = []
  const byId = new Set<string>()
  for (const page of pages) {
    for (const entry of page.entries) {
      if (byId.has(entry.id)) continue
      byId.add(entry.id)
      entries.push(entry)
    }
  }
  return { origin: new URL(url).origin, url, pages, entries }
}

/**
 * Build an ANP-08 collection page — the document a domain hosts at
 * `agentDescriptionIndexUrl(origin)` so other agents can find what it publishes. The
 * inverse of `assertCollectionPage`, and shaped after the spec's own example (L67–90).
 *
 * `url` is required rather than defaulted: the page has to state where it lives (L56),
 * and the only party that knows is the one putting the file in place. Pass
 * `agentDescriptionIndexUrl(domain)`.
 *
 * One publishing bug is refused rather than written through: duplicate `@id`s. The
 * READER deduplicates silently — a caller sees one agent either way — so a page that
 * lists the same description twice is only discoverable as a mistake here.
 */
export function buildAgentDescriptionIndex(input: {
  url: string
  items: AgentDescriptionIndexInput[]
  next?: string
}): AgentDescriptionIndex {
  const url = input.url
  if (typeof url !== 'string' || url === '') {
    throw new ConnectxError('invalid_argument', 'buildAgentDescriptionIndex needs the URL the page will live at')
  }
  try {
    new URL(url)
  } catch {
    throw new ConnectxError('invalid_argument', `"${url}" is not an absolute URL`)
  }
  const seen = new Set<string>()
  const items = input.items.map((item) => {
    const id = item.id
    if (typeof id !== 'string' || id === '') {
      throw new ConnectxError('invalid_argument', `An index entry for "${item.name}" has no "@id" URL`)
    }
    try {
      new URL(id)
    } catch {
      throw new ConnectxError('invalid_argument', `Index entry "${id}" for "${item.name}" is not an absolute URL`)
    }
    if (seen.has(id)) {
      throw new ConnectxError('invalid_argument', `Index lists "${id}" more than once`)
    }
    seen.add(id)
    return { '@type': COLLECTION_ITEM_TYPE, name: item.name, '@id': id }
  })
  return {
    '@context': COLLECTION_PAGE_CONTEXT,
    '@type': COLLECTION_PAGE_TYPE,
    url,
    items,
    ...(input.next == null ? {} : { next: input.next }),
  }
}
