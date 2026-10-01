import { describe, it, expect } from 'vitest'
import {
  AGENT_DESCRIPTIONS_PATH,
  agentDescriptionIndexUrl,
  buildAgentDescriptionIndex,
  fetchAgentDescriptionIndex,
} from './agentDiscovery'

const ORIGIN = 'example.com'
const INDEX_URL = `https://example.com${AGENT_DESCRIPTIONS_PATH}`
const CDN = 'cdn.example.net'
const CDN_URL = `https://${CDN}${AGENT_DESCRIPTIONS_PATH}`

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  })
}

// Route by URL so one stub serves every page in a chain. Anything unrouted is a 404 —
// which the "later page missing" test relies on.
function routedFetch(over: Record<string, () => Response> = {}) {
  return async (url: string): Promise<Response> => {
    const canned = over[url]
    if (canned) return canned()
    return new Response('not found', { status: 404 })
  }
}

const publicResolve = async () => ['93.184.216.34']

function opts(extra: Record<string, unknown> = {}) {
  return {
    allowedHosts: [ORIGIN, CDN],
    resolveAddresses: publicResolve,
    allowUncontrolledFetch: true,
    ...extra,
  }
}

function page(items: unknown[], extra: Record<string, unknown> = {}) {
  return { '@type': 'CollectionPage', url: INDEX_URL, items, ...extra }
}

const ITEM = { '@type': 'ad:AgentDescription', name: 'Smart Assistant', '@id': `https://${ORIGIN}/agents/a/ad.json` }

describe('agentDescriptionIndexUrl', () => {
  it('appends the well-known path to a bare domain', () => {
    expect(agentDescriptionIndexUrl('example.com')).toBe(INDEX_URL)
    expect(AGENT_DESCRIPTIONS_PATH).toBe('/.well-known/agent-descriptions')
  })

  it('accepts an origin URL, a trailing slash and uppercase — URL normalizes all three', () => {
    for (const origin of ['https://example.com', 'https://example.com/', 'EXAMPLE.COM']) {
      expect(agentDescriptionIndexUrl(origin)).toBe(INDEX_URL)
    }
  })

  it('keeps a port, so a local dev host stays reachable', () => {
    expect(agentDescriptionIndexUrl('http://localhost:3000')).toBe(
      `http://localhost:3000${AGENT_DESCRIPTIONS_PATH}`,
    )
  })

  it('refuses input that is not a bare domain', () => {
    // `example.com/agents` reads like a domain and would otherwise become a valid URL
    // pointing somewhere the caller never asked about.
    expect(() => agentDescriptionIndexUrl('')).toThrow(/cannot be empty/)
    expect(() => agentDescriptionIndexUrl('example.com/agents')).toThrow(/carries a path/)
    expect(() => agentDescriptionIndexUrl('example.com?a=1')).toThrow(/carries a path/)
    expect(() => agentDescriptionIndexUrl('https://')).toThrow(/names no host|not a domain/)
  })
})

describe('fetchAgentDescriptionIndex', () => {
  it('reads one page and reports where it came from', async () => {
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({ fetch: routedFetch({ [INDEX_URL]: () => json(page([ITEM])) }) }) as never,
    )
    expect(index.origin).toBe(`https://${ORIGIN}`)
    expect(index.url).toBe(INDEX_URL)
    expect(index.pages).toHaveLength(1)
    expect(index.pages[0]!.url).toBe(INDEX_URL)
    expect(index.pages[0]!.declaredUrl).toBe(INDEX_URL)
    expect(index.entries).toEqual([{ id: ITEM['@id'], name: 'Smart Assistant' }])
  })

  it('accepts an item with no `name` — a display label is not worth the whole page', async () => {
    const bare = { '@type': 'ad:AgentDescription', '@id': `https://${ORIGIN}/agents/b/ad.json` }
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({ fetch: routedFetch({ [INDEX_URL]: () => json(page([bare])) }) }) as never,
    )
    expect(index.entries).toEqual([{ id: bare['@id'] }])
    expect(index.entries[0]).not.toHaveProperty('name')
  })

  it('follows `next` until there is none (ANP-08 L94) and reports the pages in order', async () => {
    const NEXT = `${INDEX_URL}?page=2`
    const second = { '@type': 'ad:AgentDescription', name: 'Support', '@id': `https://${ORIGIN}/agents/c/ad.json` }
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({
        fetch: routedFetch({
          [INDEX_URL]: () => json(page([ITEM], { next: NEXT })),
          [NEXT]: () => json({ '@type': 'CollectionPage', items: [second] }),
        }),
      }) as never,
    )
    expect(index.pages.map((p) => p.url)).toEqual([INDEX_URL, NEXT])
    expect(index.entries.map((e) => e.id)).toEqual([ITEM['@id'], second['@id']])
  })

  it('deduplicates by `@id` across pages, keeping the first sighting', async () => {
    const NEXT = `${INDEX_URL}?page=2`
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({
        fetch: routedFetch({
          [INDEX_URL]: () => json(page([ITEM], { next: NEXT })),
          [NEXT]: () => json(page([{ ...ITEM, name: 'Renamed' }])),
        }),
      }) as never,
    )
    expect(index.entries).toEqual([{ id: ITEM['@id'], name: 'Smart Assistant' }])
  })

  it('follows a `next` on another host the caller allowlisted, the same way an ad.json does', async () => {
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({
        fetch: routedFetch({
          [INDEX_URL]: () => json(page([ITEM], { next: CDN_URL })),
          [CDN_URL]: () => json(page([])),
        }),
      }) as never,
    )
    expect(index.pages.map((p) => p.url)).toEqual([INDEX_URL, CDN_URL])
  })

  it('refuses a `next` host the caller did not allowlist — the document chose that host', async () => {
    let reached = false
    await expect(
      fetchAgentDescriptionIndex(
        ORIGIN,
        opts({
          allowedHosts: [ORIGIN], // NOT cdn.example.net
          fetch: async (url: string) => {
            if (url === CDN_URL) reached = true
            return routedFetch({ [INDEX_URL]: () => json(page([ITEM], { next: CDN_URL })) })(url)
          },
        }) as never,
      ),
    ).rejects.toThrow(/not in the allowed hosts list/)
    expect(reached).toBe(false)
  })

  it('reports `ad_index_not_found` when the domain publishes no index', async () => {
    await expect(
      fetchAgentDescriptionIndex(ORIGIN, opts({ fetch: routedFetch() }) as never),
    ).rejects.toThrow(/No agent discovery index at .*\(404\)/)
  })

  it('reports `ad_index_fetch_failed` when a LATER page is missing — a broken chain, not an answer', async () => {
    const NEXT = `${INDEX_URL}?page=2`
    await expect(
      fetchAgentDescriptionIndex(
        ORIGIN,
        opts({ fetch: routedFetch({ [INDEX_URL]: () => json(page([ITEM], { next: NEXT })) }) }) as never,
      ),
    ).rejects.toThrow(/Failed to fetch Agent description index from .*page=2 \(404\)/)
  })

  it('refuses a pagination chain that loops back', async () => {
    await expect(
      fetchAgentDescriptionIndex(
        ORIGIN,
        opts({ fetch: routedFetch({ [INDEX_URL]: () => json(page([ITEM], { next: INDEX_URL })) }) }) as never,
      ),
    ).rejects.toThrow(/does not terminate: "next" points back to/)
  })

  it('refuses to truncate at maxPages — a short list would be indistinguishable from a small domain', async () => {
    const p1 = INDEX_URL
    const p2 = `${INDEX_URL}?page=2`
    const p3 = `${INDEX_URL}?page=3`
    await expect(
      fetchAgentDescriptionIndex(
        ORIGIN,
        opts({
          maxPages: 2,
          fetch: routedFetch({
            [p1]: () => json(page([ITEM], { next: p2 })),
            [p2]: () => json(page([], { next: p3 })),
            [p3]: () => json(page([])),
          }),
        }) as never,
      ),
    ).rejects.toThrow(/has more than 2 pages; raise maxPages/)
  })

  it('reports `ad_index_malformed` for a body that is not a collection page', async () => {
    const cases: Array<[unknown, RegExp]> = [
      [[], /is not a JSON object/],
      [{}, /declares @type "undefined", not "CollectionPage"/],
      [{ '@type': 'ItemList', items: [] }, /declares @type "ItemList"/],
      [{ '@type': 'CollectionPage' }, /has no "items" array/],
      [{ '@type': 'CollectionPage', items: 'x' }, /has no "items" array/],
      [page(['nope']), /item at index 0 that is not an object/],
      [page([{ name: 'x' }]), /has an "@id" on the item at index 0 that is not a URL/],
      [page([{ '@id': '/agents/a/ad.json' }]), /"\/agents\/a\/ad\.json" that is not an absolute URL/],
      [page([{ '@id': ITEM['@id'], name: 7 }]), /has a "name" at index 0 that is number, not a string/],
      [page([ITEM], { url: 'nope' }), /has a "url" "nope" that is not an absolute URL/],
      [page([ITEM], { next: '/page=2' }), /has a "next" "\/page=2" that is not an absolute URL/],
    ]
    for (const [body, message] of cases) {
      await expect(
        fetchAgentDescriptionIndex(ORIGIN, opts({ fetch: routedFetch({ [INDEX_URL]: () => json(body) }) }) as never),
      ).rejects.toThrow(message)
    }
  })

  it('carries a declaration through without trusting it — a wrong `url` is reported, not rejected', async () => {
    // ANP-08 states no MUST for `url`, and a lie here aims nothing: every `@id` is
    // absolute and is fetched under the caller's own allowlist.
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({ fetch: routedFetch({ [INDEX_URL]: () => json(page([ITEM], { url: `https://elsewhere.test/x` })) }) }) as never,
    )
    expect(index.pages[0]!.declaredUrl).toBe('https://elsewhere.test/x')
    expect(index.pages[0]!.url).toBe(INDEX_URL)
  })

  it('fails closed with no allowedHosts — the index is never even fetched', async () => {
    let fetched = false
    await expect(
      fetchAgentDescriptionIndex(ORIGIN, {
        allowUncontrolledFetch: true,
        fetch: async () => {
          fetched = true
          return json(page([]))
        },
      } as never),
    ).rejects.toThrow(/allowedHosts/)
    expect(fetched).toBe(false)
  })
})

// The write half. These matter because the reader and the writer must agree on the
// shape: a page this SDK publishes is one this SDK can consume, byte for byte.
describe('buildAgentDescriptionIndex', () => {
  it("emits ANP-08's own shape, down to the context object the spec's example uses", () => {
    const built = buildAgentDescriptionIndex({
      url: INDEX_URL,
      items: [{ id: ITEM['@id'], name: 'Smart Assistant' }],
    })
    expect(built).toEqual({
      '@context': {
        '@vocab': 'https://schema.org/',
        did: 'https://w3id.org/did#',
        ad: 'https://agent-network-protocol.com/ad#',
      },
      '@type': 'CollectionPage',
      url: INDEX_URL,
      items: [{ '@type': 'ad:AgentDescription', name: 'Smart Assistant', '@id': ITEM['@id'] }],
    })
    expect(built).not.toHaveProperty('next')
  })

  it('produces a page the reader accepts unchanged', async () => {
    const built = buildAgentDescriptionIndex({
      url: INDEX_URL,
      items: [{ id: ITEM['@id'], name: 'Smart Assistant' }],
      next: `${INDEX_URL}?page=2`,
    })
    const index = await fetchAgentDescriptionIndex(
      ORIGIN,
      opts({
        fetch: routedFetch({
          [INDEX_URL]: () => json(built),
          [`${INDEX_URL}?page=2`]: () => json(buildAgentDescriptionIndex({ url: `${INDEX_URL}?page=2`, items: [] })),
        }),
      }) as never,
    )
    expect(index.pages[0]!.declaredUrl).toBe(INDEX_URL)
    expect(index.entries).toEqual([{ id: ITEM['@id'], name: 'Smart Assistant' }])
  })

  it('refuses a duplicate `@id` — the reader deduplicates silently, so only the writer can catch it', () => {
    expect(() =>
      buildAgentDescriptionIndex({
        url: INDEX_URL,
        items: [
          { id: ITEM['@id'], name: 'A' },
          { id: ITEM['@id'], name: 'B' },
        ],
      }),
    ).toThrow(/lists ".*" more than once/)
  })

  it('refuses a relative or empty URL instead of publishing something a reader must reject', () => {
    expect(() => buildAgentDescriptionIndex({ url: '/x', items: [] })).toThrow(/is not an absolute URL/)
    expect(() => buildAgentDescriptionIndex({ url: '', items: [] })).toThrow(/needs the URL/)
    expect(() =>
      buildAgentDescriptionIndex({ url: INDEX_URL, items: [{ id: '/a/ad.json', name: 'A' }] }),
    ).toThrow(/is not an absolute URL/)
    expect(() =>
      buildAgentDescriptionIndex({ url: INDEX_URL, items: [{ id: '', name: 'A' }] }),
    ).toThrow(/has no "@id" URL/)
  })

  it('round-trips the URL a publisher derives from its own domain', () => {
    const built = buildAgentDescriptionIndex({ url: agentDescriptionIndexUrl('example.com'), items: [] })
    expect(built.url).toBe(INDEX_URL)
  })
})
