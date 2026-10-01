import { describe, it, expect } from 'vitest'
import {
  agentDescriptionService,
  buildAgentDescription,
  fetchAgentDescription,
} from './agentDescription'
import { createDidDocumentStore, verifyDidDocument } from './resolveDid'
import { createAnpIdentity } from './signer'
import { AGENT_DESCRIPTION_SERVICE_TYPE } from './didDocument'

const DID = 'did:web:example.com'
const DOC_URL = 'https://example.com/.well-known/did.json'
const AD_URL = 'https://cdn.example.net/agents/alice/ad.json'
const AD_HOST = 'cdn.example.net'

// A minimal ANP-07 document: exactly the fields the spec marks Required.
const ad = {
  protocolType: 'ANP',
  protocolVersion: '1.0.0',
  type: 'AgentDescription',
  name: "Alice's Agent",
  did: DID,
  securityDefinitions: { didwba_sc: { scheme: 'didwba', in: 'header', name: 'Authorization' } },
  security: 'didwba_sc',
}

const SERVICE = [{ id: `${DID}#ad`, type: 'AgentDescription', serviceEndpoint: AD_URL }]

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  })
}

// Route by URL so one stub serves both hops. `over` replaces the canned body for a
// URL; anything unrouted is a 404, which no test here relies on.
function routedFetch(over: Record<string, () => Response> = {}) {
  return async (url: string): Promise<Response> => {
    const canned = over[url]
    if (canned) return canned()
    if (url === DOC_URL) return json({ id: DID, service: SERVICE })
    if (url === AD_URL) return json(ad)
    return new Response('not found', { status: 404 })
  }
}

// Deterministic and offline: the allowlisted host resolves to a public address
// instead of doing a real DNS lookup. No test here opens a socket.
const publicResolve = async () => ['93.184.216.34']

function opts(extra: Record<string, unknown> = {}) {
  return {
    // BOTH hosts. The description lives on a different host from the DID, and the
    // second fetch answers to the same allowlist — see the dedicated test below.
    allowedHosts: ['example.com', AD_HOST],
    resolveAddresses: publicResolve,
    allowUncontrolledFetch: true,
    ...extra,
  }
}

describe('fetchAgentDescription', () => {
  it('locates the description through the DID document service entry and parses it', async () => {
    const resolved = await fetchAgentDescription(DID, opts({ fetch: routedFetch() }) as never)
    expect(resolved.did).toBe(DID)
    expect(resolved.url).toBe(AD_URL)
    expect(resolved.docUrl).toBe(DOC_URL)
    expect(resolved.document.name).toBe("Alice's Agent")
    expect(resolved.document.security).toBe('didwba_sc')
  })

  it('accepts a description with no `did` — ANP-07 1.2 makes it optional', async () => {
    const { did: _omit, ...withoutDid } = ad
    const resolved = await fetchAgentDescription(
      DID,
      opts({ fetch: routedFetch({ [AD_URL]: () => json(withoutDid) }) }) as never,
    )
    expect(resolved.document.did).toBeUndefined()
  })

  it('rejects a description whose `did` names a different identity', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({ fetch: routedFetch({ [AD_URL]: () => json({ ...ad, did: 'did:web:evil.test' }) }) }) as never,
      ),
    ).rejects.toThrow(/describes DID "did:web:evil.test"/)
  })

  // --- the proof's host binding (ANP-07 L647) ----------------------------------
  // The SIGNATURE is still not verified — this SDK implements no ANP-07 cryptosuite. What
  // is checked is the string the document makes about where it lives, against where it
  // actually came from. The description here is served from a CDN host on purpose, so
  // "which host" is a question the tests can get wrong.
  const proofFetch = (proof: unknown) =>
    opts({ fetch: routedFetch({ [AD_URL]: () => json({ ...ad, proof }) }) }) as never

  it('accepts a proof whose domain is the host the description was obtained from', async () => {
    const resolved = await fetchAgentDescription(
      DID,
      proofFetch({ domain: AD_HOST, challenge: 'c-1', proofValue: 'z3Do…' }),
    )
    expect(resolved.document.proof?.domain).toBe(AD_HOST)
  })

  it('compares the HOST, so a domain written as a URL or with a port still binds', async () => {
    for (const domain of [`https://${AD_HOST}/`, `${AD_HOST}:8443`, AD_HOST.toUpperCase()]) {
      await expect(fetchAgentDescription(DID, proofFetch({ domain, challenge: 'c-1' }))).resolves.toBeDefined()
    }
  })

  it('rejects a proof that names a domain the description did not come from', async () => {
    // The DID's own host, not the CDN's: the document claiming it lives where it does not
    // is exactly the forgery L647 exists for.
    await expect(
      fetchAgentDescription(DID, proofFetch({ domain: 'example.com', challenge: 'c-1' })),
    ).rejects.toThrow(/was obtained from "cdn.example.net", but its proof names domain "example.com"/)
  })

  it('rejects a proof domain without a challenge — L648 pairs them', async () => {
    await expect(fetchAgentDescription(DID, proofFetch({ domain: AD_HOST }))).rejects.toThrow(
      /names a proof domain without a challenge/,
    )
  })

  it('rejects a proof shape that would make the domain check unreadable, rather than skipping it', async () => {
    // Each of these would otherwise read as "no domain to compare" — a check an attacker
    // can switch off by sending a string or a number is not a check.
    await expect(fetchAgentDescription(DID, proofFetch('trusted.example'))).rejects.toThrow(
      /has a "proof" that is string, not an object/,
    )
    await expect(fetchAgentDescription(DID, proofFetch([]))).rejects.toThrow(
      /has a "proof" that is an array, not an object/,
    )
    await expect(
      fetchAgentDescription(DID, proofFetch({ domain: 42, challenge: 'c-1' })),
    ).rejects.toThrow(/defines a proof domain as number, not a string/)
    await expect(
      fetchAgentDescription(DID, proofFetch({ domain: 'not a host', challenge: 'c-1' })),
    ).rejects.toThrow(/is not a host/)
  })

  it('reports `ad_not_found` when the DID document publishes no service at all', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({ fetch: routedFetch({ [DOC_URL]: () => json({ id: DID }) }) }) as never,
      ),
    ).rejects.toThrow(/no AgentDescription service entry/)
  })

  it('ignores service entries of other types', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({
          fetch: routedFetch({
            [DOC_URL]: () =>
              json({
                id: DID,
                service: [{ id: `${DID}#handle`, type: 'ANPHandleService', serviceEndpoint: 'https://example.com/.well-known/handle/alice' }],
              }),
          }),
        }) as never,
      ),
    ).rejects.toThrow(/no AgentDescription service entry/)
  })

  it('rejects a serviceEndpoint that is not an absolute URL', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({
          fetch: routedFetch({
            [DOC_URL]: () => json({ id: DID, service: [{ id: `${DID}#ad`, type: 'AgentDescription', serviceEndpoint: '/agents/alice/ad.json' }] }),
          }),
        }) as never,
      ),
    ).rejects.toThrow(/not an absolute URL/)
  })

  it('reports `ad_malformed` when the body is not JSON', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({ fetch: routedFetch({ [AD_URL]: () => new Response('<html>', { status: 200, headers: { 'content-type': 'application/json' } }) }) }) as never,
      ),
    ).rejects.toThrow(/is not valid JSON/)
  })

  it('reports `ad_malformed` when a required field is missing', async () => {
    const { security: _omit, ...withoutSecurity } = ad
    await expect(
      fetchAgentDescription(DID, opts({ fetch: routedFetch({ [AD_URL]: () => json(withoutSecurity) }) }) as never),
    ).rejects.toThrow(/missing required field "security"/)
  })

  // The reader and the writer have to agree: `buildAgentDescription` refuses to write a
  // document whose `security` names nothing, so a reader that accepted one would report a
  // self-contradicting document as well-formed and hand it to a caller doing capability
  // discovery or picking an auth mechanism.
  it('reports `ad_malformed` when `security` names nothing in securityDefinitions', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({ fetch: routedFetch({ [AD_URL]: () => json({ ...ad, security: 'nope' }) }) }) as never,
      ),
    ).rejects.toThrow(/names security "nope", which is not defined in securityDefinitions \(have: didwba_sc\)/)
  })

  it('does not count an inherited member as a definition', async () => {
    // `toString` is readable through any object and nobody wrote it into this document.
    await expect(
      fetchAgentDescription(
        DID,
        opts({ fetch: routedFetch({ [AD_URL]: () => json({ ...ad, security: 'toString' }) }) }) as never,
      ),
    ).rejects.toThrow(/which is not defined in securityDefinitions/)
  })

  it('reports `ad_malformed` when the named definition is not an object', async () => {
    for (const [definition, shape] of [
      [['didwba'], 'an array'],
      ['didwba', 'string'],
      [null, 'null'],
    ] as const) {
      await expect(
        fetchAgentDescription(
          DID,
          opts({
            fetch: routedFetch({ [AD_URL]: () => json({ ...ad, securityDefinitions: { didwba_sc: definition } }) }),
          }) as never,
        ),
      ).rejects.toThrow(new RegExp(`defines security "didwba_sc" as ${shape}, not an object`))
    }
  })

  it('accepts a custom definition that is an object — the check is integrity, not a scheme', async () => {
    const custom = { ...ad, security: 'my_sc', securityDefinitions: { my_sc: { scheme: 'my-own' } } }
    const resolved = await fetchAgentDescription(
      DID,
      opts({ fetch: routedFetch({ [AD_URL]: () => json(custom) }) }) as never,
    )
    expect(resolved.document.security).toBe('my_sc')
  })

  it('reports `ad_malformed` when protocolType is not "ANP"', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({ fetch: routedFetch({ [AD_URL]: () => json({ ...ad, protocolType: 'MCP' }) }) }) as never,
      ),
    ).rejects.toThrow(/protocolType "MCP"/)
  })

  it('reports `ad_malformed` when the body is a JSON array', async () => {
    await expect(
      fetchAgentDescription(DID, opts({ fetch: routedFetch({ [AD_URL]: () => json([ad]) }) }) as never),
    ).rejects.toThrow(/is not a JSON object/)
  })

  it('fails closed with no allowedHosts — the DID is never even fetched', async () => {
    let fetched = false
    const spy = async () => {
      fetched = true
      return json({ id: DID, service: SERVICE })
    }
    await expect(
      fetchAgentDescription(DID, { allowUncontrolledFetch: true, fetch: spy } as never),
    ).rejects.toThrow(/allowedHosts/)
    expect(fetched).toBe(false)
  })

  // The decision this whole feature turns on: the description's host is chosen by
  // the DID DOCUMENT, so an endpoint on a host the caller never named must be
  // refused. Otherwise a hostile document could aim the second fetch anywhere.
  it('refuses an ad.json host the caller did not allowlist', async () => {
    let reached = false
    const spy = routedFetch()
    await expect(
      fetchAgentDescription(DID, {
        allowedHosts: ['example.com'], // the DID host only — NOT cdn.example.net
        resolveAddresses: publicResolve,
        allowUncontrolledFetch: true,
        fetch: async (url: string) => {
          if (url === AD_URL) reached = true
          return spy(url)
        },
      } as never),
    ).rejects.toThrow(/not in the allowed hosts list/)
    expect(reached).toBe(false)
  })

  it('refuses an ad.json host that resolves to a private address', async () => {
    await expect(
      fetchAgentDescription(
        DID,
        opts({
          resolveAddresses: async (host: string) => (host === AD_HOST ? ['127.0.0.1'] : ['93.184.216.34']),
          fetch: routedFetch(),
        }) as never,
      ),
    ).rejects.toThrow(/private\/loopback address/)
  })

  it('fetches the description once the second host is allowlisted too', async () => {
    const resolved = await fetchAgentDescription(
      DID,
      opts({ fetch: routedFetch() }) as never,
    )
    expect(resolved.url).toBe(AD_URL)
  })

  it('refuses a plain-http endpoint unless that host is opted in', async () => {
    const insecure = 'http://cdn.example.net/agents/alice/ad.json'
    const service = [{ id: `${DID}#ad`, type: 'AgentDescription', serviceEndpoint: insecure }]
    await expect(
      fetchAgentDescription(
        DID,
        opts({
          fetch: routedFetch({ [DOC_URL]: () => json({ id: DID, service }) }),
        }) as never,
      ),
    ).rejects.toThrow(/is not https/)
  })

  it('aborts a description fetch that exceeds the timeout', async () => {
    const never = (_u: string, init: RequestInit) =>
      new Promise<Response>((_, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('aborted')))
      })
    await expect(
      fetchAgentDescription(
        DID,
        opts({
          timeoutMs: 30,
          fetch: async (url: string, init: RequestInit) =>
            url === AD_URL ? never(url, init) : routedFetch()(url),
        }) as never,
      ),
    ).rejects.toThrow(/aborted/i)
  }, 5000)

  it('reuses a caller-supplied DID document store instead of re-fetching', async () => {
    const store = createDidDocumentStore()
    let docFetches = 0
    const fetch = async (url: string) => {
      if (url === DOC_URL) docFetches++
      return routedFetch()(url)
    }
    const options = opts({ fetch, documentStore: store })
    await fetchAgentDescription(DID, options as never)
    await fetchAgentDescription(DID, options as never)
    expect(docFetches).toBe(1)
  })

  it('docUrl is the DID document URL, not the description URL', async () => {
    const resolved = await fetchAgentDescription(
      DID,
      opts({ fetch: routedFetch() }) as never,
    )
    expect(resolved.docUrl).toBe(DOC_URL)
    expect(resolved.url).toBe(AD_URL)
  })
})

// The write half. These matter because the reader and the writer must agree on the
// shape: a document this SDK publishes is one this SDK can consume, byte for byte.
describe('buildAgentDescription', () => {
  it('produces a document the reader accepts unchanged', async () => {
    const built = buildAgentDescription({ name: 'Alice', did: DID, url: 'https://example.com' })
    const resolved = await fetchAgentDescription(
      DID,
      opts({
        fetch: routedFetch({
          [DOC_URL]: () => json({ id: DID, service: [agentDescriptionService(AD_URL, DID)] }),
          [AD_URL]: () => json(built),
        }),
      }) as never,
    )
    expect(resolved.document).toEqual(built)
  })

  it('fills in the protocol fields and the did:wba security block', () => {
    const built = buildAgentDescription({ name: 'Alice' })
    expect(built.protocolType).toBe('ANP')
    expect(built.type).toBe('AgentDescription')
    expect(built.security).toBe('didwba_sc')
    expect(built.securityDefinitions).toEqual({
      didwba_sc: { scheme: 'didwba', in: 'header', name: 'Authorization' },
    })
  })

  it('omits every optional field it was not given — including `created`', () => {
    const built = buildAgentDescription({ name: 'Alice' })
    for (const key of ['did', 'url', 'description', 'owner', 'handle', 'interfaces', 'Infomations', 'created']) {
      expect(built).not.toHaveProperty(key)
    }
  })

  it('refuses a `security` that names nothing in securityDefinitions', () => {
    expect(() => buildAgentDescription({ name: 'Alice', security: 'nope' })).toThrow(/not defined in securityDefinitions/)
    expect(() =>
      buildAgentDescription({
        name: 'Alice',
        security: 'other',
        securityDefinitions: { didwba_sc: {} },
      }),
    ).toThrow(/have: didwba_sc/)
  })
})

describe('agentDescriptionService', () => {
  it('is found by the reader — the entry IS the locator', async () => {
    // Built the way a caller would: one entry, no DID at hand for the id.
    const entry = agentDescriptionService(AD_URL)
    expect(entry.type).toBe(AGENT_DESCRIPTION_SERVICE_TYPE)
    const resolved = await fetchAgentDescription(
      DID,
      opts({ fetch: routedFetch({ [DOC_URL]: () => json({ id: DID, service: [entry] }) }) }) as never,
    )
    expect(resolved.url).toBe(AD_URL)
  })

  it('embeds the DID in the entry id when one is given', () => {
    expect(agentDescriptionService(AD_URL, DID).id).toBe(`${DID}#agent-description`)
    expect(agentDescriptionService(AD_URL).id).toBe('#agent-description')
  })
})

// The constraint R2.3 turns on: a service entry is only publishable if it was in the
// document at signing time, because the proof covers whatever was there.
describe('publishing a service entry in a signed DID document', () => {
  const HOST = 'example.com'

  it('signs a document that carries the entry, and still verifies', () => {
    const identity = createAnpIdentity(HOST, { service: [agentDescriptionService(AD_URL, undefined)] })
    expect(identity.did).toContain(HOST)
    const doc = identity.didDocument as { service: unknown[] }
    expect(doc.service).toEqual([agentDescriptionService(AD_URL, undefined)])
    expect(() => verifyDidDocument(identity.didDocument, identity.did)).not.toThrow()
  })

  it('builds the entry from the DID the caller cannot know in advance', () => {
    // The endpoint embeds the DID, which only exists once the key does — hence the
    // function form of `service`.
    const identity = createAnpIdentity(HOST, {
      service: (did) => [agentDescriptionService(`https://${HOST}/agents/${did}/ad.json`, did)],
    })
    const doc = identity.didDocument as { service: Array<{ id: string; serviceEndpoint: string }> }
    expect(doc.service[0].id).toBe(`${identity.did}#agent-description`)
    expect(doc.service[0].serviceEndpoint).toBe(`https://${HOST}/agents/${identity.did}/ad.json`)
    expect(() => verifyDidDocument(identity.didDocument, identity.did)).not.toThrow()
  })

  it('a service entry appended AFTER signing breaks the proof', () => {
    // Not a hypothetical: it is why `service` is an option on the identity builders
    // rather than something a caller can add on the way out.
    const identity = createAnpIdentity(HOST)
    const tampered = JSON.parse(JSON.stringify(identity.didDocument))
    tampered.service = [agentDescriptionService(AD_URL)]
    expect(() => verifyDidDocument(tampered, identity.did)).toThrow()
  })
})
