import { describe, it, expect } from 'vitest'
import {
  didConfirmationUrl,
  handleResolutionUrl,
  handleService,
  parseHandle,
  resolveHandle,
  verifyHandleBinding,
  type HandleResolutionDocument,
} from './wns'
import { createAnpIdentity } from './signer'
import { createWebIdentity } from './webIdentity'
import { didToUrl } from './resolveDid'
import type { DidDocumentService } from './didDocument'

const HANDLE = 'alice.example.com'
const DOMAIN = 'example.com'
const RES_URL = `https://${DOMAIN}/.well-known/handle/alice`

// One identity per shape under test, carrying the three things that have to agree: the
// DID, the document served for it, and the resolution body that reports it. Every
// document here is a REAL signed `did:wba` one, so the mainline path runs through the
// resolver's proof policy instead of a fixture that would sidestep it.
function site(service: DidDocumentService[]) {
  const identity = createAnpIdentity(DOMAIN, { service })
  const did = identity.did
  const body: HandleResolutionDocument = {
    handle: HANDLE,
    did,
    status: 'active',
    binding_generation: '8',
  }
  return { did, doc: identity.didDocument, docUrl: didToUrl(did), body }
}

// The mainline: the DID holder publishes the PUBLIC-mode endpoint, i.e. this Handle's
// own standard Resolution Endpoint (§6.2 mode 1).
const mainline = site([handleService(RES_URL)])
const DID = mainline.did
const CONFIRM_URL = didConfirmationUrl(DOMAIN, DID)

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
    ...init,
  })
}

// Route by URL so one stub serves every hop. `over` replaces the canned answer for a
// URL (and is consulted FIRST, which is how the tests make one URL answer differently
// on its second visit); anything unrouted is a 404.
function routed(over: Record<string, () => Response> = {}, s = mainline) {
  const calls: string[] = []
  const fetch = async (url: string): Promise<Response> => {
    calls.push(url)
    const canned = over[url]
    if (canned) return canned()
    if (url === RES_URL) return json(s.body)
    if (url === s.docUrl) return json(s.doc)
    return new Response('not found', { status: 404 })
  }
  return { fetch, calls }
}

/** A stub whose n-th visit to `url` answers `responses[n]`. */
function nth(url: string, responses: (() => Response)[]) {
  let n = 0
  return { [url]: () => responses[Math.min(n++, responses.length - 1)]!() }
}

// Deterministic and offline: nothing here opens a socket.
const publicResolve = async () => ['93.184.216.34']

// The same three-piece shape for a NATIVE `did:web` holder (ANP-02 附录 B). Its document
// carries no proof, so resolution exercises the method's own exemption rather than the
// WBA proof policy — which is exactly what a compat-mode test has to run through.
function webSite(service: DidDocumentService[], path?: string[]) {
  const identity = createWebIdentity(DOMAIN, { service, path })
  const did = identity.did
  const body: HandleResolutionDocument = {
    handle: HANDLE,
    did,
    status: 'active',
    binding_generation: '8',
  }
  return { did, doc: identity.didDocument, docUrl: didToUrl(did), body }
}

function opts(extra: Record<string, unknown> = {}) {
  return {
    allowedHosts: [DOMAIN],
    resolveAddresses: publicResolve,
    allowUncontrolledFetch: true,
    ...extra,
  }
}

describe('parseHandle', () => {
  it('normalizes before it validates — §3.1 L101 is a MUST, so uppercase is legal input', () => {
    const parsed = parseHandle('Alice.Example.com')
    expect(parsed.handle).toBe('alice.example.com')
    expect(parsed.localPart).toBe('alice')
    expect(parsed.domain).toBe('example.com')
  })

  it('accepts every spelling §3.1 L106–L109 gives as valid', () => {
    for (const h of ['alice.example.com', 'bob-smith.example.com', 'agent-42.example.com', 'a.example.com']) {
      expect(parseHandle(h).handle).toBe(h)
    }
  })

  it('splits at the FIRST dot, because a local-part never contains one', () => {
    const parsed = parseHandle('a.b.example.com')
    expect(parsed.localPart).toBe('a')
    expect(parsed.domain).toBe('b.example.com')
  })

  it('derives the standard Resolution Endpoint (§4.2 L175)', () => {
    expect(parseHandle(HANDLE).resolutionUrl).toBe(RES_URL)
    expect(handleResolutionUrl(HANDLE)).toBe(RES_URL)
  })

  it('strips the `wba://` propagation prefix (§3.2 L126–L127)', () => {
    expect(parseHandle('wba://alice.example.com').handle).toBe(HANDLE)
    expect(parseHandle('wba://Alice.Example.com').handle).toBe(HANDLE)
  })

  it('does NOT treat the §3.2 L132 Web URL as another spelling of a Handle', () => {
    // Only `wba://` is a propagation form; `https://…` is a separate locator, so this is
    // not a Handle at all rather than one that silently gets its scheme dropped.
    expect(() => parseHandle(RES_URL)).toThrow(/local part/)
  })

  it('rejects the three local-part shapes §3.1 L110–L112 gives as invalid', () => {
    expect(() => parseHandle('-alice.example.com')).toThrow(/local part/)
    expect(() => parseHandle('alice-.example.com')).toThrow(/local part/)
    expect(() => parseHandle('al--ice.example.com')).toThrow(/consecutive hyphens/)
  })

  it('rejects a Handle with no domain part', () => {
    expect(() => parseHandle('alice')).toThrow(/local-part\.domain/)
    expect(() => parseHandle('alice.')).toThrow(/invalid domain/)
  })

  it('rejects a domain that carries a port — §3.1 L100 says it never does', () => {
    expect(() => parseHandle('alice.example.com:8080')).toThrow(/carries a port/)
  })

  it('rejects a single-label domain, which no public CA can cover (§9.1 L739)', () => {
    expect(() => parseHandle('alice.localhost')).toThrow(/invalid domain/)
  })

  it('caps the local part at 63 characters (§3.1 L89 says 1–63)', () => {
    expect(parseHandle(`${'a'.repeat(63)}.example.com`).handle).toBe(`${'a'.repeat(63)}.example.com`)
    expect(() => parseHandle(`${'a'.repeat(64)}.example.com`)).toThrow(/invalid local part/)
  })

  it('rejects empty input, with the code a caller branches on', () => {
    try {
      parseHandle('   ')
      throw new Error('expected parseHandle to throw')
    } catch (err) {
      expect(err).toMatchObject({ code: 'invalid_handle' })
    }
  })
})

describe('didConfirmationUrl', () => {
  it('percent-encodes the whole DID as one query value, as §4.3.1 L239 / §6.2 L505 spell it', () => {
    expect(didConfirmationUrl(DOMAIN, DID)).toBe(
      `https://${DOMAIN}/.well-known/handle/by-did?did=${encodeURIComponent(DID)}`,
    )
    expect(didConfirmationUrl(DOMAIN, DID)).toContain('%3A')
  })

  it('rejects a domain that is not one, and a missing DID', () => {
    expect(() => didConfirmationUrl('example.com:8443', DID)).toThrow(/not a valid Handle Provider domain/)
    expect(() => didConfirmationUrl(DOMAIN, '')).toThrow(/needs a DID/)
  })
})

describe('handleService', () => {
  it('builds the reverse declaration, with the `#handle` suffix §6.2 L511 suggests', () => {
    expect(handleService(RES_URL, DID)).toEqual({
      id: `${DID}#handle`,
      type: 'ANPHandleService',
      serviceEndpoint: RES_URL,
    })
    expect(handleService(RES_URL).id).toBe('#handle')
  })
})

describe('resolveHandle', () => {
  it('returns the resolved facts, normalized and unpacked', async () => {
    const resolved = await resolveHandle('Alice.Example.com', opts({ fetch: routed().fetch }))
    expect(resolved.handle).toBe(HANDLE)
    expect(resolved.domain).toBe(DOMAIN)
    expect(resolved.did).toBe(DID)
    expect(resolved.status).toBe('active')
    expect(resolved.bindingGeneration).toBe('8')
  })

  it('answers 404 and 410 with their own code — §4.8 L436–L437 make them conclusions, not failures', async () => {
    for (const status of [404, 410]) {
      const { fetch } = routed({ [RES_URL]: () => new Response('gone', { status }) })
      await expect(resolveHandle(HANDLE, opts({ fetch }))).rejects.toMatchObject({ code: 'handle_not_found' })
    }
  })

  it('reports any other non-2xx as a fetch failure, keeping the status reachable', async () => {
    const { fetch } = routed({ [RES_URL]: () => new Response('boom', { status: 503 }) })
    await expect(resolveHandle(HANDLE, opts({ fetch }))).rejects.toMatchObject({
      code: 'handle_fetch_failed',
      status: 503,
    })
  })

  it('refuses a host that is not allowlisted', async () => {
    const { fetch } = routed()
    await expect(
      resolveHandle(HANDLE, { ...opts({ fetch }), allowedHosts: ['other.example'] }),
    ).rejects.toMatchObject({ code: 'handle_fetch_failed' })
  })

  it('rejects a body that is not a Handle Resolution Document, field by field', async () => {
    const cases: unknown[] = [
      [],
      { ...mainline.body, did: undefined },
      { ...mainline.body, status: 'pending' },
      { ...mainline.body, binding_generation: 8 },
      { ...mainline.body, binding_generation: '8 ' },
      { ...mainline.body, binding_generation: undefined },
      { ...mainline.body, handle: 'bob.example.com' },
    ]
    for (const body of cases) {
      const { fetch } = routed({ [RES_URL]: () => json(body) })
      await expect(resolveHandle(HANDLE, opts({ fetch }))).rejects.toMatchObject({ code: 'handle_malformed' })
    }
  })

  it('rejects a body that is not JSON at all, and one served as HTML', async () => {
    const notJson = routed({
      [RES_URL]: () => new Response('nope', { status: 200, headers: { 'content-type': 'application/json' } }),
    })
    await expect(resolveHandle(HANDLE, opts({ fetch: notJson.fetch }))).rejects.toMatchObject({
      code: 'handle_malformed',
    })

    const html = routed({
      [RES_URL]: () => new Response('<html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    })
    await expect(resolveHandle(HANDLE, opts({ fetch: html.fetch }))).rejects.toMatchObject({
      code: 'handle_malformed',
    })
  })

  it('does not follow a 301/308 — §4.8 L444–L446 refuse to accept a binding from a redirect', async () => {
    const { fetch, calls } = routed({
      [RES_URL]: () => new Response('', { status: 301, headers: { location: 'https://elsewhere.example/handle' } }),
    })
    await expect(resolveHandle(HANDLE, opts({ fetch }))).rejects.toMatchObject({ code: 'handle_fetch_failed' })
    expect(calls).toEqual([RES_URL])
  })
})

describe('verifyHandleBinding', () => {
  it('reaches `exact-handle` when the DID document declares this Handle and the endpoint answers for it', async () => {
    const { fetch, calls } = routed()
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toEqual({
      result: 'exact-handle',
      handle: HANDLE,
      did: DID,
      serviceEndpoint: RES_URL,
      status: 'active',
      bindingGeneration: '8',
    })
    // Rules 1–2, 3, then 6 — the Handle, its DID document, then the declared endpoint.
    expect(calls).toEqual([RES_URL, mainline.docUrl, RES_URL])
  })

  it('reaches `provider-confirmed` on a private-confirmation endpoint (§6.3.1 rule 8)', async () => {
    const s = site([handleService(CONFIRM_URL)])
    const { fetch } = routed({ [CONFIRM_URL]: () => json({ did: s.did, confirmed: true }) }, s)
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toMatchObject({ result: 'provider-confirmed', did: s.did, serviceEndpoint: CONFIRM_URL })
  })

  it('refuses to read `provider-confirmed` as an exact Handle — §6.3.1 rule 8 / L518', async () => {
    // A provider answers "yes" for ANY handle it hosts, so a `handle` coming back from the
    // private endpoint is not the exact reverse confirmation rule 7 demands.
    const s = site([handleService(CONFIRM_URL)])
    const { fetch } = routed({ [CONFIRM_URL]: () => json({ did: s.did, confirmed: true, handle: HANDLE }) }, s)
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toMatchObject({ result: 'unverified', reason: 'endpoint_not_canonical' })
  })

  it('picks the entry that declares THIS Handle when the DID publishes several (rule 7)', async () => {
    const other = `https://${DOMAIN}/.well-known/handle/bob`
    const s = site([handleService(other), handleService(RES_URL)])
    // The first entry answers for a DIFFERENT handle, so "first entry wins" would fail
    // rule 7 here. Reading the entry that IS the canonical endpoint is what makes a DID
    // holding two Handles verifiable at all.
    const { fetch } = routed({ [other]: () => json({ ...s.body, handle: 'bob.example.com' }) }, s)
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toMatchObject({ result: 'exact-handle', serviceEndpoint: RES_URL })
  })

  it('fails closed with `no_handle_service` when the DID document makes no reverse declaration', async () => {
    const s = site([])
    const { fetch } = routed({}, s)
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toMatchObject({ result: 'unverified', reason: 'no_handle_service', did: s.did })
  })

  it('rejects a non-https endpoint, a relative one, and one on another host (rule 5)', async () => {
    const cases: [DidDocumentService[], string][] = [
      [[handleService('http://example.com/.well-known/handle/alice')], 'endpoint_not_https'],
      [[handleService('/.well-known/handle/alice')], 'endpoint_not_https'],
      [[handleService('https://other.example/.well-known/handle/alice')], 'endpoint_host_mismatch'],
    ]
    for (const [service, reason] of cases) {
      const { fetch } = routed({}, site(service))
      expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
        result: 'unverified',
        reason,
      })
    }
  })

  it('reports an endpoint that cannot be dereferenced, and does not follow its redirects', async () => {
    const gone = routed(
      nth(RES_URL, [() => json(mainline.body), () => new Response('gone', { status: 404 })]),
    )
    const a = await verifyHandleBinding(HANDLE, opts({ fetch: gone.fetch }))
    expect(a).toMatchObject({ result: 'unverified', reason: 'endpoint_unreachable', serviceEndpoint: RES_URL })

    const moved = routed(
      nth(RES_URL, [
        () => json(mainline.body),
        () => new Response('', { status: 308, headers: { location: `${RES_URL}/x` } }),
      ]),
    )
    expect(await verifyHandleBinding(HANDLE, opts({ fetch: moved.fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'endpoint_unreachable',
    })
  })

  it('rejects an endpoint body that is JSON but not an object (rule 6)', async () => {
    const { fetch } = routed(
      nth(RES_URL, [() => json(mainline.body), () => json(['not', 'an', 'object'])]),
    )
    expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'endpoint_malformed',
    })
  })

  it('requires the answered `did` to be the one rule 2 resolved (rules 7 / 8)', async () => {
    const { fetch } = routed(
      nth(RES_URL, [() => json(mainline.body), () => json({ did: 'did:web:example.com', handle: HANDLE })]),
    )
    expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'did_mismatch',
    })
  })

  it('requires the answered `handle` to be exactly the input Handle (rule 7)', async () => {
    const { fetch } = routed(
      nth(RES_URL, [() => json(mainline.body), () => json({ did: DID, handle: 'bob.example.com' })]),
    )
    expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'handle_mismatch',
    })
  })

  it('treats "no handle and no confirmed" as unverified (rule 9)', async () => {
    const { fetch } = routed(nth(RES_URL, [() => json(mainline.body), () => json({ did: DID })]))
    expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'not_confirmed',
    })
  })

  it('enforces §4.4 rule 1 — the Handle domain MUST be the DID’s host — without resolving it', async () => {
    // A provider claiming this Handle for a DID on someone else's host is exactly the
    // attack §6 L476 opens with.
    const foreign = routed({ [RES_URL]: () => json({ ...mainline.body, did: 'did:web:other.example' }) })
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch: foreign.fetch }))
    expect(verdict).toMatchObject({ result: 'unverified', reason: 'did_host_mismatch' })
    // Rule 1 already decided, so that DID's document is never fetched.
    expect(foreign.calls).toEqual([RES_URL])
  })

  it('ignores the port a did:wba authority may carry (§4.4 L381, L400)', async () => {
    // `example.com%3A8800` is the encoded authority form §4.4 L397 shows; the comparison
    // is on the hostname, so the port must not make a valid Handle look foreign.
    const s = site([handleService(RES_URL)])
    const portDID = 'did:wba:example.com%3A8800:user:alice:e1_abc'
    const { fetch } = routed(
      {
        [RES_URL]: () => json({ ...s.body, did: portDID }),
        [didToUrl(portDID)]: () => json({ ...s.doc, id: portDID }),
      },
      s,
    )
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    // The fixture's document is not signed for this DID, so the resolution itself fails —
    // what this asserts is that it did NOT fail as `did_host_mismatch`.
    expect(verdict).toMatchObject({ result: 'unverified', reason: 'did_unresolved', did: portDID })
  })

  it('refuses a DID it cannot derive a hostname from at all', async () => {
    const { fetch } = routed({ [RES_URL]: () => json({ ...mainline.body, did: 'eip155:1:0xabc' }) })
    expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'did_host_mismatch',
    })
  })

  it('refuses a suspended or revoked Handle — §4.7 L425–L427, not one of the ten rules', async () => {
    for (const status of ['suspended', 'revoked']) {
      const { fetch } = routed({ [RES_URL]: () => json({ ...mainline.body, status }) })
      expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
        result: 'unverified',
        reason: 'handle_not_active',
        did: DID,
      })
    }
  })

  it('carries a resolution failure through as the reason (rules 1–2)', async () => {
    const missing = routed({ [RES_URL]: () => new Response('gone', { status: 404 }) })
    expect(await verifyHandleBinding(HANDLE, opts({ fetch: missing.fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'handle_not_found',
    })

    const broken = routed({ [RES_URL]: () => json({ ...mainline.body, binding_generation: 'x' }) })
    expect(await verifyHandleBinding(HANDLE, opts({ fetch: broken.fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'handle_unresolved',
    })

    const noDID = routed({ [RES_URL]: () => json({ ...mainline.body, did: 'did:web:unreachable.example' }) })
    expect(await verifyHandleBinding(HANDLE, opts({ fetch: noDID.fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'did_host_mismatch',
    })
  })

  it('throws on a malformed input Handle rather than reporting an unverified binding', async () => {
    await expect(verifyHandleBinding('alice', opts())).rejects.toMatchObject({ code: 'invalid_handle' })
  })

  it('keeps the failure detail on the caller’s side of the wire, never on a success', async () => {
    const { fetch } = routed({ [RES_URL]: () => json({ ...mainline.body, did: 'did:web:other.example' }) })
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict.result).toBe('unverified')
    if (verdict.result !== 'unverified') throw new Error('unreachable')
    expect(verdict.detail).toContain('other.example')
    expect(verdict).not.toHaveProperty('bindingGeneration')
  })

  it('distinguishes the three results §6.3.2 L594–L598 asks implementations to keep apart', async () => {
    const seen = new Set<string>()
    seen.add((await verifyHandleBinding(HANDLE, opts({ fetch: routed().fetch }))).result)

    const priv = site([handleService(CONFIRM_URL)])
    const confirmed = await verifyHandleBinding(
      HANDLE,
      opts({ fetch: routed({ [CONFIRM_URL]: () => json({ did: priv.did, confirmed: true }) }, priv).fetch }),
    )
    seen.add(confirmed.result)

    const bare = site([])
    seen.add((await verifyHandleBinding(HANDLE, opts({ fetch: routed({}, bare).fetch }))).result)

    expect([...seen].sort()).toEqual(['exact-handle', 'provider-confirmed', 'unverified'])
  })
})

describe('verifyHandleBinding — native did:web (附录 B.4)', () => {
  it('reaches provider-domain without dereferencing the endpoint', async () => {
    const web = webSite([handleService(RES_URL)])
    const { fetch, calls } = routed({ [RES_URL]: () => json(web.body) }, web)
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toEqual({
      result: 'provider-domain',
      handle: HANDLE,
      did: web.did,
      serviceEndpoint: RES_URL,
      status: 'active',
      bindingGeneration: '8',
    })
    // The DID document is resolved (B.1 L470 is a MUST) and then nothing else: B.4 L31
    // says the compat path does not require dereferencing the endpoint.
    expect(calls).toEqual([RES_URL, web.docUrl])
  })

  it('never returns exact-handle or provider-confirmed, even when the endpoint would answer', async () => {
    // Same bytes the mainline would turn into `exact-handle` (a `handle` that matches
    // the input, from the standard endpoint) and into `provider-confirmed` (a private
    // endpoint answering `confirmed: true`). Neither may be claimed for a method whose
    // identifier binds no key: §6.3.1 rule 10 (L587–L588) reserves `exact-handle` for
    // the precise reverse confirmation, and B.4 L31 says the compat path is not it.
    const web = webSite([handleService(RES_URL)])
    const wouldBeExact = routed({ [RES_URL]: () => json(web.body) }, web)
    expect((await verifyHandleBinding(HANDLE, opts({ fetch: wouldBeExact.fetch }))).result).toBe('provider-domain')
    expect(wouldBeExact.calls).not.toContain(RES_URL + '?never')

    const privateEndpoint = didConfirmationUrl(DOMAIN, web.did)
    const webPriv = webSite([handleService(privateEndpoint)])
    const wouldBeConfirmed = routed(
      { [privateEndpoint]: () => json({ did: webPriv.did, confirmed: true }) },
      webPriv,
    )
    expect((await verifyHandleBinding(HANDLE, opts({ fetch: wouldBeConfirmed.fetch }))).result).toBe('provider-domain')
    expect(wouldBeConfirmed.calls).not.toContain(privateEndpoint)
  })

  it('picks the first entry whose LOCATION passes, since there is no canonical endpoint to prefer', async () => {
    // A did:web holder with an unrelated entry first: the mainline rule ("the entry
    // whose serviceEndpoint IS this Handle's standard endpoint") has nothing to match
    // on here, so falling back to `entries[0]` would report `endpoint_host_mismatch`
    // for a DID that does declare a correct entry.
    const web = webSite([
      handleService('https://other.example/.well-known/handle/alice'),
      handleService(RES_URL),
    ])
    const { fetch } = routed({ [RES_URL]: () => json(web.body) }, web)
    expect(await verifyHandleBinding(HANDLE, opts({ fetch }))).toMatchObject({
      result: 'provider-domain',
      serviceEndpoint: RES_URL,
    })
  })

  it('still applies rule 5 to a did:web DID: the endpoint must be https on the Handle domain', async () => {
    const cases: [DidDocumentService[], string][] = [
      [[handleService('http://example.com/.well-known/handle/alice')], 'endpoint_not_https'],
      [[handleService('/.well-known/handle/alice')], 'endpoint_not_https'],
      [[handleService('https://other.example/.well-known/handle/alice')], 'endpoint_host_mismatch'],
    ]
    for (const [service, reason] of cases) {
      const web = webSite(service)
      const { fetch } = routed({}, web)
      expect(await verifyHandleBinding(HANDLE, opts({ fetch })), reason).toMatchObject({
        result: 'unverified',
        reason,
      })
    }
  })

  it('keeps the earlier rules exactly as they are for a did:web DID', async () => {
    const bare = webSite([])
    // §4.4 rule 1 is method-agnostic: the Handle's domain must be the DID's host, so a
    // did:web holder on another domain is refused before anything else happens.
    const elsewhere = routed({ [RES_URL]: () => json({ ...bare.body, did: 'did:web:other.example' }) })
    expect(await verifyHandleBinding(HANDLE, opts({ fetch: elsewhere.fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'did_host_mismatch',
    })

    // And no `ANPHandleService` entry is still `no_handle_service`, not a compat pass.
    expect(await verifyHandleBinding(HANDLE, opts({ fetch: routed({}, bare).fetch }))).toMatchObject({
      result: 'unverified',
      reason: 'no_handle_service',
    })
  })

  it('does not treat did:webvh as did:web', async () => {
    // `did:webvh:` is a different method — 附录 C 明确"不定义可直接启用的 WebVH 绑定" ——
    // so the dispatch on `did:web:` must not catch it by prefix. This SDK can derive no URL
    // for it either, so it dies at rule 1 instead of getting a compat verdict.
    const { fetch } = routed({
      [RES_URL]: () => json({ ...mainline.body, did: 'did:webvh:abc123:example.com:alice' }),
    })
    const verdict = await verifyHandleBinding(HANDLE, opts({ fetch }))
    expect(verdict).toMatchObject({ result: 'unverified', reason: 'did_host_mismatch' })
    if (verdict.result !== 'unverified') throw new Error('unreachable')
    expect(verdict.detail).toContain('Cannot derive a hostname')
  })

  it('admits a fourth result value, so the compat verdict is never read as a mainline one', async () => {
    const web = webSite([handleService(RES_URL)])
    const seen = new Set<string>()
    seen.add((await verifyHandleBinding(HANDLE, opts({ fetch: routed().fetch }))).result)
    seen.add((await verifyHandleBinding(HANDLE, opts({ fetch: routed({}, web).fetch }))).result)
    expect([...seen].sort()).toEqual(['exact-handle', 'provider-domain'])
  })
})
