// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { createConfig } from './config'
import { login, register } from './actions'
import { createAnpIdentity, signAnpLoginRequest } from './crypto/signer'
import { signDidDocumentProofSync } from './crypto/dataIntegrity'
import { createDidDocumentStore, didToUrl } from './crypto/resolveDid'
import type { AnpConnector, AnpSigningIdentity, DidSupersededInfo } from './types'
import type { ConnectxError } from './errors'

// A peer answers 409 `did_superseded` when the DID we signed with has updated away
// (ANP-03 §3.2). The body's `currentDid` is an UNVERIFIED HINT — the spec says in so
// many words that a client must not retry from it. What a client must do instead is
// fetch the OLD document, follow `successorDid` to the DID that is current, and
// re-sign with THAT. These tests drive exactly that, and the ones that matter are the
// negatives: no chain configured → no fetch, and a hint that disagrees with our own
// verification → refused.

const HOST = 'example.com'
const LOGIN_URI = `https://${HOST}/api/login/anp/verify`
const REGISTER_URI = `https://${HOST}/api/register/anp`
const PATH = ['user', 'alice']

/** A connector around a real signing identity, so the body it produces carries the
 *  DID that actually signed — which is what these tests assert on. */
function connectorFor(identity: AnpSigningIdentity): AnpConnector {
  return {
    id: identity.did,
    name: identity.did,
    type: 'anp-cli',
    isAvailable: async () => true,
    getIdentity: async () => identity,
    signRequest: async (req) =>
      ({
        did: identity.did,
        keyid: identity.keyid,
        didDocument: identity.didDocument,
        ...(await signAnpLoginRequest({
          identity,
          nonce: req.nonce,
          method: req.method,
          url: req.url,
          ...(req.handle === undefined ? {} : { handle: req.handle }),
        })),
      }),
  }
}

/** The DID as the peer saw it: read out of the signed body, not out of the connector. */
function didInBody(body: BodyInit | null | undefined): string {
  return (JSON.parse(String(body)) as { did: string }).did
}

/** A subscription to the requests a transport received, in order. */
function requests() {
  const bodies: string[] = []
  const record = (init: RequestInit) => {
    const did = didInBody(init.body)
    bodies.push(did)
    return did
  }
  return { bodies, record }
}

/** Serve DID documents from memory — the chain walk's own transport. */
function didServer(docs: Map<string, Record<string, unknown>>) {
  return async (url: string) =>
    docs.has(url)
      ? new Response(JSON.stringify(docs.get(url)), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      : new Response('not found', { status: 404 })
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

/** A two-generation update on ONE stable subject path: `old` is deactivated and
 *  points at `next`, which is active. */
function update() {
  const old = createAnpIdentity(HOST, { path: PATH })
  const next = createAnpIdentity(HOST, { path: PATH })

  // The old document stays fetchable, deactivated, naming its direct successor — and
  // re-signed so the transition is covered by the predecessor's OWN binding key
  // (§2.5.5), which is what makes the hop `verified`.
  const transition: Record<string, unknown> = {
    ...old.didDocument,
    deactivated: true,
    successorDid: next.did,
  }
  delete transition.proof
  transition.proof = signDidDocumentProofSync(transition, old.keyid, old.priv)

  const docs = new Map<string, Record<string, unknown>>([
    [didToUrl(old.did), transition],
    [didToUrl(next.did), next.didDocument],
  ])

  const chainOptions = {
    allowedHosts: [HOST],
    resolveAddresses: async () => ['93.184.216.34'],
    allowUncontrolledFetch: true,
    fetch: didServer(docs),
  }

  return { old, next, docs, chainOptions }
}

/** The peer's 409 body: it names the DID it rejected, and (optionally) claims a DID
 *  is current — which these tests treat as a hint to be checked, never obeyed. */
const supersededBody = (requestedDid: string, claimedCurrentDid?: string) => ({
  code: 'did_superseded',
  requestedDid,
  ...(claimedCurrentDid === undefined ? {} : { currentDid: claimedCurrentDid }),
  stableSubjectId: 'example.com:user:alice',
})

describe('login — 409 did_superseded with a chain walk (ANP-03 §2.6, §3.2)', () => {
  it('walks the chain and retries with the DID our own verification produced', async () => {
    const { old, next, chainOptions } = update()
    const oldConnector = connectorFor(old)
    const nextConnector = connectorFor(next)
    const config = createConfig([oldConnector, nextConnector], oldConnector.id)

    const { bodies, record } = requests()
    let seen: DidSupersededInfo | undefined
    let calls = 0

    const outcome = await login(config, {
      connectorId: oldConnector.id,
      nonce: 'n1',
      targetUri: LOGIN_URI,
      didChain: chainOptions,
      onDidSuperseded: (info) => {
        seen = info
        return nextConnector
      },
      transport: async (_url, init) => {
        record(init)
        calls += 1
        if (calls === 1) return json(409, supersededBody(old.did, next.did))
        return json(200, { token: 'tok_after_update' })
      },
    })

    // Two requests: the rejected one, then the retry — signed by the SUCCESSOR.
    expect(bodies).toEqual([old.did, next.did])
    expect(outcome.did).toBe(next.did)
    // The subject is unchanged by the update, which is the point of the whole flow.
    expect(outcome.subject).toBe('did:wba:example.com:user:alice')
    expect(outcome.token).toBe('tok_after_update')
    // The hook is handed both halves, named apart: what the peer CLAIMED and what our
    // own walk VERIFIED.
    expect(seen?.requestedDid).toBe(old.did)
    expect(seen?.claimedCurrentDid).toBe(next.did)
    expect(seen?.verifiedCurrentDid).toBe(next.did)
    expect(seen?.chain?.assurance).toBe('verified')
    expect(seen?.chain?.hops).toHaveLength(1)
  })

  it('refuses to sign with the peer-suggested DID when our walk says otherwise', async () => {
    // The Peer's Hint Is Not The Credential. The 409 body points at an attacker's DID
    // while the real chain leads to the true successor, and the hook — standing in for
    // a naive caller — returns the hinted one. The SDK must refuse: coming out of here
    // with the attacker's DID would mean the peer chose our identity.
    const { old, next, chainOptions, docs } = update()
    const attacker = createAnpIdentity(HOST, { path: ['user', 'mallory'] })
    docs.set(didToUrl(attacker.did), attacker.didDocument)

    const config = createConfig([connectorFor(old), connectorFor(next), connectorFor(attacker)])
    const { bodies, record } = requests()
    let calls = 0
    let seen: DidSupersededInfo | undefined

    await expect(
      login(config, {
        connectorId: old.did,
        nonce: 'n1',
        targetUri: LOGIN_URI,
        didChain: chainOptions,
        onDidSuperseded: (info) => {
          seen = info
          return connectorFor(attacker)
        },
        transport: async (_url, init) => {
          record(init)
          calls += 1
          return json(409, supersededBody(old.did, attacker.did))
        },
      }),
    ).rejects.toMatchObject({ code: 'invalid_argument' })

    expect(seen?.claimedCurrentDid).toBe(attacker.did)
    expect(seen?.verifiedCurrentDid).toBe(next.did)
    // Only the first, rejected request went out — the hinted DID was never signed.
    expect(bodies).toEqual([old.did])
    expect(calls).toBe(1)
  })

  it('issues no DID-document fetch when no chain is configured (默认不取)', async () => {
    const { old, next } = update()
    const config = createConfig([connectorFor(old)])
    const { bodies, record } = requests()

    await expect(
      login(config, {
        connectorId: old.did,
        nonce: 'n1',
        targetUri: LOGIN_URI,
        // No didChain and no hook: a supersede report is reported, not investigated.
        transport: async (_url, init) => {
          record(init)
          return json(409, supersededBody(old.did, next.did))
        },
      }),
    ).rejects.toMatchObject({ code: 'did_superseded', status: 409, serverCode: 'did_superseded' })

    expect(bodies).toEqual([old.did])
  })

  it('walks the chain on `didChain` alone, and reports the answer on the error', async () => {
    // `didChain` alone is the common case, not a degenerate one. ANP-03 §3.2 tells the
    // client to fetch the old document, verify it, and walk forward — that IS the
    // prescribed answer to the 409, and it needs no signer. A caller whose key was just
    // retired cannot produce one (an update means a new key), so requiring the hook
    // before fetching would withhold the only part the caller cannot compute itself.
    const { old, next, docs } = update()
    let fetched = 0
    const config = createConfig([connectorFor(old)])
    const { bodies, record } = requests()

    const err = await login(config, {
      connectorId: old.did,
      nonce: 'n1',
      targetUri: LOGIN_URI,
      didChain: {
        allowedHosts: [HOST],
        resolveAddresses: async () => ['93.184.216.34'],
        allowUncontrolledFetch: true,
        fetch: async (url) => {
          fetched += 1
          return didServer(docs)(url)
        },
      },
      transport: async (_url, init) => {
        record(init)
        return json(409, supersededBody(old.did, next.did))
      },
    }).then(
      () => {
        throw new Error('expected a rejection')
      },
      (e: unknown) => e as ConnectxError,
    )

    // No retry: the credential is unchanged, so nothing was re-sent.
    expect(bodies).toEqual([old.did])
    // The walk ran, and its conclusion — OURS, not the peer's hint — rides the error.
    expect(fetched).toBeGreaterThan(0)
    expect(err.code).toBe('did_superseded')
    expect(err.didSuperseded?.claimedCurrentDid).toBe(next.did)
    expect(err.didSuperseded?.verifiedCurrentDid).toBe(next.did)
    expect(err.didSuperseded?.chain?.assurance).toBe('verified')
  })

  it('issues no request at all when `didChain` is absent', async () => {
    // The other half of the same rule: nothing authorises an outbound fetch on a 409
    // unless the caller configured one, so there is nothing to report either.
    const { old, next } = update()
    const config = createConfig([connectorFor(old)])
    const { bodies, record } = requests()

    const err = await login(config, {
      connectorId: old.did,
      nonce: 'n1',
      targetUri: LOGIN_URI,
      transport: async (_url, init) => {
        record(init)
        return json(409, supersededBody(old.did, next.did))
      },
    }).then(
      () => {
        throw new Error('expected a rejection')
      },
      (e: unknown) => e as ConnectxError,
    )

    expect(bodies).toEqual([old.did])
    expect(err.code).toBe('did_superseded')
    expect(err.didSuperseded).toBeUndefined()
  })

  it('reports the 409 when the hook declines to supply a signer', async () => {
    const { old, chainOptions } = update()
    const config = createConfig([connectorFor(old)])
    const { bodies, record } = requests()

    await expect(
      login(config, {
        connectorId: old.did,
        nonce: 'n1',
        targetUri: LOGIN_URI,
        didChain: chainOptions,
        onDidSuperseded: () => undefined,
        transport: async (_url, init) => {
          record(init)
          return json(409, supersededBody(old.did))
        },
      }),
    ).rejects.toMatchObject({ code: 'did_superseded' })
    expect(bodies).toEqual([old.did])
  })

  it('propagates a broken chain as its own diagnosis, not a login failure', async () => {
    const { old, next, docs, chainOptions } = update()
    // Re-point the old document at a successor on a DIFFERENT stable subject path.
    const other = createAnpIdentity(HOST, { path: ['user', 'bob'] })
    const bad: Record<string, unknown> = { ...old.didDocument, deactivated: true, successorDid: other.did }
    delete bad.proof
    bad.proof = signDidDocumentProofSync(bad, old.keyid, old.priv)
    docs.set(didToUrl(old.did), bad)
    docs.set(didToUrl(other.did), other.didDocument)

    const config = createConfig([connectorFor(old), connectorFor(next)])
    await expect(
      login(config, {
        connectorId: old.did,
        nonce: 'n1',
        targetUri: LOGIN_URI,
        didChain: chainOptions,
        onDidSuperseded: () => connectorFor(next),
        transport: async () => json(409, supersededBody(old.did, next.did)),
      }),
    ).rejects.toMatchObject({ code: 'did_chain_broken' })
  })

  it('refuses to retry from a store-cached terminal the walk never confirmed live', async () => {
    // The chain is signature-less, so its assurance rests entirely on §2.5.5's provider
    // assertion — which requires every document, the TERMINAL included, to have been
    // fetched in THIS resolution. The active successor sits in the caller's store, and a
    // stored copy cannot show an update made since it was written, so nothing here
    // confirms that `next` is still current: retrying as it would mean signing with a
    // DID nobody just confirmed. The caller DID opt into `provider_asserted`, which is
    // exactly the opt-in this must not be defeated by (ANP-2026-09-17-01).
    const old = createAnpIdentity(HOST, { path: PATH })
    const next = createAnpIdentity(HOST, { path: PATH })
    const transition: Record<string, unknown> = {
      ...old.didDocument,
      deactivated: true,
      successorDid: next.did,
    }
    delete transition.proof // §2.5.5 permits an absent proof on a transition document

    const docs = new Map<string, Record<string, unknown>>([
      [didToUrl(old.did), transition],
      [didToUrl(next.did), next.didDocument],
    ])
    const store = createDidDocumentStore()
    await store.set({
      did: next.did,
      document: next.didDocument,
      docUrl: didToUrl(next.did),
      source: 'network',
      fetchedAt: Date.now(),
    })

    const config = createConfig([connectorFor(old), connectorFor(next)])
    const { bodies, record } = requests()
    let calls = 0
    let hooked = 0

    await expect(
      login(config, {
        connectorId: old.did,
        nonce: 'n1',
        targetUri: LOGIN_URI,
        didChain: {
          allowedHosts: [HOST],
          resolveAddresses: async () => ['93.184.216.34'],
          allowUncontrolledFetch: true,
          fetch: didServer(docs),
          documentStore: store,
          acceptProviderAsserted: true,
        },
        onDidSuperseded: () => {
          hooked += 1
          return connectorFor(next)
        },
        transport: async (_url, init) => {
          record(init)
          calls += 1
          return json(409, supersededBody(old.did, next.did))
        },
      }),
    ).rejects.toMatchObject({ code: 'did_chain_assurance_too_low' })

    // One rejected request, no retry: the opt-in is not a licence to sign blind.
    expect(bodies).toEqual([old.did])
    expect(calls).toBe(1)
    expect(hooked).toBe(0)
  })

  it('does not act on a report that names a DID we never signed with', async () => {
    const { old, next, chainOptions } = update()
    const config = createConfig([connectorFor(old), connectorFor(next)])
    const { bodies, record } = requests()

    await expect(
      login(config, {
        connectorId: old.did,
        nonce: 'n1',
        targetUri: LOGIN_URI,
        didChain: chainOptions,
        onDidSuperseded: () => connectorFor(next),
        transport: async (_url, init) => {
          record(init)
          // The body rejects a different DID than the one we proved.
          return json(409, supersededBody('did:wba:example.com:user:someone-else:e1_x', next.did))
        },
      }),
    ).rejects.toMatchObject({ code: 'did_superseded' })
    expect(bodies).toEqual([old.did])
  })

  it('leaves an unrelated 409 alone (handle_taken is not an update)', async () => {
    const { old, chainOptions } = update()
    const config = createConfig([connectorFor(old)])
    await expect(
      register(config, {
        connectorId: old.did,
        handle: 'alice',
        nonce: 'n1',
        targetUri: REGISTER_URI,
        didChain: chainOptions,
        onDidSuperseded: () => undefined,
        transport: async () => json(409, { code: 'handle_taken', error: 'taken' }),
      }),
    ).rejects.toMatchObject({ code: 'register_failed', serverCode: 'handle_taken' })
  })

  it('retries a registration too, and keeps the confirmed handle', async () => {
    const { old, next, chainOptions } = update()
    const config = createConfig([connectorFor(old), connectorFor(next)])
    const { bodies, record } = requests()
    let calls = 0

    const outcome = await register(config, {
      connectorId: old.did,
      handle: 'alice',
      nonce: 'n1',
      targetUri: REGISTER_URI,
      didChain: chainOptions,
      onDidSuperseded: () => connectorFor(next),
      transport: async (_url, init) => {
        record(init)
        calls += 1
        if (calls === 1) return json(409, supersededBody(old.did, next.did))
        return json(200, { handle: 'alice', token: 'tok' })
      },
    })

    expect(bodies).toEqual([old.did, next.did])
    expect(outcome).toMatchObject({ did: next.did, handle: 'alice', token: 'tok' })
  })

  it('follows the server challenge on the retry, not the original nonce', async () => {
    // A server that burned the first nonce answers the retry with a fresh challenge;
    // the retry must go through the same 401 treatment as the first attempt.
    const { old, next, chainOptions } = update()
    const config = createConfig([connectorFor(old), connectorFor(next)])
    const nonces: string[] = []
    let calls = 0

    const outcome = await login(config, {
      connectorId: old.did,
      nonce: 'stale',
      targetUri: LOGIN_URI,
      didChain: chainOptions,
      onDidSuperseded: () => connectorFor(next),
      transport: async (_url, init) => {
        nonces.push((JSON.parse(String(init.body)) as { nonce: string }).nonce)
        calls += 1
        if (calls === 1) return json(409, supersededBody(old.did, next.did))
        if (calls === 2) {
          return new Response(JSON.stringify({ error: 'invalid_nonce' }), {
            status: 401,
            headers: { 'www-authenticate': 'DIDWba realm="example.com", error="invalid_nonce", nonce="fresh"' },
          })
        }
        return json(200, { token: 'tok' })
      },
    })

    expect(nonces).toEqual(['stale', 'stale', 'fresh'])
    expect(outcome.did).toBe(next.did)
  })

  it('accepts a connectorId from the hook, not only a connector', async () => {
    const { old, next, chainOptions } = update()
    const nextConnector = connectorFor(next)
    const config = createConfig([connectorFor(old), nextConnector])
    let calls = 0

    const outcome = await login(config, {
      connectorId: old.did,
      nonce: 'n1',
      targetUri: LOGIN_URI,
      didChain: chainOptions,
      onDidSuperseded: () => nextConnector.id,
      transport: async () => {
        calls += 1
        return calls === 1 ? json(409, supersededBody(old.did, next.did)) : json(200, { token: 'tok' })
      },
    })
    expect(outcome.did).toBe(next.did)
  })
})
