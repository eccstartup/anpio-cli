// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { discoverDidServer } from './discovery'
import { ConnectxError } from '../errors'

// What a server publishes for ITSELF is the only authority for two facts a registration
// needs: the DID domain to compose the client DID under, and the ANPMessageService entry
// the submitted document must carry. Both are read, never inferred from the URL — a server
// reached at `127.0.0.1:8765` may publish as `did:wba:localhost`, and a client DID composed
// under the URL's host would be refused as a foreign domain.

const origin = 'http://127.0.0.1:8765'
const documentUrl = `${origin}/.well-known/did.json`

const service = {
  id: 'did:wba:localhost#anp-message',
  type: 'ANPMessageService',
  serviceEndpoint: 'http://127.0.0.1:8765/anp-im/rpc',
  serviceDid: 'did:wba:localhost',
  profiles: ['anp.direct.base.v1'],
  securityProfiles: ['transport-protected'],
  authSchemes: ['bearer', 'didwba'],
}

function selfDocument(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: 'did:wba:localhost',
    verificationMethod: [],
    service: [service],
    ...overrides,
  }
}

function answering(status: number, body: string, contentType = 'application/json') {
  let captured: { url: string; init: RequestInit } | undefined
  const transport = async (url: string, init: RequestInit): Promise<Response> => {
    captured = { url, init }
    return new Response(body, { status, headers: { 'content-type': contentType } })
  }
  return { transport, captured: () => captured }
}

function serving(document: unknown) {
  return answering(200, JSON.stringify(document))
}

async function failure(transport: (url: string, init: RequestInit) => Promise<Response>) {
  return discoverDidServer(origin, { transport }).catch((e: unknown) => e)
}

describe('discoverDidServer — reads the domain and the service entry', () => {
  it('reads both out of the document the server publishes for itself', async () => {
    const { transport, captured } = serving(selfDocument())
    const found = await discoverDidServer(origin, { transport })

    expect(captured()!.url).toBe(documentUrl)
    expect(found.documentUrl).toBe(documentUrl)
    expect(found.did).toBe('did:wba:localhost')
    expect(found.didDomain).toBe('localhost')
    // Verbatim, unknown members included: the proof of the document a caller submits
    // covers the whole entry, so a lossy copy could not be accepted.
    expect(found.service).toEqual(service)
  })

  it('accepts any URL on the server, since the well-known path is absolute', async () => {
    const { transport, captured } = serving(selfDocument())
    const found = await discoverDidServer(`${origin}/user-service/v1/did-auth/rpc`, { transport })
    expect(captured()!.url).toBe(documentUrl)
    expect(found.didDomain).toBe('localhost')
  })

  it('decodes a host carrying a port, which the DID spells percent-encoded', async () => {
    const { transport } = serving(
      selfDocument({ id: 'did:wba:127.0.0.1%3A8765', service: [] }),
    )
    // The service array is empty here, so this document is refused for that reason —
    // but the host it publishes is still read the way the DID layer spells it.
    const err = await failure(transport)
    expect((err as ConnectxError).code).toBe('invalid_argument')
    expect((err as ConnectxError).message).toContain('0 ANPMessageService entries')

    const { transport: ok } = serving(
      selfDocument({ id: 'did:wba:127.0.0.1%3A8765', service: [service] }),
    )
    expect((await discoverDidServer(origin, { transport: ok })).didDomain).toBe('127.0.0.1:8765')
  })
})

describe('discoverDidServer — what cannot be read is refused, not guessed', () => {
  const cases: { name: string; respond: () => ReturnType<typeof answering>; expect: string }[] = [
    {
      name: 'a server that publishes no document there',
      respond: () => answering(404, 'not found', 'text/plain'),
      expect: '404',
    },
    {
      name: 'a body that is not JSON',
      respond: () => answering(200, '<html></html>', 'text/html'),
      expect: 'did not answer JSON',
    },
    {
      name: 'a JSON array',
      respond: () => answering(200, '[]'),
      expect: 'not a DID document',
    },
    {
      name: 'a document with no id',
      respond: () => serving(selfDocument({ id: undefined })),
      expect: 'no "id"',
    },
    {
      name: 'an id that is not a did:wba DID',
      respond: () => serving(selfDocument({ id: 'did:web:localhost' })),
      expect: 'did:wba domain',
    },
    {
      name: 'no ANPMessageService entry',
      respond: () => serving(selfDocument({ service: [] })),
      expect: '0 ANPMessageService entries',
    },
    {
      name: 'two ANPMessageService entries',
      respond: () => serving(selfDocument({ service: [service, service] })),
      expect: '2 ANPMessageService entries',
    },
    {
      name: 'an entry with no endpoint',
      respond: () =>
        serving(selfDocument({ service: [{ ...service, serviceEndpoint: undefined }] })),
      expect: 'no "serviceEndpoint"',
    },
    {
      name: 'a host with broken percent-encoding',
      respond: () => serving(selfDocument({ id: 'did:wba:local%ZZhost' })),
      expect: 'broken percent-encoding',
    },
    {
      name: 'a host that is not a host',
      respond: () => serving(selfDocument({ id: 'did:wba:local host' })),
      expect: 'not a host this SDK can compose a DID under',
    },
  ]

  for (const c of cases) {
    it(`refuses ${c.name}, naming the URL`, async () => {
      const { transport } = c.respond()
      const err = await failure(transport)
      expect(err).toBeInstanceOf(ConnectxError)
      expect((err as ConnectxError).code).toBe('invalid_argument')
      expect((err as ConnectxError).message).toContain(c.expect)
    })
  }

  it('reports an unreachable server as a transport failure', async () => {
    const transport = async (): Promise<Response> => {
      throw new Error('fetch failed')
    }
    const err = await failure(transport)
    expect((err as ConnectxError).message).toContain('fetch failed')
  })

  it('refuses a non-URL origin', async () => {
    const { transport } = serving(selfDocument())
    const err = await discoverDidServer('localhost:8765', { transport }).catch((e: unknown) => e)
    expect((err as ConnectxError).message).toContain('not a URL')
  })

  it('holds an oversized document to the SDK’s byte cap', async () => {
    const transport = async (): Promise<Response> =>
      new Response('{}', { status: 200, headers: { 'content-length': String(2 * 1024 * 1024) } })
    const err = await failure(transport)
    expect((err as ConnectxError).code).toBe('response_too_large')
  })
})
