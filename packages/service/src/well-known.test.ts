import { describe, expect, it } from 'vitest'
import { discoverMessageService, type ServiceEntry, type ServiceLocator } from '@agentx/core'
import { buildServiceEntry } from './well-known'
import { loadConfig } from './config'

/** A deployment whose public URL and service DID are not derived from loopback, so the two
 *  fields the document reports are visibly distinct from each other. */
const entry = () =>
  buildServiceEntry(
    loadConfig({ AGENTX_PUBLIC_URL: 'https://agentx.example', AGENTX_SERVICE_DID: 'did:web:agentx.example' }),
  )

describe('the service entry', () => {
  it('carries the three fields P2 §7.1 L337–341 makes mandatory', () => {
    const built = entry()
    expect(built.id).toBe('did:web:agentx.example#anp-message-service')
    expect(built.type).toBe('ANPMessageService')
    expect(built.serviceEndpoint).toBe('https://agentx.example/anp-im/rpc')
  })

  it('reports the service DID it was configured with, as a DID and not a DID URL', () => {
    // §8.7 L512. The config layer refuses a fragment or query, so what gets here is already
    // a bare DID; this pins that the document does not decorate it.
    expect(entry().serviceDid).toBe('did:web:agentx.example')
  })

  it('derives the endpoint from the public URL rather than from the listen address', () => {
    // The service may bind 127.0.0.1:8787 behind a proxy that publishes https://…; the
    // document must name the address the world reaches, not the one the socket is on.
    const behindProxy = buildServiceEntry(
      loadConfig({
        AGENTX_LISTEN: '127.0.0.1:8787',
        AGENTX_PUBLIC_URL: 'https://agentx.example/anp',
        AGENTX_SERVICE_DID: 'did:web:agentx.example:anp',
      }),
    )
    expect(behindProxy.serviceEndpoint).toBe('https://agentx.example/anp/anp-im/rpc')
  })
})

describe('what counts as a profile of the service', () => {
  it('advertises the spec profiles and keeps every extension out of them', () => {
    const built = entry()
    expect(built.profiles).toEqual([
      'anp.attachment.v1',
      'anp.core.binding.v1',
      'anp.direct.base.v1',
      'anp.direct.e2ee.v2',
      'anp.group.base.v2',
    ])
    expect(built.securityProfiles).toEqual(['direct-e2ee', 'group-e2ee', 'transport-protected'])
    // §13 L834–838: a client that reads these is deciding what it may send, and an
    // `x_agentx.*` value there would make a spec-only service look like it spoke them.
    for (const profile of [...built.profiles, ...built.securityProfiles]) {
      expect(profile.startsWith('x_')).toBe(false)
    }
  })

  it('puts the extensions in the x_agentx block instead', () => {
    const built = entry()
    expect(built.x_agentx.profiles).toEqual([
      'x_agentx.contacts.v1',
      'x_agentx.group_remarks.v1',
      'x_agentx.inbox.v1',
      'x_agentx.stream.v1',
    ])
    expect(built.x_agentx.methods).toEqual([
      'contacts.list',
      'contacts.put',
      'contacts.remove',
      'group_remarks.list',
      'group_remarks.put',
      'group_remarks.remove',
      'inbox.get',
      'inbox.mark_read',
      'message.get_batch',
      'stream.ack',
      'stream.auth',
      'sync.delta',
    ])
  })

  it('does not list the spec methods among the extensions', () => {
    const { methods } = entry().x_agentx
    expect(methods).not.toContain('direct.send')
    expect(methods).not.toContain('anp.get_capabilities')
  })
})

describe('the interface with whoever embeds it', () => {
  it('is an entry the client side of this repo reads back', async () => {
    // The DID Service embeds the object; what proves the interface is that core's own
    // discovery — the code a client uses — turns it into the same endpoint and DIDs. The
    // `id` is the one field the embedder rewrites (it belongs to the agent's document, not
    // this service's), so the stub does that and nothing else.
    const built = buildServiceEntry(
      loadConfig({ AGENTX_PUBLIC_URL: 'https://agentx.example', AGENTX_SERVICE_DID: 'did:web:agentx.example' }),
    )
    const locator: ServiceLocator = {
      locate: (identity: string): Promise<ServiceEntry[]> => Promise.resolve([{ ...built, id: `${identity}#anp-message-service` }]),
    }

    const target = await discoverMessageService('did:web:agentx.example', { locator })
    expect(target.serviceId).toBe('did:web:agentx.example#anp-message-service')
    expect(target.endpoint).toBe('https://agentx.example/anp-im/rpc')
    expect(target.serviceDid).toBe('did:web:agentx.example')
    expect(target.hintedProfiles).toEqual(built.profiles)
    expect(target.hintedSecurityProfiles).toEqual(built.securityProfiles)
  })
})
