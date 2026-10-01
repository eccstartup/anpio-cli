import { describe, it, expect } from 'vitest'
import { discoverMessageService, negotiateProfiles, parseCapabilities } from './discovery'
import type { ServiceLocator, ServiceEntry } from './locator'

function locatorOf(services: ServiceEntry[]): ServiceLocator {
  return { async locate() { return services } }
}

const MESSAGE_SERVICE: ServiceEntry = {
  id: 'did:wba:peer.example:user:bob:e1_x#anp-message-service',
  type: 'ANPMessageService',
  serviceEndpoint: 'https://peer.example/anp-im/rpc',
  serviceDid: 'did:web:peer.example',
  profiles: ['anp.direct.base.v1'],
  securityProfiles: ['transport-protected'],
}

describe('discoverMessageService', () => {
  it('returns the single ANPMessageService entry with its hints', async () => {
    const target = await discoverMessageService('did:wba:peer.example:user:bob:e1_x', {
      locator: locatorOf([MESSAGE_SERVICE, { id: '#ad', type: 'AgentDescription', serviceEndpoint: 'https://peer.example/ad.json' }]),
    })
    expect(target.endpoint).toBe('https://peer.example/anp-im/rpc')
    expect(target.serviceDid).toBe('did:web:peer.example')
    expect(target.hintedProfiles).toEqual(['anp.direct.base.v1'])
  })

  it('rejects a document with two ANPMessageService entries', async () => {
    // P2 §7.1: exactly one cross-domain entry is a MUST. Picking "the first" would
    // work locally and fail interoperably, so this cannot be lenient.
    await expect(
      discoverMessageService('did:wba:peer.example:user:bob:e1_x', {
        locator: locatorOf([MESSAGE_SERVICE, { ...MESSAGE_SERVICE, id: '#second' }]),
      }),
    ).rejects.toThrow(/exposes 2 ANPMessageService entries/)
  })

  it('rejects a document with none', async () => {
    await expect(
      discoverMessageService('did:wba:peer.example:user:bob:e1_x', { locator: locatorOf([]) }),
    ).rejects.toThrow(/exposes 0 ANPMessageService entries/)
  })

  it('omits serviceDid when the entry does not declare one', async () => {
    const { serviceDid: _drop, ...noServiceDid } = MESSAGE_SERVICE
    const target = await discoverMessageService('did:wba:peer.example:user:bob:e1_x', {
      locator: locatorOf([noServiceDid]),
    })
    expect('serviceDid' in target).toBe(false)
  })
})

describe('parseCapabilities', () => {
  it('reads the underscore-named runtime result', () => {
    const caps = parseCapabilities({
      service_did: 'did:web:agentx.example',
      supported_profiles: ['anp.core.binding.v1'],
      supported_security_profiles: ['transport-protected'],
      limits: { max_request_bytes: '1048576' },
      supported_content_types: ['text/plain'],
    })
    expect(caps.serviceDid).toBe('did:web:agentx.example')
    expect(caps.supportedProfiles).toEqual(['anp.core.binding.v1'])
    // §7.3 L491: counter limits are decimal STRINGS, not numbers.
    expect(caps.limits.max_request_bytes).toBe('1048576')
  })

  it('rejects a result missing the two required lists', () => {
    expect(() => parseCapabilities({ supported_profiles: ['anp.core.binding.v1'] })).toThrow(
      /supported_profiles and supported_security_profiles/,
    )
  })

  it('treats the optional members as absent rather than malformed', () => {
    const caps = parseCapabilities({
      supported_profiles: [],
      supported_security_profiles: [],
    })
    expect(caps.limits).toEqual({})
    expect(caps.supportedContentTypes).toEqual([])
    expect(caps.serviceDid).toBeUndefined()
  })
})

describe('negotiateProfiles', () => {
  const hinted = { hintedProfiles: ['anp.direct.base.v1'], hintedSecurityProfiles: ['transport-protected'] }

  it('prefers the runtime result over the static hint', () => {
    const result = negotiateProfiles({
      hinted,
      runtime: {
        supportedProfiles: ['anp.core.binding.v1'],
        supportedSecurityProfiles: ['direct-e2ee'],
        limits: {},
        supportedContentTypes: [],
      },
    })
    expect(result).toEqual({
      profiles: ['anp.core.binding.v1'],
      securityProfiles: ['direct-e2ee'],
      source: 'runtime',
    })
  })

  it('falls back to the hint as a whole, not field by field', () => {
    expect(negotiateProfiles({ hinted })).toEqual({
      profiles: ['anp.direct.base.v1'],
      securityProfiles: ['transport-protected'],
      source: 'hint',
    })
  })
})
