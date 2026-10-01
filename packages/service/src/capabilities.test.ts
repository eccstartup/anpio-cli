import { describe, expect, it } from 'vitest'
import { capabilitiesResult, serviceCapabilities, WITHHELD_PROFILE_LIST } from './capabilities'
import { loadConfig } from './config'
import { allMethods } from './rpc/methods'

describe('serviceCapabilities', () => {
  it('files each profile by its namespace, and keeps the two apart', () => {
    const capabilities = serviceCapabilities()
    expect(capabilities.profiles).toEqual([
      'anp.attachment.v1',
      'anp.core.binding.v1',
      'anp.direct.base.v1',
      'anp.direct.e2ee.v2',
      'anp.group.base.v2',
    ])
    expect(capabilities.securityProfiles).toEqual(['direct-e2ee', 'transport-protected'])
    expect(capabilities.extensionProfiles).toEqual(['x_agentx.inbox.v1', 'x_agentx.stream.v1'])
    expect(capabilities.extensionMethods).toEqual([
      'inbox.get',
      'inbox.mark_read',
      'message.get_batch',
      'stream.ack',
      'stream.auth',
      'sync.delta',
    ])
  })

  it('derives them all from the method table, so a method added later cannot be left out', () => {
    // This is the reason the lists are not written by hand: a hand-written copy does not go
    // red when a method arrives, and it is exactly what a client reads to decide what it may
    // send. The loop states the invariant for every spec rather than for the ones that exist
    // today.
    //
    // The one exception is `WITHHELD_PROFILES`, and it is spelled out here rather than left
    // implicit so that the exception stays narrow: a spec's profile is advertised unless the
    // profile was deliberately withheld, and the withheld list itself is pinned below.
    const capabilities = serviceCapabilities()
    const withheld = new Set(WITHHELD_PROFILE_LIST)
    const advertised = new Set([
      ...capabilities.profiles,
      ...capabilities.securityProfiles,
      ...capabilities.extensionProfiles,
    ])
    expect(allMethods().length).toBeGreaterThan(0)
    for (const spec of allMethods()) {
      for (const profile of [...spec.profiles, ...spec.securityProfiles]) {
        if (withheld.has(profile)) continue
        expect(advertised.has(profile)).toBe(true)
      }
      const extension = spec.profiles.every((profile) => profile.startsWith('x_'))
      if (extension) expect(capabilities.extensionMethods).toContain(spec.name)
      else expect(capabilities.extensionMethods).not.toContain(spec.name)
    }
  })

  it('withholds exactly one profile, and only while the spec has not stabilised its codepoint', () => {
    // §6.3.1 L430: the MLS `ExtensionType` `0xF0A1` this profile's device binding is written
    // against "is not an IANA allocation", and "ANP MUST publish a stable registration code
    // point before releasing v2"; §20 L2457 lists that registration among the tables a later
    // version SHOULD establish. Until then a standard client reading `supported_profiles` as
    // the runtime authority (§8.3 L591–593) would take this service as safe to send to, while
    // the extension value it has to embed is still a draft private value.
    //
    // This list is deliberately this short. Adding to it is a promise being withdrawn, so it
    // has to be argued for here — which is why the test names the list rather than counting it.
    expect(WITHHELD_PROFILE_LIST).toEqual(['anp.group.e2ee.v2'])
    // A withheld profile that no method declares would be dead weight, and would hide the
    // fact that the method it was withheld for had been renamed or removed.
    const declared = new Set(allMethods().flatMap((spec) => [...spec.profiles, ...spec.securityProfiles]))
    for (const profile of WITHHELD_PROFILE_LIST) expect(declared.has(profile)).toBe(true)
  })
})

describe('capabilitiesResult', () => {
  it('reports this service did and the cap it actually enforces', () => {
    const config = loadConfig({ AGENTX_SERVICE_DID: 'did:web:agentx.example', AGENTX_MAX_BODY: '2048' })
    expect(capabilitiesResult(config)).toEqual({
      service_did: 'did:web:agentx.example',
      supported_profiles: [
        'anp.attachment.v1',
        'anp.core.binding.v1',
        'anp.direct.base.v1',
        'anp.direct.e2ee.v2',
        'anp.group.base.v2',
      ],
      supported_security_profiles: ['direct-e2ee', 'transport-protected'],
      limits: { max_request_bytes: '2048', max_message_bytes: '2048' },
      supported_content_types: [
        'text/plain',
        'application/json',
        'application/anp-attachment-manifest+json',
        'application/anp-direct-init+json',
        'application/anp-direct-cipher+json',
      ],
    })
  })

  it('carries no extension profile, because this result is the spec conformance answer', () => {
    const result = capabilitiesResult(loadConfig({}))
    for (const profile of result.supported_profiles as string[]) {
      expect(profile.startsWith('x_')).toBe(false)
    }
  })
})
