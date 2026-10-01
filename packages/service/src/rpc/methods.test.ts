import { describe, expect, it } from 'vitest'
import type { AnpMeta } from '@agentx/core'
import { DIRECT_SEND, checkMethod, lookupMethod, targetBindingHolds } from './methods'
import type { MethodSpec } from './methods'

const spec = (): MethodSpec => {
  const found = lookupMethod(DIRECT_SEND)
  if (found === undefined) throw new Error('the table lost direct.send')
  return found
}

function meta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: 'did:web:sender.example',
    target: { kind: 'agent', did: 'did:web:receiver.example' },
    operation_id: 'op-1',
    message_id: 'msg-1',
    content_type: 'text/plain',
    ...overrides,
  }
}

describe('lookupMethod', () => {
  it('knows direct.send and nothing else', () => {
    expect(lookupMethod(DIRECT_SEND)?.name).toBe('direct.send')
    expect(lookupMethod('direct.sendx')).toBeUndefined()
    expect(lookupMethod('group.create')).toBeUndefined()
  })
})

describe('checkMethod', () => {
  it('accepts meta that satisfies every declared MUST', () => {
    expect(checkMethod(spec(), meta())).toBeUndefined()
  })

  it('refuses an unsupported profile with 1001', () => {
    const refused = checkMethod(spec(), meta({ profile: 'anp.direct.e2ee.v2' }))
    expect(refused?.code).toBe(1001)
    expect(refused?.anpCode).toBe('anp.unsupported_profile')
  })

  it('refuses an unsupported security profile with 1002', () => {
    const refused = checkMethod(spec(), meta({ security_profile: 'e2ee' }))
    expect(refused?.code).toBe(1002)
    expect(refused?.anpCode).toBe('anp.unsupported_security_profile')
  })

  it.each(['sender_did', 'operation_id', 'message_id', 'content_type'] as const)(
    'refuses a missing meta.%s with 1003',
    (field) => {
      const refused = checkMethod(spec(), meta({ [field]: undefined }))
      expect(refused?.code).toBe(1003)
      expect(refused?.message).toContain(`meta.${field}`)
    },
  )

  it.each(['sender_device_id', 'recipient_device_id'] as const)(
    'refuses meta.%s on a Base operation with 1003, and not with a 1015-series code',
    (field) => {
      // P3 §7.1.2 L362 keeps the selectors out of `direct.send`; §10.3 L724 says a Base
      // operation that receives one treats it as an invalid parameter, and that the four
      // device codes belong to the device-addressed E2EE overlays only.
      const refused = checkMethod(spec(), meta({ [field]: 'dev-1' }))
      expect(refused?.code).toBe(1003)
      expect(refused?.anpCode).toBe('anp.invalid_params_shape')
    },
  )

  it('refuses a missing target with 1003, because what is wrong is the shape', () => {
    const refused = checkMethod(spec(), meta({ target: undefined }))
    expect(refused?.code).toBe(1003)
  })

  it('refuses a target kind that is not the declared modelling mode with 1014', () => {
    const refused = checkMethod(spec(), meta({ target: { kind: 'group', did: 'did:web:g.example' } }))
    expect(refused?.code).toBe(1014)
    expect(refused?.anpCode).toBe('anp.invalid_target_binding')
    expect(refused?.details).toEqual({ received: 'group' })
  })

  it('checks the profile before anything else, so the client hears the real reason', () => {
    const refused = checkMethod(spec(), meta({ profile: 'nope', message_id: undefined }))
    expect(refused?.anpCode).toBe('anp.unsupported_profile')
  })
})

describe('targetBindingHolds', () => {
  it('requires an agent target for an agent-addressed method', () => {
    expect(targetBindingHolds(spec(), { kind: 'agent', did: 'did:web:a' })).toBe(true)
    expect(targetBindingHolds(spec(), { kind: 'service', did: 'did:web:a' })).toBe(false)
  })

  it('has nothing to compare for an endpoint-local method', () => {
    // The mode that allows omitting `target` names no kind, so there is nothing for a
    // target — or its absence — to disagree with.
    const local: MethodSpec = { ...spec(), targetMode: 'endpoint-local' }
    expect(targetBindingHolds(local, undefined)).toBe(true)
    expect(targetBindingHolds(local, { kind: 'service', did: 'did:web:a' })).toBe(true)
  })
})

describe('the origin-proof override', () => {
  it('requires a proof for the Base profile', () => {
    expect(spec().requiresOriginProof(meta())).toBe(true)
  })

  it('drops the requirement for anp.direct.e2ee.v2', () => {
    // P3 §4.3 L161: that overlay authenticates the sender through its own key material
    // and AAD, and it overrides P3 §6.4 L290's rule. The branch is unreachable through
    // `checkMethod` today — `profiles` refuses the overlay first — and becomes reachable
    // in C12, when the overlay is added to `profiles` and this line must not be forgotten.
    expect(spec().requiresOriginProof(meta({ profile: 'anp.direct.e2ee.v2' }))).toBe(false)
  })
})
