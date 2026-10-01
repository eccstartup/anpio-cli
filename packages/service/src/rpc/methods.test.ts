import { describe, expect, it } from 'vitest'
import { ORIGIN_PROOF_SCHEME, type AnpMeta, type AnpParams } from '@agentx/core'
import { DIRECT_SEND, GET_CAPABILITIES, checkMethod, groupMethodNames, lookupMethod, lookupStreamMethod, targetBindingHolds } from './methods'
import type { MethodSpec } from './methods'
import { GROUP_HANDLERS } from './groups'
import { STREAM_AUTH } from './stream'

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

/** `checkMethod` 收整个 `params`（它中间要跑 `validateParams`），所以测试也得给一个 `auth`
 *  位——不给就是"没有 `auth`"，那正是 Base 与 v2 都要的那种情形之一。 */
function params(overrides: Partial<AnpMeta> = {}): AnpParams {
  return { meta: meta(overrides), body: {} }
}

describe('lookupMethod', () => {
  it('knows the spec methods and nothing else', () => {
    expect(lookupMethod(DIRECT_SEND)?.name).toBe('direct.send')
    expect(lookupMethod(GET_CAPABILITIES)?.name).toBe('anp.get_capabilities')
    expect(lookupMethod('direct.sendx')).toBeUndefined()
    // P4 §8.12 L934：`group.member_did_update` 是保留的 Host 动作标识，**不是** JSON-RPC
    // 方法；调用它 MUST 收到 -32601，而这一层就是 -32601 的来源。
    expect(lookupMethod('group.member_did_update')).toBeUndefined()
  })

  it('has a handler for every group method it declares', () => {
    // 群方法在分发层是按名字查处理器的（`groups.ts` 的 `GROUP_HANDLERS`），所以"方法表里
    // 有、处理器表里没有"这件事不会在编译期红，只会在运行时变成一个 500。
    for (const name of groupMethodNames()) {
      expect(GROUP_HANDLERS[name]).toBeTypeOf('function')
    }
  })

  it('does not hand a stream method to the control plane', () => {
    // realtime.md §9: `stream.auth` is reachable over one transport only, and the way that
    // is enforced is that this table does not contain it.
    expect(lookupMethod(STREAM_AUTH)).toBeUndefined()
    expect(lookupStreamMethod(STREAM_AUTH)?.name).toBe(STREAM_AUTH)
    expect(lookupStreamMethod(DIRECT_SEND)).toBeUndefined()
  })
})

describe('checkMethod', () => {
  it('accepts meta that satisfies every declared MUST', () => {
    expect(checkMethod(spec(), params())).toBeUndefined()
  })

  it('refuses an unsupported profile with 1001', () => {
    // `anp.direct.e2ee.v2` 从 C12 起就在这个方法的 `profiles` 里，所以这里换一个真的
    // 不受支持的——用 v2 当反例的写法在 C12 之后会变成"故意写一个错的期望"。
    const refused = checkMethod(spec(), params({ profile: 'anp.direct.e2ee.v3' }))
    expect(refused?.code).toBe(1001)
    expect(refused?.anpCode).toBe('anp.unsupported_profile')
  })

  it('refuses an unsupported security profile with 1002', () => {
    const refused = checkMethod(spec(), params({ security_profile: 'e2ee' }))
    expect(refused?.code).toBe(1002)
    expect(refused?.anpCode).toBe('anp.unsupported_security_profile')
  })

  it.each(['sender_did', 'operation_id', 'message_id', 'content_type'] as const)(
    'refuses a missing meta.%s with 1003',
    (field) => {
      const refused = checkMethod(spec(), params({ [field]: undefined }))
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
      const refused = checkMethod(spec(), params({ [field]: 'dev-1' }))
      expect(refused?.code).toBe(1003)
      expect(refused?.anpCode).toBe('anp.invalid_params_shape')
    },
  )

  it('refuses a missing target with 1003, because what is wrong is the shape', () => {
    const refused = checkMethod(spec(), params({ target: undefined }))
    expect(refused?.code).toBe(1003)
  })

  it('refuses a target kind that is not the declared modelling mode with 1014', () => {
    const refused = checkMethod(spec(), params({ target: { kind: 'group', did: 'did:web:g.example' } }))
    expect(refused?.code).toBe(1014)
    expect(refused?.anpCode).toBe('anp.invalid_target_binding')
    expect(refused?.details).toEqual({ received: 'group' })
  })

  it('checks the profile before anything else, so the client hears the real reason', () => {
    const refused = checkMethod(spec(), params({ profile: 'nope', message_id: undefined }))
    expect(refused?.anpCode).toBe('anp.unsupported_profile')
  })
})

/**
 * P5 §3.6–§3.8 与 §9.3：同一个 `direct.send`，在 `anp.direct.e2ee.v2` 下换了一整套 wire
 * 契约。这一组是那套契约里**方法表判得了**的部分——判不了的（正文里的字段与两个 id 对不对
 * 得上）是收件设备的事，本服务不解密（§10.7 L1392）。
 */
describe('direct.send under the e2ee overlay', () => {
  const e2ee = (overrides: Partial<AnpMeta> = {}): AnpParams =>
    params({
      profile: 'anp.direct.e2ee.v2',
      security_profile: 'direct-e2ee',
      content_type: 'application/anp-direct-init+json',
      sender_device_id: 'dev-s',
      recipient_device_id: 'dev-r',
      // §3.7 L134 要这两个相等，所以夹具里就相等——每一条 v2 用例都在这个前提下才谈得上
      // "下一件不对的事是什么"。
      message_id: 'op-1',
      ...overrides,
    })

  it('accepts the §9.3 shape', () => {
    expect(checkMethod(spec(), e2ee())).toBeUndefined()
  })

  it.each(['sender_device_id', 'recipient_device_id'] as const)(
    'refuses a missing meta.%s with 1015, the device-addressing code',
    (field) => {
      // P1 §10.3 L713 defines 1015 as exactly "a device selector the overlay requires is
      // missing" — the envelope's own 1003 would describe a spec-authored code as a
      // generic shape problem.
      const refused = checkMethod(spec(), e2ee({ [field]: undefined }))
      expect(refused?.code).toBe(1015)
      expect(refused?.anpCode).toBe('anp.device_binding_required')
    },
  )

  it('accepts the cipher content type too: one direct.send carries either hop (§3.6 L120)', () => {
    expect(checkMethod(spec(), e2ee({ content_type: 'application/anp-direct-cipher+json' }))).toBeUndefined()
  })

  it('refuses a content type outside §3.6 L120 with 1009', () => {
    const refused = checkMethod(spec(), e2ee({ content_type: 'text/plain' }))
    expect(refused?.code).toBe(1009)
    expect(refused?.anpCode).toBe('anp.unsupported_content_type')
  })

  it('refuses an operation_id that is not the message_id, per §3.7 L134', () => {
    const refused = checkMethod(spec(), e2ee({ operation_id: 'op-2' }))
    expect(refused?.code).toBe(1003)
    expect(refused?.anpCode).toBe('anp.invalid_params_shape')
    expect(refused?.message).toContain('operation_id')
  })

  it('refuses params.auth, per §3.8 L140', () => {
    // Not "ignore it": the spec says the receiver MUST reject it. The accountability
    // extension that would allow it is not negotiated, so there is no exception branch —
    // and a well-formed proof is refused exactly like a malformed one, which is the point:
    // this branch is about the field being there at all.
    const auth = {
      scheme: ORIGIN_PROOF_SCHEME,
      origin_proof: { contentDigest: 'sha-256=:x:', signatureInput: 'sig1=()', signature: 'sig1=:x:' },
    }
    const refused = checkMethod(spec(), { ...e2ee(), auth })
    expect(refused?.code).toBe(1003)
    expect(refused?.message).toContain('auth')
  })

  it('does not run the P3 payload rule, because a v2 body has no body.payload', () => {
    // §16.1–16.4 put the E2EE carrier object at the **top level** of `body`; nothing under
    // `body.payload` exists to satisfy `payloadFieldRequiredBy`. Running it here would
    // reject every valid v2 request with the spec's own validation.
    expect(spec().validateBody?.({ session_id: 's', ciphertext_b64u: 'x' }, e2ee().meta)).toBeUndefined()
    // …and the Base path still runs it, so the skip is a branch and not a deletion.
    expect(spec().validateBody?.({}, meta())?.code).toBe(1003)
  })

  it('hands both device selectors to the idempotency key, sender first (§11.5 L1458)', () => {
    expect(spec().deviceAddressed?.(e2ee().meta, {})).toEqual({
      pairs: [
        { identity: 'did:web:sender.example', deviceId: 'dev-s' },
        { identity: 'did:web:receiver.example', deviceId: 'dev-r' },
      ],
      requirement: {
        profiles: expect.arrayContaining(['anp.direct.e2ee.v2']),
        signingRelationship: 'assertionMethod',
        e2eeRelationship: 'keyAgreement',
      },
    })
  })

  it('has no device addressing on a Base operation', () => {
    // §9.1 L639: for a DID-addressed Base operation the device identifiers are not part of
    // the idempotency scope — and there are none to check either.
    expect(spec().deviceAddressed?.(meta(), {})).toBeUndefined()
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
    // P3 §4.3 L161: that overlay authenticates the sender through its own key material and
    // AAD, and it overrides P3 §6.4 L290's rule. §3.8 L140 goes further and forbids `auth`
    // outright on that profile — the `params.auth` case above is where that side lives, and
    // it is the same `meta.profile` test driving both.
    expect(spec().requiresOriginProof(meta({ profile: 'anp.direct.e2ee.v2' }))).toBe(false)
  })
})
