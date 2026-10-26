import { describe, it, expect } from 'vitest'
import { ConnectxError } from '../errors'
import {
  buildMessageRequest,
  buildMessageNotification,
  isNotification,
  parseEnvelope,
  profileRejection,
  toErrorObject,
  type AnpMeta,
} from './envelope'

function meta(overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile: 'anp.direct.base.v1',
    security_profile: 'transport-protected',
    sender_did: 'did:wba:a.example:user:alice:e1_abc',
    target: { kind: 'agent', did: 'did:wba:b.example:user:bob:e1_xyz' },
    operation_id: 'op-1',
    message_id: 'msg-1',
    content_type: 'text/plain',
    ...overrides,
  }
}

describe('buildMessageRequest', () => {
  it('produces a request our own parser accepts, unchanged', () => {
    // The invariant that matters: one package both emits and parses this shape, so a
    // builder whose output `parseEnvelope` would refuse is a request no peer can read.
    const request = buildMessageRequest({
      id: 'req-1',
      method: 'direct.send',
      meta: meta(),
      body: { text: 'hello' },
    })
    const parsed = parseEnvelope(request)
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect(parsed.value).toEqual(request)
    expect(isNotification(parsed.value)).toBe(false)
  })

  it('defaults body to an object, so a bodyless method is still spec-shaped', () => {
    // `anp.get_capabilities` sends `"body": {}` — P1 §5.1 wants `params` to be an
    // object, and an omitted `body` would make it a different one.
    const request = buildMessageRequest({ id: 'req-1', method: 'anp.get_capabilities', meta: meta() })
    expect(request.params.body).toEqual({})
    expect(parseEnvelope(request).ok).toBe(true)
  })

  it('includes auth only when it is given', () => {
    const without = buildMessageRequest({ id: 'r', method: 'anp.get_capabilities', meta: meta() })
    expect('auth' in without.params).toBe(false)

    const auth = {
      scheme: 'anp-rfc9421-origin-proof-v1',
      origin_proof: { contentDigest: 'd', signatureInput: 'i', signature: 's' },
    }
    const with_ = buildMessageRequest({ id: 'r', method: 'direct.send', meta: meta(), auth })
    expect(with_.params.auth).toEqual(auth)
    expect(parseEnvelope(with_).ok).toBe(true)
  })

  it('keeps the spec order meta / auth / body on the wire', () => {
    const request = buildMessageRequest({
      id: 'r',
      method: 'direct.send',
      meta: meta(),
      auth: { scheme: 'anp-rfc9421-origin-proof-v1', origin_proof: { contentDigest: 'd', signatureInput: 'i', signature: 's' } },
      body: { text: 'hi' },
    })
    expect(Object.keys(request.params)).toEqual(['meta', 'auth', 'body'])
  })

  it('refuses an id that is not a non-empty string (P1 §5.2 L157)', () => {
    for (const id of ['', undefined as unknown as string]) {
      expect(() => buildMessageRequest({ id, method: 'direct.send', meta: meta() })).toThrow(ConnectxError)
    }
  })

  it('refuses the reserved rpc. prefix (P1 §5.5 L188)', () => {
    expect(() => buildMessageRequest({ id: 'r', method: 'rpc.discover', meta: meta() })).toThrow(
      /reserved "rpc\." prefix/,
    )
  })

  it('refuses an unknown core meta field (P1 §12.1 L776)', () => {
    // `x_` is the escape hatch; anything else is a field no peer may be sent.
    const bad = { ...meta(), bogus: 1 } as unknown as AnpMeta
    expect(() => buildMessageRequest({ id: 'r', method: 'direct.send', meta: bad })).toThrow(
      /Unknown core meta field "bogus"/,
    )

    const extension = { ...meta(), x_anpiocli_retry: 1 } as unknown as AnpMeta
    expect(() => buildMessageRequest({ id: 'r', method: 'direct.send', meta: extension })).not.toThrow()
  })
})

describe('buildMessageNotification', () => {
  it('produces a notification our own parser accepts, unchanged', () => {
    const notification = buildMessageNotification({
      method: 'direct.incoming',
      meta: meta(),
      body: { text: 'hi' },
    })
    const parsed = parseEnvelope(JSON.parse(JSON.stringify(notification)))
    expect(parsed.ok).toBe(true)
    expect(parsed.ok && isNotification(parsed.value)).toBe(true)
  })

  it('carries no id, even when the input object has one', () => {
    // §5.6 L201/L204 hang "the peer must answer" on `id`, so an envelope that has one is
    // a Request and this builder's whole job is to not be one. `buildOutbound` only ever
    // writes method / meta / body, which is what makes that structural rather than a
    // convention a spread could break.
    const withId = { id: 'req-1', method: 'direct.incoming', meta: meta(), body: {} }
    const notification = buildMessageNotification(withId)
    expect('id' in notification).toBe(false)
    expect(Object.keys(notification)).toEqual(['jsonrpc', 'method', 'params'])
  })

  it('carries the origin proof through unchanged', () => {
    // P3 §7.2.3 L420: the intermediary forwards the ORIGINAL business proof. It is not
    // this builder's business to check that — only to not be a place that drops it.
    const auth = {
      scheme: 'anp-rfc9421-origin-proof-v1',
      origin_proof: { contentDigest: 'sha-256=:a:', signatureInput: 'sig1=("@method")', signature: 'sig1=:b:' },
    }
    const notification = buildMessageNotification({ method: 'direct.incoming', meta: meta(), auth })
    expect(notification.params.auth).toEqual(auth)
  })

  it('applies the same unconditional checks as a request', () => {
    expect(() => buildMessageNotification({ method: 'rpc.discover', meta: meta() })).toThrow(
      /reserved "rpc\." prefix/,
    )
    const bad = { ...meta(), bogus: 1 } as unknown as AnpMeta
    expect(() => buildMessageNotification({ method: 'direct.incoming', meta: bad })).toThrow(
      /Unknown core meta field "bogus"/,
    )
  })

  it('defaults an absent body to an empty object, like a request does', () => {
    const notification = buildMessageNotification({ method: 'anp.get_capabilities', meta: meta() })
    expect(notification.params.body).toEqual({})
  })
})

describe('profileRejection', () => {
  // P1 §10.3 L697 固定的只是公共段 1000–1021；业务 Profile 的码在它之外（P3 2000–2007）。
  // 这条护栏守的是：那种码能进 `anp_code`，且 `code` 不被误算成公共表里的值。
  it('carries a code from a Profile segment, not the P1 table', () => {
    const rejection = profileRejection(2005, 'direct.invalid_origin_proof', 'origin_proof did not verify')
    expect(rejection.code).toBe(2005)
    expect(toErrorObject(rejection).data).toMatchObject({
      anp_code: 'direct.invalid_origin_proof',
      retryable: false,
    })
  })

  it('marks a retryable Profile error as such', () => {
    const rejection = profileRejection(2000, 'direct.recipient_unreachable', 'try again', { retryable: true })
    expect(rejection.retryable).toBe(true)
  })
})
