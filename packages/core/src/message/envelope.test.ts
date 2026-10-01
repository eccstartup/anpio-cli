import { describe, it, expect } from 'vitest'
import { ConnectxError } from '../errors'
import { buildMessageRequest, parseEnvelope, isNotification, type AnpMeta } from './envelope'

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

    const extension = { ...meta(), x_agentx_retry: 1 } as unknown as AnpMeta
    expect(() => buildMessageRequest({ id: 'r', method: 'direct.send', meta: extension })).not.toThrow()
  })
})
