import { describe, expect, it } from 'vitest'
import type { AnpRejection } from '@agentx/core'
import { errorResponse, failureId, parseRequestText } from './envelope'

/** A request body that passes every check, so a case can break exactly one thing. */
function envelope(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    jsonrpc: '2.0',
    id: 'req-1',
    method: 'direct.send',
    params: {
      meta: {
        profile: 'anp.direct.base.v1',
        security_profile: 'plain',
        sender_did: 'did:web:a.example',
        target: { kind: 'agent', did: 'did:web:b.example' },
      },
      body: { message_id: 'm1' },
    },
    ...overrides,
  })
}

/** The rejection a body produces. The return type is the real one, so a case can read
 *  whatever a rejection happens to carry (`anpCode`, `details`, …) rather than a subset. */
function rejectionOf(text: string): AnpRejection {
  const parsed = parseRequestText(text)
  if (parsed.ok) throw new Error('expected a rejection')
  return parsed.error
}

async function errorBody(response: ReturnType<typeof errorResponse>): Promise<Record<string, unknown>> {
  return JSON.parse(response.body) as Record<string, unknown>
}

describe('a well-formed request', () => {
  it('parses into an envelope with its id and method', () => {
    const parsed = parseRequestText(envelope())
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    // `'id' in` rather than a type guard — see the note on `ParsedRequest`.
    if (!('id' in parsed.value)) throw new Error('expected a request, not a notification')
    expect(parsed.value.id).toBe('req-1')
    expect(parsed.value.method).toBe('direct.send')
  })

  it('parses a notification, which has no id', () => {
    const withId = JSON.parse(envelope()) as Record<string, unknown>
    delete withId.id
    const parsed = parseRequestText(JSON.stringify(withId))
    expect(parsed.ok).toBe(true)
    if (!parsed.ok) return
    expect('id' in parsed.value).toBe(false)
  })

  it('rejects a request whose meta is missing a MUST field', () => {
    const text = JSON.stringify({ jsonrpc: '2.0', id: 'r', method: 'm', params: { meta: {}, body: {} } })
    expect(parseRequestText(text).ok).toBe(false)
  })
})

// message-service.md §3, one case per row.
describe('the §3 table', () => {
  it('rejects a body that is not JSON, with a null id', () => {
    const error = rejectionOf('{oops')
    expect(error.code).toBe(-32700)
    expect(error.anpCode).toBeUndefined()
    expect(failureId('{oops', error)).toBeNull()
  })

  it('rejects jsonrpc that is not exactly "2.0"', () => {
    expect(rejectionOf(envelope({ jsonrpc: '2.1' })).code).toBe(-32600)
  })

  it('rejects a batch with the ANP code rather than -32600 (§5.4 L179)', () => {
    const text = JSON.stringify([JSON.parse(envelope())])
    const error = rejectionOf(text)
    expect(error.anpCode).toBe('anp.batch_not_supported')
    expect(error.code).toBe(1004)
    // A batch has no single id to echo.
    expect(failureId(text, error)).toBeNull()
  })

  it('rejects a numeric id and does not echo it', () => {
    const error = rejectionOf(envelope({ id: 7 }))
    expect(error.anpCode).toBe('anp.invalid_request_id')
    expect(failureId(envelope({ id: 7 }), error)).toBeNull()
  })

  it('rejects a null id', () => {
    expect(rejectionOf(envelope({ id: null })).anpCode).toBe('anp.invalid_request_id')
  })

  it('rejects array params', () => {
    const text = JSON.stringify({ jsonrpc: '2.0', id: 'r', method: 'm', params: [] })
    expect(rejectionOf(text).anpCode).toBe('anp.invalid_params_shape')
  })

  it('rejects a top-level params member that is not meta / auth / body', () => {
    const text = JSON.stringify({ jsonrpc: '2.0', id: 'r', method: 'm', params: { meta: {}, body: {}, extra: 1 } })
    expect(rejectionOf(text).code).toBe(-32600)
  })

  it('rejects an unknown core meta field, which is how a downgrade is prevented', () => {
    const text = JSON.stringify({
      jsonrpc: '2.0',
      id: 'r',
      method: 'm',
      params: { meta: { profile: 'p', security_profile: 's', security_profil: 'typo' }, body: {} },
    })
    const error = rejectionOf(text)
    expect(error.code).toBe(-32600)
    expect(error.details?.field).toBe('security_profil')
  })

  it('allows an x_ prefixed meta field through', () => {
    const text = JSON.stringify({
      jsonrpc: '2.0',
      id: 'r',
      method: 'm',
      params: { meta: { profile: 'p', security_profile: 's', x_agentx_trace: 'abc' }, body: {} },
    })
    expect(parseRequestText(text).ok).toBe(true)
  })

  it('rejects an unknown auth field', () => {
    const text = JSON.stringify({
      jsonrpc: '2.0',
      id: 'r',
      method: 'm',
      params: { meta: { profile: 'p', security_profile: 's' }, auth: { scheme: 's', bearer: 'x' }, body: {} },
    })
    expect(rejectionOf(text).code).toBe(-32600)
  })

  it('rejects a target kind outside agent | group | service', () => {
    const text = JSON.stringify({
      jsonrpc: '2.0',
      id: 'r',
      method: 'm',
      params: { meta: { profile: 'p', security_profile: 's', target: { kind: 'user', did: 'did:web:x' } }, body: {} },
    })
    expect(rejectionOf(text).anpCode).toBe('anp.invalid_target_binding')
  })

  it('rejects a transport URL in target.did', () => {
    const text = JSON.stringify({
      jsonrpc: '2.0',
      id: 'r',
      method: 'm',
      params: {
        meta: { profile: 'p', security_profile: 's', target: { kind: 'agent', did: 'https://b.example/anp-im/rpc' } },
        body: {},
      },
    })
    expect(rejectionOf(text).anpCode).toBe('anp.invalid_target_binding')
  })

  it('rejects a method using the reserved rpc. prefix', () => {
    const text = JSON.stringify({ jsonrpc: '2.0', id: 'r', method: 'rpc.discover', params: { meta: {}, body: {} } })
    expect(rejectionOf(text).code).toBe(-32601)
  })
})

describe('failureId', () => {
  it('keeps the id of a request that failed for another reason (§5.6 L203)', () => {
    const text = envelope({ method: 'rpc.bad' })
    const error = rejectionOf(text)
    expect(failureId(text, error)).toBe('req-1')
  })

  it('is null when the body never parsed', () => {
    expect(failureId('not json', { code: -32700, retryable: false, message: 'Parse error' })).toBeNull()
  })

  it('is null when there is no id at all', () => {
    const text = JSON.stringify({ jsonrpc: '2.0', method: 'm', params: {} })
    expect(failureId(text, { code: -32600, retryable: false, message: 'x' })).toBeNull()
  })
})

describe('errorResponse', () => {
  it('carries anp_code only for a code in the ANP range (§10.2 L695)', async () => {
    const anp = await errorBody(
      errorResponse('r', { code: 1000, anpCode: 'anp.invalid_request_id', retryable: false, message: 'bad id' }),
    )
    expect((anp.error as Record<string, unknown>).data).toMatchObject({ anp_code: 'anp.invalid_request_id' })

    const standard = await errorBody(errorResponse('r', { code: -32700, retryable: false, message: 'Parse error' }))
    const data = (standard.error as Record<string, unknown>).data as Record<string, unknown>
    expect('anp_code' in data).toBe(false)
    expect(data.retryable).toBe(false)
  })

  it('echoes the id it was given', async () => {
    const body = await errorBody(errorResponse('req-1', { code: -32601, retryable: false, message: 'x' }))
    expect(body.id).toBe('req-1')
    expect(body.jsonrpc).toBe('2.0')
  })
})
