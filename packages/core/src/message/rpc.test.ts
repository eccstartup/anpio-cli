import { describe, it, expect } from 'vitest'
import { ConnectxError } from '../errors'
import type { ResolveDidOptions } from '../crypto/resolveDid'
import { buildMessageRequest, type AnpMeta, type AnpResponse } from './envelope'
import { anpCodeOf, postMessage } from './rpc'

const ENDPOINT = 'https://peer.example/anp-im'

const META: AnpMeta = {
  profile: 'anp.core.binding.v1',
  security_profile: 'transport-protected',
  sender_did: 'did:wba:a.example:user:alice:e1_abc',
}

const REQUEST = buildMessageRequest({ id: 'req-1', method: 'anp.get_capabilities', meta: META })

/** Options that let a fake transport stand in for the network, while the allowlist and
 *  resolved-address gates still run for real — the point of routing through
 *  `fetchControlledJson` is that a POST gets the same policy as a GET. */
function options(
  handler: (url: string, init: RequestInit) => Promise<Response>,
  extra: ResolveDidOptions = {},
): ResolveDidOptions {
  return {
    allowedHosts: ['peer.example'],
    resolveAddresses: async () => ['93.184.216.34'],
    fetch: handler,
    allowUncontrolledFetch: true,
    ...extra,
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

describe('postMessage', () => {
  it('POSTs the envelope as JSON, with its own content-type', async () => {
    let seen: { url: string; init: RequestInit } | undefined
    const response = await postMessage(
      ENDPOINT,
      REQUEST,
      options(async (url, init) => {
        seen = { url, init }
        return json({ jsonrpc: '2.0', id: 'req-1', result: { supported_profiles: [] } })
      }),
    )
    expect(seen?.url).toBe(ENDPOINT)
    expect(seen?.init.method).toBe('POST')
    expect(seen?.init.body).toBe(JSON.stringify(REQUEST))
    expect((seen?.init.headers as Record<string, string>)['content-type']).toBe('application/json')
    expect('result' in response && response.result).toEqual({ supported_profiles: [] })
  })

  it('returns the error response instead of throwing — a rejection is the protocol working', async () => {
    // P1 §5.6 L202: a failure is a 2xx whose body carries `error`. Throwing here would
    // turn `anp.did_superseded` (which the caller must branch on) into a transport fault.
    const response = await postMessage(
      ENDPOINT,
      REQUEST,
      options(async () =>
        json({
          jsonrpc: '2.0',
          id: 'req-1',
          error: { code: 1019, message: 'superseded', data: { anp_code: 'anp.did_superseded', retryable: false } },
        }),
      ),
    )
    expect('error' in response).toBe(true)
    expect(anpCodeOf(response as Extract<AnpResponse, { error: unknown }>)).toBe('anp.did_superseded')
  })

  it('reports an absent anp_code rather than inventing one', async () => {
    // §10.2 L695 only forces `anp_code` on the ANP-defined range; a -32xxx code has none.
    const response = await postMessage(
      ENDPOINT,
      REQUEST,
      options(async () => json({ jsonrpc: '2.0', id: 'req-1', error: { code: -32601, message: 'Method not found' } })),
    )
    expect(anpCodeOf(response as Extract<AnpResponse, { error: unknown }>)).toBeUndefined()
  })

  it('refuses a response id that is not ours (P1 §5.6 L204)', async () => {
    await expect(
      postMessage(ENDPOINT, REQUEST, options(async () => json({ jsonrpc: '2.0', id: 'req-9', result: {} }))),
    ).rejects.toMatchObject({ code: 'message_invalid' })
  })

  it('refuses a response carrying both result and error', async () => {
    await expect(
      postMessage(
        ENDPOINT,
        REQUEST,
        options(async () => json({ jsonrpc: '2.0', id: 'req-1', result: {}, error: { code: -32603, message: 'x' } })),
      ),
    ).rejects.toMatchObject({ code: 'message_invalid' })
  })

  it('refuses a response carrying neither', async () => {
    await expect(
      postMessage(ENDPOINT, REQUEST, options(async () => json({ jsonrpc: '2.0', id: 'req-1' }))),
    ).rejects.toMatchObject({ code: 'message_invalid' })
  })

  it('applies the network policy to a POST the same way it does to a GET', async () => {
    let called = false
    await expect(
      postMessage(
        ENDPOINT,
        REQUEST,
        options(
          async () => {
            called = true
            return json({ jsonrpc: '2.0', id: 'req-1', result: {} })
          },
          { allowedHosts: ['other.example'] },
        ),
      ),
    ).rejects.toMatchObject({ code: 'message_send_failed', blockedReason: 'host_not_allowlisted' })
    expect(called).toBe(false)
  })

  it('does not follow a redirect away from the endpoint it was given', async () => {
    // A signed body re-sent to (or replaced at) another host is a different request.
    let calls = 0
    await expect(
      postMessage(
        ENDPOINT,
        REQUEST,
        options(async () => {
          calls += 1
          return new Response('', { status: 307, headers: { location: 'https://elsewhere.example/anp-im' } })
        }),
      ),
    ).rejects.toMatchObject({ code: 'message_send_failed' })
    expect(calls).toBe(1)
  })

  it('surfaces a rejected request with the peer status', async () => {
    const err: unknown = await postMessage(
      ENDPOINT,
      REQUEST,
      options(async () => new Response('nope', { status: 403, headers: { 'content-type': 'application/json' } })),
    ).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ConnectxError)
    expect(err).toMatchObject({ code: 'message_send_failed', status: 403 })
  })
})
