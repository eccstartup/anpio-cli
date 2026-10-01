import { afterEach, describe, expect, it } from 'vitest'
import { loadConfig } from '../config'
import { createServer, RPC_PATH, STREAM_PATH, WELL_KNOWN_PATH, type RpcHandler, type RunningServer } from './server'

/** A config bound to an OS-chosen port, so a test never collides with a real service. */
function testConfig(overrides: Record<string, string> = {}) {
  return loadConfig({ AGENTX_LISTEN: '127.0.0.1:0', AGENTX_DB: ':memory:', ...overrides })
}

let running: RunningServer | undefined

/** What `core`'s client sends, and what a test must send too: a string body makes `fetch`
 *  add `content-type: text/plain` on its own, which the service refuses with 415. */
const JSON_HEADERS = { 'content-type': 'application/json' }

afterEach(async () => {
  await running?.close()
  running = undefined
})

async function start(handleRpc: RpcHandler, overrides: Record<string, string> = {}) {
  running = createServer({ config: testConfig(overrides), handleRpc })
  await running.listen()
  return `http://127.0.0.1:${running.address.port}`
}

const echo: RpcHandler = (request) => ({
  status: 200,
  contentType: 'application/json',
  body: JSON.stringify({ jsonrpc: '2.0', id: 'r1', result: { echoed: JSON.parse(request.body) } }),
})

describe('POST /anp-im/rpc', () => {
  it('hands the handler the body text and the request url', async () => {
    const base = await start(echo)
    const res = await fetch(`${base}${RPC_PATH}`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: '{"jsonrpc":"2.0","id":"r1"}',
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ jsonrpc: '2.0', id: 'r1', result: { echoed: { jsonrpc: '2.0', id: 'r1' } } })
  })

  it('answers 405 on a GET, naming POST in Allow', async () => {
    const base = await start(echo)
    const res = await fetch(`${base}${RPC_PATH}`)
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toBe('POST')
  })

  it('answers 415 when the body is not declared as JSON', async () => {
    const base = await start(echo)
    const res = await fetch(`${base}${RPC_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{}',
    })
    expect(res.status).toBe(415)
  })

  it('accepts a JSON content type with parameters and in any case', async () => {
    const base = await start(echo)
    for (const header of ['application/json; charset=utf-8', 'APPLICATION/JSON']) {
      const res = await fetch(`${base}${RPC_PATH}`, { method: 'POST', headers: { 'content-type': header }, body: '{}' })
      expect(res.status).toBe(200)
    }
  })

  it('accepts a request with no content type header at all', async () => {
    const base = await start(echo)
    // A string body makes `fetch` add `content-type: text/plain` by itself, so the header
    // is only really absent when the body is bytes.
    const res = await fetch(`${base}${RPC_PATH}`, { method: 'POST', body: new TextEncoder().encode('{}') })
    expect(res.status).toBe(200)
  })

  it('answers 413 once the body passes the cap', async () => {
    const base = await start(echo, { AGENTX_MAX_BODY: '16' })
    const res = await fetch(`${base}${RPC_PATH}`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({ padding: 'x'.repeat(64) }),
    })
    expect(res.status).toBe(413)
    expect(await res.json()).toMatchObject({ error: expect.stringContaining('16') })
  })

  // The cap is a byte count, not a character count: a body of multi-byte characters that
  // fits in `maxBody` characters can still be over it in bytes.
  it('counts bytes rather than characters', async () => {
    const base = await start(echo, { AGENTX_MAX_BODY: '10' })
    const res = await fetch(`${base}${RPC_PATH}`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({ text: '一二三四五' }),
    })
    expect(res.status).toBe(413)
  })

  it('passes a protocol error through as the handler wrote it', async () => {
    const base = await start(() => ({
      status: 200,
      body: JSON.stringify({ jsonrpc: '2.0', id: 'r1', error: { code: -32600, message: 'Invalid Request' } }),
    }))
    const res = await fetch(`${base}${RPC_PATH}`, { method: 'POST', headers: JSON_HEADERS, body: '{}' })
    // 200 even though it is an error: §2.1 keeps every JSON-RPC answer on 200 so the
    // client can read `error.data.anp_code`.
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ error: { code: -32600 } })
  })

  it('answers 500 when the handler throws', async () => {
    const base = await start(() => {
      throw new Error('boom')
    })
    const res = await fetch(`${base}${RPC_PATH}`, { method: 'POST', headers: JSON_HEADERS, body: '{}' })
    expect(res.status).toBe(500)
  })

  it('accepts a handler that answers out of band', async () => {
    const base = await start(async () => {
      await new Promise((resolve) => setTimeout(resolve, 1))
      return { status: 200, body: '{"jsonrpc":"2.0","id":"r1","result":{}}' }
    })
    const res = await fetch(`${base}${RPC_PATH}`, { method: 'POST', headers: JSON_HEADERS, body: '{}' })
    expect(res.status).toBe(200)
  })
})

describe('the routes that are not built yet', () => {
  it('answers 501 on the stream route, not 404', async () => {
    const base = await start(echo)
    const res = await fetch(`${base}${STREAM_PATH}`)
    expect(res.status).toBe(501)
  })

  it('answers 501 on the well-known document', async () => {
    const base = await start(echo)
    const res = await fetch(`${base}${WELL_KNOWN_PATH}`)
    expect(res.status).toBe(501)
  })

  it('answers 405 on a non-GET against either', async () => {
    const base = await start(echo)
    for (const path of [STREAM_PATH, WELL_KNOWN_PATH]) {
      const res = await fetch(`${base}${path}`, { method: 'POST', headers: JSON_HEADERS, body: '{}' })
      expect(res.status).toBe(405)
      expect(res.headers.get('allow')).toBe('GET')
    }
  })
})

describe('anything else', () => {
  it('answers 404', async () => {
    const base = await start(echo)
    expect((await fetch(`${base}/`)).status).toBe(404)
    expect((await fetch(`${base}/anp-im`)).status).toBe(404)
  })

  it('does not answer 404 for a path that merely starts the same way', async () => {
    const base = await start(echo)
    expect((await fetch(`${base}/anp-im/rpc/extra`)).status).toBe(404)
  })
})

describe('a refusal does not poison the connection pool', () => {
  // A response sent while the request body is still unread makes Node destroy the socket;
  // undici then hands the NEXT request on that pooled connection a reset. The symptom is
  // two requests away from the cause, which is why this is pinned here.
  it('serves the request after a 413', async () => {
    const base = await start(echo, { AGENTX_MAX_BODY: '64' })
    const oversize = await fetch(`${base}${RPC_PATH}`, {
      method: 'POST',
      headers: JSON_HEADERS,
      body: JSON.stringify({ padding: 'x'.repeat(1024) }),
    })
    expect(oversize.status).toBe(413)

    const after = await fetch(`${base}${RPC_PATH}`, { method: 'POST', headers: JSON_HEADERS, body: '{"jsonrpc":"2.0"}' })
    expect(after.status).toBe(200)
  })

  it('serves the request after a 415', async () => {
    const base = await start(echo)
    const wrongType = await fetch(`${base}${RPC_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'a body that will never be read',
    })
    expect(wrongType.status).toBe(415)

    const after = await fetch(`${base}${RPC_PATH}`, { method: 'POST', headers: JSON_HEADERS, body: '{"jsonrpc":"2.0"}' })
    expect(after.status).toBe(200)
  })

  it('closes the connection on a refusal, so the client is not left guessing', async () => {
    const base = await start(echo)
    const res = await fetch(`${base}/nope`)
    expect(res.status).toBe(404)
    expect(res.headers.get('connection')).toBe('close')
  })
})

describe('binding', () => {
  it('reports the port the OS picked when the config asks for 0', async () => {
    const base = await start(echo)
    expect(base).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
    expect(running?.address.port).toBeGreaterThan(0)
  })

  it('leaves the port process-wide free after close', async () => {
    const base = await start(echo)
    const port = running?.address.port
    await running?.close()
    running = undefined

    // Binding the same port again is the assertion: `close` must have released it.
    running = createServer({ config: loadConfig({ AGENTX_LISTEN: `127.0.0.1:${port}`, AGENTX_DB: ':memory:' }), handleRpc: echo })
    await expect(running.listen()).resolves.toBeUndefined()
    void base
  })
})
