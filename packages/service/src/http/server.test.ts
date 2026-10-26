import { afterEach, describe, expect, it } from 'vitest'
import { connect } from 'node:net'
import { loadConfig } from '../config'
import { Readable } from 'node:stream'
import { OBJECTS_PATH, UPLOAD_PATH } from '../rpc/attachments'
import type { DataPlaneHandler } from '../dataplane'
import {
  createServer,
  groupDidRoutePrefix,
  RPC_PATH,
  STREAM_PATH,
  WELL_KNOWN_PATH,
  type RpcHandler,
  type RunningServer,
} from './server'

/** A config bound to an OS-chosen port, so a test never collides with a real service. */
function testConfig(overrides: Record<string, string> = {}) {
  return loadConfig({ ANPIOCLI_LISTEN: '127.0.0.1:0', ANPIOCLI_DB: ':memory:', ...overrides })
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
    const base = await start(echo, { ANPIOCLI_MAX_BODY: '16' })
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
    const base = await start(echo, { ANPIOCLI_MAX_BODY: '10' })
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
  it('answers 426 on the stream route, because a plain GET is missing the upgrade', async () => {
    // C7 wired the stream up, so this is no longer "not built" — but a plain GET still
    // cannot be served by it, and `405` would blame the method, which is the one part that
    // is right (§2.1).
    const base = await start(echo)
    const res = await fetch(`${base}${STREAM_PATH}`)
    expect(res.status).toBe(426)
    expect(res.headers.get('upgrade')).toBe('websocket')
  })

  it('serves the service entry once the wiring supplies one', async () => {
    // C8: the document is data, so the route's job is to hand it back and say it is JSON.
    const document = JSON.stringify({ type: 'ANPMessageService', serviceDid: 'did:web:anpio.example' })
    running = createServer({ config: testConfig(), handleRpc: echo, wellKnown: document })
    await running.listen()
    const res = await fetch(`http://127.0.0.1:${running.address.port}${WELL_KNOWN_PATH}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('application/json')
    expect(await res.json()).toEqual({ type: 'ANPMessageService', serviceDid: 'did:web:anpio.example' })
  })

  it('answers 501 on the well-known document when nothing was wired to it', async () => {
    // An unbuilt surface must stay distinguishable from a missing one (§2.1).
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

  it('destroys an upgrade to a path that is not the stream', async () => {
    // The upgrade event is separate from the router, so a path it does not want has to be
    // ended here: an un-upgraded socket would otherwise sit until it timed out.
    await start(echo)
    const refused = await new Promise<boolean>((resolve) => {
      const socket = connect(running?.address.port ?? 0, '127.0.0.1')
      socket.on('error', () => {
        resolve(true)
      })
      socket.on('close', () => {
        resolve(true)
      })
      socket.write(
        [
          'GET /anp-im/elsewhere HTTP/1.1',
          'Host: localhost',
          'Upgrade: websocket',
          'Connection: Upgrade',
          'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
          'Sec-WebSocket-Version: 13',
          '',
          '',
        ].join('\r\n'),
      )
    })
    expect(refused).toBe(true)
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
    const base = await start(echo, { ANPIOCLI_MAX_BODY: '64' })
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
    running = createServer({ config: loadConfig({ ANPIOCLI_LISTEN: `127.0.0.1:${port}`, ANPIOCLI_DB: ':memory:' }), handleRpc: echo })
    await expect(running.listen()).resolves.toBeUndefined()
    void base
  })
})

describe('the P7 data-plane routes', () => {
  /** The routes are wired through the same `createServer` seam as `handleRpc`; `undefined`
   *  is how a test asks what an unwired surface answers. */
  async function startPlane(options: { upload?: DataPlaneHandler; object?: DataPlaneHandler } = {}): Promise<string> {
    running = createServer({
      config: testConfig(),
      handleRpc: echo,
      ...(options.upload !== undefined ? { handleUpload: options.upload } : {}),
      ...(options.object !== undefined ? { handleObject: options.object } : {}),
    })
    await running.listen()
    return `http://127.0.0.1:${running.address.port}`
  }

  it('hands the upload its token and the bytes that arrived', async () => {
    const seen: { resource: string; body: string }[] = []
    const base = await startPlane({
      upload: async (request) => {
        const chunks: Buffer[] = []
        for await (const chunk of request.body) chunks.push(Buffer.from(chunk))
        seen.push({ resource: request.resource, body: Buffer.concat(chunks).toString() })
        return { status: 200 }
      },
    })
    const res = await fetch(`${base}${UPLOAD_PATH}/tok-1`, { method: 'PUT', body: 'the bytes' })
    expect(res.status).toBe(200)
    expect(seen).toEqual([{ resource: 'tok-1', body: 'the bytes' }])
  })

  it('answers 405 with an Allow, because the route takes exactly one method', async () => {
    const base = await startPlane({ upload: () => ({ status: 200 }) })
    const res = await fetch(`${base}${UPLOAD_PATH}/tok-1`)
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toBe('PUT')
  })

  it('sends an object as bytes with the length the store reported', async () => {
    const bytes = Buffer.from('object bytes')
    const base = await startPlane({
      object: () => ({
        status: 200,
        contentType: 'application/octet-stream',
        headers: { 'content-disposition': 'attachment' },
        stream: { read: Readable.from([bytes]), length: bytes.byteLength },
      }),
    })
    const res = await fetch(`${base}${OBJECTS_PATH}/obj-1`, { headers: { authorization: 'Bearer t' } })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('application/octet-stream')
    expect(res.headers.get('content-length')).toBe(String(bytes.byteLength))
    expect(res.headers.get('content-disposition')).toBe('attachment')
    expect(Buffer.from(await res.arrayBuffer()).equals(bytes)).toBe(true)
  })

  it('decodes the segment, so the token a client was handed is the token it sends back', async () => {
    const seen: string[] = []
    const base = await startPlane({
      upload: (request) => {
        seen.push(request.resource)
        return { status: 200 }
      },
    })
    // `%2F` decodes to a slash, which would otherwise be read as a second path segment.
    await fetch(`${base}${UPLOAD_PATH}/a%20b`, { method: 'PUT', body: '' })
    expect(seen).toEqual(['a b'])
  })

  it('answers 400 for a segment that cannot be decoded, rather than crashing', async () => {
    const base = await startPlane({ object: () => ({ status: 200 }) })
    const res = await fetch(`${base}${OBJECTS_PATH}/%zz`)
    expect(res.status).toBe(400)
  })

  it('answers 501 when the route is not wired, which is not the same as a missing route', async () => {
    const base = await startPlane()
    const upload = await fetch(`${base}${UPLOAD_PATH}/tok-1`, { method: 'PUT', body: '' })
    expect(upload.status).toBe(501)
    const object = await fetch(`${base}${OBJECTS_PATH}/obj-1`)
    expect(object.status).toBe(501)
  })

  it('closes the connection on a refusal, because a refused PUT still has a body in flight', async () => {
    const base = await startPlane({
      upload: () => ({ status: 413, contentType: 'application/json', body: '{"anp_code":"x"}' }),
    })
    const res = await fetch(`${base}${UPLOAD_PATH}/tok-1`, { method: 'PUT', body: 'a lot of bytes' })
    expect(res.status).toBe(413)
    expect(res.headers.get('connection')).toBe('close')
  })
})

// ---------------------------------------------------------------------------
// B1b-A3 —— 群 DID 文档的托管路由。
//
// 这条路由的路径**不是**一个常量：`didToUrl` 把 `group_did`（= `serviceDid + ":g:" + <id>`）
// 映成 `…/<serviceDid 自己的路径段>/g/<id>/did.json`，所以 `serviceDid` 带路径段时路由也
// 跟着挪。下面第一条测试钉的就是这件事，其余钉状态码。
describe('GET …/g/<id>/did.json (B1b-A3)', () => {
  async function startGroups(
    handleGroupDid?: (groupDid: string) => string | undefined,
    overrides: Record<string, string> = {},
  ): Promise<string> {
    running = createServer({
      config: testConfig(overrides),
      handleRpc: echo,
      ...(handleGroupDid !== undefined ? { handleGroupDid } : {}),
    })
    await running.listen()
    return `http://127.0.0.1:${running.address.port}`
  }

  const SERVICE = 'did:web:groups.example'
  const DOC = '{"id":"did:web:groups.example:g:AAAA"}'

  it('derives its path from didToUrl, so a service DID with its own path segments moves it too', () => {
    // 路由的前缀与"对端会去 GET 的那个 URL"必须是同一个推导，否则表现是"本地的群文档找
    // 不到，而跨域解析总是 404"。
    expect(groupDidRoutePrefix(testConfig({ ANPIOCLI_PUBLIC_URL: 'https://groups.example' }))).toBe('')
    expect(
      groupDidRoutePrefix(
        testConfig({ ANPIOCLI_PUBLIC_URL: 'https://host.example', ANPIOCLI_SERVICE_DID: 'did:web:host.example:svc' }),
      ),
    ).toBe('/svc')
  })

  it('serves the document as application/did+json and hands the handler the group DID', async () => {
    const seen: string[] = []
    const base = await startGroups(
      (groupDid) => {
        seen.push(groupDid)
        return DOC
      },
      { ANPIOCLI_PUBLIC_URL: 'https://groups.example' },
    )

    const res = await fetch(`${base}/g/AAAA/did.json`)

    expect(res.status).toBe(200)
    // 与 awiki 那条路一致，也是 packages/e2e 的玩具主机在用的。
    expect(res.headers.get('content-type')).toBe('application/did+json')
    expect(await res.text()).toBe(DOC)
    // 路由交给处理器的是**群 DID**，不是路径里那段 id——拼回来的那一步在路由这一侧，因为
    // 只有它知道 `serviceDid`（`group_did` 的形状是 groups.md §2）。
    expect(seen).toEqual(['did:web:groups.example:g:AAAA'])
  })

  it('serves it under the service DID\'s own path prefix', async () => {
    const base = await startGroups(
      () => DOC,
      { ANPIOCLI_PUBLIC_URL: 'https://host.example', ANPIOCLI_SERVICE_DID: 'did:web:host.example:svc' },
    )

    expect((await fetch(`${base}/svc/g/AAAA/did.json`)).status).toBe(200)
    // 前缀之外的同名路径不是这条路由。
    expect((await fetch(`${base}/g/AAAA/did.json`)).status).toBe(404)
  })

  it('answers 404 for a group this service did not mint — not 500', async () => {
    // 陌生人猜了一个 id 打过来，是"这里没有你问的东西"。v11 之前建的、没有钥的群也是这条。
    const base = await startGroups(() => undefined)
    const res = await fetch(`${base}/g/not-ours/did.json`)
    expect(res.status).toBe(404)
  })

  it('answers 405 naming GET, because the route takes exactly one method', async () => {
    const base = await startGroups(() => DOC)
    const res = await fetch(`${base}/g/AAAA/did.json`, { method: 'POST', body: '{}' })
    expect(res.status).toBe(405)
    expect(res.headers.get('allow')).toBe('GET')
  })

  it('answers 501 when the route is not wired, which is not the same as a missing group', async () => {
    const base = await startGroups()
    expect((await fetch(`${base}/g/AAAA/did.json`)).status).toBe(501)
  })

  it('answers 404 for a path that is not this route, and never 500', async () => {
    const base = await startGroups(() => DOC)
    // 空 id、多了一段、以及解不开的转义。数据面那条路由对畸形段答 400（那是客户端拿到手的
    // 凭据，坏掉就是请求的错）；这里答 404，因为"DID 文档在这个 URL 上吗"的答案是"没有"，
    // 而这正是 DID 解析器期待的答复。
    for (const path of ['/g/did.json', '/g/a/b/did.json', '/g/%zz/did.json', '/g/AAAA/did.json/x']) {
      expect((await fetch(`${base}${path}`)).status, path).toBe(404)
    }
  })
})
