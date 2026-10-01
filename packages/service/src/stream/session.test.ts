// C7 —— 一条连接上的协议（`stream/session.ts`）。
//
// 这里测的是"这一层自己的判断"：握手、注册、补齐到实时的切换、投递确认的边界。传输本身
// （RFC 6455 的帧、掩码、关闭握手）在 `ws.test.ts`，注册表的缓冲与背压在 `registry.test.ts`，
// 所以这个文件用一台假连接——它不是"少测了一层"，而是把这一层从另外两层里摘出来。
//
// 唯一不假的是**签名**：每一帧都是真签的，锚点、时间窗、摘要走的都是生产路径。所以
// "拒绝"类用例证的是这一层的接线，不是验签本身。

import { describe, expect, it } from 'vitest'
import {
  DidKeyResolver,
  buildMessageRequest,
  buildOriginProofAuth,
  createAnpIdentity,
  ed25519OriginProofSigner,
  type AnpMeta,
  type AnpSigningIdentity,
  type KeyResolver,
  type LocateOptions,
} from '@agentx/core'
import type { IncomingMessage } from 'node:http'
import { openStorage } from '../storage/sqlite'
import { createSubscriberRegistry, type SubscriberRegistry } from './registry'
import { createStreamSession, STREAM_PROFILES, type StreamSession } from './session'
import { STREAM_ACK, STREAM_AUTH, STREAM_HELLO, STREAM_PROFILE } from '../rpc/stream'
import { EXTENSION_PROFILE } from '../rpc/inbox'
import { CLOSE_GOING_AWAY, CLOSE_NORMAL, CLOSE_TRY_AGAIN_LATER, type WebSocketConnection } from './ws'
import type { RpcHandler, RpcRequest, RpcResponse } from '../http/server'
import type { DeliveryRecord, Storage } from '../storage/types'

const owner = createAnpIdentity('owner.example')
const other = createAnpIdentity('other.example')

const NOW = new Date('2026-10-01T12:00:00Z')
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000)

/** 与 `dispatch.test.ts` 同一套：只有钥的解析被换成本地文档，其余都是真路径。 */
function inlineResolver(documents: Record<string, unknown>): KeyResolver {
  const base = new DidKeyResolver()
  return {
    resolve(identity: string, keyid: string, opts: LocateOptions = {}) {
      const bare = keyid.includes('#') ? keyid.slice(0, keyid.indexOf('#')) : keyid
      return base.resolve(identity, keyid, { ...opts, didDocument: documents[bare] })
    },
  }
}

const DOCUMENTS: Record<string, unknown> = {
  [owner.did]: owner.didDocument,
  [other.did]: other.didDocument,
}

interface Frame {
  jsonrpc?: string
  id?: unknown
  method?: string
  params?: { server_did?: string; head_seq?: number; profiles?: string[] }
  result?: Record<string, unknown>
  error?: { code: number; message: string; data?: { anp_code?: string } }
}

/** A connection that records instead of writing. A send after close is dropped, the way
 *  the real transport drops it, so "nothing more is pushed" means the same thing here. */
class FakeConnection implements WebSocketConnection {
  readonly sent: string[] = []
  readonly closes: { code: number; reason: string }[] = []
  destroyed = false
  queued = 0
  private closedFlag = false

  send(text: string): void {
    if (this.closedFlag) return
    this.sent.push(text)
  }
  close(code = CLOSE_NORMAL, reason = ''): void {
    if (this.closedFlag) return
    this.closedFlag = true
    this.closes.push({ code, reason })
  }
  destroy(): void {
    this.closedFlag = true
    this.destroyed = true
  }
  get bufferedAmount(): number {
    return this.queued
  }
  get closed(): boolean {
    return this.closedFlag
  }
  frames(): Frame[] {
    return this.sent.map((text) => JSON.parse(text) as Frame)
  }
  /** Everything the server sent after the opening `stream.hello`. */
  afterHello(): Frame[] {
    return this.frames().slice(1)
  }
  last(): Frame {
    return this.frames()[this.frames().length - 1] as Frame
  }
}

/** 一帧客户端请求。`params.profile` 是方法自己那一族的 Profile（§9）——两个传输方法在
 *  `x_agentx.stream.v1` 下，补齐用的 `sync.delta` 在 `x_agentx.inbox.v1` 下。 */
function meta(profile: string, overrides: Partial<AnpMeta> = {}): AnpMeta {
  return {
    profile,
    security_profile: 'transport-protected',
    sender_did: owner.did,
    target: { kind: 'agent', did: owner.did },
    operation_id: `op-${String(Math.random()).slice(2, 8)}`,
    ...overrides,
  }
}

async function frameText(options: {
  method: string
  meta?: AnpMeta
  body?: Record<string, unknown>
  signer?: AnpSigningIdentity
  id?: string
}): Promise<string> {
  const under = options.meta ?? meta(STREAM_PROFILE)
  const body = options.body ?? {}
  const auth = await buildOriginProofAuth({
    method: options.method,
    meta: under,
    body,
    signer: ed25519OriginProofSigner(options.signer?.priv ?? owner.priv, options.signer?.keyid ?? owner.keyid),
    created: NOW_SECONDS - 60,
    expires: NOW_SECONDS + 3600,
  })
  return JSON.stringify(
    buildMessageRequest({ id: options.id ?? 'req-1', method: options.method, meta: under, body, auth }),
  )
}

/** `sync.delta` 的一个完整答案。`has_more` 与 `next_since` 由用例给，因为补齐在哪一序列
 *  结束，正是这一层要读出来的东西。 */
function deltaResponse(request: RpcRequest, nextSince: number, hasMore = false): RpcResponse {
  const parsed = JSON.parse(request.body) as { id?: unknown }
  return {
    status: 200,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: parsed.id ?? null,
      result: { messages: [], next_since: nextSince, has_more: hasMore },
    }),
  }
}

/** The upgrade request's stand-in. Only `headers` and `url` are read, and only to hand
 *  them to the control plane. */
const REQUEST = { headers: { host: 'agentx.example' }, url: '/anp-im/stream' } as unknown as IncomingMessage

interface Harness {
  session: StreamSession
  registry: SubscriberRegistry
  storage: Storage
  logs: string[]
  requests: RpcRequest[]
  connect(): { conn: FakeConnection; send(text: string): void; close(): void }
  /** Append one delivery and publish it, the way `dispatch.ts` does after a commit. */
  deliver(): DeliveryRecord
}

function harness(overrides: { handleRpc?: RpcHandler } = {}): Harness {
  const storage = openStorage({ path: ':memory:' })
  const registry = createSubscriberRegistry()
  const logs: string[] = []
  const requests: RpcRequest[] = []
  const handleRpc: RpcHandler =
    overrides.handleRpc ??
    ((request) => {
      requests.push(request)
      return deltaResponse(request, 0)
    })
  const session = createStreamSession({
    serverDid: 'did:web:agentx.example',
    storage,
    registry,
    handleRpc,
    resolver: inlineResolver(DOCUMENTS),
    now: () => NOW,
    log: (line) => logs.push(line),
  })
  return {
    session,
    registry,
    storage,
    logs,
    requests,
    connect() {
      const conn = new FakeConnection()
      const handlers = session.handlersFor(conn, REQUEST)
      return { conn, send: (text: string) => handlers.onMessage(text), close: () => handlers.onClose() }
    },
    deliver() {
      const record = storage.appendDelivery({
        ownerDid: owner.did,
        messageId: `m-${String(storage.headSeq(owner.did) + 1)}`,
        method: 'direct.incoming',
        paramsJson: JSON.stringify({ meta: {}, body: { text: 'hi' } }),
        acceptedAt: NOW.toISOString(),
      })
      registry.publish(record)
      return record
    },
  }
}

async function until(predicate: () => boolean, limit = 200): Promise<void> {
  for (let i = 0; i < limit; i++) {
    if (predicate()) return
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
  throw new Error('condition was never met')
}

describe('stream.hello', () => {
  it('is the first frame, naming the service and the profiles this endpoint speaks', () => {
    const h = harness()
    const { conn } = h.connect()
    expect(conn.frames()).toHaveLength(1)
    const hello = conn.frames()[0] as Frame
    expect(hello.method).toBe(STREAM_HELLO)
    expect(hello.params?.server_did).toBe('did:web:agentx.example')
    expect(hello.params?.profiles).toEqual([...STREAM_PROFILES])
    expect(STREAM_PROFILES).toContain(EXTENSION_PROFILE)
  })

  it('reports head_seq 0, because the mailbox is not known until the handshake', () => {
    const h = harness()
    h.deliver()
    const { conn } = h.connect()
    // The authoritative head arrives with `stream.ready`; anything here would be a
    // sequence for a mailbox this connection has not named yet.
    expect((conn.frames()[0] as Frame).params?.head_seq).toBe(0)
  })
})

describe('stream.auth', () => {
  it('answers stream.ready with the head latched now and the stored cursor', async () => {
    const h = harness()
    for (let i = 0; i < 3; i++) h.deliver()
    h.storage.advanceCursor(owner.did, 'phone', 2)
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    expect(conn.last().result).toEqual({ device_id: 'phone', cursor_accepted: 2, head_seq: 3 })
  })

  it('takes a --since override for this backfill without storing it', async () => {
    const h = harness()
    for (let i = 0; i < 3; i++) h.deliver()
    h.storage.advanceCursor(owner.did, 'phone', 3)
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone', cursor: 1 } }))
    await until(() => conn.sent.length === 2)
    expect(conn.last().result?.cursor_accepted).toBe(1)
    // §5.4: `--since` is a debugging override for one backfill. Writing it back would turn
    // a flag into lost history.
    expect(h.storage.cursor(owner.did, 'phone')).toBe(3)
  })

  it('refuses a second handshake on one connection', async () => {
    const h = harness()
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'laptop' }, id: 'req-2' }))
    await until(() => conn.sent.length === 3)
    expect(conn.last().error?.code).toBe(-32600)
    // The handshake that did happen is the one still registered.
    expect(conn.closes).toHaveLength(0)
  })

  it('closes the connection when the proof does not verify', async () => {
    const h = harness()
    const { conn, send } = h.connect()
    // Signed by `owner` but claiming to be `other`: the key does not belong to the anchor.
    send(
      await frameText({
        method: STREAM_AUTH,
        meta: meta(STREAM_PROFILE, { sender_did: other.did, target: { kind: 'agent', did: other.did } }),
        body: { device_id: 'phone' },
      }),
    )
    await until(() => conn.closes.length > 0)
    expect(conn.last().error?.data?.anp_code).toBe('anp.unauthorized')
    // §4.1: 握手失败即关连接. The reason goes out first, then the socket.
    expect(conn.closes[0]?.code).toBe(CLOSE_NORMAL)
    expect(h.registry.size()).toBe(0)
  })

  it('refuses a handshake body that is not one, without closing', async () => {
    const h = harness()
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone', since: 3 } }))
    await until(() => conn.sent.length === 2)
    expect(conn.last().error?.data?.anp_code).toBe('anp.invalid_params_shape')
    expect(conn.closes).toHaveLength(0)
    expect(h.registry.size()).toBe(0)
  })
})

describe('the backfill window', () => {
  it('holds a delivery until the delta answers, then pushes it', async () => {
    // The backfill is held open on purpose: the window §5.2 describes only exists while
    // the delta is in flight, so the test has to be the one deciding when it lands.
    let release: (() => void) | undefined
    const h = harness({
      handleRpc: async (request) => {
        await new Promise<void>((resolve) => {
          release = resolve
        })
        return deltaResponse(request, 0)
      },
    })
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)

    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 }, id: 'req-2' }))
    await until(() => release !== undefined)
    h.deliver()
    await new Promise((resolve) => setTimeout(resolve, 5))
    // Registered but still catching up: §5.2 says hold it, not drop it and not race the
    // replay with it.
    expect(conn.sent).toHaveLength(2)

    // The backfill answered up to 0, so the delivery (seq 1) is newer than the replay.
    release?.()
    await until(() => conn.sent.length === 4)
    // The replay goes out first and the held frame after it: the handover is one ordering
    // the server owns, which is what makes it gapless (§5.2).
    expect(conn.afterHello()[1]?.result?.messages).toEqual([])
    const pushed = conn.last()
    expect(pushed.method).toBe('direct.incoming')
    expect(pushed.params).toEqual({ meta: {}, body: { text: 'hi' } })
  })

  it('drops a held frame the backfill already carried', async () => {
    const h = harness({
      handleRpc: (request) => deltaResponse(request, 1),
    })
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)

    h.deliver()
    await new Promise((resolve) => setTimeout(resolve, 5))
    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 }, id: 'req-2' }))
    // The handshake frame, the delta response, and nothing else: seq 1 was in the answer.
    await until(() => conn.sent.length === 3)
    expect(conn.afterHello()[1]?.result).toBeDefined()
  })

  it('leaves the subscription held while the delta is paged', async () => {
    const h = harness({ handleRpc: (request) => deltaResponse(request, 1, true) })
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    h.deliver()
    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 }, id: 'req-2' }))
    await until(() => conn.sent.length === 3)
    await new Promise((resolve) => setTimeout(resolve, 5))
    // `has_more` means the client is mid-backfill; going live now would push a message the
    // next page is about to repeat.
    expect(conn.sent).toHaveLength(3)
  })

  it('leaves the subscription held when the delta is refused', async () => {
    const h = harness({
      handleRpc: (request) => {
        const parsed = JSON.parse(request.body) as { id?: unknown }
        return {
          status: 200,
          body: JSON.stringify({ jsonrpc: '2.0', id: parsed.id ?? null, error: { code: -32600, message: 'no' } }),
        }
      },
    })
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    h.deliver()
    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 }, id: 'req-2' }))
    await until(() => conn.sent.length === 3)
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(conn.sent).toHaveLength(3)
  })

  it('routes everything that is not a transport method through the control plane', async () => {
    const h = harness()
    const { conn, send } = h.connect()
    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 } }))
    await until(() => conn.sent.length === 2)
    expect(h.requests).toHaveLength(1)
    // The connection's own request stands in for the frame's: same socket, same headers.
    expect(h.requests[0]?.url.pathname).toBe('/anp-im/stream')
    expect(h.requests[0]?.headers.host).toBe('agentx.example')
  })

  it('answers an unknown method with the control plane’s -32601', async () => {
    const h = harness({
      handleRpc: (request) => {
        const parsed = JSON.parse(request.body) as { id?: unknown }
        return {
          status: 200,
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: parsed.id ?? null,
            error: { code: -32601, message: 'Method not found: nope' },
          }),
        }
      },
    })
    const { conn, send } = h.connect()
    send(await frameText({ method: 'nope', meta: meta(EXTENSION_PROFILE), body: {} }))
    await until(() => conn.sent.length === 2)
    expect(conn.last().error?.code).toBe(-32601)
  })
})

describe('stream.ack', () => {
  it('advances the delivery cursor and answers with it', async () => {
    const h = harness()
    for (let i = 0; i < 3; i++) h.deliver()
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    send(await frameText({ method: STREAM_ACK, body: { seq: 2 }, id: 'req-2' }))
    await until(() => conn.sent.length === 3)
    expect(conn.last().result).toEqual({ cursor: 2 })
    expect(h.storage.cursor(owner.did, 'phone')).toBe(2)
  })

  it('never moves the cursor backwards', async () => {
    const h = harness()
    for (let i = 0; i < 3; i++) h.deliver()
    h.storage.advanceCursor(owner.did, 'phone', 3)
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    send(await frameText({ method: STREAM_ACK, body: { seq: 1 }, id: 'req-2' }))
    await until(() => conn.sent.length === 3)
    expect(h.storage.cursor(owner.did, 'phone')).toBe(3)
  })

  it('clamps an ack to the head, so a bogus sequence cannot skip real mail', async () => {
    const h = harness()
    h.deliver()
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    send(await frameText({ method: STREAM_ACK, body: { seq: 9999 }, id: 'req-2' }))
    await until(() => conn.sent.length === 3)
    expect(conn.last().result).toEqual({ cursor: 1 })
  })

  it('refuses an ack before the handshake', async () => {
    const h = harness()
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_ACK, body: { seq: 1 } }))
    await until(() => conn.sent.length === 2)
    expect(conn.last().error?.code).toBe(-32600)
  })

  it('refuses an ack signed by an identity this connection did not authenticate as', async () => {
    const h = harness()
    h.deliver()
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    // A real signature by `other`, over a request addressed to `other` — so the proof
    // verifies and the refusal is this layer's own.
    send(
      await frameText({
        method: STREAM_ACK,
        meta: meta(STREAM_PROFILE, { sender_did: other.did, target: { kind: 'agent', did: other.did } }),
        body: { seq: 1 },
        signer: other,
        id: 'req-2',
      }),
    )
    await until(() => conn.sent.length === 3)
    expect(conn.last().error?.code).toBe(-32600)
    expect(h.storage.cursor(owner.did, 'phone')).toBe(0)
  })
})

describe('connection state', () => {
  it('ends every open connection on shutdown, with 1001', () => {
    const h = harness()
    h.connect()
    h.connect()
    expect(h.session.size()).toBe(2)
    h.session.closeAll('server shutting down')
    expect(h.session.size()).toBe(0)
  })

  it('stops pushing to a connection that closed', async () => {
    const h = harness()
    const { conn, send, close } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    expect(h.registry.size()).toBe(1)
    close()
    expect(h.registry.size()).toBe(0)
    h.deliver()
    // The subscription went with the socket, so nothing accumulates for a peer that is
    // gone. The message is in storage and the next connection's cursor finds it.
    expect(conn.sent).toHaveLength(2)
    expect(h.session.size()).toBe(0)
  })

  it('processes frames in arrival order, even when one of them is slow', async () => {
    let release: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    const h = harness({
      handleRpc: async (request) => {
        await gate
        return deltaResponse(request, 1)
      },
    })
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)

    h.deliver()
    // The delta is stuck; the ack behind it must wait. Order matters here for a reason the
    // `id` cannot fix: the switch to live happens on the delta's response, and an ack that
    // overtook it would be answered against a connection that had not gone live yet.
    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 }, id: 'req-2' }))
    send(await frameText({ method: STREAM_ACK, body: { seq: 1 }, id: 'req-3' }))
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(conn.sent).toHaveLength(2)

    release()
    await until(() => conn.sent.length === 4)
    expect(conn.frames()[2]?.id).toBe('req-2')
    expect(conn.frames()[3]?.id).toBe('req-3')
  })

  it('drops a subscriber that never finishes its backfill, with 1013', async () => {
    const h = harness({ handleRpc: () => new Promise<RpcResponse>(() => {}) })
    const { conn, send } = h.connect()
    send(await frameText({ method: STREAM_AUTH, body: { device_id: 'phone' } }))
    await until(() => conn.sent.length === 2)
    // §5.3: over the bound, the connection is what gives way — the messages stay in
    // storage, so a reconnect with the cursor recovers them.
    for (let i = 0; i < 257; i++) h.deliver()
    expect(conn.closes[0]?.code).toBe(CLOSE_TRY_AGAIN_LATER)
    expect(h.registry.size()).toBe(0)
  })

  it('closes the connection when a frame makes this service look broken', async () => {
    const h = harness({
      handleRpc: () => {
        throw new Error('this is a bug')
      },
    })
    const { conn, send } = h.connect()
    send(await frameText({ method: 'sync.delta', meta: meta(EXTENSION_PROFILE), body: { since: 0 } }))
    await until(() => conn.closes.length > 0)
    expect(conn.closes[0]?.code).toBe(1011)
    expect(h.logs.some((line) => line.includes('this is a bug'))).toBe(true)
  })
})
