// `msg listen` against a fake socket. The real one needs an `AgentXAgent` to talk to
// (TODO1, C1–C7), so the handshake, the cursor arithmetic, the backfill and the reconnect
// schedule are pinned here instead — everything except the bytes on the wire, which is the
// only part the injected transport owns.

import { describe, it, expect } from 'vitest'
import { ConnectxError } from '@agentx/core'
import { backoffMs, decodeMessage, runListen, streamUrl, type ListenDeps, type StreamConnection } from './listen'
import type { ListenEvent, ListenView } from './listen-view'
import type { Channel } from './channel'

/** A socket we drive by hand. `sent` is what the command put on the wire, in order;
 *  `deliver` is a frame arriving from the server. */
class FakeSocket implements StreamConnection {
  readonly sent: Record<string, unknown>[] = []
  private closed = false
  constructor(
    private readonly onFrame: (frame: unknown) => void,
    private readonly onClose: (reason?: string) => void,
  ) {}

  send(frame: unknown): void {
    this.sent.push(frame as Record<string, unknown>)
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    this.onClose('closed by the client')
  }

  /** A frame from the server. */
  deliver(frame: unknown): void {
    this.onFrame(frame)
  }

  /** The server goes away. */
  drop(reason?: string): void {
    if (this.closed) return
    this.closed = true
    this.onClose(reason)
  }

  /** The request whose `method` is `method`, then whatever came next — the reply the
   *  command is waiting on. */
  request(method: string): Record<string, unknown> {
    const found = this.sent.find((frame) => frame.method === method)
    if (found === undefined) throw new Error(`no ${method} was sent; sent: ${JSON.stringify(this.sent.map((f) => f.method))}`)
    return found
  }
}

/** Let every pending microtask run. The command is all microtasks once the socket and the
 *  signer are fakes, but the proof builder awaits its own digest a few times over, so one
 *  turn of the event loop is not always enough to reach the next `send`. */
const flush = async (): Promise<void> => {
  for (let turn = 0; turn < 5; turn += 1) await new Promise((resolve) => setImmediate(resolve))
}

/** The harness: one fake socket, an event log, and the deps `runListen` takes. */
function harness() {
  const events: ListenEvent[] = []
  const connections: FakeSocket[] = []
  const abort = new AbortController()
  const view: ListenView = {
    event(event) {
      events.push(event)
    },
  }
  const channel: Channel = {
    sender: {
      did: 'did:wba:example.com:user:alice:e1_key',
      // A signature nobody verifies: this suite is about the frames, and the real proof
      // is pinned in core's own `originProof.test.ts`.
      signer: { keyid: 'did:wba:example.com:user:alice:e1_key#key-1', sign: () => new Uint8Array(64) },
      agent: 'claude-code',
      profile: 'default',
    },
    target: {
      identity: 'did:wba:example.com:user:alice:e1_key',
      serviceId: 'anp-message-service',
      endpoint: 'https://agentx.example/anp-im/rpc',
      serviceDid: 'did:wba:agentx.example',
      hintedProfiles: [],
      hintedSecurityProfiles: [],
    },
    options: { allowedHosts: [] },
  }

  const deps: ListenDeps = {
    view,
    signal: abort.signal,
    openChannel: async () => channel,
    random: () => 0.5, // no jitter, so the schedule below is exact
    sleep: async () => {},
    connect: async (_url, handlers) => {
      const socket = new FakeSocket(handlers.onFrame, handlers.onClose)
      connections.push(socket)
      return socket
    },
  }
  return { deps, events, connections, channel, stop: () => abort.abort() }
}

const HELLO = { jsonrpc: '2.0', method: 'stream.hello', params: { server_did: 'did:wba:agentx.example', head_seq: 42, profiles: ['anp.direct.base.v1'] } }

function response(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result }
}

function incoming(message_id: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    method: 'direct.incoming',
    params: {
      meta: {
        profile: 'anp.direct.base.v1',
        security_profile: 'transport-protected',
        sender_did: 'did:wba:example.com:user:bob:e1_key',
        target: { kind: 'agent', did: 'did:wba:example.com:user:alice:e1_key' },
        message_id,
        created_at: '2026-09-30T14:02:11Z',
        content_type: 'text/plain',
      },
      body: { text: 'hello' },
      ...overrides,
    },
  }
}

/** The Profile each method must be sent under (realtime.md §9). The real service checks
 *  `meta.profile` against the method's own list and answers 1001 when it is wrong
 *  (`rpc/methods.ts`'s `checkMethod`), so this fake does too. A double that accepted any
 *  profile is exactly what let one profile for the whole connection pass this suite while a
 *  real service would have refused every backfill. */
const PROFILE_OF: Record<string, string> = {
  'stream.auth': 'x_agentx.stream.v1',
  'stream.ack': 'x_agentx.stream.v1',
  'sync.delta': 'x_agentx.inbox.v1',
  'inbox.mark_read': 'x_agentx.inbox.v1',
}

/** Answer whatever request was just sent, by replying to its `id`. This is the server half
 *  the command is written against, kept in the test so the two cannot drift. */
function serve(socket: FakeSocket, results: Record<string, unknown>): void {
  const last = socket.sent[socket.sent.length - 1]
  if (last === undefined) throw new Error('nothing was sent')
  const method = String(last.method)
  const profile = (last.params as { meta?: { profile?: unknown } } | undefined)?.meta?.profile
  const expected = PROFILE_OF[method]
  if (expected !== undefined && profile !== expected) {
    socket.deliver({
      jsonrpc: '2.0',
      id: last.id,
      error: {
        code: 1001,
        message: `${method} does not implement profile ${String(profile)}`,
        data: { anp_code: 'anp.unsupported_profile' },
      },
    })
    return
  }
  const result = results[method]
  socket.deliver(response(last.id, result))
}

describe('streamUrl', () => {
  it('replaces the last path segment with "stream"', () => {
    expect(streamUrl('https://agentx.example/anp-im/rpc')).toBe('wss://agentx.example/anp-im/stream')
    expect(streamUrl('http://localhost:8080/rpc')).toBe('ws://localhost:8080/stream')
    expect(streamUrl('https://agentx.example/')).toBe('wss://agentx.example/stream')
  })

  it('refuses an endpoint no stream address can be derived from', () => {
    expect(() => streamUrl('mailto:someone@example.com')).toThrow(ConnectxError)
    expect(() => streamUrl('not a url')).toThrow(ConnectxError)
  })
})

describe('backoffMs', () => {
  it('doubles, and stops at the ceiling', () => {
    // The design document's own example: attempt 2 waits 4s.
    expect(backoffMs(1, 0.5)).toBe(2000)
    expect(backoffMs(2, 0.5)).toBe(4000)
    expect(backoffMs(3, 0.5)).toBe(8000)
    expect(backoffMs(20, 0.5)).toBe(30_000)
  })

  it('spreads clients around the schedule rather than stacking them', () => {
    expect(backoffMs(2, 0)).toBeLessThan(4000)
    expect(backoffMs(2, 1)).toBeGreaterThan(4000)
  })
})

describe('decodeMessage', () => {
  it('reads a direct message out of the payload the service pushes', () => {
    const decoded = decodeMessage(incoming('msg-1'), 43)
    expect(decoded).toEqual({
      type: 'message',
      seq: 43,
      message_id: 'msg-1',
      from: 'did:wba:example.com:user:bob:e1_key',
      target_kind: 'agent',
      content_type: 'text/plain',
      text: 'hello',
      accepted_at: '2026-09-30T14:02:11Z',
    })
  })

  it('reads a group message, and names the group', () => {
    const frame = incoming('msg-2', {
      meta: {
        sender_did: 'did:wba:example.com:user:bob:e1_key',
        target: { kind: 'group', did: 'did:wba:example.com:group:contract-team' },
        message_id: 'msg-2',
        content_type: 'text/plain',
      },
      body: { text: 'attachment first' },
    })
    const decoded = decodeMessage(frame, 44)
    expect(decoded?.target_kind).toBe('group')
    expect(decoded?.group_did).toBe('did:wba:example.com:group:contract-team')
  })

  it('renders a JSON payload as JSON', () => {
    const frame = incoming('msg-3', { body: { payload: { kind: 'ping' } } })
    expect(decodeMessage(frame, 1)?.text).toBe('{\n  "kind": "ping"\n}')
  })

  it('leaves an encrypted payload unrendered instead of dumping base64', () => {
    // The CLI holds no key and never will (message-service.md §11), so there is nothing
    // here to show; saying so is the whole of what can honestly be printed.
    const frame = incoming('msg-4', { body: { payload_b64u: 'AAAA' } })
    expect(decodeMessage(frame, 1)?.text).toBeUndefined()
  })

  it('ignores frames that are not delivered messages', () => {
    expect(decodeMessage({ jsonrpc: '2.0', method: 'group.state_changed', params: {} }, 1)).toBeUndefined()
    expect(decodeMessage(response('abc', {}), 1)).toBeUndefined()
    expect(decodeMessage('not a frame', 1)).toBeUndefined()
  })
})

describe('runListen', () => {
  it('refuses a --since that is not a delivery number before it reads the keystore', async () => {
    // The order is the point: reporting a typo should not cost a password prompt, a DID
    // document fetch and a socket.
    const h = harness()
    let opened = false
    const deps: ListenDeps = {
      ...h.deps,
      openChannel: async () => {
        opened = true
        return h.channel
      },
    }
    await expect(runListen({ since: 'nope', once: true }, deps)).rejects.toMatchObject({ code: 'invalid_argument' })
    expect(opened).toBe(false)
  })

  it('introduces itself, authenticates, backfills, then prints live', async () => {
    const h = harness()
    const run = runListen({}, h.deps)
    await flush() // let the socket open
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'claude-code/default', cursor_accepted: 40, head_seq: 42 } })
    await flush()
    serve(socket, { 'sync.delta': { messages: [{ seq: 41, method: 'direct.incoming', params: incoming('msg-41').params }], has_more: false } })
    await flush()

    expect(h.events).toContainEqual({ state: 'connecting', service: 'wss://agentx.example/anp-im/stream' })
    expect(h.events).toContainEqual({ state: 'connected', device: 'claude-code/default', head: 42 })

    // The backfill is rendered with the delivery number the service gave it.
    const backfilled = h.events.find((e) => 'message_id' in e && e.message_id === 'msg-41')
    expect(backfilled).toMatchObject({ seq: 41, text: 'hello' })

    // A live frame is rendered with the number the client counted from the head.
    socket.deliver(incoming('msg-43'))
    await flush()
    expect(h.events.find((e) => 'message_id' in e && e.message_id === 'msg-43')).toMatchObject({ seq: 43 })

    // …and the next one counts on, without the server having said so.
    socket.deliver(incoming('msg-44'))
    await flush()
    expect(h.events.find((e) => 'message_id' in e && e.message_id === 'msg-44')).toMatchObject({ seq: 44 })

    h.stop()
    await run
  })

  it('asks for the cursor it was told to start from, and for the device it was given', async () => {
    const h = harness()
    const run = runListen({ device: 'laptop', since: '7', once: true }, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    const auth = socket.request('stream.auth')
    expect(auth.params).toMatchObject({ body: { device_id: 'laptop', cursor: 7 } })
    expect(auth.method).toBe('stream.auth')
    // The handshake is signed like any other call: an unsigned one would let anyone claim
    // the queue that the cursor names, and P1 附录 A.4 L1068 requires the target the
    // signature is bound to (message-service.md §9.1).
    expect(auth.params).toHaveProperty('auth')
    expect(auth.params).toMatchObject({ meta: { target: { kind: 'agent', did: 'did:wba:example.com:user:alice:e1_key' } } })
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'laptop', cursor_accepted: 7, head_seq: 9 } })
    await flush()
    serve(socket, { 'sync.delta': { messages: [], has_more: false } })
    await run
    // The backfill names the same device as the handshake: the service filters the page by
    // it (P5 §10.7.1 L1407), so a catch-up that stayed anonymous would replay the account's
    // rows and drop this device's own.
    expect(socket.request('sync.delta').params).toMatchObject({ body: { since: 7, device_id: 'laptop' } })
  })

  it('exits after the backfill with --once, without waiting for anything to arrive', async () => {
    const h = harness()
    const run = runListen({ once: true }, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'claude-code/default', cursor_accepted: 0, head_seq: 0 } })
    await flush()
    serve(socket, { 'sync.delta': { messages: [], has_more: false } })
    await expect(run).resolves.toBeUndefined()
    expect(socket.sent.map((f) => f.method)).toEqual(['stream.auth', 'sync.delta'])
  })

  it('refuses to keep talking to a stream that named a different service DID', async () => {
    // The upgrade is plaintext until the handshake, so this is the first check that the
    // signed request is going where the DID document said it would (realtime.md §4.2).
    const h = harness()
    const run = runListen({}, h.deps)
    await flush()
    h.connections[0].deliver({ jsonrpc: '2.0', method: 'stream.hello', params: { server_did: 'did:wba:elsewhere.example', head_seq: 0 } })
    await expect(run).rejects.toThrow(/elsewhere\.example/)
  })

  it('does not retry a refusal, because the same key would be refused again', async () => {
    const h = harness()
    const run = runListen({}, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    const last = socket.sent[socket.sent.length - 1]
    socket.deliver({
      jsonrpc: '2.0',
      id: last.id,
      error: { code: 1001, message: 'unsupported', data: { anp_code: 'anp.unsupported_profile' } },
    })
    await expect(run).rejects.toMatchObject({ code: 'unsupported_extension' })
    expect(h.connections).toHaveLength(1)
  })

  it('reconnects after a drop, and says so before waiting', async () => {
    const h = harness()
    const run = runListen({}, h.deps)
    await flush()
    h.connections[0].drop('network')
    await flush()
    await flush()
    expect(h.events).toContainEqual({ state: 'reconnecting', attempt: 1, after_ms: 2000 })
    expect(h.connections).toHaveLength(2)
    h.connections[1].drop()
    await flush()
    await flush()
    expect(h.events).toContainEqual({ state: 'reconnecting', attempt: 2, after_ms: 4000 })
    h.stop()
    await run
  })

  it('marks each message read, and moves the cursor, only when --ack was asked for', async () => {
    const h = harness()
    const run = runListen({ ack: true }, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'claude-code/default', cursor_accepted: 0, head_seq: 0 } })
    await flush()
    serve(socket, { 'sync.delta': { messages: [], has_more: false } })
    await flush()
    socket.deliver(incoming('msg-1'))
    await flush()
    const read = socket.request('inbox.mark_read')
    expect(read.params).toMatchObject({ body: { message_ids: ['msg-1'] } })
    serve(socket, { 'inbox.mark_read': { updated_count: 1, message_ids: ['msg-1'] } })
    await flush()
    // realtime.md §6: the read state (`msg inbox --include-read` reads it back) and the
    // delivery cursor (what stops a reconnect from replaying) are two questions, so two
    // calls. The seq is the one the client counted for the frame it just rendered (§5.5).
    const confirmed = socket.request('stream.ack')
    expect(confirmed.params).toMatchObject({ body: { seq: 1 } })
    serve(socket, { 'stream.ack': { cursor: 1 } })
    await flush()
    h.stop()
    await run
  })

  it('names each call the Profile its own method belongs to', async () => {
    // The fake server above refuses a mismatched profile, so this is the direct statement
    // of what those refusals would have been about: two profiles on one connection.
    const h = harness()
    const run = runListen({ ack: true }, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'd', cursor_accepted: 0, head_seq: 0 } })
    await flush()
    serve(socket, { 'sync.delta': { messages: [], has_more: false } })
    await flush()
    socket.deliver(incoming('msg-1'))
    await flush()
    serve(socket, { 'inbox.mark_read': {} })
    await flush()
    serve(socket, { 'stream.ack': { cursor: 1 } })
    await flush()
    const profileOfSent = (method: string): unknown =>
      (socket.request(method).params as { meta?: { profile?: unknown } }).meta?.profile
    expect(profileOfSent('stream.auth')).toBe('x_agentx.stream.v1')
    expect(profileOfSent('sync.delta')).toBe('x_agentx.inbox.v1')
    expect(profileOfSent('inbox.mark_read')).toBe('x_agentx.inbox.v1')
    expect(profileOfSent('stream.ack')).toBe('x_agentx.stream.v1')
    h.stop()
    await run
  })

  it('pages the backfill until the service says there is no more', async () => {
    const h = harness()
    const run = runListen({ once: true }, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'd', cursor_accepted: 0, head_seq: 3 } })
    await flush()
    serve(socket, {
      'sync.delta': { messages: [{ seq: 1, method: 'direct.incoming', params: incoming('a').params }], has_more: true, next_since: 2 },
    })
    await flush()
    serve(socket, {
      'sync.delta': { messages: [{ seq: 2, method: 'direct.incoming', params: incoming('b').params }], has_more: false, next_since: 3 },
    })
    await expect(run).resolves.toBeUndefined()
    const ids = h.events.filter((e) => 'message_id' in e).map((e) => e.message_id)
    expect(ids).toEqual(['a', 'b'])
  })

  it('stops paging rather than repeating a page that does not move the cursor', async () => {
    // A service that answers has_more with the same next_since forever would otherwise
    // make this an infinite loop on a command whose whole job is to stay running.
    const h = harness()
    const run = runListen({ once: true }, h.deps)
    await flush()
    const socket = h.connections[0]
    socket.deliver(HELLO)
    await flush()
    serve(socket, { 'stream.auth': { device_id: 'd', cursor_accepted: 0, head_seq: 1 } })
    await flush()
    serve(socket, { 'sync.delta': { messages: [], has_more: true, next_since: 0 } })
    await expect(run).resolves.toBeUndefined()
    expect(socket.sent.filter((f) => f.method === 'sync.delta')).toHaveLength(1)
  })
})
