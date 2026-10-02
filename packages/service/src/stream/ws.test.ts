// The WebSocket layer, tested two ways on purpose.
//
// The happy path is driven by Node's own `WebSocket` client — the same constructor
// `connectx msg listen` uses — so the masking, the length encoding and the UTF-8 handling
// are checked against an implementation that is not this one. Everything a well-behaved
// client never sends (an unmasked frame, invalid UTF-8, a frame that announces a gigabyte,
// a fragmented message) is hand-built on a raw socket, because those paths exist precisely
// for peers that are not well-behaved and a conforming client cannot reach them.

import { afterEach, describe, expect, it } from 'vitest'
import { createServer as createHttpServer, type Server } from 'node:http'
import { connect, type AddressInfo, type Socket } from 'node:net'
import type { Duplex } from 'node:stream'
import { PassThrough } from 'node:stream'
import { acceptKey, isWebSocketUpgrade, upgrade, type WebSocketConnection } from './ws'

interface Harness {
  port: number
  received: string[]
  opened: WebSocketConnection[]
  closed: () => number
  stop: () => Promise<void>
}

const running: Server[] = []
/** Raw clients are held here so the teardown can end them: `server.close()` waits for
 *  every connection to finish, and a socket a test left open would hang the hook rather
 *  than fail the test that leaked it. */
const rawSockets: Socket[] = []
/** Upgraded connections are held for the same reason, and one more: an upgraded socket is
 *  detached from the HTTP server, so `closeAllConnections()` does not reach it and the
 *  server would wait for it forever. */
const upgraded: WebSocketConnection[] = []

afterEach(async () => {
  for (const connection of upgraded.splice(0)) connection.destroy()
  for (const socket of rawSockets.splice(0)) socket.destroy()
  for (const server of running.splice(0)) {
    server.closeAllConnections()
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
})

async function startServer(onMessage?: (text: string) => void): Promise<Harness> {
  const received: string[] = []
  const opened: WebSocketConnection[] = []
  let closed = 0
  const server = createHttpServer((_req, res) => {
    res.writeHead(404)
    res.end()
  })
  server.on('upgrade', (req, socket, head) => {
    const connection = upgrade(req, socket as Duplex, head, () => ({
      onMessage: (text) => {
        received.push(text)
        onMessage?.(text)
      },
      onClose: () => {
        closed += 1
      },
    }))
    if (connection === undefined) {
      socket.destroy()
      return
    }
    opened.push(connection)
    upgraded.push(connection)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  running.push(server)
  return {
    port: (server.address() as AddressInfo).port,
    received,
    opened,
    closed: () => closed,
    stop: async () => {
      server.closeAllConnections()
      await new Promise<void>((resolve) => server.close(() => resolve()))
    },
  }
}

/** Poll until `done`, or give up. A deadline rather than a fixed sleep, so a loaded
 *  machine slows the test down instead of failing it. */
async function until(done: () => boolean, deadlineMs = 2000): Promise<void> {
  const deadline = Date.now() + deadlineMs
  while (!done()) {
    if (Date.now() > deadline) throw new Error('timed out')
    await new Promise((resolve) => setTimeout(resolve, 5))
  }
}

interface WebSocketLike {
  send(data: string): void
  close(): void
  addEventListener(type: string, listener: (event: unknown) => void): void
}

/** The global constructor `msg listen` uses. Reached structurally because this package
 *  does not load `lib.dom`. */
function webSocket(url: string): WebSocketLike {
  const Ctor = (globalThis as { WebSocket?: new (url: string) => WebSocketLike }).WebSocket
  if (Ctor === undefined) throw new Error('this Node has no global WebSocket')
  return new Ctor(url)
}

/** Wait until the client's own `open` has fired.
 *
 *  **The server's `opened` is not a substitute.** That one fires when the connection is
 *  built on the server, which can be a poll or two before the client has processed the 101
 *  — and a `send()` from a socket still in CONNECTING throws
 *  `InvalidStateError: Sent before connected`. Waiting on the server side only is how this
 *  test flakes under load. */
async function clientOpen(socket: WebSocketLike): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.addEventListener('open', () => resolve())
    socket.addEventListener('error', (event) => reject(new Error(`client websocket errored: ${String(event)}`)))
  })
}

// ---- a raw client, for the frames a conforming one will not send -----------------

interface RawClient {
  socket: Socket
  handshake: string
  /** Write one already-framed buffer. */
  write(frame: Buffer): void
  /** Every server frame read so far, decoded. */
  frames: { opcode: number; payload: Buffer }[]
  closed: () => boolean
}

/** Server-to-client frames are unmasked (§5.1), which makes this a plain length walk. */
function decodeServerFrames(buf: Buffer, into: { opcode: number; payload: Buffer }[]): Buffer {
  let at = 0
  for (;;) {
    if (at + 2 > buf.length) break
    const b0 = buf[at] as number
    const b1 = buf[at + 1] as number
    const opcode = b0 & 0x0f
    let length = b1 & 0x7f
    let headerEnd = at + 2
    if (length === 126) {
      if (headerEnd + 2 > buf.length) break
      length = buf.readUInt16BE(headerEnd)
      headerEnd += 2
    } else if (length === 127) {
      if (headerEnd + 8 > buf.length) break
      length = Number(buf.readBigUInt64BE(headerEnd))
      headerEnd += 8
    }
    if (headerEnd + length > buf.length) break
    into.push({ opcode, payload: buf.subarray(headerEnd, headerEnd + length) })
    at = headerEnd + length
  }
  return buf.subarray(at)
}

/** A masked client frame — the only kind a client may send (§5.1). */
function clientFrame(opcode: number, payload: Buffer, fin = true): Buffer {
  const mask = Buffer.from([0x12, 0x34, 0x56, 0x78])
  const masked = Buffer.allocUnsafe(payload.length)
  for (let i = 0; i < payload.length; i++) masked[i] = (payload[i] as number) ^ (mask[i & 3] as number)
  let header: Buffer
  if (payload.length < 126) {
    header = Buffer.allocUnsafe(2)
    header[1] = 0x80 | payload.length
  } else if (payload.length < 65536) {
    header = Buffer.allocUnsafe(4)
    header[1] = 0x80 | 126
    header.writeUInt16BE(payload.length, 2)
  } else {
    header = Buffer.allocUnsafe(10)
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(payload.length), 2)
  }
  header[0] = (fin ? 0x80 : 0) | opcode
  return Buffer.concat([header, mask, masked])
}

async function rawClient(port: number): Promise<RawClient> {
  const socket = connect(port, '127.0.0.1')
  rawSockets.push(socket)
  const frames: { opcode: number; payload: Buffer }[] = []
  let closed = false
  let pending: Buffer = Buffer.alloc(0)
  let handshake = ''
  let handshakeDone = false

  socket.on('data', (chunk: Buffer) => {
    if (!handshakeDone) {
      pending = Buffer.concat([pending, chunk])
      const end = pending.indexOf('\r\n\r\n')
      if (end === -1) return
      handshake = pending.subarray(0, end).toString('latin1')
      handshakeDone = true
      pending = pending.subarray(end + 4)
    } else {
      pending = Buffer.concat([pending, chunk])
    }
    pending = decodeServerFrames(pending, frames)
  })
  socket.on('close', () => {
    closed = true
  })
  await new Promise<void>((resolve) => socket.once('connect', resolve))
  socket.write(
    [
      'GET /anp-im/stream HTTP/1.1',
      `Host: 127.0.0.1:${String(port)}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
      'Sec-WebSocket-Version: 13',
      '',
      '',
    ].join('\r\n'),
  )
  await until(() => handshakeDone)
  return {
    socket,
    get handshake() {
      return handshake
    },
    write: (frame) => socket.write(frame),
    frames,
    closed: () => closed,
  }
}

// ---- the handshake ---------------------------------------------------------------

describe('the handshake', () => {
  it('hashes the key the way RFC 6455 §1.3 spells out', () => {
    // The RFC's own worked example, so this is checked against the spec and not against
    // this implementation's previous output.
    expect(acceptKey('dGhlIHNhbXBsZSBub25jZQ==')).toBe('s3pPLMBiTxaQ9kYGzzhZRbK+xOo=')
  })

  it('only takes over a request that is really an upgrade', () => {
    const base = {
      method: 'GET',
      headers: {
        upgrade: 'websocket',
        connection: 'Upgrade',
        'sec-websocket-version': '13',
        'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
      },
    }
    const request = (over: Record<string, unknown>): never => ({ ...base, ...over }) as never
    expect(isWebSocketUpgrade(request({}))).toBe(true)
    expect(isWebSocketUpgrade(request({ headers: { ...base.headers, connection: 'keep-alive, Upgrade' } }))).toBe(true)
    expect(isWebSocketUpgrade(request({ method: 'POST' }))).toBe(false)
    expect(isWebSocketUpgrade(request({ headers: { ...base.headers, upgrade: 'h2c' } }))).toBe(false)
    expect(isWebSocketUpgrade(request({ headers: { ...base.headers, 'sec-websocket-version': '8' } }))).toBe(false)
    expect(isWebSocketUpgrade(request({ headers: { ...base.headers, 'sec-websocket-key': undefined } }))).toBe(false)
  })

  it('answers 101 and leaves a non-upgrade GET to the HTTP layer', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    expect(raw.handshake).toContain('101 Switching Protocols')
    expect(raw.handshake).toContain(`Sec-WebSocket-Accept: ${acceptKey('dGhlIHNhbXBsZSBub25jZQ==')}`)
    raw.socket.destroy()

    const response = await fetch(`http://127.0.0.1:${String(h.port)}/anp-im/stream`)
    // The upgrade handler declined, so the ordinary request handler answered.
    expect(response.status).toBe(404)
  })
})

// ---- the frames ------------------------------------------------------------------

describe('text frames', () => {
  it('carries a message each way with a real client', async () => {
    const h = await startServer()
    const socket = webSocket(`ws://127.0.0.1:${String(h.port)}/anp-im/stream`)
    const seen: string[] = []
    socket.addEventListener('message', (event) => {
      seen.push(String((event as { data: unknown }).data))
    })
    await clientOpen(socket)
    await until(() => h.opened.length === 1)

    socket.send('{"jsonrpc":"2.0","method":"stream.auth"}')
    await until(() => h.received.length === 1)
    expect(h.received[0]).toBe('{"jsonrpc":"2.0","method":"stream.auth"}')

    h.opened[0]?.send('{"jsonrpc":"2.0","method":"direct.incoming"}')
    await until(() => seen.length === 1)
    expect(seen[0]).toBe('{"jsonrpc":"2.0","method":"direct.incoming"}')
  })

  it('reads a frame that was pipelined with the upgrade request', async () => {
    // The bytes after the request headers come to `upgrade()` as `head`. A client that
    // sends its first frame without waiting for the 101 — which is what a pipelining client
    // does, and what Node's own client does on a fast path — would otherwise have that
    // frame dropped before any handler existed to receive it.
    const h = await startServer()
    const socket = connect(h.port, '127.0.0.1')
    rawSockets.push(socket)
    await new Promise<void>((resolve) => socket.once('connect', resolve))
    socket.write(
      Buffer.concat([
        Buffer.from(
          [
            'GET /anp-im/stream HTTP/1.1',
            `Host: 127.0.0.1:${String(h.port)}`,
            'Upgrade: websocket',
            'Connection: Upgrade',
            'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version: 13',
            '',
            '',
          ].join('\r\n'),
        ),
        clientFrame(0x1, Buffer.from('{"method":"stream.auth"}')),
      ]),
    )
    await until(() => h.received.length > 0)
    expect(h.received).toEqual(['{"method":"stream.auth"}'])
  })

  it('reassembles a fragmented message and delivers it once', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(clientFrame(0x1, Buffer.from('{"a":'), false))
    raw.write(clientFrame(0x0, Buffer.from('1}'), true))
    await until(() => h.received.length > 0)
    expect(h.received).toEqual(['{"a":1}'])
  })

  it('sends a large payload with the 16-bit length form and reads it back', async () => {
    // Enough to cross 125 (the 7-bit form) and 65535 (the 16-bit one), which is where an
    // encoder that always used the short form would produce a frame nobody can parse.
    const h = await startServer()
    const socket = webSocket(`ws://127.0.0.1:${String(h.port)}/anp-im/stream`)
    const seen: string[] = []
    socket.addEventListener('message', (event) => {
      seen.push(String((event as { data: unknown }).data))
    })
    await clientOpen(socket)
    await until(() => h.opened.length === 1)

    const payload = JSON.stringify({ text: 'x'.repeat(70_000) })
    socket.send(payload)
    await until(() => h.received.length === 1)
    expect(h.received[0]).toBe(payload)

    h.opened[0]?.send(payload)
    await until(() => seen.length === 1)
    expect(seen[0]).toBe(payload)
  })

  it('answers a ping with the same payload, before any message is read', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(clientFrame(0x9, Buffer.from('keepalive')))
    await until(() => raw.frames.length > 0)
    expect(raw.frames[0]?.opcode).toBe(0xa)
    expect(raw.frames[0]?.payload.toString()).toBe('keepalive')
    expect(h.received).toEqual([])
  })

  it('echoes a close and reports the connection as gone', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(clientFrame(0x8, Buffer.from([0x03, 0xe8]))) // 1000
    await until(() => raw.frames.length > 0)
    expect(raw.frames[0]?.opcode).toBe(0x8)
    expect(raw.frames[0]?.payload.readUInt16BE(0)).toBe(1000)
    await until(() => h.closed() === 1)
  })

  it('keeps an error listener on a socket it has already finished with', () => {
    // A peer that vanishes makes Node read an `ECONNRESET` *after* the connection was torn
    // down, and Node emits that as an `error` event a tick later. An `error` event with no
    // listener is fatal by design, so a listener left in place is the whole difference
    // between "a client disconnected abruptly" and "the service exited" — which is what a
    // `finish` that stripped `error` along with `data` and `close` used to turn it into.
    const socket = new PassThrough()
    const connection = upgrade(
      {
        method: 'GET',
        headers: {
          upgrade: 'websocket',
          connection: 'Upgrade',
          'sec-websocket-version': '13',
          'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
        },
      } as never,
      socket,
      Buffer.alloc(0),
      () => ({ onMessage: () => {}, onClose: () => {} }),
    )
    expect(connection).toBeDefined()
    connection?.destroy()

    expect(socket.listenerCount('error')).toBeGreaterThan(0)
    expect(() => socket.emit('error', new Error('read ECONNRESET'))).not.toThrow()
  })
})

// ---- the frames a conforming client does not send ---------------------------------

describe('refusals', () => {
  /** The close code the peer sent, read out of the close frame. */
  async function refusalCode(raw: RawClient): Promise<number | undefined> {
    await until(() => raw.frames.some((frame) => frame.opcode === 0x8) || raw.closed())
    return raw.frames.find((frame) => frame.opcode === 0x8)?.payload.readUInt16BE(0)
  }

  it('refuses an unmasked client frame', async () => {
    // §5.1. Accepting it would mean reading a payload the peer never had to prove it
    // wrote, which is the whole anti-cache-poisoning point of the mask.
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(Buffer.concat([Buffer.from([0x81, 0x02]), Buffer.from('hi')]))
    expect(await refusalCode(raw)).toBe(1002)
    expect(h.received).toEqual([])
  })

  it('refuses a frame with a reserved bit set', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    const frame = clientFrame(0x1, Buffer.from('hi'))
    frame[0] = (frame[0] as number) | 0x40 // RSV1
    raw.write(frame)
    expect(await refusalCode(raw)).toBe(1002)
  })

  it('refuses a text frame whose payload is not valid UTF-8', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(clientFrame(0x1, Buffer.from([0x7b, 0xff, 0xfe, 0x7d])))
    expect(await refusalCode(raw)).toBe(1007)
    expect(h.received).toEqual([])
  })

  it('refuses a frame that announces more than it may send', async () => {
    // The 64-bit length is the peer's to choose. Refusing on the ANNOUNCED length is what
    // keeps this from being an allocation primitive.
    const h = await startServer()
    const raw = await rawClient(h.port)
    const header = Buffer.allocUnsafe(10)
    header[0] = 0x81
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(8 * 1024 * 1024), 2)
    raw.write(Buffer.concat([header, Buffer.from([0, 0, 0, 0])]))
    expect(await refusalCode(raw)).toBe(1009)
  })

  it('refuses a continuation with nothing to continue', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(clientFrame(0x0, Buffer.from('orphan'), true))
    expect(await refusalCode(raw)).toBe(1002)
  })

  it('refuses a binary frame rather than passing it on as JSON', async () => {
    const h = await startServer()
    const raw = await rawClient(h.port)
    raw.write(clientFrame(0x2, Buffer.from('binary')))
    expect(await refusalCode(raw)).toBe(1003)
    expect(h.received).toEqual([])
  })

  it('stops sending once the connection is closed', async () => {
    const h = await startServer()
    const socket = webSocket(`ws://127.0.0.1:${String(h.port)}/anp-im/stream`)
    await until(() => h.opened.length === 1)
    const connection = h.opened[0] as WebSocketConnection
    connection.destroy()
    expect(connection.closed).toBe(true)
    // A notification racing a close is normal (realtime.md §1), so this must be a no-op
    // rather than a throw into whatever loop was publishing.
    connection.send('{"jsonrpc":"2.0"}')
    await until(() => socket !== undefined)
  })
})
