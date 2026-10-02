// The WebSocket half of the subscription path: RFC 6455, server side, as far as this
// service needs it.
//
// It is written here rather than taken from a package because the package would be the
// service's first runtime dependency, and because the parts this service actually needs
// are the parts it must be strict about. The subset is: text frames, fragmentation,
// ping/pong, the close handshake. No extensions are negotiated — `permessage-deflate` and
// friends are optional to accept and not accepting them is what RFC 6455 §9.1 allows — and
// binary frames are read but reported as unsupported to the caller.
//
// Three rules here are MUSTs from the RFC and are the reason this is not simply a frame
// splitter:
//
//   * a client-to-server frame MUST be masked (§5.1), so an unmasked one is a protocol
//     error (1002) rather than something to read anyway;
//   * RSV bits MUST be zero when no extension was negotiated (§5.2) — the same 1002;
//   * a text frame's payload MUST be valid UTF-8 (§5.6, §8.1), which `toString('utf8')`
//     does NOT enforce: it substitutes U+FFFD for bad bytes. That substitution is how a
//     frame smuggling invalid UTF-8 gets past a layer that then re-serializes it.
//
// Payload sizes are capped on the way in, because the 64-bit length is the client's to
// choose: without a cap, eight bytes on the wire ask this process to allocate 2^63.

import { createHash } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import type { Duplex } from 'node:stream'

/** The magic value RFC 6455 §1.3 puts in the accept hash. */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

/** One message may not exceed this. realtime.md §3 frames are JSON-RPC envelopes whose
 *  body cap is already `AGENTX_MAX_BODY`; this is the same order of magnitude and is
 *  enforced before a fragment is buffered, so a peer cannot announce a huge frame. */
export const MAX_MESSAGE = 1024 * 1024

/** How much may be queued to a client before it counts as too slow to keep (realtime.md
 *  §5.3: buffer overflow is answered by dropping the connection, never by dropping a
 *  message). */
export const MAX_BUFFERED = 4 * 1024 * 1024

const OP_CONTINUATION = 0x0
const OP_TEXT = 0x1
const OP_BINARY = 0x2
const OP_CLOSE = 0x8
const OP_PING = 0x9
const OP_PONG = 0xa

/** Close codes that mean "this connection is not usable"; 1000 is a normal closure. */
export const CLOSE_NORMAL = 1000
export const CLOSE_PROTOCOL_ERROR = 1002
export const CLOSE_UNSUPPORTED_DATA = 1003
export const CLOSE_INVALID_PAYLOAD = 1007
export const CLOSE_MESSAGE_TOO_BIG = 1009
export const CLOSE_INTERNAL_ERROR = 1011
/** 1001 — "going away": the server is shutting down. Distinct from 1013 below so a client
 *  can tell "I am leaving" from "you come back". Both end in a reconnect; only the second
 *  is worth a shorter backoff. */
export const CLOSE_GOING_AWAY = 1001
/** 1013 (§7.4.1) — the server ended the connection and the client should come back. It is
 *  what a subscriber that fell behind gets (realtime.md §5.3): the answer to "you are too
 *  far back" is a reconnect with a cursor, not a retry on this socket. */
export const CLOSE_TRY_AGAIN_LATER = 1013

/** `Sec-WebSocket-Accept`, RFC 6455 §4.2.2. Exported because the handshake is the one
 *  piece a test can check against the RFC's own worked example. */
export function acceptKey(key: string): string {
  return createHash('sha1').update(key + GUID).digest('base64')
}

/** Is this request asking to upgrade to WebSocket, per RFC 6455 §4.2.1? Checks only what
 *  that section says MUST be present. */
export function isWebSocketUpgrade(req: IncomingMessage): boolean {
  if (req.method !== 'GET') return false
  if (req.headers.upgrade?.toLowerCase() !== 'websocket') return false
  // `Connection` is a comma-separated list whose members are case-insensitive.
  const connection = req.headers.connection ?? ''
  if (!connection.split(',').some((token) => token.trim().toLowerCase() === 'upgrade')) return false
  if (req.headers['sec-websocket-version'] !== '13') return false
  const key = req.headers['sec-websocket-key']
  return typeof key === 'string' && key !== ''
}

export interface WebSocketHandlers {
  /** One complete text message. Binary messages never reach here: this protocol carries
   *  JSON envelopes, and a binary frame is refused with 1003. */
  onMessage(text: string): void
  /** The connection is gone, for any reason. Fires at most once. */
  onClose(): void
}

export interface WebSocketConnection {
  /** Send one text frame. A send after close is ignored rather than throwing: a
   *  notification is best-effort (realtime.md §1) and racing a close is normal. */
  send(text: string): void
  /** Begin the closing handshake. */
  close(code?: number, reason?: string): void
  /** End the connection without waiting for the peer's close frame. */
  destroy(): void
  /** Bytes written but not yet flushed to the kernel. A client that stops reading shows
   *  up here, which is how the registry decides it is too slow. */
  readonly bufferedAmount: number
  readonly closed: boolean
}

type Decoded =
  | { kind: 'message'; fin: boolean; opcode: number; payload: Buffer }
  | { kind: 'control'; fin: boolean; opcode: number; payload: Buffer }
  | { kind: 'protocol-error'; code: number; reason: string }

/** Read as many whole frames as `buf` holds. A partial trailing frame is left for the
 *  next chunk by returning how many bytes were consumed. */
function decodeFrames(buf: Buffer): { results: Decoded[]; rest: Buffer } {
  const results: Decoded[] = []
  let at = 0

  for (;;) {
    if (at + 2 > buf.length) break
    const b0 = buf[at] as number
    const b1 = buf[at + 1] as number
    const fin = (b0 & 0x80) !== 0
    const rsv = b0 & 0x70
    const opcode = b0 & 0x0f
    const masked = (b1 & 0x80) !== 0
    let length = b1 & 0x7f

    // §5.2: no extension was negotiated, so no RSV bit may be set.
    if (rsv !== 0) {
      results.push({ kind: 'protocol-error', code: CLOSE_PROTOCOL_ERROR, reason: 'RSV bits set with no extension negotiated' })
      return { results, rest: Buffer.alloc(0) }
    }
    // §5.1: every client-to-server frame MUST be masked.
    if (!masked) {
      results.push({ kind: 'protocol-error', code: CLOSE_PROTOCOL_ERROR, reason: 'client frame was not masked' })
      return { results, rest: Buffer.alloc(0) }
    }
    if (opcode !== OP_CONTINUATION && opcode !== OP_TEXT && opcode !== OP_BINARY && opcode < OP_CLOSE) {
      results.push({ kind: 'protocol-error', code: CLOSE_PROTOCOL_ERROR, reason: `unknown opcode ${opcode}` })
      return { results, rest: Buffer.alloc(0) }
    }

    let headerEnd = at + 2
    if (length === 126) {
      if (headerEnd + 2 > buf.length) break
      length = buf.readUInt16BE(headerEnd)
      headerEnd += 2
    } else if (length === 127) {
      if (headerEnd + 8 > buf.length) break
      const big = buf.readBigUInt64BE(headerEnd)
      headerEnd += 8
      // §5.2: the most significant bit MUST be 0, and the value must fit the platform's
      // idea of a length. A negative read would be worse than a refusal.
      if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
        results.push({ kind: 'protocol-error', code: CLOSE_MESSAGE_TOO_BIG, reason: 'frame length is out of range' })
        return { results, rest: Buffer.alloc(0) }
      }
      length = Number(big)
    }

    const control = opcode >= OP_CLOSE
    // §5.5: control frames MUST NOT be fragmented and MUST NOT carry more than 125 bytes.
    if (control && (!fin || length > 125)) {
      results.push({ kind: 'protocol-error', code: CLOSE_PROTOCOL_ERROR, reason: 'control frame was fragmented or too long' })
      return { results, rest: Buffer.alloc(0) }
    }
    // The cap is checked against the announced length, BEFORE the payload is buffered.
    if (!control && length > MAX_MESSAGE) {
      results.push({ kind: 'protocol-error', code: CLOSE_MESSAGE_TOO_BIG, reason: `frame announces ${length} bytes` })
      return { results, rest: Buffer.alloc(0) }
    }

    const maskStart = headerEnd
    const payloadStart = maskStart + 4
    if (payloadStart + length > buf.length) break

    const payload = Buffer.allocUnsafe(length)
    buf.copy(payload, 0, payloadStart, payloadStart + length)
    const mask = buf.subarray(maskStart, maskStart + 4)
    for (let i = 0; i < length; i++) payload[i] = (payload[i] as number) ^ (mask[i & 3] as number)

    results.push({ kind: control ? 'control' : 'message', fin, opcode, payload })
    at = payloadStart + length
  }

  return { results, rest: buf.subarray(at) }
}

/**
 * Complete the handshake and take over the socket.
 *
 * Returns `undefined` when the request is not a WebSocket upgrade, in which case the
 * caller answers it as an ordinary HTTP request.
 *
 * `handlersFor` is handed the connection and returns the handlers, which is the only
 * order that works: what a session does with a message is written in terms of the
 * connection it came in on, so the connection has to exist first. Bytes already read past
 * the request (`head`) are parsed before this function returns, so a handler attached
 * afterwards would miss a client's very first frame — the handshake, if the client
 * pipelined it with the upgrade.
 */
export function upgrade(
  req: IncomingMessage,
  socket: Duplex,
  head: Buffer,
  handlersFor: (connection: WebSocketConnection) => WebSocketHandlers,
): WebSocketConnection | undefined {
  if (!isWebSocketUpgrade(req)) return undefined
  const key = req.headers['sec-websocket-key'] as string

  // §4.2.2. No `Sec-WebSocket-Extensions` and no `Sec-WebSocket-Protocol` are echoed:
  // an extension the client offered and the server did not select is simply not in use.
  const headers = [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey(key)}`,
    '',
    '',
  ]
  socket.write(headers.join('\r\n'))

  let closed = false
  let fragmentOpcode: number | undefined
  let fragments: Buffer[] = []
  let fragmentLength = 0
  // Explicitly `Buffer<ArrayBufferLike>`: `Buffer.alloc` narrows to the `ArrayBuffer`
  // flavour while `subarray` does not, and an inferred type here would only hold one of
  // the two things this variable is assigned.
  let pending: Buffer = Buffer.alloc(0)

  // `fatal: true` is the whole point: the decoders replace malformed input with U+FFFD,
  // which would let a frame carrying invalid UTF-8 through as if it were text.
  const utf8 = new TextDecoder('utf-8', { fatal: true })

  const sendFrame = (opcode: number, payload: Buffer): void => {
    if (socket.destroyed) return
    socket.write(encodeFrame(opcode, payload))
  }

  const connection: WebSocketConnection = {
    send(text: string): void {
      if (closed) return
      sendFrame(OP_TEXT, Buffer.from(text, 'utf8'))
    },
    close(code = CLOSE_NORMAL, reason = ''): void {
      if (closed) return
      sendFrame(OP_CLOSE, closePayload(code, reason))
      finish()
      // Give the close frame a chance to flush before the socket goes away. A peer that
      // never answers is not worth waiting on beyond that.
      socket.end()
    },
    destroy(): void {
      finish()
      socket.destroy()
    },
    get bufferedAmount(): number {
      return socket.writableLength
    },
    get closed(): boolean {
      return closed
    },
  }

  const handlers = handlersFor(connection)

  const finish = (): void => {
    if (closed) return
    closed = true
    socket.removeAllListeners('data')
    socket.removeAllListeners('close')
    // The `error` listener deliberately stays. `finish` runs on the way out — from a close
    // frame, from `destroy()`, from the first error — and tearing the socket down is what
    // provokes the *next* one: a peer that vanished gets its RST read a tick later, and Node
    // emits that as an `error` event. An `error` event with no listener is fatal by design,
    // so removing this one turns "a client disconnected abruptly" into "the service exits".
    // `finish` is already idempotent through `closed`, which is what makes leaving it on safe.
    handlers.onClose()
  }

  const fail = (code: number, reason: string): void => {
    // The reason is sent as bytes, not as JSON: this is the WebSocket close frame's own
    // payload (§5.5.1), and its length limit is 123 bytes including the code.
    sendFrame(OP_CLOSE, closePayload(code, reason))
    finish()
    socket.end()
  }

  const handle = (decoded: Decoded): boolean => {
    if (decoded.kind === 'protocol-error') {
      fail(decoded.code, decoded.reason)
      return false
    }
    if (decoded.kind === 'control') {
      switch (decoded.opcode) {
        case OP_PING:
          sendFrame(OP_PONG, decoded.payload)
          return true
        case OP_PONG:
          return true
        case OP_CLOSE:
          // §5.5.1: echo the close and go. The peer's code, if any, is echoed back as the
          // code and nothing more — its reason text is not ours to repeat.
          sendFrame(
            OP_CLOSE,
            closePayload(decoded.payload.length >= 2 ? decoded.payload.readUInt16BE(0) : CLOSE_NORMAL, ''),
          )
          finish()
          socket.end()
          return false
        default:
          return true
      }
    }

    if (decoded.opcode === OP_BINARY) {
      // A frame this protocol has no use for. Refusing it is honest; accepting it would
      // mean either parsing bytes as JSON or silently dropping a message.
      fail(CLOSE_UNSUPPORTED_DATA, 'this endpoint carries JSON text frames only')
      return false
    }
    if (decoded.opcode === OP_TEXT) {
      if (fragmentOpcode !== undefined) {
        fail(CLOSE_PROTOCOL_ERROR, 'a new data frame arrived while a fragmented message was open')
        return false
      }
      if (decoded.payload.length > MAX_MESSAGE) {
        fail(CLOSE_MESSAGE_TOO_BIG, 'message too big')
        return false
      }
      fragmentOpcode = OP_TEXT
      fragments = [decoded.payload]
      fragmentLength = decoded.payload.length
    } else {
      // Continuation. `decodeFrames` guarantees a control frame is never a continuation.
      if (fragmentOpcode === undefined) {
        fail(CLOSE_PROTOCOL_ERROR, 'continuation frame with no message to continue')
        return false
      }
      fragmentLength += decoded.payload.length
      if (fragmentLength > MAX_MESSAGE) {
        fail(CLOSE_MESSAGE_TOO_BIG, 'message too big')
        return false
      }
      fragments.push(decoded.payload)
    }

    // A fragmented message is delivered once, whole. The frames before the last are
    // remembered only as bytes: nothing here can interpret a partial JSON envelope.
    if (!decoded.fin) return true

    const payload = fragments.length === 1 ? (fragments[0] as Buffer) : Buffer.concat(fragments)
    fragmentOpcode = undefined
    fragments = []
    fragmentLength = 0

    let text: string
    try {
      text = utf8.decode(payload)
    } catch {
      fail(CLOSE_INVALID_PAYLOAD, 'text frame payload is not valid UTF-8')
      return false
    }
    handlers.onMessage(text)
    return true
  }

  const onData = (chunk: Buffer): void => {
    pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk])
    const { results, rest } = decodeFrames(pending)
    pending = rest
    for (const decoded of results) {
      if (!handle(decoded)) return
    }
  }

  socket.on('data', onData)
  socket.on('close', finish)
  socket.on('error', finish)
  if (head.length > 0) onData(head)

  return connection
}

/** Encoding writes the length in the shortest form RFC 6455 §5.2 allows. */
function encodeFrame(opcode: number, payload: Buffer): Buffer {
  const length = payload.length
  let header: Buffer
  if (length < 126) {
    header = Buffer.allocUnsafe(2)
    header[1] = length
  } else if (length < 65536) {
    header = Buffer.allocUnsafe(4)
    header[1] = 126
    header.writeUInt16BE(length, 2)
  } else {
    header = Buffer.allocUnsafe(10)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(length), 2)
  }
  header[0] = 0x80 | opcode
  return Buffer.concat([header, payload])
}

/** §5.5.1: a close frame's body is a 2-byte code followed by UTF-8 reason text. */
function closePayload(code: number, reason: string): Buffer {
  const text = Buffer.from(reason, 'utf8')
  // 123 bytes of reason is the limit the 125-byte control-frame cap leaves.
  const body = Buffer.allocUnsafe(2 + Math.min(text.length, 123))
  body.writeUInt16BE(code, 0)
  text.copy(body, 2, 0, body.length - 2)
  return body
}
