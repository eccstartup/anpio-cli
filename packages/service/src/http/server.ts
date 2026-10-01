// The HTTP layer: routing, body reading, and nothing else.
//
// Everything above it — envelope validation, the method table, auth, idempotency — lives
// behind the `handleRpc` seam below, which `main.ts` fills with `createDispatch`. Keeping
// the transport this thin is what lets the router be tested without a database and the RPC
// surface be tested without opening a socket (see http/server.test.ts and rpc/dispatch.test.ts).
//
// Routes and the status codes that are NOT 200 are message-service.md §2.1.

import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import type { Duplex } from 'node:stream'
import type { Config } from '../config'
import { upgrade, type WebSocketConnection, type WebSocketHandlers } from '../stream/ws'

export const RPC_PATH = '/anp-im/rpc'
export const STREAM_PATH = '/anp-im/stream'
export const WELL_KNOWN_PATH = '/.well-known/anp-message-service.json'

/** `POST /anp-im/rpc`, the control plane. `body` is the request text, undecoded: the
 *  envelope layer needs the bytes it was given, and the `Content-Digest` check (C3)
 *  covers those bytes rather than a re-serialization of them. */
export interface RpcRequest {
  body: string
  headers: IncomingMessage['headers']
  url: URL
}

export interface RpcResponse {
  /** 200 for every JSON-RPC exchange, success or failure (§2.1). The field is here
   *  because `handleRpc` is also where a future 413/415 refusal would be produced. */
  status: number
  body: string
  contentType?: string
}

/** The seam C2 onward plugs into. Returning a value rather than writing to the response
 *  keeps a handler free of `ServerResponse`. */
export type RpcHandler = (request: RpcRequest) => Promise<RpcResponse> | RpcResponse

/**
 * What the stream route does with a connection (C7).
 *
 * It hands back the handlers, which are built around the connection, and the HTTP layer
 * never learns what a frame means — the same division as {@link RpcHandler}. The reason
 * the connection is the argument is in `ws.ts`'s `upgrade`: a client may pipeline its
 * first frame with the upgrade, and those bytes are parsed before this returns.
 */
export type StreamHandler = (connection: WebSocketConnection, request: IncomingMessage) => WebSocketHandlers

export interface ServerOptions {
  config: Config
  handleRpc: RpcHandler
  /** Absent means the stream route keeps answering 501, which is what a service with no
   *  subscriber registry wired up should say. */
  handleStream?: StreamHandler
}

export interface RunningServer {
  /** The address actually bound. `config.listen.port` may be 0, in which case this is the
   *  port the OS picked. */
  address: { host: string; port: number }
  listen(): Promise<void>
  close(): Promise<void>
}

function send(
  res: ServerResponse,
  status: number,
  contentType: string,
  body: string,
  extra: Record<string, string> = {},
): void {
  // An empty body gets no content type: a Notification is answered with nothing at all
  // (§5.6 L201), and promising JSON that is not there is a lie about the payload.
  const headers: Record<string, string | number> = { 'content-length': Buffer.byteLength(body), ...extra }
  if (body !== '') headers['content-type'] = contentType
  res.writeHead(status, headers)
  res.end(body)
}

/**
 * Answer a request whose body was never read.
 *
 * Node destroys a keep-alive socket when the response finishes while the request body is
 * still unread, and the client sees that as a connection reset — on the NEXT request, if
 * it reused the pooled connection. So every refusal here ends the connection on purpose
 * and says so in the response.
 *
 * The body is deliberately NOT drained first. Draining a request that announced gigabytes
 * is the denial of service `AGENTX_MAX_BODY` exists to prevent, and draining is only
 * cheap for the requests that are not the problem.
 */
function refuse(res: ServerResponse, status: number, message: string, extra: Record<string, string> = {}): void {
  send(res, status, 'application/json', JSON.stringify({ error: message }), { ...extra, connection: 'close' })
}

/**
 * Read the whole request body, refusing as soon as it exceeds `maxBody`.
 *
 * The cap is enforced while reading rather than after: a request that announces 4 GiB and
 * sends it would otherwise be buffered in full before the size is known, which is the
 * denial of service the cap exists to prevent.
 */
async function readBody(req: IncomingMessage, maxBody: number): Promise<string | undefined> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buf = chunk as Buffer
    size += buf.length
    // Stop reading here rather than draining the rest: `refuse` closes the connection.
    if (size > maxBody) return undefined
    chunks.push(buf)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/** Is this a `Content-Type` we will hand on as JSON? Parameters (`; charset=utf-8`) and
 *  case are ignored: both spell the same media type. An absent header is accepted, because
 *  a client with no body to describe is not lying about one. */
function isJsonContentType(value: string | undefined): boolean {
  if (value === undefined) return true
  const mediaType = value.split(';')[0]?.trim().toLowerCase() ?? ''
  return mediaType === 'application/json'
}

export function createServer(options: ServerOptions): RunningServer {
  const { config } = options
  const address = { ...config.listen }

  const server: Server = createHttpServer((req, res) => {
    void route(req, res).catch(() => {
      // Only reachable if `handleRpc` throws: every path below returns. That is a bug in
      // this service rather than a protocol event, so it is a 500 and not a JSON-RPC error.
      if (res.headersSent) res.end()
      else send(res, 500, 'application/json', JSON.stringify({ error: 'internal error' }))
    })
  })

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // `req.url` is a path on this server, so the base is only there to satisfy the URL
    // parser; it is never read and never leaves this function's scope.
    const url = new URL(req.url ?? '/', 'http://localhost')

    if (url.pathname === RPC_PATH) {
      if (req.method !== 'POST') {
        refuse(res, 405, 'method not allowed', { allow: 'POST' })
        return
      }
      if (!isJsonContentType(req.headers['content-type'])) {
        refuse(res, 415, 'content-type must be application/json')
        return
      }
      const body = await readBody(req, config.maxBody)
      if (body === undefined) {
        refuse(res, 413, `request body exceeds ${config.maxBody} bytes`)
        return
      }
      const answer = await options.handleRpc({ body, headers: req.headers, url })
      send(res, answer.status, answer.contentType ?? 'application/json', answer.body)
      return
    }

    if (url.pathname === STREAM_PATH) {
      if (req.method !== 'GET') {
        refuse(res, 405, 'method not allowed', { allow: 'GET' })
        return
      }
      // An ordinary GET reaches here only when the upgrade listener declined it, and the
      // one thing such a request is missing is the upgrade itself. `426` says that; `405`
      // would blame the method, which is the one part that is right.
      refuse(res, 426, `${STREAM_PATH} only answers a WebSocket upgrade`, { upgrade: 'websocket' })
      return
    }

    if (url.pathname === WELL_KNOWN_PATH) {
      if (req.method !== 'GET') {
        refuse(res, 405, 'method not allowed', { allow: 'GET' })
        return
      }
      // C8. Answering 501 keeps an unbuilt surface distinguishable from a missing one.
      refuse(res, 501, `${WELL_KNOWN_PATH} is not implemented yet`)
      return
    }

    refuse(res, 404, 'not found')
  }

  // The upgrade is a separate event, not a route: Node hands the socket over before any
  // response exists. Only this path is accepted; anything else is destroyed rather than
  // left hanging, since an un-upgraded socket would otherwise sit there until it timed out.
  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const handleStream = options.handleStream
    if (url.pathname !== STREAM_PATH || handleStream === undefined) {
      socket.destroy()
      return
    }
    const connection = upgrade(req, socket as Duplex, head, (conn) => handleStream(conn, req))
    // `upgrade` returns undefined when the request was not a valid upgrade (a missing
    // `Sec-WebSocket-Version`, say), in which case nothing was written.
    if (connection === undefined) socket.destroy()
  })

  return {
    get address() {
      return address
    },
    listen(): Promise<void> {
      return new Promise((resolve, reject) => {
        const onError = (err: Error): void => {
          server.off('listening', onListening)
          reject(err)
        }
        const onListening = (): void => {
          server.off('error', onError)
          const bound = server.address()
          if (bound !== null && typeof bound === 'object') {
            address.host = bound.address
            address.port = bound.port
          }
          resolve()
        }
        server.once('error', onError)
        server.once('listening', onListening)
        server.listen(config.listen.port, config.listen.host)
      })
    },
    close(): Promise<void> {
      return new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()))
      })
    },
  }
}
