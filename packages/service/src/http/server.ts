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
import { pipeline } from 'node:stream/promises'
import { ConnectxError, didToUrl } from '@agentx/core'
import type { Config } from '../config'
import type { DataPlaneHandler, DataPlaneResponse } from '../dataplane'
// 这两条路由的路径由**铸 `upload_uri` / `object_uri` 的那个模块**定义：客户端的 URL 与
// 服务端的路由表必须说的是同一个字符串，各写一份字面量只会有一半跟着改。
import { OBJECTS_PATH, UPLOAD_PATH } from '../rpc/attachments'
import { upgrade, type WebSocketConnection, type WebSocketHandlers } from '../stream/ws'

export const RPC_PATH = '/anp-im/rpc'
export const STREAM_PATH = '/anp-im/stream'
export const WELL_KNOWN_PATH = '/.well-known/anp-message-service.json'

/** 群 DID 文档路径的尾段。头一段（`…/g/`）由 {@link groupDidRoutePrefix} 推出来，因为它
 *  跟着 `serviceDid` 变；这一段是固定的。两段合起来正好是 `didToUrl` 对群 DID 的映射。 */
const GROUP_DID_SUFFIX = '/did.json'

/** 一个端点先当成 URL 解出来。解不出来就是一条不会自己好的失败——报清楚是哪一端的文档
 *  写坏了，而不是让 `new URL` 的 `Invalid URL` 混进重试日志。 */
function endpointUrl(raw: string): URL {
  try {
    return new URL(raw)
  } catch {
    throw new ConnectxError('message_send_failed', `${JSON.stringify(raw)} is not a usable serviceEndpoint`)
  }
}

/** 本服务入口的绝对地址。`serviceEndpoint`（well-known 里发布的那一条）与"这是不是我
 *  自己"必须是同一个字符串，所以两者都从这里取。 */
export function ingressUrl(config: Config): URL {
  return new URL(`${config.publicUrl}${RPC_PATH}`)
}

/**
 * P8 §3.3 那条唯一的"该不该出站"判断：目标公开的 `ANPMessageService` 是不是本服务。
 *
 * 只比 origin 与路径。要判"两个 DID 是不是同一个域"是个我们无从权威得知的属性，而这里
 * 问的是更小的一件事——解析出来的那个端点指向谁。放在这个模块，是因为 `RPC_PATH` 定义
 * 在这里：路由改了而这里没改，表现会是"本地的收件人被当成跨域送出去"。
 */
export function isOurOwnIngress(config: Config, endpoint: string): boolean {
  const theirs = endpointUrl(endpoint)
  const own = ingressUrl(config)
  return (
    theirs.origin === own.origin &&
    trimTrailingSlash(theirs.pathname) === trimTrailingSlash(own.pathname)
  )
}

function trimTrailingSlash(path: string): string {
  return path.replace(/\/+$/, '')
}

/** 群 DID 文档的路由前缀（B1b-A3）。
 *
 *  groups.md §2 的 `group_did = serviceDid + ":g:" + <id>` 决定了文档的 URL 就是
 *  `didToUrl(serviceDid + ":g:" + <id>)`——`did:web:host:g:XXXX` →
 *  `https://host/g/XXXX/did.json`。这里拿一个哨兵 id 去问**同一个** `didToUrl`，再把哨兵
 *  那一段切掉，于是"对端会 GET 的路径"与"我们挂的路由"不可能变成两条各写一份的规则。
 *
 *  `serviceDid` 自带路径段时（`did:web:host:svc:g:XXXX`）前缀是 `/svc`——这正是不能把
 *  `/g/` 当成绝对路径写死的原因。返回空串表示群文档就挂在根上。 */
export function groupDidRoutePrefix(config: Config): string {
  const probe = 'probe'
  return new URL(didToUrl(`${config.serviceDid}:g:${probe}`)).pathname.slice(0, -`/g/${probe}/did.json`.length)
}

/** `POST /anp-im/rpc`, the control plane. `body` is the request text, undecoded: the
 *  envelope layer needs the bytes it was given, and the `Content-Digest` check (C3)
 *  covers those bytes rather than a re-serialization of them. */
export interface RpcRequest {
  body: string
  headers: IncomingMessage['headers']
  url: URL
  /**
   * 这次调用是作为**哪一个 HTTP 方法**到达的。
   *
   * 只为外层签名而带（P8 §6.2.2 第 8 步的 `@method`）：那个签名覆盖的是 `@method` 与
   * `@target-uri`，两者都是 HTTP 请求的属性，而不是 JSON-RPC 的。所以这个字段缺席表示
   * "这次调用不是一次 HTTP 请求"——流式那条路上的帧就是这种（`stream/session.ts` 把升级
   * 请求的头借给了帧，但帧本身不是 HTTP 请求，对它跑外层认证等于拿升级时签的东西去证明
   * 另一件事）。缺席时外层认证整段跳过，业务层的 `origin_proof` 照常。
   */
  method?: string
}

export interface RpcResponse {
  /** 200 for every JSON-RPC exchange, success or failure (§2.1). The field is here
   *  because `handleRpc` is also where a future 413/415 refusal would be produced. */
  status: number
  body: string
  contentType?: string
  /**
   * 附加响应头。
   *
   * 存在的理由是外层认证那一条：ANP-02 §3.2.4.1 把 401 的挑战放在 `WWW-Authenticate`
   * 里，而那个判定要读过信封才做得了（八步的第一步是 caller anchor），所以它发生在
   * `handleRpc` 这一侧——响应头因此必须能穿过这道缝，而不是让 HTTP 层自己再判一次。
   */
  headers?: Record<string, string>
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
  /** The body of `/.well-known/anp-message-service.json` (C8). Absent means 501 for the same
   *  reason as `handleStream`: an unbuilt surface stays distinguishable from a missing one.
   *  It is data rather than a callback because the document is a pure function of the
   *  configuration and the method table — `main.ts` builds it once, at startup. */
  wellKnown?: string
  /** `PUT {upload_uri}` (P7 §11.1, C10). Absent means 501, same rule as above. */
  handleUpload?: DataPlaneHandler
  /** `GET {object_uri}` (P7 §11.2). */
  handleObject?: DataPlaneHandler
  /**
   * `GET …/g/<id>/did.json` (B1b-A3). Absent means 501, same rule as `wellKnown`.
   *
   * 传入的是**群 DID**（前缀由 {@link groupDidRoutePrefix} 从 `config.serviceDid` 推出来，
   *  路由把它拼回去），返回文档的 JSON 文本。返回 `undefined` 表示"这里没有你问的那个群"
   *  ——未知的 id 与 v11 之前建的、没有钥的群都走这条，路由答 404。**不是 500**：一个陌生人
   *  猜了一个 id 打过来，是"没有这个东西"，不是"我们坏了"（TODO3 A3）。
   */
  handleGroupDid?: (groupDid: string) => string | undefined
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
 * The byte path: unlike {@link send} this one can put a `Readable` on the wire, because an
 * attachment object is a few MiB and reading it into a string first is the thing the size
 * cap exists to avoid.
 *
 * Every non-2xx ends the connection, for the same reason {@link refuse} does: a refused
 * upload usually still has its request body in flight, and a pooled connection reused for
 * the next request would hit those leftover bytes.
 */
async function sendDataPlane(res: ServerResponse, answer: DataPlaneResponse): Promise<void> {
  const headers: Record<string, string | number> = { ...answer.headers }
  if (answer.contentType !== undefined) headers['content-type'] = answer.contentType
  if (answer.status >= 400) headers.connection = 'close'

  if (answer.stream !== undefined) {
    headers['content-length'] = answer.stream.length
    res.writeHead(answer.status, headers)
    await pipeline(answer.stream.read, res)
    return
  }
  const body = answer.body ?? ''
  headers['content-length'] = Buffer.byteLength(body)
  res.writeHead(answer.status, headers)
  res.end(body)
}

/** The resource id out of a route path, or `undefined` when it is not decodable. Node's URL
 *  parser leaves percent-escapes in `pathname`, so the segment still has to be decoded —
 *  and a malformed escape is a bad request rather than a crash. */
function resourceOf(pathname: string, prefix: string): string | undefined {
  return decodeSegment(pathname.slice(prefix.length + 1))
}

/** One path segment, decoded — or `undefined` when it is empty, contains a separator, or
 *  carries a malformed escape. Both route families that name a resource share it: a
 *  segment is either a usable id or it is not, and the answer must not depend on which
 *  route asked. */
function decodeSegment(raw: string): string | undefined {
  if (raw === '' || raw.includes('/')) return undefined
  try {
    return decodeURIComponent(raw)
  } catch {
    return undefined
  }
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
  /** `…/<serviceDid 自己的路径段>/g/`，群文档的 id 段紧跟在它后面（B1b-A3）。 */
  const groupDidPath = `${groupDidRoutePrefix(config)}/g/`

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
      const method = req.method
      if (method !== 'POST') {
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
      const answer = await options.handleRpc({ body, headers: req.headers, url, method })
      send(res, answer.status, answer.contentType ?? 'application/json', answer.body, answer.headers ?? {})
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
      const document = options.wellKnown
      if (document === undefined) {
        // Wiring, not routing, decides whether this is a 501 or a 200 — a service that has
        // not built the document is not a service that has no such route.
        refuse(res, 501, `${WELL_KNOWN_PATH} is not implemented yet`)
        return
      }
      send(res, 200, 'application/json', document)
      return
    }

    // ---- P4 group DID documents (B1b-A3) -------------------------------------
    // 群 DID 住在本服务自己的命名空间里，所以它的文档也由本服务发布（groups.md §2/§2.2）。
    // 前缀在 `createServer` 里从 `didToUrl` 推一次，之后按它认路径。
    if (url.pathname.startsWith(groupDidPath) && url.pathname.endsWith(GROUP_DID_SUFFIX)) {
      const groupId = decodeSegment(url.pathname.slice(groupDidPath.length, -GROUP_DID_SUFFIX.length))
      if (groupId !== undefined) {
        if (req.method !== 'GET') {
          refuse(res, 405, 'method not allowed', { allow: 'GET' })
          return
        }
        if (options.handleGroupDid === undefined) {
          refuse(res, 501, `${groupDidPath}<id>/did.json is not implemented yet`)
          return
        }
        // 未知的群 id（以及 v11 之前建的、没有钥的群）是 404：这里没有你问的东西，不是我们
        // 坏了。一个陌生人猜了一个 id 打过来不该看到 500（TODO3 A3）。
        const document = options.handleGroupDid(`${config.serviceDid}:g:${groupId}`)
        if (document === undefined) {
          refuse(res, 404, 'no such group')
          return
        }
        // `application/did+json`：与 awiki 那条路一致，也是 packages/e2e 的玩具主机在用的。
        send(res, 200, 'application/did+json', document)
        return
      }
    }

    // ---- P7 data plane (C10) -------------------------------------------------
    // Exact-prefix rather than exact-path routes: the last segment IS the credential (for
    // the upload) or the object's locator (for the download). Both routes are byte routes,
    // so neither goes through the JSON-RPC envelope or the `refuse` body cap.
    for (const [prefix, method, handler] of [
      [UPLOAD_PATH, 'PUT', options.handleUpload],
      [OBJECTS_PATH, 'GET', options.handleObject],
    ] as const) {
      if (!url.pathname.startsWith(`${prefix}/`)) continue
      if (req.method !== method) {
        refuse(res, 405, 'method not allowed', { allow: method })
        return
      }
      const resource = resourceOf(url.pathname, prefix)
      if (resource === undefined) {
        refuse(res, 400, 'malformed resource id')
        return
      }
      if (handler === undefined) {
        refuse(res, 501, `${prefix} is not implemented yet`)
        return
      }
      await sendDataPlane(res, await handler({ resource, headers: req.headers, body: req }))
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
