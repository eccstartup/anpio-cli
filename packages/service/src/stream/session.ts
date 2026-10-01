// C7 —— 一条订阅连接的生命周期（realtime.md §3–§5）。
//
// 这一层只做**流才有的事**：握手、注册、补齐到实时的切换、投递确认。其余每一帧都原样交给
// `handleRpc`——信封校验、方法表、认证、正文、幂等一行都没有第二份实现（§3 说这是本设计最
// 省事的一处，这个文件就是那句话的兑现）。所以这里的判断只有三类：
//
//   * 这一帧是不是那两个传输方法（`stream.auth` / `stream.ack`）；
//   * 这个连接走到哪一步了（还没握手 / 补齐中 / 实时）；
//   * 我们回给客户端的这一帧要不要动订阅。
//
// 帧必须**按到达顺序**处理。理由不是 JSON-RPC 的要求（`id` 自己就能对上），而是顺序本身
// 在这条路上有意义：`stream.auth` 注册订阅与 `sync.delta` 的响应之间夹着一次切换，乱序就
// 会切错。所以帧走一条 promise 链，串行。

import {
  DidKeyResolver,
  JSON_RPC_ERROR,
  rpcRejection,
  type AnpRequest,
  type KeyResolver,
  type LocateOptions,
} from '@agentx/core'
import type { IncomingMessage } from 'node:http'
import { EXTENSION_PROFILE } from '../rpc/inbox'
import { authenticate, callerAnchor } from '../rpc/auth'
import { checkMethod, lookupStreamMethod, type MethodSpec } from '../rpc/methods'
import { STREAM_ACK, STREAM_AUTH, STREAM_HELLO, STREAM_PROFILE, cursorOf, deviceIdOf, seqOf } from '../rpc/stream'
import { errorResponse, failureId, parseRequestText, successResponse } from '../rpc/envelope'
import type { RpcHandler, RpcResponse } from '../http/server'
import type { Storage } from '../storage/types'
import type { SubscriberRegistry, SubscriberTarget, Subscription } from './registry'
import { CLOSE_GOING_AWAY, CLOSE_INTERNAL_ERROR, CLOSE_NORMAL, CLOSE_TRY_AGAIN_LATER, type WebSocketConnection, type WebSocketHandlers } from './ws'

export interface StreamSessionDeps {
  /** What the service calls itself in `stream.hello` (realtime.md §4.2). */
  serverDid: string
  storage: Storage
  registry: SubscriberRegistry
  /** Everything that is not a transport method. `main.ts` fills it with `createDispatch`. */
  handleRpc: RpcHandler
  resolver?: KeyResolver
  resolverOptions?: LocateOptions
  now?: () => Date
  log?: (line: string) => void
}

/**
 * One session's protocol, in two halves because the transport needs them in that order:
 * hand {@link StreamSession.handlersFor} to `upgrade()` to get the connection, and the
 * session is already running when it returns.
 */
export interface StreamSession {
  handlersFor(connection: WebSocketConnection, request: IncomingMessage): WebSocketHandlers
  /**
   * End every open connection.
   *
   * The HTTP server cannot do this itself: an upgraded socket is detached from it, so
   * `server.close()` waits for connections it has no way to reach. Without this, a
   * shutdown with one listener attached never finishes.
   */
  closeAll(reason: string): void
  /** How many connections are open — for the shutdown line, and for tests. */
  size(): number
}

/** What `stream.hello` advertises (realtime.md §4.1: "客户端连上即知"). Both of this
 *  service's extension profiles, because the stream speaks both: the transport's own, and
 *  the read surface the backfill is made of. They are deliberately NOT in
 *  `anp.get_capabilities` (realtime.md §9) — that list is spec conformance, this one is
 *  what this endpoint can do. */
export const STREAM_PROFILES: readonly string[] = [STREAM_PROFILE, EXTENSION_PROFILE]

export function createStreamSession(deps: StreamSessionDeps): StreamSession {
  const resolver = deps.resolver ?? new DidKeyResolver()
  const resolverOptions = deps.resolverOptions
  const now = deps.now ?? ((): Date => new Date())
  const log = deps.log ?? ((line: string): void => void process.stderr.write(`${line}\n`))
  /** Open connections. Added when one is opened and removed when it closes, which the
   *  transport guarantees happens at most once per connection. */
  const open = new Set<WebSocketConnection>()

  return {
    handlersFor(connection, request): WebSocketHandlers {
      /** Where this connection is. `backfilling` is the window of §5.2: registered, held,
       *  waiting for the backfill to be answered. */
      let ownerDid = ''
      let deviceId = ''
      let subscription: Subscription | undefined
      let backfilling = false
      let tail: Promise<void> = Promise.resolve()

      const target: SubscriberTarget = {
        send: (frame) => connection.send(frame),
        // §5.3: a subscription that fell behind is ended, not skipped. 1013 tells the client
        // to come back, and coming back with a cursor is what recovers the messages.
        close: (reason) => connection.close(CLOSE_TRY_AGAIN_LATER, reason),
        bufferedAmount: () => connection.bufferedAmount,
      }

      /** Write one answer. An empty body is a Notification being answered with nothing
       *  (§5.6 L201), which the stream represents by sending no frame at all. */
      const emit = (answer: RpcResponse): void => {
        if (answer.body !== '') connection.send(answer.body)
      }

      /** The two transport methods, run through the same layers as everything else. */
      async function transportFrame(envelope: AnpRequest, spec: MethodSpec): Promise<void> {
        const refused = checkMethod(spec, envelope.params.meta)
        if (refused !== undefined) {
          emit(errorResponse(envelope.id, refused))
          return
        }
        const body = envelope.params.body
        const bodyRefusal = spec.validateBody?.(body, envelope.params.meta)
        if (bodyRefusal !== undefined) {
          emit(errorResponse(envelope.id, bodyRefusal))
          return
        }
        const outcome = await authenticate({
          envelope,
          expectedAnchor: callerAnchor(envelope.method, envelope.params),
          resolver,
          ...(resolverOptions !== undefined ? { resolverOptions } : {}),
          codes: spec.authCodes,
          now: Math.floor(now().getTime() / 1000),
        })
        if (!outcome.ok) {
          // §4.1: 握手失败即关连接. The response goes first — the client is told why and
          // then loses the socket, rather than having to guess from a bare close.
          log(`anp: ${spec.name} not authenticated (${outcome.reason})`)
          emit(errorResponse(envelope.id, outcome.error))
          connection.close(CLOSE_NORMAL, 'authentication failed')
          return
        }
        if (spec.name === STREAM_AUTH) ready(envelope)
        else ack(envelope)
      }

      /** §4 + §5.2: register the subscription at the head taken NOW, and only then answer.
       *  The other order would leave a window for a message to be neither held nor replayed. */
      function ready(envelope: AnpRequest): void {
        if (subscription !== undefined) {
          emit(
            errorResponse(
              envelope.id,
              rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, `${STREAM_AUTH} may only be sent once per connection`),
            ),
          )
          return
        }
        const body = envelope.params.body
        deviceId = deviceIdOf(body)
        ownerDid = envelope.params.meta.sender_did ?? ''
        const headSeq = deps.storage.headSeq(ownerDid)
        subscription = deps.registry.subscribe(target, ownerDid, deviceId, headSeq)
        backfilling = true
        // §5.4: the stored cursor is the default; `--since` overrides it for THIS backfill
        // only. Writing an override back would turn a debugging flag into a lost history.
        const cursorAccepted = cursorOf(body) ?? deps.storage.cursor(ownerDid, deviceId)
        emit(successResponse(envelope.id, { device_id: deviceId, cursor_accepted: cursorAccepted, head_seq: headSeq }))
      }

      /** §6: advance the delivery cursor. Not a read receipt for the sender — the spec
       *  defines none (P5 §10.7, P6, P8 §35). */
      function ack(envelope: AnpRequest): void {
        if (subscription === undefined) {
          // The device is only known from the handshake, so an ack without one has nothing
          // to advance (§5.4: the cursor is per `(owner_did, device_id)`).
          emit(
            errorResponse(
              envelope.id,
              rpcRejection(JSON_RPC_ERROR.INVALID_REQUEST, `${STREAM_ACK} requires ${STREAM_AUTH} first`),
            ),
          )
          return
        }
        if (envelope.params.meta.sender_did !== ownerDid) {
          // Signing as someone else would write a cursor row under an identity this
          // connection never proved — it is not this connection's queue to move.
          emit(
            errorResponse(
              envelope.id,
              rpcRejection(
                JSON_RPC_ERROR.INVALID_REQUEST,
                `${STREAM_ACK} must be signed by the identity this connection authenticated as`,
              ),
            ),
          )
          return
        }
        // Clamped to the head: `advanceCursor` never goes backwards, so one ack for a
        // sequence that does not exist yet would jump the cursor past real messages and the
        // next reconnect would silently skip them. Bounding it here is what keeps "the
        // cursor is never ahead of the queue" true.
        const seq = Math.min(seqOf(envelope.params.body), deps.storage.headSeq(ownerDid))
        deps.storage.advanceCursor(ownerDid, deviceId, seq)
        emit(successResponse(envelope.id, { cursor: deps.storage.cursor(ownerDid, deviceId) }))
      }

      /** §5.2's second half: the backfill answer went out, so the held frames may. */
      function backfillAnswered(answer: RpcResponse): void {
        if (!backfilling || subscription === undefined) return
        const resumeAfter = deltaResumeAfter(answer.body)
        // A paged delta is not the end of the backfill; a refused one never answered it.
        // Both leave the subscription held, which is the safe side: the bound in §5.3
        // eventually ends a client that stops halfway.
        if (resumeAfter === undefined) return
        backfilling = false
        subscription.goLive(resumeAfter)
      }

      async function handleFrame(text: string): Promise<void> {
        const parsed = parseRequestText(text)
        if (!parsed.ok) {
          emit(errorResponse(failureId(text, parsed.error), parsed.error))
          return
        }
        const envelope = parsed.value
        // A Notification from the client: nothing to answer (§5.3 L162) and no transport
        // method in this protocol is one.
        if (!('id' in envelope)) return

        const spec = lookupStreamMethod(envelope.method)
        if (spec !== undefined) {
          await transportFrame(envelope, spec)
          return
        }
        // Not ours, so it goes through the control plane's own path. The upgrade request's
        // headers are passed along, but no HTTP method is: a frame is not an HTTP request,
        // and the outer signature (C11) covers `@method` / `@target-uri`. Verifying one from
        // an upgrade that happened earlier would be proving a different thing with it, so
        // `method` stays absent and the outer layer stands down (§2.3). What authenticates
        // the frame is the business layer — `stream.auth` holds the mailbox and every call
        // still carries its own `origin_proof`.
        const answer = await deps.handleRpc({ body: text, headers: request.headers, url: frameUrl(request) })
        emit(answer)
        backfillAnswered(answer)
      }

      // `stream.hello` before anything else (§4.2): the client checks this before it signs
      // anything, which is the point — the upgrade was plaintext.
      open.add(connection)
      connection.send(
        JSON.stringify({
          jsonrpc: '2.0',
          method: STREAM_HELLO,
          params: {
            server_did: deps.serverDid,
            // Nothing else can be said here: the head is per mailbox and the mailbox is not
            // known until `stream.auth`. §5.5 的权威值随 `stream.ready` 一起给。
            head_seq: 0,
            profiles: STREAM_PROFILES,
          },
        }),
      )

      return {
        onMessage(text: string): void {
          tail = tail
            .then(() => handleFrame(text))
            .catch((err: unknown) => {
              // Every refusal inside `handleFrame` is answered in place, and `handleRpc`
              // catches its own. So reaching this line means this service has a bug, and the
              // connection's state is no longer known: end it rather than continue on it.
              log(
                `anp: stream frame failed internally: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
              )
              connection.close(CLOSE_INTERNAL_ERROR, 'internal error')
            })
        },
        onClose(): void {
          open.delete(connection)
          subscription?.detach()
        },
      }
    },

    closeAll(reason: string): void {
      for (const connection of [...open]) connection.close(CLOSE_GOING_AWAY, reason)
      open.clear()
    },

    size(): number {
      return open.size
    },
  }
}

/** The URL of the frame's connection, rebuilt the same way the HTTP layer builds it — a
 *  path on this server, so the base is only there to satisfy the parser. */
function frameUrl(request: IncomingMessage): URL {
  return new URL(request.url ?? '/', 'http://localhost')
}

/**
 * The sequence a `sync.delta` answer ended at, or `undefined` when it did not end one.
 *
 * Read out of the response rather than recomputed: the backfill's real end is whatever the
 * delta actually returned, and it can be past the head taken at registration (the window
 * `registry.ts` describes). A JSON-RPC error, a `has_more` page and a body that is not an
 * object all mean "not finished".
 */
function deltaResumeAfter(bodyText: string): number | undefined {
  if (bodyText === '') return undefined
  let parsed: unknown
  try {
    parsed = JSON.parse(bodyText)
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null || 'error' in parsed) return undefined
  const result = (parsed as { result?: unknown }).result
  if (typeof result !== 'object' || result === null) return undefined
  const row = result as Record<string, unknown>
  if (row.has_more === true) return undefined
  const next = row.next_since
  return typeof next === 'number' && Number.isInteger(next) ? next : undefined
}
