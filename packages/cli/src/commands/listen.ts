// `msg listen` — the state machine behind the CLI's only long-running process.
//
// The contract is docs/design/realtime.md §7, and the shape of the code follows one
// decision from it: the transport is INJECTED. Nothing below builds a WebSocket; it is
// handed something that opens one and reports frames. That is not testability for its own
// sake — a CLI cannot connect to a server that does not exist yet (`AgentXAgent` is C1–C7
// in TODO1), and a state machine that could only be exercised by the one thing it cannot
// have would ship unexercised. What is injected is only the socket; the handshake, the
// cursor arithmetic, the backoff and the decoding are all real code under test.
//
// Rendering lives in `listen-view.ts`. This file decides; that one draws.

import { randomUUID } from 'node:crypto'
import { buildMessageRequest, buildOriginProofAuth, anpCodeOf, ConnectxError } from '@agentx/core'
import type { AnpErrorResponse, AnpMeta, AnpResponse } from '@agentx/core'
import { cliError, type Values } from './auth'
import { openChannel, type Channel } from './channel'
import { viewFor, type ListenMessage, type ListenView } from './listen-view'

/** The stream's own Profile (realtime.md §9): the transport handshake is not a normative
 *  operation, so it names an extension Profile the way the read surface does. */
export const STREAM_PROFILE = 'x_agentx.stream.v1'

const STREAM_AUTH = 'stream.auth'
const STREAM_HELLO = 'stream.hello'
const SYNC_DELTA = 'sync.delta'

/** realtime.md §3: the notifications that carry a delivered message. The other two
 *  (`group.state_changed` / `group.e2ee.notice`) are pushed over the same socket but are
 *  not queue entries, so they are not rendered and — this is the part that matters — they
 *  do not advance the cursor (§5.5). */
const INCOMING_METHODS = ['direct.incoming', 'group.incoming']

/** JSON-RPC "no such method" / P1 §10.3 error 1001, as in `msg.ts`. */
const METHOD_NOT_FOUND = -32601
const UNSUPPORTED_PROFILE = 'anp.unsupported_profile'

/** How many missed messages `sync.delta` asks for at a time. */
const DELTA_PAGE = 100

/** realtime.md §7.2: exponential backoff, bounded. The base is 2s so attempt 2 lands on
 *  the 4s the design document's own example shows. */
const BACKOFF_BASE_MS = 2000
const BACKOFF_MAX_MS = 30_000
/** ±20%. A fixed schedule makes every client of a restarted service reconnect together. */
const BACKOFF_JITTER = 0.2

// ---- the transport -----------------------------------------------------------

/** One open stream. `send` takes a whole envelope; `close` ends it. */
export interface StreamConnection {
  send(frame: unknown): void
  close(): void
}

/** What is injected: opening a connection. `onFrame` is handed the parsed JSON of one
 *  frame; `onClose` fires once when the socket ends, for any reason. */
export type StreamConnect = (
  url: string,
  handlers: { onFrame: (frame: unknown) => void; onClose: (reason?: string) => void },
) => Promise<StreamConnection>

/** Node 24 has a global `WebSocket`, so the real transport needs no dependency. It is
 *  reached structurally rather than through `lib.dom`, which this package does not load. */
interface WebSocketLike {
  send(data: string): void
  close(): void
  addEventListener(type: string, listener: (event: unknown) => void): void
}

export const webSocketConnect: StreamConnect = async (url, handlers) => {
  const Ctor = (globalThis as { WebSocket?: new (url: string) => WebSocketLike }).WebSocket
  if (Ctor === undefined) {
    throw new ConnectxError(
      'connector_unavailable',
      'this runtime has no WebSocket; `msg listen` needs Node 24 or newer',
    )
  }
  const socket = new Ctor(url)
  await new Promise<void>((resolve, reject) => {
    socket.addEventListener('open', () => {
      resolve()
    })
    socket.addEventListener('error', () => {
      reject(new ConnectxError('message_send_failed', `could not open ${url}`))
    })
    socket.addEventListener('close', () => {
      // An error arriving before `open` already rejected; this covers the other order.
      handlers.onClose()
    })
  })
  socket.addEventListener('message', (event) => {
    const data = (event as { data?: unknown }).data
    if (typeof data !== 'string') return
    let parsed: unknown
    try {
      parsed = JSON.parse(data)
    } catch {
      // A frame that is not JSON is not a frame (realtime.md §3). Dropping it keeps one
      // bad frame from ending a stream that is otherwise delivering.
      return
    }
    handlers.onFrame(parsed)
  })
  return {
    send(frame) {
      socket.send(JSON.stringify(frame))
    },
    close() {
      socket.close()
    },
  }
}

// ---- the stream endpoint -----------------------------------------------------

/** realtime.md §3: the stream is the control plane's endpoint with its last path segment
 *  replaced by `stream` — `https://host/anp-im/rpc` → `wss://host/anp-im/stream`.
 *
 *  Derived rather than configured, because a second flag naming the same host is one more
 *  way to point a signed connection at the wrong place. The assumption is stated on the
 *  command's help page, since a service that mounts its stream elsewhere cannot be reached
 *  by this command. */
export function streamUrl(endpoint: string): string {
  let parsed: URL
  try {
    parsed = new URL(endpoint)
  } catch {
    throw new ConnectxError('message_service_not_found', `the service endpoint ${JSON.stringify(endpoint)} is not a URL`)
  }
  const scheme = parsed.protocol === 'https:' ? 'wss:' : parsed.protocol === 'http:' ? 'ws:' : undefined
  if (scheme === undefined) {
    throw new ConnectxError(
      'message_service_not_found',
      `the service endpoint ${JSON.stringify(endpoint)} is not an http(s) URL, so no stream address can be derived from it`,
    )
  }
  const segments = parsed.pathname.split('/').filter((segment) => segment !== '')
  segments.pop()
  segments.push('stream')
  return `${scheme}//${parsed.host}/${segments.join('/')}`
}

// ---- the frame queue ---------------------------------------------------------

type Arrival = { kind: 'frame'; frame: unknown } | { kind: 'closed'; reason?: string }

/** The reply to one of our Requests, once it is recognised as one. */
type Reply = { kind: 'frame'; frame: AnpResponse } | { kind: 'closed'; reason?: string }

/** Frames as they arrive, for a consumer that reads them one at a time. The socket
 *  delivers asynchronously and the state machine reads synchronously, so something has to
 *  hold the difference; this is that and nothing more. */
class Arrivals {
  private readonly queue: unknown[] = []
  private waiter: (() => void) | undefined
  private closed = false
  private reason: string | undefined

  push(frame: unknown): void {
    this.queue.push(frame)
    this.wake()
  }

  /** Put a frame back at the front. A Notification that arrives while a Response is
   *  awaited was not consumed by that wait, and dropping it would lose a message. */
  unshift(frame: unknown): void {
    this.queue.unshift(frame)
    this.wake()
  }

  close(reason?: string): void {
    if (this.closed) return
    this.closed = true
    this.reason = reason
    this.wake()
  }

  async next(): Promise<Arrival> {
    for (;;) {
      if (this.queue.length > 0) return { kind: 'frame', frame: this.queue.shift() }
      if (this.closed) return { kind: 'closed', reason: this.reason }
      await new Promise<void>((resolve) => {
        this.waiter = resolve
      })
    }
  }

  private wake(): void {
    const waiter = this.waiter
    this.waiter = undefined
    waiter?.()
  }
}

// ---- reading frames ----------------------------------------------------------

type Row = Record<string, unknown>

function asRow(value: unknown): Row | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Row) : undefined
}

function stringAt(row: Row | undefined, key: string): string | undefined {
  const value = row?.[key]
  return typeof value === 'string' && value !== '' ? value : undefined
}

function isErrorResponse(response: AnpResponse): response is AnpErrorResponse {
  return 'error' in response
}

/** A server-initiated frame. Only Notifications are read this way: a Response carries an
 *  `id` and belongs to the request that is waiting for it. */
function notificationOf(frame: unknown): { method: string; params: Row } | undefined {
  const row = asRow(frame)
  if (row === undefined || row.id !== undefined) return undefined
  const method = stringAt(row, 'method')
  const params = asRow(row.params)
  if (method === undefined || params === undefined) return undefined
  return { method, params }
}

/** A delivered message, or `undefined` for a frame that is not one.
 *
 *  The decoding is [message-service.md](../docs/design/message-service.md) §8.2 read
 *  backwards: the payload a service pushes is the original message's `meta` and `body`,
 *  unchanged, with `origin_proof` copied rather than re-signed. Nothing here verifies that
 *  proof — a CLI holds no key of the sender's, and the service is the party that checked
 *  it on the way in; what this does is take the service at the field names it promised. */
export function decodeMessage(frame: unknown, seq: number): ListenMessage | undefined {
  const notification = notificationOf(frame)
  if (notification === undefined || !INCOMING_METHODS.includes(notification.method)) return undefined

  const meta = asRow(notification.params.meta)
  const body = asRow(notification.params.body)
  const target = asRow(meta?.target)
  const kind = stringAt(target, 'kind') === 'group' ? 'group' : 'agent'
  const groupDid = kind === 'group' ? stringAt(target, 'did') : undefined

  return {
    type: 'message',
    seq,
    message_id: stringAt(meta, 'message_id') ?? stringAt(meta, 'operation_id') ?? `seq-${seq}`,
    from: stringAt(meta, 'sender_did') ?? '(unknown sender)',
    target_kind: kind,
    ...(groupDid !== undefined ? { group_did: groupDid } : {}),
    content_type: stringAt(meta, 'content_type') ?? 'application/octet-stream',
    ...bodyText(notification.params, body),
    ...(stringAt(meta, 'created_at') !== undefined ? { accepted_at: stringAt(meta, 'created_at') } : {}),
  }
}

/** P3 §6.2: exactly one of `text` / `payload` / `payload_b64u` is present. Text is passed
 *  through; a JSON payload is shown as JSON; an encrypted or binary one is left opaque
 *  (message-service.md §11 — the CLI holds no key and never will), which leaves `text`
 *  unset so the renderer says what the body is instead of printing a base64 blob. */
function bodyText(params: Row, body: Row | undefined): { text?: string } {
  const source = body ?? asRow(params.body)
  if (source === undefined) return {}
  if (typeof source.text === 'string') return { text: source.text }
  if (source.payload !== undefined) return { text: JSON.stringify(source.payload, null, 2) }
  return {}
}

// ---- backoff -----------------------------------------------------------------

/** realtime.md §7.2: exponential with jitter, bounded. `random` is a parameter so a test
 *  can pin the schedule instead of asserting against a moving target. */
export function backoffMs(attempt: number, random: number): number {
  const growth = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** Math.max(0, attempt - 1))
  const swing = growth * BACKOFF_JITTER * (random * 2 - 1)
  return Math.max(BACKOFF_BASE_MS, Math.round(growth + swing))
}

// ---- the session -------------------------------------------------------------

interface ListenOptions {
  device: string
  since?: number
  ack: boolean
  once: boolean
}

type Outcome =
  | { kind: 'ended' } // `--once` finished the backfill, or the caller interrupted us
  | { kind: 'dropped'; reason?: string }
  | { kind: 'fatal'; error: ConnectxError }

/** An outcome, or a successful reply. The three failure shapes above are what every step
 *  of a session can end in; `frame` is what continuing looks like. */
type Step = Outcome | { kind: 'frame'; frame: Row }

export interface ListenDeps {
  connect?: StreamConnect
  openChannel?: (v: Values) => Promise<Channel>
  view?: ListenView
  /** Jitter source, `[0, 1)`. Injected so a test's reconnect schedule is deterministic. */
  random?: () => number
  sleep?: (ms: number, signal: AbortSignal) => Promise<void>
  /** An interrupt the caller already holds, on top of the SIGINT / SIGTERM this command
   *  installs itself. It is also the only way to end a stream in a test: the real exit is
   *  a signal, and a suite that raised one would be raising it at the test runner. */
  signal?: AbortSignal
}

export async function runListen(v: Values, deps: ListenDeps = {}): Promise<void> {
  const connect = deps.connect ?? webSocketConnect
  const view = deps.view ?? viewFor(v.json === true)
  const random = deps.random ?? Math.random
  const sleep = deps.sleep ?? sleepUntil

  // `--since` is checked before the keystore is opened, the same way `msg send` checks its
  // body first: a typo in an argument should not cost a password prompt and a DID document
  // fetch (and over a network, a discovery round trip) before it is reported.
  const since = sinceOf(v)

  const channel = await (deps.openChannel ?? openChannel)(v)
  const url = streamUrl(channel.target.endpoint)
  const options: ListenOptions = {
    device: deviceFor(v, channel),
    ...(since !== undefined ? { since } : {}),
    ack: v.ack === true,
    once: v.once === true,
  }

  const abort = new AbortController()
  const interrupt = (): void => {
    abort.abort()
  }
  process.once('SIGINT', interrupt)
  process.once('SIGTERM', interrupt)
  const outward = deps.signal
  outward?.addEventListener('abort', interrupt)

  try {
    // realtime.md §7.2: a drop reconnects, an interrupted run exits 0, and a refusal that
    // will not change on retry exits 1. Nothing here resets the attempt counter — a
    // service that accepts a connection and immediately drops it is exactly the case the
    // backoff exists for, and one that stays up long enough to matter will have its own
    // drops spread far apart anyway.
    let attempt = 0
    for (;;) {
      if (attempt === 0) view.event({ state: 'connecting', service: url })
      const outcome = await session({ connect, url, options, view, signal: abort.signal, channel })
      if (outcome.kind === 'fatal') throw outcome.error
      if (outcome.kind === 'ended') return
      if (abort.signal.aborted) return
      attempt += 1
      const delay = backoffMs(attempt, random())
      view.event({ state: 'reconnecting', attempt, after_ms: delay })
      await sleep(delay, abort.signal)
      if (abort.signal.aborted) return
    }
  } finally {
    process.off('SIGINT', interrupt)
    process.off('SIGTERM', interrupt)
    outward?.removeEventListener('abort', interrupt)
  }
}

interface SessionContext {
  connect: StreamConnect
  url: string
  options: ListenOptions
  view: ListenView
  signal: AbortSignal
  channel: Channel
}

/** One connection, from upgrade to close. Everything that ends a stream ends it here:
 *  a refusal, an interrupt, `--once` finishing, or the socket going away. */
async function session(context: SessionContext): Promise<Outcome> {
  const arrivals = new Arrivals()
  const onAbort = (): void => {
    arrivals.close('interrupted')
  }
  context.signal.addEventListener('abort', onAbort)

  let connection: StreamConnection | undefined
  try {
    connection = await context.connect(context.url, {
      onFrame: (frame) => {
        arrivals.push(frame)
      },
      onClose: (reason) => {
        arrivals.close(reason)
      },
    })
    // The interrupt may have arrived while the socket was opening; the listener above
    // only fires on a NEW abort, so this is the one case it cannot have caught.
    if (context.signal.aborted) return { kind: 'ended' }

    // realtime.md §4.2: the server says who it is before anything is signed, and the
    // stream is a plaintext upgrade until then — so this is the first man-in-the-middle
    // check. A document that names no cross-domain identity has nothing to compare, and
    // that absence is the document's, not a verdict this command can improve on.
    const hello = await expectNotification(arrivals, STREAM_HELLO)
    if (hello.kind !== 'frame') return dropped(hello, 'the stream closed before it introduced itself')
    const serverDid = stringAt(hello.frame, 'server_did')
    if (context.channel.target.serviceDid !== undefined && serverDid !== context.channel.target.serviceDid) {
      return {
        kind: 'fatal',
        error: new ConnectxError(
          'message_invalid',
          `${context.url} introduced itself as ${serverDid ?? '(nothing)'}, but the DID document names ${context.channel.target.serviceDid} (realtime.md §4.2)`,
        ),
      }
    }

    const ready = await authenticate(connection, arrivals, context)
    if (ready.kind !== 'frame') return ready
    const headSeq = numberAt(ready.frame, 'head_seq') ?? 0
    const cursorAccepted = numberAt(ready.frame, 'cursor_accepted') ?? context.options.since ?? 0
    context.view.event({ state: 'connected', device: context.options.device, head: headSeq })

    const backfill = await delta(connection, arrivals, context, cursorAccepted)
    if (backfill.kind !== 'frame') return backfill
    if (context.options.once) return { kind: 'ended' }

    // `await`, not a bare return: the `finally` below closes the socket, and a bare return
    // would run it while the live loop is still reading from that socket.
    return await live(connection, arrivals, context, headSeq)
  } catch (error) {
    // A transport that throws while opening is a dropped connection, not a verdict: the
    // backoff above is the answer to it.
    if (error instanceof ConnectxError && error.code === 'unsupported_extension') {
      return { kind: 'fatal', error }
    }
    return { kind: 'dropped', ...(error instanceof Error ? { reason: error.message } : {}) }
  } finally {
    context.signal.removeEventListener('abort', onAbort)
    connection?.close()
  }
}

/** `--since` is a debugging override for the service-side cursor (§5.4), so a value that
 *  is not a sequence number is a mistake worth refusing before any connection is made. */
function sinceOf(v: Values): number | undefined {
  const raw = v.since as string | undefined
  if (raw === undefined) return undefined
  const parsed = Number(raw)
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw cliError('invalid_argument', `--since must be a non-negative integer (got ${JSON.stringify(raw)})`)
  }
  return parsed
}

/** realtime.md §5.4: the cursor is per `(owner_did, device_id)`, and the device defaults
 *  to the local `agent/profile` — the same two names `connectx` already stores everything
 *  else under, so "the same machine, a different profile" is two devices, as it should be. */
function deviceFor(v: Values, channel: Channel): string {
  const named = v.device as string | undefined
  if (named !== undefined) {
    if (named.trim() === '') throw cliError('invalid_argument', '--device must not be empty')
    return named
  }
  return `${channel.sender.agent}/${channel.sender.profile}`
}

/** The handshake (realtime.md §4): one authenticated Request, whose result is the ready
 *  payload. Signed over `{method, meta, body}` exactly as every other call is — the
 *  handshake is where the connection learns who is on it, so it is the last place to
 *  accept something unsigned. */
async function authenticate(connection: StreamConnection, arrivals: Arrivals, context: SessionContext): Promise<Step> {
  const body: Row = { device_id: context.options.device }
  if (context.options.since !== undefined) body.cursor = context.options.since
  const ready = await request(connection, arrivals, context, STREAM_AUTH, body)
  return ready.kind === 'frame' ? { kind: 'frame', frame: ready.frame } : ready
}

/** The backfill (realtime.md §5.2): everything the device missed, from the accepted cursor
 *  up to the head the server took when it registered this connection. The server holds
 *  live frames until this exchange finishes, so there is no gap for one to fall into. */
async function delta(connection: StreamConnection, arrivals: Arrivals, context: SessionContext, since: number): Promise<Step> {
  let cursor = since
  for (;;) {
    const page = await request(connection, arrivals, context, SYNC_DELTA, { since: cursor, limit: DELTA_PAGE })
    if (page.kind !== 'frame') return page
    const entries = Array.isArray(page.frame.messages) ? page.frame.messages : []
    for (const entry of entries) {
      // message-service.md §9.3: each entry IS the notification the stream would have
      // pushed, with the delivery number the stream would have given it. One decoder
      // therefore serves both halves of the connection.
      const row = asRow(entry)
      if (row === undefined) continue
      const seq = numberAt(row, 'seq') ?? cursor
      const decoded = decodeMessage({ jsonrpc: '2.0', method: row.method, params: row.params }, seq)
      if (decoded !== undefined) render(context, decoded)
    }
    if (page.frame.has_more !== true) return { kind: 'frame', frame: page.frame }
    const next = numberAt(page.frame, 'next_since')
    // A page that does not move the cursor would repeat forever, and an empty page that
    // claims more would too, which is what the second half guards.
    if (next === undefined || next <= cursor) return { kind: 'frame', frame: page.frame }
    cursor = next
  }
}

/** After the backfill, the cursor is the head the server took at registration, and every
 *  frame from here on is one message further (realtime.md §5.5). Non-message notifications
 *  do not advance it — they are not queue entries. */
async function live(connection: StreamConnection, arrivals: Arrivals, context: SessionContext, headSeq: number): Promise<Outcome> {
  let cursor = headSeq
  for (;;) {
    const arrival = await arrivals.next()
    if (arrival.kind === 'closed') return { kind: 'dropped', ...(arrival.reason !== undefined ? { reason: arrival.reason } : {}) }
    const notification = notificationOf(arrival.frame)
    if (notification === undefined) continue // a Response nobody is waiting for
    if (!INCOMING_METHODS.includes(notification.method)) continue
    cursor += 1
    const message = decodeMessage(arrival.frame, cursor)
    if (message === undefined) continue
    render(context, message)
    if (context.options.ack) {
      // realtime.md §6: `--ack` advances the read state, which is what lets the service
      // move this device's cursor. It is opt-in because the failure it prevents (a replay)
      // is survivable and the one it causes (a message nobody saw, gone) is not.
      const acked = await request(connection, arrivals, context, 'inbox.mark_read', { message_ids: [message.message_id] })
      if (acked.kind !== 'frame') return acked
    }
  }
}

function render(context: SessionContext, message: ListenMessage): void {
  context.view.event(message)
}

// ---- small readers -----------------------------------------------------------

function numberAt(row: Row, key: string): number | undefined {
  const value = row[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/** Read until the next Notification. A Response here belongs to a request that is no
 *  longer waiting, and is skipped. */
async function expectNotification(
  arrivals: Arrivals,
  method: string,
): Promise<{ kind: 'frame'; frame: Row } | { kind: 'closed'; reason?: string }> {
  for (;;) {
    const arrival = await arrivals.next()
    if (arrival.kind === 'closed') return arrival
    const notification = notificationOf(arrival.frame)
    if (notification !== undefined && notification.method === method) {
      return { kind: 'frame', frame: notification.params }
    }
  }
}

/** Read until the Response to `id`. A Notification that arrives first is not consumed by
 *  this wait, so it is held and put back once the response is in hand — a message that
 *  arrived while a `sync.delta` page was in flight is still a message. */
async function readResponse(arrivals: Arrivals, id: string): Promise<Reply> {
  const held: unknown[] = []
  try {
    for (;;) {
      const arrival = await arrivals.next()
      if (arrival.kind === 'closed') return arrival
      const row = asRow(arrival.frame)
      if (row !== undefined && row.id === id) return { kind: 'frame', frame: arrival.frame as AnpResponse }
      held.push(arrival.frame)
    }
  } finally {
    for (const frame of held.reverse()) arrivals.unshift(frame)
  }
}

/** One extension call over the stream. The refusal rules are the read surface's
 *  (message-service.md §9): a peer that does not have this method has ANSWERED, and the
 *  caller gets to say so rather than reporting a generic failure. */
async function request(
  connection: StreamConnection,
  arrivals: Arrivals,
  context: SessionContext,
  method: string,
  body: Row,
): Promise<Step> {
  const meta: AnpMeta = {
    profile: STREAM_PROFILE,
    security_profile: 'transport-protected',
    sender_did: context.channel.sender.did,
    // P1 附录 A.4 L1068: a method carrying an `origin_proof` MUST have `meta.target`, and
    // the same appendix leaves an endpoint-local method's target modelling to its Profile
    // (realtime.md §9). The queue being subscribed to belongs to the identity in use, so
    // the request is addressed to it.
    target: { kind: 'agent', did: context.channel.sender.did },
    operation_id: randomUUID(),
    created_at: new Date().toISOString(),
  }
  const auth = await buildOriginProofAuth({ method, meta, body, signer: context.channel.sender.signer })
  const id = randomUUID()
  connection.send(buildMessageRequest({ id, method, meta, auth, body }))

  const reply = await readResponse(arrivals, id)
  if (reply.kind !== 'frame') return dropped(reply, `the stream closed during ${method}`)
  if (!isErrorResponse(reply.frame)) return { kind: 'frame', frame: asRow(reply.frame.result) ?? {} }

  const anpCode = anpCodeOf(reply.frame)
  const named = anpCode ?? `JSON-RPC error ${reply.frame.error.code}`
  // realtime.md §7.2: a refusal is not retried. Reconnecting with the same key gets the
  // same answer, and a loop of them would look like a working listener.
  if (reply.frame.error.code === METHOD_NOT_FOUND || anpCode === UNSUPPORTED_PROFILE) {
    return {
      kind: 'fatal',
      error: new ConnectxError(
        'unsupported_extension',
        `${context.channel.sender.did} does not implement ${method} (${named}): the stream is an implementation ` +
          'extension, not defined by the ANP message specification',
        { ...(anpCode !== undefined ? { serverCode: anpCode } : {}), cause: reply.frame.error },
      ),
    }
  }
  return {
    kind: 'fatal',
    error: new ConnectxError(
      'message_send_failed',
      `${context.channel.sender.did} rejected ${method}: ${named}: ${reply.frame.error.message}`,
      { ...(anpCode !== undefined ? { serverCode: anpCode } : {}), cause: reply.frame.error },
    ),
  }
}

// ---- the wait ----------------------------------------------------------------

/** A sleep that a Ctrl-C ends immediately, so the backoff never delays an exit. */
function sleepUntil(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    if (signal.aborted) {
      resolve()
      return
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', stop)
      resolve()
    }, ms)
    const stop = (): void => {
      clearTimeout(timer)
      resolve()
    }
    signal.addEventListener('abort', stop, { once: true })
  })
}

function dropped(arrival: { reason?: string }, fallback: string): Outcome {
  return { kind: 'dropped', reason: arrival.reason ?? fallback }
}
