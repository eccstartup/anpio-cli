// `msg listen`'s two renderers, the same split `login-view.ts` makes: this file renders
// states it is handed and decides nothing about how receiving works.
//
// The split matters more here than it does for a login. `msg listen` is the CLI's only
// long-running process, so its stdout is a stream a script may be reading for hours; the
// shape of one line is therefore a contract rather than a convenience. Nothing below
// fetches, connects, or retries — it is given an event and writes it.
//
// docs/design/realtime.md §7.1 fixes the machine contract: ONE JSON object per line, and
// `state` values shared with the login (`connecting` / `connected` / `error`, plus
// `reconnecting`). The human contract is the scrolling IM rendering below.

import pc from 'picocolors'

/** One message as it arrives. The fields are the ones a renderer needs and no more:
 *  re-stating the whole envelope here would make this a second implementation of it. */
export interface ListenMessage {
  type: 'message'
  /** The delivery cursor this message came with. Monotonic per device, which is what
   *  makes it the right key to deduplicate on across a reconnect (realtime.md §5.2). */
  seq: number
  message_id: string
  /** The sender. A DID, because that is what the envelope carries: there is no address
   *  book, and a display name invented here would be one more thing to disagree with the
   *  peer's own view of who sent it. */
  from: string
  /** `agent` for a direct message, `group` for one addressed to a group. */
  target_kind: 'agent' | 'group'
  /** Set when `target_kind` is `group`. */
  group_did?: string
  content_type: string
  /** Set when the body was text. A P5/P6 payload stays opaque — the CLI holds no key and
   *  never will (message-service.md §11), so the line says what it is instead of nothing. */
  text?: string
  /** When the service accepted it, as the service reported it. */
  accepted_at?: string
}

/** One line of the stream. The three non-message states are the login's vocabulary plus
 *  `reconnecting`, so a consumer that already reads `anp login --json` reads this too. */
export type ListenEvent =
  | { state: 'connecting'; service: string }
  | { state: 'connected'; device: string; head: number }
  | { state: 'reconnecting'; attempt: number; after_ms: number }
  | { state: 'error'; code: string; message: string }
  | ListenMessage

/** True when the event is a message rather than a state change. */
export function isMessage(event: ListenEvent): event is ListenMessage {
  return 'type' in event && event.type === 'message'
}

/** One event, one line, on stdout. Not `console.log`: this is a wire, and a wire does not
 *  pretty-print. */
export function writeListenEvent(event: ListenEvent): void {
  process.stdout.write(`${JSON.stringify(event)}\n`)
}

/** What a person sees, one line per state change. Kept apart from the message rendering
 *  because it is not a message: a reconnect notice between two messages reads as one if
 *  it is drawn like one. */
export function renderListenState(event: Exclude<ListenEvent, ListenMessage>): string {
  switch (event.state) {
    case 'connecting':
      return pc.dim(`connecting to ${event.service}`)
    case 'connected':
      return pc.dim(`connected as ${event.device}, at cursor ${event.head}`)
    case 'reconnecting':
      return pc.yellow(`reconnecting: attempt ${event.attempt} in ${formatDelay(event.after_ms)}`)
    case 'error':
      return pc.red(`error: ${event.code}: ${event.message}`)
  }
}

/** The IM rendering, in the shape realtime.md §7.1 sketches: a header line naming who
 *  sent it and when, then the body hanging under it.
 *
 *  A group message is headed by the GROUP, with the sender prefixed to the body. The
 *  other way round would make two groups look like two private conversations with the
 *  same person. */
export function renderListenMessage(event: ListenMessage): string {
  const where = event.target_kind === 'group' && event.group_did !== undefined ? event.group_did : event.from
  const when = event.accepted_at === undefined ? '' : `  ${formatTime(event.accepted_at)}`
  const head = `${pc.cyan('●')} ${where}${event.target_kind === 'group' ? pc.dim(' (group)') : ''}${when}`
  const body = bodyLines(event)
  const first = event.target_kind === 'group' ? `${event.from}: ${body[0]}` : body[0]
  return [head, `  ${first}`, ...body.slice(1).map((line) => `  ${line}`)].join('\n')
}

/** The body, as lines. Text arrives as it was sent, including its newlines; anything else
 *  is described rather than dumped — a reader needs to know a message arrived and what it
 *  is, and a base64 blob tells them neither. */
function bodyLines(event: ListenMessage): string[] {
  if (event.text !== undefined) return event.text.split('\n')
  return [pc.dim(`(${event.content_type} body, not rendered)`)]
}

/** `<YYYY-MM-DD HH:MM>` in local time. Hand-formatted rather than through `Intl`: the
 *  output of this command is a contract, and a locale that shifts with the environment
 *  would make the same stream render differently on two machines. */
export function formatTime(iso: string): string {
  const at = new Date(iso)
  if (Number.isNaN(at.getTime())) return iso
  const pad = (n: number): string => String(n).padStart(2, '0')
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${pad(at.getHours())}:${pad(at.getMinutes())}`
}

/** A backoff, said the way a person waiting reads it. */
export function formatDelay(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${Math.round(ms / 100) / 10}s`
}

/** Where the two renderers are chosen. A pipe is a machine even when nobody asked for
 *  `--json`: `connectx msg listen | tee log` is a thing people do, and the NDJSON form is
 *  the one a file should hold.
 *
 *  On a terminal, messages go to stdout and state changes to stderr, so
 *  `connectx msg listen > messages.txt` leaves the file holding messages. In the machine
 *  form both go to stdout, because there the state changes are part of the stream a
 *  consumer is reading. */
export interface ListenView {
  event(event: ListenEvent): void
  /** Called when the stream ends, so a renderer can close a line it left open. */
  done?(): void
}

export function machineView(): ListenView {
  return { event: writeListenEvent }
}

export function humanView(): ListenView {
  return {
    event(event) {
      if (isMessage(event)) {
        process.stdout.write(`${renderListenMessage(event)}\n`)
        return
      }
      process.stderr.write(`${renderListenState(event)}\n`)
    },
  }
}

/** `--json`, or a stdout nobody is looking at. */
export function viewFor(json: boolean): ListenView {
  return json || process.stdout.isTTY !== true ? machineView() : humanView()
}
