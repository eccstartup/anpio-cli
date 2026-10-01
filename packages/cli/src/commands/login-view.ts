// The login's two non-pixel renderers (Part W ③ and ⑤).
//
// W0's first principle is machine-first: an agent's component is stdout and an exit code,
// and a human-readable rendering is the optional second layer. So the same login state has
// two renderers here — a card drawn on a terminal, and one JSON object per line for
// everything that is not one — and both are driven by the SAME SDK `login()` the rest of
// this package calls. Nothing in this file decides anything about how a login works: it
// renders states it is handed. That is W0 principle 2 (one contract, many renderers), the
// same split as `<ConnectButton>` / `<AgentBridge>` on the page.
//
// The states are the ones a caller can actually observe (U1.5). No `challenge` state and
// no `onState` hook on the SDK to fake one: this CLI signs through one `login()` call, so
// a nonce the server challenged us for is not a moment it can stand outside of and
// announce. A stream that named states the caller cannot really be in would be worse than
// a coarser one, because a machine would act on it.

import { once } from 'node:events'
import pc from 'picocolors'
import type { LoginOutcome } from '@agentx/core'

/** Where the signing key is, in the card's own words. Never a key — only where it is.
 *  The second half of W0 principle 3: the thing that must not leave is named, and then
 *  shown not to. */
export interface KeyLocation {
  /** `store` — this CLI's identity store (an agent names an identity, never a key);
   *  `material` — `--key` / `$ANP_PRIVATE_KEY`; `wallet` — an EIP-1193 wallet the agent
   *  only ever asks to sign. */
  source: 'store' | 'material' | 'wallet'
  /** The curve, when the CLI handled the key material. A wallet holds its own. */
  curve?: string
}

/** What the session cache did — reported apart from the outcome because it is a different
 *  fact: the login succeeded either way (ADR-0001 §2.5). */
export type SessionWrite = 'saved' | 'skipped' | 'failed'

/** One line of the login's machine contract. */
export type LoginEvent =
  | { state: 'connecting'; target: string }
  | { state: 'signing'; did: string; keyid: string; key: KeyLocation }
  | { state: 'connected'; session: SessionWrite; outcome: LoginOutcome }
  | { state: 'error'; code: string; message: string; status?: number }

/** One event, one line, on stdout. Not `console.log`: this is a wire, and a wire does not
 *  pretty-print. `outcome` is carried as the SDK built it rather than flattened into CLI
 *  field names — a machine reading this should be reading the SDK's own type. */
export function writeEvent(event: LoginEvent): void {
  process.stdout.write(`${JSON.stringify(event)}\n`)
}

/** `ed25519 · local store · never sent` — where the key is, for the operator to check
 *  before approving. */
export function describeKey(key: KeyLocation): string {
  if (key.source === 'wallet') return 'EIP-1193 wallet · never leaves the wallet'
  const where = key.source === 'store' ? 'local store' : 'local key material'
  return `${key.curve ?? 'key'} · ${where} · never sent`
}

/** What the card says about the token cache, before the login happens. `ttl` is the bound
 *  the caller asked for, not a promise: the server's own `exp` wins whenever it is shorter
 *  (see the session store). */
export function describeSession(save: boolean, ttlSeconds: number): string {
  return save ? `session.json, ttl ${formatTtl(ttlSeconds)} max` : 'not saved (--no-save-session)'
}

export interface LoginCard {
  /** The host being signed in to, as an operator would say it. */
  host: string
  /** The endpoint the signature goes to. */
  target: string
  /** `<agent>/<profile>` — which identity is acting. */
  agent: string
  /** The identity the site will see: the DID. */
  did: string
  key: KeyLocation
  /** Already worded by `describeSession`. */
  session: string
}

const LABEL_WIDTH = 9

/** The card: Part U's `<ConnectButton>` drawn in ANSI. Lines wrap rather than truncate —
 *  the DID is the one thing on it that must stay unambiguous, and a shortened fingerprint
 *  is how two agents get confused for each other. */
export function renderCard(card: LoginCard, width = terminalWidth()): string {
  const inner = Math.max(40, width - 4)
  const rows: Array<[string, string]> = [
    ['agent', card.agent],
    ['DID', card.did],
    ['key', describeKey(card.key)],
    ['endpoint', card.target],
    ['session', card.session],
  ]

  const lines = [top(` connectx `, inner), row(`Sign in to  ${card.host}`, inner)]
  for (const [name, value] of rows) {
    lines.push(
      ...wrap(`  ${name.padEnd(LABEL_WIDTH)}${value}`, inner, `  ${' '.repeat(LABEL_WIDTH)}`).map(
        (line) => row(line, inner),
      ),
    )
  }
  lines.push(bottom(` Enter to approve · n to cancel `, inner))
  return lines.join('\n')
}

/** The card's other half — the agent's "Sign in" button (W③: the button is ⏎). One
 *  keypress, no Enter after it: ⏎ approves, `n` cancels, Ctrl-C cancels. The caller only
 *  reaches here on a terminal at both ends, because a prompt nobody can see is worse than
 *  no prompt. */
export async function askApproval(): Promise<boolean> {
  const stdin = process.stdin
  stdin.setRawMode(true)
  stdin.resume()
  try {
    for (;;) {
      const chunk = (await once(stdin, 'data')) as unknown as Buffer
      const ch = chunk.toString('utf8')
      if (ch === '\r' || ch === '\n') return true
      if (ch === 'n' || ch === 'N') return false
      // Raw mode means the terminal hands us Ctrl-C as a byte instead of raising SIGINT,
      // so cancelling has to be handled here or the process would ignore it.
      if (ch === '\u0003' || ch === '\u0004') {
        process.stdout.write('\n')
        return false
      }
    }
  } finally {
    stdin.setRawMode(false)
    stdin.pause()
  }
}

/** A human summary after the card was approved, so the terminal path does not have to
 *  print the machine's JSON at a person. */
export interface LoginSummary {
  host: string
  /** What the site saw: the DID. */
  did: string
  /** The access token, when the site issued one. */
  token?: string
  /** The `token_type` the site named, verbatim. */
  tokenType?: string
  session: SessionWrite
  /** Where the token went, when it went somewhere. */
  sessionFile?: string
}

export function renderSummary(summary: LoginSummary): string {
  const lines = [
    `${pc.green('✓')} signed in to ${summary.host}`,
    `  did    ${summary.did}`,
  ]
  if (summary.token) lines.push(`  token  ${summary.token}`)
  if (summary.session === 'saved' && summary.sessionFile) lines.push(`  saved  ${summary.sessionFile}`)
  if (summary.session === 'failed') lines.push(`  ${pc.yellow('session not saved')} — the token above is the only copy`)
  if (summary.token && summary.tokenType && summary.tokenType.toLowerCase() !== 'bearer') {
    lines.push(`  ${pc.yellow('note')}   the server named token_type "${summary.tokenType}" — present this token`)
    lines.push('         the way that profile requires, not as a Bearer token (ANP-02 §3.2.3)')
  }
  return lines.join('\n')
}

function top(title: string, inner: number): string {
  const head = title.length > inner ? '' : title
  return `┌${head}${'─'.repeat(Math.max(0, inner + 2 - head.length))}┐`
}

function bottom(title: string, inner: number): string {
  const head = title.length > inner ? '' : title
  return `└${head}${'─'.repeat(Math.max(0, inner + 2 - head.length))}┘`
}

function row(text: string, inner: number): string {
  return `│ ${text.padEnd(inner)} │`
}

/** Hard-wrap at `inner`, continuing under `indent`. Wrapping mid-fingerprint is fine;
 *  hiding it is not. */
function wrap(text: string, inner: number, indent: string): string[] {
  if (text.length <= inner) return [text]
  const out: string[] = []
  let rest = text
  let prefix = ''
  while (rest.length > 0) {
    const room = inner - prefix.length
    out.push(prefix + rest.slice(0, room))
    rest = rest.slice(room)
    prefix = indent
  }
  return out
}

function formatTtl(seconds: number): string {
  if (seconds % 86400 === 0) return `${seconds / 86400}d`
  if (seconds % 3600 === 0) return `${seconds / 3600}h`
  if (seconds % 60 === 0) return `${seconds / 60}m`
  return `${seconds}s`
}

/** A terminal is 80 columns unless it says otherwise — and a width under 40 is not a card,
 *  so that is treated as "no idea". */
function terminalWidth(): number {
  const cols = process.stdout.columns
  return cols !== undefined && cols > 40 ? cols : 80
}
