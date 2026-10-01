// Session store — the short-lived credential cache (ADR-0001 §2.5). One
// `session.json` per (agent, profile), encrypted at rest (see secret.ts) and
// keyed by target host, so Codex and Claude Code never overwrite each other's
// token. A session is NOT an identity: the next `login` with the same key is
// still "you" whatever this file holds.
//
// Reads are forgiving by design: a corrupt / undecryptable / expired cache is
// treated as absent so a stale file can never break a login.
//
// Writes take a cross-process lock file and, when the existing file is present but
// unreadable, quarantine it instead of overwriting it — see `withSessionLock` and
// `readOrQuarantine` (audit 2026-09-11 §3).

import { closeSync, existsSync, openSync, readFileSync, renameSync, statSync, unlinkSync } from 'node:fs'
import { ConnectxError } from '@agentx/core'
import { openSecret, sealSecret } from './secret'
import { ensureDir, warnIfPermissive, writeFileAtomic } from './store'
import type { StoreLocation } from './paths'

const FILE_MODE = 0o600
// Cross-process write lock. `saveSessionToken` is
// read-decrypt-modify-encrypt-rename, so two processes (e.g. Codex and Claude Code
// on one agent) racing the same session.json would otherwise lose one host's entry.
const LOCK_RETRY_MS = 25
const LOCK_TIMEOUT_MS = 5_000
// A lock older than this is assumed to be a crashed process's leftover and reclaimed.
const LOCK_STALE_MS = 30_000

/** Server expiry is authoritative; this fallback only applies to a token that is
 *  not a decodable JWT (matches the reference server's 7-day TTL). */
export const DEFAULT_SESSION_TTL_SECONDS = 7 * 24 * 60 * 60

export interface SessionEntry {
  token: string
  did: string
  /**
   * The stable subject the token was issued to (0.3.0+). Optional because a
   * session file written by 0.2.x has none, and this file is deliberately
   * forgiving — a stale cache must never break a login.
   *
   * Recorded INSIDE the entry rather than used as the key: a token is issued by a
   * host and bound to the host + DID pair, so the host remains the correct key
   * (see `SessionFile.sessions`). Recording the subject lets a caller notice that
   * a cached token predates a key update even though the identity is the same.
   */
  subject?: string
  /**
   * The `token_type` the server named for this token, verbatim (ANP-02 §3.2.3) —
   * carried through from `LoginOutcome.tokenType` so a cached token does not lose the
   * one field that says how it must be presented.
   *
   * Optional for the same reason `subject` is: entries written before this existed
   * have none, and that is indistinguishable from a server that named no type — in
   * both cases the spec's default (`Bearer`) applies, so the absence is not a loss.
   */
  tokenType?: string
  issuedAt: string
  expiresAt: string
}

export interface SessionFile {
  version: 1
  /** Keyed by target host, e.g. `localhost:3000`. The host, not the DID or the
   *  subject, is the key: a token is issued per host and is meaningless
   *  elsewhere, whereas both the DID (changes) and the subject (shared across
   *  hosts) would collide entries. */
  sessions: Record<string, SessionEntry>
}

/** Parse `--session-ttl`: `<n>` (seconds) or `<n>s|m|h|d`. Empty → default. */
export function parseTtlSeconds(spec: string | undefined): number {
  if (spec === undefined || spec.trim() === '') return DEFAULT_SESSION_TTL_SECONDS
  const m = /^(\d+)([smhd])?$/.exec(spec.trim())
  if (!m) {
    throw new ConnectxError('invalid_argument', `Invalid --session-ttl "${spec}" (use e.g. 7d, 24h, 30m, 3600s)`)
  }
  const value = Number(m[1])
  const unit = m[2] ?? 's'
  const mult = unit === 's' ? 1 : unit === 'm' ? 60 : unit === 'h' ? 3600 : 86400
  const seconds = value * mult
  if (seconds <= 0) throw new ConnectxError('invalid_argument', '--session-ttl must be positive')
  return seconds
}

/** Read `exp` / `iat` from a JWT payload. Never throws: the token is opaque to us
 *  and only used for a local cache expiry — a non-JWT token just yields `{}`. */
export function decodeJwtExpiry(token: string): { expiresAt?: string; issuedAt?: string } {
  const parts = token.split('.')
  if (parts.length !== 3) return {}
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown>
    const out: { expiresAt?: string; issuedAt?: string } = {}
    if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
      out.expiresAt = new Date(payload.exp * 1000).toISOString()
    }
    if (typeof payload.iat === 'number' && Number.isFinite(payload.iat)) {
      out.issuedAt = new Date(payload.iat * 1000).toISOString()
    }
    return out
  } catch {
    return {}
  }
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms))

/** A lock file left by a process that crashed before releasing it. */
function isStaleLock(lockPath: string): boolean {
  try {
    return Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS
  } catch {
    return false // it disappeared between the EEXIST and here — a waiter won the race
  }
}

/** Run `fn` while holding an exclusive, cross-process lock on the session file, so
 *  a read-modify-write cannot interleave with another process's. Bounded wait, and
 *  a stale lock (crashed holder) is reclaimed rather than blocking forever. */
async function withSessionLock<T>(location: StoreLocation, fn: () => Promise<T>): Promise<T> {
  ensureDir(location.dir)
  const lockPath = `${location.sessionFile}.lock`
  const deadline = Date.now() + LOCK_TIMEOUT_MS
  let fd: number | undefined
  for (;;) {
    try {
      fd = openSync(lockPath, 'wx', FILE_MODE)
      break
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err
      if (isStaleLock(lockPath)) {
        try {
          unlinkSync(lockPath)
          continue // reclaimed — try to take it immediately
        } catch {
          // Another waiter removed it first; fall through to the bounded wait.
        }
      }
      if (Date.now() >= deadline) {
        throw new ConnectxError(
          'session_busy',
          `Another connectx process is writing ${location.sessionFile}; try again`,
        )
      }
      await delay(LOCK_RETRY_MS)
    }
  }
  try {
    return await fn()
  } finally {
    try {
      closeSync(fd)
    } catch {
      // already closed
    }
    try {
      unlinkSync(lockPath)
    } catch {
      // already released (e.g. reclaimed as stale while we held it)
    }
  }
}

/** Read + decrypt `session.json` strictly: `null` only when the file is ABSENT. A
 *  file that exists but cannot be decrypted or parsed THROWS, so a caller about to
 *  rewrite it can quarantine instead of silently clobbering another host's entry. */
async function readSessionStrict(location: StoreLocation, password: string): Promise<SessionFile | null> {
  if (!existsSync(location.sessionFile)) return null
  warnIfPermissive(location.sessionFile, 'stored session')
  const obj = JSON.parse(await openSecret(readFileSync(location.sessionFile, 'utf8'), password)) as SessionFile
  if (obj?.version !== 1 || typeof obj.sessions !== 'object' || obj.sessions === null) {
    throw new ConnectxError('session_invalid', `Unsupported session schema in ${location.sessionFile}`)
  }
  return obj
}

/** Read `session.json` for a writer: an unreadable file is moved aside (quarantined)
 *  to `session.json.corrupt-<timestamp>` and `null` returned, so the rewrite starts
 *  clean WITHOUT destroying whatever the previous file held. */
async function readOrQuarantine(location: StoreLocation, password: string): Promise<SessionFile | null> {
  try {
    return await readSessionStrict(location, password)
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err)
    const quarantined = `${location.sessionFile}.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}`
    try {
      renameSync(location.sessionFile, quarantined)
      console.error(
        `connectx: warning: could not read ${location.sessionFile} (${reason}); moved it to ${quarantined} and started a fresh session file`,
      )
    } catch {
      console.error(`connectx: warning: could not read ${location.sessionFile} (${reason}); replacing it`)
    }
    return null
  }
}

/** Read + decrypt `session.json`, or `null` if absent. A corrupt / undecryptable
 *  file is warned about and treated as absent — a broken cache must not break a
 *  login. */
export async function readSession(location: StoreLocation, password: string): Promise<SessionFile | null> {
  try {
    return await readSessionStrict(location, password)
  } catch (err) {
    console.error(
      `connectx: warning: could not read ${location.sessionFile} (${err instanceof Error ? err.message : String(err)}); treating as no session`,
    )
    return null
  }
}

/** The valid (unexpired) session for `host`, or `null`. */
export async function getValidSession(
  location: StoreLocation,
  password: string,
  host: string,
): Promise<SessionEntry | null> {
  const file = await readSession(location, password)
  const entry = file?.sessions[host]
  if (!entry) return null
  const expires = Date.parse(entry.expiresAt)
  if (!Number.isFinite(expires) || expires <= Date.now()) return null
  return entry
}

export interface SaveSessionOptions {
  location: StoreLocation
  password: string
  /** Target host — the session key. */
  host: string
  token: string
  did: string
  /** Stable subject of the identity the token was issued to (recorded in the
   *  entry; see `SessionEntry.subject`). */
  subject?: string
  /** The `token_type` the server named for the token, if any — recorded verbatim
   *  (see `SessionEntry.tokenType`). */
  tokenType?: string
  /** Fallback lifetime for a token with no decodable `exp`. */
  ttlSeconds: number
}

/** Persist a token under `host`, read-merge-writing so logging into host B does
 *  not drop host A. Expiry never exceeds the server's `exp` when that is
 *  decodable. */
export async function saveSessionToken(opts: SaveSessionOptions): Promise<void> {
  const { location, password, host, token, did, subject, tokenType, ttlSeconds } = opts
  const jwt = decodeJwtExpiry(token)
  const nowMs = Date.now()
  const fallbackMs = nowMs + ttlSeconds * 1000
  const jwtExpMs = jwt.expiresAt ? Date.parse(jwt.expiresAt) : Number.NaN
  const expiresAt = new Date(Number.isFinite(jwtExpMs) ? Math.min(jwtExpMs, fallbackMs) : fallbackMs).toISOString()

  // Read-merge-write entirely under one lock, so a concurrent login into another
  // host is either already visible here or lands after us — never lost.
  await withSessionLock(location, async () => {
    const file = (await readOrQuarantine(location, password)) ?? { version: 1, sessions: {} }
    const entry: SessionEntry = {
      token,
      did,
      issuedAt: jwt.issuedAt ?? new Date(nowMs).toISOString(),
      expiresAt,
    }
    if (subject != null) entry.subject = subject
    if (tokenType != null) entry.tokenType = tokenType
    file.sessions[host] = entry
    writeFileAtomic(location.sessionFile, await sealSecret(JSON.stringify(file), password), FILE_MODE)
  })
}
