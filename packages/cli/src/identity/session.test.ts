// Session store behaviour: the encrypted / host-keyed token cache, TTL handling,
// and merge-on-write. Runs against a temp `$CONNECTX_HOME`.

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, statSync, readFileSync, readdirSync, writeFileSync, utimesSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { storeLocation } from './paths'
import {
  saveSessionToken,
  getValidSession,
  readSession,
  decodeJwtExpiry,
  parseTtlSeconds,
  DEFAULT_SESSION_TTL_SECONDS,
} from './session'

const PASSWORD = 'session-test-password'
const HOST_A = 'localhost:3000'
const HOST_B = 'example.com'

let home: string
const prevHome = process.env.CONNECTX_HOME

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'connectx-session-'))
  process.env.CONNECTX_HOME = home
})

afterAll(() => {
  if (prevHome === undefined) delete process.env.CONNECTX_HOME
  else process.env.CONNECTX_HOME = prevHome
  rmSync(home, { recursive: true, force: true })
})

const loc = (agent: string, profile = 'default') => storeLocation(agent, profile)

function jwt(payload: Record<string, unknown>): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.sig`
}

const nowSec = () => Math.floor(Date.now() / 1000)

describe('saveSessionToken / getValidSession', () => {
  it('seals the token to a 0600 encrypted file and reads it back', async () => {
    const location = loc('claude-code')
    const token = jwt({ exp: nowSec() + 3600, iat: nowSec() })
    await saveSessionToken({ location, password: PASSWORD, host: HOST_A, token, did: 'did:wba:x', ttlSeconds: 3600 })

    expect(statSync(location.dir).mode & 0o777).toBe(0o700)
    expect(statSync(location.sessionFile).mode & 0o777).toBe(0o600)
    // The token must not appear in cleartext on disk.
    expect(readFileSync(location.sessionFile, 'utf8')).not.toContain(token)

    const entry = await getValidSession(location, PASSWORD, HOST_A)
    expect(entry).toMatchObject({ token, did: 'did:wba:x' })
    expect(Date.parse(entry!.expiresAt)).toBeGreaterThan(Date.now())
  })

  it('keeps the token_type across the cache, and does not invent one', async () => {
    const location = loc('token-type-agent')
    await saveSessionToken({
      location,
      password: PASSWORD,
      host: HOST_A,
      token: jwt({ exp: nowSec() + 3600 }),
      did: 'did:wba:x',
      tokenType: 'DPoP',
      ttlSeconds: 3600,
    })
    await saveSessionToken({
      location,
      password: PASSWORD,
      host: HOST_B,
      token: jwt({ exp: nowSec() + 3600 }),
      did: 'did:wba:y',
      ttlSeconds: 3600,
    })

    // The cache is the only thing standing between a login and a later request, so a
    // type the server stated must survive it — otherwise a caller reads back a token
    // that looks like a plain Bearer one.
    expect((await getValidSession(location, PASSWORD, HOST_A))?.tokenType).toBe('DPoP')
    // A server that named no type stays indistinguishable from an old entry, which is
    // correct: in both cases the spec's Bearer default applies.
    expect((await getValidSession(location, PASSWORD, HOST_B))?.tokenType).toBeUndefined()
  })

  it('merges on write — logging into a second host keeps the first', async () => {
    const location = loc('merge-agent')
    await saveSessionToken({ location, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'd', ttlSeconds: 60 })
    await saveSessionToken({ location, password: PASSWORD, host: HOST_B, token: jwt({}), did: 'd', ttlSeconds: 60 })
    const file = await readSession(location, PASSWORD)
    expect(Object.keys(file!.sessions).sort()).toEqual([HOST_A, HOST_B].sort())
  })

  it('ignores an expired session', async () => {
    const location = loc('expired-agent')
    const token = jwt({ exp: nowSec() - 10 })
    await saveSessionToken({ location, password: PASSWORD, host: HOST_A, token, did: 'd', ttlSeconds: 3600 })
    expect(await getValidSession(location, PASSWORD, HOST_A)).toBeNull()
  })

  it('isolates two (agent, profile) stores', async () => {
    const a = loc('iso-a')
    const b = loc('iso-b')
    await saveSessionToken({ location: a, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'a', ttlSeconds: 60 })
    await saveSessionToken({ location: b, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'b', ttlSeconds: 60 })
    expect((await getValidSession(a, PASSWORD, HOST_A))?.did).toBe('a')
    expect((await getValidSession(b, PASSWORD, HOST_A))?.did).toBe('b')
  })

  it('treats a corrupt file or wrong password as absent (never throws)', async () => {
    const corrupt = loc('corrupt-agent')
    await saveSessionToken({ location: corrupt, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'd', ttlSeconds: 60 })
    writeFileSync(corrupt.sessionFile, 'not a valid envelope')
    expect(await readSession(corrupt, PASSWORD)).toBeNull()

    const wrongPw = loc('wrong-pw-agent')
    await saveSessionToken({ location: wrongPw, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'd', ttlSeconds: 60 })
    expect(await readSession(wrongPw, 'nope')).toBeNull()
  })
})

describe('concurrent writes and corruption quarantine (audit 2026-09-11 §3)', () => {
  it('does not lose a host when two logins write the same file concurrently', async () => {
    const location = loc('concurrent-agent')
    await Promise.all([
      saveSessionToken({ location, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'a', ttlSeconds: 60 }),
      saveSessionToken({ location, password: PASSWORD, host: HOST_B, token: jwt({}), did: 'b', ttlSeconds: 60 }),
    ])
    const file = await readSession(location, PASSWORD)
    expect(Object.keys(file!.sessions).sort()).toEqual([HOST_A, HOST_B].sort())
    expect((await getValidSession(location, PASSWORD, HOST_A))?.did).toBe('a')
    expect((await getValidSession(location, PASSWORD, HOST_B))?.did).toBe('b')
  })

  it('releases the lock after a write and reclaims a stale one', async () => {
    const location = loc('lock-agent')
    // A lock left behind by a crashed process must not block a login forever.
    mkdirSync(location.dir, { recursive: true })
    const lockPath = `${location.sessionFile}.lock`
    writeFileSync(lockPath, '')
    const stale = (Date.now() - 60_000) / 1000
    utimesSync(lockPath, stale, stale)

    await saveSessionToken({ location, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'a', ttlSeconds: 60 })
    expect(existsSync(lockPath)).toBe(false)
    expect((await getValidSession(location, PASSWORD, HOST_A))?.did).toBe('a')
  })

  it('quarantines an unreadable file instead of silently clobbering it', async () => {
    const location = loc('quarantine-agent')
    await saveSessionToken({ location, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'a', ttlSeconds: 60 })
    writeFileSync(location.sessionFile, 'not a valid envelope')

    await saveSessionToken({ location, password: PASSWORD, host: HOST_B, token: jwt({}), did: 'b', ttlSeconds: 60 })

    // The unreadable bytes are preserved under an explicit, recoverable name…
    const backups = readdirSync(location.dir).filter((f) => f.startsWith('session.json.corrupt-'))
    expect(backups).toHaveLength(1)
    expect(readFileSync(join(location.dir, backups[0]), 'utf8')).toBe('not a valid envelope')

    // …and the fresh file holds the new login cleanly.
    const file = await readSession(location, PASSWORD)
    expect(Object.keys(file!.sessions)).toEqual([HOST_B])
  })

  it('quarantines a file written under a different password', async () => {
    const location = loc('quarantine-wrong-pw')
    await saveSessionToken({ location, password: PASSWORD, host: HOST_A, token: jwt({}), did: 'a', ttlSeconds: 60 })

    // A login that presents the wrong password must not overwrite the encrypted file.
    await saveSessionToken({ location, password: 'different', host: HOST_B, token: jwt({}), did: 'b', ttlSeconds: 60 })

    expect(readdirSync(location.dir).some((f) => f.startsWith('session.json.corrupt-'))).toBe(true)
    expect((await getValidSession(location, 'different', HOST_B))?.did).toBe('b')
  })
})

describe('decodeJwtExpiry', () => {
  it('reads exp / iat from a JWT payload', () => {
    const exp = nowSec() + 3600
    const iat = nowSec()
    expect(decodeJwtExpiry(jwt({ exp, iat }))).toEqual({
      expiresAt: new Date(exp * 1000).toISOString(),
      issuedAt: new Date(iat * 1000).toISOString(),
    })
  })

  it('never throws on a non-JWT or malformed token', () => {
    expect(decodeJwtExpiry('opaque-token')).toEqual({})
    expect(decodeJwtExpiry('two.segments')).toEqual({})
    expect(decodeJwtExpiry(jwt({ exp: 'soon' }))).toEqual({})
    expect(decodeJwtExpiry('a.!!!not-base64!!!.c')).toEqual({})
  })
})

describe('parseTtlSeconds', () => {
  it('parses units and defaults', () => {
    expect(parseTtlSeconds(undefined)).toBe(DEFAULT_SESSION_TTL_SECONDS)
    expect(parseTtlSeconds('30m')).toBe(1800)
    expect(parseTtlSeconds('24h')).toBe(86400)
    expect(parseTtlSeconds('7d')).toBe(604800)
    expect(parseTtlSeconds('90')).toBe(90)
  })

  it('rejects garbage', () => {
    expect(() => parseTtlSeconds('soon')).toThrowError()
    expect(() => parseTtlSeconds('0d')).toThrowError()
  })
})
