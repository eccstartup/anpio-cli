// `connectx agent use|show|list` — the current agent, and the one file it lives in.
//
// The feature exists so that a later command needs no `--agent`, so the case that
// matters most is `use` followed by a resolution that finds the selection. Everything
// runs against a store root of its own: with the default root, a selection already made
// on the machine running the tests would answer for it.

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runAgent } from './agent'
import { currentAgentFile, resolveAgentId, storeLocation } from '../identity/paths'
import { initIdentity } from '../identity/store'
import type { Values } from './auth'

const KEYS = [
  'CLAUDECODE',
  'CODEX_HOME',
  'CODEX_SANDBOX',
  'CONNECTX_AGENT',
  'CONNECTX_PROFILE',
  'CONNECTX_HOME',
] as const
let saved: Record<string, string | undefined>
let home = ''

beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]))
  // Cleared, not inherited: this suite itself runs inside an agent, whose markers would
  // otherwise decide the detection cases.
  for (const k of KEYS) delete process.env[k]
  home = mkdtempSync(join(tmpdir(), 'connectx-agent-unit-'))
  process.env.CONNECTX_HOME = home
})

afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
  rmSync(home, { recursive: true, force: true })
})

async function run(sub: string, id?: string, over: Record<string, unknown> = {}) {
  const out: string[] = []
  const err: string[] = []
  const log = vi.spyOn(console, 'log').mockImplementation((...a) => void out.push(a.join(' ')))
  const errSpy = vi.spyOn(console, 'error').mockImplementation((...a) => void err.push(a.join(' ')))
  try {
    await runAgent(over as unknown as Values, sub, id)
    return { out: out.join('\n'), err: err.join('\n') }
  } finally {
    log.mockRestore()
    errSpy.mockRestore()
  }
}

describe('agent use', () => {
  it('selects an agent the next invocation acts as, with no flag', async () => {
    const { out } = await run('use', 'alice')
    expect(out).toBe('current agent: alice')
    expect(readFileSync(currentAgentFile(), 'utf8').trim()).toBe('alice')
    expect(resolveAgentId()).toBe('alice')
    // The flag still wins: a script that names its agent is never redirected.
    expect(resolveAgentId('bob')).toBe('bob')
  })

  it('selects an id with nothing stored yet, and says so', async () => {
    const { err } = await run('use', 'alice')
    expect(err).toContain('no identity is stored for agent "alice"')
    expect(resolveAgentId()).toBe('alice')
  })

  it('says nothing when an identity is already stored for the id', async () => {
    await initIdentity({ location: storeLocation('alice', 'default'), curve: 'ed25519', password: '', force: false })
    const { err } = await run('use', 'alice')
    expect(err).toBe('')
  })

  it('refuses an id that cannot be a path segment, and writes nothing', async () => {
    await expect(run('use', '../evil')).rejects.toThrowError(/Invalid agent id/)
    expect(existsSync(currentAgentFile())).toBe(false)
  })

  it('refuses to select nothing', async () => {
    await expect(run('use', undefined)).rejects.toThrowError(/Missing required argument <id>/)
    await expect(run('use', '  ')).rejects.toThrowError(/Missing required argument <id>/)
  })

  it('reports the file it wrote under --json', async () => {
    const { out } = await run('use', 'alice', { json: true })
    expect(JSON.parse(out)).toEqual({ agent: 'alice', file: currentAgentFile() })
  })
})

describe('agent list', () => {
  const store = (agent: string) =>
    initIdentity({ location: storeLocation(agent, 'default'), curve: 'ed25519', password: '', force: false })

  it('marks the rows of the current agent and leaves the others unmarked', async () => {
    await store('alice')
    await store('claude-code')
    await run('use', 'alice')
    const { out } = await run('list')
    const lines = out.split('\n')
    expect(lines.find((l) => l.includes('alice/default'))).toMatch(/^current alice\/default {2}not registered {2}ed25519 {2}/)
    expect(lines.find((l) => l.includes('claude-code/default'))).toMatch(/^ {8}claude-code\/default/)
  })

  it('marks nothing when no agent was selected', async () => {
    await store('alice')
    expect((await run('list')).out).not.toContain('current ')
  })

  // A selection outlives the identity it named: it is the agent every later command acts
  // as, so hiding it would hide the reason those commands fail.
  it('lists a current agent that has nothing stored', async () => {
    await run('use', 'bob')
    expect((await run('list')).out).toContain('current bob  no identity stored')
  })

  it('says the store is empty, unless a current agent names one', async () => {
    expect((await run('list')).out).toBe('No agents are stored. Run: connectx did create')
    await run('use', 'bob')
    expect((await run('list')).out).toBe('current bob  no identity stored')
  })

  it('reports the current agent beside the identities as JSON', async () => {
    await store('alice')
    await run('use', 'alice')
    const listed = JSON.parse((await run('list', undefined, { json: true })).out)
    expect(listed.current).toBe('alice')
    expect(listed.identities.map((i: { agent: string }) => i.agent)).toEqual(['alice'])

    rmSync(currentAgentFile(), { force: true })
    expect(JSON.parse((await run('list', undefined, { json: true })).out).current).toBe(null)
  })
})

describe('agent show', () => {
  it('names the source that decided the agent', async () => {
    expect((await run('show')).out).toContain('nothing named one: the fallback')

    process.env.CLAUDECODE = '1'
    expect((await run('show')).out).toContain('detected from the environment')
    delete process.env.CLAUDECODE

    await run('use', 'alice')
    expect((await run('show')).out).toContain('current agent (')

    // A selection sits below the env var: one invocation can still name its own agent.
    process.env.CONNECTX_AGENT = 'bob'
    expect((await run('show')).out).toContain('CONNECTX_AGENT')
  })

  it('prints the agent and its source as JSON', async () => {
    await run('use', 'alice')
    expect(JSON.parse((await run('show', undefined, { json: true })).out)).toEqual({
      agent: 'alice',
      source: 'current',
      file: currentAgentFile(),
    })
  })

  it('reports the ambiguity detection would refuse on', async () => {
    process.env.CLAUDECODE = '1'
    process.env.CODEX_HOME = '/home/u/.codex'
    const err = await run('show').catch((thrown: { code?: string }) => thrown)
    expect((err as { code?: string }).code).toBe('agent_ambiguous')
  })
})

describe('the pointer as a file', () => {
  it('treats a half-written value as a broken selection, not as an agent id', async () => {
    writeFileSync(currentAgentFile(), '')
    expect(resolveAgentId()).toBe('default')
  })
})
