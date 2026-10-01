// Agent / profile resolution precedence and the path-safety guard.
//
// The one file these cases touch is the current-agent pointer, so every one of them runs
// against a store root of its own: with the default root, an agent selected on the
// machine running the tests would decide the answers below.

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { currentAgentFile, resolveAgentId, resolveProfileName, storeLocation, storeRoot } from './paths'

const KEYS = ['CLAUDECODE', 'CODEX_HOME', 'CODEX_SANDBOX', 'CONNECTX_AGENT', 'CONNECTX_PROFILE', 'CONNECTX_HOME'] as const
let saved: Record<string, string | undefined>
let home = ''

beforeEach(() => {
  saved = Object.fromEntries(KEYS.map((k) => [k, process.env[k]]))
  for (const k of KEYS) delete process.env[k]
  home = mkdtempSync(join(tmpdir(), 'connectx-paths-'))
  process.env.CONNECTX_HOME = home
})

afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
  rmSync(home, { recursive: true, force: true })
})

describe('resolveAgentId', () => {
  it('flag beats env beats detection beats default', () => {
    process.env.CONNECTX_AGENT = 'from-env'
    process.env.CLAUDECODE = '1'
    expect(resolveAgentId('from-flag')).toBe('from-flag')
    expect(resolveAgentId()).toBe('from-env')
  })

  it('detects Claude Code from $CLAUDECODE', () => {
    process.env.CLAUDECODE = '1'
    expect(resolveAgentId()).toBe('claude-code')
  })

  it('detects Codex from its markers', () => {
    process.env.CODEX_HOME = '/home/u/.codex'
    expect(resolveAgentId()).toBe('codex')
  })

  it('treats multiple markers of the SAME agent as unambiguous', () => {
    process.env.CODEX_HOME = '/home/u/.codex'
    process.env.CODEX_SANDBOX = '1'
    expect(resolveAgentId()).toBe('codex')
  })

  it('refuses to guess when the environment matches two agents', () => {
    // e.g. Codex launched from inside a Claude Code shell: CLAUDECODE is inherited.
    process.env.CLAUDECODE = '1'
    process.env.CODEX_HOME = '/home/u/.codex'
    try {
      resolveAgentId()
      throw new Error('expected resolveAgentId to throw')
    } catch (err) {
      expect((err as { code?: string }).code).toBe('agent_ambiguous')
      expect((err as Error).message).toMatch(/--agent/)
    }
  })

  it('an explicit $CONNECTX_AGENT resolves the ambiguity', () => {
    process.env.CLAUDECODE = '1'
    process.env.CODEX_HOME = '/home/u/.codex'
    process.env.CONNECTX_AGENT = 'codex'
    expect(resolveAgentId()).toBe('codex')
  })

  it('an explicit --agent resolves the ambiguity', () => {
    process.env.CLAUDECODE = '1'
    process.env.CODEX_HOME = '/home/u/.codex'
    expect(resolveAgentId('claude-code')).toBe('claude-code')
  })

  it('falls back to "default"', () => {
    expect(resolveAgentId()).toBe('default')
  })

  it('rejects path-escaping ids', () => {
    expect(() => resolveAgentId('../evil')).toThrowError()
    expect(() => resolveAgentId('a/b')).toThrowError()
  })

  it('the current agent decides when the flag and the env var are silent', () => {
    writeFileSync(currentAgentFile(), 'alice\n')
    expect(resolveAgentId()).toBe('alice')
  })

  it('the current agent beats detection, and settles its ambiguity', () => {
    process.env.CLAUDECODE = '1'
    expect(resolveAgentId()).toBe('claude-code')
    process.env.CODEX_HOME = '/home/u/.codex'
    expect(() => resolveAgentId()).toThrowError(/Ambiguous agent/)
    // A selection is a statement of who is acting, so it answers where a guess refuses.
    writeFileSync(currentAgentFile(), 'alice\n')
    expect(resolveAgentId()).toBe('alice')
  })

  it('the flag and the env var beat the current agent', () => {
    writeFileSync(currentAgentFile(), 'alice\n')
    process.env.CONNECTX_AGENT = 'bob'
    expect(resolveAgentId()).toBe('bob')
    expect(resolveAgentId('carol')).toBe('carol')
  })

  it('an empty current-agent file is no selection', () => {
    writeFileSync(currentAgentFile(), '\n')
    expect(resolveAgentId()).toBe('default')
  })

  it('refuses a current-agent file that is not an agent id, naming that file', () => {
    writeFileSync(currentAgentFile(), '../evil\n')
    expect(() => resolveAgentId()).toThrowError(/current-agent/)
    expect(() => resolveAgentId()).toThrowError(/agent use/)
    // The flag is answered before that file is ever read, so a corrupt pointer cannot
    // take down an invocation that named its own agent.
    expect(resolveAgentId('alice')).toBe('alice')
  })
})

describe('resolveProfileName', () => {
  it('flag > env > default', () => {
    process.env.CONNECTX_PROFILE = 'from-env'
    expect(resolveProfileName('from-flag')).toBe('from-flag')
    expect(resolveProfileName()).toBe('from-env')
  })

  it('defaults to "default"', () => {
    expect(resolveProfileName()).toBe('default')
  })

  it('rejects traversal', () => {
    expect(() => resolveProfileName('..')).toThrowError()
  })
})

describe('storeLocation', () => {
  it('rejects traversal in either segment (security boundary)', () => {
    expect(() => storeLocation('..', 'default')).toThrowError(/Invalid agent id/)
    expect(() => storeLocation('ok', '../../etc')).toThrowError(/Invalid profile name/)
  })

  it('composes ~/.connectx/agents/<agent>/<profile>', () => {
    process.env.CONNECTX_HOME = '/tmp/connectx-test-home'
    const loc = storeLocation('claude-code', 'work')
    expect(loc.dir).toBe('/tmp/connectx-test-home/agents/claude-code/work')
    expect(loc.keyFile).toBe('/tmp/connectx-test-home/agents/claude-code/work/key')
  })

  it('storeRoot honours $CONNECTX_HOME', () => {
    process.env.CONNECTX_HOME = '/tmp/custom-home'
    expect(storeRoot()).toBe('/tmp/custom-home')
  })
})
