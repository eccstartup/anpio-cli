// The two login renderers: the card a terminal gets, and the state stream everything
// else gets. Both are pure functions over a state the caller already has, so they are
// pinned here rather than through the network — the login they render is `login()`'s job
// and is covered by src/cli-e2e.mjs.

import { describe, expect, it, vi } from 'vitest'
import type { LoginOutcome } from '@agentx/core'
import {
  describeKey,
  describeSession,
  renderCard,
  renderSummary,
  writeEvent,
  type LoginCard,
} from './login-view'

const DID = 'did:wba:localhost%3A3000:user:claude:e1_FfKRmQ2vXb8sTn4pLd6yHc1zWa0oUj9gEr3iKt5xNv7B'

const card: LoginCard = {
  host: 'localhost:3000',
  target: 'http://localhost:3000/api/login/anp/verify',
  agent: 'claude/default',
  did: DID,
  key: { source: 'store', curve: 'ed25519' },
  session: describeSession(true, 604800),
}

/** The lines between the rails, right-padded — i.e. the box has to be a box. */
function lines(text: string): string[] {
  return text.split('\n')
}

describe('renderCard', () => {
  it('draws a closed box, a rule per line', () => {
    const out = lines(renderCard(card, 80))
    expect(out[0].startsWith('┌ connectx ')).toBe(true)
    expect(out[0].endsWith('┐')).toBe(true)
    expect(out.at(-1)?.startsWith('└ Enter to approve · n to cancel ')).toBe(true)
    expect(out.at(-1)?.endsWith('┘')).toBe(true)
    for (const line of out.slice(1, -1)) {
      expect(line.startsWith('│ ')).toBe(true)
      expect(line.endsWith(' │')).toBe(true)
    }
    // Every line the same width, which is what makes it a box rather than a scribble.
    expect(new Set(out.map((l) => l.length)).size).toBe(1)
  })

  it('names the host, the acting agent, the key and where the token goes', () => {
    const out = renderCard(card, 100)
    expect(out).toContain('Sign in to  localhost:3000')
    expect(out).toContain('claude/default')
    expect(out).toContain('ed25519 · local store · never sent')
    expect(out).toContain('http://localhost:3000/api/login/anp/verify')
    expect(out).toContain('session.json, ttl 7d max')
  })

  it('wraps a long DID instead of hiding any of it', () => {
    // A truncated fingerprint is how two agents get mistaken for each other, so the
    // glyph it is supposed to be compared against has to survive the narrow terminal.
    const out = renderCard(card, 60)
    // Rejoined across the wrap and the rails: every byte of it is still on the card.
    expect(out.replace(/[│\n ]/g, '')).toContain(DID)
    for (const line of lines(out)) expect(line.length).toBeLessThanOrEqual(60)
  })

  it('falls back to 80 columns when the terminal does not say', () => {
    const columns = process.stdout.columns
    process.stdout.columns = undefined as unknown as number
    try {
      expect(lines(renderCard(card))[0].length).toBe(80)
    } finally {
      process.stdout.columns = columns as number
    }
  })
})

describe('describeKey', () => {
  it('says where the key is, and never what it is', () => {
    expect(describeKey({ source: 'store', curve: 'ed25519' })).toBe('ed25519 · local store · never sent')
    expect(describeKey({ source: 'material', curve: 'secp256k1' })).toBe(
      'secp256k1 · local key material · never sent',
    )
    expect(describeKey({ source: 'wallet' })).toBe('EIP-1193 wallet · never leaves the wallet')
  })
})

describe('describeSession', () => {
  it('names the bound the caller asked for, or why nothing is written', () => {
    expect(describeSession(true, 604800)).toBe('session.json, ttl 7d max')
    expect(describeSession(true, 5400)).toBe('session.json, ttl 90m max')
    expect(describeSession(true, 45)).toBe('session.json, ttl 45s max')
    expect(describeSession(false, 604800)).toBe('not saved (--no-save-session)')
  })
})

describe('writeEvent', () => {
  it('writes one event per line, and nothing else on stdout', () => {
    const write = vi.spyOn(process.stdout, 'write').mockReturnValue(true)
    try {
      writeEvent({ state: 'connecting', target: 'http://localhost:3000/api/login/anp/verify' })
      writeEvent({
        state: 'signing',
        did: DID,
        keyid: `${DID}#key-1`,
        key: { source: 'store', curve: 'ed25519' },
      })

      const lines = write.mock.calls.map((c) => String(c[0]))
      expect(lines).toHaveLength(2)
      for (const line of lines) {
        expect(line.endsWith('\n')).toBe(true)
        // One line each: a machine splits on newlines and parses each of them.
        expect(line.trimEnd()).not.toContain('\n')
        expect(() => JSON.parse(line)).not.toThrow()
      }
      expect(JSON.parse(lines[1])).toMatchObject({ state: 'signing', key: { source: 'store' } })
    } finally {
      write.mockRestore()
    }
  })

  it('carries the SDK outcome through untouched', () => {
    const outcome: LoginOutcome = {
      subject: 'did:wba:localhost%3A3000:user:claude',
      did: DID,
      method: 'anp',
      walletType: 'anp-cli',
      token: 'tok_live',
      tokenType: 'Bearer',
    }
    const write = vi.spyOn(process.stdout, 'write').mockReturnValue(true)
    try {
      writeEvent({ state: 'connected', session: 'saved', outcome })
      const line = JSON.parse(String(write.mock.calls[0][0])) as { outcome: LoginOutcome }
      // Not re-spelled: a machine reading this reads the SDK's own type.
      expect(line.outcome).toEqual(outcome)
    } finally {
      write.mockRestore()
    }
  })
})

describe('renderSummary', () => {
  const outcome: LoginOutcome = {
    subject: 'did:wba:localhost%3A3000:user:claude',
    did: DID,
    method: 'anp',
    walletType: 'anp-cli',
    token: 'tok_live',
  }

  it('reports the DID, the token and where the token went', () => {
    const out = renderSummary({
      host: 'localhost:3000',
      did: outcome.did,
      token: outcome.token,
      session: 'saved',
      sessionFile: '/home/x/session.json',
    })
    expect(out).toContain('signed in to localhost:3000')
    expect(out).toContain(DID)
    expect(out).toContain('tok_live')
    expect(out).toContain('/home/x/session.json')
  })

  it('says so when the token was never written', () => {
    const out = renderSummary({
      host: 'localhost:3000',
      did: outcome.did,
      token: outcome.token,
      session: 'skipped',
    })
    expect(out).not.toContain('session.json')
    const failed = renderSummary({
      host: 'localhost:3000',
      did: outcome.did,
      token: outcome.token,
      session: 'failed',
    })
    expect(failed).toContain('the token above is the only copy')
  })

  it('flags a token type that is not Bearer, as the register path does', () => {
    const out = renderSummary({
      host: 'localhost:3000',
      did: outcome.did,
      token: outcome.token,
      tokenType: 'DPoP',
      session: 'saved',
      sessionFile: '/home/x/session.json',
    })
    expect(out).toContain('token_type "DPoP"')
    expect(out).toContain('ANP-02 §3.2.3')
  })
})
