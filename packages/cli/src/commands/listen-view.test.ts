// `msg listen`'s renderers are the whole of what this command promises a script, so they
// are pinned here rather than left to the socket. Everything below is a pure function of
// an event: no connection is opened and none can be, which is exactly why these cases are
// worth having — the stream itself cannot be exercised until a service exists.

import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  formatDelay,
  formatTime,
  isMessage,
  renderListenMessage,
  renderListenState,
  viewFor,
  writeListenEvent,
  type ListenEvent,
  type ListenMessage,
} from './listen-view'

/** picocolors decides at import time whether this process can show colour, and a test
 *  runner is not a terminal — but the assertions below are about the text, so any escape
 *  that does slip through is removed rather than asserted around. */
function plain(text: string): string {
  return text.replace(new RegExp(String.fromCharCode(27) + '\\[[0-9;]*m', 'g'), '')
}

function message(overrides: Partial<ListenMessage> = {}): ListenMessage {
  return {
    type: 'message',
    seq: 43,
    message_id: 'msg-1',
    from: 'did:wba:example.com:user:bob:e1_xyz',
    target_kind: 'agent',
    content_type: 'text/plain',
    text: 'hello',
    accepted_at: '2026-09-30T14:02:11Z',
    ...overrides,
  }
}

describe('renderListenMessage', () => {
  it('heads a direct message with the sender and indents the body', () => {
    const lines = plain(renderListenMessage(message())).split('\n')
    expect(lines[0]).toContain('did:wba:example.com:user:bob:e1_xyz')
    expect(lines[0]).not.toContain('(group)')
    expect(lines[1]).toBe('  hello')
  })

  it('heads a group message with the group, and prefixes the sender to the body', () => {
    // The group is the addressee, so it is what the header names; the sender underneath.
    // Headed by the sender instead, two groups would read as two private conversations
    // with the same person.
    const lines = plain(
      renderListenMessage(message({ target_kind: 'group', group_did: 'did:wba:example.com:group:contract-team' })),
    ).split('\n')
    expect(lines[0]).toContain('did:wba:example.com:group:contract-team')
    expect(lines[0]).toContain('(group)')
    expect(lines[1]).toBe('  did:wba:example.com:user:bob:e1_xyz: hello')
  })

  it('keeps a multi-line body hanging under its own indent', () => {
    const lines = plain(renderListenMessage(message({ text: 'first\nsecond\nthird' }))).split('\n')
    expect(lines.slice(1)).toEqual(['  first', '  second', '  third'])
  })

  it('describes a body it cannot render instead of dumping it', () => {
    // A P5/P6 payload is ciphertext; the CLI holds no key and never will
    // (message-service.md §11). The line says a message arrived and what it is — which a
    // base64 blob would not.
    const lines = plain(
      renderListenMessage(message({ content_type: 'application/anp-envelope', text: undefined })),
    ).split('\n')
    expect(lines[1]).toBe('  (application/anp-envelope body, not rendered)')
  })

  it('omits the time rather than inventing one the service did not give', () => {
    const lines = plain(renderListenMessage(message({ accepted_at: undefined }))).split('\n')
    expect(lines[0].endsWith('did:wba:example.com:user:bob:e1_xyz')).toBe(true)
  })
})

describe('renderListenState', () => {
  it('renders each state as one line naming what happened', () => {
    expect(plain(renderListenState({ state: 'connecting', service: 'https://agentx.example/anp-im/rpc' }))).toBe(
      'connecting to https://agentx.example/anp-im/rpc',
    )
    expect(plain(renderListenState({ state: 'connected', device: 'claude-code/default', head: 42 }))).toBe(
      'connected as claude-code/default, at cursor 42',
    )
    expect(plain(renderListenState({ state: 'reconnecting', attempt: 2, after_ms: 4000 }))).toBe(
      'reconnecting: attempt 2 in 4s',
    )
    expect(plain(renderListenState({ state: 'error', code: 'unauthorized', message: 'no key' }))).toBe(
      'error: unauthorized: no key',
    )
  })
})

describe('formatTime and formatDelay', () => {
  it('formats a time the same way in every locale', () => {
    // Hand-formatted rather than through Intl: this command's stdout is a contract, and a
    // date that shifted with the environment would make one stream render two ways.
    const formatted = formatTime('2026-09-30T14:02:11Z')
    expect(formatted).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  })

  it('passes through a time it cannot parse rather than printing Invalid Date', () => {
    expect(formatTime('not a time')).toBe('not a time')
  })

  it('says short delays in milliseconds and long ones in seconds', () => {
    expect(formatDelay(250)).toBe('250ms')
    expect(formatDelay(4000)).toBe('4s')
    expect(formatDelay(1250)).toBe('1.3s')
  })
})

describe('isMessage', () => {
  it('separates a message from a state change', () => {
    expect(isMessage(message())).toBe(true)
    expect(isMessage({ state: 'connecting', service: 'https://h/anp-im/rpc' })).toBe(false)
  })
})

describe('the machine stream', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('writes exactly one JSON object per line, unformatted', () => {
    // Not console.log: this is a wire. A consumer reading lines for hours is the reason
    // the shape is asserted rather than assumed.
    const written: string[] = []
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      written.push(String(chunk))
      return true
    })
    const events: ListenEvent[] = [
      { state: 'connecting', service: 'https://h/anp-im/rpc' },
      message(),
      { state: 'reconnecting', attempt: 2, after_ms: 4000 },
    ]
    for (const event of events) writeListenEvent(event)
    expect(written).toHaveLength(3)
    for (const [index, line] of written.entries()) {
      expect(line.endsWith('\n')).toBe(true)
      expect(line.trimEnd()).not.toContain('\n')
      expect(JSON.parse(line)).toEqual(events[index])
    }
  })
})

describe('viewFor', () => {
  it('draws a message rather than serializing it when a terminal is watching', () => {
    // `connectx msg listen | tee log` is a thing people do, and the NDJSON form is the one
    // a file should hold — so a pipe is a machine even without --json.
    const original = process.stdout.isTTY
    try {
      Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true })
      const written: string[] = []
      vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
        written.push(String(chunk))
        return true
      })
      viewFor(false).event(message())
      // On a terminal the message is drawn, not serialized.
      expect(plain(written.join(''))).toContain('●')
      expect(written.join('')).not.toContain('"type":"message"')
    } finally {
      Object.defineProperty(process.stdout, 'isTTY', { value: original, configurable: true })
    }
  })
})
