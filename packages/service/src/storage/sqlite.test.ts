import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { SCHEMA_VERSION } from './schema'
import { openStorage } from './sqlite'
import type { Storage } from './types'

let dir: string
let storage: Storage | undefined

function open(path = ':memory:'): Storage {
  const opened = openStorage({ path })
  storage = opened
  return opened
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'agentx-storage-'))
})

afterEach(() => {
  storage?.close()
  storage = undefined
  rmSync(dir, { recursive: true, force: true })
})

describe('openStorage', () => {
  it('creates a usable schema and stamps the version', () => {
    const path = join(dir, 'fresh.db')
    const opened = open(path)
    expect(opened.headSeq('did:web:a')).toBe(0)

    // Re-opening the same file is not a fresh create and must not throw.
    opened.close()
    storage = undefined
    const again = open(path)
    expect(again.headSeq('did:web:a')).toBe(0)
  })

  it('refuses a file written by a newer build', () => {
    const path = join(dir, 'newer.db')
    const raw = new DatabaseSync(path)
    raw.exec(`PRAGMA user_version = ${SCHEMA_VERSION + 1}`)
    raw.close()

    expect(() => openStorage({ path })).toThrow(/newer than this build/)
  })
})

describe('messages', () => {
  it('round-trips a message, keeping absent device ids absent', () => {
    const store = open()
    store.insertMessage({
      messageId: 'did:web:a:msg-1',
      senderDid: 'did:web:a',
      targetDid: 'did:web:b',
      profile: 'anp.direct.v1',
      securityProfile: 'plain',
      contentType: 'text/plain',
      bodyJson: '{"text":"hi"}',
      acceptedAt: '2026-10-01T00:00:00Z',
    })

    const found = store.message('did:web:a:msg-1')
    expect(found).toBeDefined()
    expect(found?.bodyJson).toBe('{"text":"hi"}')
    // Not `''` and not `null`: a device id that was never sent stays out of the object.
    expect('senderDeviceId' in (found ?? {})).toBe(false)
    expect(store.message('did:web:a:msg-2')).toBeUndefined()
  })

  it('keeps the optional device and conversation ids when they are there', () => {
    const store = open()
    store.insertMessage({
      messageId: 'm',
      senderDid: 'did:web:a',
      targetDid: 'did:web:b',
      profile: 'anp.direct.v1',
      securityProfile: 'p5',
      contentType: 'application/anp+e2ee',
      bodyJson: '{}',
      senderDeviceId: 'dev-1',
      recipientDeviceId: 'dev-2',
      conversationId: 'conv-1',
      acceptedAt: '2026-10-01T00:00:00Z',
    })
    const found = store.message('m')
    expect(found?.senderDeviceId).toBe('dev-1')
    expect(found?.recipientDeviceId).toBe('dev-2')
    expect(found?.conversationId).toBe('conv-1')
  })
})

describe('deliveries', () => {
  it('numbers each owner from 1 independently', () => {
    const store = open()
    const a1 = store.appendDelivery({
      ownerDid: 'did:web:a',
      messageId: 'm1',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: '2026-10-01T00:00:00Z',
    })
    const b1 = store.appendDelivery({
      ownerDid: 'did:web:b',
      messageId: 'm1',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: '2026-10-01T00:00:00Z',
    })
    const a2 = store.appendDelivery({
      ownerDid: 'did:web:a',
      messageId: 'm2',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: '2026-10-01T00:00:01Z',
    })

    expect([a1.seq, b1.seq, a2.seq]).toEqual([1, 1, 2])
    expect(store.headSeq('did:web:a')).toBe(2)
    expect(store.headSeq('did:web:b')).toBe(1)
    expect(store.headSeq('did:web:nobody')).toBe(0)
  })

  it('pages after a sequence, in order', () => {
    const store = open()
    for (let i = 0; i < 5; i++) {
      store.appendDelivery({
        ownerDid: 'did:web:a',
        messageId: `m${i}`,
        method: 'direct.incoming',
        paramsJson: JSON.stringify({ i }),
        acceptedAt: '2026-10-01T00:00:00Z',
      })
    }

    const page = store.deliveriesSince('did:web:a', 2, 2)
    expect(page.map((record) => record.seq)).toEqual([3, 4])
    expect(page.map((record) => record.messageId)).toEqual(['m2', 'm3'])
    expect(store.deliveriesSince('did:web:a', 5, 10)).toEqual([])
  })

  it('advances a cursor per device and never backwards', () => {
    const store = open()
    expect(store.cursor('did:web:a', 'dev-1')).toBe(0)

    store.advanceCursor('did:web:a', 'dev-1', 3)
    store.advanceCursor('did:web:a', 'dev-2', 1)
    expect(store.cursor('did:web:a', 'dev-1')).toBe(3)
    expect(store.cursor('did:web:a', 'dev-2')).toBe(1)

    // A reconnecting device that replays an older acknowledgement must not un-read mail.
    store.advanceCursor('did:web:a', 'dev-1', 2)
    expect(store.cursor('did:web:a', 'dev-1')).toBe(3)
    store.advanceCursor('did:web:a', 'dev-1', 9)
    expect(store.cursor('did:web:a', 'dev-1')).toBe(9)
  })
})

describe('idempotency', () => {
  // The key is core's `idempotencyKey()` output. Its shape does not matter here — only
  // that a row is found by the exact key and by nothing else.
  const key = 'did:web:a|did:web:svc|direct.send|op-1'
  const row = {
    key,
    fingerprint: 'sha-256=:abc:',
    responseJson: '{"accepted":true}',
    createdAt: '2026-10-01T00:00:00Z',
  }

  it('finds what it remembered and nothing else', () => {
    const store = open()
    expect(store.idempotentRow(key)).toBeUndefined()

    store.rememberIdempotent(row)
    expect(store.idempotentRow(key)?.responseJson).toBe('{"accepted":true}')
    expect(store.idempotentRow(`${key}-other`)).toBeUndefined()
  })

  it('keeps the fingerprint, which is what separates a replay from a conflict', () => {
    const store = open()
    store.rememberIdempotent(row)
    expect(store.idempotentRow(key)?.fingerprint).toBe('sha-256=:abc:')
  })

  it('rejects a second write for the same key rather than overwriting the response', () => {
    const store = open()
    store.rememberIdempotent(row)
    expect(() =>
      store.rememberIdempotent({ ...row, responseJson: '{"accepted":false}', createdAt: '2026-10-01T00:00:01Z' }),
    ).toThrow()
    expect(store.idempotentRow(key)?.responseJson).toBe('{"accepted":true}')
  })
})

describe('outbox', () => {
  const draft = (endpointUri: string, nextAttemptAt: string) => ({
    endpointUri,
    payloadJson: '{"jsonrpc":"2.0"}',
    nextAttemptAt,
  })

  it('returns what is due, oldest first, and leaves the future alone', () => {
    const store = open()
    store.enqueueOutbox(draft('https://a.example/anp-im/rpc', '2026-10-01T00:00:02Z'))
    store.enqueueOutbox(draft('https://b.example/anp-im/rpc', '2026-10-01T00:00:00Z'))
    store.enqueueOutbox(draft('https://c.example/anp-im/rpc', '2026-10-01T00:01:00Z'))

    const due = store.dueOutbox('2026-10-01T00:00:05Z', 10)
    expect(due.map((entry) => entry.endpointUri)).toEqual([
      'https://b.example/anp-im/rpc',
      'https://a.example/anp-im/rpc',
    ])
    expect(due[0]?.attempts).toBe(0)
    expect('lastError' in (due[0] ?? {})).toBe(false)
  })

  it('reschedules, then drops', () => {
    const store = open()
    const seq = store.enqueueOutbox(draft('https://a.example/anp-im/rpc', '2026-10-01T00:00:00Z'))

    store.rescheduleOutbox(seq, 1, '2026-10-01T00:00:30Z', 'ECONNREFUSED')
    expect(store.dueOutbox('2026-10-01T00:00:05Z', 10)).toEqual([])
    const later = store.dueOutbox('2026-10-01T00:01:00Z', 10)
    expect(later).toHaveLength(1)
    expect(later[0]?.attempts).toBe(1)
    expect(later[0]?.lastError).toBe('ECONNREFUSED')

    store.dropOutbox(seq)
    expect(store.dueOutbox('2026-10-01T00:01:00Z', 10)).toEqual([])
  })

  it('bounds a page', () => {
    const store = open()
    for (let i = 0; i < 4; i++) {
      store.enqueueOutbox(draft(`https://${i}.example/anp-im/rpc`, '2026-10-01T00:00:00Z'))
    }
    expect(store.dueOutbox('2026-10-01T00:00:01Z', 2)).toHaveLength(2)
  })
})
