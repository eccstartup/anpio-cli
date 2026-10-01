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

    const found = store.message('did:web:a', 'did:web:b', 'did:web:a:msg-1')
    expect(found).toBeDefined()
    expect(found?.bodyJson).toBe('{"text":"hi"}')
    // Not `''` and not `null`: a device id that was never sent stays out of the object.
    expect('senderDeviceId' in (found ?? {})).toBe(false)
    expect(store.message('did:web:a', 'did:web:b', 'did:web:a:msg-2')).toBeUndefined()
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
    const found = store.message('did:web:a', 'did:web:b', 'm')
    expect(found?.senderDeviceId).toBe('dev-1')
    expect(found?.recipientDeviceId).toBe('dev-2')
    expect(found?.conversationId).toBe('conv-1')
  })

  it('holds two senders that picked the same message id', () => {
    // P1 §6.2.7 L402 makes `message_id` the SENDER's own label, so a collision between
    // two senders is legal and the key has to admit it. A `message_id`-only primary key
    // turned the second one into a constraint error, which surfaced as a 500.
    const store = open()
    const shared = { messageId: 'msg-1', targetDid: 'did:web:b', profile: 'p', securityProfile: 's', contentType: 'text/plain', bodyJson: '{}', acceptedAt: '2026-10-01T00:00:00Z' }
    store.insertMessage({ ...shared, senderDid: 'did:web:a' })
    store.insertMessage({ ...shared, senderDid: 'did:web:c' })

    expect(store.message('did:web:a', 'did:web:b', 'msg-1')?.senderDid).toBe('did:web:a')
    expect(store.message('did:web:c', 'did:web:b', 'msg-1')?.senderDid).toBe('did:web:c')
    // …and the same sender twice is still one message.
    expect(() => store.insertMessage({ ...shared, senderDid: 'did:web:a' })).toThrow()
  })
})

describe('the v1 → v2 migration', () => {
  /** A file as v1 wrote it: `message_id` alone is the key, and the outbox pins an
   *  endpoint that was resolved when the entry was enqueued. */
  function writeV1(path: string): void {
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE messages (
       message_id          TEXT PRIMARY KEY,
       sender_did          TEXT NOT NULL,
       target_did          TEXT NOT NULL,
       profile             TEXT NOT NULL,
       security_profile    TEXT NOT NULL,
       content_type        TEXT NOT NULL,
       body_json           TEXT NOT NULL,
       sender_device_id    TEXT,
       recipient_device_id TEXT,
       conversation_id     TEXT,
       accepted_at         TEXT NOT NULL
     )`)
    db.exec(`CREATE TABLE outbox (
       seq            INTEGER PRIMARY KEY AUTOINCREMENT,
       endpoint_uri   TEXT NOT NULL,
       payload_json   TEXT NOT NULL,
       attempts       INTEGER NOT NULL DEFAULT 0,
       next_attempt_at TEXT NOT NULL,
       last_error     TEXT
     )`)
    db.exec(`INSERT INTO messages
       (message_id, sender_did, target_did, profile, security_profile, content_type, body_json,
        sender_device_id, recipient_device_id, conversation_id, accepted_at)
       VALUES ('msg-1', 'did:web:a', 'did:web:b', 'anp.direct.base.v1', 'transport-protected',
               'text/plain', '{"text":"hi"}', NULL, NULL, 'conv-1', '2026-09-30T00:00:00Z')`)
    db.exec(`INSERT INTO outbox (endpoint_uri, payload_json, next_attempt_at)
       VALUES ('https://b.example/anp-im/rpc', '{"jsonrpc":"2.0"}', '2026-09-30T00:00:00Z')`)
    db.exec('PRAGMA user_version = 1')
    db.close()
  }

  it('carries the rows over, drops the outbox, and admits the second sender', () => {
    const path = join(dir, 'v1.db')
    writeV1(path)

    const store = open(path)
    const kept = store.message('did:web:a', 'did:web:b', 'msg-1')
    expect(kept?.bodyJson).toBe('{"text":"hi"}')
    expect(kept?.conversationId).toBe('conv-1')

    // A row the old key would have refused. This is what the bump was for.
    store.insertMessage({
      messageId: 'msg-1',
      senderDid: 'did:web:c',
      targetDid: 'did:web:b',
      profile: 'anp.direct.base.v1',
      securityProfile: 'transport-protected',
      contentType: 'text/plain',
      bodyJson: '{}',
      acceptedAt: '2026-10-01T00:00:00Z',
    })

    // The outbox held a resolved endpoint, which a retry must not reuse; it is retry
    // state and nothing else, so it goes rather than being rewritten.
    expect(store.enqueueOutbox({ recipientDid: 'did:web:b', payloadJson: '{}', nextAttemptAt: '2026-10-01T00:00:00Z' })).toBe(1)
  })

  it('leaves a file it has already migrated alone', () => {
    const path = join(dir, 'twice.db')
    writeV1(path)
    open(path).close()
    storage = undefined

    const again = open(path)
    expect(again.message('did:web:a', 'did:web:b', 'msg-1')?.messageId).toBe('msg-1')
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
  const draft = (recipientDid: string, nextAttemptAt: string) => ({
    recipientDid,
    payloadJson: '{"jsonrpc":"2.0"}',
    nextAttemptAt,
  })

  it('returns what is due, oldest first, and leaves the future alone', () => {
    const store = open()
    store.enqueueOutbox(draft('did:web:a.example', '2026-10-01T00:00:02Z'))
    store.enqueueOutbox(draft('did:web:b.example', '2026-10-01T00:00:00Z'))
    store.enqueueOutbox(draft('did:web:c.example', '2026-10-01T00:01:00Z'))

    const due = store.dueOutbox('2026-10-01T00:00:05Z', 10)
    expect(due.map((entry) => entry.recipientDid)).toEqual([
      'did:web:b.example',
      'did:web:a.example',
    ])
    expect(due[0]?.attempts).toBe(0)
    expect('lastError' in (due[0] ?? {})).toBe(false)
  })

  it('reschedules, then drops', () => {
    const store = open()
    const seq = store.enqueueOutbox(draft('did:web:a.example', '2026-10-01T00:00:00Z'))

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
      store.enqueueOutbox(draft(`did:web:${i}.example`, '2026-10-01T00:00:00Z'))
    }
    expect(store.dueOutbox('2026-10-01T00:00:01Z', 2)).toHaveLength(2)
  })
})
