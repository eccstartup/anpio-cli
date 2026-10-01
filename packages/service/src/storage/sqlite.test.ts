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

  it('keeps the recipient device on the row, and filters the read by it', () => {
    // P5 §10.7 L1391: a ciphertext is queued for one device, and §10.7.1 L1407 forbids
    // handing it to a sibling. A P3 message has no device at all, which is a different
    // fact from "device" being an empty string — `toDelivery` has to keep them apart.
    const store = open()
    store.appendDelivery({
      ownerDid: 'did:web:a',
      messageId: 'm1',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: '2026-10-01T00:00:00Z',
      recipientDeviceId: 'dev-1',
    })
    store.appendDelivery({
      ownerDid: 'did:web:a',
      messageId: 'm2',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: '2026-10-01T00:00:01Z',
    })

    // The device that owns the ciphertext sees both rows: its own, and the account's.
    const asDev1 = store.deliveriesSince('did:web:a', 'dev-1', 0, 10)
    expect(asDev1.map((record) => record.messageId)).toEqual(['m1', 'm2'])
    expect(asDev1[0]?.recipientDeviceId).toBe('dev-1')
    expect(asDev1[1]?.recipientDeviceId).toBeUndefined()

    // A caller that declared no device — and a sibling that declared a different one —
    // get the account's row only. That second case is the one §10.7.1 L1407 is about.
    expect(store.deliveriesSince('did:web:a', '', 0, 10).map((r) => r.messageId)).toEqual(['m2'])
    expect(store.deliveriesSince('did:web:a', 'dev-2', 0, 10).map((r) => r.messageId)).toEqual(['m2'])
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

    const page = store.deliveriesSince('did:web:a', '', 2, 2)
    expect(page.map((record) => record.seq)).toEqual([3, 4])
    expect(page.map((record) => record.messageId)).toEqual(['m2', 'm3'])
    expect(store.deliveriesSince('did:web:a', '', 5, 10)).toEqual([])
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

describe('attachment slots, objects and the authorization chain (P7, C10)', () => {
  const SLOT = {
    attachmentId: 'att-1',
    slotId: 'slot-1',
    ownerDid: 'did:web:a.example',
    uploadToken: 'upload-token',
    commitToken: 'commit-token',
    objectEncryptionMode: 'none',
    messageSecurityProfile: 'transport-protected',
    state: 'pending',
    expiresAt: '2026-10-01T00:15:00.000Z',
    objectUri: 'https://a.example/anp-im/objects/obj-1',
  }

  it('round-trips a slot and leaves the columns nothing has filled in absent', () => {
    const store = open()
    store.insertAttachmentSlot(SLOT)

    const slot = store.attachmentSlot('att-1', 'slot-1')
    expect(slot?.state).toBe('pending')
    expect(slot?.objectUri).toBe(SLOT.objectUri)
    // Absent, not `undefined`: "this slot has no digest yet" is a fact the row does not state.
    expect('size' in (slot ?? {})).toBe(false)
    expect('digest' in (slot ?? {})).toBe(false)
    expect('committedAt' in (slot ?? {})).toBe(false)
  })

  it('finds a slot by the two tokens the data plane holds, and by nothing else', () => {
    const store = open()
    store.insertAttachmentSlot(SLOT)
    expect(store.attachmentSlotByUploadToken('upload-token')?.slotId).toBe('slot-1')
    // The empty string is what the v5 migration backfills for rows written before this
    // column existed, so it must not be a key that finds one of them.
    expect(store.attachmentSlotByUploadToken('')).toBeUndefined()
    expect(store.attachmentSlotByObjectUri(SLOT.objectUri)?.slotId).toBe('slot-1')
  })

  it('records what the upload stream saw, then the terminal state with its time', () => {
    const store = open()
    store.insertAttachmentSlot(SLOT)
    store.recordAttachmentUpload('att-1', 'slot-1', 12, 'digest-1')

    const uploaded = store.attachmentSlot('att-1', 'slot-1')
    expect(uploaded?.state).toBe('uploaded')
    expect(uploaded?.size).toBe(12)
    expect(uploaded?.digest).toBe('digest-1')

    store.setAttachmentSlotState('att-1', 'slot-1', 'committed', '2026-10-01T00:00:05.000Z')
    expect(store.attachmentSlot('att-1', 'slot-1')?.committedAt).toBe('2026-10-01T00:00:05.000Z')
  })

  it('indexes a committed object by its digest, so the same bytes are one row', () => {
    const store = open()
    store.insertAttachmentObject({ digest: 'digest-1', size: 12, committedAt: '2026-10-01T00:00:00.000Z' })
    expect(store.attachmentObject('digest-1')?.size).toBe(12)
    expect(store.attachmentObject('never')).toBeUndefined()
  })

  it('keys a grant by the triple, because one attachment id may recur across messages', () => {
    const store = open()
    const grant = {
      attachmentId: 'att-1',
      objectUri: 'https://a.example/anp-im/objects/obj-1',
      messageSecurityProfile: 'transport-protected',
      messageTargetDid: 'did:web:b.example',
      createdAt: '2026-10-01T00:00:00.000Z',
    }
    store.insertAttachmentGrant({ ...grant, messageId: 'msg-1' })
    // §7.2 L432–433: the same `attachment_id` in another message is a different grant, not a
    // collision.
    store.insertAttachmentGrant({ ...grant, messageId: 'msg-2' })

    expect(store.attachmentGrant('msg-1', 'att-1', grant.objectUri)?.messageTargetDid).toBe('did:web:b.example')
    expect(store.attachmentGrant('msg-2', 'att-1', grant.objectUri)?.messageId).toBe('msg-2')
    expect(store.attachmentGrant('msg-3', 'att-1', grant.objectUri)).toBeUndefined()
  })

  it('stores a ticket under its hash, and only one caller consumes a one-time ticket', () => {
    const store = open()
    store.insertDownloadTicket({
      tokenHash: 'hash-1',
      attachmentId: 'att-1',
      objectUri: 'https://a.example/anp-im/objects/obj-1',
      requesterDid: 'did:web:b.example',
      messageId: 'msg-1',
      messageSecurityProfile: 'transport-protected',
      messageTargetDid: 'did:web:b.example',
      oneTime: true,
      issuedAt: '2026-10-01T00:00:00.000Z',
      expiresAt: '2026-10-01T00:05:00.000Z',
    })

    const ticket = store.downloadTicket('hash-1')
    expect(ticket?.oneTime).toBe(true)
    expect('groupDid' in (ticket ?? {})).toBe(false)
    expect('consumedAt' in (ticket ?? {})).toBe(false)

    // The check and the write are one statement, so the second caller loses even if it
    // arrives at the same instant as the first.
    expect(store.consumeDownloadTicket('hash-1', '2026-10-01T00:00:01.000Z')).toBe(true)
    expect(store.consumeDownloadTicket('hash-1', '2026-10-01T00:00:02.000Z')).toBe(false)
    expect(store.downloadTicket('hash-1')?.consumedAt).toBe('2026-10-01T00:00:01.000Z')
    expect(store.consumeDownloadTicket('hash-never-issued', '2026-10-01T00:00:01.000Z')).toBe(false)
  })
})

describe('the v4 → v5 migration', () => {
  /** A file as v4 wrote it: `attachment_slots` has no `upload_token`, and the three tables
   *  the authorization chain needs are missing entirely. */
  function writeV4(path: string): void {
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE attachment_slots (
       attachment_id              TEXT NOT NULL,
       slot_id                    TEXT NOT NULL,
       owner_did                  TEXT NOT NULL,
       object_encryption_mode     TEXT NOT NULL,
       message_security_profile   TEXT NOT NULL,
       commit_token               TEXT NOT NULL,
       state                      TEXT NOT NULL,
       expires_at                 TEXT NOT NULL,
       object_uri                 TEXT,
       size                       INTEGER,
       digest                     TEXT,
       committed_at               TEXT,
       PRIMARY KEY (attachment_id, slot_id)
     )`)
    db.exec(`INSERT INTO attachment_slots
       (attachment_id, slot_id, owner_did, object_encryption_mode, message_security_profile,
        commit_token, state, expires_at)
       VALUES ('att-old', 'slot-old', 'did:web:a.example', 'none', 'transport-protected',
               'tok', 'pending', '2026-10-01T00:15:00.000Z')`)
    db.exec('PRAGMA user_version = 4')
    db.close()
  }

  it('adds the upload token to the rows that predate it, and the three new tables', () => {
    const path = join(dir, 'v4.db')
    writeV4(path)

    const store = open(path)
    const slot = store.attachmentSlot('att-old', 'slot-old')
    // Not a usable token: the empty string is the "no token on this row" the migration
    // backfills, and the partial unique index in `SCHEMA` excludes exactly that value.
    expect(slot?.uploadToken).toBe('')
    expect(store.attachmentSlotByUploadToken('')).toBeUndefined()

    // The three tables arrive from `SCHEMA`'s `IF NOT EXISTS` pass, which is why the version
    // has to move for a file that needs no column change.
    expect(store.attachmentObject('never')).toBeUndefined()
    expect(store.attachmentGrant('msg', 'att', 'uri')).toBeUndefined()
    expect(store.downloadTicket('hash')).toBeUndefined()
  })
})

describe('the v6 → v7 migration', () => {
  /** A file as v6 wrote it: `deliveries` has no device column. */
  function writeV6(path: string): void {
    const db = new DatabaseSync(path)
    db.exec(`CREATE TABLE deliveries (
       owner_did    TEXT NOT NULL,
       seq          INTEGER NOT NULL,
       message_id   TEXT NOT NULL,
       method       TEXT NOT NULL,
       params_json  TEXT NOT NULL,
       accepted_at  TEXT NOT NULL,
       PRIMARY KEY (owner_did, seq)
     )`)
    db.exec(`INSERT INTO deliveries (owner_did, seq, message_id, method, params_json, accepted_at)
       VALUES ('did:web:a', 1, 'm1', 'direct.incoming', '{}', '2026-10-01T00:00:00Z')`)
    db.exec('PRAGMA user_version = 6')
    db.close()
  }

  it('adds the device column, leaving the rows that predate it account-addressed', () => {
    const path = join(dir, 'v6.db')
    writeV6(path)

    const store = open(path)
    // The row written before the column existed is a P3 delivery, so it must read back
    // with no device rather than with an empty one — that difference is what decides who
    // the frame is pushed to (registry.ts `reaches`).
    const [record] = store.deliveriesSince('did:web:a', '', 0, 10)
    expect(record?.messageId).toBe('m1')
    expect(record?.recipientDeviceId).toBeUndefined()

    const a2 = store.appendDelivery({
      ownerDid: 'did:web:a',
      messageId: 'm2',
      method: 'direct.incoming',
      paramsJson: '{}',
      acceptedAt: '2026-10-01T00:00:01Z',
      recipientDeviceId: 'dev-1',
    })
    expect(a2.recipientDeviceId).toBe('dev-1')
  })
})

/** P5 §7 的密钥材料（C12）。这一层要判的是**行语义**：一设备一行、按上传顺序发、领取是
 *  一次互斥的 UPDATE。上面那些"哪一步先判"是 `rpc/keys.test.ts` 的事。 */
describe('prekey bundles and one-time prekeys (P5, C12)', () => {
  const OWNER = 'did:web:owner.example'
  const DEV = 'dev-a'

  function bundleRow(bundleId: string, publishedAt = '2026-10-01T00:00:00Z') {
    return {
      ownerDid: OWNER,
      ownerDeviceId: DEV,
      bundleId,
      bundleJson: JSON.stringify({ bundle_id: bundleId }),
      publishedAt,
    }
  }

  function opk(keyId: string, uploadedAt: string, publicKeyB64u = 'AA') {
    return {
      ownerDid: OWNER,
      ownerDeviceId: DEV,
      keyId,
      publicKeyB64u,
      state: 'available',
      uploadedAt,
    }
  }

  it('keeps one row per device, replacing the previous bundle (§7.3 L592)', () => {
    const store = open()
    expect(store.prekeyBundle(OWNER, DEV)).toBeUndefined()

    store.upsertPrekeyBundle(bundleRow('bundle-1'))
    expect(store.prekeyBundle(OWNER, DEV)?.bundleId).toBe('bundle-1')

    // 第二次发布覆盖，而不是堆历史：§7.3 L592 交回的是"最新那一份"，而 §6.2.2 L371 的
    // 唯一性规则看的是接受窗口里那一行，不是全部历史（`types.ts` 的 `upsertPrekeyBundle`）。
    store.upsertPrekeyBundle(bundleRow('bundle-2', '2026-10-01T00:00:05Z'))
    expect(store.prekeyBundle(OWNER, DEV)?.bundleId).toBe('bundle-2')
  })

  it('counts only the prekeys that were actually new', () => {
    // `key_id` 由发布方选（§6.4 L401），所以重发同一批是正常事。这个数是
    // `published_opk_count`（§7.1 L497），必须是**落进去的行数**，不是入参长度。
    const store = open()
    expect(store.insertOneTimePrekeys([opk('opk-1', '2026-10-01T00:00:00Z'), opk('opk-2', '2026-10-01T00:00:00Z')])).toBe(2)
    expect(store.insertOneTimePrekeys([opk('opk-1', '2026-10-01T00:00:01Z'), opk('opk-3', '2026-10-01T00:00:01Z')])).toBe(1)
    expect(store.availableOneTimePrekeys(OWNER, DEV)).toBe(3)

    // 首次写入者赢：重发不能把已经发出去的公开钥换掉。
    store.insertOneTimePrekeys([opk('opk-1', '2026-10-01T00:00:02Z', 'ZZ')])
    expect(store.claimOneTimePrekey(OWNER, DEV, 'did:web:asker.example', '2026-10-01T00:00:03Z')?.publicKeyB64u).toBe('AA')
  })

  it('hands out the oldest prekey first, and only once (§6.6 L847)', () => {
    const store = open()
    store.insertOneTimePrekeys([
      opk('opk-b', '2026-10-01T00:00:01Z'),
      opk('opk-a', '2026-10-01T00:00:02Z'),
      // 同一时刻的两枚由 `opk_id` 定序，否则同一批上传的发放在两次读之间没有确定的顺序。
      opk('opk-c', '2026-10-01T00:00:02Z'),
    ])

    const first = store.claimOneTimePrekey(OWNER, DEV, 'did:web:asker.example', '2026-10-01T00:00:03Z')
    expect(first?.keyId).toBe('opk-b')
    expect(first?.state).toBe('assigned')
    // 领到了谁：§6.6 要靠它回答"同一枚钥出现在两个会话里"。
    expect(first?.assignedTo).toBe('did:web:asker.example')
    expect(first?.assignedAt).toBe('2026-10-01T00:00:03Z')

    expect(store.claimOneTimePrekey(OWNER, DEV, 'did:web:asker.example', '2026-10-01T00:00:03Z')?.keyId).toBe('opk-a')
    expect(store.availableOneTimePrekeys(OWNER, DEV)).toBe(1)
    store.claimOneTimePrekey(OWNER, DEV, 'did:web:asker.example', '2026-10-01T00:00:03Z')
    // 池子干了就是 `undefined`——`require_opk` 靠这个区分"没有"与"领取失败"。
    expect(store.claimOneTimePrekey(OWNER, DEV, 'did:web:asker.example', '2026-10-01T00:00:03Z')).toBeUndefined()
    expect(store.availableOneTimePrekeys(OWNER, DEV)).toBe(0)
  })

  it('keeps one device pool separate from another', () => {
    const store = open()
    store.insertOneTimePrekeys([opk('opk-1', '2026-10-01T00:00:00Z')])
    store.insertOneTimePrekeys([{ ...opk('opk-1', '2026-10-01T00:00:00Z'), ownerDeviceId: 'dev-b' }])

    expect(store.claimOneTimePrekey(OWNER, DEV, 'x', '2026-10-01T00:00:01Z')?.keyId).toBe('opk-1')
    expect(store.availableOneTimePrekeys(OWNER, DEV)).toBe(0)
    // 另一台设备那枚还在——池子的键是 `(owner_did, owner_device_id, opk_id)`。
    expect(store.availableOneTimePrekeys(OWNER, 'dev-b')).toBe(1)
  })
})
