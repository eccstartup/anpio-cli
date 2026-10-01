// v1's only `Storage` implementation, on `node:sqlite`.
//
// `node:sqlite` is a Node 24 builtin (it existed from 22.5 but only stopped warning in
// 24), which is where the service's `engines` floor comes from — see the ⚠ in
// message-service.md §2 about the TEXT decoder truncating at an embedded NUL before
// 24.16.0. Message bodies are arbitrary bytes, so that floor is a correctness
// requirement and not a preference.

import { DatabaseSync, type StatementSync } from 'node:sqlite'
import { ConnectxError } from '@agentx/core'
import { SCHEMA, SCHEMA_VERSION } from './schema'
import type {
  DeliveryRecord,
  IdempotencyRow,
  OutboxEntry,
  Storage,
  StoredMessage,
} from './types'

/** A row as `node:sqlite` hands it over: a null-prototype object of SQLite scalars. */
type Row = Record<string, unknown>

function text(value: unknown): string {
  return typeof value === 'string' ? value : String(value)
}

function maybeText(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

function int(value: unknown): number {
  return typeof value === 'number' ? value : Number(value)
}

/** The file's schema version, from SQLite's own `user_version`. */
function schemaVersion(db: DatabaseSync): number {
  const row = db.prepare('PRAGMA user_version').get() as Row | undefined
  const raw = row === undefined ? 0 : Object.values(row)[0]
  return raw === undefined ? 0 : int(raw)
}

/**
 * A file written by a newer build is refused instead of opened: this build would read
 * the tables it knows and silently ignore a column the newer one depends on. A fresh
 * file (version 0) gets the schema; a file at the current version is left alone.
 *
 * There is no migration path yet, and none is needed until SCHEMA_VERSION moves — at
 * which point the step is added HERE, where both sides of it are visible.
 */
function applySchema(db: DatabaseSync): void {
  const version = schemaVersion(db)
  if (version === SCHEMA_VERSION) return
  if (version > SCHEMA_VERSION) {
    throw new ConnectxError(
      'invalid_argument',
      `database schema version ${version} is newer than this build understands (${SCHEMA_VERSION}); ` +
        'run the build that wrote it, or start from a new database file',
    )
  }
  db.exec('BEGIN IMMEDIATE')
  try {
    for (const statement of SCHEMA) db.exec(statement)
    // `user_version` takes a literal, so the constant is interpolated rather than bound.
    db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`)
    db.exec('COMMIT')
  } catch (err) {
    db.exec('ROLLBACK')
    throw err
  }
}

function toMessage(row: Row): StoredMessage {
  const message: StoredMessage = {
    messageId: text(row.message_id),
    senderDid: text(row.sender_did),
    targetDid: text(row.target_did),
    profile: text(row.profile),
    securityProfile: text(row.security_profile),
    contentType: text(row.content_type),
    bodyJson: text(row.body_json),
    acceptedAt: text(row.accepted_at),
  }
  const senderDeviceId = maybeText(row.sender_device_id)
  if (senderDeviceId !== undefined) message.senderDeviceId = senderDeviceId
  const recipientDeviceId = maybeText(row.recipient_device_id)
  if (recipientDeviceId !== undefined) message.recipientDeviceId = recipientDeviceId
  const conversationId = maybeText(row.conversation_id)
  if (conversationId !== undefined) message.conversationId = conversationId
  return message
}

function toDelivery(row: Row): DeliveryRecord {
  return {
    ownerDid: text(row.owner_did),
    seq: int(row.seq),
    messageId: text(row.message_id),
    method: text(row.method),
    paramsJson: text(row.params_json),
    acceptedAt: text(row.accepted_at),
  }
}

function toOutbox(row: Row): OutboxEntry {
  const entry: OutboxEntry = {
    seq: int(row.seq),
    endpointUri: text(row.endpoint_uri),
    payloadJson: text(row.payload_json),
    attempts: int(row.attempts),
    nextAttemptAt: text(row.next_attempt_at),
  }
  const lastError = maybeText(row.last_error)
  if (lastError !== undefined) entry.lastError = lastError
  return entry
}

class SqliteStorage implements Storage {
  private readonly db: DatabaseSync
  private readonly statements = new Map<string, StatementSync>()
  /** How many `transaction()` frames are open. 0 means no transaction is active. */
  private depth = 0

  constructor(db: DatabaseSync) {
    this.db = db
  }

  /** Prepared statements are cached per SQL text. Preparing inside a transaction is
   *  fine; preparing once is simply what SQLite prefers. */
  private stmt(sql: string): StatementSync {
    const cached = this.statements.get(sql)
    if (cached !== undefined) return cached
    const prepared = this.db.prepare(sql)
    this.statements.set(sql, prepared)
    return prepared
  }

  /** Run `body` in one immediate transaction. `BEGIN IMMEDIATE` takes the write lock at
   *  the start rather than at the first write, which is what makes the read-modify-write
   *  in `appendDelivery` safe against a second process.
   *
   *  Re-entrant, because the unit of atomicity is an OPERATION (several accessors) while
   *  each accessor must also work on its own, and SQLite refuses a nested `BEGIN`
   *  ("cannot start a transaction within a transaction"). An inner failure propagates to
   *  the outermost frame, which rolls the whole thing back — there are no partial
   *  commits, which is the point. */
  transaction<T>(body: () => T): T {
    if (this.depth > 0) {
      this.depth += 1
      try {
        return body()
      } finally {
        this.depth -= 1
      }
    }
    this.db.exec('BEGIN IMMEDIATE')
    this.depth = 1
    try {
      const result = body()
      this.depth = 0
      this.db.exec('COMMIT')
      return result
    } catch (err) {
      this.depth = 0
      this.db.exec('ROLLBACK')
      throw err
    }
  }

  idempotentRow(key: string): IdempotencyRow | undefined {
    const row = this.stmt(
      'SELECT key, fingerprint, response_json, created_at FROM idempotency WHERE key = ?',
    ).get(key) as Row | undefined
    if (row === undefined) return undefined
    return {
      key: text(row.key),
      fingerprint: text(row.fingerprint),
      responseJson: text(row.response_json),
      createdAt: text(row.created_at),
    }
  }

  rememberIdempotent(row: IdempotencyRow): void {
    // A plain INSERT: the key is the whole primary key, so a conflict means two operations
    // with the same key ran at once. An upsert would hide that by letting the later one
    // overwrite the response the caller already received.
    this.stmt(
      'INSERT INTO idempotency (key, fingerprint, response_json, created_at) VALUES (?, ?, ?, ?)',
    ).run(row.key, row.fingerprint, row.responseJson, row.createdAt)
  }

  insertMessage(message: StoredMessage): void {
    this.stmt(
      `INSERT INTO messages
         (message_id, sender_did, target_did, profile, security_profile, content_type, body_json,
          sender_device_id, recipient_device_id, conversation_id, accepted_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      message.messageId,
      message.senderDid,
      message.targetDid,
      message.profile,
      message.securityProfile,
      message.contentType,
      message.bodyJson,
      message.senderDeviceId ?? null,
      message.recipientDeviceId ?? null,
      message.conversationId ?? null,
      message.acceptedAt,
    )
  }

  message(messageId: string): StoredMessage | undefined {
    const row = this.stmt('SELECT * FROM messages WHERE message_id = ?').get(messageId) as Row | undefined
    return row === undefined ? undefined : toMessage(row)
  }

  appendDelivery(delivery: Omit<DeliveryRecord, 'seq'>): DeliveryRecord {
    return this.transaction(() => {
      const row = this.stmt(
        'SELECT COALESCE(MAX(seq), 0) + 1 AS seq FROM deliveries WHERE owner_did = ?',
      ).get(delivery.ownerDid) as Row
      const seq = int(row.seq)
      this.stmt(
        `INSERT INTO deliveries (owner_did, seq, message_id, method, params_json, accepted_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(delivery.ownerDid, seq, delivery.messageId, delivery.method, delivery.paramsJson, delivery.acceptedAt)
      return { ...delivery, seq }
    })
  }

  deliveriesSince(ownerDid: string, since: number, limit: number): DeliveryRecord[] {
    const rows = this.stmt(
      'SELECT * FROM deliveries WHERE owner_did = ? AND seq > ? ORDER BY seq LIMIT ?',
    ).all(ownerDid, since, limit) as Row[]
    return rows.map(toDelivery)
  }

  headSeq(ownerDid: string): number {
    const row = this.stmt(
      'SELECT COALESCE(MAX(seq), 0) AS head FROM deliveries WHERE owner_did = ?',
    ).get(ownerDid) as Row
    return int(row.head)
  }

  cursor(ownerDid: string, deviceId: string): number {
    const row = this.stmt(
      'SELECT last_seq FROM delivery_cursor WHERE owner_did = ? AND device_id = ?',
    ).get(ownerDid, deviceId) as Row | undefined
    return row === undefined ? 0 : int(row.last_seq)
  }

  advanceCursor(ownerDid: string, deviceId: string, seq: number): void {
    // `MAX(last_seq, excluded.last_seq)`: a device that reconnects with an older cursor
    // than the one on file must not move it backwards, which would re-deliver messages
    // it has already acknowledged and, worse, make an ack look unread again.
    this.stmt(
      `INSERT INTO delivery_cursor (owner_did, device_id, last_seq) VALUES (?, ?, ?)
         ON CONFLICT (owner_did, device_id) DO UPDATE SET last_seq = MAX(last_seq, excluded.last_seq)`,
    ).run(ownerDid, deviceId, seq)
  }

  enqueueOutbox(draft: Omit<OutboxEntry, 'seq' | 'attempts' | 'lastError'>): number {
    const result = this.stmt(
      'INSERT INTO outbox (endpoint_uri, payload_json, next_attempt_at) VALUES (?, ?, ?)',
    ).run(draft.endpointUri, draft.payloadJson, draft.nextAttemptAt)
    return int(result.lastInsertRowid)
  }

  dueOutbox(now: string, limit: number): OutboxEntry[] {
    const rows = this.stmt(
      'SELECT * FROM outbox WHERE next_attempt_at <= ? ORDER BY next_attempt_at, seq LIMIT ?',
    ).all(now, limit) as Row[]
    return rows.map(toOutbox)
  }

  rescheduleOutbox(seq: number, attempts: number, nextAttemptAt: string, lastError: string): void {
    this.stmt('UPDATE outbox SET attempts = ?, next_attempt_at = ?, last_error = ? WHERE seq = ?').run(
      attempts,
      nextAttemptAt,
      lastError,
      seq,
    )
  }

  dropOutbox(seq: number): void {
    this.stmt('DELETE FROM outbox WHERE seq = ?').run(seq)
  }

  close(): void {
    this.statements.clear()
    this.db.close()
  }
}

export interface OpenStorageOptions {
  /** SQLite file path, or `:memory:`. */
  path: string
}

/** Open (creating if needed) and return the storage. The caller owns `close()`. */
export function openStorage(options: OpenStorageOptions): Storage {
  const db = new DatabaseSync(options.path)
  // WAL is the reason a reader (the pick-up surface) does not block the writer (an
  // accepted send). A memory database has no journal file to put in WAL mode, and
  // asking for it there is an error rather than a no-op.
  if (options.path !== ':memory:') db.exec('PRAGMA journal_mode = WAL')
  // `node:sqlite` leaves busy_timeout at 0, so a second process holding the write lock
  // makes `BEGIN IMMEDIATE` fail with SQLITE_BUSY at once instead of waiting. The
  // serialization the row layer relies on is only correct if the loser waits.
  db.exec('PRAGMA busy_timeout = 5000')
  db.exec('PRAGMA foreign_keys = ON')
  applySchema(db)
  return new SqliteStorage(db)
}
