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
  InboxQuery,
  InboxRow,
  OutboxEntry,
  Storage,
  StoredAttachmentGrant,
  StoredAttachmentObject,
  StoredAttachmentSlot,
  StoredDownloadTicket,
  StoredGroup,
  StoredGroupEvent,
  StoredGroupMember,
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

/** `undefined` for a NULL column, a number otherwise. A SQLite NULL is what "this row has
 *  no value here" looks like, and `Number(null)` is 0 — a column that means "absent" must
 *  not be read as the number zero. */
function maybeInt(value: unknown): number | undefined {
  return value === null || value === undefined ? undefined : int(value)
}

/** The file's schema version, from SQLite's own `user_version`. */
function schemaVersion(db: DatabaseSync): number {
  const row = db.prepare('PRAGMA user_version').get() as Row | undefined
  const raw = row === undefined ? 0 : Object.values(row)[0]
  return raw === undefined ? 0 : int(raw)
}

/**
 * v1 → v2.
 *
 * Both changes are ones SQLite cannot make in place, which is why they are the version
 * bump and not an `ALTER`.
 *
 * `messages`' primary key was `message_id`. §8.2 L444–450 scopes message-level duplicate
 * recognition by `(sender_did, target.did, message_id)` — the label is the sender's own
 * (P1 §6.2.7 L402), so two senders picking the same one is legal, and the old key refused
 * the second as a constraint violation. The new key is a strict superset, so copying the
 * rows over cannot collide.
 *
 * `outbox.endpoint_uri` was a resolved endpoint pinned when the entry was written; a retry
 * has to resolve the recipient's DID again (C5b). The table holds nothing but retry state,
 * so it is dropped and left to `SCHEMA` to recreate rather than migrated.
 */
function migrateV1ToV2(db: DatabaseSync): void {
  db.exec(
    `CREATE TABLE messages_v2 (
       message_id          TEXT NOT NULL,
       sender_did          TEXT NOT NULL,
       target_did          TEXT NOT NULL,
       profile             TEXT NOT NULL,
       security_profile    TEXT NOT NULL,
       content_type        TEXT NOT NULL,
       body_json           TEXT NOT NULL,
       sender_device_id    TEXT,
       recipient_device_id TEXT,
       conversation_id     TEXT,
       accepted_at         TEXT NOT NULL,
       PRIMARY KEY (sender_did, target_did, message_id)
     )`,
  )
  db.exec(
    `INSERT INTO messages_v2
       SELECT message_id, sender_did, target_did, profile, security_profile, content_type,
              body_json, sender_device_id, recipient_device_id, conversation_id, accepted_at
         FROM messages`,
  )
  // The index on the old table goes with it; `SCHEMA` recreates every index by name.
  db.exec('DROP TABLE messages')
  db.exec('ALTER TABLE messages_v2 RENAME TO messages')
  db.exec('DROP TABLE IF EXISTS outbox')
}

/**
 * Add a column to a table that may be missing it — and skip the table entirely when it does
 * not exist yet.
 *
 * `ADD COLUMN` is the one schema change SQLite can make in place, so it needs no
 * version-gated rebuild the way v1→v2 did. It does need to be idempotent twice over: a
 * version-0 file gets its columns from `SCHEMA` (which runs after this), and older files
 * may or may not have the table at all — `PRAGMA table_info` on a missing table answers
 * with no rows rather than an error, which is what makes the two cases one branch.
 */
function addColumnIfMissing(db: DatabaseSync, table: string, column: string, type: string): void {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all() as Row[]
  if (columns.length === 0) return
  if (columns.some((row) => text(row.name) === column)) return
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`)
}

/**
 * A file written by a newer build is refused instead of opened: this build would read
 * the tables it knows and silently ignore a column the newer one depends on. A fresh
 * file (version 0) gets the schema; a file at the current version is left alone.
 *
 * Every step runs inside this transaction and before `SCHEMA`, so a file that has just
 * been migrated is then topped up with whatever `IF NOT EXISTS` statements it is missing
 * and stamped with the version only once all of that succeeded.
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
    if (version === 1) migrateV1ToV2(db)
    // v4. P4 §7.2 L379–380: both are part of the `group_member` object `group.get_info`
    // returns, and neither was in the table before C9 needed to answer with it.
    addColumnIfMissing(db, 'group_members', 'joined_at', 'TEXT')
    addColumnIfMissing(db, 'group_members', 'added_by', 'TEXT')
    // v4. P4 §8.9.4 L868–875 + §10.3 L1046–1052: a replayed `group.send` answers with the
    // position the message was accepted at, which only the row can still know.
    addColumnIfMissing(db, 'messages', 'group_event_seq', 'INTEGER')
    addColumnIfMissing(db, 'messages', 'group_state_version', 'INTEGER')
    // v5. attachments.md §3: the data plane's PUT is a plain HTTP request with no
    // `origin_proof` behind it, so the unguessable half of `upload_uri` is that request's
    // whole credential and has to be on the row. The default is what SQLite insists on for
    // `ADD COLUMN … NOT NULL`; the partial unique index in `SCHEMA` excludes the empty
    // string precisely so the rows this backfills cannot collide with each other.
    addColumnIfMissing(db, 'attachment_slots', 'upload_token', "TEXT NOT NULL DEFAULT ''")
    // v7. P5 §10.7 L1391 + §10.7.1 L1407: a ciphertext is queued for one device and MUST
    // NOT be fanned out to a sibling. `toDelivery` reads it back as absent when it is
    // NULL, which is exactly what a P3 message means (every device of the account).
    addColumnIfMissing(db, 'deliveries', 'recipient_device_id', 'TEXT')
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
  const groupEventSeq = maybeInt(row.group_event_seq)
  if (groupEventSeq !== undefined) message.groupEventSeq = groupEventSeq
  const groupStateVersion = maybeInt(row.group_state_version)
  if (groupStateVersion !== undefined) message.groupStateVersion = groupStateVersion
  return message
}

function toDelivery(row: Row): DeliveryRecord {
  const record: DeliveryRecord = {
    ownerDid: text(row.owner_did),
    seq: int(row.seq),
    messageId: text(row.message_id),
    method: text(row.method),
    paramsJson: text(row.params_json),
    acceptedAt: text(row.accepted_at),
  }
  const recipientDeviceId = maybeText(row.recipient_device_id)
  if (recipientDeviceId !== undefined) record.recipientDeviceId = recipientDeviceId
  return record
}

/** `group_member` (P4 §7.2). The two optional columns are omitted rather than set to
 *  `undefined`, so a caller doing `{...row, role: 'admin'}` keeps the distinction. */
function toGroupMember(row: Row): StoredGroupMember {
  const member: StoredGroupMember = {
    groupDid: text(row.group_did),
    memberDid: text(row.member_did),
    // §7.2 L384: an absent role is read as `member`. Normalized on the way IN as well, so
    // the column is never the place where "absent" and "member" mean different things.
    role: text(row.role),
    membershipStatus: text(row.membership_status),
    stateVersion: int(row.state_version),
  }
  const joinedAt = maybeText(row.joined_at)
  if (joinedAt !== undefined) member.joinedAt = joinedAt
  const addedBy = maybeText(row.added_by)
  if (addedBy !== undefined) member.addedBy = addedBy
  return member
}

function toOutbox(row: Row): OutboxEntry {
  const entry: OutboxEntry = {
    seq: int(row.seq),
    recipientDid: text(row.recipient_did),
    payloadJson: text(row.payload_json),
    attempts: int(row.attempts),
    nextAttemptAt: text(row.next_attempt_at),
  }
  const lastError = maybeText(row.last_error)
  if (lastError !== undefined) entry.lastError = lastError
  return entry
}

/** One upload slot. The five optional columns are omitted rather than set to `undefined`:
 *  `undefined` means "the PUT has not happened yet", and a caller spreading the row must
 *  not have that turn into a present-but-empty value. */
function toAttachmentSlot(row: Row): StoredAttachmentSlot {
  const slot: StoredAttachmentSlot = {
    attachmentId: text(row.attachment_id),
    slotId: text(row.slot_id),
    ownerDid: text(row.owner_did),
    uploadToken: text(row.upload_token),
    commitToken: text(row.commit_token),
    objectEncryptionMode: text(row.object_encryption_mode),
    messageSecurityProfile: text(row.message_security_profile),
    state: text(row.state),
    expiresAt: text(row.expires_at),
  }
  const objectUri = maybeText(row.object_uri)
  if (objectUri !== undefined) slot.objectUri = objectUri
  const size = maybeInt(row.size)
  if (size !== undefined) slot.size = size
  const digest = maybeText(row.digest)
  if (digest !== undefined) slot.digest = digest
  const committedAt = maybeText(row.committed_at)
  if (committedAt !== undefined) slot.committedAt = committedAt
  return slot
}

function toAttachmentGrant(row: Row): StoredAttachmentGrant {
  const grant: StoredAttachmentGrant = {
    messageId: text(row.message_id),
    attachmentId: text(row.attachment_id),
    objectUri: text(row.object_uri),
    messageSecurityProfile: text(row.message_security_profile),
    createdAt: text(row.created_at),
  }
  const messageTargetDid = maybeText(row.message_target_did)
  if (messageTargetDid !== undefined) grant.messageTargetDid = messageTargetDid
  const groupDid = maybeText(row.group_did)
  if (groupDid !== undefined) grant.groupDid = groupDid
  return grant
}

function toDownloadTicket(row: Row): StoredDownloadTicket {
  const ticket: StoredDownloadTicket = {
    tokenHash: text(row.token_hash),
    attachmentId: text(row.attachment_id),
    objectUri: text(row.object_uri),
    requesterDid: text(row.requester_did),
    messageId: text(row.message_id),
    messageSecurityProfile: text(row.message_security_profile),
    // SQLite has no boolean type; 0/1 is the storage and this is the only place that
    // decides which numbers mean what.
    oneTime: int(row.one_time) !== 0,
    issuedAt: text(row.issued_at),
    expiresAt: text(row.expires_at),
  }
  const messageTargetDid = maybeText(row.message_target_did)
  if (messageTargetDid !== undefined) ticket.messageTargetDid = messageTargetDid
  const groupDid = maybeText(row.group_did)
  if (groupDid !== undefined) ticket.groupDid = groupDid
  const consumedAt = maybeText(row.consumed_at)
  if (consumedAt !== undefined) ticket.consumedAt = consumedAt
  return ticket
}

/**
 * Newest first, ties broken by id.
 *
 * The tie-break is not decoration: `skip` is an offset, and an order that is not total
 * pages over a different list on every call — a reader would see one message twice and
 * never see another, with nothing in the responses saying so.
 */
function newestFirst(a: InboxRow, b: InboxRow): number {
  if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt ? 1 : -1
  if (a.messageId !== b.messageId) return a.messageId < b.messageId ? 1 : -1
  return 0
}

/** An incoming row, shaped from the DELIVERY rather than from the `messages` table.
 *
 *  The delivery row is the per-owner copy, and it is the only side that exists for every
 *  profile: a group message's `messages` row is addressed to the GROUP, so joining it
 *  back to a member's delivery would need a rule this table does not have. Its
 *  `params_json` is the notification `direct.incoming` / `group.incoming` carries, whose
 *  `meta` has the sender and the content type (§7.2.3 L411–418). */
function toIncomingRow(row: Row): InboxRow {
  const params = JSON.parse(text(row.params_json)) as { meta?: unknown; body?: unknown }
  const meta = (typeof params.meta === 'object' && params.meta !== null ? params.meta : {}) as Record<string, unknown>
  return {
    messageId: text(row.message_id),
    senderDid: typeof meta.sender_did === 'string' ? meta.sender_did : '',
    recipientDid: text(row.owner_did),
    contentType: typeof meta.content_type === 'string' ? meta.content_type : '',
    direction: 'incoming',
    bodyJson: JSON.stringify(params.body ?? {}),
    createdAt: text(row.accepted_at),
    readAt: maybeText(row.read_at) ?? null,
  }
}

/** The other direction: a message this owner sent. There is no delivery row for the
 *  sender's own copy, so the `messages` row is the only source. */
function toOutgoingRow(row: Row): InboxRow {
  return {
    messageId: text(row.message_id),
    senderDid: text(row.sender_did),
    recipientDid: text(row.target_did),
    contentType: text(row.content_type),
    direction: 'outgoing',
    bodyJson: text(row.body_json),
    createdAt: text(row.accepted_at),
    readAt: maybeText(row.read_at) ?? null,
  }
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
          sender_device_id, recipient_device_id, conversation_id, accepted_at,
          group_event_seq, group_state_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
      message.groupEventSeq ?? null,
      message.groupStateVersion ?? null,
    )
  }

  message(senderDid: string, targetDid: string, messageId: string): StoredMessage | undefined {
    const row = this.stmt(
      'SELECT * FROM messages WHERE sender_did = ? AND target_did = ? AND message_id = ?',
    ).get(senderDid, targetDid, messageId) as Row | undefined
    return row === undefined ? undefined : toMessage(row)
  }

  appendDelivery(delivery: Omit<DeliveryRecord, 'seq'>): DeliveryRecord {
    return this.transaction(() => {
      const row = this.stmt(
        'SELECT COALESCE(MAX(seq), 0) + 1 AS seq FROM deliveries WHERE owner_did = ?',
      ).get(delivery.ownerDid) as Row
      const seq = int(row.seq)
      this.stmt(
        `INSERT INTO deliveries (owner_did, seq, message_id, method, params_json, accepted_at, recipient_device_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        delivery.ownerDid,
        seq,
        delivery.messageId,
        delivery.method,
        delivery.paramsJson,
        delivery.acceptedAt,
        delivery.recipientDeviceId ?? null,
      )
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

  /** 每个方向各取 `limit + skip` 行，在内存里并成一条时间线再切页。
   *
   *  这不需要把两张表合成一个视图：全局第 k 行必定落在**任一侧**的前 k 行之内，所以
   *  取够 `limit + skip` 就不可能切错，而每一侧各自走自己的索引（PK 与 `messages_*`），
   *  不产生一次全表排序。硬要并成一条 SQL 就得 `UNION ALL` 两张形状不同的表，还得把
   *  `params_json` 里的字段用 `json_extract` 挖出来——那才是把口子开在错误的地方。 */
  inboxPage(ownerDid: string, query: InboxQuery): InboxRow[] {
    const want = query.limit + query.skip
    const rows = [
      ...this.incomingRows(ownerDid, want, query.includeRead),
      ...this.outgoingRows(ownerDid, want),
    ]
    rows.sort(newestFirst)
    return rows.slice(query.skip, query.skip + query.limit)
  }

  inboxSize(ownerDid: string, includeRead: boolean): number {
    const row = this.stmt(
      `SELECT
         (SELECT COUNT(*) FROM deliveries d
            LEFT JOIN message_reads r
              ON r.owner_did = d.owner_did AND r.message_id = d.message_id
           WHERE d.owner_did = ? AND (? = 1 OR r.read_at IS NULL))
       + (SELECT COUNT(*) FROM messages WHERE sender_did = ?) AS total`,
    ).get(ownerDid, includeRead ? 1 : 0, ownerDid) as Row
    return int(row.total)
  }

  inboxRows(ownerDid: string, messageIds: readonly string[]): InboxRow[] {
    if (messageIds.length === 0) return []
    // `json_each` rather than an `IN (?, ?, …)`: the id list comes from the caller and
    // `msg read --all` hands over every unread id at once, so the arity is unbounded —
    // and SQLite's variable limit is a real ceiling. One parameter, one cached statement.
    const ids = JSON.stringify(messageIds)
    const rows = [
      ...(this.stmt(
        `SELECT d.owner_did, d.message_id, d.params_json, d.accepted_at, r.read_at
           FROM deliveries d
           LEFT JOIN message_reads r
             ON r.owner_did = d.owner_did AND r.message_id = d.message_id
          WHERE d.owner_did = ? AND d.message_id IN (SELECT value FROM json_each(?))`,
      ).all(ownerDid, ids) as Row[]).map(toIncomingRow),
      ...(this.stmt(
        `SELECT m.message_id, m.sender_did, m.target_did, m.content_type, m.body_json, m.accepted_at, r.read_at
           FROM messages m
           LEFT JOIN message_reads r
             ON r.owner_did = m.sender_did AND r.message_id = m.message_id
          WHERE m.sender_did = ? AND m.message_id IN (SELECT value FROM json_each(?))`,
      ).all(ownerDid, ids) as Row[]).map(toOutgoingRow),
    ]
    // The SQL layer has no order to give: the caller asked for a list, and `IN` answers
    // as a set. Restore the order asked for, keeping the first of any repeat.
    const order = new Map(messageIds.map((id, index) => [id, index]))
    return [...new Map(rows.map((row) => [row.messageId, row])).values()].sort(
      (a, b) => (order.get(a.messageId) ?? 0) - (order.get(b.messageId) ?? 0),
    )
  }

  markRead(ownerDid: string, messageIds: readonly string[], readAt: string): string[] {
    return this.transaction(() => {
      const marked: string[] = []
      const holds = this.stmt(
        `SELECT 1 AS found
          WHERE EXISTS (SELECT 1 FROM deliveries WHERE owner_did = ? AND message_id = ?)
             OR EXISTS (SELECT 1 FROM messages WHERE sender_did = ? AND message_id = ?)`,
      )
      // `OR IGNORE`: the first read wins. Re-marking must not move `read_at` forward —
      // "when did you read it" has one answer, and a second call is not a new event.
      const insert = this.stmt(
        'INSERT OR IGNORE INTO message_reads (owner_did, message_id, read_at) VALUES (?, ?, ?)',
      )
      for (const id of messageIds) {
        // An id the owner does not hold is skipped, not recorded: the mailbox is the
        // scope of this operation, and without this check any caller could write rows
        // for messages that are none of its business.
        if (holds.get(ownerDid, id, ownerDid, id) === undefined) continue
        if (int(insert.run(ownerDid, id, readAt).changes) > 0) marked.push(id)
      }
      return marked
    })
  }

  private incomingRows(ownerDid: string, limit: number, includeRead: boolean): InboxRow[] {
    const rows = this.stmt(
      `SELECT d.owner_did, d.message_id, d.params_json, d.accepted_at, r.read_at
         FROM deliveries d
         LEFT JOIN message_reads r
           ON r.owner_did = d.owner_did AND r.message_id = d.message_id
        WHERE d.owner_did = ? AND (? = 1 OR r.read_at IS NULL)
        ORDER BY d.accepted_at DESC, d.message_id DESC
        LIMIT ?`,
    ).all(ownerDid, includeRead ? 1 : 0, limit) as Row[]
    return rows.map(toIncomingRow)
  }

  private outgoingRows(ownerDid: string, limit: number): InboxRow[] {
    const rows = this.stmt(
      `SELECT m.message_id, m.sender_did, m.target_did, m.content_type, m.body_json, m.accepted_at, r.read_at
         FROM messages m
         LEFT JOIN message_reads r
           ON r.owner_did = m.sender_did AND r.message_id = m.message_id
        WHERE m.sender_did = ?
        ORDER BY m.accepted_at DESC, m.message_id DESC
        LIMIT ?`,
    ).all(ownerDid, limit) as Row[]
    return rows.map(toOutgoingRow)
  }

  group(groupDid: string): StoredGroup | undefined {
    const row = this.stmt('SELECT * FROM groups WHERE group_did = ?').get(groupDid) as Row | undefined
    if (row === undefined) return undefined
    return {
      groupDid: text(row.group_did),
      hostServiceDid: text(row.host_service_did),
      groupStateVersion: int(row.group_state_version),
      groupEventSeq: int(row.group_event_seq),
      groupProfileJson: text(row.group_profile_json),
      groupPolicyJson: text(row.group_policy_json),
      createdAt: text(row.created_at),
      creatorDid: text(row.creator_did),
    }
  }

  insertGroup(group: StoredGroup): void {
    // A plain INSERT, like `rememberIdempotent`: two builds accepting the same `group_did`
    // at once is a collision in the id space, not something to paper over by overwriting
    // one group with another.
    this.stmt(
      `INSERT INTO groups
         (group_did, host_service_did, group_state_version, group_event_seq,
          group_profile_json, group_policy_json, created_at, creator_did)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      group.groupDid,
      group.hostServiceDid,
      group.groupStateVersion,
      group.groupEventSeq,
      group.groupProfileJson,
      group.groupPolicyJson,
      group.createdAt,
      group.creatorDid,
    )
  }

  updateGroupProfile(groupDid: string, profileJson: string): void {
    this.stmt('UPDATE groups SET group_profile_json = ? WHERE group_did = ?').run(profileJson, groupDid)
  }

  updateGroupPolicy(groupDid: string, policyJson: string): void {
    this.stmt('UPDATE groups SET group_policy_json = ? WHERE group_did = ?').run(policyJson, groupDid)
  }

  /** One statement, so the two counters cannot be read under one operation and written
   *  under another. `UPDATE … RETURNING` needs no round trip back through the caller. */
  advanceGroupCounters(
    groupDid: string,
    advanceStateVersion: boolean,
  ): { groupStateVersion: number; groupEventSeq: number } {
    const row = this.stmt(
      `UPDATE groups
          SET group_state_version = group_state_version + ?,
              group_event_seq     = group_event_seq + 1
        WHERE group_did = ?
        RETURNING group_state_version, group_event_seq`,
    ).get(advanceStateVersion ? 1 : 0, groupDid) as Row | undefined
    if (row === undefined) {
      // The caller looked the group up in the same transaction, so this is a code error and
      // not a request error — silently returning 0/0 would put a wrong sequence in a
      // receipt that the group then signs.
      throw new Error(`no group ${groupDid} to advance`)
    }
    return { groupStateVersion: int(row.group_state_version), groupEventSeq: int(row.group_event_seq) }
  }

  groupMember(groupDid: string, memberDid: string): StoredGroupMember | undefined {
    const row = this.stmt('SELECT * FROM group_members WHERE group_did = ? AND member_did = ?').get(
      groupDid,
      memberDid,
    ) as Row | undefined
    return row === undefined ? undefined : toGroupMember(row)
  }

  groupMembers(groupDid: string): StoredGroupMember[] {
    const rows = this.stmt('SELECT * FROM group_members WHERE group_did = ? ORDER BY member_did').all(
      groupDid,
    ) as Row[]
    return rows.map(toGroupMember)
  }

  upsertGroupMember(member: StoredGroupMember): void {
    this.stmt(
      `INSERT INTO group_members
         (group_did, member_did, role, membership_status, state_version, joined_at, added_by)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (group_did, member_did) DO UPDATE SET
         role              = excluded.role,
         membership_status = excluded.membership_status,
         state_version     = excluded.state_version,
         joined_at         = excluded.joined_at,
         added_by          = excluded.added_by`,
    ).run(
      member.groupDid,
      member.memberDid,
      member.role,
      member.membershipStatus,
      member.stateVersion,
      member.joinedAt ?? null,
      member.addedBy ?? null,
    )
  }

  countActiveMembers(groupDid: string): number {
    const row = this.stmt(
      "SELECT COUNT(*) AS total FROM group_members WHERE group_did = ? AND membership_status = 'active'",
    ).get(groupDid) as Row
    return int(row.total)
  }

  appendGroupEvent(event: StoredGroupEvent): void {
    this.stmt(
      `INSERT INTO group_events (group_did, event_seq, event_type, payload_json, occurred_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(event.groupDid, event.eventSeq, event.eventType, event.payloadJson, event.occurredAt)
  }

  // ---- attachments (P7, C10) -------------------------------------------------

  insertAttachmentSlot(slot: StoredAttachmentSlot): void {
    // Plain INSERT: `(attachment_id, slot_id)` is the whole key, so a conflict means two
    // `create_slot` calls minted the same slot id at once — an id-space collision to
    // surface, not to overwrite.
    this.stmt(
      `INSERT INTO attachment_slots
         (attachment_id, slot_id, owner_did, upload_token, object_encryption_mode,
          message_security_profile, commit_token, state, expires_at, object_uri, size, digest, committed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      slot.attachmentId,
      slot.slotId,
      slot.ownerDid,
      slot.uploadToken,
      slot.objectEncryptionMode,
      slot.messageSecurityProfile,
      slot.commitToken,
      slot.state,
      slot.expiresAt,
      slot.objectUri ?? null,
      slot.size ?? null,
      slot.digest ?? null,
      slot.committedAt ?? null,
    )
  }

  attachmentSlot(attachmentId: string, slotId: string): StoredAttachmentSlot | undefined {
    const row = this.stmt(
      'SELECT * FROM attachment_slots WHERE attachment_id = ? AND slot_id = ?',
    ).get(attachmentId, slotId) as Row | undefined
    return row === undefined ? undefined : toAttachmentSlot(row)
  }

  attachmentSlotByUploadToken(uploadToken: string): StoredAttachmentSlot | undefined {
    // The empty string is the "no token" the v5 migration backfills, and it must not be a
    // lookup key: an upload addressed by nothing would be an upload addressed by anything.
    if (uploadToken === '') return undefined
    const row = this.stmt('SELECT * FROM attachment_slots WHERE upload_token = ?').get(uploadToken) as
      | Row
      | undefined
    return row === undefined ? undefined : toAttachmentSlot(row)
  }

  attachmentSlotByObjectUri(objectUri: string): StoredAttachmentSlot | undefined {
    const row = this.stmt('SELECT * FROM attachment_slots WHERE object_uri = ?').get(objectUri) as
      | Row
      | undefined
    return row === undefined ? undefined : toAttachmentSlot(row)
  }

  recordAttachmentUpload(attachmentId: string, slotId: string, size: number, digest: string): void {
    // `state = 'uploaded'` rather than a second call: the row's claim about the bytes and
    // the bytes' arrival are one fact, and splitting them would let a crash between the
    // two leave a slot that says `pending` with a digest on it.
    this.stmt(
      `UPDATE attachment_slots
          SET size = ?, digest = ?, state = 'uploaded'
        WHERE attachment_id = ? AND slot_id = ?`,
    ).run(size, digest, attachmentId, slotId)
  }

  setAttachmentSlotState(attachmentId: string, slotId: string, state: string, committedAt?: string): void {
    // `COALESCE` keeps a `committed_at` that is already on the row: the only caller that
    // passes a timestamp is the commit, and the abort that follows must not blank it.
    this.stmt(
      `UPDATE attachment_slots
          SET state = ?, committed_at = COALESCE(?, committed_at)
        WHERE attachment_id = ? AND slot_id = ?`,
    ).run(state, committedAt ?? null, attachmentId, slotId)
  }

  insertAttachmentObject(object: StoredAttachmentObject): void {
    // `OR IGNORE`, and that is the content-addressing paying off: the same bytes uploaded
    // through two slots produce one digest, so the second commit finds the row already
    // there and has nothing to add. `committed_at` stays the first, which is when those
    // bytes actually became available.
    this.stmt(
      'INSERT OR IGNORE INTO attachment_objects (digest, size, committed_at) VALUES (?, ?, ?)',
    ).run(object.digest, object.size, object.committedAt)
  }

  attachmentObject(digest: string): StoredAttachmentObject | undefined {
    const row = this.stmt('SELECT * FROM attachment_objects WHERE digest = ?').get(digest) as Row | undefined
    if (row === undefined) return undefined
    return { digest: text(row.digest), size: int(row.size), committedAt: text(row.committed_at) }
  }

  insertAttachmentGrant(grant: StoredAttachmentGrant): void {
    // `OR IGNORE` on the §7.2 L434 triple: a manifest that lists the same
    // `(attachment_id, object_uri)` twice names one attachment, and the second listing
    // must not turn an accepted message into a constraint violation.
    this.stmt(
      `INSERT OR IGNORE INTO attachment_grants
         (message_id, attachment_id, object_uri, message_security_profile,
          message_target_did, group_did, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      grant.messageId,
      grant.attachmentId,
      grant.objectUri,
      grant.messageSecurityProfile,
      grant.messageTargetDid ?? null,
      grant.groupDid ?? null,
      grant.createdAt,
    )
  }

  attachmentGrant(messageId: string, attachmentId: string, objectUri: string): StoredAttachmentGrant | undefined {
    const row = this.stmt(
      'SELECT * FROM attachment_grants WHERE message_id = ? AND attachment_id = ? AND object_uri = ?',
    ).get(messageId, attachmentId, objectUri) as Row | undefined
    return row === undefined ? undefined : toAttachmentGrant(row)
  }

  insertDownloadTicket(ticket: StoredDownloadTicket): void {
    // Plain INSERT: the hash comes from 32 random bytes, so a conflict is a code error
    // rather than a request one, and overwriting would hand the second requester the
    // first one's binding.
    this.stmt(
      `INSERT INTO download_tickets
         (token_hash, attachment_id, object_uri, requester_did, message_id,
          message_security_profile, message_target_did, group_did, one_time,
          issued_at, expires_at, consumed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      ticket.tokenHash,
      ticket.attachmentId,
      ticket.objectUri,
      ticket.requesterDid,
      ticket.messageId,
      ticket.messageSecurityProfile,
      ticket.messageTargetDid ?? null,
      ticket.groupDid ?? null,
      ticket.oneTime ? 1 : 0,
      ticket.issuedAt,
      ticket.expiresAt,
      ticket.consumedAt ?? null,
    )
  }

  downloadTicket(tokenHash: string): StoredDownloadTicket | undefined {
    const row = this.stmt('SELECT * FROM download_tickets WHERE token_hash = ?').get(tokenHash) as
      | Row
      | undefined
    return row === undefined ? undefined : toDownloadTicket(row)
  }

  consumeDownloadTicket(tokenHash: string, consumedAt: string): boolean {
    // `AND consumed_at IS NULL`: redemption is the first one. Two concurrent GETs with the
    // same `one_time` ticket both reach here, and only one may be the redemption — the
    // other's `changes` is 0, which is how the caller tells them apart.
    const result = this.stmt(
      'UPDATE download_tickets SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL',
    ).run(consumedAt, tokenHash)
    return result.changes > 0
  }

  enqueueOutbox(draft: Omit<OutboxEntry, 'seq' | 'attempts' | 'lastError'>): number {
    const result = this.stmt(
      'INSERT INTO outbox (recipient_did, payload_json, next_attempt_at) VALUES (?, ?, ?)',
    ).run(draft.recipientDid, draft.payloadJson, draft.nextAttemptAt)
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

  consumeHttpNonce(keyid: string, nonce: string, expiresAt: string, now: string): boolean {
    // 两句，一个事务。清理与判定必须一起看：先删过期行，再让 UPSERT 去撞主键——留下的
    // 那一行如果还有效就是重放（`changes` 为 0），已经过期就由 DO UPDATE 覆盖掉。
    //
    // 判据写成 SQL 而不是"先 SELECT 再看"：后者在两句之间有窗口，两个并发的同一份签名
    // 会双双读到"没用过"。这里 `changes` 是不是 1，就是"这次是我兑掉的吗"。
    return this.transaction(() => {
      this.stmt('DELETE FROM http_nonces WHERE expires_at <= ?').run(now)
      const result = this.stmt(
        `INSERT INTO http_nonces (keyid, nonce, expires_at) VALUES (?, ?, ?)
           ON CONFLICT (keyid, nonce) DO UPDATE SET expires_at = excluded.expires_at
           WHERE http_nonces.expires_at <= ?`,
      ).run(keyid, nonce, expiresAt, now)
      return result.changes > 0
    })
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
