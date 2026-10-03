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
import { deviceFilter } from './types'
import type {
  DeliveryRecord,
  IdempotencyRow,
  OutboxEntry,
  Storage,
  StoredAttachmentGrant,
  StoredAttachmentObject,
  StoredAttachmentSlot,
  StoredContact,
  StoredDeviceEnvelope,
  StoredDownloadTicket,
  StoredGroup,
  StoredGroupDidUpdate,
  StoredGroupEvent,
  StoredGroupKeyPackage,
  StoredGroupLeaf,
  StoredGroupMember,
  StoredGroupRemark,
  StoredGroupSigningKey,
  StoredMessage,
  StoredOneTimePrekey,
  StoredPrekeyBundle,
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
    // v10. The periodic DID refresh's cursor (A3c-4, `refresh/memberDidRefresh.ts`): when the
    // sweep last looked at this row. Nullable and with no default on purpose — "never looked"
    // is a state the sweep has to tell apart from "looked a long time ago", because the first
    // batch after an upgrade is exactly the members that have never been checked.
    addColumnIfMissing(db, 'group_members', 'last_did_checked_at', 'TEXT')
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
    // v9. P6 §8.2.4 L767 allows marking a handed-out KeyPackage `reserved`, and the row has
    // to say who took it: §8.2.4 L769's "SHOULD NOT let two adds reuse one KeyPackage" is
    // only checkable if the reservation names its taker. Same shape as the OPK pool's
    // `assigned_to` / `assigned_at`, and not bookkeeping for idempotency — that is the
    // `idempotency` table's job.
    addColumnIfMissing(db, 'group_key_packages', 'reserved_to', 'TEXT')
    addColumnIfMissing(db, 'group_key_packages', 'reserved_at', 'TEXT')
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
  const lastDidCheckedAt = maybeText(row.last_did_checked_at)
  if (lastDidCheckedAt !== undefined) member.lastDidCheckedAt = lastDidCheckedAt
  return member
}

/** The group's own key (v11, B1b-A1). One row, and the row IS the key material — nothing
 *  else reads it, so there is no shape to keep in sync beyond the column order. */
function toGroupSigningKey(row: Row): StoredGroupSigningKey {
  return {
    groupDid: text(row.group_did),
    privateKeyHex: text(row.private_key),
    createdAt: text(row.created_at),
  }
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

function toPrekeyBundle(row: Row): StoredPrekeyBundle {
  return {
    ownerDid: text(row.owner_did),
    ownerDeviceId: text(row.owner_device_id),
    bundleId: text(row.bundle_id),
    bundleJson: text(row.bundle_json),
    publishedAt: text(row.published_at),
  }
}

function toOneTimePrekey(row: Row): StoredOneTimePrekey {
  const key: StoredOneTimePrekey = {
    ownerDid: text(row.owner_did),
    ownerDeviceId: text(row.owner_device_id),
    keyId: text(row.opk_id),
    publicKeyB64u: text(row.public_key_b64u),
    state: text(row.state),
    uploadedAt: text(row.uploaded_at),
  }
  const assignedTo = maybeText(row.assigned_to)
  if (assignedTo !== undefined) key.assignedTo = assignedTo
  const assignedAt = maybeText(row.assigned_at)
  if (assignedAt !== undefined) key.assignedAt = assignedAt
  return key
}

function toGroupKeyPackage(row: Row): StoredGroupKeyPackage {
  const entry: StoredGroupKeyPackage = {
    ownerDid: text(row.owner_did),
    ownerDeviceId: text(row.owner_device_id),
    keyPackageId: text(row.key_package_id),
    packageJson: text(row.package_json),
    state: text(row.state),
    publishedAt: text(row.published_at),
  }
  const reservedTo = maybeText(row.reserved_to)
  if (reservedTo !== undefined) entry.reservedTo = reservedTo
  const reservedAt = maybeText(row.reserved_at)
  if (reservedAt !== undefined) entry.reservedAt = reservedAt
  return entry
}

function toGroupLeaf(row: Row): StoredGroupLeaf {
  return {
    groupDid: text(row.group_did),
    memberDid: text(row.member_did),
    memberDeviceId: text(row.member_device_id),
    cryptoGroupId: text(row.crypto_group_id),
    epoch: text(row.epoch),
    state: text(row.state),
    addedByRefJson: text(row.added_by_ref_json),
    updatedAt: text(row.updated_at),
  }
}

function toGroupDidUpdate(row: Row): StoredGroupDidUpdate {
  return {
    groupDid: text(row.group_did),
    eventRefJson: text(row.event_ref_json),
    progress: text(row.progress),
    expectedJson: text(row.expected_json),
    doneJson: text(row.done_json),
    startedAt: text(row.started_at),
  }
}

function toDeviceEnvelope(row: Row): StoredDeviceEnvelope {
  const envelope: StoredDeviceEnvelope = {
    recipientDid: text(row.recipient_did),
    recipientDeviceId: text(row.recipient_device_id),
    seq: int(row.seq),
    groupDid: text(row.group_did),
    kind: text(row.kind),
    envelopeJson: text(row.envelope_json),
    attempts: int(row.attempts),
    nextAttemptAt: text(row.next_attempt_at),
    enqueuedAt: text(row.enqueued_at),
  }
  const originContextJson = maybeText(row.origin_context_json)
  if (originContextJson !== undefined) envelope.originContextJson = originContextJson
  const lastError = maybeText(row.last_error)
  if (lastError !== undefined) envelope.lastError = lastError
  return envelope
}

function toContact(row: Row): StoredContact {
  const contact: StoredContact = {
    ownerDid: text(row.owner_did),
    subject: text(row.subject),
    did: text(row.did),
    createdAt: text(row.created_at),
    updatedAt: text(row.updated_at),
  }
  const remark = maybeText(row.remark)
  if (remark !== undefined) contact.remark = remark
  return contact
}

function toGroupRemark(row: Row): StoredGroupRemark {
  // 没有 `maybeText` 那一手：`remark` 在这里是 NOT NULL 的（见 `StoredGroupRemark`），
  // 一行没有名字不是一种状态。
  return {
    ownerDid: text(row.owner_did),
    groupDid: text(row.group_did),
    remark: text(row.remark),
    createdAt: text(row.created_at),
    updatedAt: text(row.updated_at),
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

  deliveriesSince(
    ownerDid: string,
    deviceId: string,
    since: number,
    limit: number,
    notBefore: string | undefined,
  ): DeliveryRecord[] {
    // The floor is spelled as a predicate that is simply absent when there is no floor,
    // rather than `(? IS NULL OR accepted_at >= ?)`: the latter needs `notBefore` bound
    // twice, and it sits right where `deviceFilter` also binds a `?` — an off-by-one in
    // positional arguments there is silent, since a timestamp bound into the device
    // column just matches nothing and answers an empty page. Lexicographic `>=` is exact
    // because every `accepted_at` this service writes is
    // `Date.prototype.toISOString()`: one format, UTC, three fractional digits
    // (`dispatch.ts` 的 `acceptedAt`).
    const floor = notBefore === undefined ? '' : ' AND accepted_at >= ?'
    const args: (string | number)[] = [ownerDid, since, deviceId]
    if (notBefore !== undefined) args.push(notBefore)
    const rows = this.stmt(
      `SELECT * FROM deliveries
        WHERE owner_did = ? AND seq > ? AND ${deviceFilter('deliveries')}${floor}
        ORDER BY seq LIMIT ?`,
    ).all(...args, limit) as Row[]
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

  groupSigningKey(groupDid: string): StoredGroupSigningKey | undefined {
    const row = this.stmt('SELECT * FROM group_keys WHERE group_did = ?').get(groupDid) as Row | undefined
    return row === undefined ? undefined : toGroupSigningKey(row)
  }

  insertGroupSigningKey(row: StoredGroupSigningKey): void {
    // A plain INSERT for the same reason `insertGroup` uses one: the row is this group's
    // identity, and a second write for one `group_did` is a collision, not an update.
    this.stmt('INSERT INTO group_keys (group_did, private_key, created_at) VALUES (?, ?, ?)').run(
      row.groupDid,
      row.privateKeyHex,
      row.createdAt,
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

  /** §8.12 定时刷新（A3c-4）的取行：**该看的**那一小批 active 成员。 */
  groupMembersDueForDidCheck(before: string, limit: number): StoredGroupMember[] {
    // `last_did_checked_at IS NOT NULL` 排在前面的是 0（未看过），所以从未看过的行优先——升级
    // 之后的第一批就该是它们。同档之内按戳记由旧到新，让"轮转"是真正的最久未看优先，而不是给
    // 每个 tick 换一批新面孔。最后两个键只是让顺序**确定**：批与批之间不能出现一行反复被看到、
    // 另一行永远排不上（没有确定顺序时 SQLite 的返回顺序不保证稳定）。
    const rows = this.stmt(
      `SELECT * FROM group_members
        WHERE membership_status = 'active'
          AND (last_did_checked_at IS NULL OR last_did_checked_at <= ?)
        ORDER BY last_did_checked_at IS NOT NULL, last_did_checked_at, group_did, member_did
        LIMIT ?`,
    ).all(before, limit) as Row[]
    return rows.map(toGroupMember)
  }

  /** 记下这次查看，无论结果如何。 */
  markGroupMemberDidChecked(groupDid: string, memberDid: string, at: string): void {
    // 无条件写：这里记的是"看过"，不是"没问题"。一次解析失败（对端 DID 服务器不可达）如果
    // 不留戳，那一行就会永远卡在队头，把后面所有人挡住——一个暂时不可达的对端就成了整个刷新的
    // 单点。
    this.stmt(
      'UPDATE group_members SET last_did_checked_at = ? WHERE group_did = ? AND member_did = ?',
    ).run(at, groupDid, memberDid)
  }

  countActiveMembers(groupDid: string): number {
    const row = this.stmt(
      "SELECT COUNT(*) AS total FROM group_members WHERE group_did = ? AND membership_status = 'active'",
    ).get(groupDid) as Row
    return int(row.total)
  }

  /** §8.12 的改名。返回值是**比较并交换**的成败，不是"写了几行"——调用方靠它区分"我做
   *  成了"与"别人已经做过了"。整个动作一个事务，中途没有"删了旧的还没写新的"的窗口。 */
  renameGroupMember(groupDid: string, fromDid: string, toDid: string, stateVersion: number): boolean {
    return this.transaction(() => {
      // 先确认要改的那一行在。**顺序要紧**：下面会为让路删掉新 DID 名下的陈旧行，而"没得
      // 可改"时那一删不该发生——那会让一次落空的比较并交换顺手改掉别的状态。
      const source = this.stmt(
        'SELECT 1 AS present FROM group_members WHERE group_did = ? AND member_did = ?',
      ).get(groupDid, fromDid) as Row | undefined
      if (source === undefined) return false
      const clash = this.stmt(
        'SELECT membership_status FROM group_members WHERE group_did = ? AND member_did = ?',
      ).get(groupDid, toDid) as Row | undefined
      if (clash !== undefined) {
        if (text(clash.membership_status) === 'active') {
          // §8.12 第 4 条要求调用方先确认"新 DID 不是另一个 active 成员"。走到这里说明那条
          // 判断漏了，而**另一种**处置——删掉那条活着的成员行——是拿调错代码去毁掉另一个成员。
          throw new Error(`${toDid} is already an active member of ${groupDid}`)
        }
        // 陈旧的非 active 行（这个 DID 以前在群里后来走了）：§8.12 要保留的是**旧行**身上那份
        // 会员史，所以让路的是它。`upsertGroupMember` 重新激活时也是覆盖这一行，同一件事。
        this.stmt('DELETE FROM group_members WHERE group_did = ? AND member_did = ?').run(groupDid, toDid)
      }
      const result = this.stmt(
        `UPDATE group_members
            SET member_did = ?, state_version = ?
          WHERE group_did = ? AND member_did = ?`,
      ).run(toDid, stateVersion, groupDid, fromDid)
      // 只写这两列：`role` / `membership_status` / `joined_at` / `added_by` 原样留在行上。
      return result.changes > 0
    })
  }

  appendGroupEvent(event: StoredGroupEvent): void {
    this.stmt(
      `INSERT INTO group_events (group_did, event_seq, event_type, payload_json, occurred_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(event.groupDid, event.eventSeq, event.eventType, event.payloadJson, event.occurredAt)
  }

  // ---- E2EE key material (P5, C12) -------------------------------------------

  prekeyBundle(ownerDid: string, ownerDeviceId: string): StoredPrekeyBundle | undefined {
    const row = this.stmt('SELECT * FROM prekey_bundles WHERE owner_did = ? AND owner_device_id = ?').get(
      ownerDid,
      ownerDeviceId,
    ) as Row | undefined
    return row === undefined ? undefined : toPrekeyBundle(row)
  }

  upsertPrekeyBundle(bundle: StoredPrekeyBundle): void {
    this.stmt(
      `INSERT INTO prekey_bundles (owner_did, owner_device_id, bundle_id, bundle_json, published_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (owner_did, owner_device_id) DO UPDATE SET
         bundle_id    = excluded.bundle_id,
         bundle_json  = excluded.bundle_json,
         published_at = excluded.published_at`,
    ).run(bundle.ownerDid, bundle.ownerDeviceId, bundle.bundleId, bundle.bundleJson, bundle.publishedAt)
  }

  insertOneTimePrekeys(keys: readonly StoredOneTimePrekey[]): number {
    // One statement per key rather than a multi-row INSERT, because the count has to be
    // what LANDED: `INSERT OR IGNORE` reports 0 changes for a `key_id` that was already
    // there, and a bulk insert would only give one number for the whole batch. A pool is
    // uploaded a hundred at a time at most, so the loop costs nothing.
    const stmt = this.stmt(
      `INSERT OR IGNORE INTO one_time_prekeys
         (owner_did, owner_device_id, opk_id, public_key_b64u, state, assigned_to, assigned_at, uploaded_at)
       VALUES (?, ?, ?, ?, 'available', NULL, NULL, ?)`,
    )
    let inserted = 0
    for (const key of keys) {
      const result = stmt.run(key.ownerDid, key.ownerDeviceId, key.keyId, key.publicKeyB64u, key.uploadedAt)
      if (result.changes > 0) inserted += 1
    }
    return inserted
  }

  claimOneTimePrekey(
    ownerDid: string,
    ownerDeviceId: string,
    assignedTo: string,
    assignedAt: string,
  ): StoredOneTimePrekey | undefined {
    // Oldest first, so a pool drains in the order it was uploaded and a prekey does not sit
    // around long enough to be a stale one. `opk_id` breaks ties deterministically: two
    // uploads can share a timestamp.
    const row = this.stmt(
      `SELECT * FROM one_time_prekeys
        WHERE owner_did = ? AND owner_device_id = ? AND state = 'available'
        ORDER BY uploaded_at ASC, opk_id ASC
        LIMIT 1`,
    ).get(ownerDid, ownerDeviceId) as Row | undefined
    if (row === undefined) return undefined

    // The CLAIM is this UPDATE, not the SELECT above. `state = 'available'` in the WHERE
    // is what makes it exclusive: whoever sees `changes > 0` is the one that moved the row,
    // so two callers cannot both return the same key (§6.6 L847). Inside an operation's
    // `BEGIN IMMEDIATE` the two statements cannot interleave at all; called on its own by
    // two processes, the loser gets `undefined` and reads it as an empty pool — which is
    // the safe direction, since retrying costs one request and double-issuing does not.
    const result = this.stmt(
      `UPDATE one_time_prekeys SET state = 'assigned', assigned_to = ?, assigned_at = ?
        WHERE owner_did = ? AND owner_device_id = ? AND opk_id = ? AND state = 'available'`,
    ).run(assignedTo, assignedAt, ownerDid, ownerDeviceId, text(row.opk_id))
    if (result.changes === 0) return undefined

    const key = toOneTimePrekey(row)
    key.state = 'assigned'
    key.assignedTo = assignedTo
    key.assignedAt = assignedAt
    return key
  }

  availableOneTimePrekeys(ownerDid: string, ownerDeviceId: string): number {
    const row = this.stmt(
      `SELECT COUNT(*) AS total FROM one_time_prekeys
        WHERE owner_did = ? AND owner_device_id = ? AND state = 'available'`,
    ).get(ownerDid, ownerDeviceId) as Row
    return int(row.total)
  }

  // ---- P6 group E2EE (C13) ---------------------------------------------------

  groupKeyPackage(
    ownerDid: string,
    ownerDeviceId: string,
    keyPackageId: string,
  ): StoredGroupKeyPackage | undefined {
    const row = this.stmt(
      `SELECT * FROM group_key_packages
        WHERE owner_did = ? AND owner_device_id = ? AND key_package_id = ?`,
    ).get(ownerDid, ownerDeviceId, keyPackageId) as Row | undefined
    return row === undefined ? undefined : toGroupKeyPackage(row)
  }

  insertGroupKeyPackage(entry: StoredGroupKeyPackage): void {
    // OR IGNORE, for the same reason the OPK pool ignores a re-upload: `key_package_id` is
    // the publisher's own name (§7.3 L563), so a second publish of it is expected. Applying
    // it would do two bad things at once — resurrect a `consumed` package (§13.2 L1610
    // allows that only under an explicit last-resort declaration) and swap the `package_json`
    // out from under a caller already handed this id.
    this.stmt(
      `INSERT OR IGNORE INTO group_key_packages
         (owner_did, owner_device_id, key_package_id, package_json, state, published_at, reserved_to, reserved_at)
       VALUES (?, ?, ?, ?, 'available', ?, NULL, NULL)`,
    ).run(entry.ownerDid, entry.ownerDeviceId, entry.keyPackageId, entry.packageJson, entry.publishedAt)
  }

  availableGroupKeyPackages(ownerDid: string, ownerDeviceId: string): StoredGroupKeyPackage[] {
    // Oldest first, so a cabinet is handed out in publish order. `key_package_id` breaks
    // ties: two publishes can share a timestamp.
    //
    // A list rather than a COUNT because §8.2.4 L763's "SHOULD return an unexpired one"
    // needs `expires_at`, which lives *inside* the KeyPackage object — digging it out
    // would be `json_extract` on an opaque blob, which this store does not do: a payload
    // column is bytes to it, and whoever needs a field inside parses it.
    const rows = this.stmt(
      `SELECT * FROM group_key_packages
        WHERE owner_did = ? AND owner_device_id = ? AND state = 'available'
        ORDER BY published_at ASC, key_package_id ASC`,
    ).all(ownerDid, ownerDeviceId) as Row[]
    return rows.map(toGroupKeyPackage)
  }

  claimGroupKeyPackage(
    ownerDid: string,
    ownerDeviceId: string,
    keyPackageId: string,
    reservedTo: string,
    reservedAt: string,
  ): boolean {
    // The CLAIM is this UPDATE, not a prior read — same shape as `claimOneTimePrekey`, and
    // for the same reason: §8.2.4 L769 SHOULD NOT let two adds reuse one package, and only
    // the caller that sees `changes > 0` moved the row out of `available`.
    const result = this.stmt(
      `UPDATE group_key_packages SET state = 'reserved', reserved_to = ?, reserved_at = ?
        WHERE owner_did = ? AND owner_device_id = ? AND key_package_id = ? AND state = 'available'`,
    ).run(reservedTo, reservedAt, ownerDid, ownerDeviceId, keyPackageId)
    return result.changes > 0
  }

  markGroupKeyPackageConsumed(
    ownerDid: string,
    ownerDeviceId: string,
    keyPackageId: string,
  ): 'missing' | 'consumed' | 'already-consumed' {
    // The write is the test (`state <> 'consumed'` in the WHERE), so no read comes first and
    // there is no window between the two. `reserved` and `available` both go to `consumed`:
    // §8.2.4 L769 triggers on the accepted `add`, which carries the package inline, whether
    // or not this service was the one that handed it out.
    const result = this.stmt(
      `UPDATE group_key_packages SET state = 'consumed'
        WHERE owner_did = ? AND owner_device_id = ? AND key_package_id = ? AND state <> 'consumed'`,
    ).run(ownerDid, ownerDeviceId, keyPackageId)
    if (result.changes > 0) return 'consumed'

    // Nothing moved. The row is either not here — this service never issued that id, so
    // there is nothing it may call consumed — or already consumed.
    const row = this.stmt(
      `SELECT state FROM group_key_packages
        WHERE owner_did = ? AND owner_device_id = ? AND key_package_id = ?`,
    ).get(ownerDid, ownerDeviceId, keyPackageId) as Row | undefined
    return row === undefined ? 'missing' : 'already-consumed'
  }

  groupLeaf(groupDid: string, memberDid: string, memberDeviceId: string): StoredGroupLeaf | undefined {
    const row = this.stmt(
      `SELECT * FROM group_leaves
        WHERE group_did = ? AND member_did = ? AND member_device_id = ?`,
    ).get(groupDid, memberDid, memberDeviceId) as Row | undefined
    return row === undefined ? undefined : toGroupLeaf(row)
  }

  activeGroupLeaves(groupDid: string): StoredGroupLeaf[] {
    const rows = this.stmt(
      `SELECT * FROM group_leaves WHERE group_did = ? AND state = 'active'
        ORDER BY member_did, member_device_id`,
    ).all(groupDid) as Row[]
    return rows.map(toGroupLeaf)
  }

  upsertGroupLeaf(leaf: StoredGroupLeaf): void {
    // Replacing the row it had is deliberate: §10.3 L1066's re-join trigger is consumed by
    // the Add that takes it, and two rows for one `(did, device)` would make "is this device
    // currently a leaf" a question with two answers.
    this.stmt(
      `INSERT INTO group_leaves
         (group_did, member_did, member_device_id, crypto_group_id, epoch, state, added_by_ref_json, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (group_did, member_did, member_device_id) DO UPDATE SET
         crypto_group_id   = excluded.crypto_group_id,
         epoch             = excluded.epoch,
         state             = excluded.state,
         added_by_ref_json = excluded.added_by_ref_json,
         updated_at        = excluded.updated_at`,
    ).run(
      leaf.groupDid,
      leaf.memberDid,
      leaf.memberDeviceId,
      leaf.cryptoGroupId,
      leaf.epoch,
      leaf.state,
      leaf.addedByRefJson,
      leaf.updatedAt,
    )
  }

  groupDidUpdate(groupDid: string): StoredGroupDidUpdate | undefined {
    const row = this.stmt('SELECT * FROM group_did_updates WHERE group_did = ?').get(groupDid) as
      | Row
      | undefined
    return row === undefined ? undefined : toGroupDidUpdate(row)
  }

  upsertGroupDidUpdate(row: StoredGroupDidUpdate): void {
    // One row per group, so a step that advances the orchestration overwrites its
    // predecessor: the row is "where did this pause get to", not a history of it (§11.10.3
    // L1374 says this is not protocol-level membership state at all).
    this.stmt(
      `INSERT INTO group_did_updates
         (group_did, event_ref_json, progress, expected_json, done_json, started_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (group_did) DO UPDATE SET
         event_ref_json = excluded.event_ref_json,
         progress       = excluded.progress,
         expected_json  = excluded.expected_json,
         done_json      = excluded.done_json,
         started_at     = excluded.started_at`,
    ).run(row.groupDid, row.eventRefJson, row.progress, row.expectedJson, row.doneJson, row.startedAt)
  }

  clearGroupDidUpdate(groupDid: string): void {
    this.stmt('DELETE FROM group_did_updates WHERE group_did = ?').run(groupDid)
  }

  enqueueDeviceEnvelope(envelope: Omit<StoredDeviceEnvelope, 'seq'>): number {
    return this.transaction(() => {
      // Per-device head, for the reason `appendDelivery` reads one: the sequence has to be
      // assigned under the write lock, or two enqueues interleave into a queue that is not
      // sorted. §12.6 orders a device's queue by `group_event_seq` (commits by epoch), which
      // is enqueue order — so the number assigned here IS that order.
      const row = this.stmt(
        `SELECT COALESCE(MAX(seq), 0) + 1 AS seq FROM device_envelopes
          WHERE recipient_did = ? AND recipient_device_id = ?`,
      ).get(envelope.recipientDid, envelope.recipientDeviceId) as Row
      const seq = int(row.seq)
      this.stmt(
        `INSERT INTO device_envelopes
           (recipient_did, recipient_device_id, seq, group_did, kind, envelope_json, origin_context_json,
            attempts, next_attempt_at, last_error, enqueued_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, ?)`,
      ).run(
        envelope.recipientDid,
        envelope.recipientDeviceId,
        seq,
        envelope.groupDid,
        envelope.kind,
        envelope.envelopeJson,
        envelope.originContextJson ?? null,
        envelope.nextAttemptAt,
        envelope.enqueuedAt,
      )
      return seq
    })
  }

  dueDeviceEnvelopes(now: string, limit: number): StoredDeviceEnvelope[] {
    // Ordered by the queue's own key, not by `next_attempt_at`: the scan picks which rows are
    // due, but a caller walking the result walks each device's queue in order — §6.1 lets a
    // `welcome` overtake the pending application envelopes, and that call needs to see them
    // in the order they are queued, not in the order they happened to come due.
    //
    // The `NOT EXISTS` is the head-of-line rule. Only a head is ever attempted, so only a head
    // can be rescheduled into the future; a row is therefore deliverable only when nothing
    // earlier in its queue is still waiting. Handing back the rows behind a stalled head would
    // hand the caller a delivery it is forbidden to make (§12.6 requires a device's
    // `group.incoming` in `group_event_seq` order), and one stalled device's backlog would
    // fill `limit` on every pass and starve every other queue.
    const rows = this.stmt(
      `SELECT * FROM device_envelopes d WHERE d.next_attempt_at <= ?
        AND NOT EXISTS (SELECT 1 FROM device_envelopes e
                         WHERE e.recipient_did = d.recipient_did
                           AND e.recipient_device_id = d.recipient_device_id
                           AND e.seq < d.seq
                           AND e.next_attempt_at > ?)
        ORDER BY d.recipient_did, d.recipient_device_id, d.seq LIMIT ?`,
    ).all(now, now, limit) as Row[]
    return rows.map(toDeviceEnvelope)
  }

  rescheduleDeviceEnvelope(
    recipientDid: string,
    recipientDeviceId: string,
    seq: number,
    attempts: number,
    nextAttemptAt: string,
    lastError: string,
  ): void {
    this.stmt(
      `UPDATE device_envelopes SET attempts = ?, next_attempt_at = ?, last_error = ?
        WHERE recipient_did = ? AND recipient_device_id = ? AND seq = ?`,
    ).run(attempts, nextAttemptAt, lastError, recipientDid, recipientDeviceId, seq)
  }

  dropDeviceEnvelope(recipientDid: string, recipientDeviceId: string, seq: number): void {
    this.stmt(
      'DELETE FROM device_envelopes WHERE recipient_did = ? AND recipient_device_id = ? AND seq = ?',
    ).run(recipientDid, recipientDeviceId, seq)
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

  // ---- address book (TODO6 §3) -------------------------------------------------

  contacts(ownerDid: string): StoredContact[] {
    const rows = this.stmt('SELECT * FROM contacts WHERE owner_did = ? ORDER BY subject').all(
      ownerDid,
    ) as Row[]
    return rows.map(toContact)
  }

  upsertContact(contact: StoredContact): StoredContact {
    // 一句话写完整行：`did` 与 `remark` 都以**这次的**值为准，所以一次换钥之后的 re-put
    // 只挪 `did`；`created_at` 靠 DO UPDATE 那句保持不动——它是"这一行什么时候进来的"，
    // 不是"这一行最后一次被摸是什么时候"（那是 `updated_at`）。
    //
    // `remark` 缺省写 NULL 而不是留着旧值：`contacts.put` 的语义是"这一行现在长这样"。
    // 想保留旧备注的调用方要自己把它带上。
    this.stmt(
      `INSERT INTO contacts (owner_did, subject, did, remark, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (owner_did, subject) DO UPDATE SET
         did = excluded.did,
         remark = excluded.remark,
         updated_at = excluded.updated_at`,
    ).run(
      contact.ownerDid,
      contact.subject,
      contact.did,
      contact.remark ?? null,
      contact.createdAt,
      contact.updatedAt,
    )
    // 读回来而不是把入参原样返回：`created_at` 在冲突那一支上保留的是**旧值**，而调用方
    // 给的那一份是它自己猜的时刻。答案只能从行里取。
    const row = this.stmt(
      'SELECT * FROM contacts WHERE owner_did = ? AND subject = ?',
    ).get(contact.ownerDid, contact.subject) as Row
    return toContact(row)
  }

  rememberContact(contact: {
    ownerDid: string
    subject: string
    did: string
    at: string
  }): void {
    // 与 `upsertContact` 只差一处，但那一处是全部：冲突那一支**不动 `remark`**。
    // 这条路径是服务自己走的（收到一条消息，认识一下发件人），用户起的名字不归它管——
    // 照搬 `contacts.put` 的"缺即清空"会在被备注的人下次来信时把名字抹掉。
    // `created_at` 同理：只由 INSERT 写，冲突支不在 SET 里，于是它留的是第一次那个瞬间。
    this.stmt(
      `INSERT INTO contacts (owner_did, subject, did, remark, created_at, updated_at)
       VALUES (?, ?, ?, NULL, ?, ?)
       ON CONFLICT (owner_did, subject) DO UPDATE SET
         did = excluded.did,
         updated_at = excluded.updated_at`,
    ).run(contact.ownerDid, contact.subject, contact.did, contact.at, contact.at)
  }

  removeContact(ownerDid: string, subject: string): boolean {
    const result = this.stmt('DELETE FROM contacts WHERE owner_did = ? AND subject = ?').run(
      ownerDid,
      subject,
    )
    return result.changes > 0
  }

  // ---- the address book's other half: groups (TODO6 §4.2) ----------------------

  groupRemarks(ownerDid: string): StoredGroupRemark[] {
    const rows = this.stmt('SELECT * FROM group_remarks WHERE owner_did = ? ORDER BY group_did').all(
      ownerDid,
    ) as Row[]
    return rows.map(toGroupRemark)
  }

  upsertGroupRemark(remark: StoredGroupRemark): StoredGroupRemark {
    // `contacts` 那条的三句话这里逐句成立，只把 `subject`/`did` 换成了 `group_did`：
    // 整行以这次的为准（`remark` 一定在，那一列是 NOT NULL）、`created_at` 由 INSERT 写
    // 而冲突支不动它。没有"只挪一行的一部分"的路径，所以也没有第二个写入方法。
    this.stmt(
      `INSERT INTO group_remarks (owner_did, group_did, remark, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (owner_did, group_did) DO UPDATE SET
         remark = excluded.remark,
         updated_at = excluded.updated_at`,
    ).run(remark.ownerDid, remark.groupDid, remark.remark, remark.createdAt, remark.updatedAt)
    // 读回来而不是把入参原样返回：冲突那一支保留的是**旧的** `created_at`。
    const row = this.stmt('SELECT * FROM group_remarks WHERE owner_did = ? AND group_did = ?').get(
      remark.ownerDid,
      remark.groupDid,
    ) as Row
    return toGroupRemark(row)
  }

  removeGroupRemark(ownerDid: string, groupDid: string): boolean {
    const result = this.stmt('DELETE FROM group_remarks WHERE owner_did = ? AND group_did = ?').run(
      ownerDid,
      groupDid,
    )
    return result.changes > 0
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
