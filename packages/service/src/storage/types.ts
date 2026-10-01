// The storage contract.
//
// message-service.md §2 says `Storage` is an interface and SQLite is v1's only
// implementation, so this file is the seam that a second implementation would take. It
// is deliberately a ROW layer: sequence assignment and idempotency hit-testing are here,
// because they cannot be done correctly outside a transaction, while the meanings on top
// of the rows (what a duplicate operation means, how a push is retried, when a group's
// state version moves) belong to the modules that own those features.
//
// The methods are added by the feature that needs them. §7 declares tables for groups,
// E2EE and attachments up front because the schema is cheaper to settle once than to
// migrate; their accessors arrive with C9 / C12 / C13 / C10.

/**
 * One accepted operation, as a row.
 *
 * `key` is core's `idempotencyKey()` output and nothing else — P1 §9.1 L628 puts
 * `(sender_did, target_scope, method, operation_id)` in the scope and L639 requires every
 * device selector to be in it too for a device-addressed overlay, so the scope is not a
 * fixed column list and cannot be spelled as one. Storing the composed key means the
 * scope has exactly ONE definition, in core, shared with the sender that retries.
 *
 * `fingerprint` is what tells a replay from a conflict: same key, different fingerprint is
 * `anp.idempotency_conflict` (§9.1 L630–631).
 */
export interface IdempotencyRow {
  key: string
  fingerprint: string
  /** The response that was sent the first time, stored as the JSON that went on the wire.
   *  A repeat is answered with this exact object (C4). */
  responseJson: string
  createdAt: string
}

export interface StoredMessage {
  messageId: string
  senderDid: string
  targetDid: string
  profile: string
  securityProfile: string
  contentType: string
  /** The `body` object as it arrived, serialized. Opaque for P5/P6. */
  bodyJson: string
  senderDeviceId?: string
  recipientDeviceId?: string
  conversationId?: string
  acceptedAt: string
}

/** One recipient's copy of a message, with the position it occupies in that recipient's
 *  own sequence. `params` is the notification payload as it will be pushed, so a replay
 *  of the sequence (`sync.delta`) needs no reconstruction. */
export interface DeliveryRecord {
  ownerDid: string
  seq: number
  messageId: string
  method: string
  paramsJson: string
  acceptedAt: string
}

export interface OutboxEntry {
  seq: number
  endpointUri: string
  payloadJson: string
  attempts: number
  nextAttemptAt: string
  lastError?: string
}

export interface Storage {
  /** The record for this key, or `undefined` if the operation has not run. The key comes
   *  from core's `idempotencyKey(scope)`. */
  idempotentRow(key: string): IdempotencyRow | undefined
  /** Record the outcome of an operation. Writing must happen in the same transaction as
   *  the state change it describes (C4), so this is a plain insert rather than an
   *  upsert: a second write for one key means two transactions raced. */
  rememberIdempotent(row: IdempotencyRow): void

  insertMessage(message: StoredMessage): void
  message(messageId: string): StoredMessage | undefined

  /** Append one delivery and return the record with the sequence this owner was given.
   *  The sequence is assigned inside a transaction, so concurrent senders cannot both
   *  take the same number. */
  appendDelivery(delivery: Omit<DeliveryRecord, 'seq'>): DeliveryRecord
  /** The owner's deliveries after `since`, in order. `limit` bounds one page. */
  deliveriesSince(ownerDid: string, since: number, limit: number): DeliveryRecord[]
  /** The highest sequence this owner has, whether or not a device has read it. */
  headSeq(ownerDid: string): number
  /** How far this device has been advanced. 0 when it has never read. */
  cursor(ownerDid: string, deviceId: string): number
  /** Advance a device's cursor. Never backwards: a stale replay must not un-read mail. */
  advanceCursor(ownerDid: string, deviceId: string, seq: number): void

  enqueueOutbox(draft: Omit<OutboxEntry, 'seq' | 'attempts' | 'lastError'>): number
  /** Entries due at or before `now`, oldest first. */
  dueOutbox(now: string, limit: number): OutboxEntry[]
  rescheduleOutbox(seq: number, attempts: number, nextAttemptAt: string, lastError: string): void
  /** Drop an entry that was delivered, or one that will never be. */
  dropOutbox(seq: number): void

  close(): void
}
