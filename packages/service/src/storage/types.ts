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
  /** The OPERATION'S RESULT as JSON — not the JSON-RPC envelope that carried it.
   *  A retry is a different request with its own `id`, so replaying a stored envelope
   *  would answer the retry under the first request's `id`; the envelope is rebuilt around
   *  this result with the retry's own. §9.1 L630 says the service returns the same or an
   *  equivalent *result* and says nothing about the transport's id, which is where the
   *  distinction comes from. */
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
  /**
   * Where the message landed in its group, for a group message: the `group_event_seq` the
   * Host assigned it and the `group_state_version` that was current when it was accepted
   * (P4 §10.2 L1028–1032).
   *
   * Stored rather than derived because a message-level replay has to answer with the
   * ORIGINAL acceptance's snapshot and sequence, and by then both have moved on. Absent for
   * every direct message.
   */
  groupEventSeq?: number
  groupStateVersion?: number
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
  /**
   * The one device this delivery goes to, for a P5 message (P5 §10.7 L1391). Absent for a
   * P3 message, which is addressed to the account and therefore goes to every device
   * watching it.
   *
   * It is not part of the sequence's identity: the number belongs to the account
   * (realtime.md §5.1 L106), and this picks who the frame is pushed to.
   */
  recipientDeviceId?: string
}

/**
 * One group, as the Host keeps it (P4 §6.2–§6.3).
 *
 * The two counters are the whole reason this row exists: §10.1 L1015 requires one linear
 * order per `group_did`, and an order assembled from two reads is not an order. They move
 * inside the same transaction as the members and events they describe.
 *
 * `groupStateVersion` / `groupEventSeq` are integers here and decimal STRINGS on the wire
 * (§6.2 L236 says the version is opaque, §6.3 L249 says the sequence is a decimal string).
 * Storing the number is what makes "monotonic" enforceable; the string is a rendering.
 */
export interface StoredGroup {
  groupDid: string
  hostServiceDid: string
  groupStateVersion: number
  groupEventSeq: number
  /** `group_profile` as it was last written, serialized (P4 §7.4). */
  groupProfileJson: string
  /** `group_policy` as it was last written, serialized (P4 §7.1). */
  groupPolicyJson: string
  createdAt: string
  creatorDid: string
}

/** `role` is `owner` | `admin` | `member` and defaults to `member` when absent
 *  (§7.2 L384); `membershipStatus` is `active` | `left` | `removed` (§6.5). */
export interface StoredGroupMember {
  groupDid: string
  memberDid: string
  role: string
  membershipStatus: string
  /** The `group_state_version` this membership row was last written at. */
  stateVersion: number
  joinedAt?: string
  addedBy?: string
}

/** One `group.state_changed` event, as it will be replayed (§7.10). */
export interface StoredGroupEvent {
  groupDid: string
  eventSeq: number
  eventType: string
  /** The event object itself, serialized — it is what `group.state_changed.body` carries. */
  payloadJson: string
  occurredAt: string
}

/**
 * One upload slot, halfway through its §10.1 lifecycle (attachments.md §2).
 *
 * `state` is `pending` | `uploaded` | `committed` | `aborted`. `expired` is deliberately
 * NOT a state: an expiry is a reading of `expiresAt` taken when the slot is used, so a
 * row cannot disagree with the clock (attachments.md §8).
 */
export interface StoredAttachmentSlot {
  attachmentId: string
  slotId: string
  ownerDid: string
  /** The unguessable half of `upload_uri`, and the data plane's ONLY credential: the PUT
   *  is a plain HTTP request from a plain HTTP client, so it carries no `origin_proof`
   *  and none could be required of it (attachments.md §3). */
  uploadToken: string
  commitToken: string
  objectEncryptionMode: string
  /** The security profile the SENDER intends to carry the manifest under (§10.2.2
   *  `intended_message_security_profile`). Checked against `objectEncryptionMode` at
   *  creation (§10.2.2 L875). */
  messageSecurityProfile: string
  state: string
  expiresAt: string
  /** Issued at creation, before the bytes exist: it is a locator, not a claim that the
   *  object is there (§7.5 L489, §10.1 L826). */
  objectUri?: string
  /** Filled in by the PUT as it streams, so `commit_object` can check what arrived. */
  size?: number
  digest?: string
  /** The time of the TERMINAL transition — commit or abort, whichever happened. One column
   *  rather than two because `state` already says which: the response's `committed_at` and
   *  `aborted_at` are the same fact about a row that has only one ending. */
  committedAt?: string
}

/** One committed object. The bytes live on the filesystem addressed by `digest`; this
 *  row is the index that says "these bytes exist", not the container for them
 *  (attachments.md §4). */
export interface StoredAttachmentObject {
  digest: string
  size: number
  committedAt: string
}

/**
 * One Access Grant (P7 §9.2 L652–664).
 *
 * Keyed by the triple §7.2 L434 requires — `attachment_id` alone is only unique within one
 * Attachment Message and may legally recur across messages (L432–433).
 *
 * Created when the message carrying the manifest is ACCEPTED (§9.2 L656), in the same
 * transaction: outside it there would be a window in which the message exists and its
 * attachments cannot be downloaded, and nothing in that window would tell the client.
 */
export interface StoredAttachmentGrant {
  messageId: string
  attachmentId: string
  objectUri: string
  messageSecurityProfile: string
  /** Private context: the original message's target agent DID. */
  messageTargetDid?: string
  /** Group context: the group the original message went to. */
  groupDid?: string
  createdAt: string
}

/** One issued download ticket (P7 §9.4 L681–689).
 *
 *  Only the token's SHA-256 is stored: it is a bearer credential, and the ledger is not
 *  the place for one in the clear (attachments.md §7). */
export interface StoredDownloadTicket {
  tokenHash: string
  attachmentId: string
  objectUri: string
  requesterDid: string
  messageId: string
  messageSecurityProfile: string
  messageTargetDid?: string
  groupDid?: string
  oneTime: boolean
  issuedAt: string
  expiresAt: string
  /** Set when a `one_time` ticket has been redeemed. */
  consumedAt?: string
}

export interface OutboxEntry {
  seq: number
  /** The recipient's DID, NOT a resolved endpoint. The push resolves it through the
   *  locator on every attempt, because a domain can move its ingress service between
   *  the enqueue and the retry; pinning the answer from the first attempt would make
   *  the retry aim at an address that may no longer be anyone's. */
  recipientDid: string
  payloadJson: string
  attempts: number
  nextAttemptAt: string
  lastError?: string
}

/**
 * One message as the mailbox owner sees it — the row shape of the pick-up surface
 * (message-service.md §9.3), assembled from the delivery row (incoming) or the message
 * row (outgoing).
 *
 * The two directions are one list because that is what a conversation is: `inbox.get`
 * orders them together by time, and `direction` alone tells them apart. `recipientDid` is
 * therefore the counterpart of the row, not always the owner.
 */
export interface InboxRow {
  messageId: string
  senderDid: string
  recipientDid: string
  contentType: string
  direction: 'incoming' | 'outgoing'
  /** The `body` object as it arrived, serialized. Opaque for P5/P6. */
  bodyJson: string
  createdAt: string
  /** When the OWNER marked it read, or `null`. Only incoming rows have a meaningful
   *  value: a message the owner sent is not something the owner reads. */
  readAt: string | null
}

/** One page request against {@link Storage.inboxPage}. */
export interface InboxQuery {
  limit: number
  /** How many rows to step over. Offset rather than a sequence number because the list
   *  is a merge of two tables and has no single cursor of its own. */
  skip: number
  /** `false` drops incoming messages the owner has already read. Outgoing rows are
   *  never dropped: `read_at` has no meaning for them, so it cannot be the filter. */
  includeRead: boolean
}

export interface Storage {
  /** Run `body` as one transaction, committing when it returns and rolling back when it
   *  throws. Re-entrant: a call already inside a transaction joins the enclosing one, and
   *  only the outermost commits. That matters because the unit of atomicity is the
   *  OPERATION (message row + deliveries + the idempotency record, §8.1) while the
   *  individual accessors below also need a transaction of their own when called alone —
   *  SQLite refuses a nested `BEGIN`, so the depth has to be tracked here. */
  transaction<T>(body: () => T): T

  /** The record for this key, or `undefined` if the operation has not run. The key comes
   *  from core's `idempotencyKey(scope)`. */
  idempotentRow(key: string): IdempotencyRow | undefined
  /** Record the outcome of an operation. Writing must happen in the same transaction as
   *  the state change it describes (C4), so this is a plain insert rather than an
   *  upsert: a second write for one key means two transactions raced. */
  rememberIdempotent(row: IdempotencyRow): void

  insertMessage(message: StoredMessage): void
  /** One message by the triple §8.2 L444–450 scopes message-level duplicate recognition
   *  over. `message_id` alone is not a key: it is the sender's own label, so two senders
   *  may pick the same one. */
  message(senderDid: string, targetDid: string, messageId: string): StoredMessage | undefined

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

  /** The owner's messages, newest first, both directions merged (取件面 §9.3).
   *  `limit + skip` rows are read from each side and merged, which is enough to answer
   *  the page: the global k-th row lies within the first k of one of the two. */
  inboxPage(ownerDid: string, query: InboxQuery): InboxRow[]
  /** How many rows `inboxPage` would return in total for the same filter. */
  inboxSize(ownerDid: string, includeRead: boolean): number
  /** Those of `messageIds` that belong in THIS owner's mailbox, in the order asked.
   *  The mailbox is the scope, not a lookup helper: an id the owner never sent or
   *  received must not be readable, and must not be markable either. */
  inboxRows(ownerDid: string, messageIds: readonly string[]): InboxRow[]
  /** Mark messages read. Returns the ids that were not read before — an id the owner
   *  does not hold is skipped rather than recorded. */
  markRead(ownerDid: string, messageIds: readonly string[], readAt: string): string[]

  /** The group row, or `undefined` if this service hosts no such group. */
  group(groupDid: string): StoredGroup | undefined
  /** Write a new group. The counters are given rather than derived: `group.create` starts
   *  them at 1/1 (§6.2 L237), and that is a decision of the operation, not of the store. */
  insertGroup(group: StoredGroup): void
  /** Replace the stored `group_profile` / `group_policy`. The caller has already merged the
   *  patch and validated the RESULT (groups.md §8), so this writes a finished object. */
  updateGroupProfile(groupDid: string, profileJson: string): void
  updateGroupPolicy(groupDid: string, policyJson: string): void
  /**
   * Take the next `group_event_seq`, and the next `group_state_version` when the caller says
   * this operation is a state change.
   *
   * One accessor for both because the two are always written together and always inside the
   * operation's transaction: read-modify-write across two calls would let a concurrent
   * operation slip between them and produce two events sharing a sequence number.
   * §6.2 L238 is why `advanceStateVersion` is a parameter: a group MESSAGE advances the
   * sequence and must NOT advance the version.
   */
  advanceGroupCounters(
    groupDid: string,
    advanceStateVersion: boolean,
  ): { groupStateVersion: number; groupEventSeq: number }

  groupMember(groupDid: string, memberDid: string): StoredGroupMember | undefined
  /** Every member row of a group, in a stable order (by member DID). */
  groupMembers(groupDid: string): StoredGroupMember[]
  /** Insert or replace one membership row. A re-activation overwrites `joinedAt` /
   *  `addedBy` — they are properties of THIS membership, not of the DID (groups.md §3). */
  upsertGroupMember(member: StoredGroupMember): void
  /** How many DIDs are currently `active`. §7.1 L370 counts DIDs, not devices. */
  countActiveMembers(groupDid: string): number

  /** Append one `group.state_changed` event. `eventSeq` is the value
   *  {@link Storage.advanceGroupCounters} just returned, which is what makes the events
   *  table an ordered replay source even though its sequence numbers are not contiguous
   *  (group messages take numbers without leaving an event row). */
  appendGroupEvent(event: StoredGroupEvent): void

  // ---- attachments (P7, C10) -------------------------------------------------
  //
  // The bytes are NOT here — they are on the filesystem, addressed by digest
  // (attachments.md §4). These four tables are the authorization and lifecycle ledger
  // that has to be transactional: the Grant has to appear in the same transaction that
  // accepts the message which carries its manifest.

  insertAttachmentSlot(slot: StoredAttachmentSlot): void
  attachmentSlot(attachmentId: string, slotId: string): StoredAttachmentSlot | undefined
  /** The data plane's only lookup: the PUT is addressed by the upload token, which is
   *  the one credential that request has. */
  attachmentSlotByUploadToken(uploadToken: string): StoredAttachmentSlot | undefined
  /** The download route's lookup. `object_uri` is issued at creation and is unique to
   *  one slot, so it is both the route parameter and the lookup key. */
  attachmentSlotByObjectUri(objectUri: string): StoredAttachmentSlot | undefined
  /** Record what the PUT received. Also the transition into `uploaded`. */
  recordAttachmentUpload(attachmentId: string, slotId: string, size: number, digest: string): void
  /** Transition into `committed` (or `aborted`). A terminal state; never moved back. */
  setAttachmentSlotState(attachmentId: string, slotId: string, state: string, committedAt?: string): void

  /** Index a committed object. A content-addressed store makes this idempotent: the same
   *  bytes uploaded twice are one row and one file. */
  insertAttachmentObject(object: StoredAttachmentObject): void
  attachmentObject(digest: string): StoredAttachmentObject | undefined

  /** Create one Access Grant. Inserted after the message row, in its transaction. */
  insertAttachmentGrant(grant: StoredAttachmentGrant): void
  attachmentGrant(messageId: string, attachmentId: string, objectUri: string): StoredAttachmentGrant | undefined

  insertDownloadTicket(ticket: StoredDownloadTicket): void
  /** By the SHA-256 of the token the client presented, never by the token itself. */
  downloadTicket(tokenHash: string): StoredDownloadTicket | undefined
  /** Redeem a `one_time` ticket. Returns whether THIS call was the redemption — the check
   *  and the write are one statement, so two concurrent GETs with the same ticket cannot
   *  both pass a separate "has it been consumed" read. */
  consumeDownloadTicket(tokenHash: string, consumedAt: string): boolean

  enqueueOutbox(draft: Omit<OutboxEntry, 'seq' | 'attempts' | 'lastError'>): number
  /** Entries due at or before `now`, oldest first. */
  dueOutbox(now: string, limit: number): OutboxEntry[]
  rescheduleOutbox(seq: number, attempts: number, nextAttemptAt: string, lastError: string): void
  /** Drop an entry that was delivered, or one that will never be. */
  dropOutbox(seq: number): void

  // ---- federation (P8, C11) --------------------------------------------------
  //
  // ANP-02 L437 要求服务端实现重放防护。core 的 `verifyHttpMessageSignature` 因此留了
  // 一个 `nonceStore` 接缝，这里给它一个能跨进程存活的实现——进程内那张 Map 一次重启
  // 就清空，而"重启一下就能把同一份签名再放一遍"正是重放防护要防的。

  /**
   * Consume `(keyid, nonce)`, returning whether THIS call was the consumption.
   *
   * The check and the write are one statement, and that is the whole point of putting it
   * here rather than in the caller: two concurrent requests carrying the same signature
   * both reach this call, and exactly one of them may win. A read-then-write pair in
   * application code has a window between the two where both read "unused".
   *
   * `expiresAt` is when the row stops standing for anything; a pair that is already there
   * but expired is replaced rather than remembered, because a nonce older than the
   * signature window cannot be replayed inside one and would otherwise fill the table
   * with answers that no longer mean anything.
   */
  consumeHttpNonce(keyid: string, nonce: string, expiresAt: string, now: string): boolean

  close(): void
}
