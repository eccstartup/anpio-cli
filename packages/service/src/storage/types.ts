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

/**
 * One group's own Ed25519 key (B1b-A1) — the key `group.create` mints and the one that
 * signs this group's DID document and every `group_receipt.proof`.
 *
 * It lives in its own table rather than as a column of {@link StoredGroup} so that
 * `Storage.group()` — a `SELECT *` read that plenty of call sites do just to look at the
 * policy — cannot carry private key material along with it. Reading a key is a call site's
 * explicit decision here, not a side effect of reading a group.
 *
 * `privateKeyHex` is the 32-byte seed as bare hex, the same text form `AGENTX_KEY_FILE`
 * accepts, so `parsePrivateKey(hex, 'ed25519')` reads both. The public key is deliberately
 * NOT stored: it is derivable, and two copies of one fact can disagree.
 */
export interface StoredGroupSigningKey {
  groupDid: string
  privateKeyHex: string
  createdAt: string
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
  /** When the periodic DID refresh (A3c-4) last **looked** at this row. Absent means never.
   *
   *  It is the sweep's cursor, not a fact about the membership — nothing else reads it, and a
   *  change of DID does not clear it (the new DID simply gets looked at once more). */
  lastDidCheckedAt?: string
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
 * One published `group_key_package` (P6 §7.3), one row per
 * `(owner_did, owner_device_id, key_package_id)`.
 *
 * `packageJson` is the object **verbatim**, `did_wba_binding` included: §8.2.3 hands the same
 * object to the caller that will put it in `group.e2ee.add` (§9.3.3), and the Group Host then
 * checks the binding it carries — so anything this service normalized away would change what
 * every party downstream is verifying.
 *
 * `state` is `available` | `reserved` | `consumed` (§8.2.4 L765–770). Unlike P5's OPK pool
 * there IS a third state, because the transition into `consumed` is triggered by something
 * this service does see: an accepted `group.e2ee.add` carries the KeyPackage inline, so the
 * Host can name the row (e2ee-group.md §4).
 *
 * `reservedTo` / `reservedAt` are not bookkeeping for the reservation's own sake — §8.2.4
 * L769 needs to be able to say which caller took this one, so that a second `add` cannot
 * quietly reuse it.
 */
export interface StoredGroupKeyPackage {
  ownerDid: string
  ownerDeviceId: string
  keyPackageId: string
  packageJson: string
  state: string
  publishedAt: string
  reservedTo?: string
  reservedAt?: string
}

/**
 * One row of P6 §11.10.3 L1372's public projection: which `(did, device)` is a leaf, on which
 * `crypto_group_id` and `epoch`.
 *
 * This is the Host's ONLY group-cryptography-side state and it holds no material that could
 * take part in a computation (§11.11 L1386 — the Host does not judge whether a Commit is
 * valid). Every row is the conclusion of one accepted control action.
 *
 * `state = terminal` rows are KEPT after a Remove: §10.3 L1066's trigger asks whether that
 * exact device currently has NO leaf, and deleting the row would erase the difference between
 * a first join and a re-join (e2ee-group.md §11).
 */
export interface StoredGroupLeaf {
  groupDid: string
  memberDid: string
  memberDeviceId: string
  cryptoGroupId: string
  epoch: string
  /** `active` | `terminal`. */
  state: string
  /** Which accepted action established it, serialized. */
  addedByRefJson: string
  updatedAt: string
}

/**
 * P6 §10.5's orchestration progress for one group, at most one row per `group_did`.
 *
 * §11.10.3 L1374 says outright that this is NOT new protocol-level membership state — but it
 * has to be on disk, or a restart cannot tell where the pause got to (e2ee-group.md §8).
 */
export interface StoredGroupDidUpdate {
  groupDid: string
  /** The identity of the P4 `member-did-updated` being carried out: its `group_state_ref`
   *  (`group_did` + `group_state_version`) **and** the two DIDs, serialized. The DIDs are in
   *  here rather than being re-derived because §10.5 needs them on every step of the
   *  orchestration — the new DID to recognise the Adds that belong to it, the old one to
   *  refuse a Remove aimed anywhere else. */
  eventRefJson: string
  /** `add-pending` | `remove-pending`. Flips to `remove-pending` on the first accepted
   *  Remove, which §10.5 makes the observable end of the Add phase: it forbids a Remove
   *  before every selected Add has succeeded, and the Host cannot count the owner's Adds. */
  progress: string
  /** The exact `(did, device)` pairs still to do, serialized. For a DID update that is the
   *  old DID's leaves — the Removes that retire it. */
  expectedJson: string
  /** The ones already done, serialized. */
  doneJson: string
  startedAt: string
}

/**
 * One queued P6 envelope (P6 §12.6), for exactly one recipient device.
 *
 * The queue is a DELIVERY mechanism, not group history (§12.6 L1523): a row exists only
 * while the envelope has not been transport-confirmed, and there is no `state` column
 * because "here" and "not here" is the whole of its state.
 *
 * `envelopeJson` is the envelope **verbatim** — §12.6 requires a re-delivery to reproduce
 * `meta.message_id` / `operation_id` / `content_type`, the ordering fields, `group_receipt`,
 * a preserved `auth` and `body` losslessly, and forbids re-addressing, merging, splitting,
 * reordering or renumbering. `originContextJson` is the extra P6 `group.incoming` carries
 * (§13.6 L1665: freshness and validity are judged differently at submission and at delivery).
 */
export interface StoredDeviceEnvelope {
  recipientDid: string
  recipientDeviceId: string
  /** Position in THIS device's queue. §12.6 orders a device's queue by `group_event_seq`
   *  (and a `commit-delivery` by epoch), which enqueue order already is. */
  seq: number
  groupDid: string
  /** `incoming` | `commit` | `welcome` | `final-notice`. Not taxonomy: §6.1's ordering
   *  table lets a `welcome-delivery` overtake the pending application envelopes, and only it. */
  kind: string
  envelopeJson: string
  originContextJson?: string
  attempts: number
  nextAttemptAt: string
  lastError?: string
  enqueuedAt: string
}

/**
 * One published PreKey Bundle (P5 §7.1 L467), one row per `(owner_did, owner_device_id)`.
 *
 * `bundleJson` is the `body.prekey_bundle` object **verbatim**, `proof` included: §7.2 hands
 * the same object back out and the sender re-verifies it (§6.5), so anything this service
 * normalized away would change what the sender is checking. The service never reads inside
 * it.
 *
 * One row per device rather than a history: §7.3 L592 returns "the latest" bundle, and
 * §6.2.2 L371's uniqueness rule is checked against the row already here (see
 * `upsertPrekeyBundle`).
 */
export interface StoredPrekeyBundle {
  ownerDid: string
  ownerDeviceId: string
  bundleId: string
  bundleJson: string
  publishedAt: string
}

/**
 * One one-time prekey in a device's pool (P5 §6.6).
 *
 * `state` is `available` | `assigned`, and `assigned` is TERMINAL. §6.6 L849 asks for a
 * second transition on session setup (`consumed`), but that happens between the two callers
 * and this service is not on that path — so it would be a state nothing ever writes, which
 * is why there is not one (e2ee-direct.md §2).
 *
 * `assignedTo` is not bookkeeping for idempotency — that is the `idempotency` table's job.
 * It is the only record of which sender received this key, which §6.6 needs to be able to
 * say when a key shows up in two sessions.
 */
export interface StoredOneTimePrekey {
  ownerDid: string
  ownerDeviceId: string
  keyId: string
  publicKeyB64u: string
  state: string
  /** The DID the key was handed to, on the `get_prekey_bundle` that took it. */
  assignedTo?: string
  assignedAt?: string
  uploadedAt: string
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

/**
 * One line of somebody's address book (TODO6 §3, `x_agentx.contacts.v1`).
 *
 * `subject` is the stable identity and `did` is where that identity currently lives — the
 * pair is the whole point of the table (TODO6 §3.2). A key update moves the DID and leaves
 * the subject where it was, so keying a remark on the DID would make it vanish at exactly
 * the moment the two names come apart; a row is therefore re-`put` under the same subject
 * with the new DID, and `remark` survives because nothing looked at `did` to find it.
 *
 * `remark` is the name the OWNER gave this peer — not `nickname`, which the peer gives
 * itself and which lives on its own DID host. It is nullable: adding somebody before
 * naming them is a normal state.
 */
export interface StoredContact {
  ownerDid: string
  /** core's `subjectOf(did)` — the protocol's "this is still the same party". Not
   *  `stableSubjectId`, which throws on anything but `did:wba`: the RPC layer derives this
   *  from a caller-supplied DID, and a total function is what keeps an odd DID from being a
   *  500. */
  subject: string
  /** Where that subject currently lives. A column, never a key. */
  did: string
  remark?: string
  createdAt: string
  updatedAt: string
}

/**
 * One group's name, as one owner calls it (TODO6 §4.2, `x_agentx.group_remarks.v1`).
 *
 * The sibling of {@link StoredContact}, and deliberately not the same table. A contact is a
 * peer this owner can `msg send` to — an `agent` target. A group is `group`-addressed, and
 * its own name already exists: `group_profile.display_name`, on the group's host, changed by
 * `group.update_profile`, and visible to **every** member. What is stored here is the
 * contrary thing: the name only this owner sees.
 *
 * **`group_did` is the key where a contact keys on `subject`**, and the difference is real
 * rather than an oversight. An agent DID embeds a key fingerprint, so `did update` moves it —
 * which is why a remark hung on it would vanish and why the address book keys on the stable
 * subject instead (§3.2). A group DID is `did:web:…:g:<id>` in the service's own namespace;
 * it carries no fingerprint and does not move, and `subjectOf` returns it unchanged. Wrapping
 * it in a `subject` would be a column a reader has to check is an identity.
 *
 * `remark` is **not** optional here, unlike a contact's. Nothing but a deliberate naming
 * creates one of these rows: there is no traffic path that teaches an owner a group's name
 * (the owner already sees the group's real name in `group.get_info`), so a row without a
 * remark would not be a state, it would be a bug. Clearing a name drops the row.
 */
export interface StoredGroupRemark {
  ownerDid: string
  groupDid: string
  /** What this owner calls the group. Never empty — see the type comment. */
  remark: string
  createdAt: string
  updatedAt: string
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
 * Who sees which delivery: `recipient_device_id IS NULL OR recipient_device_id = ?`.
 *
 * This is P5 §10.7.1 L1407 read as a **read-side** rule as well as a push-side one. A
 * `direct.send` in v2 puts a ciphertext in the mailbox of exactly one device; handing that
 * row to a request that stands for a different device — or for no device at all — is the
 * fan-out that clause forbids, and it is worse here than on the live path because the
 * reader gets to keep it.
 *
 * `''` ("no device declared") therefore sees only the account-addressed rows, which is the
 * same rule the live subscription applies (`stream/registry.ts` 的 `reaches`). One rule for
 * both halves of one mailbox: `sync.delta` replays what the stream would have pushed, so a
 * divergence here would make catch-up and live disagree about what this device was sent.
 *
 * A P3 message has no recipient device and is addressed to the account, so every device
 * still receives it — §7.2.3 L421 wants exactly that.
 *
 * Takes the table alias rather than being a constant: three of the four queries alias the
 * table, and a predicate pasted next to `d.` would read as `d.(…)` — a syntax error that
 * only shows up at prepare time.
 */
export function deviceFilter(alias: string): string {
  return `(${alias}.recipient_device_id IS NULL OR ${alias}.recipient_device_id = ?)`
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
  /** The owner's deliveries after `since`, in order, **for `deviceId`** — `''` means no
   *  device was declared, so only the account-addressed rows come back (see
   *  {@link deviceFilter}). `limit` bounds one page.
   *
   *  `notBefore` is the read window's floor: rows accepted strictly before it are not
   *  answered. `undefined` means no floor at all, which is what the storage layer's own
   *  tests and the mailbox readers that are not the pickup surface want — the floor is a
   *  **policy of the caller** (`config.deliveryReadWindowMs`, applied by
   *  `rpc/inbox.ts`), not a property of what this table holds. Nothing is ever deleted
   *  from `deliveries`; a row outside the window is still there, it is just not handed
   *  out.
   *
   *  The window is a **prefix** of the sequence, not a scatter: `seq` is assigned by
   *  appending and `accepted_at` is that same request's instant, so a row the caller may
   *  not see is followed only by rows it may. That is what lets a client's cursor walk
   *  into the window and stay there — see {@link next_since} in `readDelta`. */
  deliveriesSince(
    ownerDid: string,
    deviceId: string,
    since: number,
    limit: number,
    notBefore: string | undefined,
  ): DeliveryRecord[]
  /** The highest sequence this owner has, whether or not a device has read it. */
  headSeq(ownerDid: string): number
  /** How far this device has been advanced. 0 when it has never read. */
  cursor(ownerDid: string, deviceId: string): number
  /** Advance a device's cursor. Never backwards: a stale replay must not un-read mail. */
  advanceCursor(ownerDid: string, deviceId: string, seq: number): void

  /** The DID this account's mailbox was last seen filed under, keyed by the stable
   *  subject path (`subjectOf`). `undefined` means this service has never seen the
   *  subject act as itself — which is what every account starts at, and also what a
   *  non-`did:wba` identity that never rotates into a new DID stays at forever.
   *  See `account_dids` in `schema.ts` and `rpc/ownerDidUpdate.ts`. */
  accountDid(subject: string): string | undefined
  /** Record that this subject just acted as `did`. Called for every self-addressed
   *  authenticated request, so the row is the service's memory of "who this account is
   *  now" — the starting point the rotation check needs. `at` is the request's instant. */
  rememberAccountDid(subject: string, did: string, at: string): void

  /**
   * Re-file an owner's mailbox under a new DID (TODO7 §3 第 4 条, 用户 2026-10-03 裁定).
   *
   * Moves `deliveries` / `delivery_cursor` / `device_envelopes` / `message_reads` from
   * `fromDid` to `toDid` in one transaction. **Nothing is deleted** — the §7 retention
   * contract is about rows, and a row that changes hands is still the same row.
   *
   * Sequence numbers are the delicate part. `deliveries.seq` is per `(owner_did)`, so the
   * two namespaces each start at 1 and moving one into the other would collide on the
   * primary key. `toDid`'s rows are therefore shifted **above** everything `fromDid` has
   * first: the older mail keeps the numbers a client's cursor may already point at (so a
   * catch-up after rotation neither skips nor rewinds), and the mail that arrived after the
   * rotation lands after it. `device_envelopes` gets the same treatment with its own
   * per-`(did, device)` head; `delivery_cursor` merges by `MAX` on a per-device conflict.
   *
   * Returns how many deliveries changed hands, which is the number worth logging.
   */
  migrateOwner(fromDid: string, toDid: string): number

  /** The group row, or `undefined` if this service hosts no such group. */
  group(groupDid: string): StoredGroup | undefined
  /** Write a new group. The counters are given rather than derived: `group.create` starts
   *  them at 1/1 (§6.2 L237), and that is a decision of the operation, not of the store. */
  insertGroup(group: StoredGroup): void
  /** The group's own signing key, or `undefined` if this service hosts no such group.
   *
   *  Every group created from v11 on has one; a group created by an older build does not,
   *  and the callers that need to SIGN (the DID document of B1b-A2, the receipt proof of
   *  B1b-A5) treat that absence as "this group cannot be proved about" rather than as a
   *  reason to mint one late — a key minted after the fact would not be the key any earlier
   *  statement was made under. */
  groupSigningKey(groupDid: string): StoredGroupSigningKey | undefined
  /** Write a group's signing key. Called from `group.create` in the same transaction as
   *  {@link Storage.insertGroup}, which is the whole point: a group row without its key has
   *  no recovery path (B1b-A1). The primary key makes a second insert for one group collide
   *  instead of replacing the identity it was created with. */
  insertGroupSigningKey(row: StoredGroupSigningKey): void
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

  /** The active members whose DID has not been checked since `before`, oldest first, never
   *  checked at all ahead of those — the periodic DID refresh's batch (A3c-4).
   *
   *  Ordered by the stored stamp and then by `(group_did, member_did)`, so consecutive ticks
   *  walk the whole roster without favouring anyone and without depending on scan order. */
  groupMembersDueForDidCheck(before: string, limit: number): StoredGroupMember[]
  /** Record that the refresh looked at this row. Written even when the check failed, or an
   *  unreachable peer's DID would sit at the head of the queue forever. */
  markGroupMemberDidChecked(groupDid: string, memberDid: string, at: string): void

  /** Rename an active member's DID in place — §8.12's "replace only the current `agent_did`".
   *
   *  Returns `false` when no row matched `(groupDid, fromDid)`: that is the compare-and-swap
   *  §8.12 item 5 requires. A second trigger — the periodic sweep racing a request — finds
   *  nothing left to rename, and the caller reads that as "already done" rather than as an
   *  error, which is what makes the deterministic operation id converge.
   *
   *  Only `member_did` and `state_version` are written. `role`, `membership_status`,
   *  `joined_at` and `added_by` therefore survive **by construction** rather than by being
   *  copied across, and a copy is a place the next edit can silently drop one of them.
   *
   *  The **Leaf projection is deliberately left alone**. `group_leaves` says which `(did,
   *  device)` currently holds an MLS leaf, and only `group.e2ee.add` / `remove` change that —
   *  so renaming those rows here would assert leaves under the new DID before the owner ever
   *  Added them. Two things break if it does: `group.e2ee.send` would stop looking paused
   *  (§10.5's gate is "an active leaf whose DID is no longer an active member"), and the next
   *  `group.incoming` would be addressed to a device that holds no MLS state for the group.
   *  The old DID's leaves are retired by the P6 orchestration, not by this rename.
   *
   *  A non-active row already sitting on the new DID is removed first: §8.12 item 4 only
   *  forbids the new DID belonging to another *active* member, so a stale `removed` row is
   *  legal input, and without this the rename would collide on the primary key instead of
   *  converging. An **active** row on the new DID is a code error — the caller checked for it
   *  — and throws rather than deleting a live membership to make room for this one. */
  renameGroupMember(groupDid: string, fromDid: string, toDid: string, stateVersion: number): boolean

  /** Append one `group.state_changed` event. `eventSeq` is the value
   *  {@link Storage.advanceGroupCounters} just returned, which is what makes the events
   *  table an ordered replay source even though its sequence numbers are not contiguous
   *  (group messages take numbers without leaving an event row). */
  appendGroupEvent(event: StoredGroupEvent): void

  // ---- E2EE key material (P5, C12) -------------------------------------------
  //
  // Two of the three surfaces P5 §7 defines. The third — `direct.send` carrying ciphertext
  // — is not here at all: the service stores opaque bytes in `messages`/`deliveries` and
  // never touches key material for it.

  /** The device's current bundle, or `undefined` if it never published one. */
  prekeyBundle(ownerDid: string, ownerDeviceId: string): StoredPrekeyBundle | undefined
  /** Write the device's bundle, replacing the row it had.
   *
   *  Replacing is right because §7.3 L592 returns the latest one, and because §6.2.2 L371's
   *  rule is about the ACCEPTING WINDOW, not about history: an old bundle carrying a
   *  redefined `bundle_id` stops mattering the moment the device publishes a new row —
   *  which is exactly what §6.5's re-verification by the sender would do too.
   *
   *  The uniqueness check itself (`bundle_id` → the six fields, §6.2.2 L371) is the caller's,
   *  against {@link Storage.prekeyBundle}: it needs to compare six fields of the stored JSON
   *  and then produce a 4001, neither of which belongs in a row accessor. */
  upsertPrekeyBundle(bundle: StoredPrekeyBundle): void

  /** Add prekeys to a device's pool, and return how many were actually NEW.
   *
   *  `key_id` is chosen by the publisher (§6.4 L401), so a re-upload of the same id is
   *  expected: it is ignored rather than overwritten — first writer wins, or a later upload
   *  could replace a public key that has already been handed to a sender. The count is what
   *  `published_opk_count` reports (§7.1 L497), so it must be the rows that landed, not the
   *  length of the argument. */
  insertOneTimePrekeys(keys: readonly StoredOneTimePrekey[]): number

  /** Take the oldest `available` prekey from the device's pool and mark it assigned in the
   *  same call, returning it. `undefined` when the pool is dry.
   *
   *  One accessor rather than a read plus a write, because §6.6 L847 forbids handing one
   *  prekey to two senders: the claim is the conditional UPDATE, and only the caller that
   *  moved the row out of `available` gets to return it. Inside an operation's transaction
   *  (`BEGIN IMMEDIATE`) the two statements cannot be split; called on its own by two
   *  processes, at most one of them sees `changes > 0`. */
  claimOneTimePrekey(
    ownerDid: string,
    ownerDeviceId: string,
    assignedTo: string,
    assignedAt: string,
  ): StoredOneTimePrekey | undefined

  /** How many prekeys are still `available`. `require_opk` (§7.2 L479) is answered from
   *  this, not from a claim that has already taken one. */
  availableOneTimePrekeys(ownerDid: string, ownerDeviceId: string): number

  // ---- P6 group E2EE (C13) ---------------------------------------------------
  //
  // Three surfaces: the KeyPackage cabinet (§8), the leaf projection (§11.10.3 L1372) and
  // the Device Delivery Queue (§12.6). The first is P5's pool with a third state; the
  // second and third are new here.

  /** One published KeyPackage, or `undefined` if this device never published that id. */
  groupKeyPackage(ownerDid: string, ownerDeviceId: string, keyPackageId: string): StoredGroupKeyPackage | undefined
  /** Add a KeyPackage to the device's cabinet. A re-publish of the same `key_package_id`
   *  is IGNORED rather than applied.
   *
   *  Ignoring is what keeps a consumed package consumed: §13.2 L1610 allows a consumed
   *  KeyPackage back into circulation only under a deployment's explicit last-resort
   *  declaration, so a second publish of the same id must not resurrect it — and the same
   *  property keeps a package already handed to a caller from changing under it. */
  insertGroupKeyPackage(entry: StoredGroupKeyPackage): void
  /** This device's `available` packages, in publish order (oldest first).
   *
   *  A list rather than a count because the caller has to look inside the objects to answer
   *  §8.2.4 L763's "SHOULD return an unexpired one": `expires_at` is a field of the
   *  KeyPackage, and a payload column is opaque bytes to this store — whoever needs a field
   *  inside one parses it, rather than the store reaching in with `json_extract`. */
  availableGroupKeyPackages(ownerDid: string, ownerDeviceId: string): StoredGroupKeyPackage[]
  /** Take one named `available` package and mark it `reserved` in the same call, returning
   *  whether THIS call took it.
   *
   *  §8.2.4 L767 makes the reservation a MAY; taking it anyway is what stops two concurrent
   *  `group.e2ee.add` operations from being handed the same KeyPackage (L769). The claim is
   *  a conditional UPDATE, so only the caller that moved the row out of `available` wins —
   *  same shape as `claimOneTimePrekey`, and for the same reason. */
  claimGroupKeyPackage(
    ownerDid: string,
    ownerDeviceId: string,
    keyPackageId: string,
    reservedTo: string,
    reservedAt: string,
  ): boolean
  /** Mark a package `consumed` (§8.2.4 L769).
   *
   *  Three outcomes rather than a boolean because the caller has to tell them apart: a
   *  package this service never issued cannot be called consumed (nothing proves it was),
   *  while one already consumed must be refused with `group.e2ee.key_package_consumed`. */
  markGroupKeyPackageConsumed(
    ownerDid: string,
    ownerDeviceId: string,
    keyPackageId: string,
  ): 'missing' | 'consumed' | 'already-consumed'

  /** One leaf of the public projection, or `undefined`. A `terminal` row still answers. */
  groupLeaf(groupDid: string, memberDid: string, memberDeviceId: string): StoredGroupLeaf | undefined
  /** The group's `active` leaves, in a stable order (by member DID, then device). This is
   *  who a `group.e2ee.notice` has to be fanned out to. */
  activeGroupLeaves(groupDid: string): StoredGroupLeaf[]
  /** Write the projection row for one `(member_did, member_device_id)`.
   *
   *  A re-join overwrites the `terminal` row it had: the distinction between first join and
   *  re-join is consumed by the Add that makes it, and keeping both rows would make "is this
   *  device currently a leaf" a question with two answers. */
  upsertGroupLeaf(leaf: StoredGroupLeaf): void

  /** The DID-update orchestration in progress for this group, or `undefined` when there is
   *  none — which is the normal state. */
  groupDidUpdate(groupDid: string): StoredGroupDidUpdate | undefined
  upsertGroupDidUpdate(row: StoredGroupDidUpdate): void
  /** Drop the row once the last step succeeded (§10.5 L1094). */
  clearGroupDidUpdate(groupDid: string): void

  /** Append one envelope to a device's queue and return its position in it.
   *
   *  The position is assigned here because §12.6 orders a device's queue by
   *  `group_event_seq` (and commits by epoch), which is enqueue order: assigning it
   *  anywhere else would let two transactions interleave into a queue that is not sorted. */
  enqueueDeviceEnvelope(envelope: Omit<StoredDeviceEnvelope, 'seq'>): number
  /** Envelopes that may be delivered now, ordered by `(recipient_did, recipient_device_id,
   *  seq)` — the queue's own order, so a caller walking it in order walks each device's
   *  queue in order, and each queue only ever yields its head first.
   *
   *  A queue whose head is not due (it failed and was rescheduled) contributes **nothing**,
   *  even though its later rows are due: §12.6 requires `group.incoming` in `group_event_seq`
   *  order, so the head blocks its queue. Handing those later rows back would be handing the
   *  caller a delivery it is forbidden to make, and would let one stalled device crowd out
   *  every other queue's work inside the same `limit`. */
  dueDeviceEnvelopes(now: string, limit: number): StoredDeviceEnvelope[]
  rescheduleDeviceEnvelope(
    recipientDid: string,
    recipientDeviceId: string,
    seq: number,
    attempts: number,
    nextAttemptAt: string,
    lastError: string,
  ): void
  /** Drop an envelope that was delivered, or one that hit the retention bound. */
  dropDeviceEnvelope(recipientDid: string, recipientDeviceId: string, seq: number): void

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

  // ---- address book (TODO6 §3) -----------------------------------------------
  //
  // A row layer, and nothing more: name matching — how `contacts resolve Alice` picks a row,
  // and what it does when two rows answer to "Alice" — belongs to the caller that knows what
  // a name is. Doing a `LIKE` here would put half of that rule in SQL, where the "list the
  // candidates" half cannot live.

  /** Every row of `ownerDid`'s address book, ordered by subject.
   *
   *  The whole book rather than a lookup: a person's address book is small, and the client
   *  has to hold it anyway to answer "which of these is Alice" — a per-name round trip would
   *  be one network call per keystroke of an agent's reasoning. */
  contacts(ownerDid: string): StoredContact[]
  /** Insert or replace one row, returning it **as stored**. The key is
   *  `(ownerDid, subject)`, so this is how a row's `did` is brought up to date after a key
   *  update; `createdAt` is written only by the insert and kept by every later write, which
   *  is why the answer comes back rather than being assumed — the caller cannot know which
   *  of the two happened without asking. */
  upsertContact(contact: StoredContact): StoredContact
  /** Learn a peer from traffic (TODO6 §3.3 write path ②): create the row if this owner has
   *  never seen this subject, and otherwise move `did` to the one just seen — a key update
   *  is thus picked up the next time the peer writes.
   *
   *  **`remark` is never touched, and that is the whole reason this is not `upsertContact`.**
   *  `contacts.put`'s rule is "absent means clear"; a message arriving is not the user
   *  saying anything about the name, so applying that rule here would erase a name the user
   *  chose, the first time the named peer writes again. `createdAt` is likewise kept.
   *
   *  `at` stamps both columns on the insert; on the update only `updated_at` moves. */
  rememberContact(contact: { ownerDid: string; subject: string; did: string; at: string }): void
  /** Drop one row. Returns whether one was there, so `contacts.remove` can answer honestly
   *  instead of reporting success for a no-op. */
  removeContact(ownerDid: string, subject: string): boolean

  // ---- the address book's other half: groups (TODO6 §4.2) ----------------------
  //
  // Same shape of accessor and the same reasoning about where name matching lives: nothing
  // here decides anything about names, it moves rows.

  /** Every group `ownerDid` has named, ordered by `group_did`.
   *
   *  The whole table rather than a lookup for the reason {@link Storage.contacts} gives: it is
   *  small, and `group info` needs it in one piece to answer "what did I call this one". */
  groupRemarks(ownerDid: string): StoredGroupRemark[]
  /** Insert or replace one row, returning it **as stored**.
   *
   *  There is no `rememberGroupRemark` counterpart to `rememberContact`: a group's name is
   *  never learned from traffic, so the only writer is the owner naming it. `createdAt` is
   *  written only by the insert and kept by every later write, which is why the answer comes
   *  back rather than being assumed. */
  upsertGroupRemark(remark: StoredGroupRemark): StoredGroupRemark
  /** Drop one row, i.e. forget the name. Returns whether one was there. */
  removeGroupRemark(ownerDid: string, groupDid: string): boolean

  close(): void
}
