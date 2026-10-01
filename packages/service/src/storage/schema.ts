// The database shape, from message-service.md §7.
//
// Written as statements rather than as one blob so that a table can be pointed at by
// name in a test and so that the reason for a non-obvious column can sit next to it.
//
// §7 is labelled 草案 in the design document, and two of its statements are corrected
// below; each carries its reason rather than being folded in silently.

/** Bumped when a statement below changes in a way that existing files cannot absorb.
 *  Stored in SQLite's own `user_version`, so a file written by a later build is
 *  recognisable as such. */
export const SCHEMA_VERSION = 1

export const SCHEMA: readonly string[] = [
  // ---- idempotency -----------------------------------------------------------
  // 幂等台账：先查这张表，再谈其他 (P1 §9.2 L650: the server checks the operation-level
  // record BEFORE the message-level one).
  //
  // §7's draft spells this as five columns plus a composite primary key, and that shape
  // cannot hold the scope §9.1 defines: L635–637 makes `target_scope` Profile-defined
  // (so a `target_kind`/`target_did` pair is a re-derivation of something core already
  // computes), and L639 puts every device selector of a device-addressed overlay into the
  // scope as well — a variable-length list, which is not a column. The key is therefore
  // core's `idempotencyKey()` string; see `IdempotencyRow` for why only one definition of
  // the scope may exist.
  `CREATE TABLE IF NOT EXISTS idempotency (
     key            TEXT PRIMARY KEY,
     fingerprint    TEXT NOT NULL,
     response_json  TEXT NOT NULL,
     created_at     TEXT NOT NULL
   )`,

  // ---- messages --------------------------------------------------------------
  // 私聊消息：明文 P3 与密文 P5 同一张表，靠 security_profile 区分。The service never
  // reads `body_json`; for P5/P6 it is opaque bytes by construction.
  `CREATE TABLE IF NOT EXISTS messages (
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
   )`,
  `CREATE INDEX IF NOT EXISTS messages_target ON messages (target_did, accepted_at)`,

  // ---- deliveries ------------------------------------------------------------
  // NOT in §7's draft, and needed: the cursor below is a monotonic sequence per
  // (owner, device), and §7's `messages` has no sequence column at all. A group message
  // is one `message_id` delivered to N members, so the sequence cannot live on the
  // message row — one row per recipient delivery is the only shape that can carry it.
  // This is also what `sync.delta` replays (realtime.md §6) and what `inbox.get` pages.
  `CREATE TABLE IF NOT EXISTS deliveries (
     owner_did    TEXT NOT NULL,
     seq          INTEGER NOT NULL,
     message_id   TEXT NOT NULL,
     method       TEXT NOT NULL,
     params_json  TEXT NOT NULL,
     accepted_at  TEXT NOT NULL,
     PRIMARY KEY (owner_did, seq)
   )`,
  `CREATE INDEX IF NOT EXISTS deliveries_message ON deliveries (message_id)`,

  // ---- delivery cursor -------------------------------------------------------
  // 取件扩展面用的游标，每 (owner_did[, device]) 一条单调递增序号。`device_id` is
  // part of the identity rather than a column that is always the empty string: one
  // owner reaches its mailbox from several devices and each keeps its own position
  // (realtime.md §5.4).
  `CREATE TABLE IF NOT EXISTS delivery_cursor (
     owner_did  TEXT NOT NULL,
     device_id  TEXT NOT NULL DEFAULT '',
     last_seq   INTEGER NOT NULL DEFAULT 0,
     PRIMARY KEY (owner_did, device_id)
   )`,

  // ---- groups ----------------------------------------------------------------
  // 群：Host 维护线性顺序，两个单调量都在这。Both counters are what §8 orders events
  // by and what P4 puts in every group response.
  `CREATE TABLE IF NOT EXISTS groups (
     group_did            TEXT PRIMARY KEY,
     host_service_did     TEXT NOT NULL,
     group_state_version  INTEGER NOT NULL,
     group_event_seq      INTEGER NOT NULL,
     group_profile_json   TEXT NOT NULL,
     group_policy_json    TEXT NOT NULL,
     created_at           TEXT NOT NULL,
     creator_did          TEXT NOT NULL
   )`,
  `CREATE TABLE IF NOT EXISTS group_members (
     group_did          TEXT NOT NULL,
     member_did         TEXT NOT NULL,
     role               TEXT,
     membership_status  TEXT NOT NULL,
     state_version      INTEGER NOT NULL,
     PRIMARY KEY (group_did, member_did)
   )`,
  // group.state_changed 的可重放来源。
  `CREATE TABLE IF NOT EXISTS group_events (
     group_did     TEXT NOT NULL,
     event_seq     INTEGER NOT NULL,
     event_type    TEXT NOT NULL,
     payload_json  TEXT NOT NULL,
     occurred_at   TEXT NOT NULL,
     PRIMARY KEY (group_did, event_seq)
   )`,

  // ---- E2EE ------------------------------------------------------------------
  // P5/P6: the service sees no plaintext and stores opaque bytes.
  `CREATE TABLE IF NOT EXISTS prekey_bundles (
     owner_did        TEXT NOT NULL,
     owner_device_id  TEXT NOT NULL,
     bundle_id        TEXT NOT NULL,
     bundle_json      TEXT NOT NULL,
     published_at     TEXT NOT NULL,
     PRIMARY KEY (owner_did, owner_device_id)
   )`,
  `CREATE TABLE IF NOT EXISTS group_key_packages (
     owner_did        TEXT NOT NULL,
     owner_device_id  TEXT NOT NULL,
     key_package_id   TEXT NOT NULL,
     package_json     TEXT NOT NULL,
     state            TEXT NOT NULL,
     published_at     TEXT NOT NULL,
     PRIMARY KEY (owner_did, owner_device_id, key_package_id)
   )`,

  // ---- attachments (P7) ------------------------------------------------------
  // Object bytes and their digest only. `object_key` / `nonce` are not here: they travel
  // in the inner manifest of P5/P6 and never reach this service.
  `CREATE TABLE IF NOT EXISTS attachment_slots (
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
   )`,

  // ---- outbox ----------------------------------------------------------------
  // 出站：direct.incoming / group.* 推送的重试队列。
  `CREATE TABLE IF NOT EXISTS outbox (
     seq              INTEGER PRIMARY KEY AUTOINCREMENT,
     endpoint_uri     TEXT NOT NULL,
     payload_json     TEXT NOT NULL,
     attempts         INTEGER NOT NULL DEFAULT 0,
     next_attempt_at  TEXT NOT NULL,
     last_error       TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS outbox_due ON outbox (next_attempt_at)`,
]
