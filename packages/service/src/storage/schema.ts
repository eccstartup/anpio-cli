// The database shape, from message-service.md §7.
//
// Written as statements rather than as one blob so that a table can be pointed at by
// name in a test and so that the reason for a non-obvious column can sit next to it.
//
// §7 is labelled 草案 in the design document, and two of its statements are corrected
// below; each carries its reason rather than being folded in silently.

/** Bumped when a statement below changes in a way that existing files cannot absorb.
 *  Stored in SQLite's own `user_version`, so a file written by a later build is
 *  recognisable as such. The step from one version to the next lives in `sqlite.ts`,
 *  next to the code that decides whether to run it.
 *
 *  v2: `messages` gained a composite primary key and `outbox` traded a pinned endpoint
 *  for the recipient's DID. Neither is an in-place change for SQLite.
 *
 *  v3: `message_reads` is new. It needs no migration step of its own — an
 *  `IF NOT EXISTS` table is exactly what the top-up pass in `applySchema` is for — but
 *  the version still has to move: without it a file written by v2 would return early
 *  from `applySchema` and never get the table.
 *
 *  v4: `group_members` gains `joined_at` / `added_by` (P4 §7.2 L379–380 — they are part of
 *  the `group_member` object `group.get_info` returns), and `messages` gains the two
 *  position columns a group message has to be able to report (see the table below). All
 *  four are nullable, so `ALTER TABLE ADD COLUMN` is enough and no table has to be
 *  rebuilt. */
export const SCHEMA_VERSION = 4

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
  //
  // 主键是 §8.2 L444–450 给消息级重复识别定义的那个三元组，**不是** `message_id` 单列。
  // 那个标识是发送方自己起的（P1 §6.2.7 L402），两个发送方撞上同一个是合法的；P5
  // L1398 更让一条逻辑消息对每台接收设备各带一个外层 `message_id`。只拿它当主键，
  // 第二次插入就会被约束拒掉——一个本该正常受理的请求变成 500。
  //
  // 末尾两列只有群消息写：`group.send` 的**消息级**重复识别（P4 §10.3 L1046–1052）要
  // 把一条早已收下的消息报回去，而那个响应 **MUST** 带 `group_event_seq` 与
  // `group_state_version`（§8.9.4 L868–875），且后者是"该消息被接受时所属的群状态快照"
  // （§6.2 L239）——不是重放那一刻的。快照只能从受理那一刻存下来，事后再算必然算成
  // 当前的。私聊消息两列为 NULL。
  `CREATE TABLE IF NOT EXISTS messages (
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
     group_event_seq     INTEGER,
     group_state_version INTEGER,
     PRIMARY KEY (sender_did, target_did, message_id)
   )`,
  `CREATE INDEX IF NOT EXISTS messages_target ON messages (target_did, accepted_at)`,
  // 取件面按"我发出去的"这一侧翻页用的就是这一条。
  `CREATE INDEX IF NOT EXISTS messages_sender ON messages (sender_did, accepted_at)`,

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

  // ---- read state ------------------------------------------------------------
  // 已读：**不是**交付游标（realtime.md §6 用一整节把这两件事分开）。游标说"这台设备
  // 收到哪儿了"，由 ack 推进；这张表说"某个信箱主人处理过哪条消息"，由取件面显式标记。
  // 两者混成一处就会出现"客户端断了没 ack，消息显示成未读"这类永远说不清的状态。
  //
  // 键是 (owner_did, message_id) 而不是交付序号：发件人自己那一侧没有交付行
  // （`deliveries` 只收件人一份），而 `inbox.get` 两个方向都返回，得有一个两边都有的
  // 标识符。`message_id` 由发送方起（P1 §6.2.7 L402），两个发送方可能撞名——所以键里
  // 必须有 `owner_did`，它把撞名限定在一个信箱内部，而同一信箱里同名的两条消息本来就
  // 是同一条（§8.2 L444–450 认的就是这个）。
  `CREATE TABLE IF NOT EXISTS message_reads (
     owner_did   TEXT NOT NULL,
     message_id  TEXT NOT NULL,
     read_at     TEXT NOT NULL,
     PRIMARY KEY (owner_did, message_id)
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
     joined_at          TEXT,
     added_by           TEXT,
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
  //
  // 存的是收件人的 **DID**，不是解析出来的 endpoint：endpoint 由 locator 从 DID 现推，
  // 而重试必须重新推一遍（域可能已经换了入口服务），把写入那一刻的答案钉在行里，
  // 重试就是往一个可能早就失效的地址重发。
  `CREATE TABLE IF NOT EXISTS outbox (
     seq              INTEGER PRIMARY KEY AUTOINCREMENT,
     recipient_did    TEXT NOT NULL,
     payload_json     TEXT NOT NULL,
     attempts         INTEGER NOT NULL DEFAULT 0,
     next_attempt_at  TEXT NOT NULL,
     last_error       TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS outbox_due ON outbox (next_attempt_at)`,
]
