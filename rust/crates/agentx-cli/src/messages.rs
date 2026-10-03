//! The local message record: `messages.db`, the sibling of `mls/`.
//!
//! The shape is [client-messages.md](../../../../docs/design/client-messages.md) (TODO6 §7);
//! this file is that document's §2.1 write path and §3 schema. Three things in here are the
//! whole design, and each is a decision rather than an implementation detail:
//!
//! 1. **Two files, no shared transaction.** The MLS state is the crate's (`mls/`), this is
//!    ours, and "one group message arrived" moves both. The order is therefore a contract:
//!    the crate commits first, then the row, then — **in the same transaction as the row** —
//!    the local cursor. A crash between them leaves the cursor before the frame, so the
//!    service replays it on the next connect and `INSERT OR IGNORE` makes the second write a
//!    no-op. Reversing it (cursor first) loses the message silently.
//! 2. **The dedupe key is the protocol's identity**, `(conversation, sender, message_id)` —
//!    not local arrival. `message_id` is sender-scoped, so two senders may legitimately pick
//!    the same string; the service's own idempotency key carries the sender for the same
//!    reason. It is also what makes both kinds of replay (§5 #5 of the design) free.
//! 3. **The cursor is not the service's.** `sync_state.applied_seq` answers "what have I
//!    written down", `delivery_cursor` answers "what may the service stop replaying". They
//!    are different facts and are *supposed* to differ — the only rule is that this one is
//!    advanced first, which makes it a lower bound of the other.
//!
//! Nothing here is a key. The plaintext is (TODO4 §E): the file is 0600, there is no export
//! command, and the design's §5 #2 says backups of it are backups of the conversation.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::error::{AgentxError, Result};
use crate::group_receive::GroupEvent;
use crate::identity::{Identity, IdentityLocation};
use crate::message::listen::{ListenEvent, ListenView};

/// The file's name, beside `mls/` under the identity's own directory.
pub const MESSAGES_FILE: &str = "messages.db";

/// The schema this binary writes. Bumped when a migration is added, never reused.
pub const SCHEMA_VERSION: i64 = 1;

/// `<root>/<agent>/<profile>/messages.db`.
pub fn messages_path(location: &IdentityLocation) -> PathBuf {
    location.dir().join(MESSAGES_FILE)
}

/// Which conversation a row belongs to.
///
/// A surrogate id in the table, because the alternative — keying rows by the peer's DID
/// directly — would put the same string in every row and the same string twice in an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conversation {
    /// A direct message: the other agent's DID.
    Direct { peer_did: String },
    /// A group's DID, whether the message was E2EE or not.
    Group { group_did: String },
}

impl Conversation {
    fn kind(&self) -> &'static str {
        match self {
            Conversation::Direct { .. } => "direct",
            Conversation::Group { .. } => "group",
        }
    }

    fn peer_did(&self) -> &str {
        match self {
            Conversation::Direct { peer_did } => peer_did,
            Conversation::Group { group_did } => group_did,
        }
    }
}

/// Which way a message went. Both directions live in one table: a chat client shows both, and
/// a separate table would make every history read a union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Incoming => "in",
            Direction::Outgoing => "out",
        }
    }
}

/// One row to write.
#[derive(Debug, Clone)]
pub struct Record {
    pub conversation: Conversation,
    pub direction: Direction,
    /// Who sent it. Set for both directions — for an outgoing row this is *us*, which is why
    /// it is a field rather than something read off the conversation.
    pub sender_did: String,
    /// The sender's own id for this message (P3 §6 / P6 §7).
    pub message_id: String,
    pub content_type: Option<String>,
    /// §7.4's exactly-one-of, first arm.
    pub text: Option<String>,
    /// §7.4's second arm. Kept apart from `text` rather than pre-rendered: the distinction
    /// is the protocol's, and a record that flattened it could not be re-emitted faithfully.
    pub payload: Option<Value>,
    /// The delivery number. Incoming only — the service never tells a sender where its own
    /// message landed in the recipient's inbox.
    pub service_seq: Option<u64>,
    /// The service's own timestamp, when it gave one.
    pub accepted_at: Option<String>,
    /// P6 only: the group event number the service assigned (§12.5), **as the wire spells
    /// it** — a decimal string (§7.3, same as `anp.get_capabilities`' limits). The column is
    /// an INTEGER: the service's own `messages.group_event_seq` is one, because it has to
    /// *increment* it, and we need numbers to order by. `record` does the conversion and
    /// refuses a value that is not decimal.
    pub group_event_seq: Option<String>,
    /// P6 only: the group state version this row's ciphertext was encrypted against, off the
    /// cipher's `group_state_ref` (§12.5) and again a decimal string on the wire. Recorded so
    /// that the two local files can explain each other after one of them is restored from an
    /// older backup (design §3) — the crate's own stored epoch is not this number.
    pub group_state_version: Option<String>,
}

impl Record {
    /// An incoming direct or group message with the shape `msg listen` hands over.
    pub fn incoming(
        conversation: Conversation,
        sender_did: impl Into<String>,
        message_id: impl Into<String>,
    ) -> Record {
        Record {
            conversation,
            direction: Direction::Incoming,
            sender_did: sender_did.into(),
            message_id: message_id.into(),
            content_type: None,
            text: None,
            payload: None,
            service_seq: None,
            accepted_at: None,
            group_event_seq: None,
            group_state_version: None,
        }
    }

    /// A message this run sent, written **after** the service accepted it.
    ///
    /// `sender_did` is our own DID, and `message_id` is the `operation_id`: P1 §6.2.6 makes the
    /// sender choose both, which is what `--operation-id` exists to pin across a retry. The
    /// two body arms come from the caller because the two send paths hold them differently —
    /// `crate::message::payload_from` reads them back out of a P3/P4 request body, while P6's
    /// send path has the plaintext struct itself.
    ///
    /// `service_seq` stays `None` for the same reason it does on a received group frame: the
    /// service never tells a sender where its own message landed in the *recipient's* inbox.
    pub fn outgoing(
        conversation: Conversation,
        sender_did: impl Into<String>,
        message_id: impl Into<String>,
        content_type: impl Into<String>,
        text: Option<String>,
        payload: Option<Value>,
    ) -> Record {
        Record {
            conversation,
            direction: Direction::Outgoing,
            sender_did: sender_did.into(),
            message_id: message_id.into(),
            content_type: Some(content_type.into()),
            text,
            payload,
            service_seq: None,
            accepted_at: None,
            group_event_seq: None,
            group_state_version: None,
        }
    }
}

/// One identity's message record.
///
/// Holds the endpoint and device it is recording *for*, because those are what the local
/// cursor is keyed by (design §4.2). Neither is an argument to [`MessageStore::record`]: they
/// are properties of the store, and a row's `endpoint` — the namespace its delivery number is
/// in — is read from here rather than asked of the caller.
#[derive(Debug)]
pub struct MessageStore {
    conn: Connection,
    /// The inbox this record belongs to, as an origin (`scheme://host:port`).
    endpoint: String,
    owner_did: String,
    device_id: String,
}

impl MessageStore {
    /// Open (creating on first use) the record for one identity against one inbox.
    ///
    /// `endpoint` is the discovered `serviceEndpoint`, from which the **origin** is taken: the
    /// RPC path inside it is not part of which inbox this is.
    pub fn open(
        location: &IdentityLocation,
        identity: &Identity,
        endpoint: &str,
        device_id: &str,
    ) -> Result<MessageStore> {
        let path = messages_path(location);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                AgentxError::MessageInvalid(format!("creating {}: {err}", parent.display()))
            })?;
        }
        let conn = Connection::open(&path).map_err(|err| {
            AgentxError::MessageInvalid(format!("opening {}: {err}", path.display()))
        })?;
        let mut store = MessageStore {
            conn,
            endpoint: origin_of(endpoint),
            owner_did: identity.did.clone(),
            device_id: device_id.to_string(),
        };
        store.prepare()?;
        restrict_permissions(&path);
        Ok(store)
    }

    /// Open the file for **writing**, without resolving a service first.
    ///
    /// `msg read` is the caller: it writes one column and no delivery, so it needs neither an
    /// `endpoint` nor a `device_id`, and it must not go online to get them (design §8.1). The
    /// cursor those two key is untouched by such a write, which is why empty values here are
    /// not a lie about which inbox this is — [`record`](Self::record) is the only thing that
    /// reads them, and it is not called on this path.
    ///
    /// Creates the file if there is none, unlike [`open_read_only`](Self::open_read_only):
    /// "mark everything read" over a record that does not exist yet is a write of zero rows,
    /// not a missing record.
    pub fn open_unsynced(location: &IdentityLocation) -> Result<MessageStore> {
        let path = messages_path(location);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                AgentxError::MessageInvalid(format!("creating {}: {err}", parent.display()))
            })?;
        }
        let conn = Connection::open(&path).map_err(|err| {
            AgentxError::MessageInvalid(format!("opening {}: {err}", path.display()))
        })?;
        let mut store = MessageStore {
            conn,
            endpoint: String::new(),
            owner_did: String::new(),
            device_id: String::new(),
        };
        store.prepare()?;
        restrict_permissions(&path);
        Ok(store)
    }

    /// Bring the file up to [`SCHEMA_VERSION`], or refuse it.
    /// Refusing a **newer** file rather than writing into it is the service's own stance
    /// (`packages/service/src/storage/sqlite.ts`), copied because the failure it prevents is
    /// silent: a binary older than the file would write yesterday's columns into it.
    fn prepare(&mut self) -> Result<()> {
        let version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(sql_err("reading the schema version"))?;
        if version > SCHEMA_VERSION {
            return Err(AgentxError::MessageInvalid(format!(
                "this messages.db was written by a newer agentx-cli (schema {version}, this \
                 build writes {SCHEMA_VERSION}) — upgrade, or point AGENTXCLI_HOME elsewhere"
            )));
        }
        if version == SCHEMA_VERSION {
            return Ok(());
        }

        // WAL so a reader (`msg inbox` in another process) is not blocked by the long-running
        // listener's writes. Not durable across a crash for the last transactions — that is
        // what the cursor ordering in `record` is for.
        self.conn
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(sql_err("setting journal_mode"))?;
        self.conn
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(sql_err("enabling foreign keys"))?;

        self.conn
            .execute_batch(SCHEMA)
            .map_err(sql_err("creating the schema"))?;
        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(sql_err("stamping the schema version"))?;
        Ok(())
    }

    /// Write one row, and move the cursor if the row carried a delivery number.
    ///
    /// Returns whether this row was **new**. `false` means a replay: the frame (or the
    /// envelope inside it) had already been recorded, which is a normal outcome on a reconnect
    /// and not an error — see the module comment on why both kinds of replay are expected.
    pub fn record(&mut self, record: &Record) -> Result<bool> {
        // §7.3's two counters arrive as decimal strings. Converted here rather than held as
        // strings in the file: the service's columns are integers, and ordering needs numbers.
        let group_event_seq = decimal("group_event_seq", record.group_event_seq.as_deref())?;
        let group_state_version =
            decimal("group_state_version", record.group_state_version.as_deref())?;

        let tx = self
            .conn
            .transaction()
            .map_err(sql_err("opening a transaction"))?;

        let conversation_id: i64 = {
            tx.execute(
                "INSERT OR IGNORE INTO conversations (kind, peer_did) VALUES (?1, ?2)",
                params![record.conversation.kind(), record.conversation.peer_did()],
            )
            .map_err(sql_err("filing the conversation"))?;
            tx.query_row(
                "SELECT id FROM conversations WHERE kind = ?1 AND peer_did = ?2",
                params![record.conversation.kind(), record.conversation.peer_did()],
                |row| row.get(0),
            )
            .map_err(sql_err("reading the conversation back"))?
        };

        let payload_json = match &record.payload {
            Some(value) => Some(
                serde_json::to_string(value)
                    .map_err(|err| AgentxError::MessageInvalid(format!("payload: {err}")))?,
            ),
            None => None,
        };
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO messages (
                     conversation_id, direction, sender_did, message_id, content_type,
                     text, payload_json, service_seq, endpoint, accepted_at, group_event_seq,
                     group_state_version, received_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    conversation_id,
                    record.direction.as_str(),
                    record.sender_did,
                    record.message_id,
                    record.content_type,
                    record.text,
                    payload_json,
                    record.service_seq.map(|seq| seq as i64),
                    self.endpoint,
                    record.accepted_at,
                    group_event_seq,
                    group_state_version,
                    now(),
                ],
            )
            .map_err(sql_err("writing the message"))?;

        // Only a message the service numbered moves the cursor, and it moves whether or not
        // the row was new: a replay still means "this frame is behind me now". `MAX` is the
        // only-write-forward rule — a cursor cannot be walked back by an out-of-order page.
        if let Some(seq) = record.service_seq {
            tx.execute(
                "INSERT INTO sync_state (endpoint, owner_did, device_id, applied_seq, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (endpoint, owner_did, device_id) DO UPDATE SET
                     applied_seq = MAX(applied_seq, excluded.applied_seq),
                     updated_at  = excluded.updated_at",
                params![
                    self.endpoint,
                    self.owner_did,
                    self.device_id,
                    seq as i64,
                    now()
                ],
            )
            .map_err(sql_err("advancing the local cursor"))?;
        }

        tx.execute(
            "UPDATE conversations SET last_at = COALESCE(?2, last_at) WHERE id = ?1",
            params![conversation_id, record.accepted_at],
        )
        .map_err(sql_err("updating the conversation"))?;

        tx.commit().map_err(sql_err("committing"))?;
        Ok(inserted > 0)
    }

    /// The local cursor for this store's inbox, if anything has been recorded yet.
    pub fn applied_seq(&self) -> Result<Option<u64>> {
        let seq: Option<i64> = self
            .conn
            .query_row(
                "SELECT applied_seq FROM sync_state
                 WHERE endpoint = ?1 AND owner_did = ?2 AND device_id = ?3",
                params![self.endpoint, self.owner_did, self.device_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_err("reading the local cursor"))?;
        Ok(seq.map(|seq| seq as u64))
    }

    /// How many rows are in the record. Used by tests, and by nothing else yet.
    pub fn message_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
            .map_err(sql_err("counting messages"))?;
        Ok(count as u64)
    }

    // ---- reading (design §8) ------------------------------------------------------------

    /// Open the record **for reading**: no inbox, and nothing created.
    ///
    /// The opposite duties of [`MessageStore::open`], which is why this is a second constructor
    /// rather than an argument on the first. A read never goes online (design §8.1), so it
    /// cannot discover a `serviceEndpoint` and must not need one; and a read must not **write**,
    /// so a record that is not there yet answers "nothing here" instead of being created.
    /// `msg listen` is where a record gets built.
    pub fn open_read_only(location: &IdentityLocation) -> Result<MessageStore> {
        let path = messages_path(location);
        // A file that is there but has no `messages` table is a record with no history — an
        // interrupted first `Connection::open` leaves exactly that. It is answered as empty
        // rather than upgraded, because upgrading writes and this path must not.
        let empty = || -> Result<Connection> {
            let conn =
                Connection::open_in_memory().map_err(sql_err("opening an empty in-memory record"))?;
            conn.execute_batch(SCHEMA).map_err(sql_err("building the schema"))?;
            Ok(conn)
        };
        let conn = if path.exists() {
            let conn = Connection::open(&path).map_err(|err| {
                AgentxError::MessageInvalid(format!("opening {}: {err}", path.display()))
            })?;
            let version: i64 = conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(sql_err("reading the schema version"))?;
            if version > SCHEMA_VERSION {
                return Err(AgentxError::MessageInvalid(format!(
                    "this messages.db was written by a newer agentx-cli (schema {version}, this \
                     build reads {SCHEMA_VERSION}) — upgrade to read it"
                )));
            }
            let tables: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'messages'",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_err("looking for the schema"))?;
            if tables == 0 {
                empty()?
            } else {
                conn
            }
        } else {
            empty()?
        };
        // `endpoint` / `owner_did` / `device_id` key the cursor, and no read touches the
        // cursor. Empty rather than a second struct: a store that is only read from is not a
        // reason to duplicate every query.
        Ok(MessageStore {
            conn,
            endpoint: String::new(),
            owner_did: String::new(),
            device_id: String::new(),
        })
    }

    /// What this identity has, newest first — the whole of `msg inbox`'s answer (design §8.2).
    ///
    /// `unread_only` is a **local** question: read state lives in this file and nowhere else
    /// (design §4, 2026-10-03), so it is answerable with the network down. "Unread" is
    /// incoming-only — our own outgoing rows have no read state to be in.
    pub fn recent(&self, limit: u64, unread_only: bool) -> Result<Vec<StoredMessage>> {
        let filter = if unread_only {
            "AND m.direction = 'in' AND m.read_at IS NULL"
        } else {
            ""
        };
        self.select(
            &format!("{SELECT_ROWS} WHERE 1 = 1 {filter} ORDER BY m.id DESC LIMIT ?1"),
            params![limit as i64],
        )
    }

    /// One conversation's thread, **oldest first** — the whole of `msg history`'s answer.
    ///
    /// The window is the newest `limit` rows and then reversed, not the first `limit`: a chat
    /// shows where the conversation *is*, so a truncation has to drop the far past rather than
    /// the messages just said.
    pub fn conversation(
        &self,
        conversation: &Conversation,
        limit: u64,
    ) -> Result<Vec<StoredMessage>> {
        let mut rows = self.select(
            &format!(
                "{SELECT_ROWS} WHERE c.kind = ?1 AND c.peer_did = ?2 ORDER BY m.id DESC LIMIT ?3"
            ),
            params![conversation.kind(), conversation.peer_did(), limit as i64],
        )?;
        rows.reverse();
        Ok(rows)
    }

    /// One thread, keyed by the **peer's DID alone** — what `msg history <peer_did>` asks.
    ///
    /// The kind is not part of the question, and asking the caller for it would be asking them
    /// to know something the file already knows. It is also the one place the two could be
    /// confused: a group DID (`…:g:<id>`) and an agent DID (`…:user:<handle>`) are disjoint
    /// spellings, so a peer string names at most one conversation, and no prefix test that
    /// would have to be kept in step with the service is needed here.
    pub fn conversation_with(&self, peer_did: &str, limit: u64) -> Result<Vec<StoredMessage>> {
        let mut rows = self.select(
            &format!("{SELECT_ROWS} WHERE c.peer_did = ?1 ORDER BY m.id DESC LIMIT ?2"),
            params![peer_did, limit as i64],
        )?;
        rows.reverse();
        Ok(rows)
    }

    /// Every row whose sender chose this id.
    ///
    /// A `Vec` because the id is **sender-scoped**: the unique key is
    /// `(conversation, sender, message_id)` (module comment #2), so the same string from two
    /// senders is two rows and neither of them is "the" one.
    pub fn find(&self, message_id: &str) -> Result<Vec<StoredMessage>> {
        self.select(
            &format!("{SELECT_ROWS} WHERE m.message_id = ?1 ORDER BY m.id"),
            params![message_id],
        )
    }

    /// Mark rows read, **locally**. Returns the ids that were actually changed.
    ///
    /// Locally is the ruling (design §4, 2026-10-03): the read state has one home, this file,
    /// which is why there is no service call behind this. An id that is not here, is already
    /// read, or is one of our own outgoing rows is **not** in the return: reporting it as
    /// marked would make the count say nothing about what happened.
    pub fn mark_read(&mut self, ids: &[String]) -> Result<Vec<String>> {
        let read_at = now();
        let tx = self.conn.transaction().map_err(sql_err("opening a transaction"))?;
        let mut marked = Vec::new();
        {
            let mut stmt = tx
                .prepare(
                    "UPDATE messages SET read_at = ?1
                      WHERE message_id = ?2 AND direction = 'in' AND read_at IS NULL",
                )
                .map_err(sql_err("preparing the read marker"))?;
            for id in ids {
                let changed = stmt.execute(params![read_at, id]).map_err(sql_err("marking read"))?;
                if changed > 0 {
                    marked.push(id.clone());
                }
            }
        }
        tx.commit().map_err(sql_err("committing"))?;
        Ok(marked)
    }

    /// Mark everything incoming read. Returns how many rows changed.
    pub fn mark_all_read(&mut self) -> Result<u64> {
        let changed = self
            .conn
            .execute(
                "UPDATE messages SET read_at = ?1 WHERE direction = 'in' AND read_at IS NULL",
                params![now()],
            )
            .map_err(sql_err("marking everything read"))?;
        Ok(changed as u64)
    }

    /// How many incoming rows are unread.
    pub fn unread_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE direction = 'in' AND read_at IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(sql_err("counting unread messages"))?;
        Ok(count as u64)
    }

    fn select(&self, sql: &str, params: impl rusqlite::Params) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(sql).map_err(sql_err("preparing a read"))?;
        let rows = stmt
            .query_map(params, stored_of)
            .map_err(sql_err("reading messages"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql_err("reading messages"))
    }
}

/// One row of the local record, as a reader wants it (design §8).
///
/// [`Record`]'s inverse for the columns the two share, plus what only a reader needs:
/// `received_at` (when *this device* wrote it down — not the service's `accepted_at`), and
/// `read_at`, which after the 2026-10-03 ruling is the one and only read state.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredMessage {
    pub conversation: Conversation,
    pub direction: Direction,
    pub sender_did: String,
    pub message_id: String,
    pub content_type: Option<String>,
    pub text: Option<String>,
    pub payload: Option<Value>,
    /// The delivery number, and the number this row's own inbox gave it — incoming only.
    pub service_seq: Option<i64>,
    pub group_event_seq: Option<i64>,
    pub accepted_at: Option<String>,
    pub received_at: String,
    pub read_at: Option<String>,
}

/// The columns every read here selects, in the order [`stored_of`] reads them.
const SELECT_ROWS: &str = "
SELECT c.kind, c.peer_did, m.direction, m.sender_did, m.message_id, m.content_type,
       m.text, m.payload_json, m.service_seq, m.group_event_seq, m.accepted_at,
       m.received_at, m.read_at
  FROM messages m JOIN conversations c ON c.id = m.conversation_id";

/// One row of [`SELECT_ROWS`], in that column order.
fn stored_of(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    let kind: String = row.get(0)?;
    let peer: String = row.get(1)?;
    let direction: String = row.get(2)?;
    // A payload the file itself cannot re-parse is not a reason to fail the whole read: the
    // column was written by this binary, and the text arm (if any) still renders.
    let payload_json: Option<String> = row.get(7)?;
    Ok(StoredMessage {
        conversation: if kind == "group" {
            Conversation::Group { group_did: peer }
        } else {
            Conversation::Direct { peer_did: peer }
        },
        direction: if direction == "out" {
            Direction::Outgoing
        } else {
            Direction::Incoming
        },
        sender_did: row.get(3)?,
        message_id: row.get(4)?,
        content_type: row.get(5)?,
        text: row.get(6)?,
        payload: payload_json.and_then(|json| serde_json::from_str(&json).ok()),
        service_seq: row.get(8)?,
        group_event_seq: row.get(9)?,
        accepted_at: row.get(10)?,
        received_at: row.get(11)?,
        read_at: row.get(12)?,
    })
}

/// The table definitions (design §3).
///
/// The two group counters are **integers here** even though the wire spells them as decimal
/// strings (§7.3): the service's own `messages.group_event_seq` / `group_state_version` are
/// INTEGER columns, it has to *increment* the first, and ordering by a string is not ordering.
/// `record` parses and refuses a non-decimal value.
///
/// `group_state_version` is not an epoch: P6's per-message reference is
/// `group_state_ref.group_state_version` (`anp` 1.0.5's `V2GroupStateRef`), and the crate's own
/// stored epoch is a different number. Recording the one the ciphertext actually names is the
/// only version two files can be reconciled on.
const SCHEMA: &str = "
CREATE TABLE conversations (
  id        INTEGER PRIMARY KEY,
  kind      TEXT NOT NULL CHECK (kind IN ('direct', 'group')),
  peer_did  TEXT NOT NULL,
  last_at   TEXT,
  UNIQUE (kind, peer_did)
);

CREATE TABLE messages (
  id                  INTEGER PRIMARY KEY,
  conversation_id     INTEGER NOT NULL REFERENCES conversations(id),
  direction           TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  sender_did          TEXT NOT NULL,
  message_id          TEXT NOT NULL,
  content_type        TEXT,
  text                TEXT,
  payload_json        TEXT,
  service_seq         INTEGER,
  -- Which inbox `service_seq` is a number *in* (design §4.2). A delivery number without its
  -- namespace means nothing: after a move the same conversation holds rows numbered by two
  -- different services, and ordering by a bare `service_seq` would interleave them.
  endpoint            TEXT NOT NULL,
  accepted_at         TEXT,
  group_event_seq     INTEGER,
  group_state_version INTEGER,
  received_at         TEXT NOT NULL,
  read_at             TEXT,
  UNIQUE (conversation_id, sender_did, message_id)
);

CREATE INDEX messages_by_conversation ON messages(conversation_id, id);

CREATE TABLE sync_state (
  endpoint    TEXT NOT NULL,
  owner_did   TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  applied_seq INTEGER NOT NULL,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (endpoint, owner_did, device_id)
);
";

// ---- the write hook -----------------------------------------------------------

/// The listener's view, with a `messages.db` write in front of it.
///
/// The write belongs **on the consuming side** of the listener, not inside the transport
/// (design §7): an event is recorded when this client has acted on it, and a frame the
/// transport merely received is not yet that. The inner view still gets every event, so a
/// failed write changes what is on disk and never what the person sees.
///
/// `ack` marks each recorded row read, which is where read state lives after the 2026-10-03
/// ruling (design §4): the transport asks for a confirmation, and the confirmation is a local
/// write. The transport itself still knows nothing about sqlite.
pub struct RecordingView {
    store: Mutex<MessageStore>,
    inner: Arc<dyn ListenView>,
    ack: bool,
}

impl RecordingView {
    pub fn new(store: MessageStore, inner: Arc<dyn ListenView>, ack: bool) -> RecordingView {
        RecordingView {
            store: Mutex::new(store),
            inner,
            ack,
        }
    }
}

impl ListenView for RecordingView {
    fn event(&self, event: &ListenEvent) {
        if let Some(record) = records_from(event) {
            let outcome = match self.store.lock() {
                Ok(mut store) => store
                    .record(&record)
                    .and_then(|_| {
                        if self.ack {
                            store.mark_read(std::slice::from_ref(&record.message_id))?;
                        }
                        Ok(())
                    })
                    .map_err(|err| err.to_string()),
                // A panic in an earlier write. The store may hold a half-open transaction and
                // the cursor is no longer trustworthy, so nothing is written.
                Err(_) => Err("the message store was poisoned by an earlier panic".to_string()),
            };
            if let Err(err) = outcome {
                // Not fatal, and deliberately not an exit: the row is missing **and the
                // cursor did not move**, so the next connect replays the frame and this hook
                // sees it again. Saying so to stderr is the whole of the recovery (§2.1).
                eprintln!("agentx-cli: not recorded in messages.db: {err}");
            }
        }
        self.inner.event(event);
    }
}

/// The row an event becomes, or nothing when the event is not a message.
///
/// Public because `msg fetch` is the *same* write path as the listener's: it decodes a
/// `sync.delta` entry into the frame the stream would have pushed, offers it here, and hands
/// the result to [`MessageStore::record`]. Two mappings for one frame is how the two halves
/// would come to disagree about what a delivery is. (The bin target is a separate crate from
/// this library, so "used by the bin" means `pub` here, not `pub(crate)`.)
pub fn records_from(event: &ListenEvent) -> Option<Record> {
    match event {
        ListenEvent::State(_) => None,
        ListenEvent::Message(message) => {
            let conversation = match message.target_kind {
                "group" => Conversation::Group {
                    group_did: message.group_did.clone()?,
                },
                _ => Conversation::Direct {
                    peer_did: message.from.clone(),
                },
            };
            let mut record = Record::incoming(conversation, &message.from, &message.message_id);
            record.content_type = Some(message.content_type.clone());
            body_of(&mut record, message.text.as_deref(), message.payload.as_ref());
            // A service-visible delivery, so this is the number the local cursor follows.
            record.service_seq = Some(message.seq);
            record.accepted_at = message.accepted_at.clone();
            Some(record)
        }
        ListenEvent::Group(GroupEvent::Notice { .. }) => None,
        ListenEvent::Group(GroupEvent::Message {
            group_did,
            from,
            message_id,
            group_event_seq,
            group_state_version,
            accepted_at,
            content_type,
            text,
            payload,
        }) => {
            let mut record = Record::incoming(
                Conversation::Group {
                    group_did: group_did.clone(),
                },
                from,
                message_id,
            );
            record.content_type = Some(content_type.clone());
            body_of(&mut record, text.as_deref(), payload.as_ref());
            // No `service_seq`: a §12 frame arrives on the **device queue**, not in this
            // recipient's `deliveries`, so it carries no delivery number to move the cursor
            // with (design §4.1). Its order within the group is `group_event_seq`.
            record.group_event_seq = group_event_seq.clone();
            record.group_state_version = Some(group_state_version.clone());
            record.accepted_at = accepted_at.clone();
            Some(record)
        }
    }
}

/// §7.4's exactly-one-of, kept apart in the row: when a body carried a JSON object, `text` is
/// a *rendering* of it, and recording both would store the same content twice.
fn body_of(record: &mut Record, text: Option<&str>, payload: Option<&Value>) {
    match payload {
        Some(value) => record.payload = Some(value.clone()),
        None => record.text = text.map(str::to_string),
    }
}

/// `scheme://host[:port]` — the inbox's identity, without the RPC path inside it.
fn origin_of(endpoint: &str) -> String {
    match reqwest::Url::parse(endpoint) {
        Ok(url) => {
            let host = url.host_str().unwrap_or_default();
            match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            }
        }
        // Not a URL: keep what we were given rather than inventing a key. A cursor that is
        // merely *wrong* costs a re-pull; one that is empty would collide with the next.
        Err(_) => endpoint.to_string(),
    }
}

/// Parse one of §7.3's decimal-string counters into the INTEGER the column holds.
///
/// Called before the transaction opens, so a value this client cannot represent writes
/// **nothing** — no row, and in particular no cursor movement. Refusing beats truncating: a
/// counter that silently loses its value is a counter that cannot be ordered by.
fn decimal(field: &str, wire: Option<&str>) -> Result<Option<i64>> {
    let Some(wire) = wire else { return Ok(None) };
    wire.parse::<i64>().map(Some).map_err(|_| {
        AgentxError::MessageInvalid(format!(
            "{field} is {wire:?}, which is not a decimal number — the service's own column is \
             an integer"
        ))
    })
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// 0600, like `identity.json`: the file holds plaintext (design §5 #2).
fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn sql_err(context: &'static str) -> impl Fn(rusqlite::Error) -> AgentxError {
    move |err| AgentxError::MessageInvalid(format!("{context}: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_support;
    use crate::message::listen::{ListenMessage, ListenState};

    fn store(name: &str) -> (tempdir::Dir, MessageStore) {
        let dir = tempdir::Dir::new(name);
        let store = writer(&dir);
        (dir, store)
    }

    /// A store opened the way `msg listen` opens one, so a test can write rows for a reader.
    fn writer(dir: &tempdir::Dir) -> MessageStore {
        let location = location(dir);
        std::fs::create_dir_all(location.dir()).unwrap();
        let identity = test_support::mint("alice");
        MessageStore::open(
            &location,
            &identity,
            "http://127.0.0.1:8787/anp-im/rpc",
            &identity.device_id,
        )
        .unwrap()
    }

    fn reader(dir: &tempdir::Dir) -> MessageStore {
        MessageStore::open_read_only(&location(dir)).unwrap()
    }

    fn thread(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn location(dir: &tempdir::Dir) -> IdentityLocation {
        IdentityLocation {
            root: dir.path().to_path_buf(),
            agent: "alice".to_string(),
            profile: "default".to_string(),
        }
    }

    fn incoming(seq: u64, message_id: &str) -> Record {
        let mut record = Record::incoming(
            Conversation::Direct {
                peer_did: "did:wba:example.com:bob".to_string(),
            },
            "did:wba:example.com:bob",
            message_id,
        );
        record.service_seq = Some(seq);
        record.content_type = Some("text/plain".to_string());
        record.text = Some(format!("hello {seq}"));
        record.accepted_at = Some("2026-10-02T10:00:00Z".to_string());
        record
    }

    #[test]
    fn a_message_is_recorded_once_and_the_cursor_follows_it() {
        let (_dir, mut store) = store("record");
        assert_eq!(store.message_count().unwrap(), 0);

        assert!(store.record(&incoming(1, "m-1")).unwrap(), "the first write is new");
        assert_eq!(store.message_count().unwrap(), 1);
        assert_eq!(store.applied_seq().unwrap(), Some(1));
    }

    #[test]
    fn recording_the_same_message_twice_changes_nothing_but_the_cursor() {
        let (_dir, mut store) = store("dedupe");
        store.record(&incoming(1, "m-1")).unwrap();
        // A reconnect replays the frame: same identity, same delivery number.
        assert!(
            !store.record(&incoming(1, "m-1")).unwrap(),
            "a replay is not a new row"
        );
        assert_eq!(store.message_count().unwrap(), 1);
        assert_eq!(store.applied_seq().unwrap(), Some(1));
    }

    #[test]
    fn two_senders_may_use_the_same_message_id() {
        let (_dir, mut store) = store("sender-scoped");
        store.record(&incoming(1, "m-1")).unwrap();
        let mut other = incoming(2, "m-1");
        other.sender_did = "did:wba:example.com:carol".to_string();
        assert!(
            store.record(&other).unwrap(),
            "message_id is sender-scoped, so this is a different message"
        );
        assert_eq!(store.message_count().unwrap(), 2);
    }

    #[test]
    fn the_cursor_never_walks_backwards() {
        let (_dir, mut store) = store("monotonic");
        store.record(&incoming(9, "m-9")).unwrap();
        // An out-of-order page, or `--since` pointed at an older corner of the inbox.
        store.record(&incoming(4, "m-4")).unwrap();
        assert_eq!(store.applied_seq().unwrap(), Some(9));
        assert_eq!(store.message_count().unwrap(), 2, "the row is still recorded");
    }

    #[test]
    fn an_outgoing_message_has_no_delivery_number_and_moves_nothing() {
        let (_dir, mut store) = store("outgoing");
        let record = Record::outgoing(
            Conversation::Direct {
                peer_did: "did:wba:example.com:bob".to_string(),
            },
            "did:wba:example.com:alice",
            "m-out",
            "text/plain",
            Some("hi bob".to_string()),
            None,
        );
        assert!(store.record(&record).unwrap());
        assert_eq!(store.applied_seq().unwrap(), None, "nothing was delivered to us");
        assert_eq!(store.message_count().unwrap(), 1);
        let direction: String = store
            .conn
            .query_row("SELECT direction FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(direction, "out");
    }

    #[test]
    fn a_group_message_keeps_the_state_version_it_was_encrypted_against() {
        let (_dir, mut store) = store("group-state-version");
        let mut record = Record::incoming(
            Conversation::Group {
                group_did: "did:wba:example.com:g:team".to_string(),
            },
            "did:wba:example.com:bob",
            "m-1",
        );
        // As the wire spells them: decimal strings.
        record.group_event_seq = Some("7".to_string());
        record.group_state_version = Some("3".to_string());
        record.service_seq = Some(1);
        store.record(&record).unwrap();

        let (event, version): (i64, i64) = store
            .conn
            .query_row(
                "SELECT group_event_seq, group_state_version FROM messages",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(event, 7);
        assert_eq!(version, 3);
    }

    #[test]
    fn a_counter_that_is_not_decimal_writes_nothing_at_all() {
        let (_dir, mut store) = store("not-decimal");
        let mut record = incoming(1, "m-1");
        record.group_state_version = Some("v3".to_string());
        let err = store
            .record(&record)
            .expect_err("a value the column cannot hold must be refused");
        assert!(
            err.to_string().contains("group_state_version"),
            "the refusal must name the field: {err}"
        );
        assert_eq!(store.message_count().unwrap(), 0);
        assert_eq!(
            store.applied_seq().unwrap(),
            None,
            "a refused row must not move the cursor"
        );
    }

    #[test]
    fn a_row_remembers_which_inbox_numbered_it() {
        let (_dir, mut store) = store("endpoint-column");
        store.record(&incoming(1, "m-1")).unwrap();
        let endpoint: String = store
            .conn
            .query_row("SELECT endpoint FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            endpoint, "http://127.0.0.1:8787",
            "the delivery number was a number *in* this inbox"
        );
    }

    #[test]
    fn the_origin_is_what_the_cursor_is_keyed_by() {
        assert_eq!(
            origin_of("http://127.0.0.1:8787/anp-im/rpc"),
            "http://127.0.0.1:8787"
        );
        assert_eq!(
            origin_of("https://agentx.example/anp-im/rpc"),
            "https://agentx.example"
        );
    }

    #[test]
    fn a_newer_schema_is_refused_rather_than_written_into() {
        let dir = tempdir::Dir::new("refuse-newer");
        let location = location(&dir);
        std::fs::create_dir_all(location.dir()).unwrap();
        let identity = test_support::mint("alice");
        {
            let conn = Connection::open(messages_path(&location)).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = MessageStore::open(&location, &identity, "http://127.0.0.1:8787/x", "dev")
            .expect_err("a file from the future must not be opened");
        assert!(
            err.to_string().contains("newer agentx-cli"),
            "the refusal must say why: {err}"
        );
    }

    #[test]
    fn reopening_an_existing_record_does_not_recreate_anything() {
        let dir = tempdir::Dir::new("reopen");
        let location = location(&dir);
        std::fs::create_dir_all(location.dir()).unwrap();
        let identity = test_support::mint("alice");
        {
            let mut store =
                MessageStore::open(&location, &identity, "http://127.0.0.1:8787/x", "dev").unwrap();
            store.record(&incoming(1, "m-1")).unwrap();
        }
        // The second open sees version 1 and must not re-run the schema (which would fail on
        // the existing tables).
        let store =
            MessageStore::open(&location, &identity, "http://127.0.0.1:8787/x", "dev").unwrap();
        assert_eq!(store.message_count().unwrap(), 1);
        assert_eq!(store.applied_seq().unwrap(), Some(1));
    }

    // ---- the write hook ------------------------------------------------------------------

    /// A view that only counts, standing in for the terminal: what the write hook must not do
    /// is change what the person sees.
    #[derive(Default)]
    struct Spy {
        seen: std::sync::atomic::AtomicUsize,
    }

    impl ListenView for Spy {
        fn event(&self, _event: &ListenEvent) {
            self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn delivery(seq: u64) -> ListenEvent {
        ListenEvent::Message(ListenMessage {
            kind: "message",
            seq,
            message_id: "m-1".to_string(),
            from: "did:wba:example.com:bob".to_string(),
            target_kind: "agent",
            group_did: None,
            content_type: "text/plain".to_string(),
            text: Some("hello".to_string()),
            payload: None,
            accepted_at: Some("2026-10-02T10:00:00Z".to_string()),
        })
    }

    #[test]
    fn a_direct_delivery_is_recorded_and_the_view_still_shows_it() {
        let (_dir, store) = store("hook-direct");
        let spy = Arc::new(Spy::default());
        let view = RecordingView::new(store, spy.clone(), false);

        view.event(&delivery(5));
        assert_eq!(spy.seen.load(std::sync::atomic::Ordering::SeqCst), 1);

        let store = view.store.lock().unwrap();
        assert_eq!(store.message_count().unwrap(), 1);
        assert_eq!(store.applied_seq().unwrap(), Some(5));
    }

    #[test]
    fn acknowledging_on_the_way_in_marks_the_row_it_just_wrote() {
        // `msg listen --ack` says "I have this one" to the service and, since 2026-10-03, the
        // same act marks the local row: read state has one home (design §4), so a client that
        // acknowledges must not leave the row it acknowledged sitting there unread.
        let (_dir, acknowledged) = store("hook-ack");
        let view = RecordingView::new(acknowledged, Arc::new(Spy::default()), true);

        view.event(&delivery(5));
        assert_eq!(view.store.lock().unwrap().unread_count().unwrap(), 0);

        // And without the flag the row arrives unread, which is what the flag is for.
        let (_dir, quiet) = store("hook-no-ack");
        let view = RecordingView::new(quiet, Arc::new(Spy::default()), false);
        view.event(&delivery(5));
        assert_eq!(view.store.lock().unwrap().unread_count().unwrap(), 1);
    }

    #[test]
    fn a_group_frame_is_recorded_without_moving_the_delivery_cursor() {
        let (_dir, store) = store("hook-group");
        let view = RecordingView::new(store, Arc::new(Spy::default()), false);

        // A §12 frame: it came off the device queue, so it has no delivery number.
        view.event(&ListenEvent::Group(GroupEvent::Message {
            group_did: "did:wba:example.com:g:team".to_string(),
            from: "did:wba:example.com:bob".to_string(),
            message_id: "m-1".to_string(),
            group_event_seq: Some("7".to_string()),
            group_state_version: "3".to_string(),
            accepted_at: None,
            content_type: "text/plain".to_string(),
            text: Some("secret".to_string()),
            payload: None,
        }));

        let store = view.store.lock().unwrap();
        assert_eq!(store.message_count().unwrap(), 1);
        assert_eq!(
            store.applied_seq().unwrap(),
            None,
            "nothing was delivered to this device's inbox"
        );
        let (event, version): (i64, i64) = store
            .conn
            .query_row(
                "SELECT group_event_seq, group_state_version FROM messages",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((event, version), (7, 3));
    }

    #[test]
    fn a_payload_body_is_recorded_as_a_payload_not_as_its_rendering() {
        let (_dir, store) = store("hook-payload");
        let view = RecordingView::new(store, Arc::new(Spy::default()), false);

        view.event(&ListenEvent::Message(ListenMessage {
            kind: "message",
            seq: 1,
            message_id: "m-1".to_string(),
            from: "did:wba:example.com:bob".to_string(),
            target_kind: "agent",
            group_did: None,
            content_type: "application/json".to_string(),
            // `text` is the same object pretty-printed, per `ListenMessage`'s own contract.
            text: Some("{\n  \"k\": 1\n}".to_string()),
            payload: Some(serde_json::json!({"k": 1})),
            accepted_at: None,
        }));

        let store = view.store.lock().unwrap();
        let (text, payload): (Option<String>, Option<String>) = store
            .conn
            .query_row("SELECT text, payload_json FROM messages", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(text, None, "§7.4's two arms are not the same arm twice");
        assert_eq!(
            serde_json::from_str::<Value>(&payload.unwrap()).unwrap(),
            serde_json::json!({"k": 1})
        );
    }

    #[test]
    fn a_state_line_is_forwarded_and_records_nothing() {
        let (_dir, store) = store("hook-state");
        let spy = Arc::new(Spy::default());
        let view = RecordingView::new(store, spy.clone(), false);

        view.event(&ListenEvent::State(ListenState::Connecting {
            service: "http://127.0.0.1:8787".to_string(),
        }));
        assert_eq!(spy.seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(view.store.lock().unwrap().message_count().unwrap(), 0);
    }

    #[test]
    fn a_message_the_store_refuses_is_still_shown() {
        let (_dir, store) = store("hook-refuse");
        let spy = Arc::new(Spy::default());
        let view = RecordingView::new(store, spy.clone(), false);

        view.event(&ListenEvent::Group(GroupEvent::Message {
            group_did: "did:wba:example.com:g:team".to_string(),
            from: "did:wba:example.com:bob".to_string(),
            message_id: "m-1".to_string(),
            group_event_seq: None,
            // Not a decimal number: the row cannot hold it, so nothing is written.
            group_state_version: "v3".to_string(),
            accepted_at: None,
            content_type: "text/plain".to_string(),
            text: Some("secret".to_string()),
            payload: None,
        }));

        assert_eq!(
            spy.seen.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a write failure must not swallow what someone said"
        );
        let store = view.store.lock().unwrap();
        assert_eq!(store.message_count().unwrap(), 0);
        assert_eq!(store.applied_seq().unwrap(), None);
    }

    // ---- reading (design §8) --------------------------------------------------------------

    #[test]
    fn reading_a_record_that_is_not_there_creates_nothing() {
        let dir = tempdir::Dir::new("read-missing");
        let store = reader(&dir);
        assert_eq!(store.message_count().unwrap(), 0);
        assert!(store.recent(10, false).unwrap().is_empty());
        assert_eq!(store.unread_count().unwrap(), 0);
        assert!(
            !messages_path(&location(&dir)).exists(),
            "a read must not create the record it was going to read"
        );
    }

    #[test]
    fn recent_is_newest_first_and_unread_only_drops_what_was_read() {
        let dir = tempdir::Dir::new("read-recent");
        {
            let mut store = writer(&dir);
            store.record(&incoming(1, "m-1")).unwrap();
            store.record(&incoming(2, "m-2")).unwrap();
            store.mark_read(&thread(&["m-1"])).unwrap();
        }

        let store = reader(&dir);
        let all = store.recent(10, false).unwrap();
        assert_eq!(
            all.iter().map(|m| m.message_id.as_str()).collect::<Vec<_>>(),
            ["m-2", "m-1"],
            "newest first"
        );
        assert!(all[1].read_at.is_some(), "m-1 was marked read");
        assert!(all[0].read_at.is_none());

        let unread = store.recent(10, true).unwrap();
        assert_eq!(
            unread.iter().map(|m| m.message_id.as_str()).collect::<Vec<_>>(),
            ["m-2"]
        );
        assert_eq!(store.unread_count().unwrap(), 1);
    }

    #[test]
    fn a_thread_is_oldest_first_and_truncates_the_far_past() {
        let dir = tempdir::Dir::new("read-thread");
        {
            let mut store = writer(&dir);
            for seq in 1..=5 {
                store.record(&incoming(seq, &format!("m-{seq}"))).unwrap();
            }
            // Another peer's message, so the thread must not pick it up.
            let mut other = incoming(6, "m-other");
            other.conversation = Conversation::Direct {
                peer_did: "did:wba:example.com:carol".to_string(),
            };
            store.record(&other).unwrap();
        }

        let store = reader(&dir);
        let thread = store
            .conversation(
                &Conversation::Direct {
                    peer_did: "did:wba:example.com:bob".to_string(),
                },
                3,
            )
            .unwrap();
        assert_eq!(
            thread.iter().map(|m| m.message_id.as_str()).collect::<Vec<_>>(),
            ["m-3", "m-4", "m-5"],
            "the newest three, oldest first — a chat truncates the far past"
        );
    }

    #[test]
    fn a_thread_can_be_asked_for_by_peer_alone() {
        let dir = tempdir::Dir::new("read-by-peer");
        {
            let mut store = writer(&dir);
            store.record(&incoming(1, "m-1")).unwrap();
            store.record(&incoming(2, "m-2")).unwrap();
            // The same peer string filed as a group: the two never collide, because a group
            // DID and an agent DID are disjoint spellings — and asking by peer must not
            // need the caller to say which.
            let mut group = incoming(3, "m-3");
            group.conversation = Conversation::Group {
                group_did: "did:wba:example.com:bob".to_string(),
            };
            store.record(&group).unwrap();
        }

        let store = reader(&dir);
        let direct = store.conversation_with("did:wba:example.com:bob", 10).unwrap();
        assert_eq!(
            direct.iter().map(|m| m.message_id.as_str()).collect::<Vec<_>>(),
            ["m-1", "m-2", "m-3"],
            "oldest first, and only this peer's rows"
        );
        assert!(store
            .conversation_with("did:wba:example.com:carol", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn find_returns_every_sender_scoped_row_with_that_id() {
        let dir = tempdir::Dir::new("read-find");
        {
            let mut store = writer(&dir);
            store.record(&incoming(1, "m-1")).unwrap();
            let mut other = incoming(2, "m-1");
            other.sender_did = "did:wba:example.com:carol".to_string();
            store.record(&other).unwrap();
        }

        let store = reader(&dir);
        assert_eq!(
            store.find("m-1").unwrap().len(),
            2,
            "message_id is sender-scoped, so this is two rows"
        );
        assert!(store.find("m-none").unwrap().is_empty());
    }

    #[test]
    fn marking_read_reports_only_what_changed() {
        let dir = tempdir::Dir::new("read-mark");
        let mut store = writer(&dir);
        store.record(&incoming(1, "m-1")).unwrap();
        let sent = Record::outgoing(
            Conversation::Direct {
                peer_did: "did:wba:example.com:bob".to_string(),
            },
            "did:wba:example.com:alice",
            "m-out",
            "text/plain",
            Some("hi".to_string()),
            None,
        );
        store.record(&sent).unwrap();

        let marked = store
            .mark_read(&thread(&["m-1", "m-none", "m-out"]))
            .unwrap();
        assert_eq!(
            marked,
            ["m-1"],
            "an id that is not here and our own outgoing row were not marked"
        );
        assert!(
            store.mark_read(&thread(&["m-1"])).unwrap().is_empty(),
            "already read, so nothing changed"
        );
        assert_eq!(store.unread_count().unwrap(), 0);
        assert!(
            store.recent(10, true).unwrap().is_empty(),
            "an outgoing row is never 'unread'"
        );
    }

    #[test]
    fn marking_everything_read_counts_the_incoming_rows_it_changed() {
        let dir = tempdir::Dir::new("read-mark-all");
        let mut store = writer(&dir);
        store.record(&incoming(1, "m-1")).unwrap();
        store.record(&incoming(2, "m-2")).unwrap();
        store.record(&incoming(3, "m-3")).unwrap();
        store.mark_read(&thread(&["m-1"])).unwrap();

        assert_eq!(store.mark_all_read().unwrap(), 2, "only the two still unread");
        assert_eq!(store.unread_count().unwrap(), 0);
        assert_eq!(store.mark_all_read().unwrap(), 0, "a second run changes nothing");
    }

    #[test]
    fn the_reader_refuses_a_newer_schema_without_touching_it() {
        let dir = tempdir::Dir::new("read-refuse-newer");
        let location = location(&dir);
        std::fs::create_dir_all(location.dir()).unwrap();
        {
            let conn = Connection::open(messages_path(&location)).unwrap();
            conn.pragma_update(None, "user_version", SCHEMA_VERSION + 1)
                .unwrap();
        }
        let err = MessageStore::open_read_only(&location)
            .expect_err("a file from the future must not be read");
        assert!(
            err.to_string().contains("newer agentx-cli"),
            "the refusal must say why: {err}"
        );
    }

    /// A store root of one test's own, removed when it drops.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new(name: &str) -> Dir {
                let path = std::env::temp_dir().join(format!(
                    "agentx-cli-messages-{}-{name}",
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).expect("a temp store root");
                Dir(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
