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

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::error::{AgentxError, Result};
use crate::identity::{Identity, IdentityLocation};

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
}

/// One identity's message record.
///
/// Holds the endpoint and device it is recording *for*, because those are what the local
/// cursor is keyed by (design §4.2) and neither is a property of a message.
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

    /// Bring the file up to [`SCHEMA_VERSION`], or refuse it.
    ///
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
                     text, payload_json, service_seq, accepted_at, group_event_seq,
                     group_state_version, received_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    conversation_id,
                    record.direction.as_str(),
                    record.sender_did,
                    record.message_id,
                    record.content_type,
                    record.text,
                    payload_json,
                    record.service_seq.map(|seq| seq as i64),
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

    fn store(name: &str) -> (tempdir::Dir, MessageStore) {
        let dir = tempdir::Dir::new(name);
        let location = location(&dir);
        let identity = test_support::mint("alice");
        std::fs::create_dir_all(location.dir()).unwrap();
        let store = MessageStore::open(
            &location,
            &identity,
            "http://127.0.0.1:8787/anp-im/rpc",
            &identity.device_id,
        )
        .unwrap();
        (dir, store)
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
        let mut record = Record::incoming(
            Conversation::Direct {
                peer_did: "did:wba:example.com:bob".to_string(),
            },
            "did:wba:example.com:alice",
            "m-out",
        );
        record.direction = Direction::Outgoing;
        record.text = Some("hi bob".to_string());
        assert!(store.record(&record).unwrap());
        assert_eq!(store.applied_seq().unwrap(), None, "nothing was delivered to us");
        assert_eq!(store.message_count().unwrap(), 1);
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
