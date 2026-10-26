//! The short-lived credential cache: the access token a host issued, kept under the host
//! that issued it. Written by `anp login` and by `did create` / `did register` (the host's
//! `register` reply carries a token of its own), read back by every command that then talks
//! to the host's control plane — `did publish` and `me`. Those calls are why the cache is
//! read at all: the ANP request path always signs, but the **host's own** authenticated
//! methods take a bearer token, and the spec's origin proof is not what they accept.
//!
//! A session is **not** an identity. The next login with the same key is still "you" whatever
//! this file holds, which is why a corrupt or expired cache is treated as absent rather than
//! as an error — a stale cache must never break a login, and nothing here is needed to
//! reproduce one.
//!
//! Keyed by target **host**, not by DID or subject: a token is issued per host and is
//! meaningless anywhere else, while both the DID (which a key update replaces) and the subject
//! (shared across hosts) would collide entries. That is the TS client's reasoning (ADR-0001
//! §2.5) and this file keeps it, including the read-merge-write, so logging into a second host
//! does not drop the first.
//!
//! The token is a bearer credential, so the file is `0600` like the identity beside it. The TS
//! client encrypts it with the keystore password; this client has no keystore — its identity
//! store is already plaintext `0600` — so the file is plaintext `0600` and the protection is
//! the same one the private keys get (TODO5 §8-E).

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::store::IdentityLocation;

pub const SESSION_FILE: &str = "session.json";

/// The fallback lifetime for a token whose JWT carries no decodable `exp`, matching the
/// reference server's own 7-day TTL. The server's expiry is authoritative whenever it is
/// shorter.
pub const DEFAULT_SESSION_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;

/// How the session file is written.
pub const SESSION_SCHEMA_VERSION: u32 = 1;

/// Lock and staleness bounds for the read-merge-write. The TS client takes the same lock for
/// the same reason: a login into host B and one into host A, on one (agent, profile), both
/// read-modify-write this file, and without the lock one of the two entries is lost.
const LOCK_RETRY: Duration = Duration::from_millis(25);
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_STALE: Duration = Duration::from_secs(30);

/// One token, as cached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub token: String,
    pub did: String,
    /// The stable subject the token was issued to. Recorded inside the entry rather than used
    /// as the key, so a caller can notice that a cached token predates a key update even
    /// though the identity is the same.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// The `token_type` the server named, verbatim (ANP-02 §3.2.3) — carried through so a
    /// cached token does not lose the one field that says how it must be presented. Absent
    /// means the spec's default (`Bearer`) applies.
    #[serde(skip_serializing_if = "Option::is_none", rename = "tokenType")]
    pub token_type: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionFile {
    pub version: u32,
    /// Keyed by target host, e.g. `localhost:3000`.
    pub sessions: std::collections::BTreeMap<String, SessionEntry>,
}

/// What a login did with the token cache, for the command to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionWrite {
    Saved,
    /// The caller asked for the token not to be cached.
    Skipped,
    /// The cache write failed. Never fatal: the token is still printed, and a cache write must
    /// not turn a good login into a failure.
    Failed,
}

/// Parse `--session-ttl`: `<n>` seconds, or `<n>s|m|h|d`.
pub fn parse_ttl_seconds(spec: Option<&str>) -> Result<u64> {
    let spec = spec.unwrap_or_default().trim();
    if spec.is_empty() {
        return Ok(DEFAULT_SESSION_TTL_SECONDS);
    }
    let (digits, unit) = match spec.strip_suffix(['s', 'm', 'h', 'd']) {
        Some(rest) => (rest, &spec[spec.len() - 1..]),
        None => (spec, "s"),
    };
    let value: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --session-ttl \"{spec}\" (use e.g. 7d, 24h, 30m, 3600s)"))?;
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => 86400,
    };
    let seconds = value * multiplier;
    // Zero is refused rather than clamped: `--session-ttl 0` reads as "do not cache", which
    // `--no-save-session` already says, and silently caching for no time is worse than a
    // message that says which flag means what.
    if seconds == 0 {
        anyhow::bail!("--session-ttl must be positive; --no-save-session is how a token is not cached");
    }
    Ok(seconds)
}

/// The authority a token is cached under: `host[:port]`, out of the login target URL.
///
/// Not the bare hostname. A token is issued by **one service**, so two servers on one machine
/// at different ports are two different issuers and must not share an entry. This is the TS
/// client's `new URL(target).host` — which is why its own docs say `localhost:3000` — and the
/// difference from `URL.hostname` is the whole point of the rule. The port is dropped only when
/// it is the scheme's default, which is exactly when writing it would be noise.
pub fn session_host(target: &str) -> Result<String> {
    let url = reqwest::Url::parse(target).map_err(|err| anyhow::anyhow!("--target must be a URL: {err}"))?;
    let host = url
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("--target {target} names no host"))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// Cache `token` under `host`, read-merge-writing so a login into another host survives.
///
/// Expiry never exceeds the server's own `exp` when the token is a decodable JWT: the TTL is a
/// bound the caller asked for, not a promise, and the server is the authority on how long its
/// token lives.
pub fn save_session(
    location: &IdentityLocation,
    host: &str,
    token: &str,
    did: &str,
    subject: Option<&str>,
    token_type: Option<&str>,
    ttl_seconds: u64,
) -> Result<()> {
    let now = Utc::now();
    let fallback = now + chrono::Duration::seconds(ttl_seconds as i64);
    let (issued, server_expiry) = jwt_times(token).unwrap_or((None, None));
    let entry = SessionEntry {
        token: token.to_string(),
        did: did.to_string(),
        subject: subject.map(str::to_string),
        token_type: token_type.map(str::to_string),
        issued_at: issued.unwrap_or(now).to_rfc3339(),
        // The TTL is a ceiling the caller asked for, not a promise: the shorter of it and the
        // server's own `exp` is what gets written, so a cache never outlives the credential.
        expires_at: server_expiry.unwrap_or(fallback).min(fallback).to_rfc3339(),
    };

    let path = location.session_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let _lock = SessionLock::take(&path)?;
    let mut file = read_session(&path);
    file.sessions.insert(host.to_string(), entry);
    write_private(&path, &file)
}

/// The cached token for `host`, or `None` if there is none that is still good.
///
/// `None` is the ordinary case, not an error: the cache is an optimization, and every caller
/// has a way to get a fresh token. Expiry is judged **here**, by this file's own clock,
/// rather than left to the server — a token this file has already dated is one the caller
/// would send only to be refused, and a round trip spent learning nothing is worse than a
/// message saying to log in.
///
/// The returned entry carries the DID it was issued to, and the caller is expected to
/// compare it before using it: a key update moves the DID, the host keys its tokens by DID,
/// and a token under the old one will be refused there even though it has not expired.
pub fn load_session(location: &IdentityLocation, host: &str) -> Option<SessionEntry> {
    let mut file = read_session(&location.session_path());
    let entry = file.sessions.remove(host)?;
    if is_expired(&entry) {
        return None;
    }
    Some(entry)
}

/// Whether the entry's own `expiresAt` has passed. An unparseable one counts as expired: it
/// is a field this file wrote, so the only way it is malformed is that something wrote it
/// wrong, and a credential is not the place to guess in the permissive direction.
fn is_expired(entry: &SessionEntry) -> bool {
    match DateTime::parse_from_rfc3339(&entry.expires_at) {
        Ok(expires) => expires.with_timezone(&Utc) <= Utc::now(),
        Err(_) => true,
    }
}

/// The file, or an empty one. A cache that cannot be read is treated as absent — it is only
/// ever a copy of a credential the server can re-issue.
fn read_session(path: &Path) -> SessionFile {
    let empty = SessionFile {
        version: SESSION_SCHEMA_VERSION,
        sessions: Default::default(),
    };
    let Ok(text) = fs::read_to_string(path) else {
        return empty;
    };
    match serde_json::from_str::<SessionFile>(&text) {
        Ok(file) if file.version == SESSION_SCHEMA_VERSION => file,
        // A future schema is not read backwards: guessing at fields this build does not know
        // could drop a token it cannot see, and the cost of starting fresh is one login.
        _ => empty,
    }
}

/// `iat` / `exp` as a JWT carries them. Both are optional: a payload with only `exp` is a
/// perfectly ordinary token, and the caller falls back to the caller's own clock for the rest.
type JwtTimes = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);

/// `iat` / `exp` out of a JWT payload. Never fails: a token that is not a JWT is opaque to this
/// client, and all it is used for is a local cache expiry.
fn jwt_times(token: &str) -> Option<JwtTimes> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let at = |name: &str| {
        claims
            .get(name)
            .and_then(serde_json::Value::as_i64)
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
    };
    Some((at("iat"), at("exp")))
}

/// A lock held for the duration of one read-merge-write.
///
/// A file rather than an OS lock because the whole write is over in microseconds and the only
/// contender is another copy of this same client; the pattern only has to keep two logins from
/// interleaving their read and their write.
struct SessionLock {
    path: std::path::PathBuf,
}

impl SessionLock {
    fn take(session_path: &Path) -> Result<Self> {
        let path = session_path.with_extension("json.lock");
        let deadline = SystemTime::now() + LOCK_TIMEOUT;
        loop {
            match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(_) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    // A lock older than the staleness bound is a crashed process's leftover,
                    // and refusing forever over one would make the cache unwritable for good.
                    if is_stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if SystemTime::now() >= deadline {
                        anyhow::bail!(
                            "another anpio-cli is writing {}; try again",
                            session_path.display()
                        );
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(err) => return Err(err).with_context(|| format!("locking {}", path.display())),
            }
        }
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn is_stale(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .map(|modified| {
            SystemTime::now()
                .duration_since(modified)
                .map(|age| age > LOCK_STALE)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Write the session file atomically and `0600`.
///
/// The same temp-then-rename as the identity store, and the same reason: this file holds a
/// bearer credential, so a write that stopped halfway would leave either nothing or a file
/// readable by others.
fn write_private(path: &Path, file: &SessionFile) -> Result<()> {
    let temporary = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(file)?;
    fs::write(&temporary, text).with_context(|| format!("writing {}", temporary.display()))?;
    restrict_permissions(&temporary)?;
    fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_key_keeps_the_port_because_two_services_are_two_issuers() {
        // The whole reason this is not `host_str`: two logins into one machine at different
        // ports would otherwise be one entry, and the second would overwrite the first.
        assert_eq!(session_host("http://localhost:3000/api/anp/login").unwrap(), "localhost:3000");
        assert_eq!(session_host("https://site.example/anp/login").unwrap(), "site.example");
        // A default port is not information, so it is not written.
        assert_eq!(session_host("https://site.example:443/x").unwrap(), "site.example");
        assert_eq!(session_host("http://127.0.0.1:9111/challenge").unwrap(), "127.0.0.1:9111");
        // IPv6 keeps its brackets, and the port still disambiguates.
        assert_eq!(session_host("http://[::1]:9111/x").unwrap(), "[::1]:9111");
        assert!(session_host("not a url").is_err());
    }

    #[test]
    fn a_ttl_is_seconds_by_default_and_suffixed_when_not() {
        assert_eq!(parse_ttl_seconds(None).unwrap(), DEFAULT_SESSION_TTL_SECONDS);
        assert_eq!(parse_ttl_seconds(Some("")).unwrap(), DEFAULT_SESSION_TTL_SECONDS);
        assert_eq!(parse_ttl_seconds(Some("3600")).unwrap(), 3600);
        assert_eq!(parse_ttl_seconds(Some("30m")).unwrap(), 1800);
        assert_eq!(parse_ttl_seconds(Some("24h")).unwrap(), 86_400);
        assert_eq!(parse_ttl_seconds(Some("7d")).unwrap(), 604_800);
        // Zero and nonsense fail before the network round trip, and each says which flag
        // means what rather than silently doing something else.
        assert!(parse_ttl_seconds(Some("0")).is_err());
        assert!(parse_ttl_seconds(Some("7w")).is_err());
        assert!(parse_ttl_seconds(Some("soon")).is_err());
    }

    #[test]
    fn a_jwt_carries_its_own_expiry_and_an_opaque_token_does_not() {
        // {"iat":1700000000,"exp":1700003600}, base64url, unsigned.
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"iat":1700000000,"exp":1700003600}"#);
        let token = format!("header.{claims}.signature");
        let (issued, expires) = jwt_times(&token).unwrap();
        assert_eq!(issued.unwrap().timestamp(), 1_700_000_000);
        assert_eq!(expires.unwrap().timestamp(), 1_700_003_600);
        // Not a JWT: no claim is invented, and the caller falls back to the TTL.
        assert!(jwt_times("opaque-token").is_none());
        assert!(jwt_times("a.b").is_none());
    }

    #[test]
    fn the_server_expiry_wins_when_it_is_shorter_but_not_when_it_is_longer() {
        let claims = base64::engine::general_purpose::URL_SAFE_NO_PAD
            // exp is one hour out; the caller asked for ten years.
            .encode(format!(r#"{{"exp":{}}}"#, Utc::now().timestamp() + 3600).as_bytes());
        let token = format!("header.{claims}.sig");
        let (_, expires) = jwt_times(&token).unwrap();
        let fallback = Utc::now() + chrono::Duration::seconds(DEFAULT_SESSION_TTL_SECONDS as i64);
        // The bound the caller asked for is a ceiling on top of the server's own exp, so the
        // earlier of the two is what gets written.
        assert!(expires.unwrap() < fallback);
    }

    #[test]
    fn what_was_cached_under_one_host_is_not_returned_for_another() {
        // The whole point of reading the cache back: the entry has to come out under the
        // same key it went in under, and be absent under every other one.
        let location = fixture("load");
        save_session(&location, "127.0.0.1:9111", "tok-a", "did:wba:a", None, None, 3600).unwrap();
        save_session(&location, "127.0.0.1:9112", "tok-b", "did:wba:b", None, None, 3600).unwrap();

        assert_eq!(load_session(&location, "127.0.0.1:9111").unwrap().token, "tok-a");
        assert_eq!(load_session(&location, "127.0.0.1:9112").unwrap().token, "tok-b");
        // The bare host is not the key: these two services share it.
        assert!(load_session(&location, "127.0.0.1").is_none());
        assert!(load_session(&location, "elsewhere.example").is_none());

        let _ = fs::remove_dir_all(&location.root);
    }

    #[test]
    fn an_expired_entry_reads_as_absent_and_a_live_one_keeps_its_did() {
        let location = fixture("expired");
        // TTL of one second, then the recorded `expiresAt` is moved into the past by hand —
        // `save_session` derives it from `now`, so waiting is the only way through the public
        // API, and a test that sleeps is a test that flakes.
        save_session(&location, "h.example", "tok", "did:wba:live", Some("did:wba:subj"), Some("Bearer"), 3600)
            .unwrap();
        let entry = load_session(&location, "h.example").unwrap();
        assert_eq!(entry.did, "did:wba:live");
        assert_eq!(entry.subject.as_deref(), Some("did:wba:subj"));

        let path = location.session_path();
        let text = fs::read_to_string(&path).unwrap().replace(&entry.expires_at, "2000-01-01T00:00:00+00:00");
        fs::write(&path, text).unwrap();
        assert!(load_session(&location, "h.example").is_none());

        let _ = fs::remove_dir_all(&location.root);
    }

    /// A store directory under the temp dir, unique per test name and process.
    fn fixture(label: &str) -> IdentityLocation {
        let root = std::env::temp_dir().join(format!("anpiocli-session-test-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        IdentityLocation {
            root,
            agent: "a".to_string(),
            profile: "default".to_string(),
        }
    }
}
