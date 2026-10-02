//! Where an identity lives on disk, and what is written there.
//!
//! The format is this client's own. TODO5 §8-E voids the old byte-compatibility
//! requirement: once the two clients stopped sharing a store root (§0.1 #1) there was no
//! longer anything to be compatible *with*.
//!
//! **The file holds private keys.** Per TODO4 §E the store is key material: it is written
//! `0600`, and backups, debugging and sharing are governed by the same rule as `mls/`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The store root's environment override.
///
/// Its own name on purpose: this client shares neither the TS CLI's `CONNECTX_HOME` nor
/// the service's `AGENTX_*`. Two clients pointed at one store root are one *device*, and
/// their `msg listen` processes would consume each other's deliveries (TODO5 §8-A).
pub const HOME_ENV: &str = "AGENTXCLI_HOME";

/// `<store root>`, from the environment or `~/.agentx-cli`.
pub fn store_root() -> PathBuf {
    match std::env::var(HOME_ENV) {
        Ok(value) if !value.trim().is_empty() => PathBuf::from(value),
        _ => home_dir().join(".agentx-cli"),
    }
}

fn home_dir() -> PathBuf {
    // `HOME` on unix; there is no Windows story for this client yet, and guessing one
    // here would only hide that (TODO5 §5 #4 tracks the platform matrix).
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// One identity's place in the store.
#[derive(Debug, Clone)]
pub struct IdentityLocation {
    pub root: PathBuf,
    pub agent: String,
    pub profile: String,
}

impl IdentityLocation {
    pub fn new(agent: impl Into<String>, profile: impl Into<String>) -> Self {
        Self {
            root: store_root(),
            agent: agent.into(),
            profile: profile.into(),
        }
    }

    /// `<root>/<agent>/<profile>` — the directory everything about this identity shares
    /// with its MLS store and (Phase 2) its message store.
    pub fn dir(&self) -> PathBuf {
        self.root.join(&self.agent).join(&self.profile)
    }

    pub fn identity_path(&self) -> PathBuf {
        self.dir().join("identity.json")
    }

    /// `realtime.md` §5.4: the delivery cursor is per `(owner_did, device_id)`, and the
    /// device defaults to the local `agent/profile` — the same two names everything else
    /// is stored under, so "one machine, a different profile" is two devices.
    pub fn default_device_id(&self) -> String {
        format!("{}/{}", self.agent, self.profile)
    }

    /// The location a command acts on, from its two flags. Both are validated here rather
    /// than at the first `join()`, because a name becomes a path segment.
    ///
    /// `agent` resolves through [`resolve_agent_id`] and `profile` through
    /// [`resolve_profile_name`], so neither flag has to be typed for the ordinary case.
    pub fn resolve(agent: Option<&str>, profile: Option<&str>) -> Result<Self> {
        Ok(Self {
            root: store_root(),
            agent: resolve_agent_id(agent)?,
            profile: resolve_profile_name(profile)?,
        })
    }
}

/// The environment overrides for the two names. Separate from `--agent` / `--profile` and
/// from the current-agent pointer, in that order: see [`resolve_agent_id`].
pub const AGENT_ENV: &str = "AGENTXCLI_AGENT";
pub const PROFILE_ENV: &str = "AGENTXCLI_PROFILE";

/// What the two names fall back to when nothing else named one.
const DEFAULT_AGENT: &str = "default";
const DEFAULT_PROFILE: &str = "default";

/// One path segment: letters, digits, dot, dash, underscore.
///
/// An agent id and a profile name are both directory names, so the boundary is checked
/// where the name enters — not left for a `join()` to trip over. `.` and `..` are spelled
/// out rather than left to the character class because they pass it.
pub fn assert_segment(value: &str, what: &str) -> Result<String> {
    let usable = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !usable {
        bail!(
            "invalid {what} \"{value}\" (allowed: letters, digits, dot, dash, underscore \
             — no path separators)"
        );
    }
    Ok(value.to_string())
}

/// `<store root>/current-agent` — the pointer `agent use` writes.
pub fn current_agent_path() -> PathBuf {
    store_root().join("current-agent")
}

/// The selected agent, or `None` when none was selected.
///
/// A MISSING file is the ordinary state and is not an error. A file that holds something
/// which cannot be an agent id *is* an error: it would otherwise fail later inside
/// [`assert_segment`], naming the value but not the file it came from — and that file is
/// the only thing the user can edit to fix it.
pub fn read_current_agent() -> Result<Option<String>> {
    let path = current_agent_path();
    let raw = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    let value = raw.trim();
    if value.is_empty() {
        return Ok(None);
    }
    assert_segment(value, "agent id").map(Some).map_err(|err| {
        // Re-worded to name the file: see the doc comment. The value is already in `err`.
        anyhow::anyhow!("the current agent ({}) is not a usable agent id: {err}. Run: agentx-cli agent use <id>", path.display())
    })
}

/// Write the selection, returning the file it went to.
///
/// The id is validated but NOT required to exist: selecting an agent and then creating its
/// identity is the order a new agent is born in. `agent use` says so out loud instead of
/// refusing (see `cmd_agent_use`).
pub fn select_current_agent(id: &str) -> Result<PathBuf> {
    let agent = assert_segment(id, "agent id")?;
    let path = current_agent_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(&path, format!("{agent}\n")).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Which step of the chain named the agent.
///
/// The chain itself is [`resolve_agent_id`]; this reports WHICH step spoke, because that is
/// the question `agentx-cli agent show` exists to answer. "Why is it acting as that one" is
/// otherwise a guess about the shell that ran it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSource {
    /// `--agent`.
    Flag,
    /// `$AGENTXCLI_AGENT`.
    Env,
    /// The `current-agent` pointer (`agent use` wrote it).
    Current,
    /// Nothing named one; this is the fallback.
    Default,
}

impl AgentSource {
    /// A phrase for a human reader, naming the place to look rather than the step's name.
    pub fn describe(self) -> String {
        match self {
            AgentSource::Flag => "--agent".to_string(),
            AgentSource::Env => format!("${AGENT_ENV}"),
            AgentSource::Current => format!("the current agent ({})", current_agent_path().display()),
            AgentSource::Default => "nothing named one: the fallback".to_string(),
        }
    }
}

/// `--agent` > `$AGENTXCLI_AGENT` > the current agent > `default`.
///
/// The current agent (`agentx-cli agent use`) sits BELOW the flag and the env var, each of
/// which is said for one invocation: a script that names an agent must not be redirected
/// by a selection left lying in the store. It sits ABOVE the default, which is the only
/// other candidate — this client has no equivalent of the TS CLI's marker detection, which
/// guesses an agent from other tools' environment variables (`docs/design/cli.md` §1
/// leaves that to the application; there is no marker set here to guess from, and a guess
/// is the one step that could pick the wrong identity silently).
pub fn resolve_agent_id(flag: Option<&str>) -> Result<String> {
    Ok(resolve_agent_id_with_source(flag)?.0)
}

/// The same chain, plus which step answered. `agent show` is the only caller that needs the
/// second half; everyone else wants only the name, and has no business embedding the order.
pub fn resolve_agent_id_with_source(flag: Option<&str>) -> Result<(String, AgentSource)> {
    if let Some(value) = flag.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok((assert_segment(value, "agent id")?, AgentSource::Flag));
    }
    if let Ok(value) = std::env::var(AGENT_ENV) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return Ok((assert_segment(&value, "agent id")?, AgentSource::Env));
        }
    }
    if let Some(current) = read_current_agent()? {
        return Ok((current, AgentSource::Current));
    }
    Ok((DEFAULT_AGENT.to_string(), AgentSource::Default))
}

/// `--profile` > `$AGENTXCLI_PROFILE` > `default`. No current-profile pointer: a profile
/// is a second identity for the same agent, not a machine-wide mode (`agent` family).
pub fn resolve_profile_name(flag: Option<&str>) -> Result<String> {
    if let Some(value) = flag.map(str::trim).filter(|value| !value.is_empty()) {
        return assert_segment(value, "profile name");
    }
    if let Ok(value) = std::env::var(PROFILE_ENV) {
        let value = value.trim().to_string();
        if !value.is_empty() {
            return assert_segment(&value, "profile name");
        }
    }
    Ok(DEFAULT_PROFILE.to_string())
}

/// One identity the store holds, as `agent list` prints it.
#[derive(Debug, Clone, Serialize)]
pub struct StoredIdentitySummary {
    pub agent: String,
    pub profile: String,
    pub dir: PathBuf,
    /// Read back off the identity file; `None` when it is unreadable. A malformed file
    /// must not hide the directory from the list — it is exactly the thing the user needs
    /// to see in order to fix it.
    pub did: Option<String>,
    pub handle: Option<String>,
}

/// Every `<agent>/<profile>` under the store root that holds an `identity.json`.
///
/// Reads the store; contacts nothing. Sorted by `agent/profile` so the order does not
/// depend on the filesystem's.
pub fn list_identities() -> Result<Vec<StoredIdentitySummary>> {
    let root = store_root();
    let mut out = Vec::new();
    for agent in read_dir_names(&root)? {
        for profile in read_dir_names(&root.join(&agent))? {
            let dir = root.join(&agent).join(&profile);
            let path = dir.join("identity.json");
            if !path.is_file() {
                continue;
            }
            let recorded = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Identity>(&text).ok());
            out.push(StoredIdentitySummary {
                agent: agent.clone(),
                profile,
                dir,
                did: recorded.as_ref().map(|identity| identity.did.clone()),
                handle: recorded.map(|identity| identity.handle),
            });
        }
    }
    out.sort_by(|a, b| (&a.agent, &a.profile).cmp(&(&b.agent, &b.profile)));
    Ok(out)
}

/// The directory names directly under `path`, sorted. A missing directory is empty, not an
/// error: before the first identity exists, the store root itself may not.
fn read_dir_names(path: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    let mut names: Vec<String> = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    Ok(names)
}

/// A key pair as it is stored: PEM in, PEM out, so the file does not depend on any one
/// curve's encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyPair {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

/// Everything `did show` and every later command needs about one identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub did: String,
    pub device_id: String,
    pub agent: String,
    pub profile: String,
    /// The awiki handle this identity registered under.
    pub handle: String,
    /// The host the DID document is published on, as the user typed it.
    pub did_host: String,
    pub created_at: String,
    /// `key-1` (Ed25519 identity), `key-2` (Secp256r1 E2EE signing), `key-3` (X25519
    /// agreement). Fragments match the document's verification methods.
    pub keys: BTreeMap<String, StoredKeyPair>,
    /// The signed document exactly as published — kept so `did show` can render the
    /// published state without a network round trip, and so a register can be retried.
    pub did_document: Value,
}

impl Identity {
    pub fn load(location: &IdentityLocation) -> Result<Self> {
        let path = location.identity_path();
        let text = fs::read_to_string(&path).with_context(|| {
            format!(
                "no identity for agent \"{}\" profile \"{}\" ({}). Run: agentx-cli did create, or \
                 agentx-cli agent list to see what is stored and agentx-cli agent use to select one",
                location.agent,
                location.profile,
                path.display()
            )
        })?;
        serde_json::from_str(&text).with_context(|| format!("{} is not a readable identity", path.display()))
    }

    /// Write the identity, creating its directory. Replaces atomically so an interrupted
    /// write cannot leave a half-file where a private key used to be.
    pub fn save(&self, location: &IdentityLocation) -> Result<()> {
        let dir = location.dir();
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = location.identity_path();
        let temporary = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)?;
        fs::write(&temporary, text).with_context(|| format!("writing {}", temporary.display()))?;
        restrict_permissions(&temporary)?;
        fs::rename(&temporary, &path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// True when the file is only readable by its owner. `0600` is what `save` writes;
    /// this is for the warning a later command prints when it finds otherwise.
    pub fn permissions_are_private(location: &IdentityLocation) -> bool {
        permissions_are_private(&location.identity_path())
    }
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

#[cfg(unix)]
fn permissions_are_private(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o077 == 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn permissions_are_private(_path: &Path) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// The store root and the two names are process-wide state, so the tests that set them
    /// must not run beside each other. One lock for the module is enough — nothing outside
    /// it touches these variables.
    static ENV: Mutex<()> = Mutex::new(());

    /// A temp directory that removes itself, standing in for `tempfile` (`agentx-cli` has
    /// no dev-dependencies, and one `struct` is cheaper than one for this).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("agentx-cli-store-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("creating the scratch store root");
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Point the store at a scratch root with neither name left in the environment, so a
    /// developer's own `AGENTXCLI_AGENT` cannot decide what these tests observe.
    fn isolated(name: &str) -> (MutexGuard<'static, ()>, Scratch) {
        let guard = ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let scratch = Scratch::new(name);
        std::env::set_var(HOME_ENV, &scratch.0);
        std::env::remove_var(AGENT_ENV);
        std::env::remove_var(PROFILE_ENV);
        (guard, scratch)
    }

    /// A minimal identity file: only the fields `list_identities` reads are meaningful.
    fn write_identity(root: &Path, agent: &str, profile: &str) {
        let dir = root.join(agent).join(profile);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("identity.json"),
            format!(
                r#"{{"did":"did:wba:host:user:{agent}","device_id":"{agent}/{profile}",
                    "agent":"{agent}","profile":"{profile}","handle":"{agent}",
                    "did_host":"http://host","created_at":"2026-10-02T00:00:00Z",
                    "keys":{{}},"did_document":{{}}}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn a_segment_refuses_traversal_and_separators() {
        assert_eq!(assert_segment("rusty", "agent id").unwrap(), "rusty");
        assert_eq!(assert_segment("a.b-c_1", "agent id").unwrap(), "a.b-c_1");
        for bad in ["", ".", "..", "a/b", "../x", "a b", "a\\b"] {
            assert!(
                assert_segment(bad, "agent id").is_err(),
                "{bad:?} must not become a path segment"
            );
        }
    }

    #[test]
    fn the_current_agent_is_read_back_and_a_missing_file_is_not_an_error() {
        let (_guard, scratch) = isolated("current");
        assert_eq!(read_current_agent().unwrap(), None);

        let path = select_current_agent("alice").unwrap();
        assert_eq!(path, scratch.0.join("current-agent"));
        assert_eq!(read_current_agent().unwrap().as_deref(), Some("alice"));

        select_current_agent("bob").unwrap();
        assert_eq!(
            read_current_agent().unwrap().as_deref(),
            Some("bob"),
            "overwriting is how the selection moves"
        );
    }

    #[test]
    fn a_malformed_current_agent_names_the_file_that_holds_it() {
        let (_guard, scratch) = isolated("malformed");
        fs::write(scratch.0.join("current-agent"), "not/a/name\n").unwrap();
        let err = read_current_agent().unwrap_err().to_string();
        // The file is the only thing the user can edit, so the message has to say which.
        assert!(err.contains("current-agent"), "{err}");
        assert!(err.contains("agentx-cli agent use"), "{err}");
    }

    #[test]
    fn the_chain_puts_the_flag_and_the_env_above_the_selection() {
        let (_guard, scratch) = isolated("chain");
        select_current_agent("selected").unwrap();
        std::env::set_var(AGENT_ENV, "from-env");

        assert_eq!(
            resolve_agent_id_with_source(Some("typed")).unwrap(),
            ("typed".to_string(), AgentSource::Flag)
        );
        assert_eq!(
            resolve_agent_id_with_source(None).unwrap(),
            ("from-env".to_string(), AgentSource::Env)
        );

        std::env::remove_var(AGENT_ENV);
        assert_eq!(
            resolve_agent_id_with_source(None).unwrap(),
            ("selected".to_string(), AgentSource::Current)
        );

        fs::remove_file(scratch.0.join("current-agent")).unwrap();
        assert_eq!(
            resolve_agent_id_with_source(None).unwrap(),
            (DEFAULT_AGENT.to_string(), AgentSource::Default)
        );
    }

    #[test]
    fn a_blank_flag_or_env_falls_through_instead_of_naming_an_empty_agent() {
        let (_guard, _scratch) = isolated("blank");
        assert_eq!(resolve_agent_id(Some("   ")).unwrap(), DEFAULT_AGENT);
        std::env::set_var(AGENT_ENV, "  ");
        assert_eq!(resolve_agent_id(None).unwrap(), DEFAULT_AGENT);
        assert_eq!(resolve_profile_name(None).unwrap(), DEFAULT_PROFILE);
    }

    #[test]
    fn the_profile_chain_has_no_selection_only_a_flag_and_an_env() {
        let (_guard, _scratch) = isolated("profile");
        assert_eq!(resolve_profile_name(Some("work")).unwrap(), "work");
        std::env::set_var(PROFILE_ENV, "from-env");
        assert_eq!(resolve_profile_name(None).unwrap(), "from-env");
    }

    #[test]
    fn a_location_resolves_both_names_off_the_same_root() {
        let (_guard, scratch) = isolated("location");
        select_current_agent("alice").unwrap();
        let location = IdentityLocation::resolve(None, Some("work")).unwrap();
        assert_eq!(location.root, scratch.0);
        assert_eq!(location.agent, "alice");
        assert_eq!(location.profile, "work");
        assert_eq!(location.dir(), scratch.0.join("alice").join("work"));
    }

    #[test]
    fn listing_finds_every_stored_identity_and_ignores_a_directory_with_none() {
        let (_guard, scratch) = isolated("list");
        write_identity(&scratch.0, "alice", "default");
        write_identity(&scratch.0, "bob", "work");
        write_identity(&scratch.0, "bob", "default");
        // A profile directory that never got an identity is not an identity.
        fs::create_dir_all(scratch.0.join("alice").join("empty")).unwrap();

        let found = list_identities().unwrap();
        let named: Vec<String> = found.iter().map(|e| format!("{}/{}", e.agent, e.profile)).collect();
        assert_eq!(named, ["alice/default", "bob/default", "bob/work"]);
        assert_eq!(found[0].handle.as_deref(), Some("alice"));
        assert_eq!(found[0].did.as_deref(), Some("did:wba:host:user:alice"));
    }

    #[test]
    fn a_malformed_identity_does_not_hide_itself_from_the_list() {
        let (_guard, scratch) = isolated("list-malformed");
        write_identity(&scratch.0, "alice", "default");
        let dir = scratch.0.join("broken").join("default");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("identity.json"), "{ not json").unwrap();

        let found = list_identities().unwrap();
        let broken = found.iter().find(|e| e.agent == "broken").expect("still listed");
        // It is exactly the entry the user needs to see in order to fix it.
        assert_eq!(broken.did, None);
        assert_eq!(broken.handle, None);
    }
}
