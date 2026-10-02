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

use anyhow::{Context, Result};
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
                "no identity for agent \"{}\" profile \"{}\" ({}). Run: agentx-cli did create",
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
