//! Keys held by `anpio-key`, the local signing daemon.
//!
//! `anpio-key` keeps a `did:wba` Ed25519 key inside a daemon and never hands the bytes
//! out: an agent asks over a Unix socket for an RFC 9421 signature over one HTTP request,
//! and the daemon rebuilds the signature base itself. That is enough for the surface this
//! client has in common with it — an ANP-02 login or `anp sign` — and nothing more.
//!
//! The boundary is deliberate and is enforced in [`crate::identity::Custody::refuse`]:
//! message origin proofs, MLS device keys and DID-document proofs are made from bytes this
//! client assembles, not from a whole HTTP request, so they cannot be delegated to a
//! daemon whose contract is "sign this request". An identity attached here says so up
//! front rather than failing halfway through a send.
//!
//! Everything goes through the `anpio-key` binary: this crate does not link the daemon, and
//! the daemon's socket protocol is its own (`docs/ADAPTER.md` over there). The binary is
//! `anpio-key` on `PATH`, or `$ANPIOCLI_ANPIO_KEY`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The environment override for the binary, for a checkout that is not installed yet.
pub const BINARY_ENV: &str = "ANPIOCLI_ANPIO_KEY";

const DEFAULT_BINARY: &str = "anpio-key";

/// Which `anpio-key` daemon holds a key, and which key of it signs.
///
/// The DID is not stored here: it is the identity's own, and a second copy could disagree
/// with `identity.did` — the one name every signature and every document has to agree on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnpioKey {
    /// `anpio-key --root DIR`, when the daemon does not use its default `~/.anpio-key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
    /// `--socket PATH`, when the socket is not the one derived from `root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    /// The key fragment (`key-1`, `recovery-1`, …). Absent means the daemon's default
    /// (binding) key for the DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl AnpioKey {
    /// A one-line description for humans and error messages.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(root) = &self.root {
            parts.push(format!("root {}", root.display()));
        }
        if let Some(socket) = &self.socket {
            parts.push(format!("socket {}", socket.display()));
        }
        let key = match &self.kid {
            Some(kid) => kid.clone(),
            None => "the default key".to_string(),
        };
        if parts.is_empty() {
            format!("anpio-key, {key}")
        } else {
            format!("anpio-key, {key} ({})", parts.join(", "))
        }
    }

    /// The key anpio-key will use when no fragment is named: the document's first
    /// `authentication` entry, which is the binding key for a `did:wba` E1 document.
    pub fn resolved_keyid(&self, document: &Value, did: &str) -> String {
        if let Some(kid) = &self.kid {
            return format!("{did}#{kid}");
        }
        binding_keyid(document).unwrap_or_else(|| format!("{did}#key-1"))
    }

    /// The DID document the daemon has published, verbatim.
    ///
    /// Fetching it on each signature rather than trusting the copy in `identity.json` is
    /// deliberate: the daemon is the one that owns the key, so a rotation it performed is
    /// already reflected there, and a cached document would make this client sign with a
    /// keyid the current document no longer names.
    pub fn document(&self, did: &str) -> Result<Value> {
        let mut args = vec!["document".to_string(), "--did".to_string(), did.to_string()];
        if let Some(socket) = &self.socket {
            args.push("--socket".to_string());
            args.push(socket.display().to_string());
        }
        let bytes = self.invoke(&args)?;
        let document: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("anpio-key returned a document for {did} that is not JSON"))?;
        if document.get("id").and_then(Value::as_str) != Some(did) {
            bail!(
                "anpio-key returned a document whose id is not {did}; refusing to attach a key \
                 to an identity it does not name"
            );
        }
        Ok(document)
    }

    /// Sign one HTTP request through the daemon and return the headers it made.
    ///
    /// The body goes through a private temporary file because that is the daemon's input
    /// contract (`--body` takes a path, not text), and the daemon computes `Content-Digest`
    /// over the bytes it reads — the same bytes this client will put on the wire.
    pub fn sign_headers(
        &self,
        did: &str,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        nonce: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        let body_file = match body {
            Some(bytes) => Some(write_body_file(bytes)?),
            None => None,
        };

        let mut args = vec![
            "sign".to_string(),
            "--did".to_string(),
            did.to_string(),
            "--method".to_string(),
            method.to_string(),
            "--url".to_string(),
            url.to_string(),
        ];
        if let Some(kid) = &self.kid {
            args.push("--kid".to_string());
            args.push(kid.clone());
        }
        if let Some(nonce) = nonce {
            args.push("--nonce".to_string());
            args.push(nonce.to_string());
        }
        if let Some(socket) = &self.socket {
            args.push("--socket".to_string());
            args.push(socket.display().to_string());
        }
        if let Some(path) = &body_file {
            args.push("--body".to_string());
            args.push(path.display().to_string());
        }

        let result = self.invoke(&args);
        if let Some(path) = &body_file {
            let _ = fs::remove_file(path);
        }
        parse_signed_headers(&result?, did)
    }

    fn invoke(&self, args: &[String]) -> Result<Vec<u8>> {
        let binary = match std::env::var(BINARY_ENV) {
            Ok(value) if !value.trim().is_empty() => value,
            _ => DEFAULT_BINARY.to_string(),
        };
        let mut command = Command::new(&binary);
        if let Some(root) = &self.root {
            command.arg("--root").arg(root);
        }
        command.args(args);

        let output = command.output().map_err(|err| {
            anyhow!(
                "could not run {binary}: {err}. Install anpio-key, or set ${BINARY_ENV} to its \
                 path"
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            bail!(
                "{binary} {} failed: {}",
                args.join(" "),
                if stderr.is_empty() { "no message" } else { stderr }
            );
        }
        Ok(output.stdout)
    }
}

/// `did:wba:<authority>:user:<handle>:e1_<fingerprint>` → its parts, as the attach command
/// needs them.
///
/// The authority is percent-decoded for a URL: `localhost%3A8000` is `localhost:8000`, and
/// the colon matters because it is the port. Only the two spellings that can appear in a
/// DID authority are handled; anything else is left alone rather than guessed at.
pub fn split_did(did: &str) -> Option<DidParts> {
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() != 6 || parts[0] != "did" || parts[1] != "wba" || parts[3] != "user" {
        return None;
    }
    if !parts[5].starts_with("e1_") {
        return None;
    }
    Some(DidParts {
        authority: parts[2].replace("%3A", ":").replace("%3a", ":"),
        handle: parts[4].to_string(),
    })
}

/// The two DID path segments a store entry needs.
#[derive(Debug, Clone)]
pub struct DidParts {
    /// The percent-decoded authority (`localhost:8000`).
    pub authority: String,
    /// The account handle (`alice`).
    pub handle: String,
}

impl DidParts {
    /// The URL a DID host most likely lives at, used when `--host` is not given.
    ///
    /// A DID carries an authority, not a scheme. `http` is chosen only for a loopback
    /// authority — the local `awiki-open-server` case — and `https` for everything else,
    /// because that is what a public host has to speak. It is a default, not a fact: the
    /// attach command takes `--host` for a host that is neither.
    pub fn default_host(&self) -> String {
        let host = self.authority.split(':').next().unwrap_or(&self.authority);
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "[::]");
        format!(
            "{}://{}",
            if loopback { "http" } else { "https" },
            self.authority
        )
    }
}

/// The `keyid` a signature was made under, read back from `Signature-Input`.
///
/// The daemon chooses the key, so the printed credential has to come from what it signed
/// rather than from this client's guess. `None` when the header is missing — the caller
/// then keeps its own guess, and the signature will be checked against the document anyway.
pub fn keyid_from_signature_input(headers: &BTreeMap<String, String>) -> Option<String> {
    let input = headers.get("Signature-Input")?;
    let start = input.find("keyid=\"")? + "keyid=\"".len();
    let rest = &input[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// True when the document publishes `keyid` as a verification method.
pub fn document_has_key(document: &Value, keyid: &str) -> bool {
    document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .any(|method| method.get("id").and_then(Value::as_str) == Some(keyid))
        })
        .unwrap_or(false)
}

/// The verification methods the document publishes, for an error that says what to pick.
pub fn document_keyids(document: &Value) -> Vec<String> {
    document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .map(|methods| {
            methods
                .iter()
                .filter_map(|method| method.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn binding_keyid(document: &Value) -> Option<String> {
    let first = document.get("authentication")?.as_array()?.first()?;
    match first {
        Value::String(id) => Some(id.clone()),
        Value::Object(map) => map.get("id").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

/// The daemon's header format: one `Name: value` per line, values cannot contain
/// newlines. Parsed strictly — a malformed line means the daemon and this client
/// disagree, and picking a header out of it would fail later at the peer.
fn parse_signed_headers(bytes: &[u8], did: &str) -> Result<BTreeMap<String, String>> {
    let text = std::str::from_utf8(bytes)
        .context("anpio-key returned signature headers that are not UTF-8")?;
    let mut headers = BTreeMap::new();
    for line in text.lines() {
        // A daemon on another platform may print CRLF; the value, not the line ending, is
        // what goes on the wire.
        let line = line.trim_end_matches('\r');
        let (name, value) = line.split_once(": ").ok_or_else(|| {
            anyhow!("anpio-key returned a malformed signature header: {line:?}")
        })?;
        if headers.insert(name.to_string(), value.to_string()).is_some() {
            bail!("anpio-key returned {name} twice, so the signature cannot be trusted");
        }
    }
    if !headers.contains_key("Signature-Input") || !headers.contains_key("Signature") {
        bail!("anpio-key signed for {did} but returned no Signature-Input/Signature header");
    }
    Ok(headers)
}

/// Write the request body where the daemon can read it, and nowhere else.
///
/// The body of an ANP-02 request is public — a DID, a document, a nonce — but the file is
/// still written `0600` and removed as soon as the daemon has answered: a predictable
/// path that outlives the call is a path another process can plant something at.
fn write_body_file(body: &[u8]) -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let path = std::env::temp_dir().join(format!(
        "anpio-cli-anpio-key-{}-{stamp}.json",
        std::process::id()
    ));
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    restrict_permissions(&path)?;
    Ok(path)
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
    use serde_json::json;

    #[test]
    fn a_did_wba_e1_did_is_split_into_an_authority_and_a_handle() {
        let parts = split_did("did:wba:localhost%3A8000:user:alice:e1_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG").unwrap();
        assert_eq!(parts.authority, "localhost:8000");
        assert_eq!(parts.handle, "alice");
        assert_eq!(parts.default_host(), "http://localhost:8000");
        assert_eq!(
            split_did("did:wba:did.example.com:user:bob:e1_x")
                .unwrap()
                .default_host(),
            "https://did.example.com"
        );
    }

    #[test]
    fn anything_that_is_not_a_did_wba_e1_did_is_refused() {
        for did in [
            "did:web:example.com",
            "did:wba:example.com:user:alice",
            "did:wba:example.com:user:alice:e2_x",
            "did:wba:example.com:org:alice:e1_x",
        ] {
            assert!(split_did(did).is_none(), "{did} must not look attachable");
        }
    }

    #[test]
    fn the_keyid_is_read_back_from_what_the_daemon_signed() {
        let headers = BTreeMap::from([(
            "Signature-Input".to_string(),
            "sig1=(\"@method\" \"@target-uri\");keyid=\"did:wba:h:user:a:e1_x#key-2\";created=1"
                .to_string(),
        )]);
        assert_eq!(
            keyid_from_signature_input(&headers).as_deref(),
            Some("did:wba:h:user:a:e1_x#key-2")
        );
        assert_eq!(keyid_from_signature_input(&BTreeMap::new()), None);
    }

    #[test]
    fn the_default_key_is_the_documents_first_authentication_entry() {
        let document = json!({
            "id": "did:wba:h:user:a:e1_x",
            "authentication": ["did:wba:h:user:a:e1_x#key-1"],
            "verificationMethod": [
                {"id": "did:wba:h:user:a:e1_x#key-1"},
                {"id": "did:wba:h:user:a:e1_x#recovery-1"}
            ]
        });
        let key = AnpioKey { root: None, socket: None, kid: None };
        assert_eq!(
            key.resolved_keyid(&document, "did:wba:h:user:a:e1_x"),
            "did:wba:h:user:a:e1_x#key-1"
        );
        let named = AnpioKey { kid: Some("recovery-1".to_string()), ..key };
        assert_eq!(
            named.resolved_keyid(&document, "did:wba:h:user:a:e1_x"),
            "did:wba:h:user:a:e1_x#recovery-1"
        );
        assert!(document_has_key(&document, "did:wba:h:user:a:e1_x#recovery-1"));
        assert!(!document_has_key(&document, "did:wba:h:user:a:e1_x#key-9"));
    }

    #[test]
    fn a_header_set_without_a_signature_is_not_accepted() {
        let err = parse_signed_headers(b"Signature-Input: sig1=()\n", "did:wba:h:u:a:e1_x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Signature"), "{err}");
        assert!(parse_signed_headers(b"no colon here\n", "did:wba:h:u:a:e1_x").is_err());
    }
}
