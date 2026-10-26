//! Keys held by `anpio-key`, the local signing daemon.
//!
//! `anpio-key` keeps a `did:wba` Ed25519 key inside a daemon and never hands the bytes
//! out: an agent asks over a Unix socket for an RFC 9421 signature over one HTTP request,
//! and the daemon rebuilds the signature base itself. That is enough for the surface this
//! client has in common with it — an ANP-02 login or `anp sign` — and nothing more.
//!
//! The boundary is deliberate: message origin proofs, MLS device assertions and DID-document
//! proofs are made from bytes this client assembles, not from a whole HTTP request. Which of
//! them a given daemon can make is negotiated rather than assumed — see [`Capabilities`] —
//! and `Custody::require` refuses the rest before a command starts its network work.
//!
//! Everything goes through the `anpio-key` binary: this crate does not link the daemon, and
//! the daemon's socket protocol is its own (`docs/ADAPTER.md` over there). The development
//! surface uses `anpio-key` on `PATH`, or `$ANPIOCLI_ANPIO_KEY`; the protected `data
//! --config` surface is pinned to the administrator-installed binary and never reads that
//! override.

use std::collections::{BTreeMap, BTreeSet};
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The administrator-owned protected configuration (`anpio-key data --config`). When
    /// set, capabilities are negotiated on that protected surface; absent means the
    /// development socket named by `root` / `socket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,
    /// The grant this identity was issued. Required for every protected operation except
    /// the development surface's HTTP signing; its presence is not proof that the grant is
    /// still valid (`GET_GRANT_STATUS` answers that).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// The device name in the DID document (`{device}-sign`, `{device}-agreement`). Needed
    /// once device assertions are delegated; absent means no device key is bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// The daemon's last negotiated operation names, cached so an ordinary command does
    /// not spawn `anpio-key` just to be refused. Unknown names are kept verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operations: Option<Vec<String>>,
}

/// One ANP origin proof made by the daemon.
///
/// `signature_input` and `signature` are passed through as the daemon produced them: the
/// daemon canonicalises `{method, meta, body}` and builds the signature base, so anything
/// this side rebuilt would be a second implementation of the thing the daemon exists to own.
/// `created` comes back because it was the daemon's clock that signed it.
#[derive(Debug, Clone)]
pub struct OriginProofSigning {
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
    pub created: i64,
    pub expires: Option<i64>,
}

/// A grant as `GET_GRANT_STATUS` / `RENEW_GRANT` report it.
///
/// The daemon's reply carries more (policy, boot epoch, principal); these are the fields a
/// caller can act on, and unknown ones are ignored rather than mirrored, so a daemon that
/// adds a field does not break this client.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct GrantStatus {
    pub grant_id: String,
    pub key_id: String,
    /// `active`, `expired`, `exhausted` or `revoked`.
    pub state: String,
    /// Unix seconds.
    pub expiry: i64,
    /// `request` or `session`; only a session grant can be renewed.
    pub kind: String,
    pub max_uses: u32,
    pub used_uses: u32,
    pub max_renewals: u32,
    pub renewals: u32,
}

impl GrantStatus {
    /// Uses left before the grant is exhausted, zero when it already is.
    pub fn remaining_uses(&self) -> u32 {
        self.max_uses.saturating_sub(self.used_uses)
    }

    /// Whether signing may start at all: an expired or exhausted grant fails every call.
    pub fn usable(&self) -> bool {
        self.state == "active" && self.remaining_uses() > 0
    }
}

/// When a long-running command renews, and how far out it asks for.
///
/// A listener re-signs on every reconnect, so a grant that runs out mid-run ends the stream.
/// Renewing an hour before expiry is early enough that the reconnect after it signs, and
/// late enough that starting a listener twice in an afternoon does not spend a renewal each
/// time. The request is deliberately further out than the window: the daemon clamps it to
/// the policy's ceiling, so this asks for "as long as the administrator allowed" without
/// this client having to know that number.
pub const GRANT_RENEW_WINDOW_SECS: i64 = 3_600;
pub const GRANT_RENEW_REQUEST_SECS: i64 = 86_400;

/// Whether `status` can carry a command that will still be signing later, and if not, why.
///
/// Split from the daemon calls so the decision is testable: every refusal here names what
/// the administrator would have to change, because none of it is something this client can
/// fix by trying again.
fn runway_plan(status: &GrantStatus, now: i64) -> Result<bool> {
    if !status.usable() {
        bail!(
            "anpio-key reports grant {} as {} with {} of {} uses left, so this command's first \
             signature would already fail. Ask the anpio-key administrator for a fresh grant, \
             then: anpio-cli did attach-anpio-key --grant <grant-id>",
            status.grant_id,
            status.state,
            status.remaining_uses(),
            status.max_uses
        );
    }
    if status.expiry - now >= GRANT_RENEW_WINDOW_SECS {
        return Ok(false);
    }
    if status.kind != "session" {
        bail!(
            "grant {} is a `{}` grant that expires in {} seconds; only a session grant can be \
             renewed, so a listener started on it will stop signing when it expires. Ask the \
             anpio-key administrator for a session grant",
            status.grant_id,
            status.kind,
            status.expiry - now
        );
    }
    if status.renewals >= status.max_renewals {
        bail!(
            "grant {} expires in {} seconds and has used all {} of its renewals. Ask the \
             anpio-key administrator for a fresh session grant",
            status.grant_id,
            status.expiry - now,
            status.max_renewals
        );
    }
    Ok(true)
}

/// A proof this client can ask `anpio-key` to produce.
///
/// The names are the daemon's (`ADAPTER.md` §11.3), because they are what `GET_CAPABILITIES`
/// lists; [`Operation::cli_name`] is the short spelling this client prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    /// RFC 9421 headers over one whole HTTP request (ANP-02 login, `anp sign`).
    Http,
    /// ANP origin proof: a digest over `{method, meta, body}` and a signature base over it.
    OriginProof,
    /// A fixed-purpose device assertion (MLS KeyPackage binding).
    Purpose,
    /// A W3C data-integrity proof over the DID document.
    DocumentProof,
    /// A W3C data-integrity proof over another object.
    ObjectProof,
    /// An X25519 key agreement.
    Ecdh,
}

impl Operation {
    pub fn daemon_name(self) -> &'static str {
        match self {
            Operation::Http => "SIGN_HTTP",
            Operation::OriginProof => "SIGN_ORIGIN_PROOF",
            Operation::Purpose => "SIGN_PURPOSE",
            Operation::DocumentProof => "SIGN_DOCUMENT_PROOF",
            Operation::ObjectProof => "SIGN_OBJECT_PROOF",
            Operation::Ecdh => "ECDH",
        }
    }

    pub fn cli_name(self) -> &'static str {
        match self {
            Operation::Http => "http",
            Operation::OriginProof => "origin-proof",
            Operation::Purpose => "purpose",
            Operation::DocumentProof => "document-proof",
            Operation::ObjectProof => "object-proof",
            Operation::Ecdh => "ecdh",
        }
    }

    fn from_daemon_name(name: &str) -> Option<Self> {
        [
            Operation::Http,
            Operation::OriginProof,
            Operation::Purpose,
            Operation::DocumentProof,
            Operation::ObjectProof,
            Operation::Ecdh,
        ]
        .into_iter()
        .find(|operation| operation.daemon_name() == name)
    }

    /// Whether this build has the calling code that consumes the daemon's result.
    ///
    /// A daemon may announce an operation this client cannot drive yet; that is a client
    /// gap, not a daemon gap, and the two are reported differently. Stage 1 flips this for
    /// `OriginProof`, stage 2 for `Purpose`, and so on.
    pub fn implemented(self) -> bool {
        matches!(self, Operation::Http | Operation::OriginProof)
    }

    pub fn purpose(self) -> &'static str {
        match self {
            Operation::Http => "an RFC 9421 signature over one HTTP request",
            Operation::OriginProof => "an ANP origin proof over bytes this client assembles",
            Operation::Purpose => "a device assertion for group end-to-end encryption",
            Operation::DocumentProof => "a W3C proof over the DID document",
            Operation::ObjectProof => "a W3C proof over another object",
            Operation::Ecdh => "an X25519 key agreement",
        }
    }
}

/// The six data operations every v2 daemon has today (`ADAPTER.md` §11.2). Used when a
/// daemon answers `GET_CAPABILITIES` without the `operations` field the capability schema
/// adds.
const KNOWN_V2_OPERATIONS: &[&str] = &[
    "GET_CAPABILITIES",
    "LIST_AUTHORIZED_KEYS",
    "GET_GRANT_STATUS",
    "GET_DOCUMENT",
    "SIGN_HTTP",
    "GET_REQUEST_STATUS",
];

/// Where a capability set came from, which decides how the refusal may phrase it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilitySource {
    /// Read from `AnpioKey::operations`, written by an earlier negotiation.
    Cached,
    /// Just answered by `GET_CAPABILITIES` on the protected surface.
    Daemon,
    /// No cache and no protected config: the development socket, which signs HTTP requests.
    Baseline,
}

impl CapabilitySource {
    pub fn name(self) -> &'static str {
        match self {
            CapabilitySource::Cached => "cached",
            CapabilitySource::Daemon => "daemon",
            CapabilitySource::Baseline => "baseline",
        }
    }
}

/// What this custody can delegate, as negotiated or as cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    operations: BTreeSet<Operation>,
    announced: BTreeSet<String>,
    source: CapabilitySource,
}

impl Capabilities {
    fn baseline() -> Self {
        // The development socket signs whole HTTP requests. The other five v2 names never
        // reach this client without a protected config, so claiming them here would make
        // the refusal lie about what the daemon is offering.
        Self::from_names(&["SIGN_HTTP".to_string()], CapabilitySource::Baseline)
    }

    fn from_names(names: &[String], source: CapabilitySource) -> Self {
        let mut operations = BTreeSet::new();
        let mut announced = BTreeSet::new();
        for name in names {
            if let Some(operation) = Operation::from_daemon_name(name) {
                operations.insert(operation);
            }
            announced.insert(name.clone());
        }
        Self { operations, announced, source }
    }

    pub fn contains(&self, operation: Operation) -> bool {
        self.operations.contains(&operation)
    }

    pub fn source(&self) -> CapabilitySource {
        self.source
    }

    /// The operations this build actually drives, in a stable order.
    pub fn effective(&self) -> Vec<&'static str> {
        self.operations
            .iter()
            .filter(|operation| operation.implemented())
            .map(|operation| operation.cli_name())
            .collect()
    }

    /// The daemon-announced operations this client knows by name.
    pub fn announced_operations(&self) -> Vec<&'static str> {
        self.operations
            .iter()
            .map(|operation| operation.cli_name())
            .collect()
    }

    /// Everything the daemon announced, including names newer than this client.
    pub fn announced_names(&self) -> Vec<String> {
        self.announced.iter().cloned().collect()
    }

    /// The operations announced but not driven by this build — the honest "why is this
    /// command still refused?" line.
    pub fn announced_not_effective(&self) -> Vec<&'static str> {
        self.operations
            .iter()
            .filter(|operation| !operation.implemented())
            .map(|operation| operation.cli_name())
            .collect()
    }

    pub fn announced_clause(&self) -> String {
        let names = self.announced_names();
        let list = if names.is_empty() {
            "nothing".to_string()
        } else {
            names.join(", ")
        };
        match self.source {
            CapabilitySource::Baseline => {
                format!("offers, through its development socket, only {list}")
            }
            CapabilitySource::Cached => format!("last announced {list}"),
            CapabilitySource::Daemon => format!("announces {list}"),
        }
    }
}

impl AnpioKey {
    /// A one-line description for humans and error messages.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(config) = &self.config {
            parts.push(format!("config {}", config.display()));
        }
        if let Some(root) = &self.root {
            parts.push(format!("root {}", root.display()));
        }
        if let Some(socket) = &self.socket {
            parts.push(format!("socket {}", socket.display()));
        }
        if let Some(device) = &self.device {
            parts.push(format!("device {device}"));
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

    /// What this daemon can do, asking it only when no cached answer exists.
    ///
    /// A cached set is authoritative: if it lacks an operation, this client does not fall
    /// back to the development surface or to a different operation. A daemon without a
    /// protected config and without a cache is on the development socket, which is known
    /// to sign HTTP requests and nothing else — that answer costs no subprocess.
    pub fn capabilities(&self) -> Result<Capabilities> {
        if let Some(names) = &self.operations {
            return Ok(Capabilities::from_names(names, CapabilitySource::Cached));
        }
        if self.config.is_some() {
            return self.query_capabilities();
        }
        Ok(Capabilities::baseline())
    }

    /// What is known without contacting the daemon.
    pub fn known_capabilities(&self) -> Capabilities {
        match &self.operations {
            Some(names) => Capabilities::from_names(names, CapabilitySource::Cached),
            None => Capabilities::baseline(),
        }
    }

    /// Ask the protected surface (`anpio-key data --config`) for its capability set.
    fn query_capabilities(&self) -> Result<Capabilities> {
        let config = self
            .config
            .as_ref()
            .expect("query_capabilities is only reached with a protected config");
        let request = serde_json::to_vec(&serde_json::json!({"operation": "GET_CAPABILITIES"}))?;
        let path = write_temp_json(&request)?;
        let args = vec![
            "data".to_string(),
            "--config".to_string(),
            config.display().to_string(),
            "--file".to_string(),
            path.display().to_string(),
        ];
        let result = self.invoke_protected(&args);
        let _ = fs::remove_file(&path);
        parse_capabilities(&result?)
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
            Some(bytes) => Some(write_temp_json(bytes)?),
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

    /// The request one `SIGN_ORIGIN_PROOF` sends, as the daemon reads it.
    ///
    /// Split out from the subprocess so the shape can be asserted without a daemon. There is
    /// no `created` field: the daemon's clock is the one that signs, and a caller-supplied
    /// creation time would let a proof be replayed outside its window.
    pub fn origin_proof_request(
        grant: &str,
        request_id: &str,
        method: &str,
        meta: &Value,
        body: &Value,
    ) -> Value {
        serde_json::json!({
            "operation": "SIGN_ORIGIN_PROOF",
            "grant_id": grant,
            "request_id": request_id,
            "origin": {"method": method, "meta": meta, "body": body},
        })
    }

    /// Ask the daemon for an ANP origin proof over `{method, meta, body}`.
    ///
    /// This is the protected surface only. The development socket signs whole HTTP requests
    /// and has neither grants nor audit; when the identity names no config there is nothing
    /// here to fall back to, so the refusal says which attach flag fixes it.
    pub fn sign_origin_proof(
        &self,
        did: &str,
        request_id: &str,
        method: &str,
        meta: &Value,
        body: &Value,
    ) -> Result<OriginProofSigning> {
        self.config.as_ref().ok_or_else(|| {
            anyhow!(
                "{did} reaches anpio-key over its development socket, which cannot make an ANP \
                 origin proof; re-run: anpio-cli did attach-anpio-key --config \
                 <service.json>"
            )
        })?;
        let grant = self.grant.as_ref().ok_or_else(|| {
            anyhow!(
                "{did} has no anpio-key grant, so the daemon has no authorization for \
                 SIGN_ORIGIN_PROOF; ask the anpio-key administrator for a session grant, then \
                 re-run: anpio-cli did attach-anpio-key --grant <grant-id>"
            )
        })?;

        let request = Self::origin_proof_request(grant, request_id, method, meta, body);
        origin_proof_from_data(self.protected_request(&request)?)
    }

    /// One `anpio-key data --config` call, returning the reply's `data`.
    ///
    /// The request file is written `0600` and deleted as soon as the daemon has answered;
    /// only `OK` carries a `data` object, because every other code means the operation did
    /// not happen and a caller must not proceed as if it had.
    fn protected_request(&self, request: &Value) -> Result<Value> {
        let operation = request
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("request")
            .to_string();
        let config = self.config.as_ref().ok_or_else(|| {
            anyhow!(
                "this anpio-key identity names no protected config, so {operation} cannot be \
                 requested; re-run: anpio-cli did attach-anpio-key --config <service.json>"
            )
        })?;
        let path = write_temp_json(&serde_json::to_vec(request)?)?;
        let args = vec![
            "data".to_string(),
            "--config".to_string(),
            config.display().to_string(),
            "--file".to_string(),
            path.display().to_string(),
        ];
        let result = self.invoke_protected(&args);
        let _ = fs::remove_file(&path);
        let bytes = result?;
        let reply: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("anpio-key returned a {operation} reply that is not JSON"))?;
        let code = reply
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or("missing code");
        if code != "OK" {
            bail!("anpio-key refused {operation} with {code}");
        }
        Ok(reply.get("data").cloned().unwrap_or(Value::Null))
    }

    /// The grant this identity signs under, by name.
    fn grant_id(&self) -> Result<&str> {
        self.grant.as_deref().ok_or_else(|| {
            anyhow!(
                "this anpio-key identity records no grant; ask the anpio-key administrator for \
                 one, then re-run: anpio-cli did attach-anpio-key --grant <grant-id>"
            )
        })
    }

    /// What the daemon says about this grant right now.
    ///
    /// Presence of a grant id is not proof it is usable: expiry, uses and renewals are the
    /// daemon's facts, and this is the one call that asks for them.
    pub fn grant_status(&self) -> Result<GrantStatus> {
        let grant = self.grant_id()?;
        let data = self.protected_request(&serde_json::json!({
            "operation": "GET_GRANT_STATUS",
            "grant_id": grant,
        }))?;
        serde_json::from_value(data)
            .context("anpio-key returned a grant status this client cannot read")
    }

    /// Ask to extend the grant to `expiry`.
    ///
    /// The daemon clamps the answer to the policy's ceilings, so a request further out than
    /// the policy allows is answered with the largest expiry it will grant rather than
    /// refused. An exhausted grant cannot be renewed, and a `request`-kind grant cannot
    /// either; both come back as a refusal code.
    pub fn renew_grant(&self, expiry: i64) -> Result<GrantStatus> {
        let grant = self.grant_id()?;
        let data = self.protected_request(&serde_json::json!({
            "operation": "RENEW_GRANT",
            "grant_id": grant,
            "expiry": expiry,
        }))?;
        serde_json::from_value(data)
            .context("anpio-key returned a renewed grant this client cannot read")
    }

    /// Make sure this grant can still sign later, renewing it when it is about to run out.
    ///
    /// Returns the renewed grant when a renewal happened, so the caller can say what the
    /// grant now reaches — the daemon may have clamped the request to the policy's ceiling,
    /// which is shorter than the caller asked for and worth showing. `Ok(None)` means the
    /// grant was already good enough and no daemon call beyond the status read was made.
    pub fn ensure_runway(&self) -> Result<Option<GrantStatus>> {
        let now = unix_now()?;
        let status = self.grant_status()?;
        if !runway_plan(&status, now)? {
            return Ok(None);
        }
        let renewed = self.renew_grant(now + GRANT_RENEW_REQUEST_SECS)?;
        if !renewed.usable() || renewed.expiry <= now {
            bail!(
                "anpio-key renewed grant {} but it is still {} with {} seconds left; a listener \
                 started now would stop signing immediately. Ask the anpio-key administrator to \
                 check the policy's lifetime ceiling",
                renewed.grant_id,
                renewed.state,
                renewed.expiry - now
            );
        }
        Ok(Some(renewed))
    }

    /// The DID document and key of an authorized key, read through the protected surface.
    ///
    /// The development surface has a `document` entry; the protected one does not. There the
    /// document is reached the way ADAPTER §11.3 defines it: list the principal's authorized
    /// keys, pick the one for this DID, then fetch its document — the same two calls any
    /// other protected client makes.
    pub fn authorized_document(&self, did: &str) -> Result<(Value, String)> {
        let keys = self.protected_request(&serde_json::json!({
            "operation": "LIST_AUTHORIZED_KEYS",
        }))?;
        let entry = keys
            .get("keys")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|item| item.get("did").and_then(Value::as_str) == Some(did))
            })
            .ok_or_else(|| {
                anyhow!(
                    "anpio-key authorizes no key for {did} under this principal; ask the \
                     administrator to register it, or check the DID"
                )
            })?;
        let key_id = entry
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("anpio-key listed a key without a key_id"))?;
        let kid = entry
            .get("kid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("anpio-key listed a key without a kid"))?;
        if let Some(wanted) = &self.kid {
            if wanted != kid {
                bail!(
                    "anpio-key authorizes {kid} for {did}, not {wanted}; drop --kid to use the \
                     authorized key"
                );
            }
        }
        let data = self.protected_request(&serde_json::json!({
            "operation": "GET_DOCUMENT",
            "key_id": key_id,
        }))?;
        let document = data.get("document").cloned().unwrap_or(Value::Null);
        if document.get("id").and_then(Value::as_str) != Some(did) {
            bail!(
                "anpio-key returned a document whose id is not {did}; refusing to attach a key \
                 to an identity it does not name"
            );
        }
        Ok((document, format!("{did}#{kid}")))
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

    /// Run the protected entry.
    ///
    /// Two things are deliberately absent compared with [`Self::invoke`]: `--root` (the
    /// protected surface refuses it) and `$ANPIOCLI_ANPIO_KEY` (an environment override of
    /// the binary would be a way around the administrator-pinned config). The config path
    /// itself is part of the identity record and has no command-level flag.
    fn invoke_protected(&self, args: &[String]) -> Result<Vec<u8>> {
        let output = Command::new(DEFAULT_BINARY).args(args).output().map_err(|err| {
            anyhow!(
                "could not run {DEFAULT_BINARY}: {err}. The protected entry uses the installed \
                 binary on PATH; install anpio-key or re-run: anpio-cli did attach-anpio-key"
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            bail!(
                "{DEFAULT_BINARY} {} failed: {}",
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

/// Read the `data` of a `SIGN_ORIGIN_PROOF` reply.
///
/// Every field is required: a proof missing its digest or its base is not a partial answer,
/// it is an answer this client cannot use — and sending the envelope without one would
/// produce a request the peer refuses for a reason that has nothing to do with the peer.
fn origin_proof_from_data(data: Value) -> Result<OriginProofSigning> {
    let text = |name: &str| {
        data.get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| anyhow!("anpio-key returned an origin proof without {name}"))
    };
    let created = data
        .get("created")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("anpio-key returned an origin proof without created"))?;
    Ok(OriginProofSigning {
        content_digest: text("content_digest")?,
        signature_input: text("signature_input")?,
        signature: text("signature")?,
        created,
        expires: data.get("expires").and_then(Value::as_i64),
    })
}

/// Read a `GET_CAPABILITIES` reply from `anpio-key data`.
///
/// The reply is the full v2 `Reply`, not just `data`. A daemon that predates capability
/// schema 1 answers with its original five fields and no `operations`; that is not an
/// error, it is the six known data operations.
fn parse_capabilities(bytes: &[u8]) -> Result<Capabilities> {
    let reply: Value = serde_json::from_slice(bytes)
        .context("anpio-key data returned a capability reply that is not JSON")?;
    let code = reply.get("code").and_then(Value::as_str).unwrap_or("missing code");
    if code != "OK" {
        bail!("anpio-key answered GET_CAPABILITIES with {code}");
    }
    let data = reply.get("data").cloned().unwrap_or(Value::Null);
    match data.get("operations") {
        Some(Value::Array(items)) => {
            let mut names = Vec::with_capacity(items.len());
            for item in items {
                names.push(
                    item.as_str()
                        .ok_or_else(|| {
                            anyhow!(
                                "anpio-key returned a capability operation that is not a string: \
                                 {item}"
                            )
                        })?
                        .to_string(),
                );
            }
            Ok(Capabilities::from_names(&names, CapabilitySource::Daemon))
        }
        Some(other) => bail!(
            "anpio-key returned capabilities.operations that is not an array: {other}"
        ),
        None => Ok(Capabilities::from_names(
            &KNOWN_V2_OPERATIONS
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>(),
            CapabilitySource::Daemon,
        )),
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

/// Unix seconds, for comparing against the daemon's clock.
///
/// A machine whose clock is wrong gets a refusal from the daemon rather than a verdict from
/// here: this only decides whether to *ask* for a renewal, never whether a signature is
/// valid.
fn unix_now() -> Result<i64> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before the Unix epoch")?
        .as_secs();
    i64::try_from(seconds).context("the system clock is past 292 billion years")
}

/// Write a JSON request where the daemon can read it, and nowhere else.
///
/// The body of an ANP-02 request is public — a DID, a document, a nonce — and a capability
/// request is no secret either, but the file is still written `0600` and removed as soon as
/// the daemon has answered: a predictable path that outlives the call is a path another
/// process can plant something at.
fn write_temp_json(body: &[u8]) -> Result<PathBuf> {
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
        let key = AnpioKey::default();
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

    #[test]
    fn an_old_anpio_key_record_loads_without_the_capability_fields() {
        let key: AnpioKey =
            serde_json::from_str(r#"{"root":"/srv/anpio-key","kid":"key-1"}"#).unwrap();
        assert_eq!(key.config, None);
        assert_eq!(key.grant, None);
        assert_eq!(key.device, None);
        assert_eq!(key.operations, None);
        assert!(!key.describe().contains("config"));
    }

    #[test]
    fn the_development_surface_offers_http_only_without_a_subprocess() {
        let key = AnpioKey::default();
        let capabilities = key.capabilities().unwrap();
        assert_eq!(capabilities.source(), CapabilitySource::Baseline);
        assert!(capabilities.contains(Operation::Http));
        assert!(!capabilities.contains(Operation::OriginProof));
        assert_eq!(capabilities.effective(), ["http"]);
        assert!(capabilities.announced_not_effective().is_empty());
    }

    #[test]
    fn the_origin_proof_request_carries_the_facts_and_not_the_clock() {
        let request = AnpioKey::origin_proof_request(
            "grant-1",
            "8b3f4f0e-7a5b-4c47-9c2f-2b6a1d9e0c11",
            "direct.send",
            &json!({"target": {"kind": "agent", "did": "did:wba:x:user:bob"}}),
            &json!({"text": "hi"}),
        );
        assert_eq!(request["operation"], "SIGN_ORIGIN_PROOF");
        assert_eq!(request["grant_id"], "grant-1");
        assert_eq!(
            request["request_id"],
            "8b3f4f0e-7a5b-4c47-9c2f-2b6a1d9e0c11"
        );
        assert_eq!(request["origin"]["method"], "direct.send");
        assert_eq!(request["origin"]["meta"]["target"]["kind"], "agent");
        assert_eq!(request["origin"]["body"]["text"], "hi");
        assert!(
            request["origin"].get("created").is_none(),
            "the daemon's clock signs, so the caller must not name one"
        );
    }

    #[test]
    fn an_origin_proof_reply_is_read_only_when_the_daemon_names_every_part() {
        let data = json!({
            "request_id": "r",
            "content_digest": "sha-256=:AA==:",
            "signature_input": "sig1=(\"@method\": \"direct.send\")",
            "signature": "sig1=:AA==:",
            "created": 1_700_000_000_i64,
            "expires": Value::Null,
        });
        let signed = origin_proof_from_data(data).unwrap();
        assert_eq!(signed.content_digest, "sha-256=:AA==:");
        assert!(signed.signature_input.starts_with("sig1=("));
        assert_eq!(signed.signature, "sig1=:AA==:");
        assert_eq!(signed.created, 1_700_000_000);
        assert_eq!(signed.expires, None);

        let short = json!({"created": 1});
        let err = origin_proof_from_data(short).unwrap_err().to_string();
        assert!(err.contains("content_digest"), "{err}");
    }

    #[test]
    fn a_grant_status_reads_the_fields_a_caller_acts_on() {
        let status: GrantStatus = serde_json::from_value(json!({
            "grant_id": "g-1",
            "principal_id": "p-1",
            "key_id": "k-1",
            "policy_id": "pol",
            "policy_version": 2,
            "boot_epoch": 3,
            "expiry": 1_800_000_000_i64,
            "kind": "session",
            "created_at": 1_700_000_000_i64,
            "max_uses": 100,
            "used_uses": 99,
            "max_renewals": 2,
            "renewals": 1,
            "state": "active"
        }))
        .unwrap();
        assert_eq!(status.remaining_uses(), 1);
        assert!(status.usable());

        let exhausted = GrantStatus {
            state: "exhausted".to_string(),
            used_uses: 100,
            ..status
        };
        assert_eq!(exhausted.remaining_uses(), 0);
        assert!(!exhausted.usable(), "an exhausted grant signs nothing");
    }

    #[test]
    fn a_long_run_renews_only_when_the_grant_is_about_to_run_out() {
        let base = GrantStatus {
            grant_id: "g-1".to_string(),
            key_id: "k-1".to_string(),
            state: "active".to_string(),
            expiry: 2_000_000,
            kind: "session".to_string(),
            max_uses: 100,
            used_uses: 10,
            max_renewals: 2,
            renewals: 0,
        };
        let now = 1_000_000;

        assert!(
            !runway_plan(&base, now).unwrap(),
            "a grant with a day left is not renewed"
        );

        let soon = GrantStatus { expiry: now + 600, ..base.clone() };
        assert!(runway_plan(&soon, now).unwrap(), "ten minutes left is renewed");

        let single_use = GrantStatus { kind: "request".to_string(), ..soon.clone() };
        let err = runway_plan(&single_use, now).unwrap_err().to_string();
        assert!(err.contains("session grant"), "{err}");

        let spent = GrantStatus { renewals: 2, ..soon.clone() };
        let err = runway_plan(&spent, now).unwrap_err().to_string();
        assert!(err.contains("renewals"), "{err}");

        let exhausted = GrantStatus { state: "exhausted".to_string(), ..base.clone() };
        let err = runway_plan(&exhausted, now).unwrap_err().to_string();
        assert!(err.contains("fresh grant"), "{err}");
    }

    #[test]
    fn an_origin_proof_needs_the_protected_surface_and_a_grant() {
        let development = AnpioKey {
            operations: Some(vec!["SIGN_ORIGIN_PROOF".to_string()]),
            grant: Some("grant-1".to_string()),
            ..AnpioKey::default()
        };
        let err = development
            .sign_origin_proof(
                "did:wba:x:user:alice:e1_x",
                "8b3f4f0e-7a5b-4c47-9c2f-2b6a1d9e0c11",
                "direct.send",
                &json!({}),
                &json!({}),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("development socket"), "{err}");
        assert!(err.contains("--config"), "{err}");

        let ungranted = AnpioKey {
            config: Some(PathBuf::from("/etc/anpio-key/service.json")),
            ..AnpioKey::default()
        };
        let err = ungranted
            .sign_origin_proof(
                "did:wba:x:user:alice:e1_x",
                "8b3f4f0e-7a5b-4c47-9c2f-2b6a1d9e0c11",
                "direct.send",
                &json!({}),
                &json!({}),
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("no anpio-key grant"), "{err}");
        assert!(err.contains("--grant"), "{err}");
    }

    #[test]
    fn a_cached_capability_set_is_authoritative() {
        let key = AnpioKey {
            operations: Some(vec![
                "SIGN_HTTP".to_string(),
                "SIGN_ORIGIN_PROOF".to_string(),
                "SIGN_PURPOSE".to_string(),
                "SIGN_FROM_THE_FUTURE".to_string(),
            ]),
            ..AnpioKey::default()
        };
        let capabilities = key.capabilities().unwrap();
        assert_eq!(capabilities.source(), CapabilitySource::Cached);
        assert!(capabilities.contains(Operation::OriginProof));
        // Origin proof is driven now; purpose is still a client gap, and the unknown name is
        // kept verbatim rather than guessed at.
        assert_eq!(capabilities.effective(), ["http", "origin-proof"]);
        assert_eq!(capabilities.announced_not_effective(), ["purpose"]);
        assert_eq!(
            capabilities.announced_names(),
            [
                "SIGN_FROM_THE_FUTURE",
                "SIGN_HTTP",
                "SIGN_ORIGIN_PROOF",
                "SIGN_PURPOSE"
            ]
        );
    }

    #[test]
    fn a_capability_reply_is_read_from_the_whole_reply() {
        let capabilities = parse_capabilities(
            br#"{"version":2,"code":"OK","signing_available":true,
                 "protected_supported":true,
                 "data":{"operations":["SIGN_HTTP","SIGN_ORIGIN_PROOF"]}}"#,
        )
        .unwrap();
        assert_eq!(capabilities.source(), CapabilitySource::Daemon);
        assert!(capabilities.contains(Operation::OriginProof));

        let err = parse_capabilities(
            br#"{"version":2,"code":"RESOURCE_BUSY","signing_available":false,
                 "protected_supported":true}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("RESOURCE_BUSY"), "{err}");
    }

    #[test]
    fn a_daemon_without_the_capability_field_gets_the_six_known_operations() {
        let capabilities = parse_capabilities(
            br#"{"version":2,"code":"OK","signing_available":true,
                 "protected_supported":true,"data":{"protocol_version":2}}"#,
        )
        .unwrap();
        assert_eq!(capabilities.source(), CapabilitySource::Daemon);
        assert!(capabilities.contains(Operation::Http));
        assert!(!capabilities.contains(Operation::OriginProof));
        assert_eq!(capabilities.announced_names().len(), KNOWN_V2_OPERATIONS.len());
    }
}
