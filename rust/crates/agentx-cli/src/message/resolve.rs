//! Resolving a DID to the document that serves it (P2 §9.1).
//!
//! The port of `packages/core/src/crypto/resolveDid.ts`'s URL derivation and network
//! policy — but **only that half**: the document, once fetched, is verified by the `anp`
//! crate (`validate_did_document_binding`), which already implements the `e1_` binding rule.
//! Re-implementing the verifier here would be a second copy of a security check, which is
//! the one thing this module must not contain — so where the crate's verdict and the host's
//! proofs disagree ([`document_is_bound`]), the bytes are re-encoded into the form the crate
//! does verify rather than the check being written a second time.
//!
//! **Why not the crate's resolver.** `anp::authentication::resolve_did_document` derives its
//! URL from `did_web::build_did_web_resolution_url`, which requires a dotted, multi-label
//! host. Both hosts this client has met so far (`localhost`, `127.0.0.1`) are *not* that,
//! and are exactly the hosts a development setup uses (TODO5 §8-J). So the URL derivation
//! is ours, and it follows the TS rules instead: split on `:` first, then percent-decode
//! each segment, then validate every one (TODO5 §3 #4).
//!
//! **The policy.** A DID names the host its document comes from, so the fetch goes to a
//! host the *caller* named — and, for the message hop, sometimes to a host the *peer* named
//! (`channel::discover` hands the endpoint host to `post_message`). The three gates the TS
//! client applies are ported: a non-empty allowlist, a scheme that must be `https` unless
//! the host was declared local, and a private-address refusal for literal IPs. **One part
//! is not ported and is called out at [`assert_allowed_host`]**: the TS client also
//! resolves a *name* to addresses and refuses private ones, which needs a DNS resolver this
//! client does not carry.

use base64::Engine as _;
use reqwest::Url;
use serde_json::Value;

use crate::error::{AgentxError, Result};

/// The network policy for one fetch. Mirrors `ResolveDidOptions`.
///
/// Hosts are compared the way a URL spells them: lowercase, **no port**. Naming a host is
/// the confirmation — there is deliberately no default allowlist.
#[derive(Debug, Clone, Default)]
pub struct ResolvePolicy {
    pub allowed_hosts: Vec<String>,
    /// The one sanctioned way past the private-address gate, per host.
    pub allow_private_hosts: Vec<String>,
    /// Likewise for the TLS requirement: plain `http` is allowed only for these hosts.
    pub allow_insecure_transport: Vec<String>,
}

impl ResolvePolicy {
    fn lists(hosts: &[String], host: &str) -> bool {
        hosts.iter().any(|listed| listed.eq_ignore_ascii_case(host))
    }

    pub fn allows_insecure(&self, host: &str) -> bool {
        Self::lists(&self.allow_insecure_transport, host)
    }

    fn allows_private(&self, host: &str) -> bool {
        Self::lists(&self.allow_private_hosts, host)
    }
}

fn invalid_did(message: impl Into<String>) -> AgentxError {
    AgentxError::DidInvalid(message.into())
}

fn blocked(message: impl Into<String>) -> AgentxError {
    AgentxError::DidResolveBlocked(message.into())
}

/// A response larger than this is refused rather than buffered. Matches `rpc`'s cap — the
/// same guard, because a document and a response travel the same way.
const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;

/// The percent-decode `decodeURIComponent` performs, without its `+`-is-space rule (which
/// is form encoding, not URI encoding). `None` for malformed input or invalid UTF-8, so a
/// caller cannot mistake a partial decode for a good one.
fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let high = (bytes[i + 1] as char).to_digit(16)?;
            let low = (bytes[i + 2] as char).to_digit(16)?;
            out.push((high * 16 + low) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Decode one DID segment, refusing one that was encoded twice.
///
/// A leftover `%` means double encoding (`%252e` → `%2e`); the URL layer would decode it a
/// second time and could reintroduce `.` / `..` / `/`. Rejecting outright is the only
/// reading that cannot traverse (audit 2026-09-11 ANP-…-04).
fn decode_did_segment(raw: &str, did: &str) -> Result<String> {
    let decoded = percent_decode(raw).ok_or_else(|| {
        invalid_did(format!(
            "Cannot derive URL from DID (bad percent-encoding in \"{raw}\"): {did}"
        ))
    })?;
    if decoded.contains('%') {
        return Err(invalid_did(format!(
            "Cannot derive URL from DID (double-encoded segment \"{raw}\"): {did}"
        )));
    }
    Ok(decoded)
}

/// `DID_HOST` from the TS client: an optional `:port` after a hostname that starts and ends
/// alphanumeric and may hold `.` `_` `-` in between.
fn is_valid_did_host(host: &str) -> bool {
    let (name, port) = match host.rfind(':') {
        Some(index) => (&host[..index], Some(&host[index + 1..])),
        None => (host, None),
    };
    if let Some(port) = port {
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
    }
    let bytes = name.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    if !(first.is_ascii_alphanumeric() || *first == b'-') {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if !last.is_ascii_alphanumeric() {
        return false;
    }
    bytes[1..bytes.len() - 1]
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// `DID_PATH_SEGMENT`: no `/`, no `\`, no `.` or `..`, nothing a URL layer would normalise.
fn is_valid_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// The `https` URL a `did:web` / `did:wba` DID is served from.
///
///   `did:wba:example.com`              → `https://example.com/.well-known/did.json`
///   `did:wba:example.com:user:alice`   → `https://example.com/user/alice/did.json`
///   `did:wba:example.com%3A8080`       → `https://example.com:8080/.well-known/did.json`
///
/// The method prefix must match exactly and in lowercase, so a non-DID string like
/// `example.com:user` is rejected rather than being mapped to a URL.
pub fn did_to_url(did: &str) -> Result<Url> {
    let rest = did
        .strip_prefix("did:web:")
        .or_else(|| did.strip_prefix("did:wba:"))
        .ok_or_else(|| invalid_did(format!("Cannot derive URL from DID: {did}")))?;

    let raw_segments: Vec<&str> = rest.split(':').collect();
    if raw_segments.iter().any(|segment| segment.is_empty()) {
        return Err(invalid_did(format!(
            "Cannot derive URL from DID (empty segment): {did}"
        )));
    }

    let host = decode_did_segment(raw_segments[0], did)?;
    if !is_valid_did_host(&host) {
        return Err(invalid_did(format!(
            "Cannot derive URL from DID (invalid host \"{host}\"): {did}"
        )));
    }

    let mut path = Vec::with_capacity(raw_segments.len() - 1);
    for raw in &raw_segments[1..] {
        let segment = decode_did_segment(raw, did)?;
        if !is_valid_path_segment(&segment) {
            return Err(invalid_did(format!(
                "Cannot derive URL from DID (invalid path segment \"{segment}\"): {did}"
            )));
        }
        path.push(segment);
    }

    let url = if path.is_empty() {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://{host}/{}/did.json", path.join("/"))
    };
    Url::parse(&url).map_err(|_| invalid_did(format!("Cannot derive URL from DID: {did}")))
}

/// The host a DID names, as a URL spells it — not the DID's raw first segment, which
/// percent-encodes a port (`localhost%3A8765`). The allowlist matches URL hosts, so the
/// stored spelling would never match.
pub fn did_host(did: &str) -> Result<String> {
    let url = did_to_url(did)?;
    Ok(url
        .host_str()
        .ok_or_else(|| invalid_did(format!("Cannot derive URL from DID: {did}")))?
        .to_string())
}

/// Is this hostname a spelling of "this machine"? `localhost`, `::1`, and anything in
/// `127.0.0.0/8`. Brackets are stripped first, because a URL keeps them on an IPv6 literal.
pub fn is_loopback_host_name(host: &str) -> bool {
    let bare = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if bare == "localhost" || bare == "::1" {
        return true;
    }
    match bare.parse::<std::net::Ipv4Addr>() {
        Ok(address) => address.octets()[0] == 127,
        Err(_) => false,
    }
}

/// The private/loopback/reserved ranges a fetch driven by a peer must not reach
/// (`resolveDid.ts`'s `isPrivateIpAddress`).
fn is_private_address(address: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2))))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_private_address(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            !((segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] < 0x200 || segments[1] == 0xdb8))
                && segments[0] != 0x2002
                && (segments[0] & 0xfff0) != 0x3ff0)
        }
    }
}

/// The URL a DID's document is fetched from, with the TLS requirement relaxed for a host
/// the caller declared local. `did_to_url` always yields `https` (ANP-03 requires TLS), so
/// this is the only place the scheme can change.
pub fn document_url(did: &str, policy: &ResolvePolicy) -> Result<Url> {
    let mut url = did_to_url(did)?;
    let Some(host) = url.host_str().map(str::to_string) else {
        return Err(invalid_did(format!("Cannot derive URL from DID: {did}")));
    };
    if policy.allows_insecure(&host) {
        url.set_scheme("http")
            .map_err(|_| invalid_did(format!("Cannot derive URL from DID: {did}")))?;
    }
    Ok(url)
}

/// Apply the allowlist, the address gate, and the scheme gate to one URL. Both gates apply
/// to every hop, so this is called before every fetch and before every message POST.
///
/// **Not ported:** `resolveHostAddresses` — the TS client also resolves a *hostname* through
/// `node:dns` and refuses one that resolves to a private address, which is what stops a name
/// that is not spelled loopback (a LAN name, a rebinding record) from reaching inward. Doing
/// that here needs a DNS resolver this client does not carry, so the check is limited to
/// **literal IPs**, which is the same fallback the TS client takes where `node:dns` is
/// absent (its browser path). The allowlist still bounds which hosts are reachable at all;
/// what is missing is the second opinion on what a name resolves to. Tracked in TODO5 §3.
pub fn assert_allowed_host(url: &Url, policy: &ResolvePolicy, context: &str) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| blocked(format!("{url} has no host (for {context})")))?
        .to_string();

    if policy.allowed_hosts.is_empty() {
        return Err(blocked(format!(
            "Remote resolution requires a non-empty allowedHosts allowlist (host \"{host}\"): {context}"
        )));
    }
    if !ResolvePolicy::lists(&policy.allowed_hosts, &host) {
        return Err(blocked(format!(
            "Host \"{host}\" is not in the allowed hosts list (for {context})"
        )));
    }
    if !policy.allows_private(&host) {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(address) = bare.parse::<std::net::IpAddr>() {
            if is_private_address(address) {
                return Err(blocked(format!(
                    "Host \"{host}\" resolves to a private/loopback address ({address}); pass --allow-private-host {host} to permit it"
                )));
            }
        }
    }
    if url.scheme() != "https" && !policy.allows_insecure(&host) {
        return Err(blocked(format!(
            "URL for host \"{host}\" is not https ({url}); pass --allow-private-host {host} to permit it"
        )));
    }
    Ok(())
}

/// Does this document's own proof bind it to the DID it claims?
///
/// `anp` 1.0.5's verdict is asked first and trusted when it answers *yes*. Its only known
/// blind spot is a false *no*: for a base58-btc (`z…`) `eddsa-jcs-2022` proof it folds the
/// document's `@context` into the proof options before hashing the signing input, while the
/// DID host this client resolves through signs that same proof without the fold (ANP-03
/// §2.5.5 as the host implements it). A rejection of such a proof is therefore retried
/// against the encoding the crate's own generator writes — [`proof_value_as_base64url`] —
/// which selects the crate's legacy branch and verifies the signature as it was made.
///
/// This never widens what counts as a valid signature: both branches hash the same proof
/// options minus `proofValue`, over the same document, and both still require the signing
/// key's fingerprint to be the one the DID spells.
pub fn document_is_bound(document: &Value) -> bool {
    if anp::authentication::validate_did_document_binding(document, true) {
        return true;
    }
    match proof_value_as_base64url(document) {
        Some(rewritten) => anp::authentication::validate_did_document_binding(&rewritten, true),
        None => false,
    }
}

/// The document with its `proofValue` re-encoded from base58-btc multibase to base64url, or
/// `None` when the proof is not the base58-btc `eddsa-jcs-2022` shape the crate treats
/// specially. The condition mirrors the crate's own branch test, so this only fires where
/// the two conventions can differ; the signature bytes are untouched.
fn proof_value_as_base64url(document: &Value) -> Option<Value> {
    let proof = document.get("proof")?.as_object()?;
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
        return None;
    }
    if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-jcs-2022") {
        return None;
    }
    let proof_value = proof.get("proofValue")?.as_str()?;
    let decoded = bs58::decode(proof_value.strip_prefix('z')?).into_vec().ok()?;
    if decoded.len() != 64 || format!("z{}", bs58::encode(&decoded).into_string()) != proof_value
    {
        return None;
    }

    let mut rewritten = document.clone();
    let slot = rewritten.get_mut("proof")?.as_object_mut()?;
    slot.insert(
        "proofValue".to_string(),
        Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded)),
    );
    Some(rewritten)
}

/// Fetch and verify the document a DID resolves to.
///
/// Verification is [`document_is_bound`] — the crate's `e1_` binding rule, which checks the
/// proof, its cryptosuite, that the signing method is authorized for `assertionMethod`, that
/// the signature verifies, *and* that the key's fingerprint is the one the DID itself
/// spells. The document's `id` is checked first, because a document for another DID is not
/// ours to judge.
pub async fn resolve_did_document(
    client: &reqwest::Client,
    did: &str,
    policy: &ResolvePolicy,
) -> Result<Value> {
    let url = document_url(did, policy)?;
    assert_allowed_host(&url, policy, did)?;

    let response = client
        .get(url.clone())
        .header("accept", "application/did+json, application/json")
        .send()
        .await
        .map_err(|err| AgentxError::MessageSendFailed(format!("GET {url}: {err}")))?;

    let status = response.status();
    let media_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let text = response
        .text()
        .await
        .map_err(|err| AgentxError::MessageSendFailed(format!("reading {url}: {err}")))?;
    if !status.is_success() {
        return Err(AgentxError::MessageSendFailed(format!(
            "GET {url} failed: HTTP {status}: {}",
            snippet(&text)
        )));
    }
    // Ask for a DID document rather than "anything you have": without this a server (or a
    // proxy in front of it) is free to answer with an HTML page, which would then be
    // reported as a malformed document instead of a wrong content type.
    if !media_type.is_empty()
        && media_type != "application/did+json"
        && media_type != "application/json"
        && !media_type.ends_with("+json")
    {
        return Err(AgentxError::MessageInvalid(format!(
            "the DID document from {url} has unsupported Content-Type \"{media_type}\""
        )));
    }
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(AgentxError::ResponseTooLarge(format!(
            "the DID document from {url} is {} bytes",
            text.len()
        )));
    }

    let document: Value = serde_json::from_str(&text)
        .map_err(|_| AgentxError::MessageInvalid(format!("{url} did not return a JSON document")))?;
    if document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(AgentxError::MessageInvalid(format!(
            "{url} served a document whose id is not {did}"
        )));
    }
    if !document_is_bound(&document) {
        return Err(AgentxError::MessageInvalid(format!(
            "the DID document from {url} does not bind to {did}"
        )));
    }
    Ok(document)
}

fn snippet(text: &str) -> String {
    text.trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_did_maps_to_the_url_that_serves_it() {
        assert_eq!(
            did_to_url("did:wba:example.com").unwrap().as_str(),
            "https://example.com/.well-known/did.json"
        );
        assert_eq!(
            did_to_url("did:wba:example.com:user:alice").unwrap().as_str(),
            "https://example.com/user/alice/did.json"
        );
        // The port is percent-encoded in the DID and decoded into the authority.
        assert_eq!(
            did_to_url("did:wba:example.com%3A8080").unwrap().as_str(),
            "https://example.com:8080/.well-known/did.json"
        );
        assert_eq!(
            did_to_url("did:web:example.com:user:alice").unwrap().as_str(),
            "https://example.com/user/alice/did.json"
        );
        // A local development host is not a special case in the DID.
        assert_eq!(
            did_to_url("did:wba:localhost%3A8765:user:rusty:e1_abc")
                .unwrap()
                .as_str(),
            "https://localhost:8765/user/rusty/e1_abc/did.json"
        );
    }

    #[test]
    fn traversal_and_double_encoding_are_refused() {
        for did in [
            "example.com:user",
            "did:wba:example.com:..:secret",
            "did:wba:example.com:%2e%2e:secret",
            "did:wba:example.com:%252e%252e:secret",
            "did:wba:example.com:user%2Falice",
            "did:wba:example.com:a%5Cb",
            "did:wba::user",
            "did:wba:example.com::x",
            "did:wba:example.com%3A",
        ] {
            assert!(did_to_url(did).is_err(), "{did} should not derive a URL");
        }
    }

    /// The host and segment charsets are the TS client's, and both allow a leading `-`
    /// (`DID_HOST` starts `[A-Za-z0-9-]`, `DID_PATH_SEGMENT` is a flat class). Tightening
    /// either here would make this client refuse a DID the TS one resolves — a divergence
    /// with no security gain, since the allowlist is what bounds reachability. Pinned so a
    /// later reader does not "fix" the validator into a second, stricter rule.
    #[test]
    fn a_leading_dash_is_allowed_the_way_the_ts_client_allows_it() {
        assert_eq!(
            did_to_url("did:wba:-bad.example.com").unwrap().as_str(),
            "https://-bad.example.com/.well-known/did.json"
        );
        assert_eq!(
            did_to_url("did:wba:example.com:-1").unwrap().as_str(),
            "https://example.com/-1/did.json"
        );
    }

    #[test]
    fn host_is_spelled_the_way_a_url_spells_it() {
        assert_eq!(
            did_host("did:wba:localhost%3A8765:user:rusty").unwrap(),
            "localhost"
        );
        assert_eq!(did_host("did:wba:127.0.0.1%3A8080:user:a").unwrap(), "127.0.0.1");
    }

    #[test]
    fn loopback_names_are_recognised() {
        for host in ["localhost", "127.0.0.1", "127.9.9.9", "[::1]", "::1"] {
            assert!(is_loopback_host_name(host), "{host} is loopback");
        }
        for host in ["example.com", "10.0.0.1", "192.168.1.5", "[2001:db8::1]"] {
            assert!(!is_loopback_host_name(host), "{host} is not loopback");
        }
    }

    #[test]
    fn the_allowlist_is_required_and_exact() {
        let policy = ResolvePolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        let url = Url::parse("https://example.com/.well-known/did.json").unwrap();
        assert!(assert_allowed_host(&url, &policy, "did:wba:example.com").is_ok());

        let other = Url::parse("https://evil.com/.well-known/did.json").unwrap();
        assert!(assert_allowed_host(&other, &policy, "did:wba:evil.com").is_err());

        let empty = ResolvePolicy::default();
        assert!(assert_allowed_host(&url, &empty, "did:wba:example.com").is_err());
    }

    #[test]
    fn a_literal_private_host_needs_the_flag_and_http_needs_a_local_declaration() {
        let url = Url::parse("http://127.0.0.1:8080/.well-known/did.json").unwrap();
        let strict = ResolvePolicy {
            allowed_hosts: vec!["127.0.0.1".to_string()],
            ..Default::default()
        };
        assert!(assert_allowed_host(&url, &strict, "did:wba:127.0.0.1%3A8080").is_err());

        let relaxed = ResolvePolicy {
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allow_private_hosts: vec!["127.0.0.1".to_string()],
            allow_insecure_transport: vec!["127.0.0.1".to_string()],
        };
        assert!(assert_allowed_host(&url, &relaxed, "did:wba:127.0.0.1%3A8080").is_ok());
        assert_eq!(
            document_url("did:wba:127.0.0.1%3A8080", &relaxed).unwrap().as_str(),
            "http://127.0.0.1:8080/.well-known/did.json"
        );
    }

    #[test]
    fn https_is_kept_for_a_host_that_was_not_declared_local() {
        let policy = ResolvePolicy {
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert_eq!(
            document_url("did:wba:example.com", &policy).unwrap().as_str(),
            "https://example.com/.well-known/did.json"
        );
    }

    /// The re-encoding that lets the crate verify a base58-btc proof is byte-for-byte a
    /// representation change: same signature, only the alphabet the crate's branch test
    /// keys on differs. Anything that is not that exact proof shape is left alone.
    #[test]
    fn a_base58_proof_is_re_encoded_and_everything_else_is_not() {
        let signature = [7u8; 64];
        let multibase = format!("z{}", bs58::encode(signature).into_string());
        let document = serde_json::json!({
            "proof": {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofValue": multibase,
            }
        });

        let rewritten = proof_value_as_base64url(&document).expect("a base58 proof is re-encoded");
        let encoded = rewritten["proof"]["proofValue"].as_str().unwrap();
        assert_eq!(encoded, base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature));
        // The signature itself is unchanged; decode both back and compare.
        assert_eq!(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded).unwrap(),
            signature
        );

        for untouched in [
            // Already base64url: the branch this helper selects for.
            serde_json::json!({"proof": {"type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022", "proofValue": "AAAA"}}),
            // The right encoding but the wrong cryptosuite.
            serde_json::json!({"proof": {"type": "DataIntegrityProof",
                "cryptosuite": "secp256k1-2025", "proofValue": multibase}}),
            // A base58 payload that is not a 64-byte signature.
            serde_json::json!({"proof": {"type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "proofValue": format!("z{}", bs58::encode([1u8; 32]).into_string())}}),
            serde_json::json!({"id": "did:wba:example.com"}),
        ] {
            assert!(
                proof_value_as_base64url(&untouched).is_none(),
                "{untouched} should not be re-encoded"
            );
        }
    }
}
