//! Talking to the DID host.
//!
//! The identity is published to a real awiki host (TODO5 §0.1 #7 / §8-J) — the same route
//! the TS CLI takes, with the host on this machine. Two calls matter: read the host's own
//! service DID document (so the identity's document can advertise the service the host
//! will accept), and register the identity's document.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Url;
use serde_json::{json, Value};

use super::store::Identity;

/// The awiki JSON-RPC paths. The first is what its own client uses; the second is an
/// alias the server keeps.
const DID_AUTH_PATH: &str = "/user-service/v1/did-auth/rpc";

/// What the host says about itself, read from its `/.well-known/did.json`.
pub struct HostService {
    /// The host's own DID — the `serviceDid` an identity's document must name.
    pub service_did: String,
    /// The DID authority an identity's DID hangs under: the segment after `did:wba:` in
    /// the host's own DID (`localhost%3A8000`).
    pub authority: String,
    /// The ANP message endpoint an identity's document must advertise.
    pub service_endpoint: String,
}

/// Read the host's service DID document.
///
/// The identity's document must advertise the host's *own* message service: the awiki
/// host checks the endpoint and `serviceDid` against its configuration and refuses a
/// peer-declared one unless a switch that is off by default is turned on (TODO5 §8-J).
/// Reading them off the host beats re-deriving its settings here.
pub async fn fetch_host_service(client: &reqwest::Client, base: &Url) -> Result<HostService> {
    let url = base
        .join("/.well-known/did.json")
        .with_context(|| format!("{base} cannot serve /.well-known/did.json"))?;
    let response = client
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;
    if !status.is_success() {
        bail!("GET {url} failed: HTTP {status}: {}", snippet(&text));
    }
    let document: Value =
        serde_json::from_str(&text).with_context(|| format!("{url} did not return JSON"))?;

    let service_did = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the host's DID document has no id"))?
        .to_string();
    let authority = service_did
        .strip_prefix("did:wba:")
        .ok_or_else(|| anyhow!("the host's DID is not a did:wba DID: {service_did}"))?
        .to_string();
    let service_endpoint = document
        .get("service")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("type").and_then(Value::as_str) == Some("ANPMessageService"))
        })
        .and_then(|service| service.get("serviceEndpoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("the host's DID document names no ANPMessageService endpoint"))?
        .to_string();

    Ok(HostService {
        service_did,
        authority,
        service_endpoint,
    })
}

/// Publish the identity's document. `register` is idempotent for a DID already on file
/// only in the sense that it is refused as a conflict — a re-register after a lost
/// response needs `update_document`.
pub async fn register_identity(client: &reqwest::Client, base: &Url, identity: &Identity) -> Result<Value> {
    let url = base
        .join(DID_AUTH_PATH)
        .with_context(|| format!("{base} cannot serve {DID_AUTH_PATH}"))?;
    let body = json!({
        "jsonrpc": "2.0",
        "id": format!("agentx-cli-register-{}", std::process::id()),
        "method": "register",
        "params": {
            "handle": identity.handle,
            "did_document": identity.did_document,
        },
    });
    let response = client
        .post(url.clone())
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let text = response.text().await.with_context(|| format!("reading {url}"))?;
    if !status.is_success() {
        bail!("POST {url} failed: HTTP {status}: {}", snippet(&text));
    }
    let envelope: Value =
        serde_json::from_str(&text).with_context(|| format!("{url} did not return JSON"))?;

    if let Some(error) = envelope.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("the host refused the registration");
        bail!("the host refused to register {}: {code}: {message}", identity.did);
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| anyhow!("the host's reply carried neither result nor error"))
}

fn snippet(text: &str) -> String {
    let trimmed = text.trim();
    trimmed.chars().take(200).collect()
}
