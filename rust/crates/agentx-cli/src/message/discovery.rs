//! From a target DID to **the one** ANPMessageService that answers for it (P2 §9.1).
//!
//! The port of `packages/core/src/message/discovery.ts`, over the resolver in [`super::resolve`].
//! P2 §9.1 gives the Agent and the Group flows the same two steps, so there is no
//! group-specific lookup to write: a group's document carries its own ANPMessageService
//! entry exactly as an agent's does (TODO5 §3).

use serde_json::Value;

use crate::error::{AgentxError, Result};

use super::resolve::{resolve_did_document, ResolvePolicy};

/// P2 §7.2: the one publicly reachable message entry in a DID document.
pub const ANP_MESSAGE_SERVICE_TYPE: &str = "ANPMessageService";

/// One discovery result. The static hint and the runtime capabilities are kept apart
/// because §8.3 says the runtime wins when they disagree — merging them would hand that
/// MUST to every call site to remember.
#[derive(Debug, Clone)]
pub struct MessageServiceTarget {
    /// Whose document this came from — i.e. what `meta.target.did` must say.
    pub identity: String,
    /// The entry's `id` (one of P2 §8.1's three mandatory members).
    pub service_id: String,
    /// The `serviceEndpoint`. **Not** a DID: an HTTP(S) transport address.
    pub endpoint: String,
    /// P2 §8.7: the cross-domain service identity, a **bare domain DID**. Mandatory only
    /// for a cross-domain call, so it may be absent.
    pub service_did: Option<String>,
    /// The static hint. May differ from the runtime answer, see [`negotiate_profiles`].
    pub hinted_profiles: Vec<String>,
    pub hinted_security_profiles: Vec<String>,
}

/// P1 §8.2.2's `anp.get_capabilities` result — the **runtime authority**.
///
/// The field names are snake_case (`supported_profiles`), unlike the document's `profiles`.
/// Both sides are copied exactly; this is not a typo.
#[derive(Debug, Clone)]
pub struct AnpCapabilities {
    pub service_did: Option<String>,
    pub supported_profiles: Vec<String>,
    pub supported_security_profiles: Vec<String>,
    /// §8.2.2: the values are **decimal strings** (§7.3) — do not parse them into numbers.
    pub limits: Vec<(String, String)>,
    pub supported_content_types: Vec<String>,
}

/// Resolve `identity`'s document and take its **only** ANPMessageService entry.
///
/// Zero entries or two or more are both refused. §7.1 is a MUST: a document exposing two
/// cross-domain entries leaves the caller no way to choose, and the wrong one may well
/// "look working" — so this is not a case "take the first" can paper over. The count goes
/// into the message so the diagnosis needs no second look at the document.
pub async fn discover_message_service(
    client: &reqwest::Client,
    identity: &str,
    policy: &ResolvePolicy,
) -> Result<MessageServiceTarget> {
    let document = resolve_did_document(client, identity, policy).await?;

    let entries: Vec<&Value> = document
        .get("service")
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter(|entry| entry.get("type").and_then(Value::as_str) == Some(ANP_MESSAGE_SERVICE_TYPE))
                .collect()
        })
        .unwrap_or_default();

    if entries.len() != 1 {
        return Err(AgentxError::MessageServiceNotFound(format!(
            "\"{identity}\" exposes {} ANPMessageService entries; exactly one is required",
            entries.len()
        )));
    }

    // P2 §8.1's three mandatory members. `isServiceEntry` in the locator enforces the same
    // three; a document that is missing one is reported here rather than yielding a target
    // with an empty endpoint that only fails at the POST.
    let entry = entries[0];
    let member = |name: &str| -> Result<String> {
        entry
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                AgentxError::MessageInvalid(format!(
                    "\"{identity}\" has an ANPMessageService entry with no {name} (P2 §8.1)"
                ))
            })
    };

    Ok(MessageServiceTarget {
        identity: identity.to_string(),
        service_id: member("id")?,
        endpoint: member("serviceEndpoint")?,
        service_did: entry
            .get("serviceDid")
            .and_then(Value::as_str)
            .map(str::to_string),
        hinted_profiles: string_array(entry.get("profiles")),
        hinted_security_profiles: string_array(entry.get("securityProfiles")),
    })
}

/// Parse an `anp.get_capabilities` result.
///
/// Missing `supported_profiles` or `supported_security_profiles` is a refusal: the other
/// three are recommended or optional (§8.2.2 makes `supported_content_types` a SHOULD), but
/// those two missing means the service cannot be negotiated at all — and quietly
/// substituting empty arrays would read as "this service supports nothing".
pub fn parse_capabilities(result: &Value) -> Result<AnpCapabilities> {
    let supported_profiles = string_array_checked(result.get("supported_profiles"));
    let supported_security_profiles = string_array_checked(result.get("supported_security_profiles"));
    let (Some(supported_profiles), Some(supported_security_profiles)) =
        (supported_profiles, supported_security_profiles)
    else {
        return Err(AgentxError::MessageInvalid(
            "anp.get_capabilities result MUST carry supported_profiles and supported_security_profiles"
                .to_string(),
        ));
    };

    let limits = result
        .get("limits")
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .filter_map(|(name, value)| {
                    value.as_str().map(|value| (name.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(AnpCapabilities {
        service_did: result.get("service_did").and_then(Value::as_str).map(str::to_string),
        supported_profiles,
        supported_security_profiles,
        limits,
        supported_content_types: string_array(result.get("supported_content_types")),
    })
}

/// §8.3: when the static hint and the runtime capabilities disagree, the runtime wins.
///
/// A function of its own because "which wins" scattered across call sites will eventually
/// be read in the wrong order somewhere — and the wrong place will not fail, it will just
/// quietly use a stale hint. The fallback to the hint is **whole-group**, never per item:
/// half runtime, half hint is a combination nobody defined, and it looks legitimate.
pub fn negotiate_profiles(
    hinted_profiles: &[String],
    hinted_security_profiles: &[String],
    runtime: Option<&AnpCapabilities>,
) -> (Vec<String>, Vec<String>, &'static str) {
    match runtime {
        Some(capabilities) => (
            capabilities.supported_profiles.clone(),
            capabilities.supported_security_profiles.clone(),
            "runtime",
        ),
        None => (
            hinted_profiles.to_vec(),
            hinted_security_profiles.to_vec(),
            "hint",
        ),
    }
}

/// The strings of an array field, skipping anything that is not one. Absent or not-an-array
/// is an empty list.
fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Like [`string_array`], but tells "not an array" from "an empty array" — the two mean
/// different things to [`parse_capabilities`].
fn string_array_checked(value: Option<&Value>) -> Option<Vec<String>> {
    let items = value?.as_array()?;
    Some(
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn capabilities_parse_the_underscore_spelling() {
        let capabilities = parse_capabilities(&json!({
            "service_did": "did:web:svc.example",
            "supported_profiles": ["anp.direct.base.v1"],
            "supported_security_profiles": ["transport-protected"],
            "limits": {"max_message_bytes": "1048576"},
            "supported_content_types": ["text/plain"],
        }))
        .unwrap();
        assert_eq!(capabilities.service_did.as_deref(), Some("did:web:svc.example"));
        assert_eq!(capabilities.supported_profiles, ["anp.direct.base.v1"]);
        assert_eq!(capabilities.limits, [("max_message_bytes".to_string(), "1048576".to_string())]);
    }

    #[test]
    fn a_capabilities_probe_that_cannot_be_negotiated_is_refused() {
        assert!(parse_capabilities(&json!({"supported_profiles": ["a"]})).is_err());
        assert!(parse_capabilities(&json!({"supported_security_profiles": ["a"]})).is_err());
        // The optional three may be absent.
        assert!(parse_capabilities(&json!({
            "supported_profiles": [],
            "supported_security_profiles": [],
        }))
        .is_ok());
    }

    #[test]
    fn the_runtime_answer_wins_whole() {
        let runtime = parse_capabilities(&json!({
            "supported_profiles": ["anp.group.base.v2"],
            "supported_security_profiles": ["group-e2ee"],
        }))
        .unwrap();
        let (profiles, security, source) = negotiate_profiles(
            &["hint.profile".to_string()],
            &["hint.security".to_string()],
            Some(&runtime),
        );
        assert_eq!(source, "runtime");
        assert_eq!(profiles, ["anp.group.base.v2"]);
        assert_eq!(security, ["group-e2ee"]);

        let (profiles, security, source) = negotiate_profiles(
            &["hint.profile".to_string()],
            &["hint.security".to_string()],
            None,
        );
        assert_eq!(source, "hint");
        assert_eq!(profiles, ["hint.profile"]);
        assert_eq!(security, ["hint.security"]);
    }
}
