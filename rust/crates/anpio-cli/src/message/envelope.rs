//! Outbound envelope assembly (P1 §4–§6).
//!
//! The port of `packages/core/src/message/envelope.ts`'s build half. Same reason it exists
//! as one module there: the bytes that get signed and the bytes that go on the wire must be
//! produced in **one** place, or "you signed something other than what you sent" becomes a
//! live class of bug. So there is no way to send a request that did not come through here.
//!
//! Only the *unconditional* rules are checked here. Whether `meta.target` or `auth` is
//! required is a Profile question (the service's method table answers it, TODO5 §3) and
//! baking it in would put P3/P6 rules into P1.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{AnpioError, Result};

/// P1 §4.1: `jsonrpc` MUST be exactly this.
pub const JSONRPC_VERSION: &str = "2.0";

/// P1 §6.2.5 / §6.2.5.1: the allowed `meta.target.kind` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Agent,
    Group,
    Service,
}

/// P1 §6.2.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnpTarget {
    pub kind: TargetKind,
    pub did: String,
}

/// P1 §6.2's **core** `meta` fields.
///
/// Unknown core fields MUST be rejected; only `x_`-prefixed extensions MAY be ignored
/// (§12.1). So the extension map is kept separate and checked — a `#[serde(deny_unknown_fields)]`
/// would reject the `x_` ones too, and no attribute at all would accept a typo'd `profil`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnpMeta {
    /// §6.2.1: deprecated, kept for compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anp_version: Option<String>,
    /// §6.2.2: MUST. The single Profile this request is to be read under.
    pub profile: String,
    /// §6.2.3: MUST.
    pub security_profile: String,
    /// §6.2.4: MUST except for anonymous public discovery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_did: Option<String>,
    /// §6.2.4.1: conditional; MUST NOT appear outside P5/P6.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_device_id: Option<String>,
    /// §6.2.4.2: conditional, same.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<String>,
    /// §6.2.5: MUST when the method has a protocol-level target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<AnpTarget>,
    /// §6.2.6: MUST for every state-changing operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    /// §6.2.7: MUST for message-bearing operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    /// §6.2.8: SHOULD, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// §6.2.9: no longer a standard interop field; MUST NOT take part in any security,
    /// authorization, or idempotency decision (§13.3). Kept so a spec'd field is not
    /// rejected as unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// §6.2.10: MUST for message-bearing operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// §12.1: `x_`-prefixed implementation extensions.
    #[serde(flatten)]
    pub extensions: Map<String, Value>,
}

/// P1 appendix A: an origin proof. `auth` itself MUST NOT enter the digest input (A.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnpOriginProof {
    /// A.2: MUST be sha-256 (RFC 9530 Content-Digest).
    #[serde(rename = "contentDigest")]
    pub content_digest: String,
    /// A.2: MUST use the label `sig1` (RFC 9421 Signature-Input).
    #[serde(rename = "signatureInput")]
    pub signature_input: String,
    /// A.2: MUST use the label `sig1` (RFC 9421 Signature).
    pub signature: String,
}

/// A.1: `scheme` MUST equal this, and `origin_proof` MUST be present.
pub const ORIGIN_PROOF_SCHEME: &str = "anp-rfc9421-origin-proof-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnpAuth {
    pub scheme: String,
    pub origin_proof: AnpOriginProof,
}

/// P1 §6.1: the fixed top level `{meta, auth, body}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnpParams {
    pub meta: AnpMeta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AnpAuth>,
    pub body: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnpRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: AnpParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnpNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: AnpParams,
}

/// §12.1: the first unknown **core** `meta` field, if any. `x_` extensions are allowed.
///
/// Mirrors `firstUnknownMetaField` — the typed struct cannot be violated from inside this
/// crate, but a caller can build a `Value` by hand (a config file, an `x_` passthrough),
/// so the check runs on the flattened map rather than being assumed.
pub fn first_unknown_meta_field(meta: &AnpMeta) -> Option<&str> {
    meta.extensions
        .keys()
        .find(|key| !key.starts_with("x_"))
        .map(String::as_str)
}

fn build_outbound(
    method: &str,
    meta: AnpMeta,
    body: Option<Value>,
    auth: Option<AnpAuth>,
) -> Result<AnpParams> {
    if method.is_empty() {
        return Err(AnpioError::MessageInvalid(
            "method MUST be a non-empty string (P1 §5.5)".to_string(),
        ));
    }
    if method.starts_with("rpc.") {
        return Err(AnpioError::MessageInvalid(format!(
            "Method \"{method}\" uses the reserved \"rpc.\" prefix (P1 §5.5)"
        )));
    }
    if let Some(unknown) = first_unknown_meta_field(&meta) {
        return Err(AnpioError::MessageInvalid(format!(
            "Unknown core meta field \"{unknown}\" (P1 §12.1)"
        )));
    }
    let body = match body {
        Some(Value::Object(map)) => Value::Object(map),
        // §6.1's `body` is an object; an absent one is `{}`.
        None => Value::Object(Map::new()),
        Some(_) => {
            return Err(AnpioError::MessageInvalid(
                "params.body MUST be an object (P1 §6.1)".to_string(),
            ))
        }
    };
    Ok(AnpParams {
        meta,
        auth,
        body,
    })
}

/// Assemble an outbound Request (P1 §4.1, §5.1, §6.1).
///
/// The invariant its output must satisfy is that the peer's `parseEnvelope` accepts it —
/// the service reads envelopes with `first_unknown_meta_field` above, and "we send what we
/// would refuse" is exactly the failure this signature is arranged to prevent.
pub fn build_message_request(
    id: &str,
    method: &str,
    meta: AnpMeta,
    body: Option<Value>,
    auth: Option<AnpAuth>,
) -> Result<AnpRequest> {
    if id.is_empty() {
        return Err(AnpioError::MessageInvalid(
            "Request id MUST be a non-empty string (P1 §5.2)".to_string(),
        ));
    }
    Ok(AnpRequest {
        jsonrpc: JSONRPC_VERSION.to_string(),
        id: id.to_string(),
        method: method.to_string(),
        params: build_outbound(method, meta, body, auth)?,
    })
}

/// Assemble an outbound Notification (P1 §5.3, §6.1): the Request **without an `id`**.
///
/// Narrow by construction: §5.3 allows only async pushes needing no acknowledgement.
/// State-changing operations and sends needing an idempotent answer MUST NOT use it — they
/// need precisely the response that `id` buys (§5.6).
pub fn build_message_notification(
    method: &str,
    meta: AnpMeta,
    body: Option<Value>,
    auth: Option<AnpAuth>,
) -> Result<AnpNotification> {
    Ok(AnpNotification {
        jsonrpc: JSONRPC_VERSION.to_string(),
        method: method.to_string(),
        params: build_outbound(method, meta, body, auth)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn meta() -> AnpMeta {
        AnpMeta {
            profile: "anp.core.binding.v1".to_string(),
            security_profile: "transport-protected".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn request_serializes_to_the_spec_shape() {
        let request = build_message_request("id-1", "anp.get_capabilities", meta(), None, None).unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value,
            json!({
                "jsonrpc": "2.0",
                "id": "id-1",
                "method": "anp.get_capabilities",
                "params": {
                    "meta": {
                        "profile": "anp.core.binding.v1",
                        "security_profile": "transport-protected"
                    },
                    "body": {}
                }
            })
        );
    }

    #[test]
    fn auth_is_omitted_when_absent_and_verbatim_when_present() {
        let absent = build_message_request("id-1", "m", meta(), None, None).unwrap();
        assert!(serde_json::to_value(&absent).unwrap()["params"].get("auth").is_none());

        let auth = AnpAuth {
            scheme: ORIGIN_PROOF_SCHEME.to_string(),
            origin_proof: AnpOriginProof {
                content_digest: "sha-256=:x:".to_string(),
                signature_input: "sig1=(\"@method\")".to_string(),
                signature: "sig1=:y:".to_string(),
            },
        };
        let present = build_message_request("id-1", "m", meta(), None, Some(auth)).unwrap();
        let params = serde_json::to_value(&present).unwrap()["params"].clone();
        assert_eq!(params["auth"]["scheme"], ORIGIN_PROOF_SCHEME);
        assert_eq!(params["auth"]["origin_proof"]["contentDigest"], "sha-256=:x:");
        assert_eq!(params["auth"]["origin_proof"]["signatureInput"], "sig1=(\"@method\")");
    }

    #[test]
    fn notification_has_no_id_at_all() {
        let notification = build_message_notification("m", meta(), None, None).unwrap();
        let value = serde_json::to_value(&notification).unwrap();
        assert!(value.get("id").is_none());
    }

    #[test]
    fn reserved_prefix_and_empty_method_are_refused() {
        assert!(build_message_request("id", "rpc.discover", meta(), None, None).is_err());
        assert!(build_message_request("id", "", meta(), None, None).is_err());
        assert!(build_message_request("", "m", meta(), None, None).is_err());
    }

    #[test]
    fn unknown_core_meta_field_is_refused_but_x_extension_is_not() {
        let mut bad = meta();
        bad.extensions.insert("profil".to_string(), json!("typo"));
        assert_eq!(first_unknown_meta_field(&bad), Some("profil"));
        assert!(build_message_request("id", "m", bad, None, None).is_err());

        let mut ok = meta();
        ok.extensions.insert("x_anpiocli".to_string(), json!({"a": 1}));
        assert!(first_unknown_meta_field(&ok).is_none());
        let value = serde_json::to_value(build_message_request("id", "m", ok, None, None).unwrap()).unwrap();
        assert_eq!(value["params"]["meta"]["x_anpiocli"]["a"], 1);
    }

    #[test]
    fn body_must_be_an_object() {
        assert!(build_message_request("id", "m", meta(), Some(json!([1, 2])), None).is_err());
        assert!(build_message_request("id", "m", meta(), Some(json!("s")), None).is_err());
    }

    #[test]
    fn round_trips_through_json() {
        let request = build_message_request("id-1", "m", meta(), Some(json!({"k": 1})), None).unwrap();
        let text = serde_json::to_string(&request).unwrap();
        let back: AnpRequest = serde_json::from_str(&text).unwrap();
        assert_eq!(back.method, request.method);
        assert_eq!(back.id, request.id);
        assert_eq!(back.params.body, request.params.body);
        assert_eq!(back.params.meta.profile, request.params.meta.profile);
    }
}
