//! The `group` family — P4, `anp.group.base.v2`.
//!
//! The port of `packages/cli/src/commands/group.ts`'s non-rendering half. It is a family of
//! its own rather than more `msg` subcommands because the thing being addressed is not a
//! peer: a group has its own `group_did` and its own host, and it is reached by resolving the
//! **group's** DID document — the same five discovery steps P2 §9.1 defines for an agent
//! (§3.1 "一个群，一个 Group DID"). So there is no group addressing to invent; `discover()`
//! already does it.
//!
//! The one thing P4 does not let this be a constant is `meta.target`:
//!
//! ```text
//! group.create      kind = "service",  did = ANPMessageService.serviceDid
//! everything else   kind = "group",    did = group_did
//! ```
//!
//! `meta.target` is inside the Signed Request Object, so that difference is **signed**, not
//! routed: `group.create` asks a service to make a group, and there is no group to name yet.

use serde_json::{json, Value};

use crate::error::{AgentxError, Result};

use crate::message::{AnpTarget, MessageServiceTarget, TargetKind};

/// P4 §7.1: the five standard permission keys, and the three roles. Checked here rather than
/// left to the service, because a policy the service will refuse is a round trip the caller
/// can skip — and the refusal would arrive as a generic policy violation.
pub const POLICY_PERMISSIONS: [&str; 5] = ["send", "add", "remove", "update_profile", "update_policy"];
pub const POLICY_ROLES: [&str; 3] = ["owner", "admin", "member"];
pub const ADMISSION_MODES: [&str; 2] = ["admin-add", "open-join"];

/// P4 §7.1's recommended structure, used verbatim.
///
/// `admission_mode` is the one field worth arguing about, and the argument is not about this
/// Profile: `admin-add` would make a CLI-created group impossible to populate, because the
/// only other way in is `group.add`, which this command surface does not have (TODO1 B6).
/// `open-join` is also the value §7.1's own example carries. A deployment that wants the
/// other mode passes `--policy`.
pub fn default_policy() -> Value {
    json!({
        "message_security_profile": "transport-protected",
        "bootstrap_security_profile": "transport-protected",
        "admission_mode": "open-join",
        "permissions": {
            "send": "member",
            "add": "admin",
            "remove": "admin",
            "update_profile": "admin",
            "update_policy": "owner",
        },
        "attachments_allowed": true,
        "max_members": "500",
    })
}

/// `--policy` is JSON, merged over [`default_policy`]: the caller names what changes and the
/// rest keeps the recommended structure. A **shallow** merge, deliberately — the only nested
/// object is `permissions`, and half a permissions object is not a policy.
pub fn policy_of(raw: Option<&str>) -> Result<Value> {
    let Some(raw) = raw else {
        return Ok(default_policy());
    };
    let parsed: Value = serde_json::from_str(raw).map_err(|_| {
        AgentxError::MessageInvalid(format!(
            "--policy must be JSON (got {})",
            serde_json::to_string(raw).unwrap_or_else(|_| format!("{raw:?}"))
        ))
    })?;
    let override_fields = parsed.as_object().ok_or_else(|| {
        AgentxError::MessageInvalid("--policy must be a JSON object (P4 §7.1)".to_string())
    })?;

    let mut policy = default_policy();
    let fields = policy.as_object_mut().expect("the default policy is an object");
    for (key, value) in override_fields {
        fields.insert(key.clone(), value.clone());
    }
    check_policy(&policy)?;
    Ok(policy)
}

/// P4 §7.1: both MUST-be-present fields, and the closed sets they range over. Everything else
/// in the object is optional and passed through.
pub fn check_policy(policy: &Value) -> Result<()> {
    let fields = policy.as_object().ok_or_else(|| {
        AgentxError::MessageInvalid("a group policy must be an object (P4 §7.1)".to_string())
    })?;

    let mode = fields.get("admission_mode").and_then(Value::as_str);
    if !mode.is_some_and(|mode| ADMISSION_MODES.contains(&mode)) {
        return Err(AgentxError::MessageInvalid(format!(
            "--policy admission_mode must be one of {} (P4 §7.1 L349)",
            ADMISSION_MODES.join(", ")
        )));
    }

    let permissions = fields.get("permissions").and_then(Value::as_object).ok_or_else(|| {
        AgentxError::MessageInvalid("--policy permissions must be an object (P4 §7.1 L335)".to_string())
    })?;
    // "包含且仅包含" (L353): a sixth key is as wrong as a missing one, and it is the kind of
    // wrong a service may quietly ignore rather than refuse.
    let mut missing: Vec<&str> = Vec::new();
    for key in POLICY_PERMISSIONS {
        if !permissions.contains_key(key) {
            missing.push(key);
        }
    }
    let extra: Vec<&str> = permissions
        .keys()
        .map(String::as_str)
        .filter(|key| !POLICY_PERMISSIONS.contains(key))
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        let mut problem = format!(
            "--policy permissions must contain exactly {} (P4 §7.1 L353)",
            POLICY_PERMISSIONS.join(", ")
        );
        if !missing.is_empty() {
            problem.push_str(&format!("; missing {}", missing.join(", ")));
        }
        if !extra.is_empty() {
            problem.push_str(&format!("; unknown {}", extra.join(", ")));
        }
        return Err(AgentxError::MessageInvalid(problem));
    }

    for (key, value) in permissions {
        let role = value.as_str();
        if !role.is_some_and(|role| POLICY_ROLES.contains(&role)) {
            return Err(AgentxError::MessageInvalid(format!(
                "--policy permissions.{key} must be one of {} (P4 §7.1 L360)",
                POLICY_ROLES.join(", ")
            )));
        }
    }
    Ok(())
}

/// The target for `group.create`: the **service**, not a group (P4 §8.1.2, "`meta.target.did`
/// MUST 等于目标 `ANPMessageService.serviceDid`").
///
/// A service reachable only from its own domain is not required to publish a `serviceDid`
/// (P2 §8.7 makes it a cross-domain requirement), and this command cannot be made conformant
/// without one — `kind` is `service`, so no other DID would be the right value. Refusing with
/// the reason is the only honest answer; substituting the caller's own DID would sign a claim
/// the service never made.
pub fn service_target(target: &MessageServiceTarget) -> Result<AnpTarget> {
    let did = target.service_did.clone().ok_or_else(|| {
        AgentxError::MessageInvalid(format!(
            "{} publishes an ANPMessageService with no serviceDid, and group.create must name it \
             as the target (P4 §8.1.2; a serviceDid is otherwise only required for cross-domain \
             calls, P2 §8.7)",
            target.identity
        ))
    })?;
    Ok(AnpTarget {
        kind: TargetKind::Service,
        did,
    })
}

/// Every other group method is addressed to the group itself (P4 §8.2.2, §8.9.2).
pub fn group_target(group_did: &str) -> AnpTarget {
    AnpTarget {
        kind: TargetKind::Group,
        did: group_did.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(service_did: Option<&str>) -> MessageServiceTarget {
        MessageServiceTarget {
            identity: "did:wba:example.com:user:a".to_string(),
            service_id: "#anp-message".to_string(),
            endpoint: "https://svc.example/anp-im/rpc".to_string(),
            service_did: service_did.map(str::to_string),
            hinted_profiles: vec![],
            hinted_security_profiles: vec![],
        }
    }

    #[test]
    fn the_default_policy_is_what_the_command_sends_unchanged() {
        let policy = policy_of(None).unwrap();
        assert_eq!(policy["admission_mode"], "open-join");
        assert_eq!(policy["max_members"], "500");
        assert_eq!(policy["permissions"]["update_policy"], "owner");
    }

    #[test]
    fn an_override_merges_over_the_default_rather_than_replacing_it() {
        let policy = policy_of(Some(r#"{"admission_mode":"admin-add"}"#)).unwrap();
        assert_eq!(policy["admission_mode"], "admin-add");
        // The fields the caller did not name keep the recommended values.
        assert_eq!(policy["message_security_profile"], "transport-protected");
        assert_eq!(policy["permissions"]["send"], "member");
    }

    #[test]
    fn a_policy_that_is_not_an_object_is_refused() {
        assert!(policy_of(Some("[1,2]")).is_err());
        assert!(policy_of(Some("not json")).is_err());
    }

    #[test]
    fn the_closed_sets_are_enforced() {
        assert!(policy_of(Some(r#"{"admission_mode":"invite-only"}"#)).is_err());
        assert!(policy_of(Some(r#"{"permissions":{"send":"everyone"}}"#)).is_err());
        // A sixth key is as wrong as a missing one (§7.1 "包含且仅包含").
        assert!(policy_of(Some(
            r#"{"permissions":{"send":"member","add":"admin","remove":"admin","update_profile":"admin","update_policy":"owner","delete":"admin"}}"#
        ))
        .is_err());
        // Half a permissions object is not a policy.
        assert!(policy_of(Some(r#"{"permissions":{"send":"member"}}"#)).is_err());
    }

    #[test]
    fn group_create_names_the_service_and_everything_else_names_the_group() {
        let target = service_target(&service(Some("did:wba:example.com:service:svc"))).unwrap();
        assert_eq!(target.kind, TargetKind::Service);
        assert_eq!(target.did, "did:wba:example.com:service:svc");

        let target = group_target("did:wba:example.com:group:team");
        assert_eq!(target.kind, TargetKind::Group);
        assert_eq!(target.did, "did:wba:example.com:group:team");
    }

    #[test]
    fn a_service_without_a_service_did_cannot_be_the_create_target() {
        assert!(service_target(&service(None)).is_err());
    }
}
