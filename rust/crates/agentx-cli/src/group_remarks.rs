//! What I call a group (TODO6 §4.2).
//!
//! The other half of [`crate::contacts`], and deliberately a separate module with a separate
//! Profile. A contact is a peer `msg send --to` can reach; a group is `group`-addressed. If
//! the two shared a book, a name could resolve to a group DID and `msg send --to <that name>`
//! would take it — and the service would file a delivery owned by the group DID, a mailbox no
//! group ever reads as a group.
//!
//! ## The group's own name is not this
//!
//! It has one already: `group_profile.display_name`, on the group's host, written by
//! `group.update_profile`, and **the same for every member** (`group info` prints it as
//! `name:`). What is stored here is the contrary thing — the name only I see, which the
//! protocol has no place for and ought not: it is my memory, not a fact about the group.
//!
//! ## The key is the group DID
//!
//! Where a contact keys on `subject`: an agent DID embeds a key fingerprint and `did update`
//! moves it, so a remark hung on the DID would vanish at the moment the peer rotates a key
//! (§3.2). A group DID is `did:web:…:g:<id>` in the service's own namespace — no fingerprint,
//! nothing to rotate — so `subject_of` is the identity function on it, and a `subject` column
//! would only be something a reader has to check is one.

use serde_json::Value;

use crate::error::{AgentxError, Result};

/// One group this identity has named, as the service returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRemark {
    /// The group. The row's key, and the thing `group info` looks itself up by.
    pub group_did: String,
    /// What I call it. Never absent — a row here exists only because someone named the group
    /// (unlike a [`crate::contacts::Contact`], which can exist before it has a name).
    pub remark: String,
    pub created_at: String,
    pub updated_at: String,
}

impl GroupRemark {
    /// One row from a `group_remarks.list` / `group_remarks.put` result object.
    pub fn from_json(value: &Value) -> Result<GroupRemark> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("a group remark is not a JSON object"))?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).map(str::to_string);
        Ok(GroupRemark {
            group_did: text("group_did")
                .ok_or_else(|| malformed("a group remark names no group"))?,
            remark: text("remark").ok_or_else(|| malformed("a group remark has no remark"))?,
            created_at: text("created_at").unwrap_or_default(),
            updated_at: text("updated_at").unwrap_or_default(),
        })
    }
}

/// The `group_remarks` array out of a `group_remarks.list` result.
pub fn book_from_json(result: &Value) -> Result<Vec<GroupRemark>> {
    let rows = result
        .get("group_remarks")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("group_remarks.list answered without a group_remarks array"))?;
    rows.iter().map(GroupRemark::from_json).collect()
}

fn malformed(what: &str) -> AgentxError {
    AgentxError::MessageInvalid(format!("{what} (TODO6 §4.2 group remarks surface)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_row_is_read_back_as_the_service_stored_it() {
        let row = GroupRemark::from_json(&json!({
            "group_did": "did:web:127.0.0.1%3A8790:g:team",
            "remark": "Team",
            "created_at": "2026-10-02T00:00:00Z",
            "updated_at": "2026-10-02T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(row.group_did, "did:web:127.0.0.1%3A8790:g:team");
        assert_eq!(row.remark, "Team");
    }

    #[test]
    fn a_row_without_a_group_or_a_name_is_refused_rather_than_half_read() {
        // 两个都必须在场才有意义：没有群名的行不该存在（那是服务端的 NOT NULL 那一列），
        // 而没有群的行根本不知道在说谁。读成一个空串会让它一路走到打印那一步。
        assert!(GroupRemark::from_json(&json!({ "remark": "Team" })).is_err());
        assert!(GroupRemark::from_json(&json!({ "group_did": "did:web:a:g:b" })).is_err());
    }

    #[test]
    fn a_list_without_the_array_is_an_error_not_an_empty_book() {
        // "服务说没有" 与 "这个服务不返回这一族" 不能长得一样——后者是一个该立刻暴露的
        // 不一致，而读成空表会让 `group info` 静静地不显示备注。
        assert!(book_from_json(&json!({ "group_remarks": [] })).unwrap().is_empty());
        assert!(book_from_json(&json!({ "contacts": [] })).is_err());
    }
}
