//! The address book: name ↔ DID (TODO6 §3).
//!
//! ANP addresses by DID and `msg send --to` takes one, but a person — and an agent relaying
//! what a person said — holds a *name*: "send a note to Alice" names nobody the wire can
//! reach. This module is the layer between the two, and it is the whole of it: everything
//! that decides *which* Alice is here, and it is a pure function over the book so it can be
//! read and tested without a service.
//!
//! ## Where the book lives
//!
//! The service's own store, through `contacts.list` / `contacts.put` / `contacts.remove` —
//! not a file beside `identity.json`. A remark is "what *I* call this peer", and the service
//! already knows who "I" is: the row is keyed by `owner_did`, the verified signer of the
//! request, so one identity's remarks are invisible to another's by construction rather than
//! by file permissions, and nothing local has to be kept in step with a second copy.
//!
//! ## The key is the subject, not the DID
//!
//! TODO6 §3.2, and the reason is a bug that would otherwise be silent: `did update` moves the
//! DID (it embeds a key fingerprint), so a remark hung on the DID disappears at the moment
//! the peer rotates a key. `subject_of` drops the fingerprint and leaves the part that still
//! says "the same person", which is why the service derives it server-side from the `did` and
//! never lets a caller name it.
//!
//! ## What is deliberately absent
//!
//! No nickname and no avatar. Those are the *peer's* own words for itself, they live on the
//! peer's own host (`get_me`), and a copy here would be a cache of something this book has no
//! way to invalidate. `contacts` answers "who is this DID to me"; what the peer calls itself
//! is a different question with a different owner.

use serde_json::Value;

use crate::error::{AgentxError, Result};

/// One row of the book, as the service returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// `subject_of(did)` — the stable body, and the row's key. Present because the *service*
    /// keys on it: a client that computed it would be a second definition of the key.
    pub subject: String,
    /// The DID that subject was last seen at. A column, not a key: it moves on a key update
    /// and the row does not.
    pub did: String,
    /// What *I* call this peer. `None` is a normal state — a row can exist before it has a
    /// name, because adding a peer and naming it are two decisions.
    pub remark: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl Contact {
    /// One row from a `contacts.list` / `contacts.put` result object.
    ///
    /// `remark` is read as optional because the service reports a missing remark as JSON
    /// `null` — deliberately, so that "no remark" and "this service does not return remarks"
    /// do not look alike. `null` and an absent key both land here as `None`; `subject` and
    /// `did` do not, because a row without them is not a row, and reading it as one would put
    /// an empty string where a DID is expected.
    pub fn from_json(value: &Value) -> Result<Contact> {
        let object = value
            .as_object()
            .ok_or_else(|| malformed("a contact is not a JSON object"))?;
        let text = |name: &str| object.get(name).and_then(Value::as_str).map(str::to_string);
        Ok(Contact {
            subject: text("subject").ok_or_else(|| malformed("a contact has no subject"))?,
            did: text("did").ok_or_else(|| malformed("a contact has no did"))?,
            remark: text("remark"),
            created_at: text("created_at").unwrap_or_default(),
            updated_at: text("updated_at").unwrap_or_default(),
        })
    }

    /// The name this row answers to, if it has one.
    pub fn name(&self) -> &str {
        self.remark.as_deref().unwrap_or("(no remark)")
    }
}

/// The `contacts` array out of a `contacts.list` result.
pub fn book_from_json(result: &Value) -> Result<Vec<Contact>> {
    let rows = result
        .get("contacts")
        .and_then(Value::as_array)
        .ok_or_else(|| malformed("contacts.list answered without a contacts array"))?;
    rows.iter().map(Contact::from_json).collect()
}

/// What a lookup found. Three arms, because the caller has three different things to do —
/// send, refuse, or say how to add the contact — and collapsing any two of them is how a
/// message reaches the wrong person.
#[derive(Debug, Clone)]
pub enum Lookup {
    One(Box<Contact>),
    /// More than one row answers to the name. The caller MUST refuse and list them: picking
    /// one is the error this whole surface exists to not make (TODO6 §3.3).
    Ambiguous(Vec<Contact>),
    /// Nothing matched. `did_shaped` says whether the string should go on to discovery (a DID
    /// is already its own answer) or be reported as a name that is not in the book.
    None { did_shaped: bool },
}

/// Resolve `input` against `book`.
///
/// A remark matches exactly, and also without regard to ASCII case: the caller typed a name
/// they chose themselves, and refusing `alice` because the remark is `Alice` is a distinction
/// carrying no information. **All** matches are collected before the count is read, so a book
/// holding both `Alice` and `alice` is ambiguous rather than "the exact spelling wins" — the
/// exact spelling is not evidence about which person was meant.
///
/// A row with no remark is not addressable by name, which is what `None`'s third state is
/// for: it is reachable only by its DID until someone names it.
pub fn lookup(book: &[Contact], input: &str) -> Lookup {
    let matches: Vec<Contact> = book
        .iter()
        .filter(|contact| {
            contact
                .remark
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case(input))
        })
        .cloned()
        .collect();
    match matches.len() {
        0 => Lookup::None { did_shaped: looks_like_a_did(input) },
        1 => Lookup::One(Box::new(matches.into_iter().next().expect("length is 1"))),
        _ => Lookup::Ambiguous(matches),
    }
}

/// Is this string shaped like a DID rather than a name?
///
/// A syntax test, deliberately not a "do I know this method" test. The only decision it feeds
/// is whether to say "no contact named X, here is how to add one" or to hand the string to
/// discovery and let *that* answer — so refusing `did:webvh:…` here because this client
/// cannot resolve it would report a working DID as a typo'd name, and refusing is the worse
/// of the two mistakes because it says the opposite of the truth.
///
/// `did:web:example.com`, `did:wba:a.example:user:alice` → true. `alice`, `did:web`,
/// `did:web:` → false. A name containing colons but not starting with `did` is a name.
pub fn looks_like_a_did(input: &str) -> bool {
    let mut segments = input.split(':');
    segments.next() == Some("did")
        && segments.next().is_some_and(|method| !method.is_empty())
        && segments.next().is_some_and(|id| !id.is_empty())
}

/// The refusal for a name that is not in the book (TODO6 §3.3, third test).
///
/// The reader here is whichever agent was handed "send this to Alice", and it has to be able
/// to act on the answer: so the message names the command that fixes the problem and spells
/// out how to call it, rather than reporting a name that resolved to nothing.
pub fn unknown_name_error(input: &str) -> AgentxError {
    AgentxError::MessageInvalid(format!(
        "no contact named {input:?}: add one with `agentx-cli contacts add <did> --remark {input}`, \
         or use the DID directly"
    ))
}

/// The refusal for a name more than one contact answers to (TODO6 §3.3, second test).
///
/// Every candidate is listed with its DID: a refusal that said only "ambiguous" would leave
/// the caller unable to do anything but guess, which is what the refusal is there to stop.
pub fn ambiguous_name_error(input: &str, candidates: &[Contact]) -> AgentxError {
    let mut lines = vec![format!(
        "{input:?} matches {} contacts, so it does not name one:",
        candidates.len()
    )];
    for contact in candidates {
        lines.push(format!("  {}\t{}", contact.did, contact.name()));
    }
    lines.push(
        "Send to a DID from that list, or give them different remarks \
         (`agentx-cli contacts set-remark <name> <remark>`)."
            .to_string(),
    );
    AgentxError::MessageInvalid(lines.join("\n"))
}

/// The refusal for `contacts add` given something that is not a DID.
///
/// Without this the service would happily store the row: `subject_of` is total (it returns
/// anything it does not recognise unchanged), so `contacts add Alice --remark Alice` would
/// create an entry keyed by the literal string `Alice` — a row that can never be sent to and
/// that no DID will ever match. Catching it at the argument is the difference between a typo
/// and a junk row nobody can explain later.
pub fn not_a_did_error(input: &str) -> AgentxError {
    AgentxError::MessageInvalid(format!(
        "{input:?} is not a DID: `contacts add` takes the DID, and the name goes in --remark \
         (`agentx-cli contacts add did:wba:… --remark {input}`)"
    ))
}

fn malformed(what: &str) -> AgentxError {
    AgentxError::MessageInvalid(format!("{what} (TODO6 §3 contacts surface)"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contact(remark: Option<&str>, did: &str) -> Contact {
        Contact {
            subject: crate::identity::subject_of(did),
            did: did.to_string(),
            remark: remark.map(str::to_string),
            created_at: "2026-10-02T00:00:00.000Z".to_string(),
            updated_at: "2026-10-02T00:00:00.000Z".to_string(),
        }
    }

    const ALICE: &str = "did:wba:example.com:user:alice:e1_aaa";
    const OTHER_ALICE: &str = "did:wba:other.example:user:alice:e1_bbb";
    const BOB: &str = "did:wba:example.com:user:bob:e1_ccc";

    #[test]
    fn a_unique_name_resolves_to_its_did() {
        let book = vec![contact(Some("Alice"), ALICE), contact(Some("Bob"), BOB)];
        match lookup(&book, "Alice") {
            Lookup::One(contact) => assert_eq!(contact.did, ALICE),
            other => panic!("expected one match, got {other:?}"),
        }
    }

    #[test]
    fn two_contacts_with_the_same_name_are_ambiguous_and_both_are_listed() {
        // TODO6 §3.3: this is the one the exit code is for. Sending to the wrong Alice is the
        // most expensive mistake this surface can make, so it is refused rather than guessed.
        let book = vec![contact(Some("Alice"), ALICE), contact(Some("Alice"), OTHER_ALICE)];
        match lookup(&book, "Alice") {
            Lookup::Ambiguous(candidates) => {
                assert_eq!(candidates.len(), 2);
                let listed: Vec<&str> = candidates.iter().map(|c| c.did.as_str()).collect();
                assert!(listed.contains(&ALICE));
                assert!(listed.contains(&OTHER_ALICE));
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn case_does_not_hide_a_duplicate() {
        // `Alice` and `alice` are two entries as far as the book is concerned, so the lookup
        // must not treat the exact spelling as a tie-break: it is not evidence about which
        // person was meant.
        let book = vec![contact(Some("Alice"), ALICE), contact(Some("alice"), OTHER_ALICE)];
        assert!(matches!(lookup(&book, "Alice"), Lookup::Ambiguous(_)));
        assert!(matches!(lookup(&book, "ALICE"), Lookup::Ambiguous(_)));
    }

    #[test]
    fn case_alone_still_matches_one_contact() {
        let book = vec![contact(Some("Alice"), ALICE)];
        assert!(matches!(lookup(&book, "alice"), Lookup::One(_)));
    }

    #[test]
    fn a_contact_with_no_remark_cannot_be_addressed_by_name() {
        let book = vec![contact(None, ALICE)];
        assert!(matches!(lookup(&book, "Alice"), Lookup::None { did_shaped: false }));
    }

    #[test]
    fn an_unknown_name_is_not_a_did_but_an_unknown_did_is() {
        // The two are told apart because the caller does two different things with them:
        // "add a contact first" versus "hand it to discovery".
        assert!(matches!(lookup(&[], "Alice"), Lookup::None { did_shaped: false }));
        assert!(matches!(
            lookup(&[], "did:web:nowhere.example"),
            Lookup::None { did_shaped: true }
        ));
    }

    #[test]
    fn did_shape_is_a_syntax_test_not_a_method_allowlist() {
        assert!(looks_like_a_did("did:web:example.com"));
        assert!(looks_like_a_did("did:wba:example.com:user:alice:e1_aaa"));
        assert!(looks_like_a_did("did:webvh:example.com:abc"));
        // A method this client cannot resolve is still a DID: reporting it as a typo'd name
        // would be the opposite of the truth, and the caller would go add a contact for it.
        assert!(looks_like_a_did("did:unknown-method:whatever"));
        assert!(!looks_like_a_did("Alice"));
        assert!(!looks_like_a_did("did:web"));
        assert!(!looks_like_a_did("did:web:"));
        assert!(!looks_like_a_did("team:alice"));
    }

    #[test]
    fn the_unknown_name_refusal_names_the_command_that_fixes_it() {
        let text = unknown_name_error("Alice").to_string();
        assert!(text.contains("no contact named \"Alice\""));
        assert!(text.contains("contacts add"));
        assert!(text.contains("--remark Alice"));
    }

    #[test]
    fn the_ambiguous_refusal_lists_every_candidate_with_its_did() {
        let book = vec![contact(Some("Alice"), ALICE), contact(Some("Alice"), OTHER_ALICE)];
        let Lookup::Ambiguous(candidates) = lookup(&book, "Alice") else {
            panic!("expected ambiguity")
        };
        let text = ambiguous_name_error("Alice", &candidates).to_string();
        assert!(text.contains("matches 2 contacts"));
        assert!(text.contains(ALICE) && text.contains(OTHER_ALICE));
    }

    #[test]
    fn a_row_without_a_remark_is_read_as_none_not_as_an_empty_name() {
        // The service reports a missing remark as `null`; reading that as `""` would make an
        // unnamed row match an empty query.
        let row = json!({
            "subject": "did:wba:example.com:user:alice",
            "did": ALICE,
            "remark": null,
            "created_at": "2026-10-02T00:00:00.000Z",
            "updated_at": "2026-10-02T00:00:00.000Z"
        });
        assert_eq!(Contact::from_json(&row).unwrap().remark, None);
        assert!(matches!(lookup(&[contact(None, ALICE)], ""), Lookup::None { .. }));
    }

    #[test]
    fn a_contact_without_a_did_is_refused_rather_than_read_as_empty() {
        let row = json!({ "subject": "x", "remark": "Alice" });
        assert!(Contact::from_json(&row).is_err());
    }
}
