//! `did resolve --chain` — walking the update links a DID leaves behind.
//!
//! The walk itself belongs to `anp`: `resolve_current_did` fetches each document, verifies
//! the hop that retired it, refuses a cycle or a conflicting successor, and classifies the
//! assurance the chain adds up to. Re-implementing that loop here would be forking the one
//! thing the crate is authoritative about.
//!
//! What the crate does not own is transport. Its [`DidDocumentFetcher`] is **synchronous**,
//! while this client's DID fetch is async — it goes through the same SSRF policy and the
//! same content-type check every other hop does (`message::resolve`). So this module is that
//! adapter and nothing else.
//!
//! One thing the adapter *does* have to change is the proof `proofValue`'s encoding: the
//! walk verifies every document it stands on, and the crate's verifier misreads the base58
//! form these hosts sign (TODO5 §8-J, third pit). The fetch path already knows that
//! ([`document_in_crate_form`]), so the fetcher below hands the crate the same bytes the
//! fetch path would.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use anp::authentication::did_transition::{
    parse_did_wba_e1, resolve_current_did, DidTransitionError, InMemoryTransitionCache,
    TransitionErrorKind, TransitionResult, TransitionStatus, DEFAULT_MAX_TRANSITION_HOPS,
};
use serde_json::Value;

use crate::message::resolve::{
    document_in_crate_form, document_url, resolve_did_document, ResolvePolicy,
};

/// A chain walk that ended. `documents` holds every document the walk fetched, so the
/// caller can print the one that is current without asking the network again for something
/// it already has.
pub struct ChainResolution {
    pub result: TransitionResult,
    /// The URL the *current* DID's document is served from — what the walk last fetched.
    pub doc_url: String,
    pub documents: BTreeMap<String, Value>,
}

impl ChainResolution {
    /// True when the DID asked about is no longer the one in force. A conclusion, not a
    /// failure: `did resolve` exits 2 for it (`docs/design/cli.md` §7).
    pub fn is_superseded(&self) -> bool {
        self.result.status == TransitionStatus::Superseded
    }
}

/// The `snake_case` name of any of `anp`'s `#[serde(rename_all = "snake_case")]` enums.
///
/// Read through serde rather than re-spelled with a `match` here: a variant added upstream
/// would otherwise fall into a wildcard and be misreported, and the name is already
/// declared once, in the type's own attributes.
pub fn snake_case_name<T: serde::Serialize + std::fmt::Debug>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{value:?}"))
}

/// Why a walk ended without resolving.
///
/// The two arms are the CLI's exit codes, so the distinction is carried in the type rather
/// than left for the caller to re-derive from an error message.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The walk could not fetch a document. **Nothing was concluded** about the chain —
    /// this is a network or policy failure, the same class as any other failed fetch.
    #[error("{0:#}")]
    Unavailable(anyhow::Error),
    /// The walk reached a verdict: the chain does not verify.
    #[error("did_chain_broken: {0}")]
    Broken(DidTransitionError),
}

/// Walk `did`'s update links to the DID that is current.
///
/// `did` must be a `did:wba` DID with an `e1_` fingerprint; anything else has no update
/// links to walk, and the crate reports that as an opaque profile error, so it is refused
/// here with something a caller can act on.
pub async fn resolve_chain(
    client: &reqwest::Client,
    did: &str,
    policy: &ResolvePolicy,
) -> std::result::Result<ChainResolution, ChainError> {
    if let Err(err) = parse_did_wba_e1(did) {
        return Err(ChainError::Unavailable(anyhow::anyhow!(
            "{did} is not a did:wba DID with an e1_ fingerprint, so it has no update chain ({})",
            err.message
        )));
    }

    let client = client.clone();
    let url_policy = (*policy).clone();
    let policy = (*policy).clone();
    let requested = did.to_string();

    let walked = tokio::task::spawn_blocking(move || {
        // A current-thread runtime of our own. `resolve_current_did` is synchronous and
        // calls its fetcher from inside, so the fetcher has to drive a future to
        // completion itself; `spawn_blocking` runs with no ambient runtime, which is what
        // makes owning one here legal (`block_in_place` would be the alternative, and it
        // is a heavier hammer for the same job).
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(err) => {
                return Err(ChainError::Unavailable(anyhow::anyhow!(
                    "building a runtime for the chain walk: {err}"
                )))
            }
        };
        let fetched: RefCell<BTreeMap<String, Value>> = RefCell::new(BTreeMap::new());
        let fetcher = |target: &str| -> std::result::Result<Value, String> {
            let document = runtime
                .block_on(resolve_did_document(&client, target, &policy))
                .map_err(|err| format!("{err:#}"))?;
            // Kept raw: these are the bytes the host served, and they are what
            // `did resolve` prints when the walk supersedes the DID asked about.
            fetched.borrow_mut().insert(target.to_string(), document.clone());
            // Handed over normalized: the walk re-verifies each document it lands on, and
            // the crate's verifier reads a base58 `eddsa-jcs-2022` proofValue through a
            // branch that folds `@context` into the signed bytes, while these hosts sign
            // without that fold — so raw bytes come back as `invalid_proof` on a document
            // that is in fact well signed (TODO5 §8-J, third pit). `resolve_did_document`
            // has already established the document binds under one convention or the
            // other, so `None` here would mean the two checks disagree about the same
            // bytes; it is reported rather than unwrapped.
            document_in_crate_form(&document).ok_or_else(|| {
                format!("the DID document for {target} does not bind to it under either proof convention")
            })
        };
        let mut cache = InMemoryTransitionCache::default();
        let result = resolve_current_did(
            &requested,
            &fetcher,
            &HashMap::new(),
            &mut cache,
            DEFAULT_MAX_TRANSITION_HOPS,
        )
        .map_err(classify)?;
        Ok::<_, ChainError>((result, fetched.into_inner()))
    })
    .await
    .map_err(|err| ChainError::Unavailable(anyhow::anyhow!("the chain walk did not finish: {err}")))?;

    let (result, documents) = walked?;
    // The URL of the document that is *current*, which is the requested DID's own when
    // nothing superseded it — the same derivation, one DID later.
    let doc_url = document_url(&result.current_did, &url_policy)
        .map_err(|err| ChainError::Unavailable(err.into()))?
        .to_string();
    Ok(ChainResolution {
        doc_url,
        result,
        documents,
    })
}

/// Turn the crate's error into the arm that decides the exit code.
///
/// `NetworkError` is the crate's way of saying *the walk could not fetch something* — the
/// fetcher returns a bare `String`, so this is the only place the two cases can be told
/// apart. Everything else is a verdict: the chain was walked and does not verify.
fn classify(err: DidTransitionError) -> ChainError {
    if err.kind == TransitionErrorKind::NetworkError {
        ChainError::Unavailable(anyhow::anyhow!("{}", err.message))
    } else {
        ChainError::Broken(err)
    }
}

/// True when a document is not current: it has been deactivated, or it names the DID that
/// replaced it. Both markers are checked (`packages/core/src/crypto/resolveDid.ts:71`).
///
/// This is a *conclusion*, not a failure — `did resolve` exits 2 for it (cli.md §7).
pub fn document_is_superseded(document: &Value) -> bool {
    document.get("deactivated").and_then(Value::as_bool) == Some(true)
        || document
            .get("successorDid")
            .and_then(Value::as_str)
            .is_some()
}

/// A one-line description of a walk's verdict, for a human reader.
pub fn describe_status(result: &TransitionResult) -> String {
    match result.status {
        TransitionStatus::Active => "current".to_string(),
        TransitionStatus::Superseded => {
            format!("SUPERSEDED — the chain walks on to {}", result.current_did)
        }
    }
}

/// What the walk found when a peer refused a send with `anp.did_superseded` (P1 §10.3, P3 §5.5).
///
/// A closed set of four, so that the text below can be tested against every one of them without a
/// network. It is deliberately *not* `Result<ChainResolution, ChainError>`: the caller has already
/// flattened that, and the builder must not be able to reach back for the walk it is describing.
pub enum Supersession {
    /// The walk reached a DID that is not the one asked about: the refusal was true.
    Verified { successor: String },
    /// The walk ended at the DID asked about. The peer's claim is unconfirmed.
    StillCurrent,
    /// The walk reached a verdict: the chain does not verify.
    Broken { kind: String, message: String },
    /// The walk could not fetch a document — nothing was concluded about the chain.
    Unfetched { reason: String },
}

/// What to say when a peer refuses a send with `anp.did_superseded`.
///
/// `hint` is the peer's `error.data.details.current_did`, and the spec calls it an **unverified
/// hint**: the caller MUST verify the transition from the DID it actually asked about, because a
/// peer can name any successor it likes and a request bound to the wrong DID is a message to the
/// wrong place. So the hint is mentioned only when it *disagrees* with the walk — printing it
/// alongside an agreeing verdict would give it a standing it does not have.
///
/// Nothing here re-sends. Retrying means rebuilding every DID-bound signature, digest and
/// encrypted context, which is what a fresh `msg send --to <successor>` does from scratch; doing
/// it silently is the "retarget without saying so" the peer is forbidden to do and the caller
/// would then be doing on its behalf.
pub fn superseded_refusal_text(to: &str, hint: Option<&str>, outcome: &Supersession) -> String {
    match outcome {
        Supersession::Verified { successor } => {
            let mut text = format!(
                "{to} was refused as superseded (anp.did_superseded), and the chain verifies: it \
                 walks on to {successor}. A retry has to rebuild and re-sign everything bound to \
                 {to}, so send again to the successor rather than to the DID that was refused:\n  \
                 agentx-cli msg send --to {successor} …"
            );
            if let Some(hint) = hint {
                if hint != successor {
                    text.push_str(&format!(
                        "\nThe peer's own hint named {hint}, which is not where this walk ends — \
                         the hint is unverified and this walk is the answer."
                    ));
                }
            }
            text
        }
        Supersession::StillCurrent => format!(
            "{to} was refused as superseded (anp.did_superseded), but the chain does NOT verify \
             it: walking it ends at {to} itself, which is current. Nothing was retried — the \
             peer's claim is unconfirmed, and `agentx-cli did resolve --chain {to}` runs the same \
             walk."
        ),
        Supersession::Broken { kind, message } => format!(
            "{to} was refused as superseded (anp.did_superseded), and the chain does not verify \
             ({kind}: {message}). A successor that cannot be verified is not one to send to, so \
             nothing was retried. `agentx-cli did resolve --chain {to}` runs the same walk."
        ),
        Supersession::Unfetched { reason } => format!(
            "{to} was refused as superseded (anp.did_superseded), but the transition could not be \
             fetched to verify it ({reason}). Nothing was retried: P1 §10.3 requires verifying \
             the walk before acting on the peer's claim, rather than trusting the DID it named. \
             Try again, or run `agentx-cli did resolve --chain {to}`."
        ),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// `DidTransitionError`'s constructor is private to the crate; its fields are not.
    fn transition_error(kind: TransitionErrorKind, message: &str) -> DidTransitionError {
        DidTransitionError {
            kind,
            code: 0,
            message: message.to_string(),
        }
    }

    #[test]
    fn a_deactivated_document_is_superseded() {
        assert!(document_is_superseded(&json!({ "deactivated": true })));
    }

    #[test]
    fn a_document_naming_a_successor_is_superseded() {
        assert!(document_is_superseded(
            &json!({ "successorDid": "did:wba:host:user:a:e1_x" })
        ));
    }

    #[test]
    fn a_plain_document_is_not_superseded() {
        assert!(!document_is_superseded(&json!({ "id": "did:wba:host:a" })));
        // `deactivated: false` is the field present but not the condition — the check is
        // for the value being exactly `true`, not for the key existing.
        assert!(!document_is_superseded(&json!({ "deactivated": false })));
        // Likewise a non-string `successorDid` is not a successor.
        assert!(!document_is_superseded(&json!({ "successorDid": 7 })));
    }

    #[test]
    fn snake_case_name_reads_the_serde_name() {
        assert_eq!(snake_case_name(&TransitionStatus::Active), "active");
        assert_eq!(snake_case_name(&TransitionStatus::Superseded), "superseded");
    }

    #[test]
    fn a_network_error_is_unavailable_not_broken() {
        let err = transition_error(TransitionErrorKind::NetworkError, "connection refused");
        match classify(err) {
            ChainError::Unavailable(err) => {
                assert!(format!("{err:#}").contains("connection refused"));
            }
            ChainError::Broken(err) => panic!("expected Unavailable, got Broken: {err}"),
        }
    }

    #[test]
    fn a_verdict_error_is_broken() {
        let err = transition_error(TransitionErrorKind::InvalidProof, "no");
        match classify(err) {
            ChainError::Broken(err) => assert_eq!(err.kind, TransitionErrorKind::InvalidProof),
            ChainError::Unavailable(err) => panic!("expected Broken, got Unavailable: {err:#}"),
        }
    }

    #[test]
    fn snake_case_name_names_the_broken_kind() {
        // `did resolve` spells the verdict itself, through `snake_case_name` — reading the
        // name off the type rather than matching on the variants here.
        let err = transition_error(TransitionErrorKind::InvalidProof, "no");
        assert_eq!(snake_case_name(&err.kind), "invalid_proof");
        assert_eq!(
            snake_case_name(&TransitionErrorKind::NetworkError),
            "network_error"
        );
    }

    #[test]
    fn describe_status_names_the_did_the_chain_walks_on_to() {
        let active = TransitionResult {
            requested_did: "did:wba:host:a".to_string(),
            current_did: "did:wba:host:a".to_string(),
            status: TransitionStatus::Active,
            assurance: None,
            hops: Vec::new(),
        };
        assert_eq!(describe_status(&active), "current");

        let superseded = TransitionResult {
            current_did: "did:wba:host:b".to_string(),
            status: TransitionStatus::Superseded,
            ..active
        };
        assert_eq!(
            describe_status(&superseded),
            "SUPERSEDED — the chain walks on to did:wba:host:b"
        );
    }

    const OLD: &str = "did:wba:host.example:user:alice:e1_old";
    const NEW: &str = "did:wba:host.example:user:alice:e1_new";

    #[test]
    fn a_verified_successor_is_named_and_the_retry_is_spelled_out() {
        // The point of the walk: the caller does not get the peer's hint, it gets the DID the
        // chain actually ends at, plus the one command that retries correctly.
        let text = superseded_refusal_text(
            OLD,
            None,
            &Supersession::Verified {
                successor: NEW.to_string(),
            },
        );
        assert!(text.contains("the chain verifies"));
        assert!(text.contains(NEW));
        assert!(text.contains(&format!("agentx-cli msg send --to {NEW}")));
        assert!(text.contains("rebuild and re-sign"));
    }

    #[test]
    fn a_hint_that_agrees_with_the_walk_is_not_quoted_back() {
        // Printing an agreeing hint would give an unverified claim the same standing as the
        // walk. It is only worth a line when it says something else.
        let text = superseded_refusal_text(
            OLD,
            Some(NEW),
            &Supersession::Verified {
                successor: NEW.to_string(),
            },
        );
        assert!(!text.contains("hint"));
    }

    #[test]
    fn a_hint_that_disagrees_with_the_walk_is_called_out() {
        // A peer naming a successor the chain does not confirm is exactly the case the spec's
        // "MUST verify" is about, so the disagreement is the most important thing in the message.
        let text = superseded_refusal_text(
            OLD,
            Some("did:wba:elsewhere.example:user:alice:e1_wrong"),
            &Supersession::Verified {
                successor: NEW.to_string(),
            },
        );
        assert!(text.contains("did:wba:elsewhere.example:user:alice:e1_wrong"));
        assert!(text.contains("is unverified"));
        assert!(text.contains(NEW));
    }

    #[test]
    fn a_claim_the_chain_does_not_confirm_says_nothing_was_retried() {
        // The peer said "superseded" and the walk says otherwise. Saying so is the whole job:
        // silently retrying would be acting on the claim this arm just failed to confirm.
        let text = superseded_refusal_text(OLD, Some(NEW), &Supersession::StillCurrent);
        assert!(text.contains("does NOT verify"));
        assert!(text.contains("Nothing was retried"));
        assert!(text.contains(&format!("did resolve --chain {OLD}")));
    }

    #[test]
    fn a_broken_chain_is_reported_as_a_verdict_not_a_failure_to_reach_the_peer() {
        let text = superseded_refusal_text(
            OLD,
            None,
            &Supersession::Broken {
                kind: "invalid_proof".to_string(),
                message: "the hop's proof does not verify".to_string(),
            },
        );
        assert!(text.contains("invalid_proof"));
        assert!(text.contains("the hop's proof does not verify"));
        assert!(text.contains("nothing was retried"));
    }

    #[test]
    fn an_unfetched_chain_says_the_claim_was_never_confirmed() {
        // Network failure, not a verdict: the message must not read as "the peer lied", and it
        // must say the retry is waiting on a verification that has not happened.
        let text = superseded_refusal_text(
            OLD,
            Some(NEW),
            &Supersession::Unfetched {
                reason: "connection refused".to_string(),
            },
        );
        assert!(text.contains("connection refused"));
        assert!(text.contains("could not be fetched to verify"));
        assert!(text.contains("Nothing was retried"));
    }
}
