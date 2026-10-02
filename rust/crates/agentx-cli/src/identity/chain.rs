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
}
