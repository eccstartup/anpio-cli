//! The client's identity — its keys, the DID document that publishes them, and the
//! store directory they live in.
//!
//! This is the first thing the client needs that the `anp` crate does not have: the crate
//! mints a document in memory, and everything after that — where it is kept, how it is
//! published, which device it names — is the application's (TODO5 §2, §6 Phase 1).

mod chain;
mod did;
mod host;
mod session;
mod store;
mod update;

pub use chain::{
    describe_status, document_is_superseded, resolve_chain, snake_case_name, ChainError, ChainResolution,
};
pub use did::{create_identity, load_stored_key, retirement_document, subject_of, successor_of, CreateIdentityInput};
pub use host::{fetch_host_service, register_identity, HostService};
pub use session::{
    parse_ttl_seconds, save_session, session_host, SessionEntry, SessionFile, SessionWrite,
    DEFAULT_SESSION_TTL_SECONDS, SESSION_FILE,
};
pub use store::{
    assert_segment, current_agent_path, list_identities, read_current_agent, resolve_agent_id,
    resolve_agent_id_with_source, resolve_profile_name, select_current_agent, store_root, AgentSource, Identity,
    IdentityLocation, StoredIdentitySummary, StoredKeyPair, AGENT_ENV, HOME_ENV, PROFILE_ENV, SUCCESSOR_FILE,
};
pub use update::{deliver, Accepted, Hop, UpdateError};

/// The identity fixture other modules' tests build an identity from, without a store on
/// disk. It lives with the code that mints identities so a change to what an identity is
/// cannot leave the fixture describing yesterday's shape.
#[cfg(test)]
pub(crate) use did::test_support;
