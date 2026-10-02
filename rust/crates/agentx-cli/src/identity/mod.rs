//! The client's identity — its keys, the DID document that publishes them, and the
//! store directory they live in.
//!
//! This is the first thing the client needs that the `anp` crate does not have: the crate
//! mints a document in memory, and everything after that — where it is kept, how it is
//! published, which device it names — is the application's (TODO5 §2, §6 Phase 1).

mod chain;
mod did;
mod host;
mod store;

pub use chain::{
    describe_status, document_is_superseded, resolve_chain, snake_case_name, ChainError, ChainResolution,
};
pub use did::{create_identity, CreateIdentityInput};
pub use host::{fetch_host_service, register_identity, HostService};
pub use store::{
    assert_segment, current_agent_path, list_identities, read_current_agent, resolve_agent_id,
    resolve_agent_id_with_source, resolve_profile_name, select_current_agent, store_root, AgentSource, Identity,
    IdentityLocation, StoredIdentitySummary, StoredKeyPair, AGENT_ENV, HOME_ENV, PROFILE_ENV,
};
