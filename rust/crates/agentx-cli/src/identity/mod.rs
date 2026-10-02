//! The client's identity — its keys, the DID document that publishes them, and the
//! store directory they live in.
//!
//! This is the first thing the client needs that the `anp` crate does not have: the crate
//! mints a document in memory, and everything after that — where it is kept, how it is
//! published, which device it names — is the application's (TODO5 §2, §6 Phase 1).

mod did;
mod host;
mod store;

pub use did::{create_identity, CreateIdentityInput};
pub use host::{fetch_host_service, register_identity, HostService};
pub use store::{store_root, Identity, IdentityLocation, StoredKeyPair, HOME_ENV};
