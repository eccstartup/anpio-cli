//! `agentx-cli` — an ANP client.
//!
//! This crate is the library half of the Rust client ([TODO5.md](../../../../TODO5.md)).
//! The binary in `main.rs` is a shell over it; everything with ongoing state or protocol
//! logic lives here (`docs/design/cli.md` §1: a command face does not own state).
//!
//! What the official `anp` crate gives us, and what it deliberately does not, was settled
//! by the Phase 0 spike (TODO5 §6): it reaches the MLS operations and the *signed request
//! object*, and stops there. The HTTP hop and this service's extension surface are ours.
//! That is what `message` is.

pub mod anp;
pub mod error;
pub mod group;
pub mod group_e2ee;
pub mod group_receive;
pub mod identity;
pub mod message;
pub mod mls;

pub use error::{AgentxError, Result};
