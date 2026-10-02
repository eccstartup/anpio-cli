//! The one HTTP client every ANP exchange goes through.
//!
//! It exists for the sake of a single setting: **redirects are off**. Every hop this client
//! makes is checked against the network policy before it leaves ([`super::resolve`]), and
//! that check is only worth anything if the hop it approved is the hop that happens. A 3xx
//! would let the peer move the request to a host the policy never saw — and for a message
//! POST, the request being moved is signed.

use crate::error::{AgentxError, Result};

/// A client that does not follow redirects. A 3xx is an error rather than a hop.
pub fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| AgentxError::MessageSendFailed(format!("building the HTTP client: {err}")))
}
