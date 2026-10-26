//! HTTP transport shared by DID resolution and message requests.
//!
//! The connector uses exactly the addresses returned by the validating DNS
//! resolver; there is no second lookup between validation and connection.
use super::resolve::{assert_allowed_host, is_private_address, ResolvePolicy};
use crate::error::{AnpioError, Result};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{net::SocketAddr, sync::Arc, time::Duration};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

fn builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(REQUEST_TIMEOUT)
        // Proxies can resolve names independently and bypass address checks.
        .no_proxy()
}

pub fn http_client() -> Result<reqwest::Client> {
    builder().build().map_err(client_error)
}

fn client_error(err: reqwest::Error) -> AnpioError {
    AnpioError::MessageSendFailed(format!("building the HTTP client: {err}"))
}

struct PolicyResolver {
    policy: ResolvePolicy,
}

fn validate_addresses(
    host: &str,
    policy: &ResolvePolicy,
    addresses: Vec<SocketAddr>,
) -> std::io::Result<Addrs> {
    let private_allowed = policy
        .allow_private_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host));
    if addresses.is_empty()
        || (!private_allowed && addresses.iter().any(|a| is_private_address(a.ip())))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("DNS for {host} returned no addresses or a private/reserved address"),
        ));
    }
    Ok(Box::new(addresses.into_iter()))
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let policy = self.policy.clone();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            Ok(validate_addresses(&host, &policy, addresses)?)
        })
    }
}

/// The transport for one policy-controlled target. Caller-supplied Clients must
/// not introduce redirects, proxies, or unchecked DNS overrides. Public request
/// functions retain their Client argument for compatibility but use this client
/// for their controlled hops.
pub(crate) fn client_for_url(
    url: &reqwest::Url,
    policy: &ResolvePolicy,
    context: &str,
) -> Result<reqwest::Client> {
    assert_allowed_host(url, policy, context)?;
    builder()
        .dns_resolver(Arc::new(PolicyResolver {
            policy: policy.clone(),
        }))
        .build()
        .map_err(client_error)
}

/// Bound memory while reading, including chunked/error bodies. The request's
/// timeout remains active until the last chunk is read.
pub(crate) async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Result<String> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(AnpioError::ResponseTooLarge(format!(
            "response exceeds {limit} bytes"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| AnpioError::MessageSendFailed(err.to_string()))?
    {
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(AnpioError::ResponseTooLarge(format!(
                "response exceeds {limit} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_answers_cannot_hide_private_addresses_behind_a_name() {
        let mut policy = ResolvePolicy::default();
        for address in [
            "127.0.0.1:0",
            "10.0.0.1:0",
            "169.254.169.254:0",
            "[::1]:0",
            "[::ffff:127.0.0.1]:0",
        ] {
            assert!(
                validate_addresses("peer.example", &policy, vec![address.parse().unwrap()])
                    .is_err()
            );
        }
        assert!(validate_addresses("peer.example", &policy, vec![]).is_err());
        assert!(validate_addresses(
            "peer.example",
            &policy,
            vec!["8.8.8.8:0".parse().unwrap(), "10.0.0.1:0".parse().unwrap()]
        )
        .is_err());
        let public = vec!["8.8.8.8:0".parse().unwrap(), "1.1.1.1:0".parse().unwrap()];
        assert_eq!(
            validate_addresses("peer.example", &policy, public.clone())
                .unwrap()
                .collect::<Vec<_>>(),
            public
        );
        policy.allow_private_hosts.push("peer.example".into());
        assert!(
            validate_addresses("peer.example", &policy, vec!["10.0.0.1:0".parse().unwrap()])
                .is_ok()
        );
        assert!(validate_addresses(
            "other.example",
            &policy,
            vec!["10.0.0.1:0".parse().unwrap()]
        )
        .is_err());
    }

    fn serve_once(reply: Vec<u8>, stall: bool) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = [0; 4096];
            let _ = socket.read(&mut request);
            let _ = socket.write_all(&reply);
            if stall {
                std::thread::sleep(Duration::from_millis(300));
            }
        });
        (url, worker)
    }

    #[tokio::test]
    async fn bounds_chunked_bodies_without_waiting_for_eof() {
        for length in [16, 17] {
            let text = "x".repeat(length);
            let wire = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{length:x}\r\n{text}\r\n{}",
                if length == 16 { "0\r\n\r\n" } else { "" }
            );
            // The oversized peer never finishes its body. Overflow must win
            // over the later request timeout, rather than buffering to EOF.
            let (url, worker) = serve_once(wire.into_bytes(), length > 16);
            let response = builder()
                .build()
                .unwrap()
                .get(url)
                .timeout(Duration::from_millis(150))
                .send()
                .await
                .unwrap();
            let answer = read_bounded(response, 16).await;
            if length == 16 {
                assert_eq!(answer.unwrap(), text);
            } else {
                assert!(matches!(answer, Err(AnpioError::ResponseTooLarge(_))));
            }
            worker.join().unwrap();
        }
    }

    #[tokio::test]
    async fn body_timeout_remains_active_after_headers() {
        let (url, worker) = serve_once(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n".to_vec(),
            true,
        );
        let response = builder()
            .build()
            .unwrap()
            .get(url)
            .timeout(Duration::from_millis(100))
            .send()
            .await
            .unwrap();
        let answer = read_bounded(response, 16).await;
        assert!(matches!(answer, Err(AnpioError::MessageSendFailed(_))));
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn content_length_is_refused_before_reading_an_error_body() {
        let (url, worker) = serve_once(
            b"HTTP/1.1 500 Error\r\nContent-Length: 17\r\n\r\n".to_vec(),
            true,
        );
        let response = builder()
            .build()
            .unwrap()
            .get(url)
            .timeout(Duration::from_millis(150))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            read_bounded(response, 16).await,
            Err(AnpioError::ResponseTooLarge(_))
        ));
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn system_dns_to_loopback_requires_an_explicit_exemption() {
        let resolver = PolicyResolver {
            policy: ResolvePolicy::default(),
        };
        assert!(resolver
            .resolve("localhost".parse().unwrap())
            .await
            .is_err());
        let resolver = PolicyResolver {
            policy: ResolvePolicy {
                allow_private_hosts: vec!["localhost".into()],
                ..Default::default()
            },
        };
        let addresses = resolver
            .resolve("localhost".parse().unwrap())
            .await
            .unwrap()
            .collect::<Vec<_>>();
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| address.ip().is_loopback()));
    }

    #[tokio::test]
    async fn policy_controlled_rpc_enforces_its_own_transport_and_body_cap() {
        use super::super::{envelope::AnpRequest, rpc::post_message};
        // A caller's unchecked DNS overrides must not replace our resolver.
        let supplied = reqwest::Client::builder()
            .resolve("localhost", "8.8.8.8:80".parse().unwrap())
            .build()
            .unwrap();
        let size = MAX_RESPONSE_BYTES + 1;
        let mut wire = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size:x}\r\n")
            .into_bytes();
        wire.extend(std::iter::repeat_n(b'x', size));
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (url, worker) = serve_once(wire, false);
        let endpoint = url.replace("127.0.0.1", "localhost");
        let policy = ResolvePolicy {
            allowed_hosts: vec!["localhost".into()],
            allow_private_hosts: vec!["localhost".into()],
            allow_insecure_transport: vec!["localhost".into()],
        };
        let request: AnpRequest = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0", "id": "cap", "method": "get_capabilities", "params": {"meta": {"profile": "anp.core.binding.v1", "security_profile": "transport-protected"}, "body": {}}
        })).unwrap();
        assert!(matches!(
            post_message(&supplied, &endpoint, &request, &policy, "test").await,
            Err(AnpioError::ResponseTooLarge(_))
        ));
        worker.join().unwrap();
    }
}
