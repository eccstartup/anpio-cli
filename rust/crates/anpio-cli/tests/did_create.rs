//! `did create` against a fake host: the one-command flow, its failure paths, and the
//! pending key that survives them.
//!
//! The fake host is a few dozen lines of `std::net` rather than a service, because what
//! the command is judged on is the *shape of the conversation* — which calls it makes, in
//! which order, and what it leaves on disk when one of them fails.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};

// ---------------------------------------------------------------------------------------
// The fake host
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Decision {
    Register,
    Existing,
    Unavailable,
}

#[derive(Clone)]
struct Config {
    /// `None` is a host that never had the precheck route (404).
    decision: Option<Decision>,
    /// How many `email-status` polls answer `false` before it flips. `None` never flips.
    verify_after_polls: Option<usize>,
    register_ok: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            decision: Some(Decision::Register),
            verify_after_polls: Some(0),
            register_ok: true,
        }
    }
}

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    body: String,
}

struct State {
    config: Config,
    polls: usize,
    requests: Vec<Recorded>,
}

struct FakeHost {
    base: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeHost {
    fn start(config: Config) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a fake host");
        let port = listener.local_addr().expect("the fake host's address").port();
        listener.set_nonblocking(true).expect("nonblocking accept");
        let state = Arc::new(Mutex::new(State {
            config,
            polls: 0,
            requests: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let served = state.clone();
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, port, &served),
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base: format!("http://127.0.0.1:{port}"),
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn set_register_ok(&self, ok: bool) {
        self.state.lock().unwrap().config.register_ok = ok;
    }

    fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for FakeHost {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: std::net::TcpStream, port: u16, state: &Arc<Mutex<State>>) {
    // macOS lets an accepted socket inherit the listener's non-blocking flag, and a
    // `WouldBlock` on the first read would close the connection before the request lands.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let (body_at, content_length) = loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(at) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..at]).into_owned();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    break (at + 4, length);
                }
            }
        }
    };
    while buf.len() < body_at + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }

    let head = String::from_utf8_lossy(&buf[..body_at]).into_owned();
    let body = String::from_utf8_lossy(&buf[body_at..]).into_owned();
    let mut line = head.lines().next().unwrap_or("").split_whitespace();
    let method = line.next().unwrap_or("").to_string();
    let path = line
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .to_string();

    let (status, payload) = {
        let mut state = state.lock().unwrap();
        state.requests.push(Recorded {
            method: method.clone(),
            path: path.clone(),
            body: body.clone(),
        });
        route(&method, &path, &mut state, port)
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

fn route(method: &str, path: &str, state: &mut State, port: u16) -> (u16, String) {
    match (method, path) {
        ("GET", "/.well-known/did.json") => (
            200,
            json!({
                "id": format!("did:wba:127.0.0.1%3A{port}"),
                "service": [{
                    "id": "#anp-message",
                    "type": "ANPMessageService",
                    "serviceEndpoint": format!("http://127.0.0.1:{port}/anp-im/rpc"),
                }],
            })
            .to_string(),
        ),
        ("POST", "/user-service/v1/handle/rpc") => match state.config.decision {
            None => (404, "{}".to_string()),
            Some(decision) => {
                let decision = match decision {
                    Decision::Register => "register",
                    Decision::Existing => "existing",
                    Decision::Unavailable => "unavailable",
                };
                (
                    200,
                    json!({
                        "jsonrpc": "2.0",
                        "id": "registration-check",
                        "result": {"decision": decision, "full_handle": "mybot.example"},
                    })
                    .to_string(),
                )
            }
        },
        ("GET", "/user-service/v1/auth/email-status") => {
            state.polls += 1;
            let verified = state
                .config
                .verify_after_polls
                .is_some_and(|after| state.polls > after);
            (200, json!({"verified": verified}).to_string())
        }
        ("POST", "/user-service/v1/auth/email-send") => (200, "{}".to_string()),
        ("POST", "/user-service/v1/did-auth/rpc") => {
            if state.config.register_ok {
                (
                    200,
                    json!({
                        "jsonrpc": "2.0",
                        "id": "anpio-cli-register",
                        "result": {"access_token": "fake-token", "token_type": "Bearer"},
                    })
                    .to_string(),
                )
            } else {
                (
                    409,
                    json!({
                        "jsonrpc": "2.0",
                        "id": "anpio-cli-register",
                        "error": {
                            "code": -32001,
                            "message": "handle is already taken",
                            "data": {"type": "handle_taken"},
                        },
                    })
                    .to_string(),
                )
            }
        }
        _ => (404, "{}".to_string()),
    }
}

// ---------------------------------------------------------------------------------------
// The binary and its store
// ---------------------------------------------------------------------------------------

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "anpio-cli-create-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temp store root");
        Self(path)
    }

    fn pending(&self) -> PathBuf {
        self.0.join("pending.json")
    }

    fn identity(&self, agent: &str) -> PathBuf {
        self.0.join(agent).join("default").join("identity.json")
    }

    fn entries(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, found);
                } else {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(&self.0, &mut found);
        found
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(home: &Home, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_anpio-cli"))
        .args(args)
        .env("ANPIOCLI_HOME", &home.0)
        .env_remove("ANPIOCLI_AGENT")
        .env_remove("ANPIOCLI_PROFILE")
        .output()
        .expect("the binary under test runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn stdout(out: &Output) -> String {
    text(&out.stdout)
}

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn paths(requests: &[Recorded]) -> Vec<String> {
    requests.iter().map(|r| r.path.clone()).collect()
}

// ---------------------------------------------------------------------------------------
// The one-command flow
// ---------------------------------------------------------------------------------------

/// The whole golden path: five stages, one identity, no pending key left over.
#[test]
fn create_registers_and_writes_the_identity() {
    let host = FakeHost::start(Config::default());
    let home = Home::new("golden");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--email",
            "You@Example.com",
        ],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));

    let printed = stdout(&out);
    for stage in ["[1/5]", "[2/5]", "[3/5]", "[4/5]", "[5/5]"] {
        assert!(printed.contains(stage), "no {stage} line:\n{printed}");
    }
    assert!(printed.contains("available"), "{printed}");
    assert!(printed.contains("email already verified"), "{printed}");
    assert!(printed.contains("signer: local key ("), "{printed}");
    assert!(printed.contains("0600 file"), "the boundary note is unconditional:\n{printed}");

    let identity = read_json(&home.identity("mybot"));
    let did = identity["did"].as_str().expect("a DID");
    assert!(did.starts_with("did:wba:127.0.0.1%3A"), "{did}");
    assert!(did.contains(":user:mybot:e1_"), "{did}");
    assert!(printed.contains(did), "the printed DID is the stored one:\n{printed}");
    assert!(identity["keys"]["key-1"]["private_key_pem"].is_string(), "line 1 stores its key");
    assert_eq!(identity["handle"], "mybot");

    assert!(!home.pending().exists(), "a registered identity leaves no pending key");

    // The address is normalized before it goes out, and an already-verified one is not
    // sent another email.
    let requests = host.requests();
    let sent = requests
        .iter()
        .find(|request| request.path == "/user-service/v1/auth/email-status")
        .expect("the status is checked before registering");
    assert!(sent.body.is_empty(), "status is a GET");
    assert!(
        !paths(&requests).contains(&"/user-service/v1/auth/email-send".to_string()),
        "a verified address gets no second email: {:?}",
        paths(&requests)
    );
    let register = requests
        .iter()
        .find(|request| request.path == "/user-service/v1/did-auth/rpc")
        .expect("register is called");
    let body: Value = serde_json::from_str(&register.body).expect("register is JSON");
    assert_eq!(body["method"], "register");
    assert_eq!(body["params"]["handle"], "mybot");
    assert_eq!(body["params"]["email"], "you@example.com");
    assert!(body["params"]["did_document"].is_object());
}

/// A bare domain is read as `https://`, and a host without the precheck route says so
/// instead of pretending the name was checked.
#[test]
fn a_host_without_the_precheck_still_registers() {
    let host = FakeHost::start(Config {
        decision: None,
        ..Config::default()
    });
    let home = Home::new("no-precheck");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--no-email",
        ],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert!(stdout(&out).contains("skipped (no precheck)"), "{}", stdout(&out));
    assert!(home.identity("mybot").exists());
    assert!(paths(&host.requests()).contains(&"/user-service/v1/did-auth/rpc".to_string()));
}

/// An unavailable handle is refused before a key exists: nothing at all is written.
#[test]
fn an_unavailable_handle_writes_nothing() {
    let host = FakeHost::start(Config {
        decision: Some(Decision::Unavailable),
        ..Config::default()
    });
    let home = Home::new("unavailable");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--email",
            "you@example.com",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = stderr(&out);
    assert!(err.contains("is not available on"), "{err}");
    assert!(err.contains("no key was minted"), "{err}");
    assert!(err.contains("--handle <another-name>"), "the retry is spelled out:\n{err}");
    assert!(!err.contains("--reuse-key"), "there is no key to reuse yet:\n{err}");
    assert!(
        home.entries().is_empty(),
        "a refused handle left files: {:?}",
        home.entries()
    );
    assert!(
        !paths(&host.requests()).contains(&"/user-service/v1/did-auth/rpc".to_string()),
        "nothing was registered: {:?}",
        paths(&host.requests())
    );
}

/// `existing` proceeds to register: it may be this very DID, registered by a request
/// whose reply was lost, and only the registration itself can tell.
#[test]
fn an_existing_handle_still_registers() {
    let host = FakeHost::start(Config {
        decision: Some(Decision::Existing),
        ..Config::default()
    });
    let home = Home::new("existing");

    let out = run(
        &home,
        &["did", "create", "--host", &host.base, "--handle", "mybot", "--no-email"],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert!(stdout(&out).contains("already registered"), "{}", stdout(&out));
    assert!(home.identity("mybot").exists());
}

/// A host refusal keeps the key: the retry with another name reuses it, and the DID's
/// fingerprint — the part the key decides — does not move.
#[test]
fn a_taken_handle_keeps_the_key_and_reuse_registers_it() {
    let host = FakeHost::start(Config {
        register_ok: false,
        ..Config::default()
    });
    let home = Home::new("reuse");

    let first = run(
        &home,
        &["did", "create", "--host", &host.base, "--handle", "mybot", "--no-email"],
    );
    assert_eq!(first.status.code(), Some(1));
    assert!(stderr(&first).contains("the key is kept"), "{}", stderr(&first));
    assert!(!home.identity("mybot").exists(), "a failed registration writes no identity");

    let pending = read_json(&home.pending());
    let key = pending["keys"]["key-1"]["private_key_pem"]
        .as_str()
        .expect("the pending key")
        .to_string();
    let failed_did = pending["did"].as_str().expect("a DID").to_string();

    host.set_register_ok(true);
    let second = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot2",
            "--no-email",
            "--reuse-key",
        ],
    );
    assert!(second.status.success(), "stderr:\n{}", stderr(&second));
    assert!(stdout(&second).contains("Reusing the pending key"), "{}", stdout(&second));

    let identity = read_json(&home.identity("mybot2"));
    assert_eq!(
        identity["keys"]["key-1"]["private_key_pem"].as_str(),
        Some(key.as_str()),
        "the same key, not a fresh one"
    );
    let did = identity["did"].as_str().expect("a DID");
    assert!(did.contains(":user:mybot2:"), "{did}");
    let fingerprint = |did: &str| did.rsplit(":e1_").next().map(str::to_string);
    assert_eq!(
        fingerprint(did),
        fingerprint(&failed_did),
        "the fingerprint is the key's, so it moves with the name only"
    );
    assert!(!home.pending().exists(), "a registered identity leaves no pending key");
}

/// `--reuse-key` with nothing to reuse says where it looked and mints nothing.
#[test]
fn reuse_without_a_pending_key_mints_nothing() {
    let host = FakeHost::start(Config::default());
    let home = Home::new("nothing-to-reuse");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--no-email",
            "--reuse-key",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("pending.json"), "{}", stderr(&out));
    assert!(home.entries().is_empty(), "{:?}", home.entries());
}

/// `--no-wait` sends the email, keeps the key, and registers nothing yet.
#[test]
fn no_wait_sends_the_email_and_stops() {
    let host = FakeHost::start(Config {
        verify_after_polls: None,
        ..Config::default()
    });
    let home = Home::new("no-wait");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--email",
            "you@example.com",
            "--no-wait",
        ],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert!(stdout(&out).contains("verification email sent to you@example.com"));
    assert!(stdout(&out).contains("did register"), "the resume is named:\n{}", stdout(&out));
    assert!(home.pending().exists(), "the key waits for the verification");
    assert!(!home.identity("mybot").exists());
    assert!(paths(&host.requests()).contains(&"/user-service/v1/auth/email-send".to_string()));
    assert!(!paths(&host.requests()).contains(&"/user-service/v1/did-auth/rpc".to_string()));
}

/// The email round trip waits and then registers.
#[test]
fn the_email_round_trip_waits_and_registers() {
    let host = FakeHost::start(Config {
        verify_after_polls: Some(1),
        ..Config::default()
    });
    let home = Home::new("email-wait");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--email",
            "you@example.com",
        ],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    let printed = stdout(&out);
    assert!(printed.contains("verification email sent"), "{printed}");
    assert!(printed.contains("waiting for verification"), "{printed}");
    assert!(printed.contains("email verified"), "{printed}");
    assert!(home.identity("mybot").exists());
    assert!(!home.pending().exists());
}

/// `did register` completes a create that stopped on the email: it reads the pending key
/// and only then writes the identity.
#[tokio::test]
async fn did_register_finishes_a_pending_create() {
    let host = FakeHost::start(Config {
        verify_after_polls: None,
        ..Config::default()
    });
    let home = Home::new("register-pending");

    let out = run(
        &home,
        &[
            "did",
            "create",
            "--host",
            &host.base,
            "--handle",
            "mybot",
            "--email",
            "you@example.com",
            "--no-wait",
        ],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert!(home.pending().exists());

    let out = run(
        &home,
        &["did", "register", "--agent", "mybot", "--email", "you@example.com"],
    );
    assert!(out.status.success(), "stderr:\n{}", stderr(&out));
    assert!(home.identity("mybot").exists());
    assert!(!home.pending().exists());
}

/// A timeout is a reported timeout, not an error and not a success.
#[tokio::test]
async fn waiting_for_email_times_out_without_being_an_error() {
    let host = FakeHost::start(Config {
        verify_after_polls: None,
        ..Config::default()
    });
    let base = reqwest::Url::parse(&host.base).expect("a URL");
    let verified = anpio_cli::identity::wait_for_email(
        &reqwest::Client::new(),
        &base,
        "you@example.com",
        "mybot.example",
        Duration::from_millis(0),
        Duration::from_millis(10),
    )
    .await
    .expect("polling an answering host is not an error");
    assert!(!verified);
}

/// The precheck sends the shape the host's contract names.
#[tokio::test]
async fn the_precheck_sends_the_contract_shape() {
    let host = FakeHost::start(Config::default());
    let base = reqwest::Url::parse(&host.base).expect("a URL");
    let check = anpio_cli::identity::check_handle(
        &reqwest::Client::new(),
        &base,
        "mybot",
        "example",
    )
    .await
    .expect("the fake host answers")
    .expect("the fake host has the route");
    assert_eq!(check.decision, anpio_cli::identity::HandleDecision::Register);
    assert_eq!(check.full_handle.as_deref(), Some("mybot.example"));

    let request = host
        .requests()
        .into_iter()
        .find(|request| request.path == "/user-service/v1/handle/rpc")
        .expect("the precheck call");
    let body: Value = serde_json::from_str(&request.body).expect("JSON-RPC");
    assert_eq!(request.method, "POST");
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], "registration-check");
    assert_eq!(body["method"], "registration_check");
    assert_eq!(
        body["params"],
        json!({"handle": "mybot", "domain": "example", "check_invite": false})
    );
}
