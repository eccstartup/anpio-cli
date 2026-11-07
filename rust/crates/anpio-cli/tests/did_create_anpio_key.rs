//! `did create --key anpio-key`: the CLI asks anpio-key for a key, asks it to proof the
//! document, and records the name — never the key.
//!
//! The daemon here is a shell script, because what this line is judged on is the
//! conversation with the daemon: which subcommands are called, with which arguments, and
//! what the identity left behind says. The script logs every invocation; the tests read
//! that log instead of trusting the CLI's own summary.
//!
//! `--key anpio-key` refuses without a controlling terminal, by design. The tests that
//! reach the daemon run the binary under `script(1)`, which gives it a pty; when `script`
//! is unavailable they say so and skip rather than pretending the path passed.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Value};

/// The RFC 8032 test vector's public key, as `ed25519_public_key` reads it.
const PUBLIC_MULTIBASE: &str = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";

// ---------------------------------------------------------------------------------------
// The fake host
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    body: String,
}

struct FakeHost {
    base: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeHost {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a fake host");
        let port = listener.local_addr().expect("the fake host's address").port();
        listener.set_nonblocking(true).expect("nonblocking accept");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let recorded = requests.clone();
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => serve(stream, port, &recorded),
                    Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            // A hostname, not an IP literal: the E1 single-key document builder refuses an
            // IP authority, and a real host is a hostname anyway.
            base: format!("http://localhost:{port}"),
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    fn register_body(&self) -> Value {
        let requests = self.requests();
        let register = requests
            .iter()
            .find(|request| {
                request.method == "POST" && request.path == "/user-service/v1/did-auth/rpc"
            })
            .expect("register is called");
        serde_json::from_str(&register.body).expect("register is JSON")
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

fn serve(mut stream: std::net::TcpStream, port: u16, requests: &Arc<Mutex<Vec<Recorded>>>) {
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

    let payload = {
        requests.lock().unwrap().push(Recorded {
            method: method.clone(),
            path: path.clone(),
            body: body.clone(),
        });
        route(&method, &path, port)
    };

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        200,
        payload.len(),
        payload
    );
    let _ = stream.write_all(response.as_bytes());
}

fn route(method: &str, path: &str, port: u16) -> String {
    match (method, path) {
        ("GET", "/.well-known/did.json") => json!({
            "id": format!("did:wba:localhost%3A{port}"),
            "service": [{
                "id": "#anp-message",
                "type": "ANPMessageService",
                "serviceEndpoint": format!("http://localhost:{port}/anp-im/rpc"),
            }],
        })
        .to_string(),
        ("POST", "/user-service/v1/handle/rpc") => json!({
            "jsonrpc": "2.0",
            "id": "registration-check",
            "result": {"decision": "register", "full_handle": "mybot.example"},
        })
        .to_string(),
        ("GET", "/user-service/v1/auth/email-status") => json!({"verified": true}).to_string(),
        ("POST", "/user-service/v1/did-auth/rpc") => json!({
            "jsonrpc": "2.0",
            "id": "anpio-cli-register",
            "result": {"access_token": "fake-token", "token_type": "Bearer"},
        })
        .to_string(),
        _ => "{}".to_string(),
    }
}

// ---------------------------------------------------------------------------------------
// The fake anpio-key
// ---------------------------------------------------------------------------------------

/// The script `$ANPIOCLI_ANPIO_KEY` names. It logs every call and answers the four
/// subcommands this line uses. `$2`'s placeholder is the key's fingerprint, which the
/// tests know only once the CLI has derived a DID from the public key.
const FAKE_ANPIO_KEY: &str = r#"#!/bin/sh
log="$ANPIOCLI_TEST_ANPIO_KEY_LOG"
printf '%s\n' "$*" >> "$log"
if [ "$1" = "--root" ]; then shift 2; fi
case "$1" in
  key)
    case "$2" in
      create)
        printf '%s\n' '{"name":"k-test","thumbprint":"e1_test","public_multibase":"__MULTIBASE__","algorithm":"Ed25519"}'
        ;;
      list)
        printf '%s\n' '[{"name":"k-test","did":"","kid":"","thumbprint":"e1_test","algorithm":"Ed25519","state":"unlocked"}]'
        ;;
      sign-document)
        shift 2
        document=""; out=""
        while [ $# -gt 0 ]; do
          case "$1" in
            --document) document="$2"; shift 2 ;;
            --out) out="$2"; shift 2 ;;
            *) shift ;;
          esac
        done
        body=$(cat "$document")
        printf 'DOC %s\n' "$body" >> "$log"
        printf '%s' "${body%\}},\"proof\":{\"type\":\"FakeSignature2020\"}}" > "$out"
        ;;
      *) exit 64 ;;
    esac
    ;;
  sign)
    keyid=""
    shift 1
    while [ $# -gt 0 ]; do
      case "$1" in
        --keyid) keyid="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '%s\n' "Signature-Input: sig1=(\"@target-uri\");keyid=\"$keyid\""
    printf '%s\n' 'Signature: sig1=:ZmFrZQ==:'
    ;;
  *) exit 64 ;;
esac
"#;

struct FakeKey {
    path: PathBuf,
    log: PathBuf,
}

impl FakeKey {
    fn new(dir: &Path, name: &str) -> Self {
        let path = dir.join(format!("anpio-key-{name}"));
        let log = dir.join(format!("anpio-key-{name}.log"));
        let script = FAKE_ANPIO_KEY.replace("__MULTIBASE__", PUBLIC_MULTIBASE);
        fs::write(&path, script).expect("write the fake anpio-key");
        let mut permissions = fs::metadata(&path).expect("stat the fake anpio-key").permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
        }
        let _ = permissions;
        fs::set_permissions(&path, permissions).expect("make the fake anpio-key executable");
        Self { path, log }
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with("DOC "))
            .map(str::to_string)
            .collect()
    }

    fn documents(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("DOC ").map(str::to_string))
            .collect()
    }
}

// ---------------------------------------------------------------------------------------
// The binary and its store
// ---------------------------------------------------------------------------------------

struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "anpio-cli-named-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temp store root");
        Self(path)
    }

    fn identity(&self, agent: &str) -> PathBuf {
        self.0.join(agent).join("default").join("identity.json")
    }

    fn pending(&self) -> PathBuf {
        self.0.join("pending.json")
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn base_command(home: &Home, key: &FakeKey) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_anpio-cli"));
    command
        .env("ANPIOCLI_HOME", &home.0)
        .env("ANPIOCLI_ANPIO_KEY", &key.path)
        .env("ANPIOCLI_TEST_ANPIO_KEY_LOG", &key.log)
        .env_remove("ANPIOCLI_AGENT")
        .env_remove("ANPIOCLI_PROFILE");
    command
}

fn run(home: &Home, key: &FakeKey, args: &[&str]) -> Output {
    base_command(home, key)
        .args(args)
        .output()
        .expect("the binary under test runs")
}

/// Run a command with a controlling terminal, so the interactive refusal does not fire.
///
/// `script(1)` is the only pty available without a dependency; where it is missing the
/// caller gets `None` and the test says it skipped.
fn run_with_a_terminal(home: &Home, key: &FakeKey, args: &[&str]) -> Option<Output> {
    let mut runner = if cfg!(target_os = "macos") {
        let mut runner = Command::new("script");
        runner
            .arg("-q")
            .arg("/dev/null")
            .arg(env!("CARGO_BIN_EXE_anpio-cli"))
            .args(args)
            .env("ANPIOCLI_HOME", &home.0)
            .env("ANPIOCLI_ANPIO_KEY", &key.path)
            .env("ANPIOCLI_TEST_ANPIO_KEY_LOG", &key.log)
            .env_remove("ANPIOCLI_AGENT")
            .env_remove("ANPIOCLI_PROFILE");
        runner
    } else {
        // util-linux: the command goes in `-c`, after which the file name follows.
        let quoted = std::iter::once(env!("CARGO_BIN_EXE_anpio-cli"))
            .chain(args.iter().copied())
            .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
            .collect::<Vec<_>>()
            .join(" ");
        let mut runner = Command::new("script");
        runner
            .arg("-q")
            .arg("-e")
            .arg("-c")
            .arg(quoted)
            .arg("/dev/null")
            .env("ANPIOCLI_HOME", &home.0)
            .env("ANPIOCLI_ANPIO_KEY", &key.path)
            .env("ANPIOCLI_TEST_ANPIO_KEY_LOG", &key.log)
            .env_remove("ANPIOCLI_AGENT")
            .env_remove("ANPIOCLI_PROFILE");
        runner
    };

    match runner.stdin(Stdio::null()).output() {
        Ok(output) => Some(output),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: script(1) is not installed, so there is no pty");
            None
        }
        Err(err) => panic!("script(1): {err}"),
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn create_args<'a>(base: &'a str) -> Vec<&'a str> {
    vec![
        "did",
        "create",
        "--host",
        base,
        "--handle",
        "mybot",
        "--email",
        "you@example.com",
        "--key",
        "anpio-key",
    ]
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

/// The whole line-2 golden path: the key name comes back from anpio-key, the document is
/// proofed there, and the store keeps no private bytes.
#[test]
fn a_named_key_create_records_the_name_and_no_private_bytes() {
    let host = FakeHost::start();
    let home = Home::new("named-golden");
    let key = FakeKey::new(&home.0, "keys");

    let Some(out) = run_with_a_terminal(&home, &key, &create_args(&host.base)) else {
        return;
    };
    let printed = text(&out.stdout) + &text(&out.stderr);
    assert!(out.status.success(), "{printed}");

    for stage in ["[1/5]", "[2/5]", "[3/5]", "[4/5]", "[5/5]"] {
        assert!(printed.contains(stage), "no {stage} line:\n{printed}");
    }
    assert!(printed.contains("k-test"), "the key name is printed:\n{printed}");
    assert!(
        printed.contains("signer: anpio-key (key k-test, grant none)"),
        "{printed}"
    );
    // The grant is a separate administrator step, and the command says so where a person
    // will act on it.
    assert!(printed.contains("anpio-key grant create --key k-test"), "{printed}");
    assert!(
        printed.contains("anpio-cli key grant <grant-id> --agent mybot"),
        "the handoff names the agent the identity landed under:\n{printed}"
    );

    let identity = read_json(&home.identity("mybot"));
    let did = identity["did"].as_str().expect("a DID").to_string();
    assert!(did.ends_with(&identity_fingerprint(&identity["did_document"])), "{did}");
    assert_eq!(identity["custody"]["kind"], "anpio-key");
    assert_eq!(identity["custody"]["name"], "k-test");
    assert!(
        identity["custody"]["grant"].is_null(),
        "a grant is only written by `key grant`: {}",
        identity["custody"]
    );
    assert!(
        identity["keys"].as_object().map(|keys| keys.is_empty()).unwrap_or(false),
        "line 2 stores no keys: {}",
        identity["keys"]
    );

    // The acceptance assertion from the plan: nothing in the store can be a private key.
    for entry in store_files(&home.0) {
        let bytes = fs::read(&entry).expect("read a store file");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("PRIVATE KEY") && !text.contains("private_key_pem"),
            "{} holds private key material",
            entry.display()
        );
    }

    // The document the CLI built is the one anpio-key proofed, and the one that was
    // registered. The daemon's proof is carried through; the CLI does not replace it.
    let documents = key.documents();
    assert_eq!(documents.len(), 1, "one document is proofed: {documents:?}");
    let submitted: Value = serde_json::from_str(&documents[0]).expect("the submitted document");
    assert_eq!(submitted["id"], did);
    assert_eq!(submitted["verificationMethod"][0]["publicKeyMultibase"], PUBLIC_MULTIBASE);
    assert_eq!(identity["did_document"]["proof"]["type"], "FakeSignature2020");

    let register = host.register_body();
    assert_eq!(register["params"]["did_document"]["proof"]["type"], "FakeSignature2020");
    assert_eq!(register["params"]["did_document"]["id"], did);

    // Exactly two conversations with the daemon, in this order: mint, then proof.
    let calls = key.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert_eq!(calls[0], "key create --json");
    assert!(
        calls[1].starts_with(&format!("key sign-document --name k-test --keyid {did}#key-1")),
        "{}",
        calls[1]
    );
    assert!(!home.pending().exists(), "a registered identity leaves no pending key");

    // Re-registering uses the document the daemon proofed, not a lookup by DID — a named
    // key has none to look up.
    let again = run(&home, &key, &["did", "register", "--agent", "mybot"]);
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert_eq!(key.calls().len(), 2, "the daemon is not asked for a document: {:?}", key.calls());
}

/// Without a controlling terminal the command refuses before anything is touched, and it
/// does not quietly mint a local key instead.
#[test]
fn a_named_key_create_refuses_without_a_terminal() {
    let host = FakeHost::start();
    let home = Home::new("named-no-tty");
    let key = FakeKey::new(&home.0, "keys");

    let out = base_command(&home, &key)
        .args(create_args(&host.base))
        .stdin(Stdio::null())
        .output()
        .expect("the binary under test runs");
    assert!(!out.status.success(), "{}", text(&out.stdout));
    let printed = text(&out.stderr);
    assert!(printed.contains("interactive shell"), "{printed}");
    assert!(printed.contains("will not switch to one"), "{printed}");

    assert!(key.calls().is_empty(), "the daemon is never asked: {:?}", key.calls());
    assert!(host.requests().is_empty(), "the host is never asked");
    assert!(!home.pending().exists());
    assert!(!home.identity("mybot").exists());
}

/// `key grant <id>` is the one-time handoff: the grant lands beside the key name, and
/// `did show` says both on its first line.
#[test]
fn a_grant_is_written_once_and_shown_first() {
    let host = FakeHost::start();
    let home = Home::new("named-grant");
    let key = FakeKey::new(&home.0, "keys");

    let Some(out) = run_with_a_terminal(&home, &key, &create_args(&host.base)) else {
        return;
    };
    assert!(out.status.success(), "{}", text(&out.stderr));

    let grant = run(&home, &key, &["key", "grant", "g-7f3a", "--agent", "mybot"]);
    assert!(grant.status.success(), "{}", text(&grant.stderr));

    let identity = read_json(&home.identity("mybot"));
    assert_eq!(identity["custody"]["grant"], "g-7f3a");
    assert_eq!(
        identity["custody"]["config"],
        "/etc/anpio-key/service.json",
        "the grant records the surface it was issued on"
    );

    let show = run(&home, &key, &["did", "show", "--agent", "mybot"]);
    assert!(show.status.success(), "{}", text(&show.stderr));
    let first = text(&show.stdout).lines().next().unwrap_or_default().to_string();
    assert_eq!(
        first.trim(),
        "key:        anpio-key (key k-test, grant g-7f3a)",
        "the first line says where the key is and who authorizes it"
    );
}

/// The named signing path: the daemon is told the key and the keyid, and never a DID.
#[test]
fn a_named_signature_names_the_key_and_the_keyid() {
    let host = FakeHost::start();
    let home = Home::new("named-sign");
    let key = FakeKey::new(&home.0, "keys");

    let Some(out) = run_with_a_terminal(&home, &key, &create_args(&host.base)) else {
        return;
    };
    assert!(out.status.success(), "{}", text(&out.stderr));
    let did = read_json(&home.identity("mybot"))["did"]
        .as_str()
        .expect("a DID")
        .to_string();

    let sign = run(
        &home,
        &key,
        &[
            "anp",
            "sign",
            "--target",
            "https://awiki.me/anp-im/rpc",
            "--agent",
            "mybot",
        ],
    );
    assert!(sign.status.success(), "{}", text(&sign.stderr));
    assert!(
        text(&sign.stderr).contains("signer: anpio-key (key k-test, grant none)"),
        "{}",
        text(&sign.stderr)
    );
    let signed: Value = serde_json::from_str(&text(&sign.stdout)).expect("the signed request");
    assert_eq!(signed["keyid"], format!("{did}#key-1"));
    assert_eq!(signed["headers"]["Signature-Input"], format!(
        "sig1=(\"@target-uri\");keyid=\"{did}#key-1\""
    ));

    let call = key
        .calls()
        .into_iter()
        .find(|call| call.starts_with("sign "))
        .expect("the daemon signs the request");
    assert!(call.starts_with(&format!("sign --key k-test --keyid {did}#key-1")), "{call}");
    assert!(call.contains("--url https://awiki.me/anp-im/rpc"), "{call}");
    assert!(!call.contains("--did"), "a named key signs without a DID: {call}");
}

/// `did attach` is the recovery entry; the old name is kept as an alias.
#[test]
fn attach_is_the_name_and_attach_anpio_key_still_works() {
    let home = Home::new("attach-help");
    let key = FakeKey::new(&home.0, "keys");

    let help = run(&home, &key, &["did", "attach", "--help"]);
    assert!(help.status.success(), "{}", text(&help.stderr));
    let printed = text(&help.stdout);
    assert!(printed.contains("--name"), "{printed}");
    assert!(
        printed.contains("--did"),
        "the DID is still required — a named key carries none: {printed}"
    );

    let alias = run(&home, &key, &["did", "attach-anpio-key", "--help"]);
    assert!(alias.status.success(), "the alias parses: {}", text(&alias.stderr));
    assert!(text(&alias.stdout).contains("--name"));
}

/// Attaching a name anpio-key does not hold is refused before the store or the network.
#[test]
fn attaching_an_unknown_name_writes_nothing() {
    let home = Home::new("attach-unknown");
    let key = FakeKey::new(&home.0, "keys");

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            "did:wba:example.com:user:alice:e1_abc",
            "--name",
            "nope",
            "--agent",
            "alice",
        ],
    );
    assert!(!out.status.success(), "{}", text(&out.stdout));
    let printed = text(&out.stderr);
    assert!(printed.contains("holds no key named nope"), "{printed}");
    assert!(!home.identity("alice").exists());
}

/// The fingerprint a DID is built on: its last segment.
fn identity_fingerprint(document: &Value) -> String {
    document["id"]
        .as_str()
        .and_then(|id| id.rsplit(':').next())
        .unwrap_or_default()
        .to_string()
}

fn store_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(dir, &mut found);
    found
}
