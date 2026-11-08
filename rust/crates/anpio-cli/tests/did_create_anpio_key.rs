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

use anpio_cli::custody::{ed25519_public_key, public_key_from_multibase};
use anpio_cli::identity::{build_external_identity, CreateIdentityInput};
use serde_json::{json, Value};

/// The RFC 8032 test vector's public key, as `ed25519_public_key` reads it.
const PUBLIC_MULTIBASE: &str = "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
/// A second Ed25519 key for the device signing role.
const SIGNING_MULTIBASE: &str = "z6MkwSD8dBdqcXQzKJZQFPy2hh2izzxskndKCjdmC2dBpfME";
/// An X25519 key for the device agreement role.
const AGREEMENT_MULTIBASE: &str = "z6LSkdrX4EvewpktHBjvNxRDogPdC5iVF8LT3LPKefGAgi89";

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
/// subcommands this line uses. Each `key create` answers with the next of the three keys
/// the identity needs — root, device signing, device agreement — because a named key has
/// no DID, so the CLI derives one from the first public key it is given.
const FAKE_ANPIO_KEY: &str = r#"#!/bin/sh
log="$ANPIOCLI_TEST_ANPIO_KEY_LOG"
printf '%s\n' "$*" >> "$log"
if [ "$1" = "--root" ]; then shift 2; fi
case "$1" in
  key)
    case "$2" in
      create)
        n=$(cat "$log.count" 2>/dev/null || printf '0')
        n=$((n + 1))
        printf '%s' "$n" > "$log.count"
        case "$n" in
          1) printf '%s\n' '{"name":"k-root","thumbprint":"e1_root","public_multibase":"__ROOT__","algorithm":"Ed25519"}' ;;
          2) printf '%s\n' '{"name":"k-sign","thumbprint":"e1_sign","public_multibase":"__SIGN__","algorithm":"Ed25519"}' ;;
          *) printf '%s\n' '{"name":"k-agree","thumbprint":"x1_agree","public_multibase":"__AGREE__","algorithm":"X25519"}' ;;
        esac
        ;;
      list)
        printf '%s\n' '[{"name":"k-root","did":"","kid":"","thumbprint":"e1_root","public_multibase":"__ROOT__","algorithm":"Ed25519","state":"unlocked"},{"name":"k-sign","did":"","kid":"","thumbprint":"e1_sign","public_multibase":"__SIGN__","algorithm":"Ed25519","state":"unlocked"},{"name":"k-agree","did":"","kid":"","thumbprint":"x1_agree","public_multibase":"__AGREE__","algorithm":"X25519","state":"unlocked"}]'
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

/// The protected surface's fake: it logs the invocation and the request, and answers the
/// operations `did attach` uses with the `{code, data}` envelope the real binary prints.
///
/// The catalog and the document are woven in at construction time, so each test reads a
/// fixed DID and the key fragments that belong to it.
const FAKE_PROTECTED_ANPIO_KEY: &str = r#"#!/bin/sh
log="$ANPIOCLI_TEST_ANPIO_KEY_LOG"
printf '%s\n' "$*" >> "$log"
if [ "$1" = "data" ]; then
  shift 1
  file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --file) file="$2"; shift 2 ;;
      --config) shift 2 ;;
      *) shift ;;
    esac
  done
  request=$(cat "$file")
  printf 'REQ %s\n' "$request" >> "$log"
  op=$(printf '%s' "$request" | sed -n 's/.*"operation"[[:space:]]*:[[:space:]]*"\([A-Z_]*\)".*/\1/p')
  printf 'DATA %s\n' "$op" >> "$log"
  case "$op" in
    LIST_AUTHORIZED_KEYS)
      printf '%s\n' '{"code":"OK","data":{"keys":[{"key_id":"key-root","kid":"__DID__#key-1","did":"__DID__","role":"root"},{"key_id":"key-sign","kid":"__DID__#__SIGN__","did":"__DID__","role":"hot"}]}}'
      ;;
    GET_DOCUMENT)
      printf '{"code":"OK","data":{"document":__DOC__}}\n'
      ;;
    GET_GRANT_STATUS)
      grant=$(printf '%s' "$request" | sed -n 's/.*"grant_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
      printf '{"code":"OK","data":{"grant_id":"%s","key_id":"key-sign","state":"__STATE__","expiry":4102444800,"kind":"request","max_uses":100,"used_uses":__USED__,"max_renewals":0,"renewals":0}}\n' "$grant"
      ;;
    GET_CAPABILITIES)
      extra=""
      if [ -n "$ANPIOCLI_TEST_CAPABILITY_DID" ]; then
        extra=$(printf ',"capability_auth":true,"capability_did":"%s"' "$ANPIOCLI_TEST_CAPABILITY_DID")
      fi
      printf '{"code":"OK","data":{"operations":["SIGN_HTTP","SIGN_DOCUMENT_PROOF"],"signing_purposes":["device_assertion"]%s}}\n' "$extra"
      ;;
    *)
      exit 64
      ;;
  esac
  exit 0
fi
exit 64
"#;

/// The provisioning fake: the protected service's three admin calls and the document proof
/// a new identity needs.
///
/// The DID and the signed document are woven in at construction time; the completion reply
/// carries the keys and grants that document already publishes, so the CLI's own check that
/// the daemon minted the identity it built is exercised rather than bypassed.
const FAKE_PROTECTED_CREATE: &str = r#"#!/bin/sh
log="$ANPIOCLI_TEST_ANPIO_KEY_LOG"
printf '%s\n' "$*" >> "$log"
if [ "$1" = "admin" ]; then
  shift 1
  command=""; file=""; document=""; domain=""; challenge=""; operation=""; digest=""
  while [ $# -gt 0 ]; do
    case "$1" in
      prepare|commit|complete-secret-operation|sign-first-document|catalog) command="$1"; shift ;;
      --file) file="$2"; shift 2 ;;
      --document) document="$2"; shift 2 ;;
      --domain) domain="$2"; shift 2 ;;
      --challenge) challenge="$2"; shift 2 ;;
      --operation-id) operation="$2"; shift 2 ;;
      --digest) digest="$2"; shift 2 ;;
      --vault-id|--did|--config) shift 2 ;;
      *) shift ;;
    esac
  done
  case "$command" in
    sign-first-document)
      printf 'PROOF {"document":%s,"domain":"%s","challenge":"%s"}\n' "$(cat "$document")" "$domain" "$challenge" >> "$log"
      printf '%s\n' '{"code":"OK","data":{"document":__VALUE__,"kid":"__DID__#key-1"}}'
      ;;
    prepare)
      printf 'CHANGE %s\n' "$(cat "$file")" >> "$log"
      n=$(cat "$log.count" 2>/dev/null || printf '0')
      n=$((n + 1))
      printf '%s' "$n" > "$log.count"
      case "$n" in
        1) printf '%s\n' '{"code":"OK","prepared":{"operation_id":"op-provision","digest":"digest-provision","effect":{"kind":"ProvisionIdentity","vault_id":"vault-main","did":"__DID__","device_id":"mybot/default"},"expires_at":4102444800}}' ;;
        *) printf '%s\n' '{"code":"OK","prepared":{"operation_id":"op-install","digest":"digest-install","effect":{"kind":"InstallDocument","vault_id":"vault-main"},"expires_at":4102444800}}' ;;
      esac
      ;;
    commit)
      printf 'COMMIT %s %s\n' "$operation" "$digest" >> "$log"
      printf '%s\n' '{"code":"OK"}'
      ;;
    complete-secret-operation)
      printf 'COMPLETE %s %s\n' "$operation" "$digest" >> "$log"
      printf '%s\n' '{"code":"OK","data":__DATA__}'
      ;;
    *) exit 64 ;;
  esac
  exit 0
fi
if [ "$1" = "data" ]; then
  shift 1
  file=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --file) file="$2"; shift 2 ;;
      --config) shift 2 ;;
      *) shift ;;
    esac
  done
  request=$(cat "$file")
  printf 'REQ %s\n' "$request" >> "$log"
  request_id=$(printf '%s' "$request" | sed -n 's/.*"request_id":"\([^"]*\)".*/\1/p')
  prefix='{"code":"OK","data":{"request_id":"'
  suffix='","state":"completed","result":{"value":__VALUE__,"proof":__PROOF__}}}'
  printf '%s%s%s\n' "$prefix" "$request_id" "$suffix"
  exit 0
fi
exit 64
"#;

/// The DID the protected fake holds, in the E1 shape `did attach` accepts.
const PROTECTED_DID: &str = "did:wba:example.com:user:alice:e1_abc";
/// The hot fragment the HTTP grant covers; the binding key is `key-1`.
const PROTECTED_SIGN_KID: &str = "alice/default-sign";

struct FakeKey {
    path: PathBuf,
    log: PathBuf,
}

impl FakeKey {
    fn new(dir: &Path, name: &str) -> Self {
        let path = dir.join(format!("anpio-key-{name}"));
        let log = dir.join(format!("anpio-key-{name}.log"));
        let script = FAKE_ANPIO_KEY
            .replace("__ROOT__", PUBLIC_MULTIBASE)
            .replace("__SIGN__", SIGNING_MULTIBASE)
            .replace("__AGREE__", AGREEMENT_MULTIBASE);
        Self::write(path, log, script)
    }

    /// An `anpio-key data --config` service that reports `state` for every grant, with
    /// `used` of the 100 uses already spent.
    fn protected_with(dir: &Path, name: &str, state: &str, used: u32) -> Self {
        let path = dir.join(format!("anpio-key-{name}"));
        let log = dir.join(format!("anpio-key-{name}.log"));
        let document = json!({
            "id": PROTECTED_DID,
            "verificationMethod": [
                {
                    "id": format!("{}#key-1", PROTECTED_DID),
                    "type": "Multikey",
                    "controller": PROTECTED_DID,
                    "publicKeyMultibase": PUBLIC_MULTIBASE,
                },
                {
                    "id": format!("{}#{}", PROTECTED_DID, PROTECTED_SIGN_KID),
                    "type": "Multikey",
                    "controller": PROTECTED_DID,
                    "publicKeyMultibase": SIGNING_MULTIBASE,
                },
            ],
            "authentication": [
                format!("{}#key-1", PROTECTED_DID),
                format!("{}#{}", PROTECTED_DID, PROTECTED_SIGN_KID),
            ],
        });
        let script = FAKE_PROTECTED_ANPIO_KEY
            .replace("__DID__", PROTECTED_DID)
            .replace("__SIGN__", PROTECTED_SIGN_KID)
            .replace("__DOC__", &document.to_string())
            .replace("__STATE__", state)
            .replace("__USED__", &used.to_string());
        Self::write(path, log, script)
    }

    fn protected(dir: &Path, name: &str) -> Self {
        Self::protected_with(dir, name, "active", 0)
    }

    /// The protected service a `did create` talks to: it prepares and completes the
    /// provisioning change, proofs the first document on the management plane, and accepts
    /// the first-install commit. `did` and `signed` are the ones the client builds from the
    /// keys it returns.
    fn provisioning(dir: &Path, name: &str, did: &str, signed: &Value) -> Self {
        let path = dir.join(format!("anpio-key-{name}"));
        let log = dir.join(format!("anpio-key-{name}.log"));
        let data = json!({
            "vault_id": "vault-main",
            "did": did,
            "device_id": "mybot/default",
            "keys": [
                {
                    "key_id": "key-root",
                    "role": "root",
                    "kid": format!("{did}#key-1"),
                    "public_multibase": PUBLIC_MULTIBASE,
                },
                {
                    "key_id": "key-sign",
                    "role": "device_signing",
                    "kid": format!("{did}#mybot/default-sign"),
                    "public_multibase": SIGNING_MULTIBASE,
                },
                {
                    "key_id": "key-agree",
                    "role": "key_agreement",
                    "kid": format!("{did}#mybot/default-agreement"),
                    "public_multibase": AGREEMENT_MULTIBASE,
                },
            ],
            "grants": {
                "http": {"grant_id": "g-http", "key_id": "key-sign"},
                "document_proof": {"grant_id": "g-doc", "key_id": "key-root"},
                "purpose": {"grant_id": "g-purpose", "key_id": "key-sign"},
                "origin_proof_agent": {"grant_id": "g-agent", "key_id": "key-sign"},
                "origin_proof_group": {"grant_id": "g-group", "key_id": "key-sign"},
                "origin_proof_service": {"grant_id": "g-service", "key_id": "key-sign"},
            },
            "unlocked": ["key-root", "key-sign", "key-agree"],
        });
        let proof = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": format!("{did}#key-1"),
            "proofPurpose": "assertionMethod",
            "proofValue": "zFakeProof",
        });
        let script = FAKE_PROTECTED_CREATE
            .replace("__DID__", did)
            .replace("__DATA__", &data.to_string())
            .replace("__VALUE__", &signed.to_string())
            .replace("__PROOF__", &proof.to_string());
        Self::write(path, log, script)
    }

    fn write(path: PathBuf, log: PathBuf, script: String) -> Self {
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

    /// The operations a protected service was asked for, in order.
    fn data_calls(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("DATA ").map(str::to_string))
            .collect()
    }

    /// The request bodies the protected service was given, in order.
    fn protected_requests(&self) -> Vec<Value> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("REQ "))
            .map(|line| serde_json::from_str(line).expect("a protected request is JSON"))
            .collect()
    }

    /// The first-document proofs the management plane was asked for, in order.
    fn proofs(&self) -> Vec<Value> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("PROOF "))
            .map(|line| serde_json::from_str(line).expect("a proof request is JSON"))
            .collect()
    }

    /// Every command line, without the request/document/change payload lines.
    fn invocations(&self) -> Vec<String> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .filter(|line| {
                !["DATA ", "REQ ", "DOC ", "PROOF ", "CHANGE ", "COMMIT ", "COMPLETE "]
                    .iter()
                    .any(|prefix| line.starts_with(prefix))
            })
            .map(str::to_string)
            .collect()
    }

    /// The change documents an `admin prepare` was given, in order.
    fn changes(&self) -> Vec<Value> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix("CHANGE "))
            .map(|line| serde_json::from_str(line).expect("a prepared change is JSON"))
            .collect()
    }

    /// The `COMMIT`/`COMPLETE` records, as `<operation> <digest>`.
    fn records(&self, kind: &str) -> Vec<String> {
        let prefix = format!("{kind} ");
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
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
        // A path with no file behind it is how this suite says "no protected service is
        // installed here", so the tests read the same on a machine that has one.
        .env("ANPIOCLI_ANPIO_KEY_CONFIG", home.0.join("no-protected-service.json"))
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
    run_with_a_terminal_seeing(home, key, args, &home.0.join("no-protected-service.json"))
}

/// The same, with `$ANPIOCLI_ANPIO_KEY_CONFIG` naming `config`: a path that exists says a
/// protected service is installed, a path with no file behind it says there is none.
fn run_with_a_terminal_seeing(
    home: &Home,
    key: &FakeKey,
    args: &[&str],
    config: &Path,
) -> Option<Output> {
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
            .env("ANPIOCLI_ANPIO_KEY_CONFIG", config)
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
            .env("ANPIOCLI_ANPIO_KEY_CONFIG", config)
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

fn create_args(base: &str) -> Vec<&str> {
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
    assert!(printed.contains("k-root"), "the root key name is printed:\n{printed}");
    assert!(printed.contains("k-sign"), "the device signing key name is printed:\n{printed}");
    assert!(printed.contains("k-agree"), "the agreement key name is printed:\n{printed}");
    assert!(
        printed.contains("signer: anpio-key (key k-root, grant none)"),
        "{printed}"
    );
    // A store whose keys are named has no second, unprotected daemon to fall back to: the
    // summary points at the protected install that adopts the identity onto the one service
    // the machine runs.
    assert!(printed.contains("install.sh --adopt"), "{printed}");
    assert!(
        !printed.contains("serve --development") && !printed.contains("allow-named-key-signing"),
        "no development daemon is suggested:\n{printed}"
    );
    assert!(!printed.contains("anpio-key grant create --key"), "{printed}");

    let identity = read_json(&home.identity("mybot"));
    let did = identity["did"].as_str().expect("a DID").to_string();
    assert!(did.ends_with(&identity_fingerprint(&identity["did_document"])), "{did}");
    assert_eq!(identity["custody"]["kind"], "anpio-key");
    assert_eq!(identity["custody"]["name"], "k-root");
    assert_eq!(identity["custody"]["device_keys"]["sign"], "k-sign");
    assert_eq!(identity["custody"]["device_keys"]["agreement"], "k-agree");
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
    assert_eq!(submitted["verificationMethod"][1]["publicKeyMultibase"], SIGNING_MULTIBASE);
    assert_eq!(submitted["verificationMethod"][2]["publicKeyMultibase"], AGREEMENT_MULTIBASE);
    assert_eq!(
        submitted["deviceManifest"]["devices"].as_array().map(Vec::len),
        Some(1),
        "awiki accepts exactly one device: {}",
        submitted["deviceManifest"]
    );
    assert_eq!(
        submitted["deviceManifest"]["devices"][0]["device_id"],
        "mybot/default"
    );
    assert_eq!(identity["did_document"]["proof"]["type"], "FakeSignature2020");

    let register = host.register_body();
    assert_eq!(register["params"]["did_document"]["proof"]["type"], "FakeSignature2020");
    assert_eq!(register["params"]["did_document"]["id"], did);

    // Exactly four conversations with the daemon, in this order: three mints (root,
    // device signing, device agreement), then one proof.
    let calls = key.calls();
    assert_eq!(calls.len(), 4, "{calls:?}");
    assert_eq!(calls[0], "key create --json --algorithm ed25519");
    assert_eq!(calls[1], "key create --json --algorithm ed25519");
    assert_eq!(
        calls[2], "key create --json --algorithm x25519",
        "the agreement key is minted on the curve ECDH needs"
    );
    assert!(
        calls[3].starts_with(&format!("key sign-document --name k-root --keyid {did}#key-1")),
        "{}",
        calls[3]
    );
    // Both are proof options the awiki host checks, so they have to reach the signer —
    // adding them to the document afterwards would invalidate the signature.
    assert!(calls[3].contains(" --domain localhost"), "{}", calls[3]);
    let challenge = calls[3]
        .split(" --challenge ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("a challenge reaches anpio-key");
    assert_eq!(challenge.len(), 32, "{challenge}");
    assert!(challenge.chars().all(|c| c.is_ascii_hexdigit()), "{challenge}");
    assert!(!home.pending().exists(), "a registered identity leaves no pending key");

    // Re-registering uses the document the daemon proofed, not a lookup by DID — a named
    // key has none to look up.
    let again = run(&home, &key, &["did", "register", "--agent", "mybot"]);
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert_eq!(key.calls().len(), 4, "the daemon is not asked for a document: {:?}", key.calls());
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

/// The protected arm: on a machine with the installed service, `--key anpio-key` provisions
/// the identity *into* that service.
///
/// The conversation is judged on what it asks the daemon for: a `ProvisionIdentity` change
/// whose policies are the client's fixed capabilities and whose grants name the role that
/// may hold each one; one completion carrying `--new-secret` (the passphrase stays inside
/// the daemon); a first-document proof on the management plane, because the administrator
/// account cannot open the sign socket; and an `InstallDocument` commit in the vault the
/// provisioning named. The output then has to hand the agent administrator the exact attach
/// command — and no passphrase and no second, development daemon.
#[test]
fn a_protected_create_provisions_the_identity_with_one_confirmation() {
    let host = FakeHost::start();
    let home = Home::new("protected-create");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();

    let port = host
        .base
        .rsplit(':')
        .next()
        .and_then(|port| port.parse::<u16>().ok())
        .expect("the fake host's port");
    let input = CreateIdentityInput {
        authority: format!("localhost%3A{port}"),
        domain: "localhost".into(),
        agent: "mybot".into(),
        profile: "default".into(),
        device: Some("mybot/default".into()),
        handle: "mybot".into(),
        did_host_url: host.base.clone(),
        service_endpoint: format!("{}/anp-im/rpc", host.base),
        service_did: format!("did:wba:localhost%3A{port}"),
    };
    // The document and DID the client will build from the keys the fake returns. They are
    // the ones its own check accepts, which is the property under test.
    let external = build_external_identity(
        &input,
        ed25519_public_key(PUBLIC_MULTIBASE, "root").expect("the root key"),
        ed25519_public_key(SIGNING_MULTIBASE, "device signing").expect("the signing key"),
        public_key_from_multibase(AGREEMENT_MULTIBASE, "agreement").expect("the agreement key"),
    )
    .expect("the client's document");
    let did = external.did.clone();
    let mut signed = external.unsigned_document.clone();
    signed["proof"] = json!({
        "type": "DataIntegrityProof",
        "cryptosuite": "eddsa-jcs-2022",
        "verificationMethod": format!("{did}#key-1"),
        "proofPurpose": "assertionMethod",
        "proofValue": "zFakeProof",
    });
    let key = FakeKey::provisioning(&home.0, "protected", &did, &signed);

    let Some(out) = run_with_a_terminal_seeing(&home, &key, &create_args(&host.base), &config)
    else {
        return;
    };
    let printed = text(&out.stdout) + &text(&out.stderr);
    assert!(out.status.success(), "{printed}");

    // The provisioning change: the identity's coordinates, its six capabilities, and the
    // role that holds each grant.
    let changes = key.changes();
    assert_eq!(changes.len(), 2, "{changes:#?}");
    let provision = &changes[0];
    assert_eq!(provision["kind"], "ProvisionIdentity");
    assert_eq!(provision["host"], "localhost");
    assert_eq!(provision["port"], port);
    assert_eq!(provision["path_segments"], json!(["user", "mybot"]));
    assert_eq!(provision["device_id"], "mybot/default");
    assert!(
        provision["vault_id"].is_null(),
        "the daemon picks its one active vault: {provision}"
    );
    let policies = provision["policies"].as_array().expect("the policies");
    assert_eq!(policies.len(), 6, "{policies:#?}");
    let policy = |name: &str| {
        policies
            .iter()
            .find(|policy| policy["name"] == name)
            .unwrap_or_else(|| panic!("no {name} policy in {policies:#?}"))
    };
    let http = policy("http");
    assert_eq!(http["purpose"], "http_authentication");
    assert_eq!(http["content"]["origin"], "https://localhost");
    assert_eq!(http["content"]["signature_profile"], "anp-http-v2");
    assert_eq!(http["content"]["body"]["max_bytes"], 1_048_576);
    let paths = http["content"]["paths"].as_array().expect("the HTTP paths");
    for path in ["/anp-im/rpc", "/user-service/v1/did-auth/rpc"] {
        assert!(
            paths.iter().any(|candidate| candidate == path),
            "{path} missing from {paths:?}"
        );
    }
    assert_eq!(policy("document-proof")["content"]["proof_purposes"], json!(["assertionMethod"]));
    assert_eq!(policy("device-assertions")["content"]["purposes"], json!(["device_assertion"]));
    for kind in ["agent", "group", "service"] {
        assert_eq!(policy(&format!("origin-{kind}"))["content"]["origin"], format!("anp://{kind}"));
    }
    let mut policy_ids = policies
        .iter()
        .map(|policy| policy["policy_id"].as_str().expect("a policy id").to_string())
        .collect::<Vec<_>>();
    policy_ids.sort();
    policy_ids.dedup();
    assert_eq!(policy_ids.len(), 6, "every policy has its own id");

    let grants = provision["grants"].as_array().expect("the grants");
    assert_eq!(grants.len(), 6, "{grants:#?}");
    let granted = |name: &str| {
        let id = policy(name)["policy_id"].as_str().expect("a policy id");
        grants
            .iter()
            .find(|grant| grant["policy_id"] == id)
            .unwrap_or_else(|| panic!("no grant for {name} in {grants:#?}"))
    };
    assert_eq!(granted("document-proof")["key"], "root");
    assert_eq!(granted("device-assertions")["key"], "device_signing");
    for name in ["http", "origin-agent", "origin-group", "origin-service"] {
        assert_eq!(granted(name)["key"], "device_signing", "{name}");
    }

    // The daemon is asked to mint and seal once, on this terminal, and the flag that makes
    // it read a *new* passphrase is the only thing that reaches the process about it.
    let invocations = key.invocations();
    assert_eq!(invocations.len(), 5, "{invocations:#?}");
    assert!(
        invocations[0].starts_with(&format!("admin --config {config_text} prepare --file ")),
        "{}",
        invocations[0]
    );
    assert_eq!(
        invocations[1],
        format!(
            "admin --config {config_text} complete-secret-operation --operation-id \
             op-provision --digest digest-provision --new-secret --json"
        ),
        "one completion, carrying --new-secret"
    );
    assert!(
        invocations[2].starts_with(&format!(
            "admin --config {config_text} sign-first-document --vault-id vault-main --did {did} \
             --document "
        )),
        "the administrator account proofs the first document: {}",
        invocations[2]
    );
    assert!(
        !invocations.iter().any(|line| line.contains(" data ")),
        "the admin account never opens the sign socket: {invocations:#?}"
    );
    assert!(
        invocations[3].starts_with(&format!("admin --config {config_text} prepare --file ")),
        "{}",
        invocations[3]
    );
    assert_eq!(
        invocations[4],
        format!(
            "admin --config {config_text} commit --operation-id op-install --digest digest-install"
        )
    );
    assert_eq!(key.records("COMPLETE"), vec!["op-provision digest-provision"]);
    assert_eq!(key.records("COMMIT"), vec!["op-install digest-install"]);

    // The first-document proof names the document the client built, on the same host.
    let proofs = key.proofs();
    assert_eq!(proofs.len(), 1, "{proofs:#?}");
    assert_eq!(proofs[0]["document"], external.unsigned_document);
    assert_eq!(proofs[0]["domain"], "localhost");
    let challenge = proofs[0]["challenge"].as_str().expect("a challenge");
    assert_eq!(challenge.len(), 32, "{challenge}");
    assert!(challenge.chars().all(|c| c.is_ascii_hexdigit()), "{challenge}");

    // The proofed document is installed into the vault the provisioning reply names.
    let install = &changes[1];
    assert_eq!(install["kind"], "Catalog");
    assert_eq!(install["change"]["action"], "InstallDocument");
    assert_eq!(install["change"]["vault_id"], "vault-main");
    assert_eq!(install["change"]["document"], signed);

    // The store keeps the name and the grants, never a private byte.
    let identity = read_json(&home.identity("mybot"));
    assert_eq!(identity["did"], did);
    assert_eq!(identity["device_id"], "mybot/default");
    assert_eq!(identity["did_document"], signed);
    let custody = &identity["custody"];
    assert_eq!(custody["kind"], "anpio-key");
    assert_eq!(custody["config"].as_str(), Some(config_text.as_str()));
    assert_eq!(custody["kid"], "mybot/default-sign");
    assert_eq!(custody["device"], "mybot/default");
    assert!(custody["grant"].is_null(), "the per-purpose map replaces it: {custody}");
    let stored = custody["grants"].as_object().expect("the per-purpose grants");
    assert_eq!(stored.len(), 6, "{stored:?}");
    for (purpose, grant) in [
        ("http", "g-http"),
        ("document_proof", "g-doc"),
        ("purpose", "g-purpose"),
        ("origin_proof_agent", "g-agent"),
        ("origin_proof_group", "g-group"),
        ("origin_proof_service", "g-service"),
    ] {
        assert_eq!(stored[purpose], grant, "{purpose}");
    }
    for entry in store_files(&home.0) {
        let bytes = fs::read(&entry).expect("read a store file");
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            !text.contains("PRIVATE KEY") && !text.contains("private_key_pem"),
            "{} holds private key material",
            entry.display()
        );
    }
    assert!(!home.pending().exists());

    // The five stages, the minted counts, and the exact attach command for the agent
    // administrator. The grants printed are the ids just issued.
    for stage in ["[1/5]", "[2/5]", "[3/5]", "[4/5]", "[5/5]"] {
        assert!(printed.contains(stage), "no {stage} line:\n{printed}");
    }
    assert!(printed.contains("vault vault-main"), "{printed}");
    assert!(printed.contains("6 policies · 6 grants"), "{printed}");
    assert!(printed.contains("keys minted and sealed; 3 of 3 unlocked for signing"), "{printed}");
    assert!(printed.contains("installed the first document in the vault"), "{printed}");
    assert!(printed.contains(&format!("--config {config_text}")), "{printed}");
    assert!(printed.contains(&format!("--did {did}")), "{printed}");
    assert!(printed.contains("--kid mybot/default-sign"), "{printed}");
    assert!(printed.contains("--agent mybot --device mybot/default"), "{printed}");
    for (purpose, grant) in [
        ("http", "g-http"),
        ("document_proof", "g-doc"),
        ("purpose", "g-purpose"),
        ("origin_proof_agent", "g-agent"),
        ("origin_proof_group", "g-group"),
        ("origin_proof_service", "g-service"),
    ] {
        assert!(
            printed.contains(&format!("--grant {purpose}={grant}")),
            "no {purpose} grant in:\n{printed}"
        );
    }
    assert!(printed.contains("did show --agent mybot"), "{printed}");
    assert!(
        !printed.contains("serve --development") && !printed.contains("allow-named-key-signing"),
        "no development daemon is suggested:\n{printed}"
    );
    assert!(
        !printed.contains("--new-secret") && !printed.contains("passphrase"),
        "the passphrase never reaches this process or its output:\n{printed}"
    );
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
        "key:        anpio-key (key k-root, grant g-7f3a)",
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
        text(&sign.stderr).contains("signer: anpio-key (key k-root, grant none)"),
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
    assert!(call.starts_with(&format!("sign --key k-root --keyid {did}#key-1")), "{call}");
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

/// A document file is held to the same identity check as a fetched one: it must be the
/// document for this DID, so a file for another identity cannot be attached. This is the
/// path a machine behind a local DNS proxy uses.
#[test]
fn a_document_file_must_name_the_did_it_is_attached_to() {
    let home = Home::new("attach-document");
    let key = FakeKey::new(&home.0, "keys");
    let document = home.0.join("did.json");
    fs::write(
        &document,
        r#"{"id":"did:wba:example.com:user:alice:e1_other"}"#,
    )
    .expect("a document file");
    let document_text = document.display().to_string();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            "did:wba:example.com:user:alice:e1_root",
            "--name",
            "k-root",
            "--document",
            &document_text,
            "--agent",
            "alice",
        ],
    );
    assert!(!out.status.success(), "{}", text(&out.stdout));
    let printed = text(&out.stderr);
    assert!(printed.contains("is not the document for"), "{printed}");
    assert!(!home.identity("alice").exists());
}

/// A capability token is copied beside the identity and named by the record; the attach
/// conversation already carries it, and the clear text appears in no output. The copy is
/// what later commands use, so the administrator's minting path can move afterwards.
#[test]
fn attaching_with_a_capability_token_records_a_private_copy() {
    let home = Home::new("protected-capability");
    let key = FakeKey::protected(&home.0, "protected");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();
    let token_text = format!("anp1_{}", "A".repeat(43));
    let minted = home.0.join("minted-token");
    fs::write(&minted, format!("{token_text}\n")).expect("a minted token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&minted, fs::Permissions::from_mode(0o600)).expect("0600");
    }
    let minted_text = minted.display().to_string();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            &config_text,
            "--kid",
            PROTECTED_SIGN_KID,
            "--grant",
            "http=g-http",
            "--capability-file",
            &minted_text,
            "--agent",
            "alice",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));

    let copy = home.0.join("alice").join("default").join("capability");
    let copy_text = copy.display().to_string();
    let identity = read_json(&home.identity("alice"));
    assert_eq!(
        identity["custody"]["capability_file"].as_str(),
        Some(copy_text.as_str())
    );
    assert_eq!(fs::read_to_string(&copy).expect("the recorded token"), token_text);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&copy).expect("the copy").permissions().mode() & 0o777,
            0o600
        );
    }

    // The attach conversation already goes through the capability endpoint: a token is not
    // recorded and then ignored until the next command.
    let invocations = key.invocations();
    assert_eq!(invocations.len(), 4, "{invocations:?}");
    for call in &invocations {
        assert!(
            call.contains(&format!("--capability-file {minted_text}")),
            "{call}"
        );
    }
    let printed = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(
        !printed.contains(&token_text),
        "the clear-text token must not be printed: {printed}"
    );
}

/// A token file another account can read is refused before any daemon call, and nothing is
/// written: an identity that records it would hand out those permissions with the identity.
#[test]
fn a_world_readable_capability_token_is_refused_before_anything_is_written() {
    let home = Home::new("protected-capability-mode");
    let key = FakeKey::protected(&home.0, "protected");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();
    let minted = home.0.join("minted-token");
    fs::write(&minted, format!("anp1_{}\n", "A".repeat(43))).expect("a minted token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&minted, fs::Permissions::from_mode(0o644)).expect("0644");
    }
    let minted_text = minted.display().to_string();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            &config_text,
            "--kid",
            PROTECTED_SIGN_KID,
            "--grant",
            "http=g-http",
            "--capability-file",
            &minted_text,
            "--agent",
            "alice",
        ],
    );
    assert!(!out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("must be 0600"),
        "{}",
        text(&out.stderr)
    );
    assert!(!home.identity("alice").exists());
    assert!(
        key.invocations().is_empty(),
        "an unusable token must fail before any daemon call: {:?}",
        key.invocations()
    );
}

/// A token minted for another DID is refused while the identity is still only a plan:
/// `GET_CAPABILITIES` through the token names the DID it is pinned to.
#[test]
fn a_capability_token_bound_to_another_did_is_refused_at_attach() {
    let home = Home::new("protected-capability-did");
    let key = FakeKey::protected(&home.0, "protected");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();
    let token = home.0.join("minted-token");
    fs::write(&token, format!("anp1_{}\n", "A".repeat(43))).expect("a minted token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("0600");
    }
    let token_text = token.display().to_string();

    let out = base_command(&home, &key)
        .env(
            "ANPIOCLI_TEST_CAPABILITY_DID",
            "did:wba:example.com:user:alice:e1_other",
        )
        .args([
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            &config_text,
            "--kid",
            PROTECTED_SIGN_KID,
            "--grant",
            "http=g-http",
            "--capability-file",
            &token_text,
            "--agent",
            "alice",
        ])
        .output()
        .expect("the binary under test runs");
    assert!(!out.status.success(), "{}", text(&out.stderr));
    let printed = text(&out.stderr);
    assert!(
        printed.contains("bound to did:wba:example.com:user:alice:e1_other")
            && printed.contains("but this identity is"),
        "{printed}"
    );
    assert!(!home.identity("alice").exists());
}

/// Attaching through the protected service is a different conversation from the named-key
/// one: the catalog is listed, the document is read by key, each recorded grant is checked,
/// and the negotiated capabilities are cached. The record names the hot key and keeps one
/// grant per purpose — never a second daemon.
#[test]
fn attaching_through_the_protected_service_records_the_hot_key_and_both_grants() {
    let home = Home::new("protected-attach");
    let key = FakeKey::protected(&home.0, "protected");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();
    let config_arg = config_text.as_str();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            config_arg,
            "--kid",
            PROTECTED_SIGN_KID,
            "--grant",
            "http=g-http",
            "--grant",
            "document_proof=g-doc",
            "--agent",
            "alice",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));

    let identity = read_json(&home.identity("alice"));
    assert_eq!(identity["did"], PROTECTED_DID);
    let custody = &identity["custody"];
    assert_eq!(custody["kind"], "anpio-key");
    assert_eq!(custody["config"].as_str(), Some(config_arg));
    assert_eq!(custody["kid"], PROTECTED_SIGN_KID);
    assert!(
        custody["grant"].is_null(),
        "the per-purpose map replaces the single id: {custody}"
    );
    assert_eq!(custody["grants"]["http"], "g-http");
    assert_eq!(custody["grants"]["document_proof"], "g-doc");
    assert_eq!(identity["did_document"]["id"], PROTECTED_DID);
    let operations = custody["operations"].as_array().expect("cached capabilities");
    for operation in ["SIGN_HTTP", "SIGN_DOCUMENT_PROOF"] {
        assert!(
            operations.iter().any(|cached| cached == operation),
            "{operation} missing from {operations:?}"
        );
    }
    assert_eq!(custody["signing_purposes"][0], "device_assertion");

    // Every call goes through `data --config`, with a request file — the development
    // socket is never reached.
    let invocations = key.invocations();
    assert_eq!(invocations.len(), 5, "{invocations:?}");
    for call in &invocations {
        assert!(
            call.starts_with(&format!("data --config {config_arg} --file ")),
            "{call}"
        );
    }
    assert_eq!(
        key.data_calls(),
        vec![
            "LIST_AUTHORIZED_KEYS",
            "GET_DOCUMENT",
            "GET_GRANT_STATUS",
            "GET_GRANT_STATUS",
            "GET_CAPABILITIES",
        ]
    );
    let requests = key.protected_requests();
    assert_eq!(
        requests[1]["key_id"], "key-sign",
        "the document is read for the key the identity will sign with: {requests:?}"
    );
    // Every recorded grant is checked; the map orders the purposes, so the document proof
    // is asked about before the HTTP grant.
    let checked: Vec<&str> = requests[2..4]
        .iter()
        .map(|request| request["grant_id"].as_str().expect("a grant id"))
        .collect();
    assert_eq!(checked, vec!["g-doc", "g-http"], "{requests:?}");
}

/// A protected identity must name its key: without a fragment the service could pick the
/// binding key, and the HTTP grant does not cover it.
#[test]
fn a_protected_attach_requires_the_key_fragment() {
    let home = Home::new("protected-no-kid");
    let key = FakeKey::protected(&home.0, "protected");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            &config_text,
            "--grant",
            "http=g-http",
            "--agent",
            "alice",
        ],
    );
    assert!(!out.status.success(), "{}", text(&out.stdout));
    let printed = text(&out.stderr);
    assert!(printed.contains("must name the key it signs with"), "{printed}");
    assert!(printed.contains("--kid <fragment>"), "{printed}");
    assert!(key.invocations().is_empty(), "{:?}", key.invocations());
    assert!(!home.identity("alice").exists());
}

/// A fragment the catalog does not offer is an exact requirement, so attaching fails and
/// the message lists what the principal does hold.
#[test]
fn a_protected_attach_refuses_a_kid_the_catalog_does_not_offer() {
    let home = Home::new("protected-wrong-kid");
    let key = FakeKey::protected(&home.0, "protected");
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            &config_text,
            "--kid",
            "alice/other-sign",
            "--grant",
            "http=g-http",
            "--agent",
            "alice",
        ],
    );
    assert!(!out.status.success(), "{}", text(&out.stdout));
    let printed = text(&out.stderr);
    assert!(printed.contains("authorizes no key"), "{printed}");
    assert!(printed.contains("it offers:"), "{printed}");
    assert!(printed.contains("alice/default-sign"), "{printed}");
    assert!(!home.identity("alice").exists());
}

/// A grant the daemon already reports unusable would produce an identity that cannot sign,
/// so it is refused at attach time instead of at the first signature.
#[test]
fn a_protected_attach_refuses_an_exhausted_grant() {
    let home = Home::new("protected-exhausted");
    let key = FakeKey::protected_with(&home.0, "protected", "exhausted", 100);
    let config = home.0.join("service.json");
    fs::write(&config, "{}").expect("a service configuration");
    let config_text = config.display().to_string();

    let out = run(
        &home,
        &key,
        &[
            "did",
            "attach",
            "--did",
            PROTECTED_DID,
            "--config",
            &config_text,
            "--kid",
            PROTECTED_SIGN_KID,
            "--grant",
            "http=g-http",
            "--agent",
            "alice",
        ],
    );
    assert!(!out.status.success(), "{}", text(&out.stdout));
    let printed = text(&out.stderr);
    assert!(printed.contains("exhausted"), "{printed}");
    assert!(printed.contains("0 of 100 uses left"), "{printed}");
    assert!(printed.contains("fresh grant"), "{printed}");
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
