//! The command surface, pinned (TODO6 §5.3).
//!
//! The 143 unit tests all live on the library side — identity storage, JCS hashing, the
//! session cache, policy, envelopes. **The command face itself has almost none**, so a
//! family can be renamed or dropped and nothing goes red. This file is that missing pin,
//! and it runs the real binary rather than calling into the library, because what is
//! being pinned is the argument surface a caller types.
//!
//! Everything here is answerable **without a service and without a DID host**: a
//! `--help`, a DID-shaped argument that short-circuits before any store is opened, and
//! the two refusals that must happen before any network is touched. The end-to-end
//! recipe (TODO6 §5.2/§5.3) is a different piece of work, and it is blocked on a
//! decision about which repository supplies the DID host.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A store root of this test's own, removed when the test ends.
///
/// Named by the test, so the tests that run in parallel threads of one binary do not
/// share a directory — and so a leftover directory from a failed run says which test
/// left it.
struct Home(PathBuf);

impl Home {
    fn new(name: &str) -> Home {
        let path = std::env::temp_dir().join(format!("agentx-cli-surface-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temp store root");
        Home(path)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run the binary under test against `home`, with the ambient agent selection cleared so
/// the result depends only on the arguments.
fn run(home: &Home, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentx-cli"))
        .args(args)
        .env("AGENTXCLI_HOME", &home.0)
        .env_remove("AGENTXCLI_AGENT")
        .env_remove("AGENTXCLI_PROFILE")
        .output()
        .expect("the binary under test runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// Every family the CLI has answers `--help`.
///
/// This is the pin itself: drop or rename a family and this goes red, which is the only
/// thing in the suite that would notice. The list is spelled out rather than derived
/// from the parser, because a list derived from the parser agrees with the parser by
/// construction and would pin nothing.
#[test]
fn every_family_answers_help() {
    let home = Home::new("families");
    for family in [
        "discover", "did", "agent", "msg", "group", "anp", "contacts", "me", "version",
    ] {
        let out = run(&home, &[family, "--help"]);
        assert!(
            out.status.success(),
            "`{family} --help` exited {:?}:\n{}",
            out.status.code(),
            text(&out.stderr)
        );
        assert!(
            text(&out.stdout).contains("Usage:"),
            "`{family} --help` printed no usage"
        );
    }
}

/// A family that does not exist is clap's refusal, not a silent no-op.
#[test]
fn an_unknown_family_is_refused() {
    let home = Home::new("unknown-family");
    let out = run(&home, &["nosuchfamily"]);
    assert_eq!(out.status.code(), Some(2), "clap's usage-error exit code");
    assert!(text(&out.stderr).contains("unrecognized subcommand"));
}

/// `contacts resolve <did>` answers with no store at all.
///
/// A DID-shaped argument is already its own answer, so the client short-circuits before
/// opening an identity — which is exactly what makes `resolve` the one to reach for
/// from a script: name in, DID out, nothing else on stdout, and no setup needed when
/// what you already have is a DID.
#[test]
fn resolving_a_did_needs_no_identity_and_prints_only_the_did() {
    let home = Home::new("resolve-did");
    let out = run(&home, &["contacts", "resolve", "did:web:example.com"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    assert_eq!(text(&out.stdout).trim(), "did:web:example.com");
    assert!(
        files_under(&home.0).is_empty(),
        "resolve wrote into the store: {:?}",
        files_under(&home.0)
    );
}

/// `--json` gives the machine-readable form, which names where the DID came from.
#[test]
fn resolving_a_did_json_names_its_source() {
    let home = Home::new("resolve-did-json");
    let out = run(&home, &["contacts", "resolve", "--json", "did:web:example.com"]);
    assert!(out.status.success(), "stderr:\n{}", text(&out.stderr));
    let value: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("resolve --json is JSON");
    assert_eq!(value["did"], "did:web:example.com");
    assert_eq!(value["source"], "argument");
    assert!(value["remark"].is_null(), "an argument DID has no remark");
}

/// `contacts add <name>` is refused **before** any identity is opened, and the message
/// names the command that does the right thing.
///
/// The refusal has to be here rather than at the service: `subject_of` is total, so a
/// string that is not a DID is stored unchanged — the row would be keyed by the literal
/// name and no DID would ever match it.
#[test]
fn adding_something_that_is_not_a_did_is_refused_before_any_identity() {
    let home = Home::new("add-a-name");
    let out = run(&home, &["contacts", "add", "Alice", "--remark", "Alice"]);
    assert_eq!(out.status.code(), Some(1));
    let err = text(&out.stderr);
    assert!(err.contains("is not a DID"), "{err}");
    assert!(err.contains("contacts add"), "the refusal must name the fix:\n{err}");
    assert!(
        files_under(&home.0).is_empty(),
        "the refusal came after opening a store: {:?}",
        files_under(&home.0)
    );
}

/// The one command that is answerable with nothing set up at all.
#[test]
fn version_is_always_answerable() {
    let home = Home::new("version");
    let out = run(&home, &["version", "--json"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).expect("version --json is JSON");
    assert!(value["version"].is_string(), "got {value}");
}
