//! The command surface, pinned (TODO6 §5.3, §7).
//!
//! The unit tests all live on the library side — identity storage, JCS hashing, the
//! session cache, policy, envelopes. **The command face itself has almost none**, so a
//! family or a subcommand can be renamed or dropped and nothing goes red. This file is that
//! missing pin, and it runs the real binary rather than calling into the library, because
//! what is being pinned is the argument surface a caller types.
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

/// Every page the CLI has, spelled out — the frozen command surface (TODO6 §7).
///
/// This list is the pin itself. It is written by hand rather than derived from the parser
/// because a list derived from the parser agrees with the parser by construction and would
/// pin nothing: the point is that **dropping or renaming a command is a deliberate act**,
/// which here means editing this list. A family with no subcommands (`discover`, `version`)
/// appears once, as itself.
///
/// Flags are deliberately **not** pinned. They grow with the protocol, and copying every one
/// of them in here would make each addition a two-file change while catching nothing beyond
/// "some flag was renamed" — the reference tables in `rust/README.md` are where flags are
/// documented, and `--help` is what is authoritative.
const FROZEN_SURFACE: &[&[&str]] = &[
    &["discover"],
    &["did"],
    &["agent"],
    &["msg"],
    &["group"],
    &["anp"],
    &["contacts"],
    &["me"],
    &["version"],
    &["did", "create"],
    &["did", "show"],
    &["did", "list"],
    &["did", "register"],
    &["did", "publish"],
    &["did", "update"],
    &["did", "resolve"],
    &["did", "restore"],
    &["agent", "show"],
    &["agent", "use"],
    &["agent", "list"],
    &["msg", "send"],
    &["msg", "caps"],
    &["msg", "inbox"],
    &["msg", "history"],
    &["msg", "show"],
    &["msg", "read"],
    &["msg", "fetch"],
    &["msg", "listen"],
    &["group", "create"],
    &["group", "info"],
    &["group", "members"],
    &["group", "join"],
    &["group", "leave"],
    &["group", "send"],
    &["group", "update-profile"],
    &["group", "set-remark"],
    &["group", "e2ee", "publish"],
    &["group", "e2ee", "get-key-package"],
    &["group", "e2ee", "create"],
    &["group", "e2ee", "add"],
    &["group", "e2ee", "remove"],
    &["group", "e2ee", "send"],
    &["anp", "show"],
    &["anp", "sign"],
    &["anp", "login"],
    &["contacts", "list"],
    &["contacts", "add"],
    &["contacts", "set-remark"],
    &["contacts", "remove"],
    &["contacts", "resolve"],
    &["me", "show"],
    &["me", "set"],
];

/// Every page in [`FROZEN_SURFACE`] answers `--help`.
///
/// The failure this catches is a rename or a removal: nothing else in the suite would notice
/// one, because the parser and the help renderer are the same source of truth. A red here
/// says "the surface moved", and the fix is to decide whether it should have — and then to
/// edit the list, which is the deliberate act the pin exists to force.
#[test]
fn the_frozen_surface_answers_help() {
    let home = Home::new("frozen-surface");
    for page in FROZEN_SURFACE {
        let mut argv: Vec<&str> = page.to_vec();
        argv.push("--help");
        let named = page.join(" ");

        let out = run(&home, &argv);
        let printed = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(
            out.status.success(),
            "`agentx-cli {named} --help` exited {:?} — the surface moved:\n{printed}",
            out.status.code()
        );
        assert!(
            printed.contains("Usage:"),
            "`agentx-cli {named} --help` printed no usage:\n{printed}"
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

/// `group set-remark` says nothing without a name or `--clear`, and the two are exclusive —
/// so an empty name and a name-with-`--clear` are both refused by the parser, before any
/// identity is opened. That is what makes them checkable here at all.
#[test]
fn a_group_remark_must_be_either_a_name_or_a_clear() {
    let home = Home::new("group-remark-shape");
    let bare = run(&home, &["group", "set-remark", "did:web:example.com:g:x"]);
    assert_eq!(bare.status.code(), Some(2), "clap's usage-error exit code");

    let both = run(
        &home,
        &["group", "set-remark", "did:web:example.com:g:x", "Team", "--clear"],
    );
    assert_eq!(both.status.code(), Some(2));

    assert!(
        files_under(&home.0).is_empty(),
        "a refusal came after opening a store: {:?}",
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

/// The `agentx-cli …` invocations inside `skill/agentx-cli/SKILL.md`'s fenced blocks, with
/// the line each one starts on.
///
/// The skill deliberately does not restate the command surface — it carries judgment and
/// sends the reader to `--help` — so the only part a gate can hold is the few invocations
/// a reader copies verbatim. Those are the ones that must still resolve. This gate used to
/// live in `packages/cli/src/help/help.test.ts`, checking the same file against the TS
/// client's manifest; it moved here when the skill was renamed and rewritten for this
/// binary, because the skill now names `agentx-cli` commands and a gate on the TS side
/// would have been checking the wrong surface.
fn skill_invocations() -> Vec<(usize, Vec<String>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../skill/agentx-cli/SKILL.md");
    let markdown =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));

    let mut out = Vec::new();
    let mut in_fence = false;
    for (index, raw) in markdown.lines().enumerate() {
        if raw.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence || raw.trim_start().starts_with('#') {
            continue;
        }
        let Some(at) = raw.find("agentx-cli ") else { continue };
        let argv = raw[at + "agentx-cli ".len()..]
            .split_whitespace()
            .map(str::to_string)
            .collect();
        out.push((index + 1, argv));
    }
    out
}

/// Every invocation the skill spells out resolves against the real binary: the page
/// exists, and the flags on it are flags that page accepts.
///
/// Checked by asking the binary rather than by reading a list, for the same reason the
/// rest of this file runs the binary — what is being pinned is the surface a caller types.
#[test]
fn the_skill_only_names_commands_the_binary_has() {
    let invocations = skill_invocations();
    assert!(
        invocations.len() >= 3,
        "the skill should spell out at least the golden path, found {}",
        invocations.len()
    );

    let home = Home::new("skill");
    for (line, argv) in &invocations {
        let Some(family) = argv.first() else { continue };
        if family.starts_with('-') {
            continue; // a bare `agentx-cli --help`
        }
        let mut page: Vec<&str> = vec![family];
        if let Some(sub) = argv.get(1).filter(|token| !token.starts_with('-')) {
            page.push(sub);
        }
        let named = page.join(" ");
        page.push("--help");

        let out = run(&home, &page);
        let printed = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(
            out.status.success(),
            "SKILL.md:{line}: `agentx-cli {named}` has no such page:\n{printed}"
        );
        for token in argv {
            if !token.starts_with("--") {
                continue;
            }
            let flag = token.split('=').next().unwrap_or(token);
            assert!(
                printed.contains(flag),
                "SKILL.md:{line}: `agentx-cli {named}` does not accept {flag}"
            );
        }
    }
}
