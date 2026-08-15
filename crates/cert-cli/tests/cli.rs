//! End-to-end checks for the `certview` binary.

use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_certview");

fn fixture(path: &str) -> Vec<u8> {
    let full = format!("{}/../../fixtures/{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("read {full}: {e}"))
}

/// Resolve a workspace-relative fixture path to an absolute one. `cargo test`
/// runs the child from the crate directory, so `fixtures/...` would not
/// resolve from there; anchor it at the workspace root instead.
fn cert_path(name: &str) -> String {
    format!("{}/../../fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

fn run(args: &[&str], stdin: Option<&[u8]>) -> (bool, String) {
    let mut cmd = Command::new(BIN);
    cmd.args(args);
    // Capture stdout/stderr so `wait_with_output` actually collects them; an
    // inherited stream comes back as empty output.
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn certview");
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input)
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait certview");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn table_shows_chain_subjects() {
    let p = cert_path("certs/chain.pem");
    let (ok, out) = run(&[p.as_str(), "--format", "table"], None);
    assert!(ok);
    assert!(out.contains("SUBJECT"), "header missing:\n{out}");
    assert!(out.contains("Example Root CA"), "root missing:\n{out}");
    assert!(out.contains("Example Issuing CA"));
    assert!(out.contains("www.example.org"));
}

#[test]
fn json_output_is_machine_readable() {
    let p = cert_path("certs/leaf.pem");
    let (ok, out) = run(&[p.as_str(), "--format", "json"], None);
    assert!(ok);
    // Valid JSON and contains the leaf CN.
    let value: serde_json::Value = serde_json::from_str(&out).expect("valid json");
    let text = serde_json::to_string(&value).unwrap();
    assert!(text.contains("www.example.org"));
}

#[test]
fn stdin_is_read_when_no_path_given() {
    let bytes = fixture("certs/ec-leaf.pem");
    let (ok, out) = run(&["--format", "text"], Some(&bytes));
    assert!(ok);
    assert!(out.contains("ec.example.com"));
    assert!(out.contains("prime256v1"));
}

#[test]
fn hostname_match_is_reported_in_text() {
    let p = cert_path("certs/rsa-leaf.pem");
    let (ok, out) = run(
        &[p.as_str(), "--format", "text", "-H", "www.example.com"],
        None,
    );
    assert!(ok);
    // rsa-leaf SAN has DNS:*.example.com, so www.example.com matches.
    assert!(out.contains("matches"), "expected a hostname match:\n{out}");
}

#[test]
fn unknown_or_bad_input_exits_nonzero() {
    let (ok, _out) = run(&["/nonexistent/path.pem"], None);
    assert!(!ok);
}
