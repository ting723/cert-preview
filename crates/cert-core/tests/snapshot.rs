//! Snapshot the JSON rendering of every fixture so the Rust core and the
//! WebAssembly/Node build can be checked against one another.
//!
//! This is the "single source of truth" half of the cross-platform
//! consistency check: it captures `cert_core::format::to_json` output (the
//! exact code path the WASM `inspectJson` calls) for each fixture at a pinned
//! clock. The Node test then compares the WASM output byte-for-byte against
//! these files.
//!
//! Run with `UPDATE_SNAPSHOTS=1` to regenerate `fixtures/snapshots/*.json`.

use std::path::Path;

use cert_core::format::to_json;
use cert_core::{parse_bundle, verify_report};

/// Pinned clock (2024-06-01) so snapshots are stable across runs and machines.
const NOW: i64 = 1_717_200_000;

const FIXTURES: &[&str] = &[
    "certs/chain.pem",
    "certs/chain-incomplete.pem",
    "certs/chain-shuffled.pem",
    "certs/ec-leaf.pem",
    "certs/igca.der",
    "certs/inter.pem",
    "certs/leaf.der",
    "certs/leaf.pem",
    "certs/root.pem",
    "certs/rsa-leaf.der",
    "certs/rsa-leaf.pem",
    "keys/ec-p256.pkcs8.pem",
    "keys/ec-p256.sec1.pem",
    "keys/ec-p256.spki.pem",
    "keys/ed25519.pkcs8.pem",
    "keys/ed25519.spki.pem",
    "keys/rsa-2048.encrypted.pem",
    "keys/rsa-2048.pkcs1-pub.pem",
    "keys/rsa-2048.pkcs1.pem",
    "keys/rsa-2048.pkcs8.pem",
    "keys/rsa-2048.spki.pem",
];

fn fixture_dir() -> String {
    format!("{}/../../fixtures", env!("CARGO_MANIFEST_DIR"))
}

/// Stable snapshot filename derived from the fixture's relative path, so that
/// `leaf.pem` and `leaf.der` (which share a file stem) never collide.
fn snap_name(rel: &str) -> String {
    let collapsed = rel.replace(['/', '.'], "_");
    format!("{}.json", collapsed)
}

fn check(rel: &str, actual: &str) {
    let snap_dir = format!("{}/snapshots", fixture_dir());
    let path = format!("{}/{}", snap_dir, snap_name(rel));

    let update = std::env::var("UPDATE_SNAPSHOTS").is_ok();
    if update || !Path::new(&path).exists() {
        std::fs::create_dir_all(&snap_dir).expect("create snapshots dir");
        std::fs::write(&path, actual).unwrap_or_else(|e| panic!("write {path}: {e}"));
        eprintln!("snapshot {} -> {}", rel, path);
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    assert_eq!(
        actual, expected,
        "snapshot mismatch for {rel} (run with UPDATE_SNAPSHOTS=1 to regenerate)"
    );
}

#[test]
fn snapshots_match_across_runs() {
    let base = fixture_dir();
    let mut count = 0;
    for rel in FIXTURES {
        let full = format!("{}/{}", base, rel);
        let bytes = std::fs::read(&full).unwrap_or_else(|e| panic!("read {full}: {e}"));
        let bundle = parse_bundle(&bytes).unwrap_or_else(|e| panic!("{rel}: parse failed: {e}"));
        let report = verify_report(bundle, NOW, None);
        let json = to_json(&report).unwrap_or_else(|e| panic!("{rel}: serialise failed: {e}"));

        check(rel, &json);
        count += 1;
    }
    assert!(count == FIXTURES.len(), "expected to snapshot every fixture");
}
