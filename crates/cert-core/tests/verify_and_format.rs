//! Verify + format layer tests against the committed fixtures.
//!
//! The clock is pinned to 2024-06-01T00:00:00Z (Unix 1717200000) so validity,
//! chain and hostname results are deterministic and reproducible in CI and in
//! the browser snapshot tests.

use cert_core::model::*;
use cert_core::{parse_bundle, verify_report};

const NOW: i64 = 1_717_200_000; // 2024-06-01T00:00:00Z

fn fixture(path: &str) -> Vec<u8> {
    let full = format!("{}/../../fixtures/{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("read {full}: {e}"))
}

fn report(path: &str) -> Report {
    let raw = fixture(path);
    let bundle = parse_bundle(&raw).unwrap_or_else(|e| panic!("parse {path}: {e:?}"));
    verify_report(bundle, NOW, None)
}

fn report_with_host(path: &str, host: &str) -> Report {
    let raw = fixture(path);
    let bundle = parse_bundle(&raw).unwrap();
    verify_report(bundle, NOW, Some(host))
}

#[test]
fn chain_pem_links_to_a_complete_root() {
    let r = report("certs/chain.pem");
    assert_eq!(r.bundle.chains.len(), 1);
    let chain = &r.bundle.chains[0];
    assert!(chain.complete);
    assert_eq!(chain.len(), 3);
    // Leaf first, root last.
    assert_eq!(chain.leaf(), Some(0));
    assert_eq!(chain.root(), Some(2));
    assert!(chain.diagnostics.is_empty());
}

#[test]
fn shuffled_chain_links_identically() {
    let r = report("certs/chain-shuffled.pem");
    assert_eq!(r.bundle.chains.len(), 1);
    let chain = &r.bundle.chains[0];
    assert!(chain.complete);
    assert_eq!(chain.len(), 3);
    // Order is reconstructed leaf-first regardless of input order.
    assert_eq!(chain.indices, vec![1, 2, 0]);
}

#[test]
fn incomplete_chain_is_flagged() {
    let r = report("certs/chain-incomplete.pem");
    assert_eq!(r.bundle.chains.len(), 1);
    let chain = &r.bundle.chains[0];
    assert!(!chain.complete);
    assert!(chain
        .diagnostics
        .iter()
        .any(|d| d.code == "CHAIN_INCOMPLETE"));
}

#[test]
fn leaf_is_valid_at_pinned_time() {
    let r = report("certs/leaf.pem");
    let st = &r.certificates[0];
    assert_eq!(st.validity.state, ValidityState::Valid);
    assert!(st.validity.seconds_remaining > 0);
    // not_after 2025-01-01, so ~214 days remain.
    assert!(st.validity.seconds_remaining > 200 * 86_400);
}

#[test]
fn expired_certificate_is_detected_with_future_clock() {
    // Use a clock well past 2034-01-01 to flip rsa-leaf into Expired.
    let raw = fixture("certs/rsa-leaf.pem");
    let bundle = parse_bundle(&raw).unwrap();
    let r = verify_report(bundle, 2_200_000_000, None);
    assert_eq!(r.certificates[0].validity.state, ValidityState::Expired);
    assert!(r.certificates[0].validity.seconds_remaining < 0);
}

#[test]
fn not_yet_valid_certificate_is_detected_with_past_clock() {
    let raw = fixture("certs/rsa-leaf.pem");
    let bundle = parse_bundle(&raw).unwrap();
    let r = verify_report(bundle, 1_700_000_000, None); // before 2024-01-01
    assert_eq!(r.certificates[0].validity.state, ValidityState::NotYetValid);
}

#[test]
fn hostname_matches_dns_san() {
    let r = report_with_host("certs/leaf.pem", "www.example.org");
    let h = r.certificates[0].hostname.as_ref().unwrap();
    assert!(h.matched);
    assert_eq!(h.matched_name.as_deref(), Some("DNS:www.example.org"));
}

#[test]
fn hostname_wildcard_matches_single_label() {
    let r = report_with_host("certs/rsa-leaf.pem", "sub.example.com");
    let h = r.certificates[0].hostname.as_ref().unwrap();
    // rsa-leaf SAN has DNS:*.example.com.
    assert!(h.matched, "wildcard should match one label");
    assert_eq!(h.matched_name.as_deref(), Some("DNS:*.example.com"));
}

#[test]
fn hostname_does_not_match_unrelated() {
    let r = report_with_host("certs/leaf.pem", "evil.example.com");
    let h = r.certificates[0].hostname.as_ref().unwrap();
    assert!(!h.matched);
}

#[test]
fn report_is_healthy_for_well_formed_chain() {
    let r = report("certs/chain.pem");
    assert!(r.is_healthy());
}

#[test]
fn json_round_trips_through_serde() {
    let r = report("certs/chain.pem");
    let json = cert_core::format::to_json(&r).expect("serialise");
    // The JSON must parse back into an equivalent report.
    let back: Report = serde_json::from_str(&json).expect("parse json");
    assert_eq!(back.certificates.len(), r.certificates.len());
    assert_eq!(back.bundle.chains.len(), r.bundle.chains.len());
}

#[test]
fn text_and_table_render_without_panicking() {
    let r = report("certs/rsa-leaf.pem");
    let t = cert_core::format::text(&r);
    assert!(t.contains("Certificate 0"));
    assert!(t.contains("example.com"));
    let tbl = cert_core::format::table(&r);
    assert!(tbl.contains("SUBJECT"));
    assert!(tbl.contains("example.com"));
}
