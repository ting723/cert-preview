//! Example: drive `cert-core` directly as a Rust library.
//!
//! This exercises every public surface of the core crate:
//!   - `input::detect`   — sniff PEM / DER / base64 and count DER objects
//!   - `parse_bundle`    — decode into the shared model
//!   - `verify_report`   — evaluate at a timestamp (+ optional hostname)
//!   - `format::text` / `format::table` / `format::to_json` — three renderers
//!
//! Run:
//!   cargo run -p cert-core --example inspect -- fixtures/certs/chain.pem
//!   cargo run -p cert-core --example inspect -- fixtures/certs/rsa-leaf.pem --hostname www.example.com
//!   cat fixtures/certs/leaf.der | cargo run -p cert-core --example inspect -- --now 1717200000

use std::io::Read;
use std::path::PathBuf;

use cert_core::input::detect;
use cert_core::{format, parse_bundle, verify_report};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut path: Option<PathBuf> = None;
    let mut hostname: Option<String> = None;
    let mut now: Option<i64> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--hostname" => {
                hostname = args.get(i + 1).cloned();
                i += 2;
            }
            "--now" => {
                now = args.get(i + 1).and_then(|s| s.parse().ok());
                i += 2;
            }
            other if !other.starts_with("--") => {
                path = Some(PathBuf::from(other));
                i += 1;
            }
            _ => i += 1,
        }
    }

    // Collect input: a file argument, or stdin when none is given.
    let mut buf = Vec::new();
    if let Some(p) = &path {
        std::fs::File::open(p)?.read_to_end(&mut buf)?;
    } else {
        std::io::stdin().read_to_end(&mut buf)?;
    }

    // 1) Format detection (the input layer).
    let detected = detect(&buf)?;
    println!("detected source format : {:?}", detected.format);
    println!("DER objects found     : {}", detected.objects.len());

    // 2) Parse into the shared model.
    let bundle = parse_bundle(&buf)?;

    // 3) Verify at the supplied time (or "now").
    let now = now.unwrap_or_else(now_unix);
    let report = verify_report(bundle, now, hostname.as_deref());

    // 4) Render in every format. The three outputs describe the same data.
    println!("\n=== TEXT ===\n{}", format::text(&report));
    println!("=== TABLE ===\n{}", format::table(&report));
    println!("=== JSON ===\n{}", format::to_json(&report)?);
    Ok(())
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
