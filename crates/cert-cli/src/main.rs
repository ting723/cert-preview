//! `certview` — a command line certificate and key inspector.
//!
//! It is a thin front end over `cert-core`: read bytes, parse, evaluate at the
//! current (or a supplied) time, and render. The same `Report` the browser and
//! server receive is what the terminal prints, so the three never diverge.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, ValueEnum};
use cert_core::model::Report;
use cert_core::{format, parse_bundle, verify_report, Result};

/// Inspect X.509 certificates and private/public keys.
#[derive(Parser, Debug)]
#[command(name = "certview", version, about)]
struct Cli {
    /// Input files (PEM, DER or key files). Reads from stdin when omitted.
    #[arg(value_name = "FILE")]
    paths: Vec<PathBuf>,

    /// Output format.
    #[arg(short = 'f', long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Match this hostname against each certificate's subjectAltName.
    #[arg(short = 'H', long)]
    hostname: Option<String>,

    /// Evaluate validity at this Unix timestamp instead of the current time.
    #[arg(long)]
    now: Option<i64>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Text,
    Table,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let now = cli.now.unwrap_or_else(now_unix);

    let inputs = match read_inputs(&cli.paths) {
        Ok(inputs) => inputs,
        Err(e) => {
            eprintln!("certview: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = false;
    for (name, bytes) in inputs {
        match run_one(&name, &bytes, now, &cli.hostname, cli.format) {
            Ok(out) => print!("{out}"),
            Err(e) => {
                failed = true;
                eprintln!("certview: {name}: {e}");
            }
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Parse, evaluate and render a single input.
fn run_one(_name: &str, bytes: &[u8], now: i64, hostname: &Option<String>, fmt: Format) -> Result<String> {
    let bundle = parse_bundle(bytes)?;
    let report = verify_report(bundle, now, hostname.as_deref());
    Ok(render(&report, fmt))
}

fn render(report: &Report, fmt: Format) -> String {
    match fmt {
        Format::Text => format::text(report),
        Format::Table => format::table(report),
        Format::Json => format::to_json(report).unwrap_or_else(|e| {
            // JSON serialisation should never fail for the in-memory model.
            format!("certview: json error: {e}\n")
        }),
    }
}

/// Collect inputs: stdin when no paths are given, otherwise every file.
fn read_inputs(paths: &[PathBuf]) -> std::io::Result<Vec<(String, Vec<u8>)>> {
    if paths.is_empty() {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return Ok(vec![("(stdin)".to_string(), buf)]);
    }
    let mut out = Vec::with_capacity(paths.len());
    for p in paths {
        let mut buf = Vec::new();
        std::fs::File::open(p)?.read_to_end(&mut buf)?;
        let label = p.display().to_string();
        out.push((label, buf));
    }
    Ok(out)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
