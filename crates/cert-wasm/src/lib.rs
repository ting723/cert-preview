//! WebAssembly bindings for `cert-core`.
//!
//! The browser and Node front ends call into the exact same `parse` +
//! `verify` + `format` stack as the CLI and any server. The only thing that
//! differs is the boundary marshalling, done here with `wasm-bindgen`.
//!
//! Every entry point takes raw bytes (a PEM file, a DER blob, a key file, or a
//! base64 blob) and returns either a typed [`Report`] object or a rendering of
//! it. Errors are marshalled as the structured `ErrorPayload` that the
//! TypeScript side (see `errors.ts`) can branch on by `code`.
//!
//! `now` (Unix seconds, used for validity) is a **required** argument: the
//! `wasm32-unknown-unknown` target has no system clock, so the caller must
//! supply it. The TypeScript loaders default it to `Date.now() / 1000` when
//! the caller omits it, keeping the JS API convenient without touching the
//! platform clock.

use wasm_bindgen::prelude::*;

use cert_core::model::Report;
use cert_core::{parse_bundle, verify_report, ErrorPayload, Result as CoreResult};

#[wasm_bindgen(start)]
pub fn start() {
    // Forward Rust panics to the browser/Node console instead of trapping.
    #[cfg(feature = "console_error_panic_hook")]
    {
        console_error_panic_hook::set_once();
    }
}

/// Parse and evaluate a single input, returning the full [`Report`] object.
///
/// `now` is the Unix timestamp (seconds) used for validity — it is required
/// because the wasm target has no system clock. `hostname`, when given, is
/// matched against each certificate's subjectAltName.
///
/// On failure a structured `ErrorPayload` is thrown (see `errors.ts`).
#[wasm_bindgen]
pub fn inspect(input: &[u8], now: i64, hostname: Option<String>) -> Result<JsValue, JsValue> {
    let report = run(input, now, hostname.as_deref()).map_err(core_err)?;
    serde_wasm_bindgen::to_value(&report).map_err(ser_err)
}

/// Like [`inspect`] but returns a pretty-printed JSON string.
#[wasm_bindgen(js_name = inspectJson)]
pub fn inspect_json(input: &[u8], now: i64, hostname: Option<String>) -> Result<String, JsValue> {
    let report = run(input, now, hostname.as_deref()).map_err(core_err)?;
    cert_core::format::to_json(&report).map_err(core_err)
}

/// Like [`inspect`] but returns the multi-paragraph text rendering.
#[wasm_bindgen(js_name = inspectText)]
pub fn inspect_text(input: &[u8], now: i64, hostname: Option<String>) -> Result<String, JsValue> {
    let report = run(input, now, hostname.as_deref()).map_err(core_err)?;
    Ok(cert_core::format::text(&report))
}

/// Like [`inspect`] but returns the fixed-width chain table.
#[wasm_bindgen(js_name = inspectTable)]
pub fn inspect_table(input: &[u8], now: i64, hostname: Option<String>) -> Result<String, JsValue> {
    let report = run(input, now, hostname.as_deref()).map_err(core_err)?;
    Ok(cert_core::format::table(&report))
}

/// Shared core: parse the bytes and evaluate them at `now`.
fn run(input: &[u8], now: i64, hostname: Option<&str>) -> CoreResult<Report> {
    let bundle = parse_bundle(input)?;
    Ok(verify_report(bundle, now, hostname))
}

/// Marshal a core error into the structured `ErrorPayload` the TS side expects.
fn core_err(e: cert_core::CertError) -> JsValue {
    let payload: ErrorPayload = (&e).into();
    serde_wasm_bindgen::to_value(&payload).unwrap_or_else(|_| JsValue::from_str(&e.to_string()))
}

fn ser_err(e: serde_wasm_bindgen::Error) -> JsValue {
    JsValue::from_str(&format!("serialisation failed: {e}"))
}
