import type { Report } from "./generated/Report";

/**
 * Options accepted by every entry point.
 *
 * `now` lets the caller pin the clock (useful for reproducible output and for
 * testing); when omitted the current time is used. `hostname` triggers a SAN
 * match recorded in each certificate's status.
 */
export interface InspectOptions {
  /** Unix timestamp in seconds used to evaluate validity. Defaults to now. */
  now?: number;
  /** Hostname to match against each certificate's subjectAltName. */
  hostname?: string;
}

/**
 * The full public surface of the WebAssembly module.
 *
 * Every method is synchronous: the module is initialised once via `load()`,
 * after which calls are plain function invocations. Input is raw bytes (a PEM
 * file, a DER blob, a key file or a base64 blob). Text input must be encoded
 * first, e.g. `new TextEncoder().encode(pemString)`.
 */
export interface CertViewApi {
  /** Parse and evaluate, returning the typed {@link Report} object. */
  inspect(input: Uint8Array, opts?: InspectOptions): Report;
  /** Parse and evaluate, returning a pretty-printed JSON string. */
  inspectJson(input: Uint8Array, opts?: InspectOptions): string;
  /** Parse and evaluate, returning the multi-paragraph text report. */
  inspectText(input: Uint8Array, opts?: InspectOptions): string;
  /** Parse and evaluate, returning the fixed-width chain table. */
  inspectTable(input: Uint8Array, opts?: InspectOptions): string;
}
