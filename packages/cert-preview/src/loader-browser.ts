import init, {
  inspect as wasmInspect,
  inspectJson as wasmInspectJson,
  inspectText as wasmInspectText,
  inspectTable as wasmInspectTable,
} from "../pkg-web/cert_wasm.js";

import { asCertViewError } from "./errors";
import type { CertViewApi, InspectOptions } from "./types";
import type { Report } from "./generated/Report";

let ready: Promise<unknown> | null = null;

function ensure(): Promise<unknown> {
  if (!ready) {
    ready = init();
  }
  return ready;
}

// The wasm API requires `now` (i64) with no system-clock fallback, so the
// loader defaults it to the current time when the caller omits it. `hostname`
// stays optional and is normalised to `string | null` for `Option<String>`.
function nowArg(now: number | undefined): bigint {
  return BigInt(now ?? Math.floor(Date.now() / 1000));
}

function hostArg(host: string | undefined): string | null {
  return host === undefined ? null : host;
}

/**
 * Initialise the WebAssembly module for the browser and return the API.
 *
 * Safe to call repeatedly: the module is initialised only once. The returned
 * functions are synchronous and throw a {@link CertViewError} on bad input.
 *
 * Requires `wasm-pack build --target web` output in `../pkg-web`.
 */
export async function load(): Promise<CertViewApi> {
  await ensure();
  const call = <T>(fn: () => T): T => {
    try {
      return fn();
    } catch (e) {
      throw asCertViewError(e);
    }
  };
  return {
    inspect: (input: Uint8Array, opts?: InspectOptions): Report =>
      call(() =>
        wasmInspect(input, nowArg(opts?.now), hostArg(opts?.hostname)) as unknown as Report,
      ),
    inspectJson: (input: Uint8Array, opts?: InspectOptions): string =>
      call(() => wasmInspectJson(input, nowArg(opts?.now), hostArg(opts?.hostname))),
    inspectText: (input: Uint8Array, opts?: InspectOptions): string =>
      call(() => wasmInspectText(input, nowArg(opts?.now), hostArg(opts?.hostname))),
    inspectTable: (input: Uint8Array, opts?: InspectOptions): string =>
      call(() => wasmInspectTable(input, nowArg(opts?.now), hostArg(opts?.hostname))),
  };
}
