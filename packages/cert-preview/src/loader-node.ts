import {
  inspect as wasmInspect,
  inspectJson as wasmInspectJson,
  inspectText as wasmInspectText,
  inspectTable as wasmInspectTable,
} from "../pkg-node/cert_wasm.js";

import { asCertViewError } from "./errors";
import type { CertViewApi, InspectOptions } from "./types";
import type { Report } from "./generated/Report";

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
 * Initialise the WebAssembly module for Node.js and return the API.
 *
 * The `nodejs` wasm-pack target embeds and instantiates the wasm synchronously
 * at import time, so no async `init()` is required — the exported functions are
 * ready immediately. Each call is wrapped so a core rejection becomes a typed
 * {@link CertViewError}.
 *
 * Requires `wasm-pack build --target nodejs` output in `../pkg-node`.
 */
export async function load(): Promise<CertViewApi> {
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
