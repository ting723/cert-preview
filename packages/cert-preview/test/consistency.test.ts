import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { load } from "../src/loader-node";

/**
 * Cross-platform consistency check.
 *
 * The Rust side snapshots `cert_core::format::to_json` output (the exact code
 * path the WASM `inspectJson` calls) for every fixture at a pinned clock. This
 * test runs the compiled WebAssembly module over the same fixtures and asserts
 * the parsed object is identical — proving the browser/Node front end and the
 * CLI/server share one source of truth.
 */

// Pinned clock (2024-06-01) — must match crates/cert-core/tests/snapshot.rs.
const NOW = 1_717_200_000;

// Mirrors the allow-list in crates/cert-core/tests/snapshot.rs.
const FIXTURES: readonly string[] = [
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

// Must match `snap_name` in crates/cert-core/tests/snapshot.rs.
function snapName(rel: string): string {
  return rel.replace(/[\/.]/g, "_") + ".json";
}

test("wasm output matches rust snapshot baseline", async () => {
  const view = await load();
  for (const rel of FIXTURES) {
    await test(rel, () => {
      const bytes = readFileSync(new URL(`../../../fixtures/${rel}`, import.meta.url));
      const actual = JSON.parse(view.inspectJson(new Uint8Array(bytes), { now: NOW }));
      const expected = JSON.parse(
        readFileSync(
          new URL(`../../../fixtures/snapshots/${snapName(rel)}`, import.meta.url),
          "utf8",
        ),
      );
      assert.deepStrictEqual(actual, expected, `wasm/rust mismatch for ${rel}`);
    });
  }
});
