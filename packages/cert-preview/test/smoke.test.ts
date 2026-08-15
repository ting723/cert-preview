import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { load } from "../src/loader-node";
import { CertViewError } from "../src/errors";

const leafPem = readFileSync(new URL("../../../fixtures/certs/leaf.pem", import.meta.url));
const chainPem = readFileSync(new URL("../../../fixtures/certs/chain.pem", import.meta.url));

test("inspect returns a typed report for a leaf certificate", async () => {
  const view = await load();
  const report = view.inspect(new Uint8Array(leafPem));
  assert.ok(report.bundle.items.length >= 1, "expected at least one parsed item");
  assert.ok(Array.isArray(report.certificates));
  assert.equal(report.evaluatedAt > 0, true);
});

test("inspect_table and inspect_json stay consistent with inspect", async () => {
  const view = await load();
  const report = view.inspect(new Uint8Array(chainPem));
  const json = view.inspectJson(new Uint8Array(chainPem));
  const table = view.inspectTable(new Uint8Array(chainPem));
  const reparsed = JSON.parse(json);
  assert.equal(reparsed.bundle.items.length, report.bundle.items.length);
  assert.match(table, /SUBJECT/);
});

test("bad input throws a typed CertViewError", async () => {
  const view = await load();
  assert.throws(
    () => view.inspect(new Uint8Array([1, 2, 3, 4])),
    (e) => e instanceof CertViewError,
  );
});
