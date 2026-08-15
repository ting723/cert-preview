/**
 * Example: call cert-preview from Node.js via the WASM binding.
 *
 * Exercises every public method of the Node loader:
 *   - view.inspect      -> typed Report object
 *   - view.inspectJson  -> pretty JSON string
 *   - view.inspectText  -> multi-paragraph text rendering
 *   - view.inspectTable -> fixed-width chain table
 *   - CertViewError     -> structured error (code + offset)
 *
 * Run:
 *   npx tsx examples/node/inspect.ts
 *
 * The Node wasm-pack target instantiates the module synchronously at import
 * time, so `load()` resolves immediately and every call is synchronous.
 */
import { readFileSync } from "node:fs";
import { load } from "../../packages/cert-preview/src/loader-node.ts";
import { CertViewError } from "../../packages/cert-preview/src/errors.ts";

const repo = new URL("../../", import.meta.url);
const read = (rel: string) => readFileSync(new URL(rel, repo));

async function main(): Promise<void> {
  const view = await load();
  const now = 1_717_200_000; // 2024-06-01, fixed for reproducible output

  // --- Scenario 1: a full certificate chain -------------------------------
  const chain = new Uint8Array(read("fixtures/certs/chain.pem"));
  console.log("# inspect() returns a typed Report object");
  const report = view.inspect(chain, { now });
  console.log("  items in bundle :", report.bundle.items.length);
  console.log("  evaluatedAt     :", report.evaluatedAt);

  console.log("\n# inspectJson() — machine-readable");
  console.log(view.inspectJson(chain, { now }).slice(0, 160) + " …");

  console.log("\n# inspectText() — human-readable");
  console.log(view.inspectText(chain, { now }));

  console.log("# inspectTable() — chain overview");
  console.log(view.inspectTable(chain, { now }));

  // --- Scenario 2: hostname match against SAN -----------------------------
  const rsaLeaf = new Uint8Array(read("fixtures/certs/rsa-leaf.pem"));
  const matched = view.inspect(rsaLeaf, { now, hostname: "www.example.com" });
  const hm = matched.certificates[0]?.hostname;
  console.log("\n# hostname match: www.example.com vs SAN *.example.com");
  console.log(`  matched=${hm?.matched} via ${hm?.matchedName}`);

  // --- Scenario 3: EC certificate -----------------------------------------
  const ecLeaf = new Uint8Array(read("fixtures/certs/ec-leaf.pem"));
  const ec = view.inspect(ecLeaf, { now });
  const ecItem = ec.bundle.items.find((it) => it.kind === "certificate");
  console.log("\n# EC certificate signature algorithm:", ecItem?.signatureAlgorithm?.name);
  console.log("  public key algorithm            :", ecItem?.publicKey?.algorithm?.name);

  // --- Scenario 4: private key (metadata only, no key material) ----------
  const key = new Uint8Array(read("fixtures/keys/rsa-2048.pkcs8.pem"));
  const keyReport = view.inspect(key, { now });
  const keyItem = keyReport.bundle.items.find((it) => it.kind === "privateKey");
  console.log(
    "\n# private key metadata:",
    keyItem?.format,
    "bits=",
    keyItem?.keySizeBits,
    "algo=",
    keyItem?.algorithm?.name,
  );

  // --- Scenario 5: structured error on bad input --------------------------
  console.log("\n# bad input -> structured CertViewError");
  try {
    view.inspect(new TextEncoder().encode("this is not a certificate"), { now });
  } catch (e) {
    if (e instanceof CertViewError) {
      console.log(`  code=${e.code} offset=${e.offset} message=${e.message}`);
    } else {
      throw e;
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
