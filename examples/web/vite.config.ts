import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  // Relative asset paths so the built `dist/index.html` also works when opened
  // from any sub-path, not just at the site root.
  base: "./",
  // The demo imports the public package `cert-preview`, which (via the alias
  // below) resolves into `packages/cert-preview/...` and the compiled wasm in
  // `pkg-web/`. Those files sit outside this demo's directory, so Vite's
  // default fs guard would 403 the wasm fetch in dev. We point `fs.allow` at
  // the repo root and relax `strict` so the dev server can serve them.
  server: {
    fs: {
      allow: [resolve(here, "..", "..")],
      strict: false,
    },
  },
  // Resolve the bare `cert-preview` specifier to the package source so the
  // demo imports exactly what consumers would (`import { load } from "cert-preview"`).
  resolve: {
    alias: {
      "cert-preview": resolve(here, "..", "..", "packages/cert-preview/src/index.ts"),
    },
  },
  build: {
    target: "es2022",
    outDir: "dist",
  },
});
