import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  // Relative asset paths so the built `dist/index.html` works from any sub-path.
  base: "./",
  plugins: [react()],
  // The demo imports the public package `cert-preview`, whose wasm lives in
  // `packages/cert-preview/pkg-web/` (outside this demo dir). Relax Vite's fs
  // guard so the dev server can serve it.
  server: {
    fs: {
      allow: [resolve(here, "..", "..")],
      strict: false,
    },
  },
  // Resolve the bare `cert-preview` specifier to the package source.
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
