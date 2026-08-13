import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // libsodium-wrappers-sumo 0.7.16 ships a broken ESM entry (imports a file the
      // npm package excludes). Point at the CJS build. See web/vitest.config.ts.
      "libsodium-wrappers-sumo": fileURLToPath(
        new URL("./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js", import.meta.url),
      ),
    },
  },
  server: {
    proxy: {
      // Dev: proxy API + WS to a locally-running server.
      "/api": { target: "http://127.0.0.1:8080", ws: true, changeOrigin: true },
      "/healthz": "http://127.0.0.1:8080",
    },
  },
  build: {
    outDir: "dist",
    rollupOptions: {
      output: {
        // Immutable versioned bundles (spec 05 T6 mitigation).
        entryFileNames: "assets/[name].[hash].js",
        chunkFileNames: "assets/[name].[hash].js",
        assetFileNames: "assets/[name].[hash].[ext]",
        // quality-perf--2: the whole client shipped as ONE 1.44 MiB entry chunk, ~1.1 MiB of
        // which is vendored ballast that does not change between releases — libsodium-sumo (the
        // CJS build the alias above forces, with the wasm embedded as an escaped string) and
        // React. In one chunk their bytes carry the ENTRY's content hash, so every app edit
        // invalidated all 442 KiB gzip for every client on every release, and the unlock screen
        // waited on the whole parse. Split by CHANGE RATE, not by feature: the two vendored
        // chunks keep their hashes across a polish release, so only the ~89 KiB gzip app chunk
        // is re-downloaded (452 → 89 KiB per release; the cold-start total is unchanged).
        // Static, not dynamic import(): the crypto has to be present before the first unlock,
        // and the self-contained/CSP posture rules out anything CDN-shaped.
        // psl: the vendored public-suffix snapshot (pslData.ts, ~144 KiB of string literal).
        // This comment used to say the blob was in no web bundle at all, because psl.ts had no
        // importer outside the tests. That stopped being true on 2026-08-12: the duplicate-entry
        // checker keys clusters by registrable domain, so Vault → Health → duplicates → psl →
        // pslData is a fully static chain into the ENTRY chunk (audit F13). It is the purest
        // "never changes between releases" data in the tree riding the highest-churn chunk —
        // exactly inverted from what this split is for. Measured with `npx vite build`
        // 2026-08-13: entry 452.46 kB raw / 138.97 kB gzip before, 308.54 / 92.47 after, the
        // snapshot now its own hash-stable 143.97 / 44.84 chunk. Cold-start bytes are unchanged;
        // a polish release re-downloads ~92 kB gzip instead of ~139.
        manualChunks: {
          sodium: ["libsodium-wrappers-sumo"],
          react: ["react", "react-dom"],
          psl: [fileURLToPath(new URL("./src/vault/pslData.ts", import.meta.url))],
        },
      },
    },
  },
});
