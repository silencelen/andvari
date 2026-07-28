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
        // NOT split out: pslData (~144 KiB). It is in no web bundle at all — psl.ts is its only
        // importer and nothing in the app imports psl.ts (the eTLD+1 resolver is autofill-only,
        // and the web client has no autofill), so naming it here only mints an empty chunk.
        manualChunks: {
          sodium: ["libsodium-wrappers-sumo"],
          react: ["react", "react-dom"],
        },
      },
    },
  },
});
