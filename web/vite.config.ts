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
      },
    },
  },
});
