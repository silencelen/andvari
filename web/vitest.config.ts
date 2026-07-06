import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // libsodium-wrappers-sumo 0.7.16 ships an ESM entry that imports
      // ./libsodium-sumo.mjs — a file excluded from the npm package. Point at the
      // CJS build (which resolves the libsodium-sumo dependency normally). The
      // exports map blocks subpath imports, hence the absolute path.
      "libsodium-wrappers-sumo": fileURLToPath(
        new URL("./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js", import.meta.url),
      ),
    },
  },
  test: {
    environment: "node",
  },
});
