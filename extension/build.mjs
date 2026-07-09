// Bundles the extension's TS entry points → dist/, and copies the static files. The manifest
// references dist-relative names, so `dist/` is what you "Load unpacked". @noble is bundled in
// (pure JS, no WASM asset) — nothing loads over the network, and no eval, so the MV3 CSP is happy.
import * as esbuild from "esbuild";
import { cpSync, mkdirSync } from "node:fs";

mkdirSync("dist", { recursive: true });

await esbuild.build({
  entryPoints: {
    background: "src/background.ts",
    content: "src/content.ts",
    popup: "src/popup.ts",
  },
  bundle: true,
  format: "esm",
  target: "es2022",
  outdir: "dist",
  logLevel: "info",
  // Keep it debuggable during the spike; flip to true for a real release.
  minify: false,
  sourcemap: true,
});

cpSync("manifest.json", "dist/manifest.json");
cpSync("popup.html", "dist/popup.html");
console.log("built → dist/ (Load unpacked: extension/dist)");
