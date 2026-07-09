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
    "kdf-worker": "src/kdf-worker.ts",
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

// TARGET=firefox → the Firefox manifest (background.scripts event page); default = Chrome (SW).
const firefox = process.env.TARGET === "firefox";
cpSync(firefox ? "manifest.firefox.json" : "manifest.json", "dist/manifest.json");
cpSync("popup.html", "dist/popup.html");
console.log(`built → dist/ (${firefox ? "Firefox" : "Chrome"}; Load unpacked: extension/dist)`);
