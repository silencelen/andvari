// Bundles the extension's TS entry points → dist/, and copies the static files. The manifest
// references dist-relative names, so `dist/` is what you "Load unpacked". @noble is bundled in
// (pure JS, no WASM asset) — nothing loads over the network, and no eval, so the MV3 CSP is happy.
import * as esbuild from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";

// RELEASE=1 → minified, no sourcemaps (what gets zipped for /downloads).
// Default = debuggable dev build for load-unpacked iteration.
const release = process.env.RELEASE === "1";

rmSync("dist", { recursive: true, force: true }); // no stale entry/sourcemap leftovers in the zip
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
  minify: release,
  sourcemap: !release,
});

// TARGET=firefox → the Firefox manifest (background.scripts event page); default = Chrome (SW).
const firefox = process.env.TARGET === "firefox";
cpSync(firefox ? "manifest.firefox.json" : "manifest.json", "dist/manifest.json");
cpSync("popup.html", "dist/popup.html");
cpSync("popup.css", "dist/popup.css"); // the ported treasury theme; popup.html <link>s it
cpSync("icons", "dist/icons", { recursive: true }); // both manifests reference icons/icon{16,32,48,128}.png
cpSync("INSTALL.txt", "dist/INSTALL.txt"); // tester-facing steps travel inside the zip
console.log(`built → dist/ (${firefox ? "Firefox" : "Chrome"}${release ? ", release" : ""}; Load unpacked: extension/dist)`);
