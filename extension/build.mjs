// Bundles the extension's TS entry points → dist/, and copies the static files. The manifest
// references dist-relative names, so `dist/` is what you "Load unpacked". @noble is bundled in
// (pure JS, no WASM asset) — nothing loads over the network, and no eval, so the MV3 CSP is happy.
import * as esbuild from "esbuild";
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// RELEASE=1 → minified, no sourcemaps (what gets zipped for /downloads).
// Default = debuggable dev build for load-unpacked iteration.
const release = process.env.RELEASE === "1";
// TARGET=firefox → the Firefox manifest (background.scripts event page); TARGET=safari → the Safari
// manifest (non-persistent page, for the iOS app's Safari Web Extension); default = Chrome (SW).
const target = process.env.TARGET === "firefox" || process.env.TARGET === "safari" ? process.env.TARGET : "chrome";

rmSync("dist", { recursive: true, force: true }); // no stale entry/sourcemap leftovers in the zip
mkdirSync("dist", { recursive: true });

// The Safari build ships inside the App Store app and has no default server: it uses the server chosen in the andvari
// app, and none until the app names one. The reference origin in serverurl.ts is replaced, in that build only, by a
// name that can never resolve (RFC 6761 `.invalid`), which the worker treats as "no server chosen"; the build fails if
// the reference origin is left anywhere in dist/ (checked at the end).
const REFERENCE_ORIGIN = "https://andvari.monahanhosting.com";
const NO_SERVER_ORIGIN = "https://no-server.invalid";
const noDefaultServer = {
  name: "safari-no-default-server",
  setup(build) {
    build.onLoad({ filter: /[\\/]src[\\/]serverurl\.ts$/ }, (args) => {
      const source = readFileSync(args.path, "utf8");
      const line = `export const DEFAULT_SERVER_URL = "${REFERENCE_ORIGIN}";`;
      if (!source.includes(line)) throw new Error("serverurl.ts no longer declares DEFAULT_SERVER_URL the way the Safari build expects");
      return { contents: source.replace(line, `export const DEFAULT_SERVER_URL = "${NO_SERVER_ORIGIN}";`), loader: "ts" };
    });
  },
};

await esbuild.build({
  entryPoints: {
    background: "src/background.ts",
    content: "src/content.ts",
    popup: "src/popup.ts",
    options: "src/options.ts", // wave-3 endpoint switcher (options_ui in both manifests)
    connector: "src/connector.ts", // 0.17.0 biometric quick-unlock WebAuthn ceremony window
    offscreen: "src/offscreen.ts", // Chrome clipboard-clear backstop document (E1-4); inert on Firefox
    "kdf-worker": "src/kdf-worker.ts",
  },
  bundle: true,
  // Safari on iOS did not load the ES-module background page (2026-11), so that build is classic scripts throughout:
  // each entry is one self-contained IIFE, which also loads unchanged from the pages' <script type="module"> tags.
  format: target === "safari" ? "iife" : "esm",
  target: "es2022",
  outdir: "dist",
  logLevel: "info",
  minify: release,
  sourcemap: !release,
  // buildtarget.ts reads this: the App Store-distributed Safari build has no self-update channel.
  define: { __ANDVARI_TARGET__: JSON.stringify(target) },
  plugins: target === "safari" ? [noDefaultServer] : [],
});

cpSync({ firefox: "manifest.firefox.json", safari: "manifest.safari.json", chrome: "manifest.json" }[target], "dist/manifest.json");
if (target === "safari") {
  // iOS presents the popup as a sheet as wide as the screen: the Safari build's popup gets a viewport and a stylesheet
  // that lets it fill the sheet (popup.safari.css). The other builds keep the fixed-width desktop popup untouched.
  const html = readFileSync("popup.html", "utf8");
  const link = '<link rel="stylesheet" href="popup.css" />';
  if (!html.includes(link)) throw new Error("popup.html no longer links popup.css the way the Safari build expects");
  writeFileSync(
    "dist/popup.html",
    html.replace(link, `<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />\n    ${link}\n    <link rel="stylesheet" href="popup.safari.css" />`),
  );
  cpSync("popup.safari.css", "dist/popup.safari.css");
} else {
  cpSync("popup.html", "dist/popup.html");
}
cpSync("options.html", "dist/options.html"); // wave-3 options_ui page; <link>s popup.css for the theme
cpSync("popup.css", "dist/popup.css"); // the ported treasury theme; popup.html + options.html <link> it
cpSync("theme-boot.js", "dist/theme-boot.js"); // H134 pre-paint theme stamp; <script>d by popup/options/connector (classic, not bundled — a deferred module flashes the wrong palette)
cpSync("offscreen.html", "dist/offscreen.html"); // Chrome clipboard-clear backstop (E1-4); loads dist/offscreen.js
cpSync("connector.html", "dist/connector.html"); // 0.17.0 biometric ceremony window; loads dist/connector.js + popup.css
if (target === "safari") {
  cpSync("safari-boot.js", "dist/safari-boot.js"); // the background page's first script: load marker + error capture
  cpSync("safari-diag.js", "dist/safari-diag.js"); // the popup's reader for what it recorded
}
cpSync("icons", "dist/icons", { recursive: true }); // both manifests reference icons/icon{16,32,48,128}.png
// Tester-facing load-unpacked steps travel inside the desktop zips; the Safari build is installed with the app.
if (target !== "safari") cpSync("INSTALL.txt", "dist/INSTALL.txt");
if (target === "safari") {
  const host = new URL(REFERENCE_ORIGIN).host;
  const walk = (dir) => readdirSync(dir).flatMap((name) => (statSync(join(dir, name)).isDirectory() ? walk(join(dir, name)) : [join(dir, name)]));
  const left = walk("dist").filter((f) => !f.endsWith(".png") && readFileSync(f, "utf8").includes(host));
  if (left.length > 0) throw new Error(`the Safari build must name no default server, but ${host} is in: ${left.join(", ")}`);
}
console.log(`built → dist/ (${target}${release ? ", release" : ""}; Load unpacked: extension/dist)`);
