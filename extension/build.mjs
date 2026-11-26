// Bundles the extension's TS entry points → dist/, and copies the static files. The manifest
// references dist-relative names, so `dist/` is what you "Load unpacked". @noble is bundled in
// (pure JS, no WASM asset) — nothing loads over the network, and no eval, so the MV3 CSP is happy.
import * as esbuild from "esbuild";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { TEST_SERVER_ORIGIN } from "./src/publicinstance.testserver.ts";

// The release build is the default (round-13 review): minified, no sourcemaps, and no payment provider's test host
// (cardproviders.ts). DEBUG=1 → the readable dev build for load-unpacked iteration, which lists the providers' test hosts;
// UITEST=1 (the Safari UI-test build) lists them too. RELEASE=1 is still accepted, and changes nothing.
const debug = process.env.DEBUG === "1";
const release = !debug;
// TARGET=firefox → the Firefox manifest (background.scripts event page); TARGET=safari → the Safari
// manifest (non-persistent page, for the iOS app's Safari Web Extension); default = Chrome (SW).
const target = process.env.TARGET === "firefox" || process.env.TARGET === "safari" ? process.env.TARGET : "chrome";

rmSync("dist", { recursive: true, force: true }); // no stale entry/sourcemap leftovers in the zip
mkdirSync("dist", { recursive: true });

// No build has a default server any more (design 2026-11-15 §0.2 O, §15): every build starts at serverurl.ts's
// NO_SERVER_ORIGIN, a name that can never resolve (RFC 6761 `.invalid`), which the worker treats as "no server
// chosen". The Safari build uses the server chosen in the andvari app, and none until the app names one; it fails if
// the old reference instance's origin is left anywhere in dist/ (checked at the end).
const REFERENCE_ORIGIN = "https://andvari.monahanhosting.com";

// UITEST=1, for the iOS UI-test lane and the Safari build only: the build gets the test site's stand-in payment provider
// (cardproviders.ts), so a card fill can be tested in the simulator. Every other build defines it empty, and a Safari
// build without UITEST fails if the test origin is anywhere in dist/ (checked at the end, and again in CI on the
// release bundle).
const UITEST_PROVIDER = "https://pay.andvari-uitest.test:8443";
const uitest = process.env.UITEST === "1";
if (uitest && target !== "safari") throw new Error("UITEST=1 is for the Safari build only");

// CARDFILL (owner decision 2026-11-14): in-page card fill, per target. The Safari build ships without it (the first App
// Store version fills no card into a page) unless built with CARDFILL=1, as the UI tests and the card-preview build
// are; the Chrome and Firefox builds keep it unless built with CARDFILL=0. Without it, background.ts does not bundle the
// card path's handlers (cardfillflag.ts), which the check at the end proves of dist/background.js.
const cardFill = target === "safari" ? process.env.CARDFILL === "1" : process.env.CARDFILL !== "0";
/** Strings only the card path's handlers hold (background.ts fillCardFromPopup and revealCardForFill): a build without
 *  card fill must not contain them, a build with it must. */
const CARD_PATH_MARKERS = ["card fill wrote nothing", "no card grant"];
// And the content script's in-page card fill: the report of a frame's card forms and choice, the chip, and the fill's
// redemption (content.ts gates each on the define, so a build without card fill bundles none of them).
const CONTENT_CARD_MARKERS = ["cardFormInfo", "cardChipOffer", "Fill card with andvari", "revealCardForFill"];

// The pages the Safari build does not ship: the server is chosen in the andvari app (no Options page), quick unlock is
// the app's Face ID (no WebAuthn connector window), and Chrome's offscreen clipboard document has no use there. The
// worker refuses their messages in that build too; the check at the end fails the build if any is left in dist/.
const DESKTOP_ONLY_PAGES = ["options", "connector", "offscreen"];

// TESTBUILD=1: a person's test build of code that is not released, "andvari dev" (testbuild.test.ts), for Chrome, Edge
// and Firefox. It is chosen by this setting alone and takes no other: always minified, without source maps, with card
// fill as the target ships it. It starts at the test server, the only server host it is granted without asking
// (publicinstance.testserver.ts is bundled in place of publicinstance.ts; the manifests below); it names no update
// address and polls no update channel (background.ts); its manifest's name is "andvari dev" and says the commit it was
// built from; the popup and the options page say "andvari dev". It fails if the live server's address is anywhere in
// dist/; every other build fails if the test server's address is anywhere in it (both checked at the end). Every other
// build defines __ANDVARI_TEST_SERVER__ as null, which esbuild folds away, and bundles publicinstance.ts as before, so
// their files are byte for byte what they were before the flavour existed.
const testBuild = process.env.TESTBUILD === "1";
let testCommit = null;
if (testBuild) {
  if (target === "safari") throw new Error("TESTBUILD=1 is for the Chrome and Firefox builds only");
  if (debug || uitest || process.env.CARDFILL !== undefined) throw new Error("TESTBUILD=1 takes no DEBUG, UITEST or CARDFILL: a test build is built one way only");
  const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();
  testCommit = git("rev-parse", "--short=12", "HEAD");
  if (!/^[0-9a-f]{12}$/.test(testCommit)) throw new Error(`TESTBUILD=1: git gave no commit (${testCommit})`);
  // A tree with changes is not the commit: the version says so.
  if (git("status", "--porcelain", "--", ".") !== "") testCommit += " with changes";
}
/** Every file of dist/ but the icons. */
const distFiles = () => {
  const walk = (dir) => readdirSync(dir).flatMap((name) => (statSync(join(dir, name)).isDirectory() ? walk(join(dir, name)) : [join(dir, name)]));
  return walk("dist").filter((f) => !f.endsWith(".png"));
};

await esbuild.build({
  entryPoints: {
    background: "src/background.ts",
    content: "src/content.ts",
    popup: "src/popup.ts",
    ...(target === "safari"
      ? {}
      : {
          options: "src/options.ts", // wave-3 endpoint switcher (options_ui in the desktop manifests)
          connector: "src/connector.ts", // 0.17.0 biometric quick-unlock WebAuthn ceremony window
          offscreen: "src/offscreen.ts", // Chrome clipboard-clear backstop document (E1-4); inert on Firefox
        }),
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
  // The test build's public instance is the test server (publicinstance.testserver.ts), for every import of it.
  plugins: testBuild
    ? [
        {
          name: "test-server-instance",
          setup(b) {
            b.onResolve({ filter: /^\.\/publicinstance(\.ts)?$/ }, () => ({ path: new URL("./src/publicinstance.testserver.ts", import.meta.url).pathname }));
          },
        },
      ]
    : [],
  // buildtarget.ts reads this: the App Store-distributed Safari build has no self-update channel.
  define: {
    __ANDVARI_TARGET__: JSON.stringify(target),
    __ANDVARI_UITEST_PROVIDER__: JSON.stringify(uitest ? UITEST_PROVIDER : ""),
    // Round-12 and round-13 review: the payment providers' sandbox and test hosts are card-entry origins in the DEBUG=1
    // and UI-test builds only (cardproviders.ts CARD_PROVIDER_TEST_ORIGINS); any other build fails if one is left in it.
    __ANDVARI_PROVIDER_TEST_HOSTS__: JSON.stringify(debug || uitest),
    __ANDVARI_CARDFILL__: JSON.stringify(cardFill),
    __ANDVARI_TEST_SERVER__: testBuild ? JSON.stringify(TEST_SERVER_ORIGIN) : "null",
  },
});

const manifestFile = { firefox: "manifest.firefox.json", safari: "manifest.safari.json", chrome: "manifest.json" }[target];
if (testBuild) writeFileSync("dist/manifest.json", `${JSON.stringify(testManifest(JSON.parse(readFileSync(manifestFile, "utf8"))), null, 2)}\n`);
else cpSync(manifestFile, "dist/manifest.json");
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
if (target !== "safari") cpSync("options.html", "dist/options.html"); // wave-3 options_ui page; <link>s popup.css for the theme
if (testBuild) {
  // The test build says so on its pages (testPage below), and carries no INSTALL.txt (copied further down; it names the
  // released extension's ways in): its steps are on the page it is published with.
  writeFileSync("dist/popup.html", testPage("popup.html", 2));
  writeFileSync("dist/options.html", testPage("options.html", 1));
}
cpSync("popup.css", "dist/popup.css"); // the ported treasury theme; popup.html + options.html <link> it
cpSync("theme-boot.js", "dist/theme-boot.js"); // H134 pre-paint theme stamp; <script>d by popup/options/connector (classic, not bundled — a deferred module flashes the wrong palette)
if (target !== "safari") {
  cpSync("offscreen.html", "dist/offscreen.html"); // Chrome clipboard-clear backstop (E1-4); loads dist/offscreen.js
  cpSync("connector.html", "dist/connector.html"); // 0.17.0 biometric ceremony window; loads dist/connector.js + popup.css
}
if (target === "safari") {
  cpSync("safari-boot.js", "dist/safari-boot.js"); // the background page's first script: load marker + error capture
  cpSync("safari-diag.js", "dist/safari-diag.js"); // the popup's reader for what it recorded
}
cpSync("icons", "dist/icons", { recursive: true }); // both manifests reference icons/icon{16,32,48,128}.png
// Tester-facing load-unpacked steps travel inside the desktop zips; the Safari build is installed with the app.
if (target !== "safari") cpSync("INSTALL.txt", "dist/INSTALL.txt");
if (testBuild) rmSync("dist/INSTALL.txt");
if (target === "safari") {
  const host = new URL(REFERENCE_ORIGIN).host;
  const walk = (dir) => readdirSync(dir).flatMap((name) => (statSync(join(dir, name)).isDirectory() ? walk(join(dir, name)) : [join(dir, name)]));
  const left = walk("dist").filter((f) => !f.endsWith(".png") && readFileSync(f, "utf8").includes(host));
  if (left.length > 0) throw new Error(`the Safari build must name no default server, but ${host} is in: ${left.join(", ")}`);
  const pages = walk("dist").filter((f) => DESKTOP_ONLY_PAGES.some((p) => f === join("dist", `${p}.html`) || f === join("dist", `${p}.js`)));
  if (pages.length > 0) throw new Error(`the Safari build must not ship ${pages.join(", ")}`);
  if (!uitest) {
    const testHost = new URL(UITEST_PROVIDER).hostname;
    const leaked = walk("dist").filter((f) => !f.endsWith(".png") && readFileSync(f, "utf8").includes(testHost));
    if (leaked.length > 0) throw new Error(`only the UI-test build may name ${testHost}, but it is in: ${leaked.join(", ")}`);
  }
}
if (!debug && !uitest) {
  // The providers' sandbox and test hosts never ship (cardproviders.ts): read from the source, so a host added there is
  // checked too.
  const source = readFileSync("src/cardproviders.ts", "utf8");
  const block = source.slice(source.indexOf("export const CARD_PROVIDER_TEST_ORIGINS"), source.indexOf("];", source.indexOf("export const CARD_PROVIDER_TEST_ORIGINS")));
  const hosts = [...block.matchAll(/origin: "https:\/\/([^"]+)"/g)].map((m) => m[1]);
  if (hosts.length === 0) throw new Error("build.mjs could not read the providers' test hosts from cardproviders.ts");
  const walkAll = (dir) => readdirSync(dir).flatMap((name) => (statSync(join(dir, name)).isDirectory() ? walkAll(join(dir, name)) : [join(dir, name)]));
  const leaked = walkAll("dist").filter((f) => !f.endsWith(".png") && hosts.some((h) => readFileSync(f, "utf8").includes(h)));
  if (leaked.length > 0) throw new Error(`a release build must not list a payment provider's test host, but one is in: ${leaked.join(", ")}`);
}
{
  // The card path is in the worker exactly when the build has card fill (cardfillflag.ts).
  const worker = readFileSync("dist/background.js", "utf8");
  const held = CARD_PATH_MARKERS.filter((m) => worker.includes(m));
  if (!cardFill && held.length > 0) throw new Error(`a build without card fill must not bundle the card path, but dist/background.js holds: ${held.join(", ")}`);
  if (cardFill && held.length !== CARD_PATH_MARKERS.length) throw new Error("a build with card fill lost its card path markers: build.mjs and background.ts disagree");
  const content = readFileSync("dist/content.js", "utf8");
  const inPage = CONTENT_CARD_MARKERS.filter((m) => content.includes(m));
  if (!cardFill && inPage.length > 0) throw new Error(`a build without card fill must not bundle the content script's card fill, but dist/content.js holds: ${inPage.join(", ")}`);
  if (cardFill && inPage.length !== CONTENT_CARD_MARKERS.length) throw new Error("a build with card fill lost its content-side card markers: build.mjs and content.ts disagree");
}
{
  // The test build never names the live server; no other build names the test server. A build that does is removed.
  const banned = new URL(testBuild ? JSON.parse(readFileSync("../spec/public-instance.json", "utf8")).PUBLIC_INSTANCE.origin : TEST_SERVER_ORIGIN).host;
  const left = distFiles().filter((f) => readFileSync(f, "utf8").includes(banned));
  if (left.length > 0) {
    rmSync("dist", { recursive: true, force: true });
    throw new Error(
      testBuild
        ? `a test build must not name the live server, but ${banned} is in: ${left.join(", ")} (dist/ removed)`
        : `only a test build (TESTBUILD=1) may name the test server, but ${banned} is in: ${left.join(", ")} (dist/ removed)`,
    );
  }
}
console.log(
  testBuild
    ? `built → dist/ (${target}, test build "andvari dev" of ${testCommit}, test server ${TEST_SERVER_ORIGIN}; Load unpacked: extension/dist)`
    : `built → dist/ (${target}${release ? ", release" : ""}${uitest ? ", UI-test provider" : ""}${cardFill ? "" : ", no card fill"}; Load unpacked: extension/dist)`,
);

/** The test build's manifest, from the target's own: its name, the commit, the test server in place of the live one,
 *  no update address, and a Firefox id of its own (an add-on loaded with the released one's id would stand in for it). */
function testManifest(m) {
  const live = `${new URL(JSON.parse(readFileSync("../spec/public-instance.json", "utf8")).PUBLIC_INSTANCE.origin).origin}/*`;
  const hosts = m.host_permissions ?? [];
  if (!hosts.includes(live)) throw new Error(`${manifestFile} no longer grants ${live}: build.mjs and the manifest disagree`);
  const out = {
    ...m,
    name: "andvari dev",
    description: `A test build of andvari, from commit ${testCommit}, for the test server ${TEST_SERVER_ORIGIN} only. Not signed, not for any store.`,
    host_permissions: hosts.map((h) => (h === live ? `${TEST_SERVER_ORIGIN}/*` : h)),
    action: { ...m.action, default_title: "andvari dev" },
  };
  if (target === "firefox") {
    const gecko = { ...m.browser_specific_settings.gecko, id: "andvari-dev@andvaripass.com" };
    delete gecko.update_url;
    out.browser_specific_settings = { ...m.browser_specific_settings, gecko };
  } else {
    out.version_name = `${m.version} dev ${testCommit}`; // shown as the version on chrome://extensions and edge://extensions
  }
  return out;
}

/** A page of the test build: the brand reads "andvari dev" ([brands] times in the page), the word " dev" as text
 *  after the drawn name (src/brand.ts), and so does the tab's title. */
function testPage(file, brands) {
  const html = readFileSync(file, "utf8");
  const brand = '<path data-wordmark="" fill="currentColor"/></svg></span';
  const title = /<title>((?:[^<]* · )?)andvari<\/title>/;
  if (html.split(brand).length - 1 !== brands || !title.test(html)) throw new Error(`${file} no longer has the brand or the title the test build marks`);
  return html.replaceAll(brand, '<path data-wordmark="" fill="currentColor"/></svg> dev</span').replace(title, "<title>$1andvari dev</title>");
}
