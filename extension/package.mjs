// Release packaging: build both browser targets (minified, no sourcemaps) and zip each
// → artifacts/andvari-extension-{chrome,firefox}-<version>.zip, ready for the server's
// /downloads dir (the web Devices hub links them via manifest.json `browserExtension`).
// The zip roots the files directly (manifest.json at top level) — unzip → Load unpacked.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, statSync } from "node:fs";

const version = JSON.parse(readFileSync("manifest.json", "utf8")).version;
// The version lives in three hand-edited files; a forgotten bump would silently ship a
// firefox zip NAMED with the chrome version but CONTAINING the stale one. Refuse drift.
const ffVersion = JSON.parse(readFileSync("manifest.firefox.json", "utf8")).version;
const pkgVersion = JSON.parse(readFileSync("package.json", "utf8")).version;
if (version !== ffVersion || version !== pkgVersion) {
  throw new Error(
    `version drift: manifest.json=${version} manifest.firefox.json=${ffVersion} package.json=${pkgVersion} — bump all three`,
  );
}
mkdirSync("artifacts", { recursive: true });

// A7: refuse to zip a build whose tests fail — mirrors the version-drift refusal above.
// (verify.sh also runs these, but package.mjs is callable standalone and must self-defend.)
// Same GLOB as `npm test` — node expands it itself — so a future test file can never be
// silently skipped here while npm test runs it.
execFileSync(process.execPath, ["--test", "src/**/*.test.ts"], { stdio: "inherit" });

// A8: content.js is injected into EVERY page — it must never carry the ~144 KB PSL blob
// (pslData is imported ONLY by psl.ts, which only background.ts uses). Cap it well below
// blob size so a future import-chain slip fails the package, not the users' page loads.
const CONTENT_JS_CAP = 60 * 1024; // today ~35 KB (card autofill Tier 1: cardfill.ts + tables ride in content.js)

// firefox first, chrome last: dist/ is left holding the CHROME build, which is what the
// README's "Load + verify" (chrome://extensions → Load unpacked → extension/dist) assumes.
for (const target of ["firefox", "chrome"]) {
  execFileSync(process.execPath, ["build.mjs"], {
    stdio: "inherit",
    env: { ...process.env, RELEASE: "1", TARGET: target === "firefox" ? "firefox" : "" },
  });
  const contentSize = statSync("dist/content.js").size;
  if (contentSize > CONTENT_JS_CAP) {
    throw new Error(
      `dist/content.js is ${contentSize} bytes (> ${CONTENT_JS_CAP}) — did the PSL blob leak into the per-page bundle? (design A8)`,
    );
  }
  const zip = `artifacts/andvari-extension-${target}-${version}.zip`;
  rmSync(zip, { force: true });
  // -X: no extended attrs; cwd=dist so manifest.json sits at the zip root.
  execFileSync("zip", ["-rX", `../${zip}`, "."], { cwd: "dist", stdio: "inherit" });
  console.log(`packaged ${zip} (${(statSync(zip).size / 1024).toFixed(0)} KiB, content.js ${(contentSize / 1024).toFixed(1)} KiB)`);
}
console.log(`\nextension ${version} packaged. Publish both zips to CT122 /opt/andvari/downloads`);
console.log("and merge a browserExtension entry into manifest.json (see ops/windows-build.md for the merge pattern).");
