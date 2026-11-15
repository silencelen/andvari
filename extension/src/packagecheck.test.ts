// node --test. The 0.30.0 release check: package.mjs refused the Chrome and Firefox builds (dist/content.js over its
// cap) while scripts/verify.sh and CI were green, because neither built them the way the packaging does. Both now run
// the packaging's checks, `node package.mjs --check`: every target built as it ships, the cap applied, no zip.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (f: string): string => readFileSync(new URL(f, import.meta.url), "utf-8");

test("verify.sh and CI run the packaging's checks", () => {
  assert.match(read("../../scripts/verify.sh"), /\(cd "\$REPO_DIR\/extension" && node package\.mjs --check\)/);
  assert.match(read("../../.github/workflows/verify-js.yml"), /- name: Release packaging checks\s*working-directory: extension\s*run: node package\.mjs --check/);
});

test("the check builds every target as it ships and applies the cap, without the release gate or a zip", () => {
  const pkg = read("../package.mjs");
  assert.match(pkg, /const check = process\.argv\.includes\("--check"\);/);
  assert.match(pkg, /for \(const target of check \? \["firefox", "safari", "chrome"\] : \["firefox", "chrome"\]\) \{/);
  // As each target ships: the environment's CARDFILL is not passed to a checked build.
  assert.match(pkg, /const \{ CARDFILL: _cardFill, \.\.\.defaultEnv \} = process\.env;/);
  assert.match(pkg, /env: \{ \.\.\.\(check \? defaultEnv : process\.env\), RELEASE: "1", TARGET: target === "chrome" \? "" : target \},/);
  const cap = pkg.indexOf("if (contentSize > CONTENT_JS_CAP) {");
  const skip = pkg.indexOf("if (check) {");
  assert.ok(cap > -1 && skip > cap, "the cap is applied to every checked build before it moves on");
  assert.ok(pkg.indexOf('execFileSync("zip"') > skip, "and nothing is zipped");
  // The A15 release check (releasegate.test.ts) and the test run stay the packaging's own.
  assert.match(pkg, /if \(!check\) \{\s*const a15 = a15ReleaseProblem\(version\);/);
});
