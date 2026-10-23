// node --test. Security review 2026-10, the A16 review: the extension must never be released under a version that is
// not newer than LAST_PRE_A15_VERSION (releasegate.ts says why). The check runs where releases are made — package.mjs —
// and not in verify.sh, because between releases the tree carries the last release's version.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { a15ReleaseProblem } from "./releasegate.ts";
import { LAST_PRE_A15_VERSION } from "./trustmigrate.ts";

test("a release must be newer than the last release without the A15 trusted store", () => {
  assert.equal(LAST_PRE_A15_VERSION, "0.28.1");
  for (const v of ["0.28.1", "0.28.0", "0.27.9", "0.28", "0.1.0"]) assert.match(a15ReleaseProblem(v) ?? "", /not newer than LAST_PRE_A15_VERSION/, v);
  for (const v of ["0.28.2", "0.29.0", "1.0.0", "0.28.10"]) assert.equal(a15ReleaseProblem(v), null, v);
  for (const v of ["", "garbage", "0.29.0-beta", " "]) assert.notEqual(a15ReleaseProblem(v), null, `malformed ${JSON.stringify(v)} is refused`);
});

test("package.mjs refuses to package such a version, before it tests, builds or zips anything", () => {
  const pkg = readFileSync(new URL("../package.mjs", import.meta.url), "utf-8");
  assert.ok(pkg.includes('import { a15ReleaseProblem } from "./src/releasegate.ts";'));
  const check = pkg.indexOf("const a15 = a15ReleaseProblem(version);");
  assert.ok(check > -1 && pkg.indexOf("if (a15 !== null) throw new Error(a15);") > check);
  for (const later of ['execFileSync(process.execPath, ["--test"', 'execFileSync(process.execPath, ["build.mjs"]', 'execFileSync("zip"']) {
    assert.ok(pkg.indexOf(later) > check, `the check comes before: ${later}`);
  }
  // …and verify.sh does not carry it (the tree between releases is not wrong).
  const verify = readFileSync(new URL("../../scripts/verify.sh", import.meta.url), "utf-8");
  assert.ok(!verify.includes("a15ReleaseProblem") && !verify.includes("LAST_PRE_A15_VERSION"));
});
