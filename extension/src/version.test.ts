// Runs under Node's built-in runner (node --test); type-stripped natively (Node 22.18+).
// Excluded from tsc (tsconfig `exclude`) because it imports node:test, which the extension's
// chrome-only lib set does not type. `npm test` in extension/ runs this.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isNewerVersion } from "./version.ts";

test("strictly newer across each version component", () => {
  assert.equal(isNewerVersion("0.8.0", "0.7.0"), true); // minor
  assert.equal(isNewerVersion("1.0.0", "0.9.9"), true); // major beats a higher minor/patch
  assert.equal(isNewerVersion("0.7.1", "0.7.0"), true); // patch
  assert.equal(isNewerVersion("0.10.0", "0.9.0"), true); // numeric, not lexical (10 > 9)
});

test("equal or older is never newer (no false nag)", () => {
  assert.equal(isNewerVersion("0.7.0", "0.7.0"), false);
  assert.equal(isNewerVersion("0.6.9", "0.7.0"), false);
  assert.equal(isNewerVersion("0.7.0", "0.7.1"), false);
  assert.equal(isNewerVersion("0.9.0", "0.10.0"), false); // 9 < 10 numerically
});

test("missing trailing parts count as zero", () => {
  assert.equal(isNewerVersion("0.8", "0.8.0"), false);
  assert.equal(isNewerVersion("0.8.1", "0.8"), true);
  assert.equal(isNewerVersion("1", "0.9.9"), true);
});

test("malformed input never nags", () => {
  assert.equal(isNewerVersion("", "0.7.0"), false);
  assert.equal(isNewerVersion("garbage", "0.7.0"), false);
  assert.equal(isNewerVersion("0.7.x", "0.7.0"), false);
  assert.equal(isNewerVersion("0.7.0-beta", "0.7.0"), false); // pre-release suffix is not numeric
  assert.equal(isNewerVersion("9.9.9", "not-a-version"), false); // unreadable current fails closed
  assert.equal(isNewerVersion("1.2.3.4.5", "0.7.0"), false); // too many parts
  assert.equal(isNewerVersion("  ", "0.7.0"), false);
});
