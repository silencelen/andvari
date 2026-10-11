// Security review 2026-10, root cause A, branch A6 (DESIGN-A §1.7, owner decision Q8): source fence. The
// extension takes UVK wraps only; nothing in its key-building path opens a grant seal (v1 `sealedVk` or v2
// `signedGrant`), and no new curve dependency arrives to make that possible. Behaviour: grantkeys.test.ts.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (f: string) => readFileSync(new URL(f, import.meta.url), "utf-8");

test("Q8 fence: background.ts never opens a grant seal", () => {
  const bg = read("./background.ts");
  assert.ok(!/\bopenSharedGrant\s*\(/.test(bg), "background.ts must not call openSharedGrant");
  assert.ok(!/\bsealOpen\s*\(/.test(bg), "background.ts must not call sealOpen");
  assert.ok(/buildVaultKeysFromWraps\(/.test(bg), "the key map is built by the UVK-wraps-only leaf");
});

test("Q8 fence: the leaf opens UVK wraps only, and no new dependency", () => {
  const leaf = read("./grantkeys.ts");
  assert.ok(!/\bopenSharedGrant\s*\(|\bsealOpen\s*\(/.test(leaf));
  assert.ok(!/@noble\/curves/.test(leaf));
  const pkg = JSON.parse(read("../package.json"));
  assert.ok(!("@noble/curves" in (pkg.dependencies ?? {})), "Q8: no curve dependency to verify grants in-extension");
});

test("LOW-4 fence: accepting a personal-vault change re-opens the staged wrap under the UVK", () => {
  const bg = read("./background.ts");
  const a = bg.indexOf("async function acceptPersonalChange(");
  assert.ok(a > -1);
  const body = bg.slice(a, bg.indexOf("\n}\n", a));
  assert.ok(body.includes("reopenStagedPersonalWrap("), "the staged blob is re-authenticated, not trusted");
  assert.ok(!body.includes("session.vaultKeys.has(served.vaultId)"), "a key-presence check is not authentication");
});
