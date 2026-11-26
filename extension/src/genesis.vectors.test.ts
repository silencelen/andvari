// The account genesis in the extension (genesis.ts), graded by accountgenesis.json (design
// 2026-11-15-onboarding-trust §5.2, §5.3, §12.2 rule 2, §17): every row, against `expect.extensionVerdict`
// (the signer bound by byte equality with the extension's own Ed25519 key), and on ok rows whether the
// served personal wrap is in force (it names personalVaultId and opens under the UVK with the v1 personal AD).
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { b64Strict, b64Encode } from "./statement.ts";
import { ownKeysFromSeed, verifyGenesis } from "./genesis.ts";
import { personalVaultKey } from "./wraps.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const ag = JSON.parse(readFileSync(vectorsDir + "accountgenesis.json", "utf-8"));

const bytes = (s: string): Uint8Array => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

test("accountgenesis.json: the extension derives both of its keys from the seed", () => {
  const own = ownKeysFromSeed(b64Strict(ag.account.seedB64)!);
  assert.equal(b64Encode(own.signPub), ag.account.signPubB64);
  assert.equal(b64Encode(own.identityPub), ag.account.identityPubB64);
  assert.match(ag._about.join(" "), /The extension grades every row of this file/);
});

test("accountgenesis.json rows: expect.extensionVerdict, and the personal vault in force", () => {
  const own = ownKeysFromSeed(b64Strict(ag.account.seedB64)!);
  const uvk = b64Strict(ag.account.uvkB64)!;
  assert.ok(ag.rows.length >= 25, `rows: ${ag.rows.length}`);
  let differs = 0;
  for (const r of ag.rows) {
    const got = verifyGenesis(bytes(r.genesisB64), {
      own,
      sessionUserId: r.sessionUserId,
      pinnedInstanceId: r.pinnedInstanceId,
      servedPersonalVaultId: r.personalWrap?.vaultId ?? null,
    });
    assert.equal(got.ok ? "ok" : got.verdict, r.expect.extensionVerdict, `${r.name}: ${r.why}`);
    if (r.expect.extensionVerdict !== r.expect.verdict) differs++;
    if (got.ok) {
      assert.equal(typeof r.expect.personalVaultInForce, "boolean", r.name);
      const vk = r.personalWrap === null ? null : personalVaultKey(r.personalWrap.wrappedVkB64, r.personalWrap.vaultId, got.genesis.personalVaultId, uvk, r.sessionUserId);
      assert.equal(vk !== null, r.expect.personalVaultInForce, `${r.name}: personal vault in force`);
      if (vk !== null) assert.equal(b64Encode(vk), ag.personalVkB64, r.name);
    }
  }
  // The negated-key row (-A) was the one row where the extension's byte binding differed from a full client's; the
  // rule since 2026-11-15 is that every client refuses it as signer_not_pinned_key, so the
  // extensionVerdict column may equal the full verdict on every row. Never more than that one row differs.
  assert.ok(differs <= 1, `rows where the extension's verdict differs from a full client's: ${differs}`);
});
