// Security review 2026-10, branch A13 (q38, LOW): the quick-unlock redeem opens the SERVER-served
// encryptedIdentitySeed. It had no structure-first gate (the full unlock has had one since R38), so a malformed or
// undecodable blob fell into the generic catch: the enrolled blob was WIPED (the evidence the identity-mismatch branch
// deliberately keeps) and the popup blamed the user's own key ("set up again"). A damaged account-key blob is now the
// terminal `keys_damaged` refusal on the redeem lanes too: blob kept, tampering-class copy, never "try again".
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { bioUnlockErrorCopy, pinUnlockErrorCopy, unlockErrorCopy } from "./errors.ts";

const bg = readFileSync(fileURLToPath(new URL("./background.ts", import.meta.url)), "utf-8");
const redeem = bg.slice(bg.indexOf("async function finishRedeem("), bg.indexOf("async function disableQuickUnlock("));

test("keys_damaged on a redeem lane reads like the full unlock's H67 refusal", () => {
  const h67 = unlockErrorCopy("keys_damaged");
  for (const t of [
    pinUnlockErrorCopy("keys_damaged" as Parameters<typeof pinUnlockErrorCopy>[0]),
    bioUnlockErrorCopy("keys_damaged" as Parameters<typeof bioUnlockErrorCopy>[0]),
  ]) {
    assert.equal(t, h67);
    assert.doesNotMatch(t, /try again|set up again/i);
  }
});

test("the redeem gates the served seed blob BEFORE opening it", () => {
  const gate = redeem.indexOf("envelopeStructuralRefusal(seedEnvelope)");
  const open = redeem.indexOf("open(begin.uvk, seedEnvelope");
  assert.ok(gate > 0, "the structure-first gate runs on the redeem lane");
  assert.ok(open > gate, "the seed is opened only after the gate");
  assert.match(redeem, /throw new VaultKeyDamagedError\("encryptedIdentitySeed is not valid base64url"\)/);
});

test("a damaged seed keeps the enrolled blob and answers keys_damaged", () => {
  const caught = redeem.indexOf('if (e instanceof VaultKeyDamagedError) return { ok: false, code: "keys_damaged" };');
  assert.ok(caught > 0, "VaultKeyDamagedError has its own arm");
  assert.ok(caught < redeem.indexOf("await quickUnlock.wipe();"), "…before the stale-UVK wipe");
});
