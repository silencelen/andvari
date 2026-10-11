// Security review 2026-10, root cause A, branch A6 (DESIGN-A §1.7, owner decision Q8; A5b review LOW-3, LOW-4).
//
//  - Q8: the extension takes UVK WRAPS ONLY. It never opens (nor compares) a grant seal: not the v1 `sealedVk`
//    (anyone holding our public key, the server included, can mint one) and not the v2 `signedGrant` (verifying it
//    needs Edwards→Montgomery, which would be a new dependency). A row with no wrap is counted as "waiting" for a
//    full client, which verifies it and posts the member self-wrap the extension can then open.
//  - LOW-4: "Use the new personal vault" re-opens the staged served wrap under the session UVK with the
//    vk-personal AD and installs THAT key; no UVK (a post-eviction session) or a wrap that does not open = refused.
//  - LOW-3: the change notice names both the current and the new vault.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { adVk, adVkPersonal, seal, toB64 } from "./crypto.ts";
import { buildVaultKeysFromWraps, personalChangeNotice, reopenStagedPersonalWrap, vaultNameFromMeta, waitingGrantCount } from "./grantkeys.ts";
import { waitingGrantsLine } from "./errors.ts";

const userId = "22222222-2222-4222-8222-222222222222";
const uvk = new Uint8Array(32).fill(9);
const enc = (s: string) => new TextEncoder().encode(s);
const id = (n: number) => `aaaaaaaa-aaaa-4aaa-8aaa-${String(n).padStart(12, "0")}`;
const key = (b: number) => new Uint8Array(32).fill(b);
const wrap = (vaultId: string, vk: Uint8Array) => toB64(seal(uvk, vk, adVk(vaultId, userId)));
// Opaque blobs: the extension must never try to open them, so their content is irrelevant.
const junkSeal = toB64(new Uint8Array(120).fill(3));
const junkSigned = toB64(new Uint8Array(500).fill(4));

test("Q8: only UVK wraps are adopted; v1-only and v2-only rows are counted as waiting, never opened", () => {
  const r = buildVaultKeysFromWraps(
    [
      { vaultId: id(1), userId, role: "owner", wrappedVk: wrap(id(1), key(1)) },
      { vaultId: id(2), userId, role: "writer", wrappedVk: "", sealedVk: junkSeal },
      { vaultId: id(3), userId, role: "writer", wrappedVk: "", sealedVk: junkSeal, signedGrant: junkSigned },
      { vaultId: id(4), userId, role: "reader", wrappedVk: "", signedGrant: junkSigned },
      { vaultId: id(5), userId, role: "writer", wrappedVk: wrap(id(5), key(5)), sealedVk: junkSeal }, // member self-wrap
    ],
    uvk,
    userId,
  );
  assert.deepEqual([...r.vaultKeys.keys()].sort(), [id(1), id(5)]);
  assert.deepEqual([...r.waiting].sort(), [id(2), id(3), id(4)]);
  assert.equal(toB64(r.vaultKeys.get(id(5))!), toB64(key(5)), "the self-wrap's key, whatever the seal says");
  assert.ok(r.memberGranted.has(id(5)), "H64: a row with any seal or a non-owner role is member-granted");
  assert.ok(!r.memberGranted.has(id(1)));
  assert.equal(r.vaultRoles.get(id(5)), "writer");
  assert.equal(r.vaultRoles.has(id(2)), false, "no role recorded for a vault with no key");
});

test("Q8: a present wrap that does not open leaves the vault keyless (no seal fallback), and is not 'waiting'", () => {
  const r = buildVaultKeysFromWraps(
    [{ vaultId: id(6), userId, role: "writer", wrappedVk: wrap(id(7), key(6)), sealedVk: junkSeal }], // wrong AD
    uvk,
    userId,
  );
  assert.equal(r.vaultKeys.size, 0);
  assert.ok(r.keyUnreadable.has(id(6)));
  assert.equal(r.waiting.size, 0);
});

test("Q8: the waiting count needs no UVK (it survives an MV3 eviction) and ignores held vaults", () => {
  const grants = [
    { vaultId: id(1), userId, role: "owner", wrappedVk: "x" },
    { vaultId: id(2), userId, role: "writer", wrappedVk: "", sealedVk: junkSeal },
    { vaultId: id(4), userId, role: "reader", wrappedVk: "", signedGrant: junkSigned },
  ];
  assert.equal(waitingGrantCount(grants, new Set([id(1)])), 2);
  assert.equal(waitingGrantCount(grants, new Set([id(1), id(2)])), 1);
});

const personalWrap = (vaultId: string, vk: Uint8Array) => ({ vaultId, wrappedVk: toB64(seal(uvk, vk, adVkPersonal(vaultId, userId))) });

test("LOW-4: the staged wrap is re-opened under the UVK with the vk-personal AD; that key is installed", () => {
  const r = reopenStagedPersonalWrap(personalWrap(id(8), key(8)), uvk, userId);
  assert.ok(r.ok);
  assert.equal(toB64(r.ok ? r.vk : new Uint8Array()), toB64(key(8)));
});

test("LOW-4: no UVK (snapshot-restored session) or a staged blob that does not open is refused", () => {
  assert.deepEqual(reopenStagedPersonalWrap(personalWrap(id(8), key(8)), undefined, userId), { ok: false, code: "need_full_unlock" });
  // An owner wrap (vk AD) planted in the staged slot: not a personal wrap.
  const planted = { vaultId: id(8), wrappedVk: wrap(id(8), key(8)) };
  assert.deepEqual(reopenStagedPersonalWrap(planted, uvk, userId), { ok: false, code: "unverified" });
  assert.deepEqual(reopenStagedPersonalWrap({ vaultId: id(9), wrappedVk: personalWrap(id(8), key(8)).wrappedVk }, uvk, userId), { ok: false, code: "unverified" });
  assert.deepEqual(reopenStagedPersonalWrap({ vaultId: id(8), wrappedVk: "!!" }, uvk, userId), { ok: false, code: "unverified" });
});

test("LOW-3: the change notice names both the current and the new vault", () => {
  const meta = (vaultId: string, vk: Uint8Array, name: string) =>
    toB64(seal(vk, enc(JSON.stringify({ name })), enc(`andvari/v1|vaultmeta|${vaultId}`)));
  assert.equal(vaultNameFromMeta(key(1), id(1), meta(id(1), key(1), "Home")), "Home");
  assert.equal(vaultNameFromMeta(key(2), id(1), meta(id(1), key(1), "Home")), null, "wrong key → no name");
  assert.equal(vaultNameFromMeta(undefined, id(1), meta(id(1), key(1), "Home")), null);
  const text = personalChangeNotice("Home", "Family");
  assert.ok(text.includes("“Home”") && text.includes("“Family”"), text);
  const fallback = personalChangeNotice(null, null);
  assert.ok(fallback.includes("your current vault") && fallback.includes("another vault"), fallback);
});

test("Q8: the popup line for waiting grants", () => {
  assert.equal(waitingGrantsLine(0), "");
  assert.equal(waitingGrantsLine(1), "1 shared vault waiting — open andvari to review.");
  assert.equal(waitingGrantsLine(3), "3 shared vaults waiting — open andvari to review.");
});
