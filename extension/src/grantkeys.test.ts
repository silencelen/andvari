// Shared-vault keys in the extension (grantkeys.ts; design 2026-11-15-onboarding-trust §12.2 rule 1): only UVK wraps
// open, under the genesis-bound AD whose genesis hash comes from the account state, only on an `accept` decision, and
// never while no usable account state is held. A grant seal is never opened. The personal vault's row is skipped.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { seal, toB64 } from "./crypto.ts";

/** The v1 owner-wrap AD, spelled out: the extension no longer exports it. */
const adVk = (vaultId: string, userId: string) => new TextEncoder().encode(`andvari/v1|vk|${vaultId}|${userId}`);
import { buildVaultKeys, vaultNameFromMeta, waitingGrantCount } from "./grantkeys.ts";
import { adVkShared } from "./wraps.ts";
import { fillApproved, GRANTS_WAITING, GRANTS_WAITING_ONE, waitingGrantsLine } from "./errors.ts";

const userId = "22222222-2222-4222-8222-222222222222";
const personal = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const uvk = new Uint8Array(32).fill(9);
const enc = (s: string) => new TextEncoder().encode(s);
const id = (n: number) => `aaaaaaaa-aaaa-4aaa-8aaa-${String(n).padStart(12, "0")}`;
const key = (b: number) => new Uint8Array(32).fill(b);
const gen = (n: number) => String(n).repeat(64).slice(0, 64);
const wrap = (vaultId: string, vk: Uint8Array, genesisHash: string) => toB64(seal(uvk, vk, adVkShared(vaultId, userId, genesisHash)));
const records = (entries: [string, string, "accept" | "decline"][]) => ({
  vaults: Object.fromEntries(entries.map(([v, g]) => [v, { genesisHash: g, seq: 1, hash: "f".repeat(64) }])),
  accepted: Object.fromEntries(entries.map(([v, , d]) => [v, { owner: userId, addSeq: 1, at: 1, decision: d }])),
});

test("§12.2 rule 1: an accepted wrap opens under its genesis; a declined one, a missing record and no state wait", () => {
  const grants = [
    { vaultId: id(1), userId, role: "owner", wrappedVk: wrap(id(1), key(1), gen(1)) },
    { vaultId: id(2), userId, role: "writer", wrappedVk: wrap(id(2), key(2), gen(2)) },
    { vaultId: id(3), userId, role: "reader", wrappedVk: wrap(id(3), key(3), gen(3)) },
    { vaultId: id(4), userId, role: "writer", wrappedVk: "", signedGrant: toB64(new Uint8Array(400).fill(4)) },
    { vaultId: personal, userId, role: "owner", wrappedVk: toB64(seal(uvk, key(9), adVk(personal, userId))) },
  ];
  const r = buildVaultKeys(grants, uvk, userId, personal, records([[id(1), gen(1), "accept"], [id(2), gen(2), "decline"]]));
  assert.deepEqual([...r.vaultKeys.keys()], [id(1)]);
  assert.deepEqual(r.vaultKeys.get(id(1)), key(1));
  assert.equal(r.vaultRoles.get(id(1)), "owner");
  assert.deepEqual([...r.waiting].sort(), [id(2), id(3), id(4)]);
  assert.equal(r.keyUnreadable.size, 0);
  const none = buildVaultKeys(grants, uvk, userId, personal, null);
  assert.equal(none.vaultKeys.size, 0, "no usable account state: no shared-vault wrap opens");
});

test("§12.2 rule 1: a wrong genesis hash fails the AEAD and the vault stays closed (no seal fallback)", () => {
  const grants = [{ vaultId: id(1), userId, role: "owner", wrappedVk: wrap(id(1), key(1), gen(1)) }];
  const r = buildVaultKeys(grants, uvk, userId, personal, records([[id(1), gen(7), "accept"]]));
  assert.equal(r.vaultKeys.size, 0);
  assert.deepEqual([...r.keyUnreadable], [id(1)]);
});

test("the waiting count needs no UVK and ignores held vaults and the personal vault", () => {
  const grants = [
    { vaultId: id(1), userId, role: "owner", wrappedVk: "x" },
    { vaultId: id(2), userId, role: "writer", wrappedVk: "", signedGrant: "y" },
    { vaultId: id(3), userId, role: "writer", wrappedVk: "" },
    { vaultId: personal, userId, role: "owner", wrappedVk: "z" },
  ];
  assert.equal(waitingGrantCount(grants, new Set([id(1)]), personal), 1);
});

test("a vault's name decrypts only under a held key", () => {
  const vk = key(5);
  const meta = toB64(seal(vk, enc(JSON.stringify({ name: "Family" })), enc(`andvari/v1|vaultmeta|${id(1)}`)));
  assert.equal(vaultNameFromMeta(vk, id(1), meta), "Family");
  assert.equal(vaultNameFromMeta(undefined, id(1), meta), null);
  assert.equal(vaultNameFromMeta(key(6), id(1), meta), null);
});

test("the popup line for waiting grants", () => {
  assert.equal(waitingGrantsLine(0), "");
  assert.equal(waitingGrantsLine(1), GRANTS_WAITING_ONE);
  assert.equal(waitingGrantsLine(3), fillApproved(GRANTS_WAITING, "3"));
});
