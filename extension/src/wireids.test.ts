// Security review 2026-10 (plugin scan F1/F2; branch A10): every server-supplied id is checked against the UUID
// grammar at the wire boundary, in AndvariApi, BEFORE it can reach the session, a snapshot or a storage.local
// record. A row carrying an id with a line break or a `|` is REFUSED: dropped, and reported through
// `api.onRefusedIds`. One test per id field. Twin of core WireIdsTest.kt and web api/wireids.test.ts.
import { strict as assert } from "node:assert";
import { afterEach, test } from "node:test";
import { AndvariApi, ApiError } from "./api.ts";
import { isUuid, type Refusal } from "./wireids.ts";

const good = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const other = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const hostile = [`${good}\n${other}|${"a".repeat(64)}|confirmed`, `${good}|x`, "", "not-a-uuid", good.toUpperCase(), `${good} `];

function jsonResp(body: unknown): Response {
  return { ok: true, status: 200, statusText: "HTTP 200", json: async () => body, text: async () => JSON.stringify(body) } as unknown as Response;
}

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function served(body: unknown): { api: AndvariApi; refused: { endpoint: string; refused: Refusal[] }[] } {
  globalThis.fetch = (async () => jsonResp(body)) as unknown as typeof fetch;
  const api = new AndvariApi("https://x", "1.2.3");
  api.setTokens("a1", "r1");
  const refused: { endpoint: string; refused: Refusal[] }[] = [];
  api.onRefusedIds = (endpoint, r) => refused.push({ endpoint, refused: r });
  return { api, refused };
}

const vault = (vaultId: string) => ({ vaultId, type: "shared" });
const grant = (vaultId: string, userId: string) => ({ vaultId, userId, role: "writer", wrappedVk: "" });
const item = (itemId: string, vaultId: string) => ({ itemId, vaultId, rev: 1, deleted: false, formatVersion: 1, blob: "b" });
const sync = (p: Partial<{ vaults: unknown[]; grants: unknown[]; items: unknown[] }>) => ({ rev: 9, vaults: [], grants: [], items: [], ...p });
const KEYS = { kdfSalt: "s", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }, wrappedUvk: "w", encryptedIdentitySeed: "e", identityPub: "p" };

test("A10: the grammar is lowercase UUID only", () => {
  assert.equal(isUuid(good), true);
  for (const h of hostile) assert.equal(isUuid(h), false, JSON.stringify(h));
});

test("A10: a vault row with a hostile vaultId is dropped and reported", async () => {
  for (const h of hostile) {
    const { api, refused } = served(sync({ vaults: [vault(h), vault(good)] }));
    assert.deepEqual((await api.sync(0)).vaults.map((v) => v.vaultId), [good], JSON.stringify(h));
    assert.deepEqual(refused, [{ endpoint: "sync", refused: [{ field: "vaultId", value: h }] }]);
  }
});

test("A10: a grant row with a hostile vaultId or userId is dropped", async () => {
  for (const h of hostile) {
    const { api, refused } = served(sync({ grants: [grant(h, good), grant(good, h), grant(good, other)] }));
    assert.deepEqual((await api.sync(0)).grants.map((g) => [g.vaultId, g.userId]), [[good, other]]);
    assert.deepEqual(refused[0]!.refused.map((r) => r.field), ["vaultId", "userId"]);
  }
});

test("A10: an item row with a hostile itemId or vaultId is dropped", async () => {
  for (const h of hostile) {
    const { api, refused } = served(sync({ items: [item(h, good), item(good, h), item(other, good)] }));
    assert.deepEqual((await api.sync(0)).items.map((i) => i.itemId), [other]);
    assert.deepEqual(refused[0]!.refused.map((r) => r.field), ["itemId", "vaultId"]);
  }
});

test("A10: a member row with a hostile userId is dropped", async () => {
  const h = `${good}|${"b".repeat(64)}`;
  const row = (userId: string) => ({ userId, email: "e", displayName: "d", role: "writer" });
  const { api, refused } = served([row(h), row(good)]);
  assert.deepEqual((await api.vaultMembers(other)).map((m) => m.userId), [good]);
  assert.equal(refused[0]!.endpoint, "members");
});

test("A10: a served personal wrap with a hostile vault id is dropped (keys and login)", async () => {
  const h = `${good}|x`;
  const keys = served({ ...KEYS, personalWrap: { vaultId: h, wrappedVk: "w" } });
  assert.equal((await keys.api.getAccountKeys()).personalWrap, null);
  assert.equal(keys.refused[0]!.endpoint, "accountKeys");
  const login = served({ userId: good, deviceId: other, accessToken: "a", refreshToken: "r", accountKeys: { ...KEYS, personalWrap: { vaultId: h, wrappedVk: "w" } } });
  assert.equal((await login.api.login("e@x", "a")).accountKeys.personalWrap, null);
  assert.equal(login.refused[0]!.endpoint, "login");
});

test("A10: a session with a hostile userId or deviceId is refused", async () => {
  const h = `${good}\nx`;
  const session = (userId: string, deviceId: string) => ({ userId, deviceId, accessToken: "a", refreshToken: "r", accountKeys: KEYS });
  for (const [u, d] of [[h, good], [good, h]] as const) {
    const { api, refused } = served(session(u, d));
    await assert.rejects(api.login("e@x", "a"), (e: unknown) => e instanceof ApiError && e.code === "bad_wire_id");
    assert.equal(refused.length, 1);
  }
  assert.equal((await served(session(good, other)).api.login("e@x", "a")).userId, good);
});
