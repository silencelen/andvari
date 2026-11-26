import { afterEach, describe, expect, it, vi } from "vitest";
import type { SyncResponse } from "./types";
import { ApiClient } from "./client";
import { WireApi } from "./wireclient";
import { isUuid, NIL_USER_ID, type Refusal, refusedSession, sanitizeSync } from "./wireids";
import type { SessionResponse } from "./types";
import { WireShapeError } from "./decode";
import { decodeRecoveryVerify, decodeSession } from "./wire";

/**
 * Security review 2026-10 (plugin scan F1/F2; branch A10): every server-supplied id is checked against the UUID
 * grammar at the wire boundary, in ApiClient, BEFORE it can reach the account, the cache or a device-local trust
 * record. A row carrying an id with a line break or a `|` (the record delimiters the scan exploited) is REFUSED:
 * dropped, and reported through `client.onRefusedIds`. One test per id field. Twin of core WireIdsTest.kt and
 * extension wireids.test.ts.
 */

const good = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const other = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const hostile = [`${good}\n${other}|${"a".repeat(64)}|confirmed`, `${good}|x`, "", "not-a-uuid", good.toUpperCase(), `${good} `];

const resp = (body: unknown): Response =>
  ({ ok: true, status: 200, statusText: "200", json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

function served(body: unknown): { client: ApiClient; refused: { endpoint: string; refused: Refusal[] }[] } {
  vi.stubGlobal("fetch", vi.fn(async () => resp(body)));
  const client = new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });
  const refused: { endpoint: string; refused: Refusal[] }[] = [];
  client.onRefusedIds = (endpoint, r) => refused.push({ endpoint, refused: r });
  return { client, refused };
}

/** A sync answer's rows through the grammar the store's hydrate runs on its cached rows (the live pull's own decoder
 *  is api/wire.ts's, tested in wireclient.test.ts). */
function checked(body: unknown): { client: { sync: () => Promise<SyncResponse> }; refused: { endpoint: string; refused: Refusal[] }[] } {
  const d = sanitizeSync(body as SyncResponse);
  const refused = d.refused.length > 0 ? [{ endpoint: "sync", refused: d.refused }] : [];
  return { client: { sync: async () => d.value }, refused };
}

const vault = (vaultId: string, extra: Record<string, unknown> = {}) => ({ vaultId, type: "shared", rev: 3, metaBlob: "m", createdAt: 0, ...extra });
const grant = (vaultId: string, userId: string) => ({ vaultId, userId, role: "writer", wrappedVk: "", rev: 3 });
const item = (itemId: string, vaultId: string) => ({ itemId, vaultId, rev: 1, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [], blob: "b" });
const sync = (p: Partial<{ vaults: unknown[]; grants: unknown[]; items: unknown[]; removedGrants: unknown[]; removedGrantsInfo: unknown[] }>) => ({
  rev: 9, full: true, vaults: [], grants: [], items: [], removedGrants: [], removedGrantsInfo: [], ...p,
});
const KEYS = { kdfSalt: "s", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }, wrappedUvk: "w", encryptedIdentitySeed: "e", identityPub: "p", escrowFingerprint: "f" };

describe("wire-boundary ids (A10)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("the grammar is lowercase UUID only", () => {
    expect(isUuid(good)).toBe(true);
    for (const h of hostile) expect(isUuid(h), JSON.stringify(h)).toBe(false);
  });

  it("a vault row with a hostile vaultId is dropped and reported", async () => {
    for (const h of hostile) {
      const { client, refused } = checked(sync({ vaults: [vault(h), vault(good)] }));
      expect((await client.sync()).vaults.map((v) => v.vaultId), JSON.stringify(h)).toEqual([good]);
      expect(refused).toEqual([{ endpoint: "sync", refused: [{ field: "vaultId", value: h }] }]);
    }
  });

  it("a vault row whose transfer names a hostile userId is dropped", async () => {
    const { client, refused } = checked(
      sync({
        vaults: [
          vault(good, { pendingTransfer: { toUserId: `${other}\nx`, offerId: "o", proof: "p", expiresAt: 1, seq: 1 } }),
          vault(other, { lastTransfer: { offerId: "o", newOwnerUserId: `${good}|x`, acceptProof: "p", seq: 1 } }),
        ],
      }),
    );
    expect((await client.sync()).vaults).toEqual([]);
    expect(refused[0]!.refused.map((r) => r.field)).toEqual(["pendingTransfer.toUserId", "lastTransfer.newOwnerUserId"]);
  });

  it("a grant row with a hostile vaultId or userId is dropped", async () => {
    for (const h of hostile) {
      const { client, refused } = checked(sync({ grants: [grant(h, good), grant(good, h), grant(good, other)] }));
      expect((await client.sync()).grants.map((g) => [g.vaultId, g.userId])).toEqual([[good, other]]);
      expect(refused[0]!.refused.map((r) => r.field)).toEqual(["vaultId", "userId"]);
    }
  });

  it("an item row with a hostile itemId or vaultId is dropped", async () => {
    for (const h of hostile) {
      const { client, refused } = checked(sync({ items: [item(h, good), item(good, h), item(other, good)] }));
      expect((await client.sync()).items.map((i) => i.itemId)).toEqual([other]);
      expect(refused[0]!.refused.map((r) => r.field)).toEqual(["itemId", "vaultId"]);
    }
  });

  it("a removed-grant entry with a hostile vaultId is dropped", async () => {
    const h = `${good}\n${other}`;
    const { client, refused } = checked(sync({ removedGrants: [h, good], removedGrantsInfo: [{ vaultId: h, reason: "removed" }, { vaultId: good, reason: "removed" }] }));
    const r = await client.sync();
    expect(r.removedGrants).toEqual([good]);
    expect(r.removedGrantsInfo!.map((x) => x.vaultId)).toEqual([good]);
    expect(refused[0]!.refused.map((x) => x.field)).toEqual(["removedGrants", "removedGrantsInfo.vaultId"]);
  });

  it("a member row with a hostile userId is dropped", async () => {
    const h = `${good}|${"b".repeat(64)}`;
    const row = (userId: string) => ({ userId, email: "e", displayName: "d", role: "writer", identityPub: "p", addedAt: 0 });
    const { client, refused } = served([row(h), row(good)]);
    expect((await client.vaultMembers(other)).map((m) => m.userId)).toEqual([good]);
    expect(refused[0]!.endpoint).toBe("members");
  });

  it("a deleted item or deleted vault with a hostile id is dropped", async () => {
    const h = `${good}\n${other}`;
    // The trash is the item layer's route (api/wireclient.ts), over the same transport.
    // Newest first, as spec 03 §5.1 orders the trash (the dropped rows still count for the order).
    const items = served({ items: [{ itemId: h, vaultId: good, deletedAt: 3 }, { itemId: good, vaultId: h, deletedAt: 2 }, { itemId: other, vaultId: good, deletedAt: 1 }] });
    const trashRefused: [string, Refusal[]][] = [];
    const wire = new WireApi(items.client, undefined, (endpoint, r) => trashRefused.push([endpoint, r]));
    expect((await wire.deletedItems()).items.map((d) => d.itemId)).toEqual([other]);
    expect(trashRefused.map(([e, r]) => [e, r.length])).toEqual([["items/deleted", 2]]);
    const row = (vaultId: string) => ({ vaultId, metaBlob: "m", wrappedVk: "w", deletedAt: 1, purgeAt: 2, deleteId: "d" });
    const vaults = served([row(h), row(good)]);
    expect((await vaults.client.deletedVaults()).map((v) => v.vaultId)).toEqual([good]);
    expect(vaults.refused[0]!.endpoint).toBe("deletedVaults");
  });

  it("a served personal wrap with a hostile id is refused", async () => {
    const h = `${good}|x`;
    const keys = served({ ...KEYS, personalWrap: { vaultId: h, wrappedVk: "w" } });
    expect((await keys.client.accountKeys()).personalWrap).toBeNull();
    expect(keys.refused[0]!.endpoint).toBe("accountKeys");
  });

  it("a session with a hostile userId or deviceId is refused", async () => {
    const h = `${good}\nx`;
    const session = (userId: string, deviceId: string) => ({ userId, deviceId, accessToken: "a", refreshToken: "r", isAdmin: false, accountKeys: KEYS });
    await expect(served(session(h, good)).client.login("e@x", "a", "d")).rejects.toMatchObject({ code: "bad_wire_id" });
    await expect(served(session(good, h)).client.login("e@x", "a", "d")).rejects.toMatchObject({ code: "bad_wire_id" });
    expect((await served(session(good, other)).client.login("e@x", "a", "d")).userId).toBe(good);
    // The shared code's rule of 2026-11-17: the all-zero user id is never an account.
    await expect(served(session(NIL_USER_ID, other)).client.login("e@x", "a", "d")).rejects.toMatchObject({ code: "bad_wire_id" });
    expect(refusedSession({ userId: NIL_USER_ID, deviceId: other } as SessionResponse)).toEqual({ field: "userId", value: NIL_USER_ID });
  });

  it("the shared code's rule of 2026-11-17: a session or a kit recovery's answer that names the all-zero user id is refused", () => {
    const good = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
    const fieldOf = (run: () => unknown): string | null => {
      try {
        run();
        return null;
      } catch (e) {
        return e instanceof WireShapeError ? e.field : "not a wire refusal";
      }
    };
    // Each decoder reads the user id before the fields after it, so the refusal names the field it stopped at.
    expect(fieldOf(() => decodeSession("login", { userId: NIL_USER_ID }))).toBe("userId");
    expect(fieldOf(() => decodeSession("login", { userId: good }))).toBe("deviceId");
    expect(fieldOf(() => decodeRecoveryVerify({ recoveryTicket: "dGlja2V0", userId: NIL_USER_ID }))).toBe("userId");
    expect(fieldOf(() => decodeRecoveryVerify({ recoveryTicket: "dGlja2V0", userId: good }))).toBe("recoveryWrappedUvk");
  });
});
