import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { ApiClient, ApiError } from "./client";
import { DEVICE_KEY, DeviceIdentity, memoryStorage } from "./devicesecret";
import { AnsweredCostRefusedError, BAD_RESPONSE, WireApi } from "./wireclient";
import { decodeSync } from "./wire";

/** The v2 routes the web calls (spec 03 §0.2): the exact bodies it sends and the strictness of what it reads. */

const H = "a".repeat(64);
const U1 = "11111111-1111-4111-8111-111111111111";
const D1 = "d0000000-0000-4000-8000-000000000001";
const KEY32 = "dmn5TI1-jtERdRVMZoWG5QFr3LXPGreVJcHDayMnGio";
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };

const accountKeys = {
  kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA",
  kdfParams: KDF,
  wrappedUvk: "AQEAAA",
  encryptedIdentitySeed: "AQEAAA",
  identityPub: KEY32,
  recoveryConfirmed: true,
  personalWrap: { vaultId: U1, wrappedVk: "AQEAAA" },
  genesis: "YXZzAg",
};
const session = { userId: U1, deviceId: D1, accessToken: "acc", refreshToken: "ref", accountKeys, role: "member", totpEnrolled: false, mustEnrollTotp: false };

const memory = memoryStorage;

interface Seen {
  url: string;
  method: string;
  body: unknown;
}

function serve(answer: (s: Seen) => { status?: number; body: unknown }): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const s = { url, method: init?.method ?? "GET", body: init?.body === undefined ? undefined : JSON.parse(init.body as string) };
      seen.push(s);
      const a = answer(s);
      const status = a.status ?? 200;
      const text = typeof a.body === "string" ? a.body : JSON.stringify(a.body);
      return { ok: status < 400, status, statusText: String(status), headers: new Headers({ "Content-Type": "application/json" }), json: async () => JSON.parse(text), text: async () => text } as unknown as Response;
    }),
  );
  return seen;
}

const api = (store = memory()) => new WireApi(new ApiClient("http://server", { accessToken: "a", refreshToken: "r" }), new DeviceIdentity(store));

describe("WireApi", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => vi.unstubAllGlobals());

  it("logs in with this browser's device object, and a known device sends its id", async () => {
    const store = memory();
    const seen = serve(() => ({ body: session }));
    const a = api(store);
    await a.login("Alice@Example.com", "AK", "Firefox");
    const first = seen[0]!.body as { device: Record<string, string> };
    expect(seen[0]!.url).toBe("http://server/api/v1/auth/login");
    expect(Object.keys(first.device).sort()).toEqual(["deviceSecret", "name", "platform"]);
    expect(first.device.platform).toBe("web");
    expect(first.device.deviceSecret).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The second sign-in of the same account (its address in another case) is a known device.
    await a.login("alice@example.com ", "AK", "Firefox", "123456");
    const second = seen[1]!.body as { device: Record<string, string>; totp: string };
    expect(second.device.deviceId).toBe(D1);
    expect(second.device.deviceSecret).toBe(first.device.deviceSecret);
    expect(second.totp).toBe("123456");
    // The address itself is not stored.
    expect(store.map.get(DEVICE_KEY)).not.toContain("alice");
  });

  it("a damaged device record makes this browser a new device, never a known one", async () => {
    const store = memory();
    store.set(DEVICE_KEY, "{not json");
    const seen = serve(() => ({ body: session }));
    await api(store).login("alice@example.com", "AK", "Firefox");
    expect((seen[0]!.body as { device: Record<string, string> }).device.deviceId).toBeUndefined();
  });

  it("a login answer whose cost is refused: the issued pair is held and handed on, and the row remembered, BEFORE the refusal", async () => {
    const store = memory();
    for (const kdfParams of [{ ...KDF, memBytes: KDF.memBytes + 1 }, { ...KDF, memBytes: 1024 }]) {
      const seen = serve(() => ({ body: { ...session, accountKeys: { ...accountKeys, kdfParams } } }));
      const client = new ApiClient("http://server", null);
      const a = new WireApi(client, new DeviceIdentity(store));
      const given: string[] = [];
      const e = await a.login("alice@example.com", "AK", "Firefox", undefined, (t) => given.push(t.refreshToken)).catch((x: unknown) => x);
      expect(e).toBeInstanceOf(AnsweredCostRefusedError);
      // The server's session is the caller's to end: the transport holds it and the flow was told it.
      expect(client.getTokens()).toEqual({ accessToken: "acc", refreshToken: "ref" });
      expect(given).toEqual(["ref"]);
      // The row the server made is remembered, so a second try names it instead of making another.
      expect(a.device.deviceIdFor("alice@example.com")).toBe(D1);
      vi.unstubAllGlobals();
      expect(seen).toHaveLength(1);
    }
    const seen = serve(() => ({ body: session }));
    await new WireApi(new ApiClient("http://server", null), new DeviceIdentity(store)).login("alice@example.com", "AK", "Firefox");
    expect((seen[0]!.body as { device: Record<string, string> }).device.deviceId).toBe(D1);
  });

  it("refuses a session whose role is not one of the two", async () => {
    serve(() => ({ body: { ...session, role: "admin" } }));
    await expect(api().login("a@b.c", "AK", "x")).rejects.toMatchObject({ code: BAD_RESPONSE });
  });

  it("refuses a session whose userId is not a uuid", async () => {
    serve(() => ({ body: { ...session, userId: "../admin" } }));
    await expect(api().login("a@b.c", "AK", "x")).rejects.toMatchObject({ code: BAD_RESPONSE });
  });

  it("decodes AccountKeys without a genesis as null, for the identity fault at unlock", async () => {
    serve(() => ({ body: { ...accountKeys, genesis: undefined, personalWrap: null } }));
    const k = await api().accountKeys();
    expect(k.genesis).toBeNull();
    expect(k.personalWrap).toBeNull();
  });

  it("refuses AccountKeys under the KDF floor before anything derives under them", async () => {
    serve(() => ({ body: { ...accountKeys, kdfParams: { ...KDF, memBytes: 1024 } } }));
    await expect(api().accountKeys()).rejects.toThrow();
  });

  it("refuses a kdfParams with any field left out (spec 03 §0.1 field presence) or of the wrong type", async () => {
    serve(() => ({ body: { kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA", kdfParams: KDF } }));
    expect((await api().prelogin("a@b.c")).kdfParams).toEqual(KDF);
    vi.unstubAllGlobals();
    // An absent field is refused, never read as a default.
    serve(() => ({ body: { kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA", kdfParams: {} } }));
    await expect(api().prelogin("a@b.c")).rejects.toMatchObject({ code: BAD_RESPONSE });
    vi.unstubAllGlobals();
    serve(() => ({ body: { kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA", kdfParams: { v: 1, alg: "argon2id13", ops: 4 } } }));
    await expect(api().prelogin("a@b.c")).rejects.toMatchObject({ code: BAD_RESPONSE });
    vi.unstubAllGlobals();
    serve(() => ({ body: { kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA", kdfParams: { ...KDF, ops: "4" } } }));
    await expect(api().prelogin("a@b.c")).rejects.toMatchObject({ code: BAD_RESPONSE });
    vi.unstubAllGlobals();
    // A present field under the floor is still refused by the fence, and so is no object at all.
    serve(() => ({ body: { kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA", kdfParams: { ...KDF, ops: 1 } } }));
    await expect(api().prelogin("a@b.c")).rejects.toThrow();
    vi.unstubAllGlobals();
    serve(() => ({ body: { kdfSalt: "c2FsdHNhbHRzYWx0c2FsdA" } }));
    await expect(api().prelogin("a@b.c")).rejects.toMatchObject({ code: BAD_RESPONSE });
  });

  it("carries the extras of log_head_moved on the refusal", async () => {
    serve(() => ({ status: 409, body: { error: "log_head_moved", message: "m", seq: 4, hash: H, at: 1763164800000 } }));
    const e = (await api().appendLog(U1, { entry: "AAAA" }).catch((x) => x)) as ApiError;
    expect(e).toBeInstanceOf(ApiError);
    expect(e.code).toBe("log_head_moved");
    expect(e.extras).toEqual({ kind: "log_head_moved", head: { seq: 4, hash: H, at: 1763164800000 } });
  });

  it("pages the log until the served head", async () => {
    const pages = [
      { entries: ["AA", "AB"], head: { seq: 3, hash: H, at: 1 } },
      { entries: ["AC", "AD"], head: { seq: 3, hash: H, at: 1 } },
    ];
    const seen = serve(() => ({ body: pages.shift() }));
    const log = await api().fullLog(U1);
    expect(log.entries).toEqual(["AA", "AB", "AC", "AD"]);
    expect(seen.map((s) => s.url)).toEqual([`http://server/api/v1/vaults/${U1}/log`, `http://server/api/v1/vaults/${U1}/log?after=1`]);
  });

  it("refuses a log page with more than 500 entries", async () => {
    serve(() => ({ body: { entries: Array(501).fill("AA"), head: { seq: 600, hash: H, at: 1 } } }));
    await expect(api().logPage(U1, null)).rejects.toMatchObject({ code: BAD_RESPONSE });
  });

  it("reads a deleted vault's grace end on the log page and on the append answer (spec 03 §10.3, §10.6)", async () => {
    const head = { seq: 3, hash: H, at: 1 };
    serve((s) => ({ body: s.method === "POST" ? { rev: 4, head, deleted: { deletedAt: 1_000, purgeAt: 605_801_000 } } : { entries: [], head, deleted: { deletedAt: 1_000, purgeAt: 605_801_000 } } }));
    expect((await api().logPage(U1, 3)).deleted).toEqual({ deletedAt: 1_000, purgeAt: 605_801_000 });
    expect((await api().appendLog(U1, { entry: "AAAA" })).deleted).toEqual({ deletedAt: 1_000, purgeAt: 605_801_000 });
    vi.unstubAllGlobals();
    serve((s) => ({ body: s.method === "POST" ? { rev: 4, head, deleted: { deletedAt: 5, purgeAt: 5 } } : { entries: [], head } }));
    expect((await api().logPage(U1, 3)).deleted, "an older server sends no field").toBeNull();
    expect((await api().appendLog(U1, { entry: "AAAA" })).deleted, "a grace of zero is still a grace end").toEqual({ deletedAt: 5, purgeAt: 5 });
  });

  it("a grace end that is not two whole numbers, or ends before the delete, reads as absent and the answer still decodes", async () => {
    const head = { seq: 3, hash: H, at: 1 };
    const bad: unknown[] = [
      { deletedAt: 2_000, purgeAt: 1_999 },
      { deletedAt: "1000", purgeAt: 2_000 },
      { deletedAt: 1.5, purgeAt: 2_000 },
      { deletedAt: -1, purgeAt: 2_000 },
      { deletedAt: 1_000, purgeAt: 2 ** 60 },
      { deletedAt: 1_000 },
      [1_000, 2_000],
      "1000",
      null,
    ];
    for (const deleted of bad) {
      serve((s) => ({ body: s.method === "POST" ? { rev: 4, head, deleted } : { entries: [], head, deleted } }));
      const page = await api().logPage(U1, 3);
      expect(page.deleted, JSON.stringify(deleted)).toBeNull();
      expect(page.head.seq).toBe(3);
      const appended = await api().appendLog(U1, { entry: "AAAA" });
      expect(appended.deleted, JSON.stringify(deleted)).toBeNull();
      expect(appended.rev).toBe(4);
      vi.unstubAllGlobals();
    }
  });

  it("sends the deletion's leaves and confirm fields as spec 03 §13 names them", async () => {
    const seen = serve(() => ({ body: { deletedAt: 1763164800000 } }));
    await api().deleteAccountWithLeaves({ confirmEmail: "a@b.c", currentAuthKey: "AK", leaves: ["AAAA"] });
    expect(seen[0]!.body).toEqual({ confirmEmail: "a@b.c", currentAuthKey: "AK", leaves: ["AAAA"] });
  });

  it("refuses a request id that is not a path segment before any fetch", async () => {
    const seen = serve(() => ({ body: "ok" }));
    await expect(api().vetoRecoveryRequest("../admin", "AAAA")).rejects.toMatchObject({ code: "bad_path_segment" });
    expect(seen).toHaveLength(0);
  });

  it("decodes the delete preview's memberships with their heads", async () => {
    serve(() => ({
      body: { blockers: [], deletedVaults: [], leftVaults: [], memberships: [{ vaultId: U1, head: { seq: 2, hash: H, at: 5 } }], totpRequired: false },
    }));
    expect((await api().deletePreview()).memberships).toEqual([{ vaultId: U1, head: { seq: 2, hash: H, at: 5 } }]);
  });

  it("registers with a ticket and remembers the device row", async () => {
    const store = memory();
    const seen = serve(() => ({ body: { ...session, recoveryPieceId: "piece" } }));
    const a = api(store);
    const s = await a.register({
      auth: { signupTicket: "T" },
      email: "a@b.c",
      displayName: "A",
      userId: U1,
      kdfSalt: "s",
      kdfParams: KDF,
      authKey: "AK",
      wrappedUvk: "w",
      identityPub: KEY32,
      encryptedIdentitySeed: "e",
      genesis: "g",
      personalVault: { vaultId: U1, wrappedVk: "w", metaBlob: "m" },
      personalWrap: { vaultId: U1, wrappedVk: "w" },
      memberRecovery: { recoveryWrappedUvk: "r", recoveryAuthKey: "k" },
      recovery: { posture: "private" },
      ageConfirmed: true,
      device: a.newDevice("Firefox"),
    });
    expect(s.recoveryPieceId).toBe("piece");
    expect(seen[0]!.url).toBe("http://server/api/v1/auth/register");
    expect(a.device.deviceIdFor("A@B.C")).toBe(D1);
  });

  it("decodes the client policy's sign-up block and refuses an unknown mode", async () => {
    const policy = {
      minVersion: { web: "0.1.0" },
      kdfParams: KDF,
      autoLockSeconds: 300,
      clipboardClearSeconds: 30,
      offlineCacheAllowed: true,
      sessionAccessTtlSeconds: 3600,
      sessionRefreshTtlDays: 30,
      attachmentMaxBytes: 1,
      itemAttachmentsMaxBytes: 1,
      serverTime: 1,
      signup: { mode: "open", full: false, ageConfirmRequired: true, powBits: 0 },
      totpRequired: false,
      unknownField: 1,
    };
    serve(() => ({ body: policy }));
    expect((await api().clientPolicy()).signup).toEqual({ mode: "open", full: false, ageConfirmRequired: true, powBits: 0 });
    serve(() => ({ body: { ...policy, signup: { ...policy.signup, mode: "wide-open" } } }));
    await expect(api().clientPolicy()).rejects.toMatchObject({ code: BAD_RESPONSE });
  });
});

describe("decodeSync", () => {
  it("drops and reports a row with a malformed id, keeping the rest", () => {
    const d = decodeSync({
      rev: 9,
      full: true,
      vaults: [
        { vaultId: U1, type: "shared", rev: 1, metaBlob: "m", createdAt: 1, logHead: { seq: 2, hash: H } },
        { vaultId: "x/../y", type: "shared", rev: 1, metaBlob: "m", createdAt: 1 },
      ],
      grants: [],
      items: [],
      removedGrants: [U1, "nope"],
      linkAnswers: 2,
      recoveryRequests: 1,
    });
    expect(d.value.vaults.map((v) => v.vaultId)).toEqual([U1]);
    expect(d.value.vaults[0]!.logHead).toEqual({ seq: 2, hash: H });
    expect(d.value.removedGrants).toEqual([U1]);
    expect(d.value.recoveryRequests).toBe(1);
    expect(d.refused.map((r) => r.field)).toEqual(["vaults.vaultId", "removedGrants"]);
    expect(d.value.accountStateSeq).toBeNull(); // an answer without the counter
  });

  it("keeps the account state's counter (spec 03 §4); a value that is not a counter reads as none, so it never skips a read", () => {
    const base = { rev: 1, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    expect(decodeSync({ ...base, accountStateSeq: 7 }).value.accountStateSeq).toBe(7);
    expect(decodeSync({ ...base, accountStateSeq: 0 }).value.accountStateSeq).toBe(0);
    for (const bad of [-1, 1.5, "7", null, true]) expect(decodeSync({ ...base, accountStateSeq: bad } as never).value.accountStateSeq, String(bad)).toBeNull();
  });

  it("refuses a log head whose hash is not hex64", () => {
    expect(() =>
      decodeSync({ rev: 1, full: true, vaults: [{ vaultId: U1, type: "shared", rev: 1, metaBlob: "m", createdAt: 1, logHead: { seq: 2, hash: "ZZ" } }], grants: [], items: [], removedGrants: [] }),
    ).toThrow(/logHead.hash/);
  });
});
