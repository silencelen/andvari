import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError } from "./client";
import { DeviceIdentity, memoryStorage } from "./devicesecret";
import type { Refusal } from "./wireids";
import { BAD_RESPONSE, WireApi } from "./wireclient";

/**
 * The item routes of spec 03 §4 to §9 as the web calls them: sync push, item history and trash, attachments and the
 * usage ledger. Each test pins the request the browser sends (path, method, body) and what it accepts back.
 */
const V1 = "11111111-1111-4111-8111-111111111111";
const I1 = "22222222-2222-4222-8222-222222222222";
const A1 = "33333333-3333-4333-8333-333333333333";
const M1 = "44444444-4444-4444-8444-444444444444";

interface Seen {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function serve(answer: (s: Seen) => { status?: number; body?: unknown; bytes?: Uint8Array }): Seen[] {
  const seen: Seen[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const raw = init?.body;
      const s: Seen = { url, method: init?.method ?? "GET", headers: (init?.headers ?? {}) as Record<string, string>, body: typeof raw === "string" ? JSON.parse(raw) : raw };
      seen.push(s);
      const a = answer(s);
      const status = a.status ?? 200;
      const text = typeof a.body === "string" ? a.body : JSON.stringify(a.body ?? null);
      return {
        ok: status < 400,
        status,
        statusText: String(status),
        json: async () => JSON.parse(text),
        text: async () => text,
        arrayBuffer: async () => (a.bytes ?? new Uint8Array()).slice().buffer,
      } as unknown as Response;
    }),
  );
  return seen;
}

function api(refused: [string, Refusal[]][] = []) {
  return new WireApi(new ApiClient("http://server", { accessToken: "acc", refreshToken: "ref" }), new DeviceIdentity(memoryStorage()), (endpoint, r) => refused.push([endpoint, r]));
}

const item = { itemId: I1, vaultId: V1, rev: 9, createdAt: 1, updatedAt: 2, deleted: false, conflict: false, formatVersion: 2, attachmentIds: [], blob: "AQEAAA" };

describe("WireApi: sync push, items, attachments, usage", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("pushes the mutations as spec 03 §5 writes them and reads a status per mutation", async () => {
    const seen = serve(() => ({
      body: {
        rev: 12,
        results: [
          { mutationId: M1, status: "applied", newItemRev: 12 },
          { mutationId: "m2", status: "conflict", newItemRev: 12, serverItem: item },
          { mutationId: "m3", status: "rejected", reason: "quota_exceeded", serverItem: null },
          // A status this build does not know still reaches the drain (it is "definitive: dequeue").
          { mutationId: "m4", status: "something_new" },
        ],
      },
    }));
    const m = { mutationId: M1, op: "put" as const, itemId: I1, vaultId: V1, baseItemRev: 0, item: { formatVersion: 2, attachmentIds: [], blob: "AQEAAA" } };
    const r = await api().pushMutations([m]);
    expect(seen[0]).toMatchObject({ url: "http://server/api/v1/sync/push", method: "POST", body: { mutations: [m] } });
    expect(r.rev).toBe(12);
    expect(r.results[0]).toEqual({ mutationId: M1, status: "applied", newItemRev: 12 });
    expect(r.results[1]!.serverItem).toEqual(item);
    expect(r.results[2]).toEqual({ mutationId: "m3", status: "rejected", reason: "quota_exceeded" });
    expect(r.results[3]!.status).toBe("something_new");
  });

  it("reads serverItemOmitted (spec 03 §5): no item beside it, and a non-boolean is reported", async () => {
    const refused: [string, Refusal[]][] = [];
    serve(() => ({
      body: {
        rev: 3,
        results: [
          { mutationId: M1, status: "conflict", newItemRev: 3, serverItemOmitted: true },
          { mutationId: "m2", status: "conflict", newItemRev: 4, serverItemOmitted: true, serverItem: item },
          { mutationId: "m3", status: "applied", newItemRev: 5, serverItemOmitted: "yes" },
        ],
      },
    }));
    const r = await api(refused).pushMutations([]);
    expect(r.results[0]).toEqual({ mutationId: M1, status: "conflict", newItemRev: 3, serverItemOmitted: true });
    expect(r.results[1]!.serverItem).toBeUndefined();
    expect(r.results[1]!.serverItemOmitted).toBe(true);
    expect(r.results[2]!.serverItemOmitted).toBeUndefined();
    expect(refused).toEqual([["sync/push", [{ field: "results.serverItem", value: "beside serverItemOmitted" }, { field: "results.serverItemOmitted", value: "yes" }]]]);
  });

  it("drops and reports a displaced item whose id is malformed, and refuses an answer that is not the route's shape", async () => {
    const refused: [string, Refusal[]][] = [];
    serve(() => ({ body: { rev: 3, results: [{ mutationId: M1, status: "conflict", newItemRev: 3, serverItem: { ...item, vaultId: "../admin" } }] } }));
    const r = await api(refused).pushMutations([]);
    expect(r.results[0]!.serverItem).toBeUndefined();
    expect(refused).toEqual([["sync/push", [{ field: "results.serverItem.vaultId", value: "../admin" }]]]);
    vi.unstubAllGlobals();
    serve(() => ({ body: { rev: "3", results: [] } }));
    await expect(api().pushMutations([])).rejects.toMatchObject({ code: BAD_RESPONSE });
    vi.unstubAllGlobals();
    serve(() => ({ body: { rev: 3, results: [{ mutationId: M1 }] } }));
    await expect(api().pushMutations([])).rejects.toMatchObject({ code: BAD_RESPONSE });
  });

  it("a thrown batch refusal is the server's error, with its code", async () => {
    serve(() => ({ status: 400, body: { error: "batch_too_large", message: "x" } }));
    await expect(api().pushMutations([])).rejects.toMatchObject({ status: 400, code: "batch_too_large" });
  });

  it("reads an item's versions only when the answer is for that item", async () => {
    const seen = serve(() => ({ body: { itemId: I1, versions: [{ rev: 4, blob: "AQEAAA", formatVersion: 2, archivedAt: 77 }] } }));
    const r = await api().itemVersions(I1);
    expect(seen[0]!.url).toBe(`http://server/api/v1/items/${I1}/versions`);
    expect(r.versions).toEqual([{ rev: 4, blob: "AQEAAA", formatVersion: 2, archivedAt: 77 }]);
    await expect(api().itemVersions(A1)).rejects.toMatchObject({ code: BAD_RESPONSE });
  });

  it("refuses a path segment that is not an id before anything is sent", async () => {
    const seen = serve(() => ({ body: {} }));
    await expect(api().itemVersions("../admin/accounts")).rejects.toBeInstanceOf(Error);
    await expect(api().purgeItem("x/y")).rejects.toBeInstanceOf(Error);
    await expect(api().downloadAttachment("..")).rejects.toBeInstanceOf(Error);
    expect(seen).toEqual([]);
  });

  it("lists the trash, dropping a row with a malformed id, and restores and purges by the routes of §5.1", async () => {
    const refused: [string, Refusal[]][] = [];
    const seen = serve((s) => {
      if (s.url.endsWith("/items/deleted")) return { body: { items: [{ itemId: "nope", vaultId: V1, deletedAt: 6 }, { itemId: I1, vaultId: V1, deletedAt: 5 }] } }; // newest first (§5.1)
      return { body: { rev: 21 } };
    });
    const a = api(refused);
    expect((await a.deletedItems()).items).toEqual([{ itemId: I1, vaultId: V1, deletedAt: 5 }]);
    expect(refused[0]![0]).toBe("items/deleted");
    const upload = { formatVersion: 2, attachmentIds: [], blob: "AQEAAA" };
    expect(await a.restoreItem(I1, upload)).toEqual({ rev: 21 });
    expect(seen[1]).toMatchObject({ url: `http://server/api/v1/items/${I1}/restore`, method: "POST", body: upload });
    expect(await a.purgeItem(I1)).toEqual({ rev: 21 });
    expect(seen[2]).toMatchObject({ url: `http://server/api/v1/items/${I1}/purge`, method: "POST" });
    expect(seen[2]!.body).toBeUndefined();
  });

  it("uploads raw bytes under the three ids and accepts only a meta that names them", async () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const meta = { attachmentId: A1, itemId: I1, vaultId: V1, size: 4, sha256: "a".repeat(64), createdAt: 9 };
    const seen = serve(() => ({ body: meta }));
    expect(await api().uploadAttachment(A1, I1, V1, bytes)).toEqual(meta);
    expect(seen[0]!.url).toBe(`http://server/api/v1/attachments/${A1}?vaultId=${V1}&itemId=${I1}`);
    expect(seen[0]!.method).toBe("POST");
    expect(seen[0]!.headers["Content-Type"]).toBe("application/octet-stream");
    expect(seen[0]!.headers.Authorization).toBe("Bearer acc");
    expect(seen[0]!.body).toBe(bytes);
    vi.unstubAllGlobals();
    serve(() => ({ body: { ...meta, itemId: M1 } }));
    await expect(api().uploadAttachment(A1, I1, V1, bytes)).rejects.toMatchObject({ code: BAD_RESPONSE });
    vi.unstubAllGlobals();
    serve(() => ({ status: 413, body: { error: "quota_exceeded", message: "x", quota: "accountBytes" } }));
    const e = await api().uploadAttachment(A1, I1, V1, bytes).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect((e as ApiError).extras).toEqual({ kind: "quota_exceeded", quota: "accountBytes" });
  });

  it("downloads the stored bytes as they are", async () => {
    const seen = serve(() => ({ bytes: new Uint8Array([9, 8, 7]) }));
    expect([...(await api().downloadAttachment(A1))]).toEqual([9, 8, 7]);
    expect(seen[0]).toMatchObject({ url: `http://server/api/v1/attachments/${A1}`, method: "GET" });
  });

  it("reads the usage ledger (null is 'never written') and a refused write rejects", async () => {
    const seen = serve((s) => (s.method === "GET" ? { body: { sealedUsage: null, updatedAt: 0 } } : { body: "ok" }));
    const a = api();
    expect(await a.usage()).toEqual({ sealedUsage: null, updatedAt: 0 });
    await a.putUsage("AQEAAA");
    expect(seen[1]).toMatchObject({ url: "http://server/api/v1/usage", method: "PUT", body: { sealedUsage: "AQEAAA" } });
    vi.unstubAllGlobals();
    serve(() => ({ status: 400, body: { error: "bad_usage_blob", message: "x" } }));
    await expect(api().putUsage("AQEAAA")).rejects.toMatchObject({ code: "bad_usage_blob" });
  });
});
