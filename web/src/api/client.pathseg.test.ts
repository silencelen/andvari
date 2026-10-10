import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

/**
 * Security review 2026-10 (root cause D): an item id or attachment id a co-member authored went
 * into an authenticated URL path raw. fetch's URL parser resolves `..` segments and splits `?`,
 * so a planted `../admin/users/<id>/disable?` turned the victim's "Delete forever" into
 * `POST /api/v1/admin/users/<id>/disable` carrying an admin's bearer token, and a planted
 * attachment id turned a download into a forged `escrow_admin_read` audit row. Every id path
 * segment now passes one gate: a refused id never reaches fetch at all, and an accepted one is
 * percent-encoded. Encoding ALONE would not be enough — WHATWG treats `%2e%2e` as `..` too.
 */

const okResp = (): Response =>
  ({ ok: true, status: 200, statusText: "200", json: async () => ({ rev: 1 }), text: async () => "{\"rev\":1}", arrayBuffer: async () => new ArrayBuffer(0) }) as unknown as Response;

function stub(): { urls: string[] } {
  const urls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL) => {
      urls.push(String(url));
      return okResp();
    }),
  );
  return { urls };
}

const client = () => new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });

const HOSTILE = [
  "../admin/users/0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b/disable?",
  "../admin/users/x/escrow",
  "..",
  ".",
  "%2e%2e",
  "a/b",
  "a\\b",
  "a?b",
  "a#b",
  "",
];

describe("ApiClient refuses a non-id path segment before any request", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("purge / restore / versions refuse a planted item id", async () => {
    const { urls } = stub();
    for (const id of HOSTILE) {
      await expect(client().purgeItem(id), `purge ${JSON.stringify(id)}`).rejects.toThrow();
      await expect(client().restoreItem(id, { formatVersion: 1, attachmentIds: [], blob: "x" }), `restore ${JSON.stringify(id)}`).rejects.toThrow();
      await expect(client().itemVersions(id), `versions ${JSON.stringify(id)}`).rejects.toThrow();
    }
    expect(urls).toEqual([]);
  });

  it("attachment download / upload refuse a planted attachment id", async () => {
    const { urls } = stub();
    for (const id of HOSTILE) {
      await expect(client().downloadAttachment(id), `download ${JSON.stringify(id)}`).rejects.toThrow();
      await expect(client().uploadAttachment(id, "i", "v", new Uint8Array(1)), `upload ${JSON.stringify(id)}`).rejects.toThrow();
    }
    expect(urls).toEqual([]);
  });

  it("vault / member / admin routes refuse a non-id segment too", async () => {
    const { urls } = stub();
    await expect(client().leaveVault("../recovery/self/confirm?")).rejects.toThrow();
    await expect(client().vaultMembers("..")).rejects.toThrow();
    await expect(client().adminDisableUser("../../x")).rejects.toThrow();
    await expect(client().adminRevokeDevice("a/b")).rejects.toThrow();
    expect(urls).toEqual([]);
  });

  it("a real id still reaches exactly its own route", async () => {
    const { urls } = stub();
    const id = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
    await client().purgeItem(id);
    await client().downloadAttachment(id);
    expect(urls).toEqual([`http://server/api/v1/items/${id}/purge`, `http://server/api/v1/attachments/${id}`]);
  });
});
