import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";

/**
 * The eight vault-lifecycle routes (spec 03 §11) map to the exact method + path + body the
 * live CT122 server exposes. A stubbed fetch records each request; each test asserts the wire
 * shape (an off-by-one path or a wrong verb is silent breakage the typed method must prevent).
 */

const jsonResp = (status: number, body: unknown): Response =>
  ({
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    json: async () => body,
    text: async () => JSON.stringify(body),
  }) as unknown as Response;

interface Captured {
  method: string;
  path: string;
  body: unknown;
}

function stub(responseBody: unknown = {}): { calls: Captured[] } {
  const calls: Captured[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      calls.push({
        method: init?.method ?? "GET",
        path: String(url).replace("http://server", ""),
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      return jsonResp(200, responseBody);
    }),
  );
  return { calls };
}

const client = () => new ApiClient("http://server", { accessToken: "a", refreshToken: "r" });

describe("ApiClient vault-lifecycle routes (spec 03 §11)", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("POST /vaults/{id}/delete carries {deleteId, proof}", async () => {
    const { calls } = stub({ rev: 2, purgeAt: 99 });
    const r = await client().deleteVault("v1", { deleteId: "d", proof: "p" });
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/v1/vaults/v1/delete", body: { deleteId: "d", proof: "p" } });
    expect(r).toEqual({ rev: 2, purgeAt: 99 });
  });

  it("POST /vaults/{id}/restore carries {deleteId, proof}", async () => {
    const { calls } = stub({ rev: 3 });
    await client().restoreVault("v1", { deleteId: "d", proof: "p" });
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/v1/vaults/v1/restore", body: { deleteId: "d", proof: "p" } });
  });

  it("GET /vaults/deleted", async () => {
    const { calls } = stub([]);
    await client().deletedVaults();
    expect(calls[0]).toMatchObject({ method: "GET", path: "/api/v1/vaults/deleted" });
  });

  it("POST /vaults/{id}/leave with an empty body", async () => {
    const { calls } = stub({ rev: 4 });
    await client().leaveVault("v1");
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/v1/vaults/v1/leave", body: {} });
  });

  it("POST /vaults/{id}/transfer carries the offer", async () => {
    const { calls } = stub({ rev: 5, expiresAt: 7 });
    await client().offerTransfer("v1", { toUserId: "u2", offerId: "o", expiresAt: 7, proof: "p" });
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/v1/vaults/v1/transfer", body: { toUserId: "u2", offerId: "o", expiresAt: 7, proof: "p" } });
  });

  it("DELETE /vaults/{id}/transfer", async () => {
    const { calls } = stub({ rev: 6 });
    await client().cancelTransfer("v1");
    expect(calls[0]).toMatchObject({ method: "DELETE", path: "/api/v1/vaults/v1/transfer" });
  });

  it("POST /vaults/{id}/transfer/accept carries {offerId, wrappedVk, proof}", async () => {
    const { calls } = stub({ rev: 7 });
    await client().acceptTransfer("v1", { offerId: "o", wrappedVk: "w", proof: "p" });
    expect(calls[0]).toMatchObject({ method: "POST", path: "/api/v1/vaults/v1/transfer/accept", body: { offerId: "o", wrappedVk: "w", proof: "p" } });
  });

  it("PUT /vaults/{id}/meta carries {metaBlob, baseVaultRev}", async () => {
    const { calls } = stub({ rev: 8 });
    await client().updateVaultMeta("v1", { metaBlob: "m", baseVaultRev: 4 });
    expect(calls[0]).toMatchObject({ method: "PUT", path: "/api/v1/vaults/v1/meta", body: { metaBlob: "m", baseVaultRev: 4 } });
  });

  it("removeVaultMember rides an OPTIONAL proof body — present when given, absent otherwise", async () => {
    const withProof = stub({ rev: 9 });
    await client().removeVaultMember("v1", "u2", { proof: "p", nonce: "n" });
    expect(withProof.calls[0]).toMatchObject({ method: "DELETE", path: "/api/v1/vaults/v1/members/u2", body: { proof: "p", nonce: "n" } });
    vi.unstubAllGlobals();

    const noProof = stub({ rev: 9 });
    await client().removeVaultMember("v1", "u2");
    expect(noProof.calls[0]).toMatchObject({ method: "DELETE", path: "/api/v1/vaults/v1/members/u2" });
    expect(noProof.calls[0]!.body).toBeUndefined(); // the proofless 0.4.0 shape (no body)
  });
});
