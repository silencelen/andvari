import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "./client";
import { KdfPolicyError } from "../crypto/keys";

/**
 * H1 (spec 05 T1): the web client rejects SERVER-SUPPLIED KDF params outside the sanity fence at the
 * response boundary (prelogin / login+register session / client-policy / account keys) BEFORE any
 * argon2id derives under them — a hostile/misconfigured server can neither weaken the master-password
 * KDF nor DoS it. The fence lives in client.ts, never in masterKey (the vectors derive below the
 * floor). Fence numbers mirror core KdfUpgrade + extension crypto.ts. Also pins the R2 closure:
 * a weakened client-policy can no longer reach buildPasswordChange because the fetch itself throws.
 */

const WEAK = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 }; // libsodium minimum
const FLOOR = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }; // at-floor default — must pass
const CEIL = { v: 1, alg: "argon2id13", ops: 3, memBytes: 2_147_483_648 }; // 2 GiB > the 1 GiB ceiling
const TOKENS: Tokens = { accessToken: "at", refreshToken: "rt" };

const jsonResp = (body: unknown): Response =>
  ({ ok: true, status: 200, statusText: "200", json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

const stub = (body: unknown) => vi.stubGlobal("fetch", vi.fn(async () => jsonResp(body)));

const acct = (kdfParams: unknown) => ({ kdfSalt: "AA", kdfParams, wrappedUvk: "AA", encryptedIdentitySeed: "AA", identityPub: "AA", escrowFingerprint: "AA" });
const session = (kdfParams: unknown) => ({ userId: "u", deviceId: "d", accessToken: "s-at", refreshToken: "s-rt", accountKeys: acct(kdfParams), isAdmin: false });

describe("H1 client-side KDF fence", () => {
  afterEach(() => vi.restoreAllMocks());

  it("rejects a weakened prelogin before any argon2id", async () => {
    stub({ kdfSalt: "AA", kdfParams: WEAK });
    await expect(new ApiClient("http://s").prelogin("a@b.c")).rejects.toBeInstanceOf(KdfPolicyError);
  });

  it("rejects a prelogin whose kdfParams OMITS ops/memBytes (non-numeric JS bypass guard)", async () => {
    stub({ kdfSalt: "AA", kdfParams: { v: 1, alg: "argon2id13" } });
    await expect(new ApiClient("http://s").prelogin("a@b.c")).rejects.toBeInstanceOf(KdfPolicyError);
  });

  it("accepts the honest at-floor default", async () => {
    stub({ kdfSalt: "AA", kdfParams: FLOOR });
    await expect(new ApiClient("http://s").prelogin("a@b.c")).resolves.toMatchObject({ kdfParams: { memBytes: 67_108_864 } });
  });

  it("rejects an over-ceiling client-policy (closes the export/password-change reuse paths)", async () => {
    stub({ minVersion: {}, kdfParams: CEIL });
    await expect(new ApiClient("http://s").clientPolicy()).rejects.toBeInstanceOf(KdfPolicyError);
  });

  it("refuses a weakened login session BEFORE installing tokens", async () => {
    stub(session(WEAK));
    const onTokens = vi.fn();
    const c = new ApiClient("http://s", undefined, onTokens);
    await expect(c.login("a@b.c", "authkey", "dev")).rejects.toBeInstanceOf(KdfPolicyError);
    expect(onTokens).not.toHaveBeenCalled(); // never installed the stolen/weak session
  });

  it("tolerates an account-keys body with no kdfParams (the refresh-mock contract)", async () => {
    stub({});
    await expect(new ApiClient("http://s", TOKENS).accountKeys()).resolves.toEqual({});
  });
});
