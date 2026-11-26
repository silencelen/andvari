import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { WireApi } from "../api/wireclient";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { FakeSharedLogs } from "./fakesharedlogs.testkit";
import { VaultStore } from "./store";

/**
 * A third review of the two limits on an answer: a sync answered 401 whose body never came, after a refresh that failed,
 * waited without end, and every later sync (the minute's poll, "Sync now", the bell) joined it, with no line on the
 * screen. Now that sync ends thirty seconds after the 401's head, and the next sync goes out and is answered.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const EMPTY_SYNC = JSON.stringify({ rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] });

describe("a later sync is not queued behind a request that will never end", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("the 401 without a body after a refresh answered by a 503 page ends at once (a renewal with no answer), and the next sync is answered", async () => {
    const recovery = boxKeypairFromSeed(randomBytes(32));
    const { request } = await Account.enroll({ inviteToken: "t", email: "l1@example.com", displayName: "l1", password: "pw", kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
    const device = await Account.unlock(request.userId, "pw", { kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed, identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap! });

    const calls: string[] = [];
    let syncs = 0;
    vi.stubGlobal("fetch", async (url: string) => {
      const path = new URL(url).pathname;
      calls.push(path);
      if (path === "/api/v1/auth/refresh") return new Response("busy", { status: 503 });
      if (path === "/api/v1/sync" && syncs++ === 0) {
        return new Response(new ReadableStream<Uint8Array>({ start() {} }), { status: 401, headers: { "Content-Type": "application/json" } });
      }
      if (path === "/api/v1/sync") return new Response(EMPTY_SYNC, { status: 200, headers: { "Content-Type": "application/json" } });
      return new Response('{"error":"not_found"}', { status: 404, headers: { "Content-Type": "application/json" } });
    });
    vi.useFakeTimers();
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "a", refreshToken: "r" });
    const wire = new WireApi(client);
    const store = new VaultStore(client, device, undefined, memoryClientState(), wire);
    new FakeSharedLogs(device).attachTo(store);

    const first = { settled: false, error: undefined as unknown };
    store.sync().then(
      () => (first.settled = true),
      (e: unknown) => Object.assign(first, { settled: true, error: e }),
    );
    // The 401 is not handed back to wait on its body: the request fails at once as one whose renewal got no answer.
    await vi.advanceTimersByTimeAsync(1_000);
    expect(first.settled, "the first sync is ended without waiting on the 401's body").toBe(true);
    expect(first.error).toBeTruthy();

    const later = { settled: false, error: undefined as unknown };
    store.sync().then(
      () => (later.settled = true),
      (e: unknown) => Object.assign(later, { settled: true, error: e }),
    );
    await vi.advanceTimersByTimeAsync(1_000);
    expect(later.settled, "a later sync goes out and is answered").toBe(true);
    expect(later.error).toBeUndefined();
    expect(calls.filter((p) => p === "/api/v1/sync")).toHaveLength(2);
  });
});
