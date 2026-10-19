import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "./client";
import type { Refusal } from "./wireids";

/**
 * Security review 2026-10, branch A11 (c21, LOW): a malformed `personalWrap.vaultId` refused at login or register raised
 * no `bad-id` anomaly, because the store installs `onRefusedIds` only once it exists, after the session. The client now
 * keeps refusals reported while no handler is installed and hands them to the handler the moment one is.
 */

const good = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";
const other = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
const KEYS = { kdfSalt: "s", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 }, wrappedUvk: "w", encryptedIdentitySeed: "e", identityPub: "p", escrowFingerprint: "f" };
const resp = (body: unknown): Response =>
  ({ ok: true, status: 200, statusText: "200", json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;
const session = { userId: good, deviceId: other, accessToken: "a", refreshToken: "r", isAdmin: false, accountKeys: { ...KEYS, personalWrap: { vaultId: `${good}|x`, wrappedVk: "w" } } };

describe("refusals before the store exists (A11 c21)", () => {
  afterEach(() => vi.unstubAllGlobals());

  for (const call of ["login", "register"] as const) {
    it(`a refusal on ${call} reaches a handler installed afterwards, once`, async () => {
      vi.stubGlobal("fetch", vi.fn(async () => resp(session)));
      const client = new ApiClient("http://server", null);
      const s = call === "login" ? await client.login("e@x", "a", "d") : await client.register({} as never);
      expect(s.accountKeys.personalWrap ?? null).toBeNull();
      const got: { endpoint: string; refused: Refusal[] }[] = [];
      client.onRefusedIds = (endpoint, refused) => got.push({ endpoint, refused });
      expect(got).toEqual([{ endpoint: call, refused: [{ field: "personalWrap.vaultId", value: `${good}|x` }] }]);
      client.onRefusedIds = (endpoint, refused) => got.push({ endpoint, refused });
      expect(got).toHaveLength(1); // delivered once, not replayed to the next handler
    });
  }
});
