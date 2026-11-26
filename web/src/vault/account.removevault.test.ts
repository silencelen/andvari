import { beforeAll, describe, expect, it } from "vitest";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";

/**
 * A removed vault's key is wiped before its map entry goes. The store drops a removed vault through
 * `removeVault` first and the log key ring's `delete` second; the ring's own wipe then found no entry, so the key was
 * never zero-filled.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const V = "55555555-5555-4555-8555-555555555555";

beforeAll(async () => {
  await initSodium();
});

describe("a removed vault's key is wiped", () => {
  it("removeVault zero-fills the key, also when the log key ring's delete comes after it", async () => {
    const recovery = boxKeypairFromSeed(randomBytes(32));
    const { account } = await Account.enroll({
      inviteToken: "n3",
      email: "n3@example.com",
      displayName: "n3",
      password: "n3 removal password",
      kdfParams: KDF,
      recoveryPublicKey: recovery.publicKey,
      recoveryFingerprint: await fingerprint(recovery.publicKey),
    });
    const vk = randomBytes(32);
    vk[0] = 1;
    account.logKeyRing().set(V, vk);
    expect(account.hasVault(V)).toBe(true);
    account.removeVault(V);
    account.logKeyRing().delete(V);
    expect(account.hasVault(V)).toBe(false);
    expect([...vk].every((b) => b === 0)).toBe(true);
  });
});
