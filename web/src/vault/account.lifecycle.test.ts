import { beforeAll, describe, expect, it } from "vitest";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { vaultMadeBy } from "./fakesharedlogs.testkit";

/**
 * The VK-exposure surface the lifecycle needs (spec 03 §11): rename's read-modify-write of the metaBlob (name only,
 * metaV monotonic, unknown fields kept).
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

async function enroll(email = "a@example.com"): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "t",
    email,
    displayName: email,
    password: `pw ${email}`,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

describe("Account vault-lifecycle crypto (spec 03 §11)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("buildRenameMeta changes only the name and bumps metaV monotonically (read-modify-write)", async () => {
    const owner = await enroll();
    const { request, vaultId } = vaultMadeBy(owner, "Family"); // creation blob has no metaV
    owner.attachLogRoles(() => "owner", () => true); // the verified log names this account its owner

    const b1 = owner.buildRenameMeta(vaultId, request.metaBlob, "Household");
    expect(owner.decryptVaultName(vaultId, b1)).toBe("Household");
    expect(owner.decryptVaultMeta(vaultId, b1).metaV).toBe(1);

    // A SECOND rename must READ b1's metaV (=1) and bump to 2 — proving it preserves existing
    // structure rather than resetting it; the same {...meta} spread carries any unknown fields.
    const b2 = owner.buildRenameMeta(vaultId, b1, "The Hoard");
    expect(owner.decryptVaultName(vaultId, b2)).toBe("The Hoard");
    expect(owner.decryptVaultMeta(vaultId, b2).metaV).toBe(2);
  });
});
