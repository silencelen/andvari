import { beforeAll, describe, expect, it } from "vitest";
import { adVaultMeta } from "../crypto/ad";
import { fromB64, toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { openSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, MalformedVaultMetaError } from "./account";

/**
 * Security review 2026-10, branch A11 (q55, LOW): the vault meta plaintext is authored by ANY holder of the vault key,
 * so a co-member can seal `null`, a string or an array there. decryptVaultMeta cast it without a shape check: `null`
 * crashed the owner's rename with a TypeError, and a string/array was spread into the rewritten meta as index keys.
 * Now decryptVaultMeta refuses a non-object ({@link MalformedVaultMetaError}) and a rename over such a blob writes a
 * clean meta (just the new name, the counter restarted), instead of crashing or carrying the junk forward.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

async function enroll(email = "a@example.com"): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "t", email, displayName: email, password: `pw ${email}`, kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

describe("vault meta shape (A11 q55)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a non-object meta plaintext is refused on read and replaced cleanly on rename", async () => {
    const owner = await enroll();
    const { vaultId } = owner.buildCreateSharedVault("Family");
    // A co-member's view of the same VK (any holder can seal a meta blob).
    const kp = boxKeypairFromSeed(randomBytes(32));
    const vk = openSharedGrant(kp.publicKey, kp.privateKey, vaultId, fromB64(owner.wrapVkForMember(kp.publicKey, vaultId)));
    for (const junk of ["null", '"abc"', "[1,2,3]", "7", "true"]) {
      const blob = toB64(seal(vk, utf8(junk), adVaultMeta(vaultId)));
      expect(() => owner.decryptVaultMeta(vaultId, blob), junk).toThrow(MalformedVaultMetaError);
      const renamed = owner.buildRenameMeta(vaultId, blob, "Clean");
      const meta = owner.decryptVaultMeta(vaultId, renamed);
      expect(meta, junk).toEqual({ name: "Clean", metaV: 1 });
      expect(owner.decryptVaultName(vaultId, blob), junk).toBe("(vault)");
    }
  });
});
