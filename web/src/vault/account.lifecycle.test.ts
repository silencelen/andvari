import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64 } from "../crypto/bytes";
import { fingerprint, openEscrow } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";

/**
 * The VK-exposure surface the lifecycle needs (spec 03 §11): the lifecycleKey derivation, the
 * accept-flow owner re-wrap (same construction as vault creation, round-trip verified), and
 * rename's read-modify-write of the metaBlob (name only, metaV monotonic, unknown fields kept).
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

  it("resealEscrowFor re-seals the SAME UVK to a rotated recovery key, verified against the sheet (F57)", async () => {
    // Enroll against recovery key #1.
    const rec1 = boxKeypairFromSeed(randomBytes(32));
    const fp1 = await fingerprint(rec1.publicKey);
    const { request, account } = await Account.enroll({
      inviteToken: "t", email: "u@e.com", displayName: "u", password: "pw",
      kdfParams: KDF, recoveryPublicKey: rec1.publicKey, recoveryFingerprint: fp1,
    });
    // Oracle: the UVK recovered from the ORIGINAL escrow (sealed to key #1).
    const uvk1 = await openEscrow(rec1.publicKey, rec1.privateKey, fromB64(request.escrow.sealed));

    // Re-ceremony rotates to recovery key #2; the user confirmed fp2 against the new sheet.
    const rec2 = boxKeypairFromSeed(randomBytes(32));
    const fp2 = await fingerprint(rec2.publicKey);
    const upload = await account.resealEscrowFor(toB64(rec2.publicKey), fp2);
    expect(upload.fingerprint).toBe(fp2);
    // The re-sealed blob opens with key #2 and yields the SAME UVK (data stays recoverable).
    const uvk2 = await openEscrow(rec2.publicKey, rec2.privateKey, fromB64(upload.sealed));
    expect(uvk2.key).toBe(uvk1.key);
    expect(uvk2.userId).toBe(account.userId);

    // SECURITY: refuse to seal if the fetched pubkey doesn't match the sheet-verified fingerprint —
    // a hostile server cannot redirect the UVK escrow to an attacker key.
    await expect(account.resealEscrowFor(toB64(rec2.publicKey), fp1)).rejects.toThrow(/fingerprint/);
  });

  it("lifecycleKeyFor derives HKDF(VK, 'andvari/v1|lifecycle') identically for every VK holder", async () => {
    const owner = await enroll("owner@example.com");
    const member = await enroll("member@example.com");
    const { vaultId } = owner.buildCreateSharedVault("Family");
    const sealed = owner.wrapVkForMember(member.identityPub, vaultId);
    member.addGrant({ vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 1, sealedVk: sealed });
    // The owner and the member hold the SAME VK → the SAME lifecycle key, so a member can verify
    // the owner's proofs (and mint its own for accept).
    expect(toB64(await owner.lifecycleKeyFor(vaultId))).toBe(toB64(await member.lifecycleKeyFor(vaultId)));
  });

  it("buildOwnerWrap re-wraps the held VK under the caller's UVK — a forgotten VK re-opens from it", async () => {
    const owner = await enroll("owner@example.com");
    const member = await enroll("member@example.com");
    const { vaultId } = owner.buildCreateSharedVault("Family");
    const sealed = owner.wrapVkForMember(member.identityPub, vaultId);
    member.addGrant({ vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 1, sealedVk: sealed });

    // The accept flow's wrappedVk (round-trip-verified inside buildOwnerWrap).
    const wrappedVk = member.buildOwnerWrap(vaultId);

    // Prove it is the real VK: drop the key, then re-open it as an owner grant carrying that wrap
    // and decrypt a real item the owner sealed under the vault VK.
    const itemId = owner.newItemId();
    const item = {
      itemId, vaultId, rev: 2, createdAt: 0, updatedAt: 0, deleted: false, conflict: false,
      formatVersion: 1, attachmentIds: [], blob: owner.encryptItem(vaultId, itemId, { type: "note" as const, name: "secret" }),
    };
    member.removeVault(vaultId);
    expect(member.hasVault(vaultId)).toBe(false);
    member.addGrant({ vaultId, userId: member.userId, role: "owner", wrappedVk, rev: 3, sealedVk: null });
    expect(member.hasVault(vaultId)).toBe(true);
    expect(member.decryptItem(item)).toEqual({ type: "note", name: "secret" });
  });

  it("buildRenameMeta changes only the name and bumps metaV monotonically (read-modify-write)", async () => {
    const owner = await enroll();
    const { request, vaultId } = owner.buildCreateSharedVault("Family"); // creation blob has no metaV

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
