import { beforeAll, describe, expect, it } from "vitest";
import { adUsage } from "../crypto/ad";
import { fromB64, toB64, utf8, fromUtf8 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { usageKey } from "../crypto/usagekey";
import type { AccountKeys, PersonalWrap, WireGrant } from "../api/types";
import { Account } from "./account";

/**
 * Audit H64, web twin of core's UsagePersonalVaultProvenanceTest — the usage-ledger key must not
 * follow a server label.
 *
 * `Vault.type` is server PLAINTEXT (spec 02 §4) bound into no AD. Since
 * `usageKey = HKDF(VK(personalVault), "andvari/v1|usage")` and `adUsage(userId)` is public, a hostile server that
 * withheld the real personal wrap and relabelled a SHARED vault the victim is merely a member of would have moved the
 * ledger under a key every other member of that vault already holds — a colluding housemate could then read the
 * victim's per-item behavioural log (spec 02 §8.2), which is the one thing the single-blob design exists to keep
 * private.
 *
 * The personal vault comes only from the UVK-authenticated personal wrap (design §5.3), which a server cannot mint;
 * a shared vault's key comes only from its verified log (design §3.6, here the log key ring). These cases pin it
 * against the real crypto so a revert fails here, not in the field.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  personalVaultId: string;
  personalWrappedVk: string;
  personalWrap: PersonalWrap;
}

/** What a hostile server can serve as the personal wrap of a vault it relabelled: it holds no UVK, so never one that opens. */
const relabelledWrap = (vaultId: string): PersonalWrap => ({ vaultId, wrappedVk: toB64(randomBytes(72)) });

async function enroll(email: string): Promise<Enrolled> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({
    inviteToken: "t",
    email,
    displayName: email,
    password,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return {
    account,
    keys: {
      kdfSalt: request.kdfSalt,
      kdfParams: request.kdfParams,
      wrappedUvk: request.wrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: request.escrow!.fingerprint,
    },
    userId: request.userId,
    password,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
    personalWrap: request.personalWrap!,
  };
}

/** The personal-vault owner grant a sync delivers: wrappedVk under the account's own UVK. */
const personalGrant = (e: Enrolled): WireGrant => ({
  vaultId: e.personalVaultId,
  userId: e.userId,
  role: "owner",
  wrappedVk: e.personalWrappedVk,
  rev: 1,
});

/** A shared vault the victim is a writer of, its key adopted through its verified log (design §3.6). */
function joinShared(device: Account, vaultId: string, vk: Uint8Array): void {
  device.logKeyRing().set(vaultId, vk.slice());
}

describe("H64 — the personal vault is never a server-relabelled shared vault", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("refuses a relabelled shared vault, and a co-member cannot open the ledger", async () => {
    const victim = await enroll("victim@example.com");
    const sharedId = victim.account.newItemId();
    const sharedVk = randomBytes(32); // every member of the household vault holds this

    // A fresh unlock with the personal wrap withheld: there is no personal vault yet.
    const device = await Account.unlock(victim.userId, victim.password, victim.keys);
    expect(device.personalVaultId).toBe("");

    // The hostile feed: the shared vault is joined, then served as the personal one while the real wrap is withheld.
    joinShared(device, sharedId, sharedVk);
    expect(device.hasVault(sharedId)).toBe(true); // a refusal to ADOPT it as personal, not to join it
    device.applyPersonalWrap(relabelledWrap(sharedId));
    expect(device.personalVaultId).toBe("");
    // A grant row cannot make it personal either: the account applies only its own personal row.
    expect(() => device.addGrant({ vaultId: sharedId, userId: victim.userId, role: "owner", wrappedVk: "", rev: 3 })).toThrow();
    expect(device.personalVaultId).toBe("");
    // Fail-closed per the owner's decision: no personal vault means no ledger, which callers
    // already render as "—". Silently keying the ledger from the housemates' VK is the bug.
    await expect(device.sealUsage(utf8("{}"))).rejects.toThrow();

    // The real personal wrap finally arrives: now it is adopted, and its row applies.
    device.applyPersonalWrap(victim.personalWrap);
    expect(device.personalVaultId).toBe(victim.personalVaultId);
    device.addGrant(personalGrant(victim));
    expect(device.vkMismatch(victim.personalVaultId)).toBe(false);

    // The point of the row: a co-member holding the shared VK cannot open the victim's ledger.
    // The AD is public, so if the key had moved this open would succeed.
    const ledger = await device.sealUsage(utf8('{"item-1":{"lastUsedAt":1,"useCount":2}}'));
    expect(() => open(sharedVk, fromB64(ledger), adUsage(victim.userId))).toThrow();
    const coMemberKey = await usageKey(sharedVk);
    expect(() => open(coMemberKey, fromB64(ledger), adUsage(victim.userId))).toThrow();
    // …and the owner still reads it, under the personal VK.
    expect(fromUtf8(await device.openUsage(ledger))).toBe('{"item-1":{"lastUsedAt":1,"useCount":2}}');
  });

  it("survives the hostile ordering and leaves the honest one untouched", async () => {
    const victim = await enroll("order@example.com");
    const sharedId = victim.account.newItemId();
    const sharedVk = randomBytes(32);

    // Honest ordering: the personal vault is adopted and a later relabel cannot displace it.
    const honest = await Account.unlock(victim.userId, victim.password, victim.keys);
    honest.applyPersonalWrap(victim.personalWrap);
    honest.addGrant(personalGrant(victim));
    joinShared(honest, sharedId, sharedVk);
    honest.applyPersonalWrap(relabelledWrap(sharedId));
    expect(honest.personalVaultId).toBe(victim.personalVaultId);

    // Hostile ordering: the relabelled vault is offered first and repeatedly. Refused every time,
    // and the real vault is still adoptable afterwards — the refusal must not burn the one-shot slot.
    const attacked = await Account.unlock(victim.userId, victim.password, victim.keys);
    joinShared(attacked, sharedId, sharedVk);
    for (let i = 0; i < 3; i++) attacked.applyPersonalWrap(relabelledWrap(sharedId));
    expect(attacked.personalVaultId).toBe("");
    attacked.applyPersonalWrap(victim.personalWrap);
    expect(attacked.personalVaultId).toBe(victim.personalVaultId);
    attacked.addGrant(personalGrant(victim));
    expect(attacked.personalVaultId).toBe(victim.personalVaultId);
  });
});
