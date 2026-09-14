import { beforeAll, describe, expect, it } from "vitest";
import { adUsage } from "../crypto/ad";
import { fromB64, toB64, utf8, fromUtf8 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { openSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { usageKey } from "../crypto/usagekey";
import type { AccountKeys, WireGrant } from "../api/types";
import { Account } from "./account";

/**
 * Audit H64, web twin of core's UsagePersonalVaultProvenanceTest — the usage-ledger key must not
 * follow a server label.
 *
 * `Vault.type` is server PLAINTEXT (spec 02 §4) bound into no AD, and after enrollment nothing the
 * client holds says which vault is its own: `personalVaultId` is rebuilt on every unlock from the
 * first row the server labels `personal` whose key we happen to hold (store.ts, both the pull and
 * the cold-start hydrate). Since `usageKey = HKDF(VK(personalVault), "andvari/v1|usage")` and
 * `adUsage(userId)` is public, a hostile server that withheld the real personal row and relabelled
 * a SHARED vault the victim is merely a member of would have moved the ledger under a key every
 * other member of that vault already holds — a colluding housemate could then read the victim's
 * per-item behavioural log (spec 02 §8.2), which is the one thing the single-blob design exists to
 * keep private.
 *
 * The owner's decision is the cheap refusal: never adopt a vault whose VK arrived by member grant
 * (`sealedVk`). These cases pin it against the real crypto so a revert fails here, not in the field.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  personalVaultId: string;
  personalWrappedVk: string;
}

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
  };
}

/** The personal-vault owner grant a sync delivers: wrappedVk under the account's own UVK. */
const personalGrant = (e: Enrolled): WireGrant => ({
  vaultId: e.personalVaultId,
  userId: e.userId,
  role: "owner",
  wrappedVk: e.personalWrappedVk,
  rev: 1,
  sealedVk: null,
});

describe("H64 — the personal vault is never a server-relabelled member grant", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("refuses a relabelled member-granted vault, and a co-member cannot open the ledger", async () => {
    const victim = await enroll("victim@example.com");
    const housemate = await enroll("housemate@example.com");

    // A genuine shared vault the victim is a writer of — the household vault, nothing exotic.
    const shared = housemate.account.buildCreateSharedVault("Household");
    const memberGrant: WireGrant = {
      vaultId: shared.vaultId,
      userId: victim.userId,
      role: "writer",
      wrappedVk: "",
      rev: 3,
      sealedVk: housemate.account.wrapVkForMember(victim.account.identityPub, shared.vaultId),
    };

    // A fresh unlock: personalVaultId is EMPTY and must be rediscovered from the feed. That
    // rediscovery is the whole attack surface.
    const device = await Account.unlock(victim.userId, victim.password, victim.keys);
    expect(device.personalVaultId).toBe("");

    // The hostile feed: the member grant lands, then the shared vault row arrives relabelled
    // type="personal" while the real personal row is withheld.
    device.addGrant(memberGrant);
    expect(device.hasVault(shared.vaultId)).toBe(true); // a refusal to ADOPT, not to join
    expect(device.keyArrivedByMemberGrant(shared.vaultId)).toBe(true);
    device.setPersonalVault(shared.vaultId);

    expect(device.personalVaultId).toBe("");
    // Fail-closed per the owner's decision: no personal vault means no ledger, which callers
    // already render as "—". Silently keying the ledger from the housemates' VK is the bug.
    await expect(device.sealUsage(utf8("{}"))).rejects.toThrow();

    // The real personal row finally arrives: now it is adopted.
    device.addGrant(personalGrant(victim));
    expect(device.keyArrivedByMemberGrant(victim.personalVaultId)).toBe(false);
    device.setPersonalVault(victim.personalVaultId);
    expect(device.personalVaultId).toBe(victim.personalVaultId);

    // The point of the row: a co-member holding the shared VK cannot open the victim's ledger.
    // `spy` stands in for any other member of that vault; the AD is public, so if the key had
    // moved this open would succeed.
    const ledger = await device.sealUsage(utf8('{"item-1":{"lastUsedAt":1,"useCount":2}}'));
    const spy = boxKeypairFromSeed(randomBytes(32));
    const sharedVk = openSharedGrant(
      spy.publicKey,
      spy.privateKey,
      shared.vaultId,
      fromB64(housemate.account.wrapVkForMember(spy.publicKey, shared.vaultId)),
    );
    expect(() => open(sharedVk, fromB64(ledger), adUsage(victim.userId))).toThrow();
    const coMemberKey = await usageKey(sharedVk);
    expect(() => open(coMemberKey, fromB64(ledger), adUsage(victim.userId))).toThrow();
    // …and the owner still reads it, under the personal VK.
    expect(fromUtf8(await device.openUsage(ledger))).toBe('{"item-1":{"lastUsedAt":1,"useCount":2}}');
    expect(toB64(sharedVk).length).toBeGreaterThan(0); // the spy really did hold the VK
  });

  it("survives the hostile ordering and leaves the honest one untouched", async () => {
    const victim = await enroll("order@example.com");
    const housemate = await enroll("order-mate@example.com");
    const shared = housemate.account.buildCreateSharedVault("Household");
    const memberGrant: WireGrant = {
      vaultId: shared.vaultId,
      userId: victim.userId,
      role: "reader",
      wrappedVk: "",
      rev: 2,
      sealedVk: housemate.account.wrapVkForMember(victim.account.identityPub, shared.vaultId),
    };

    // Honest ordering: the personal vault is adopted and a later relabel cannot displace it.
    const honest = await Account.unlock(victim.userId, victim.password, victim.keys);
    honest.addGrant(personalGrant(victim));
    honest.addGrant(memberGrant);
    honest.setPersonalVault(victim.personalVaultId);
    honest.setPersonalVault(shared.vaultId);
    expect(honest.personalVaultId).toBe(victim.personalVaultId);

    // Hostile ordering: the relabelled vault is offered first and repeatedly. Refused every time,
    // and the real vault is still adoptable afterwards — the refusal must not burn the one-shot slot.
    const attacked = await Account.unlock(victim.userId, victim.password, victim.keys);
    attacked.addGrant(memberGrant);
    attacked.setPersonalVault(shared.vaultId);
    attacked.setPersonalVault(shared.vaultId);
    attacked.setPersonalVault(shared.vaultId);
    expect(attacked.personalVaultId).toBe("");
    attacked.addGrant(personalGrant(victim));
    attacked.setPersonalVault(victim.personalVaultId);
    expect(attacked.personalVaultId).toBe(victim.personalVaultId);

    // Revocation forgets the provenance with the key it describes.
    attacked.removeVault(shared.vaultId);
    expect(attacked.keyArrivedByMemberGrant(shared.vaultId)).toBe(false);
  });
});
