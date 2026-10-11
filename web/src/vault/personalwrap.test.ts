import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { AccountKeys, PersonalWrap, SyncResponse, WireGrant, WireVault } from "../api/types";
import { adVk, adVkPersonal } from "../crypto/ad";
import { fromB64, fromUtf8, toB64 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { decidePersonalVault } from "./personalvault";
import { VaultStore } from "./store";

/**
 * Security review 2026-10, root cause A §4 / §8.5 (branch A5) — web twin of core PersonalVaultIdentityTest +
 * PersonalWrapVectorTest. "Personal" is the UVK-authenticated `personalWrap`, never a server `type` label or
 * `role`; the §8.5 migration picks the right vault; re-designation is allowed with a reauth (Q9).
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "personalwrap.json", "utf-8"));
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

const adOf = (text: string): Uint8Array => {
  const [, purpose, vaultId, userId] = text.split("|");
  return purpose === "vk-personal" ? adVkPersonal(vaultId!, userId!) : adVk(vaultId!, userId!);
};

describe("personalwrap.json", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a wrap opens only under its own purpose", () => {
    const w = v.wrap;
    expect(fromUtf8(adVkPersonal(w.vaultId, w.userId))).toBe(w.adPersonalUtf8);
    expect(fromUtf8(adVk(w.vaultId, w.userId))).toBe(w.adOwnerUtf8);
    const uvk = fromB64(w.uvkB64);
    const blob = (which: string) => fromB64(which === "personal" ? w.personalWrapB64 : w.ownerWrapB64);
    for (const r of v.open) expect(toB64(open(uvk, blob(r.wrap), adOf(r.adUtf8))), r.name).toBe(r.vkB64);
    for (const r of v.reject) expect(() => open(uvk, blob(r.wrap), adOf(r.adUtf8)), r.name).toThrow();
  });

  it("§8.5 migration decisions", () => {
    for (const r of v.migration) {
      const d = decidePersonalVault(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        r.candidates.map((c: any) => ({ ...c, itemCount: 0 })),
        r.lastUsed,
      );
      if (r.expected.auto) expect(d, r.name).toEqual({ kind: "auto", vaultId: r.expected.auto });
      else expect(d.kind === "ask" ? d.choices.map((c) => c.vaultId) : d, r.name).toEqual(r.expected.ask);
    }
  });
});

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  personalVaultId: string;
  personalWrappedVk: string;
  personalMeta: string;
  personalWrap: PersonalWrap;
}

async function enroll(email: string): Promise<Enrolled> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  return {
    account,
    keys: { kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed, identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint },
    userId: request.userId,
    password,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
    personalMeta: request.personalVault.metaBlob,
    personalWrap: request.personalWrap!,
  };
}

class FakeApi {
  puts: { wrap: PersonalWrap; currentAuthKey?: string }[] = [];
  constructor(private feed: SyncResponse) {}
  async sync(): Promise<SyncResponse> {
    const f = this.feed;
    this.feed = { ...f, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    return f;
  }
  async push() {
    return { rev: 1, results: [] };
  }
  async putPersonalWrap(wrap: PersonalWrap, currentAuthKey?: string) {
    this.puts.push({ wrap, currentAuthKey });
  }
  async accountState() {
    return { sealedState: null, seq: 0 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

const feed = (vaults: WireVault[], grants: WireGrant[]): SyncResponse => ({ rev: 9, full: true, vaults, grants, items: [], removedGrants: [] });
const personalRow = (e: Enrolled, type = "personal"): WireVault => ({ vaultId: e.personalVaultId, type, rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2, sealedVk: null });

describe("the personal vault is never a server label (VaultStore)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("an OWNER-created shared vault relabelled personal (real personal withheld) is not personal", async () => {
    const victim = await enroll("owner-relabel@example.com");
    const shared = victim.account.buildCreateSharedVault("Household");
    const device = await Account.unlock(victim.userId, victim.password, victim.keys); // pre-A5 keys: no wrap
    const store = new VaultStore(
      new FakeApi(feed([{ vaultId: shared.vaultId, type: "personal", rev: 4, metaBlob: shared.request.metaBlob, createdAt: 0 }], [{ vaultId: shared.vaultId, userId: victim.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 4, sealedVk: null }])).asClient(),
      device,
    );
    await store.sync();
    expect(device.hasVault(shared.vaultId)).toBe(true);
    expect(device.personalVaultId).not.toBe(shared.vaultId);
    expect(device.personalVaultId).toBe("");
    await expect(device.sealUsage(new Uint8Array([123, 125]))).rejects.toThrow();
  });

  it("with the personal wrap, the server can swap the labels and nothing moves", async () => {
    const victim = await enroll("swap@example.com");
    const owned = victim.account.buildCreateSharedVault("Personal");
    const device = await Account.unlock(victim.userId, victim.password, { ...victim.keys, personalWrap: victim.personalWrap });
    expect(device.personalStatus).toBe("confirmed");
    const store = new VaultStore(
      new FakeApi(feed([personalRow(victim, "shared"), { vaultId: owned.vaultId, type: "personal", rev: 3, metaBlob: owned.request.metaBlob, createdAt: 0 }], [personalGrant(victim), { vaultId: owned.vaultId, userId: victim.userId, role: "owner", wrappedVk: owned.request.wrappedVk, rev: 3, sealedVk: null }])).asClient(),
      device,
      undefined,
      memoryClientState(),
    );
    await store.sync();
    expect(device.personalVaultId).toBe(victim.personalVaultId);
    const types = Object.fromEntries(store.vaults().map((x) => [x.vaultId, x.type]));
    expect(types[victim.personalVaultId]).toBe("personal");
    expect(types[owned.vaultId]).toBe("shared");
  });

  it("an unreadable personal wrap fails closed: no personal vault, no automatic re-mint", async () => {
    const victim = await enroll("unreadable@example.com");
    const device = await Account.unlock(victim.userId, victim.password, { ...victim.keys, personalWrap: { vaultId: victim.personalVaultId, wrappedVk: victim.personalWrappedVk } });
    expect(device.personalStatus).toBe("unreadable");
    const api = new FakeApi(feed([personalRow(victim)], [personalGrant(victim)]));
    await new VaultStore(api.asClient(), device, undefined, memoryClientState()).sync();
    expect(device.personalVaultId).toBe("");
    expect(api.puts).toHaveLength(0);
  });

  it("§8.5: the migration picks the right vault and stores a wrap that opens to its key", async () => {
    const victim = await enroll("migrate@example.com");
    const other = victim.account.buildCreateSharedVault("Household");
    const device = await Account.unlock(victim.userId, victim.password, victim.keys);
    const api = new FakeApi(feed([personalRow(victim), { vaultId: other.vaultId, type: "shared", rev: 3, metaBlob: other.request.metaBlob, createdAt: 0 }], [personalGrant(victim), { vaultId: other.vaultId, userId: victim.userId, role: "owner", wrappedVk: other.request.wrappedVk, rev: 3, sealedVk: null }]));
    await new VaultStore(api.asClient(), device, undefined, memoryClientState()).sync();
    expect(device.personalVaultId).toBe(victim.personalVaultId);
    expect(device.personalStatus).toBe("confirmed");
    expect(api.puts).toHaveLength(1);
    expect(api.puts[0]!.currentAuthKey).toBeUndefined();
    expect(api.puts[0]!.wrap.vaultId).toBe(victim.personalVaultId);
  });

  it("ambiguity asks; the answer and a re-designation (Q9) accept only own-UVK-wrapped vaults, with a reauth to replace", async () => {
    const victim = await enroll("ask@example.com");
    const mate = await enroll("ask-mate@example.com");
    const owned = victim.account.buildCreateSharedVault("Personal");
    const sealed = mate.account.buildCreateSharedVault("Personal");
    const device = await Account.unlock(victim.userId, victim.password, victim.keys);
    const api = new FakeApi(
      feed(
        [personalRow(victim), { vaultId: owned.vaultId, type: "personal", rev: 3, metaBlob: owned.request.metaBlob, createdAt: 0 }, { vaultId: sealed.vaultId, type: "personal", rev: 4, metaBlob: sealed.request.metaBlob, createdAt: 0 }],
        [personalGrant(victim), { vaultId: owned.vaultId, userId: victim.userId, role: "owner", wrappedVk: owned.request.wrappedVk, rev: 3, sealedVk: null }, { vaultId: sealed.vaultId, userId: victim.userId, role: "writer", wrappedVk: "", rev: 4, sealedVk: mate.account.wrapVkForMember(device.identityPub, sealed.vaultId) }],
      ),
    );
    const store = new VaultStore(api.asClient(), device, undefined, memoryClientState());
    await store.sync();
    expect(device.personalVaultId).toBe("");
    expect(new Set(store.personalVaultChoices!.map((c) => c.vaultId))).toEqual(new Set([victim.personalVaultId, owned.vaultId]));
    expect(api.puts).toHaveLength(0);
    await expect(store.designatePersonalVault(sealed.vaultId)).rejects.toThrow();

    await store.designatePersonalVault(victim.personalVaultId);
    expect(device.personalVaultId).toBe(victim.personalVaultId);
    expect(store.personalVaultChoices).toBeNull();

    expect(new Set(store.redesignationChoices().map((x) => x.vaultId))).toEqual(new Set([victim.personalVaultId, owned.vaultId]));
    await store.designatePersonalVault(owned.vaultId, "fresh-auth-key");
    expect(device.personalVaultId).toBe(owned.vaultId);
    expect(api.puts.at(-1)!.currentAuthKey).toBe("fresh-auth-key");
  });

  it("another device migrated first: a 409 adopts ITS wrap", async () => {
    const victim = await enroll("race@example.com");
    const device = await Account.unlock(victim.userId, victim.password, victim.keys);
    const api = new FakeApi(feed([personalRow(victim)], [personalGrant(victim)]));
    api.putPersonalWrap = async () => {
      throw new ApiError(409, "personal_wrap_exists", "exists");
    };
    (api as unknown as { accountKeys: () => Promise<AccountKeys> }).accountKeys = async () => ({ ...victim.keys, personalWrap: victim.personalWrap });
    await new VaultStore(api.asClient(), device, undefined, memoryClientState()).sync();
    expect(device.personalStatus).toBe("confirmed");
    expect(device.personalVaultId).toBe(victim.personalVaultId);
  });

  it("enrolment sends the personal wrap and it opens under vk-personal", async () => {
    const e = await enroll("enrol@example.com");
    const device = await Account.unlock(e.userId, e.password, { ...e.keys, personalWrap: e.personalWrap });
    expect(device.personalVaultId).toBe(e.personalVaultId);
    expect(e.account.personalStatus).toBe("confirmed");
  });
});
