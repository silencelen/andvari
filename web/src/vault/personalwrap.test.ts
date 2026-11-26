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
import { FakeSharedLogs, vaultMadeBy } from "./fakesharedlogs.testkit";
import { type ItemWire, VaultStore } from "./store";

/** A shared vault's key as its creating account holds it: what its verified log hands another device (design §3.6). */
const vkOf = (account: Account, vaultId: string): Uint8Array => (account as unknown as { vaultKeys: Map<string, Uint8Array> }).vaultKeys.get(vaultId)!.slice();

/**
 * Security review 2026-10, root cause A §4 / §8.5 (branch A5) — web twin of core PersonalVaultIdentityTest +
 * PersonalWrapVectorTest. "Personal" is the UVK-authenticated `personalWrap`, never a server `type` label or
 * `role`. The store tests run with the fake log layer attached, as every session's store is: the personal vault is the
 * one whose served wrap opened at unlock (design §5.3), and nothing else ever becomes it.
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
  constructor(private feed: SyncResponse) {}
  async sync(): Promise<SyncResponse> {
    const f = this.feed;
    this.feed = { ...f, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    return f;
  }
  async pushMutations() {
    return { rev: 1, results: [] };
  }
  async vaultMembers() {
    return [];
  }
  async accountState() {
    return { sealedState: null, seq: 0 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }

  /** The item routes the store calls (its ItemWire): this fake serves them too. */
  asWire(): ItemWire {
    return this as unknown as ItemWire;
  }
}

const feed = (vaults: WireVault[], grants: WireGrant[]): SyncResponse => ({ rev: 9, full: true, vaults, grants, items: [], removedGrants: [] });
const personalRow = (e: Enrolled, type = "personal"): WireVault => ({ vaultId: e.personalVaultId, type, rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2 });

describe("the personal vault is never a server label (VaultStore)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("an OWNER-created shared vault relabelled personal (real personal withheld) is not personal", async () => {
    const victim = await enroll("owner-relabel@example.com");
    const shared = vaultMadeBy(victim.account, "Household");
    const device = await Account.unlock(victim.userId, victim.password, victim.keys); // the served wrap is withheld
    const api = new FakeApi(feed([{ vaultId: shared.vaultId, type: "personal", rev: 4, metaBlob: shared.request.metaBlob, createdAt: 0 }], [{ vaultId: shared.vaultId, userId: victim.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 4 }]));
    const store = new VaultStore(api.asClient(), device, undefined, undefined, api.asWire());
    new FakeSharedLogs(device).attachTo(store).share(shared.vaultId, vkOf(victim.account, shared.vaultId), "owner");
    await store.sync();
    expect(device.hasVault(shared.vaultId)).toBe(true);
    expect(device.personalVaultId).not.toBe(shared.vaultId);
    expect(device.personalVaultId).toBe("");
    await expect(device.sealUsage(new Uint8Array([123, 125]))).rejects.toThrow();
  });

  it("with the personal wrap, the server can swap the labels and nothing moves", async () => {
    const victim = await enroll("swap@example.com");
    const owned = vaultMadeBy(victim.account, "Personal");
    const device = await Account.unlock(victim.userId, victim.password, { ...victim.keys, personalWrap: victim.personalWrap });
    expect(device.personalStatus).toBe("confirmed");
    const api = new FakeApi(feed([personalRow(victim, "shared"), { vaultId: owned.vaultId, type: "personal", rev: 3, metaBlob: owned.request.metaBlob, createdAt: 0 }], [personalGrant(victim), { vaultId: owned.vaultId, userId: victim.userId, role: "owner", wrappedVk: owned.request.wrappedVk, rev: 3 }]));
    const store = new VaultStore(api.asClient(), device, undefined, memoryClientState(), api.asWire());
    new FakeSharedLogs(device).attachTo(store).share(owned.vaultId, vkOf(victim.account, owned.vaultId), "owner");
    await store.sync();
    // Design §5.3: the wrap that opened at unlock is in force; the labels decide nothing.
    expect(device.personalStatus).toBe("confirmed");
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
    const store = new VaultStore(api.asClient(), device, undefined, memoryClientState(), api.asWire());
    new FakeSharedLogs(device).attachTo(store);
    await store.sync();
    expect(device.personalVaultId).toBe("");
    // Nothing can mint or send a wrap: the transport has no personal-wrap route (web-pins).
  });

  it("enrolment sends the personal wrap and it opens under vk-personal", async () => {
    const e = await enroll("enrol@example.com");
    const device = await Account.unlock(e.userId, e.password, { ...e.keys, personalWrap: e.personalWrap });
    expect(device.personalVaultId).toBe(e.personalVaultId);
    expect(e.account.personalStatus).toBe("confirmed");
  });
});

// ---- H-1 (A5 review): a WITHHELD wrap must never hand "personal" back to the server's label ----

async function h1Feed() {
  const victim = await enroll(`h1-${Math.random().toString(16).slice(2)}@example.com`);
  const mate = await enroll(`h1m-${Math.random().toString(16).slice(2)}@example.com`);
  const decoy = vaultMadeBy(mate.account, "Personal");
  // The decoy is a vault the mate shared with the victim (its log lists the victim as a writer); the server labels it
  // personal and serves an owner-labelled row for it.
  const rows = feed(
    [personalRow(victim, "shared"), { vaultId: decoy.vaultId, type: "personal", rev: 5, metaBlob: decoy.request.metaBlob, createdAt: 0 }],
    [personalGrant(victim), { vaultId: decoy.vaultId, userId: victim.userId, role: "owner", wrappedVk: "", rev: 5 }],
  );
  return { victim, decoyId: decoy.vaultId, decoyVk: vkOf(mate.account, decoy.vaultId), rows };
}

/** A store on [api] for [device], with the fake log layer listing it as a writer of the decoy. */
function h1Store(h: Awaited<ReturnType<typeof h1Feed>>, api: FakeApi, device: Account): VaultStore {
  const store = new VaultStore(api.asClient(), device, undefined, memoryClientState(), api.asWire());
  new FakeSharedLogs(device).attachTo(store).share(h.decoyId, h.decoyVk, "writer");
  return store;
}

describe("H-1 — a withheld personal wrap never lets the label decide", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a withheld wrap: no label pick, no minted wrap, no question, and the decoy stays a shared vault", async () => {
    const h = await h1Feed();
    const device = await Account.unlock(h.victim.userId, h.victim.password, h.victim.keys); // wrap withheld
    const api = new FakeApi(h.rows);
    const store = h1Store(h, api, device);
    await store.sync();
    expect(device.personalVaultId).not.toBe(h.decoyId);
    expect(device.personalVaultId).toBe("");
    // Nothing can mint or send a wrap: the transport has no personal-wrap route (web-pins).
    // Design §5.3: no question, no proposal (the store has no designation method at all: web-pins).
    expect(device.hasVault(h.decoyId)).toBe(true);
  });

  it("existing device: an absent wrap after one was seen puts no cached wrap in force (design §5.3)", async () => {
    const h = await h1Feed();
    const local = memoryClientState();
    local.set("personal.wrap", JSON.stringify(h.victim.personalWrap)); // what a pre-log browser cached
    const again = await Account.unlock(h.victim.userId, h.victim.password, h.victim.keys); // now withheld
    const api = new FakeApi(h.rows);
    const store = new VaultStore(api.asClient(), again, undefined, local, api.asWire());
    new FakeSharedLogs(again).attachTo(store).share(h.decoyId, h.decoyVk, "writer");
    await store.sync();
    expect(again.personalVaultId).toBe("");
    // Nothing can mint or send a wrap: the transport has no personal-wrap route (web-pins).
  });
});
