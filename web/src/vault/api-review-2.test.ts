import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, ItemDoc, PersonalWrap, PushResponse, RecoveryVerifyResponse, SyncResponse, VaultMemberAdd, VaultMemberSummary, WireGrant, WireItem, WireVault } from "../api/types";
import { adItem, adUvk, adVaultMeta, adVkPersonal } from "../crypto/ad";
import { fromB64, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { authKey, KdfPolicyError, type KdfParams, masterKey, wrapKey } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account, ReauthFailedError } from "./account";
import { SessionWrap } from "./sessionwrap";
import { memoryClientState } from "./accountstatesync";
import { decodeAccountState, emptyAccountState, isBlankAccountState, withPersonal } from "./accountstate";
import { FakeSharedLogs, vaultMadeBy } from "./fakesharedlogs.testkit";
import { type ItemWire, NoPersonalVaultError, ReauthStaleSessionError, VaultStore } from "./store";

/**
 * Security review 2026-10, branch A9 (web twin of core `ApiReview2Test`): the second API-review round over
 * A6b/A1b/A5c. M-1 (one fenced reauth derivation), M-2 (a second apply never switches; the store-level designation
 * tests went with the signed vault logs, under which the store decides no personal vault locally, design §5.3), M-3 (no silent rule-(b) re-issue; the
 * record only annotates; a device-local tombstone), L-1 (a home only from an applied row), L-2 (the member-granted bit
 * only from an actual adoption), and the LOW items (ownership release retried, rename through INV-WRITE-KEY, recover()
 * wipes the probe's secrets).
 */

// The recover() wipe is invisible from outside: capture the LIVE secret-key arrays each keypair derivation hands out.
const rec = vi.hoisted(() => ({ privates: [] as { live: Uint8Array; at: Uint8Array }[] }));
vi.mock("../crypto/provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../crypto/provider")>();
  const keep = (k: { privateKey: Uint8Array }) => rec.privates.push({ live: k.privateKey, at: k.privateKey.slice() });
  return {
    ...real,
    boxKeypairFromSeed: (seed: Uint8Array) => {
      const k = real.boxKeypairFromSeed(seed);
      keep(k);
      return k;
    },
    signKeypairFromSeed: (seed: Uint8Array) => {
      const k = real.signKeypairFromSeed(seed);
      keep(k);
      return k;
    },
  };
});

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const FLOOR: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const WEAK: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  identityPub: string;
  personalVaultId: string;
  personalWrappedVk: string;
  personalMeta: string;
  personalWrap: PersonalWrap;
  recoverySecret: Uint8Array;
  encryptedIdentitySeed: string;
  recoveryWrappedUvk: string;
}

async function enroll(tag: string, kdfParams: KdfParams = KDF): Promise<Enrolled> {
  const email = `${tag}-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account, recoverySecret } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  return {
    account,
    keys: {
      kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap,
    },
    userId: request.userId,
    password,
    identityPub: request.identityPub,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
    personalMeta: request.personalVault.metaBlob,
    personalWrap: request.personalWrap!,
    recoverySecret,
    encryptedIdentitySeed: request.encryptedIdentitySeed,
    recoveryWrappedUvk: request.memberRecovery.recoveryWrappedUvk,
  };
}

/** A fresh device of `e`; the wrap the server serves it is `wrap` (default: the one enrolment minted). */
const unlock = (e: Enrolled, wrap: PersonalWrap | null = e.personalWrap) => Account.unlock(e.userId, e.password, { ...e.keys, personalWrap: wrap });

async function uvkOfE(e: Enrolled): Promise<Uint8Array> {
  return open(await wrapKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
}

async function expectedAuthKey(e: Enrolled): Promise<string> {
  return toB64(await authKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)));
}

class FakeServer {
  feed: SyncResponse;
  adds: { vaultId: string; body: VaultMemberAdd }[] = [];
  reissues: { vaultId: string; userId: string; signedGrant: string }[] = [];
  removals: { vaultId: string; userId: string }[] = [];
  members: Record<string, VaultMemberSummary[]> = {};
  accountStateBlob: string | null = null;
  accountSeq = 0;
  keys: AccountKeys | null = null;
  selfUserId: string | null = null;
  withholdState = false;
  failStatePut = false;
  constructor(feed: SyncResponse) {
    this.feed = feed;
  }
  async sync(since: number): Promise<SyncResponse> {
    if (since === 0) return this.feed;
    if (since < this.feed.rev) return { ...this.feed, full: false };
    return { rev: this.feed.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async pushMutations(): Promise<PushResponse> {
    return { rev: this.feed.rev, results: [] };
  }
  async accountKeys(): Promise<AccountKeys> {
    if (!this.keys) throw new ApiError(404, "not_found", "no");
    return this.keys;
  }
  async accountState() {
    return this.withholdState ? { sealedState: null, seq: 0 } : { sealedState: this.accountStateBlob, seq: this.accountSeq };
  }
  async putAccountState(sealedState: string, baseSeq: number) {
    if (this.failStatePut) throw new ApiError(500, "internal", "no");
    if (baseSeq !== this.accountSeq) throw new ApiError(409, "stale_state", "stale");
    this.accountStateBlob = sealedState;
    this.accountSeq += 1;
    return { sealedState, seq: this.accountSeq };
  }
  async vaultMembers(vaultId: string) {
    return this.members[vaultId] ?? [];
  }
  async createVault(req: { vaultId: string; metaBlob: string; wrappedVk: string }) {
    const rev = this.feed.rev + 1;
    this.feed = {
      ...this.feed, rev,
      vaults: [...this.feed.vaults, { vaultId: req.vaultId, type: "shared", rev, metaBlob: req.metaBlob, createdAt: 0 }],
      grants: [...this.feed.grants, { vaultId: req.vaultId, userId: this.selfUserId!, role: "owner", wrappedVk: req.wrappedVk, rev }],
    };
    return { rev };
  }
  async addVaultMember(vaultId: string, body: VaultMemberAdd) {
    this.adds.push({ vaultId, body });
    return { rev: this.feed.rev + 1 };
  }
  async removeVaultMember(vaultId: string, userId: string) {
    this.removals.push({ vaultId, userId });
    return { rev: this.feed.rev + 1 };
  }
  async reissueGrant(vaultId: string, userId: string, body: { signedGrant: string }) {
    this.reissues.push({ vaultId, userId, signedGrant: body.signedGrant });
    return { rev: this.feed.rev + 1 };
  }
  async putSelfWrap() {
    return { rev: this.feed.rev + 1 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }

  /** The item routes the store calls (its ItemWire): this fake serves them too. */
  asWire(): ItemWire {
    return this as unknown as ItemWire;
  }
}

const personalRow = (e: Enrolled): WireVault => ({ vaultId: e.personalVaultId, type: "personal", rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2 });
const summary = (e: Enrolled, name: string, role: string): VaultMemberSummary =>
  ({ userId: e.userId, email: `${name}@example.com`, displayName: name, role, identityPub: e.identityPub, addedAt: 0 });

interface World {
  owner: Enrolled;
  sharedId: string;
  sharedVk: Uint8Array;
  metaBlob: string;
  ownerWrap: string;
  feed: SyncResponse;
}

async function world(params: KdfParams = KDF): Promise<World> {
  const owner = await enroll("a9", params);
  const shared = vaultMadeBy(owner.account, "Household");
  const feed: SyncResponse = {
    rev: 5, full: true,
    vaults: [personalRow(owner), { vaultId: shared.vaultId, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 }],
    grants: [personalGrant(owner), { vaultId: shared.vaultId, userId: owner.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 3 }],
    items: [], removedGrants: [],
  };
  // The shared vault's key, which its verified log hands another device of the owner (read from the creating account).
  const sharedVk = (owner.account as unknown as { vaultKeys: Map<string, Uint8Array> }).vaultKeys.get(shared.vaultId)!.slice();
  return { owner, sharedId: shared.vaultId, sharedVk, metaBlob: shared.request.metaBlob, ownerWrap: shared.request.wrappedVk, feed };
}

function serverOf(w: World, keys: AccountKeys | null = w.owner.keys): FakeServer {
  const s = new FakeServer(w.feed);
  s.keys = keys;
  s.selfUserId = w.owner.userId;
  s.members[w.sharedId] = [summary(w.owner, "Owner", "owner")];
  s.members[w.owner.personalVaultId] = [summary(w.owner, "Owner", "owner")];
  return s;
}

async function designationOn(server: FakeServer, e: Enrolled): Promise<string | null> {
  if (!server.accountStateBlob) return null;
  return (await unlock(e)).openAccountState(server.accountStateBlob).personal?.vaultId ?? null;
}

/** A store with the fake log layer attached, as every session's is; [owned] are shared vaults whose log lists the account as owner. */
const store = (server: FakeServer, account: Account, local = memoryClientState(), owned: [string, Uint8Array][] = []) => {
  const s = new VaultStore(server.asClient(), account, undefined, local, server.asWire());
  const logs = new FakeSharedLogs(account).attachTo(s);
  for (const [vaultId, vk] of owned) logs.share(vaultId, vk, "owner");
  return s;
};

describe("A9 — second API-review round (VaultStore / Account)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  // ---- M-1 ----

  it("M-1: reauthAuthKey is the one fenced derivation; the pre-session deriveAuthKey is fenced on the params", async () => {
    const owner = await enroll("a9-fence", FLOOR);
    const device = await unlock(owner);
    // Spec 01 §7: the proof runs against the wrap the session keeps; a kept cost outside the bounds derives nothing.
    const uvk = await uvkOfE(owner);
    const weak = await new SessionWrap({ ...owner.keys, kdfParams: WEAK }).prove(owner.password, owner.userId, uvk);
    expect(weak.kind).toBe("weakened");
    if (weak.kind === "weakened") expect(weak.error).toBeInstanceOf(KdfPolicyError);
    // A session that keeps no wrap proves nothing ("Lock and unlock andvari, then try again.").
    expect((await new SessionWrap(null).prove(owner.password, owner.userId, uvk)).kind).toBe("no_wrap");
    expect(await device.reauthAuthKey(owner.password)).toBe(await expectedAuthKey(owner));
    await expect(Account.deriveAuthKey(owner.password, owner.keys.kdfSalt, WEAK)).rejects.toBeInstanceOf(KdfPolicyError);
  }, 60_000);

  it("M-1 tripwire: product code derives password credentials only through the fence", () => {
    const src = fileURLToPath(new URL("../", import.meta.url));
    const files: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) && !p.includes(`${"/"}vendor${"/"}`)) files.push(p);
      }
    };
    walk(src);
    expect(files.length).toBeGreaterThan(50);
    const rel = (f: string) => f.slice(src.length);
    // The raw KDF: only inside Account (every caller fenced) and the backup KDF (its own window, spec 07 §2.3).
    const rawKdf = files.filter((f) => readFileSync(f, "utf8").split("\n").some((l) => /\bmasterKey\(/.test(l.split("//")[0]!)))
      // The post-cut-over sign-in, sign-up and kit flows (vault/onboardflow.ts, vault/registration.ts, vault/kitflow.ts)
      // fence their params at the call. So does the one re-authentication path of Settings (vault/settingsflow.ts):
      // `reauth` fences the served params, then proves the password against the session's own UVK before it derives
      // `currentAuthKey`; `changePassword` fences the policy's params before it derives the new keys.
      // The in-session proof itself (vault/sessionwrap.ts) derives under the session's own kept wrap, fenced first.
      .map(rel).filter((p) => !["vault/account.ts", "export/export.ts", "crypto/keys.ts", "vault/onboardflow.ts", "vault/registration.ts", "vault/kitflow.ts", "vault/settingsflow.ts", "vault/sessionwrap.ts"].includes(p));
    expect(rawKdf).toEqual([]);
    // The pre-session login derivation: only at the sign-in site, over the prelogin values.
    const logins = files.flatMap((f) =>
      readFileSync(f, "utf8").split("\n").flatMap((line, i) => (/Account\.deriveAuthKey\(/.test(line.split("//")[0]!) ? [{ path: rel(f), line: i + 1, code: line.trim() }] : [])),
    );
    // The one legitimate site: the sign-in over the prelogin values (the in-session proof derives through the raw KDF
    // inside Account, proving the password against the session UVK; A9 review LOW-1).
    const offenders = logins.filter((l) => !(l.path === "ui/Welcome.tsx" && l.code.includes("pre.kdfSalt") && l.code.includes("pre.kdfParams")));
    expect(offenders).toEqual([]);
    // The post-cut-over sign-in derives inside vault/onboardflow.ts (fenced above): the old helper has no caller left.
    expect(logins).toHaveLength(0);
  });

  // ---- M-2 ----

  it("review LOW-1: the reauth proves the password against the session UVK (web has no quick unlock; the proof still refuses a substituted wrap)", async () => {
    const owner = await enroll("a9-qu", FLOOR);
    const uvk = await uvkOfE(owner);
    const device = await unlock(owner);
    // A wrap that is NOT of our UVK proves nothing, whatever the password: no key derived under it is ever sent.
    const junkWrap = toB64(seal(randomBytes(32), uvk, adUvk(owner.userId)));
    expect((await new SessionWrap({ ...owner.keys, wrappedUvk: junkWrap }).prove(owner.password, owner.userId, uvk)).kind).toBe("wrong_password");
    // A wrong password is proved wrong locally (never sent to the server to find out).
    await expect(device.reauthAuthKey("not the password")).rejects.toBeInstanceOf(ReauthFailedError);
    // The session's own wrap passes.
    expect(await device.reauthAuthKey(owner.password)).toBe(await expectedAuthKey(owner));
  }, 60_000);

  it("review LOW-2: a default save with no personal vault in force is refused with 'Choose a vault for this item.'", async () => {
    const w = await world();
    const server = serverOf(w);
    const b = await unlock(w.owner, null); // the served wrap is withheld: no personal vault in force (design §5.3)
    const s = store(server, b, memoryClientState(), [[w.sharedId, w.sharedVk]]);
    await s.sync();
    expect(b.personalVaultId).toBe("");
    const doc: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "pw" } };
    await expect(s.save(null, doc)).rejects.toBeInstanceOf(NoPersonalVaultError);
    await expect(s.save(null, doc)).rejects.toThrow("Choose a vault for this item.");
    await expect(s.importDocs([])).rejects.toBeInstanceOf(NoPersonalVaultError);
    expect(s.list()).toEqual([]);
    await s.save(null, doc, [], undefined, w.sharedId);
    expect(s.list().map((i) => i.vaultId)).toEqual([w.sharedId]);
  });

  it("M-2: a second apply never switches or drops the personal vault in force (the rule lives in Account)", async () => {
    const w = await world();
    // A wrap of the shared vault that opens under this account's UVK: what a server holding an old one could serve.
    const sharedWrap: PersonalWrap = { vaultId: w.sharedId, wrappedVk: toB64(seal(await uvkOfE(w.owner), w.sharedVk, adVkPersonal(w.sharedId, w.owner.userId))) };
    const device = await unlock(w.owner);
    expect(device.personalStatus).toBe("confirmed");
    for (const later of [sharedWrap, { vaultId: w.sharedId, wrappedVk: w.ownerWrap }, null]) {
      device.applyPersonalWrap(later);
      expect(device.personalStatus).toBe("confirmed");
      expect(device.personalVaultId).toBe(w.owner.personalVaultId);
    }

    // With none in force, a withheld wrap stays "no personal vault" until a served wrap opens.
    const withheld = await unlock(w.owner, null);
    expect(withheld.personalStatus).toBe("absent");
    withheld.applyPersonalWrap({ vaultId: w.sharedId, wrappedVk: w.ownerWrap });
    expect(withheld.personalStatus).toBe("unreadable");
    expect(withheld.personalVaultId).toBe("");
  });

  it("M-2: withPersonal always outranks the designation it replaces; an absent key reads as null", () => {
    const u = "33333333-3333-4333-8333-333333333333";
    const doc = withPersonal(emptyAccountState(u), "11111111-1111-4111-8111-111111111111", 100);
    expect(doc.personal).toEqual({ vaultId: "11111111-1111-4111-8111-111111111111", at: 100 });
    const next = withPersonal(doc, "22222222-2222-4222-8222-222222222222", 5);
    expect(next.personal!.vaultId).toBe("22222222-2222-4222-8222-222222222222");
    expect(next.personal!.at).toBeGreaterThan(100);
    expect(isBlankAccountState(next)).toBe(false);
    expect(decodeAccountState(u, JSON.stringify({ v: 1, userId: u, seq: 0 })).personal).toBeNull();
  });

  // ---- L-1 ----

  it("L-1: a tombstone or an unheld row served first never homes the item", async () => {
    for (const tombstoneFirst of [true, false]) {
      const victim = await enroll("a9-victim");
      const p = victim.personalVaultId;
      const x = victim.account.newItemId();
      const doc: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "P-SECRET-0001" } };
      const up = victim.account.encryptItem(p, x, doc);
      const genuine: WireItem = { itemId: x, vaultId: p, rev: 4, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: [], blob: up.blob };
      const sId = victim.account.newItemId();
      const vkS = randomBytes(32);
      const sRow: WireVault = { vaultId: sId, type: "shared", rev: 7, metaBlob: toB64(seal(vkS, utf8('{"name":"Server"}'), adVaultMeta(sId))), createdAt: 0 };
      const first: WireItem = tombstoneFirst
        ? { itemId: x, vaultId: sId, rev: 3, createdAt: 1, updatedAt: 1, deleted: true, conflict: false, formatVersion: 1, attachmentIds: [], blob: null }
        : { itemId: x, vaultId: sId, rev: 3, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [], blob: toB64(seal(vkS, utf8('{"type":"login","name":"bait"}'), adItem(sId, x, 1))) };
      const server = new FakeServer({ rev: 9, full: true, vaults: [personalRow(victim), sRow], grants: [personalGrant(victim)], items: [first, genuine], removedGrants: [] });
      server.keys = victim.keys;
      const s = store(server, await unlock(victim));
      await s.sync();
      const label = tombstoneFirst ? "tombstone first" : "unheld row first";
      expect(s.get(x)?.vaultId, label).toBe(p);
      expect(s.get(x)?.doc, label).toEqual(doc);
      expect(s.quarantinedItems(), label).toEqual([]);
      expect(s.notices().filter((n) => n.kind === "wrong-vault"), label).toHaveLength(0);
    }
  });

  // ---- LOW ----

  it("LOW: recover() wipes the probe account's identity and signing secrets", async () => {
    const r = await enroll("a9-recover");
    const verify: RecoveryVerifyResponse = {
      userId: r.userId, recoveryTicket: "opaque-ticket", recoveryWrappedUvk: r.recoveryWrappedUvk,
      encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub,
    };
    rec.privates.length = 0;
    const commit = await Account.recover({ recoverySecret: r.recoverySecret, verify, newPassword: "a brand new master password", newKdfParams: KDF });
    expect(commit.newWrappedUvk.length).toBeGreaterThan(0);
    expect(rec.privates, "one identity keypair and one signing keypair for the probe").toHaveLength(2);
    for (const { live, at } of rec.privates) {
      expect(at.some((b) => b !== 0)).toBe(true);
      expect(live.every((b) => b === 0), "the probe account's secret key was not wiped").toBe(true);
    }
  });
  // The old account-state sync and its designation write-back are gone (the store test pins that no
  // source imports it); the account state is the session's AccountStateStore (design §5.4).
});
