import { beforeAll, describe, expect, it } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { ItemDoc, Mutation, MutationResult, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { adVaultMeta } from "../crypto/ad";
import { fromB64, toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { openSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { VaultStore } from "./store";

/**
 * spec 02 §4 warn-and-keep-newer (VaultStore.keepNewerMeta) + the pinned metaV parse rule:
 * `metaV` counts ONLY when it is an integral, non-negative JSON number, else 0 — the SAME
 * rule in metaVOf and Account.buildRenameMeta, on every client. Same drive pattern as
 * store.lifecycle.test.ts; mirrors core SyncEngineMetaVTest.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const DOC: ItemDoc = { type: "login", name: "Shared login", login: { username: "fam", password: "hunter2" } };

const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

class FakeApi {
  queue: SyncResponse[] = [];
  rev = 1;
  /** Reply 410 to the next sync (cursor gone) — the store refetches from 0. */
  goneNextSync = false;

  async sync(since: number): Promise<SyncResponse> {
    void since;
    if (this.goneNextSync) {
      this.goneNextSync = false;
      throw new ApiError(410, "gone", "cursor expired");
    }
    const resp = this.queue.shift() ?? emptySync(this.rev);
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }

  async push(mutations: Mutation[]): Promise<PushResponse> {
    const results: MutationResult[] = mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: 1 }));
    return { rev: ++this.rev, results };
  }

  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function enroll(email: string): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "test-invite",
    email,
    displayName: email,
    password: `pw ${email}`,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

interface Seed {
  owner: Account;
  member: Account;
  store: VaultStore;
  api: FakeApi;
  vaultId: string;
  vault: WireVault;
  grant: WireGrant;
  item: WireItem;
}

/** The store's cached wire row (the state keepNewerMeta protects). */
function row(s: Seed): WireVault {
  const v = (s.store as unknown as { vaultsById: Map<string, WireVault> }).vaultsById.get(s.vaultId);
  if (!v) throw new Error("vault row missing");
  return v;
}

function name(s: Seed): string {
  return s.member.decryptVaultName(s.vaultId, row(s).metaBlob);
}

/** A member holding a shared vault "Family" (metaBlob has NO metaV yet — the 0 floor) at cursor 5. */
async function seeded(): Promise<Seed> {
  const owner = await enroll("owner@example.com");
  const member = await enroll("member@example.com");
  const { request, vaultId } = owner.buildCreateSharedVault("Family");
  const sealedVk = owner.wrapVkForMember(member.identityPub, vaultId);
  const itemId = owner.newItemId();
  const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 };
  const grant: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 3, sealedVk };
  const item: WireItem = {
    itemId,
    vaultId,
    rev: 4,
    createdAt: 0,
    updatedAt: 0,
    deleted: false,
    conflict: false,
    formatVersion: 1,
    attachmentIds: [],
    blob: owner.encryptItem(vaultId, itemId, DOC).blob,
  };
  const api = new FakeApi();
  const store = new VaultStore(api.asClient(), member);
  api.queue.push({ rev: 5, full: true, vaults: [vault], grants: [grant], items: [item], removedGrants: [] });
  await store.sync();
  return { owner, member, store, api, vaultId, vault, grant, item };
}

/** Deliver a rename to "Family v2" (metaV 0 → 1) and return the renamed metaBlob. */
async function applyRename(s: Seed): Promise<string> {
  const renamed = s.owner.buildRenameMeta(s.vaultId, s.vault.metaBlob, "Family v2");
  s.api.queue.push({ rev: 6, full: false, vaults: [{ ...s.vault, rev: 6, metaBlob: renamed }], grants: [], items: [], removedGrants: [] });
  await s.store.sync();
  return renamed;
}

/** The VK, extracted the way any key-holder could (sealed to a keypair the test holds),
 *  used to craft adversarial metaBlob plaintexts no honest client would write. */
function craftMeta(s: Seed, metaVJson: string): string {
  const kp = boxKeypairFromSeed(randomBytes(32));
  const vk = openSharedGrant(kp.publicKey, kp.privateKey, s.vaultId, fromB64(s.owner.wrapVkForMember(kp.publicKey, s.vaultId)));
  return toB64(seal(vk, utf8(`{"name":"Imposter","metaV":${metaVJson}}`), adVaultMeta(s.vaultId)));
}

describe("keepNewerMeta (spec 02 §4 warn-and-keep-newer)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a replayed metaV-0 blob keeps the newer local name; rev/lifecycle fields still apply", async () => {
    const s = await seeded();
    const renamed = await applyRename(s);
    expect(name(s)).toBe("Family v2");

    // A stale/malicious server replays the PRE-RENAME row (metaV absent → 0) at a higher
    // rev, with a lifecycle field set — the metaBlob must pin, the rest apply.
    s.api.queue.push({
      rev: 7, full: false, vaults: [{ ...s.vault, rev: 7, deleteId: "did-replay" }], grants: [], items: [], removedGrants: [],
    });
    await s.store.sync();

    expect(name(s)).toBe("Family v2"); // the newer local metaBlob kept (warn-and-keep-newer)
    expect(row(s).metaBlob).toBe(renamed);
    expect(row(s).rev).toBe(7); // rev from the delivered row still applies
    expect(row(s).deleteId).toBe("did-replay"); // lifecycle fields still apply
  });

  it("emits a calm meta-regression notice so the keep-newer is user-visible, not console-only", async () => {
    const s = await seeded();
    await applyRename(s);
    expect(s.store.notices().some((n) => n.kind === "meta-regression")).toBe(false);

    // Replay the pre-rename (metaV-0) row → keepNewerMeta pins the newer blob AND surfaces it.
    s.api.queue.push({
      rev: 7, full: false, vaults: [{ ...s.vault, rev: 7 }], grants: [], items: [], removedGrants: [],
    });
    await s.store.sync();

    const notice = s.store.notices().find((n) => n.kind === "meta-regression");
    expect(notice, "a meta-regression notice must surface").toBeDefined();
    expect(notice!.vaultId).toBe(s.vaultId);
    expect(notice!.vaultName).toBe("Family v2"); // the kept (newer) name, decrypted for the banner
  });

  it("the guard is inert on a 410 resync — vaultsById was just cleared, the snapshot applies as-is", async () => {
    const s = await seeded();
    await applyRename(s);
    expect(name(s)).toBe("Family v2");

    // Cursor expired (410) → resync from 0: no held row to compare against — the server's
    // snapshot (pre-rename blob) is authoritative and must apply, never pin (this guard is
    // anti-replay, not availability).
    s.api.goneNextSync = true;
    s.api.queue.push({
      rev: 10, full: true,
      vaults: [{ ...s.vault, rev: 10 }], grants: [{ ...s.grant, rev: 10 }], items: [{ ...s.item, rev: 10 }], removedGrants: [],
    });
    await s.store.sync();

    expect(name(s)).toBe("Family"); // on a since=0 resync the guard must be inert
    expect(row(s).rev).toBe(10);
  });

  it("string-encoded, fractional and negative metaV read as 0 (spec 02 §4) — the replay stays pinned", async () => {
    const s = await seeded();
    const renamed = await applyRename(s); // held metaV = 1

    // spec 02 §4 parse rule: metaV counts ONLY as an integral, non-negative JSON number —
    // "999999" (string-encoded), 2.5 (fractional) and -3 (negative) all read as 0, so each
    // delivery regresses below the held 1 and is pinned IDENTICALLY on every client (the
    // core twin runs the same three).
    let rev = 7;
    for (const metaVJson of ['"999999"', "2.5", "-3"]) {
      s.api.queue.push({
        rev, full: false, vaults: [{ ...s.vault, rev, metaBlob: craftMeta(s, metaVJson) }], grants: [], items: [], removedGrants: [],
      });
      await s.store.sync();
      expect(name(s), `metaV ${metaVJson} must read as 0 and stay pinned`).toBe("Family v2");
      expect(row(s).metaBlob, `metaV ${metaVJson}: the newer local blob must be kept`).toBe(renamed);
      rev++;
    }
  });

  it("buildRenameMeta applies the same parse rule — the counter restarts from 0, never from junk", async () => {
    const s = await seeded();
    // Write side of the same rule: a rename on top of a crafted non-integral metaV must
    // rebase the counter to 0 and write 1 — NOT 1000000 (string) or 3.5 (fractional).
    for (const metaVJson of ['"999999"', "2.5"]) {
      const rebuilt = s.member.buildRenameMeta(s.vaultId, craftMeta(s, metaVJson), "Clean");
      const meta = s.member.decryptVaultMeta(s.vaultId, rebuilt);
      expect(meta.metaV, `metaV ${metaVJson} must read as 0 → bump writes 1`).toBe(1);
      expect(meta.name).toBe("Clean");
    }
  });
});
