import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, PushResponse, SyncResponse, VaultMemberSummary } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { FakeSharedLogs, vaultMadeBy } from "./fakesharedlogs.testkit";
import { type ItemWire, NoPersonalVaultError, VaultStore } from "./store";

/**
 * Security review 2026-10, branch A11 (web runner of `personalwrap.json`; core `PersonalDecisionVectorTest` twin).
 * Under the signed vault logs the personal vault is the genesis vault, in force at unlock only when its served wrap
 * opened (design §5.3); the store decides nothing locally, so the `decision` table's designation rows (c00, c01) have
 * no web runner any more, and neither has c19 (there is no proposal on the web to keep: design §15's web row; a second
 * apply never switching is pinned in api-review-2). What stays: c04/c08 (copy-all-to-Personal refuses with no personal
 * vault in force), driven by the REAL Account + VaultStore.
 */

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/personalwrap.json", import.meta.url)), "utf-8"));

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

class FakeServer {
  keys: AccountKeys | null = null;
  accountStateBlob: string | null = null;
  accountSeq = 0;
  members: Record<string, VaultMemberSummary[]> = {};
  pushes = 0;
  constructor(public feed: SyncResponse) {}
  async sync(since: number): Promise<SyncResponse> {
    return since === 0 ? this.feed : { rev: this.feed.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async pushMutations(m: { mutationId: string }[]): Promise<PushResponse> {
    this.pushes++;
    return { rev: this.feed.rev, results: m.map((x) => ({ mutationId: x.mutationId, status: "ok", newItemRev: this.feed.rev + 1 })) } as unknown as PushResponse;
  }
  async accountKeys(): Promise<AccountKeys> {
    if (!this.keys) throw new ApiError(404, "not_found", "no");
    return this.keys;
  }
  async accountState() {
    return { sealedState: this.accountStateBlob, seq: this.accountSeq };
  }
  async putAccountState(sealedState: string, baseSeq: number) {
    if (baseSeq !== this.accountSeq) throw new ApiError(409, "stale_state", "stale");
    this.accountStateBlob = sealedState;
    this.accountSeq += 1;
    return { sealedState, seq: this.accountSeq };
  }
  async vaultMembers(vaultId: string) {
    return this.members[vaultId] ?? [];
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }

  /** The item routes the store calls (its ItemWire): this fake serves them too. */
  asWire(): ItemWire {
    return this as unknown as ItemWire;
  }
}

async function world() {
  const email = `a11-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  const keys: AccountKeys = {
    kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed,
    identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap,
  };
  const shared = vaultMadeBy(account, "Household");
  const A = request.personalVault.vaultId;
  const C = shared.vaultId;
  const feed: SyncResponse = {
    rev: 5, full: true,
    vaults: [
      { vaultId: A, type: "personal", rev: 2, metaBlob: request.personalVault.metaBlob, createdAt: 0 },
      { vaultId: C, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 },
    ],
    grants: [
      { vaultId: A, userId: request.userId, role: "owner", wrappedVk: request.personalVault.wrappedVk, rev: 2 },
      { vaultId: C, userId: request.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 3 }, // a hint only
    ],
    items: [], removedGrants: [],
  };
  // C's key, which the verified log hands a device that is not the creating one (read from the creating account).
  const vkC = (account as unknown as { vaultKeys: Map<string, Uint8Array> }).vaultKeys.get(C)!.slice();
  return { account, keys, userId: request.userId, password, A, C, vkC, feed };
}

describe("A11 — personal-vault vectors under the signed logs (c04/c08)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the vector file still carries its decision table (other engines run it)", () => {
    expect((vectors.decision as unknown[]).length).toBeGreaterThanOrEqual(15);
  });

  it("c04/c08: copy-all-to-Personal with no personal vault in force refuses before sealing anything", async () => {
    const w = await world();
    const server = new FakeServer(w.feed);
    server.keys = { ...w.keys, personalWrap: null }; // the served wrap is withheld: no personal vault in force (§5.3)
    const device = await Account.unlock(w.userId, w.password, server.keys);
    const s = new VaultStore(server.asClient(), device, undefined, memoryClientState(), server.asWire());
    new FakeSharedLogs(device).attachTo(s).share(w.C, w.vkC, "owner"); // C's verified log lists the account as owner
    await s.sync();
    expect(device.personalVaultId).toBe("");
    expect(s.vaults().map((v) => v.vaultId)).toContain(w.C);
    await s.save(null, { type: "login", name: "Shared", login: { username: "u", password: "p" } }, [], undefined, w.C);
    const before = server.pushes;
    await expect(s.copyAllToPersonal(w.C)).rejects.toBeInstanceOf(NoPersonalVaultError);
    expect(server.pushes).toBe(before);
  });
});
