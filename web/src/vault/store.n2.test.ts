import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { SyncResponse } from "../api/types";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { type ItemWire, VaultStore } from "./store";

/**
 * The old account-state sync ran on every sync and fed four paths of the store: the fallback of "do I own
 * this vault", the offers this account made, the handovers held back for them, and the flush of ownership releases.
 * Each is retired onto what the design names as its source (the verified log, §3.3; the personal vault, §5.3), and the
 * old sync is gone.
 */

const src = fileURLToPath(new URL("..", import.meta.url));

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) out.push(...sources(p));
    else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n)) out.push(p);
  }
  return out;
}

function session() {
  const seed = randomBytes(32);
  const personalVaultId = crypto.randomUUID();
  const account = Account.fromOpened(
    { userId: crypto.randomUUID(), uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId, personalVk: randomBytes(32) },
    null,
  );
  const calls: string[] = [];
  const api = {
    onRefusedIds: undefined as unknown,
    async accountState() {
      calls.push("GET /account/state");
      return { sealedState: null, seq: 0 };
    },
    async putAccountState() {
      calls.push("PUT /account/state");
      return { sealedState: null, seq: 0 };
    },
  };
  const wire = {
    async sync(since: number): Promise<SyncResponse> {
      calls.push("GET /sync");
      return { rev: 1, full: since === 0, vaults: [], grants: [], items: [], removedGrants: [] };
    },
    async pushMutations() {
      return { rev: 1, results: [] };
    },
  };
  const store = new VaultStore(api as unknown as ApiClient, account, undefined, undefined, wire as unknown as ItemWire);
  return { account, store, calls, personalVaultId };
}

describe("the old account-state sync is retired", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a sync reads no account state through the store: the old sync's GET on every sync is gone", async () => {
    const { store, calls } = session();
    await store.sync();
    await store.sync();
    expect(calls.filter((c) => c.includes("/account/state"))).toEqual([]);
    expect(calls.filter((c) => c === "GET /sync").length).toBeGreaterThanOrEqual(2);
  });

  it("'do I own this vault' without a log layer: the personal vault is the account's own (§5.3), and nothing else is owned", () => {
    const { store, personalVaultId } = session();
    expect(store.ownsVault(personalVaultId)).toBe(true);
    expect(store.ownsVault(crypto.randomUUID())).toBe(false);
    expect(store.ownsVault("")).toBe(false);
  });

  it("the store has no own-offer record, no held handovers and no ownership-release flush: offers and handovers are the verified log's", () => {
    const store = readFileSync(join(src, "vault/store.ts"), "utf8");
    for (const gone of ["ownOffers(", "isOwnLiveOffer(", "recordOwnOffers(", "cancelOwnOffers(", "heldHandovers", "decideHeldHandovers", "ownershipReleases", "flushOwnershipReleases", "this.accountState"]) {
      expect(store, gone).not.toContain(gone);
    }
    // What replaced them: the owner's offer, an offer to this account, and a refusal, each read from the verified log.
    expect(store).toContain("this.shared!.logs.verifiedState(vaultId)?.pending");
    expect(store).toContain("const st = this.shared!.logs.verifiedState(vaultId);");
  });

  it("nothing imports the old sync, and it is not defined any more", () => {
    for (const f of sources(src)) {
      const text = readFileSync(f, "utf8");
      expect(text, f).not.toMatch(/import[^;]*\bAccountStateSync\b|new AccountStateSync\b|class AccountStateSync\b/);
    }
    const file = readFileSync(join(src, "vault/accountstatesync.ts"), "utf8");
    expect(file).not.toContain("export class");
  });

  it("the not-offered transfer notice is gone with its producer: no reason constant, no screen branch", () => {
    expect(readFileSync(join(src, "vault/store.ts"), "utf8")).not.toMatch(/\bTRANSFER_NOT_OFFERED\b|"not-offered"/);
    const vault = readFileSync(join(src, "ui/Vault.tsx"), "utf8");
    expect(vault).not.toMatch(/\bTRANSFER_NOT_OFFERED\b|from an offer you didn't make/);
  });
});
