import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import type { Mutation, PushResponse, SyncResponse } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { FakeSharedLogs } from "./fakesharedlogs.testkit";
import { boundTo, SessionClosedError, SessionFence } from "./sessionfence";
import { type ItemWire, VaultStore } from "./store";

/**
 * Before 2026-11-16, nothing ended a session's work at a lock or a sign-out. A lock now closes the session's
 * fence (VaultStore.close, from App's one effect on the open store), every later call of the session refuses before
 * anything is sent, a request already on its way is never sent again under another account's token, and the person is
 * told when a lock overtook work still on its way.
 */
const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

describe("SessionFence", () => {
  it("refuses every call after close, before the target is reached, and tells once", async () => {
    const calls: string[] = [];
    const target = { async push(x: string) { calls.push(x); return x; }, name: "t" };
    const fence = new SessionFence();
    let told = 0;
    fence.onInterrupted = () => told++;
    const w = fence.wrap(target);
    expect(await w.push("a")).toBe("a");
    expect(w.name).toBe("t");
    fence.close();
    expect(told).toBe(0); // nothing was on its way
    expect(() => w.push("b")).toThrow(SessionClosedError);
    expect(() => w.push("c")).toThrow(SessionClosedError);
    expect(calls).toEqual(["a"]);
    expect(told).toBe(1);
  });

  it("closing on a call still on its way tells the person; a quiet transport never does", async () => {
    let release: () => void = () => {};
    const target = { push: () => new Promise<void>((r) => (release = r)) };
    const fence = new SessionFence();
    let told = 0;
    fence.onInterrupted = () => told++;
    const pending = fence.wrap(target).push();
    fence.close();
    expect(told).toBe(1);
    release();
    await pending;
    const quietFence = new SessionFence();
    quietFence.onInterrupted = () => told++;
    const q = quietFence.wrap({ usage: async () => 1 }, { quiet: true });
    quietFence.close();
    expect(() => q.usage()).toThrow(SessionClosedError);
    expect(told).toBe(1);
  });

  it("boundTo refuses while the tab is bound to another account", () => {
    let bound = "A";
    const w = boundTo({ put: () => "sent" }, () => bound === "A");
    expect(w.put()).toBe("sent");
    bound = "B";
    expect(() => w.put()).toThrow(SessionClosedError);
  });
});

describe("a 401 is never retried under another account's token", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("a request made for A, answered 401 after the tab signed in as B, is not sent again", async () => {
    const sent: string[] = [];
    let release: () => void = () => {};
    const client = new ApiClient("https://vault.example.org");
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      const auth = (init.headers as Record<string, string>)["Authorization"] ?? "";
      sent.push(auth);
      if (auth === "Bearer A-access") await new Promise<void>((r) => (release = r));
      return new Response(JSON.stringify({ error: "unauthorized", message: "x" }), { status: 401, headers: { "Content-Type": "application/json" } });
    });
    client.boundUserId = "A";
    client.setTokens({ accessToken: "A-access", refreshToken: "A-refresh" });
    const late = client.sendRequest("GET", "/api/v1/sync?since=0").catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 0));
    // Signed out, then signed in as B while A's request was on its way.
    client.setTokens(null);
    client.boundUserId = "B";
    client.useSessionTokens({ accessToken: "B-access", refreshToken: "B-refresh" });
    release();
    await late;
    expect(sent).toEqual(["Bearer A-access"]);
  });
});

class FakeApi {
  pushes: Mutation[][] = [];
  syncs = 0;
  async sync(): Promise<SyncResponse> {
    this.syncs++;
    return { rev: 1, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async pushMutations(m: Mutation[]): Promise<PushResponse> {
    this.pushes.push(m);
    return { rev: 2, results: [] };
  }
  async vaultMembers() {
    return [];
  }
  async accountState() {
    return { sealedState: null, seq: 0 };
  }
}

describe("VaultStore.close: a locked session's store sends nothing", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("after close a sync asks nothing and a save is refused before anything is sent", async () => {
    const recovery = boxKeypairFromSeed(randomBytes(32));
    const { request } = await Account.enroll({ inviteToken: "t", email: "f3@example.com", displayName: "f3", password: "pw", kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
    const device = await Account.unlock(request.userId, "pw", { kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed, identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap! });
    const api = new FakeApi();
    const fence = new SessionFence();
    const store = new VaultStore(fence.wrap(api) as never, device, undefined, memoryClientState(), fence.wrap(api) as unknown as ItemWire);
    store.attachFence(fence);
    new FakeSharedLogs(device).attachTo(store);
    store.close();
    expect(store.isClosed()).toBe(true);
    expect(fence.isClosed).toBe(true);
    await store.sync();
    expect(api.syncs).toBe(0);
    await expect(store.save(null, { type: "note", name: "late" })).rejects.toBeTruthy();
    expect(api.pushes).toEqual([]);
  });
});

describe("the wiring: every transport of a session goes through its fence, and App closes it", () => {
  it("enterVault hands the fenced client and wire to the store, the log layer, the settings flows and the screens", () => {
    const open = src("../ui/opensession.ts");
    expect(open).toContain("const client = fence.wrap(ctx.client);");
    expect(open).toContain("const wire = fence.wrap(ctx.wire);");
    expect(open).toContain("new SharedLogSession(parts, wire, ctx.storage, account.logKeyRing());");
    expect(open).toContain("const store = new VaultStore(client, account, cache, undefined, wire);");
    expect(open).toContain("store.attachFence(fence);");
    expect(open).toContain("const settings: SettingsSession = { wire, pins:");
    expect(open).toContain("usageWire: boundTo(ctx.wire, () => ctx.client.boundUserId === account.userId)");
    expect(open).not.toContain("a lock wipes both");
    expect(src("./accountdocstore.ts")).not.toContain("the caller wipes it at lock");
  });

  it("App closes the store the tab leaves, whatever took it off the vault, and the screens use the session's transports", () => {
    const app = src("../ui/App.tsx");
    expect(app).toContain("const openStore = phase.kind === \"vault\" ? phase.store : null;");
    expect(app).toMatch(/useEffect\(\(\) => \{\s*if \(openStore === null\) return;\s*return \(\) => openStore\.close\(\);\s*\}, \[openStore\]\);/);
    expect(app).toContain("client={phase.meta.client}");
    expect(app).toContain("usageWire={phase.meta.usageWire}");
    expect(app).not.toContain("usageWire={ctxRef.current!.wire}");
    expect(app).toContain("store.onInterrupted(");
  });
});
