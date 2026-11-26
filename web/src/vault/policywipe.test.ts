import "fake-indexeddb/auto"; // the browser's IndexedDB, where the offline copy lives
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError, TrafficStoppedError } from "../api/client";
import type { Mutation, PushResponse } from "../api/types";
import { WireApi } from "../api/wireclient";
import {
  fill,
  POLICY_WIPE_NOTHING_LOST,
  POLICY_WIPE_TRIED,
  POLICY_WIPE_UNSENT_MANY,
  POLICY_WIPE_UNSENT_ONE,
  POLICY_WIPE_UNSENT_UNKNOWN,
  POLICY_WIPE_UNSURE_MANY,
  POLICY_WIPE_UNSURE_ONE,
  policyWipeText,
} from "../ui/copy";
import { applyOrgOfflineCachePolicy, setOfflineCopyEnabled, unsentChangeCount, wipeLocalAccountState, wipeVaultCache } from "../ui/session";
import { openVaultCache, vaultDbName } from "./idbcache";
import { VaultLogStore } from "./logstore";
import { initSodium } from "../crypto/sodium";
import {
  CopyBeingRemovedError,
  copyIsBeingRemoved,
  copyRemovalBlocked,
  keepPolicyWipeNotice,
  NotThisAccountError,
  onPolicyWipeMadeLater,
  POLICY_WIPE_BATCH,
  POLICY_WIPE_NOTICE_KEY,
  type PolicyWipeClock,
  retryHeldPolicyWipes,
  sendWaitingOnce,
  senderForCopy,
  takePolicyWipeNotice,
} from "./policywipe";

/**
 * Decided on 2026-11-17: before a server's policy wipes the offline copy, the browser tries ONCE to send what waits, then
 * wipes as specified whatever the attempt brought, and says afterwards how many changes could not be sent. Each request
 * goes out only with the copy's own account's session, checked at that request; the whole attempt has one limit; one run
 * per copy across tabs; the number is read at the wipe and is true (sent, may or may not have arrived, not sent); and
 * the notice is said only once the copy is gone.
 */

/** The question every change is asked before it is sent, answering yes for every vault: these tests are about the
 *  attempt's limits and its numbers; policywipe.asks.test.ts is about the question. */
const anyVault = (): boolean => true;

function webStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

const mutation = (n: number, vaultId = "v1"): Mutation => ({ mutationId: `m${n}`, op: "delete", itemId: `i${n}`, vaultId, baseItemRev: 1 });
const all = (rows: Mutation[], status: "applied" | "duplicate" | "conflict" | "denied" | "rejected" = "applied"): PushResponse => ({ rev: 1, results: rows.map((m) => ({ mutationId: m.mutationId, status })) });
const rows = (n: number) => Array.from({ length: n }, (_, i) => mutation(i));

/** A clock a test drives: timers fire only when [fireNext] says so, in time order. */
class DrivenClock implements PolicyWipeClock {
  t = 0;
  private timers: { at: number; fn: () => void; live: boolean }[] = [];
  now(): number {
    return this.t;
  }
  after(ms: number, fn: () => void): () => void {
    const timer = { at: this.t + ms, fn, live: true };
    this.timers.push(timer);
    return () => {
      timer.live = false;
    };
  }
  /** Moves to the earliest live timer and fires it; false when none is set. */
  fireNext(): boolean {
    const live = this.timers.filter((x) => x.live).sort((a, b) => a.at - b.at);
    const next = live[0];
    if (!next) return false;
    next.live = false;
    this.t = Math.max(this.t, next.at);
    next.fn();
    return true;
  }
}

/** Lets the run's real IndexedDB work and promise steps settle. */
const settle = () => new Promise((r) => setTimeout(r, 5));

/** One exclusive Web Lock per name, granted in the order asked (what navigator.locks does across a browser's tabs). */
function webLocks() {
  const tails = new Map<string, Promise<unknown>>();
  return {
    request(name: string, a: unknown, b?: unknown): Promise<unknown> {
      const fn = (typeof a === "function" ? a : b) as (lock: unknown) => Promise<unknown>;
      const before = tails.get(name) ?? Promise.resolve();
      const run = before.then(() => fn({ name }));
      tails.set(
        name,
        run.catch(() => {}),
      );
      return run;
    },
  };
}

const exists = (userId: string) =>
  new Promise<boolean>((resolve) => {
    const req = indexedDB.open(vaultDbName(userId));
    req.onupgradeneeded = () => {
      req.transaction?.abort();
      resolve(false);
    };
    req.onsuccess = () => {
      req.result.close();
      resolve(true);
    };
    req.onerror = () => resolve(false);
  });

async function copyWith(userId: string, queued: Mutation[]): Promise<void> {
  const cache = await openVaultCache(userId);
  for (const m of queued) expect(await cache.enqueue(m)).toBe(true);
  cache.close();
}

/** A copy at a schema this build cannot open, holding two queue rows. */
function unopenableCopy(userId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(vaultDbName(userId), 7);
    r.onupgradeneeded = () => {
      const q = r.result.createObjectStore("queue", { keyPath: "seq", autoIncrement: true });
      q.add({ mutationId: "m1", staged: 0, mutation: mutation(1) });
      q.add({ mutationId: "m2", staged: 0, mutation: mutation(2) });
    };
    r.onsuccess = () => {
      r.result.close();
      resolve();
    };
    r.onerror = () => reject(r.error);
  });
}

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

describe("one attempt to send what waits", () => {
  it("everything taken: one request per batch of the server's size, in order", async () => {
    const batches: number[] = [];
    const r = await sendWaitingOnce(rows(450), async (b) => {
      batches.push(b.length);
      return all(b);
    }, anyVault);
    expect(batches).toEqual([POLICY_WIPE_BATCH, POLICY_WIPE_BATCH, 50]);
    expect([r.taken.size, r.unsure.size, r.requests, r.end]).toEqual([450, 0, 3, "done"]);
  });

  it("only the server's own answer that it took a change counts as sent: a deletion's conflict, a refusal and a missing result do not; a put's conflict does", async () => {
    const put7: Mutation = { mutationId: "m7", op: "put", itemId: "i7", vaultId: "v1", baseItemRev: 1, item: { formatVersion: 1, attachmentIds: [], blob: "b" } };
    const r = await sendWaitingOnce([mutation(1), mutation(2), mutation(3), mutation(4), mutation(5), mutation(6), put7], async () => ({
      rev: 1,
      results: [
        { mutationId: "m1", status: "applied" },
        { mutationId: "m2", status: "duplicate" },
        { mutationId: "m3", status: "conflict" }, // a deletion over a newer edit: not made
        { mutationId: "m4", status: "denied" },
        { mutationId: "m5", status: "rejected", reason: "item_attachment_quota" },
        // m6: the answer does not say
        { mutationId: "m7", status: "conflict" }, // a put over a newer version: stored, the displaced one in its history
      ],
    }), anyVault);
    // Turned round: a put's conflict counted as not sent before; it is stored by the server.
    expect([...r.taken].sort()).toEqual(["m1", "m2", "m7"]);
    expect([...r.unsure]).toEqual(["m6"]);
  });

  it("a request with no answer may or may not have arrived; a refusal of the whole batch, or one stopped before it left, did not; either ends the run", async () => {
    const cases: [unknown, boolean][] = [
      [new TypeError("Failed to fetch"), true],
      [Object.assign(new Error("aborted"), { name: "AbortError" }), true],
      [new ApiError(504, "gateway_timeout", "the front lost the answer"), true],
      [new TrafficStoppedError("forked", true), true],
      [new ApiError(409, "conflict", "refused"), false],
      [new ApiError(401, "unauthorized", "ended"), false],
      [new TrafficStoppedError("forked", false), false],
    ];
    for (const [e, maybe] of cases) {
      let calls = 0;
      const r = await sendWaitingOnce(rows(450), async (b) => {
        calls++;
        if (calls === 2) throw e;
        return all(b);
      }, anyVault);
      expect(calls, String(e)).toBe(2);
      expect([r.taken.size, r.unsure.size, r.end], String(e)).toEqual([200, maybe ? 200 : 0, "failed"]);
    }
  });

  it("with no live session nothing is sent", async () => {
    const r = await sendWaitingOnce(rows(3), null, anyVault);
    expect([r.taken.size, r.unsure.size, r.requests, r.end]).toEqual([0, 0, 0, "no_session"]);
  });
});

describe("item 1 (a): every request goes out only with the copy's own account's session", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  it("the sender checks the session at each request: a tab signed in to another account, or holding none, sends nothing more", async () => {
    const client = { getTokens: (): unknown => ({ accessToken: "a", refreshToken: "r" }), boundUserId: "u1" as string | null };
    const wire = { pushMutations: vi.fn(async (m: Mutation[]) => all(m)) };
    expect(senderForCopy({ getTokens: () => null, boundUserId: "u1" }, wire, "u1", anyVault)).toBeNull();
    expect(senderForCopy({ getTokens: () => ({}), boundUserId: "pending-sign-in-x" }, wire, "u1", anyVault)).toBeNull();
    const send = senderForCopy(client, wire, "u1", anyVault)!;
    await send([mutation(1)], new AbortController().signal);
    client.boundUserId = "u2"; // signed out, signed in as another account
    await expect(send([mutation(2)], new AbortController().signal)).rejects.toBeInstanceOf(NotThisAccountError);
    client.boundUserId = "u1";
    client.getTokens = () => null; // the server ended the session
    await expect(send([mutation(3)], new AbortController().signal)).rejects.toBeInstanceOf(NotThisAccountError);
    expect(wire.pushMutations).toHaveBeenCalledTimes(1);
  });

  it("the check's probe: a tab rebound from X to Y during the first push sends nothing of X's under Y's token; the rest counts as not sent and the wipe follows", async () => {
    const X = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    await copyWith(X, rows(250));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "X-access", refreshToken: "X-refresh" });
    client.boundUserId = X;
    const wire = new WireApi(client);
    const auths: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        const body = JSON.parse(String(init.body)) as { mutations: Mutation[] };
        auths.push(new Headers(init.headers).get("Authorization") ?? "");
        // While the first push is on its way, the person signs out and signs in as Y in this tab.
        client.setTokens({ accessToken: "Y-access", refreshToken: "Y-refresh" });
        client.boundUserId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        expect(String(url)).toMatch(/\/sync\/push$/);
        return json(200, all(body.mutations));
      }),
    );
    const kept = await applyOrgOfflineCachePolicy(false, X, { send: senderForCopy(client, wire, X, anyVault), server: "Family", mayWrite: anyVault });
    expect(auths).toEqual(["Bearer X-access"]);
    expect(kept).toEqual({ server: "Family", unsent: 50, unsure: 0 });
    expect(await exists(X), "the copy is gone").toBe(false);
  });

  it("a push that meets a 401 is not sent again after the refresh when the tab was rebound to another account meanwhile", async () => {
    const X = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    await copyWith(X, rows(1));
    let client: ApiClient;
    client = new ApiClient("https://family.example", null, (t) => {
      // The refresh installed X's new pair; in the very next step the person signs in as Y in this tab.
      if (t?.accessToken === "X-access-2") queueMicrotask(() => {
        client.setTokens({ accessToken: "Y-access", refreshToken: "Y-refresh" });
        client.boundUserId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
      });
    });
    client.setTokens({ accessToken: "X-access", refreshToken: "X-refresh" });
    client.boundUserId = X;
    const wire = new WireApi(client);
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        const u = String(url);
        if (u.endsWith("/auth/refresh")) {
          seen.push("refresh");
          return json(200, { accessToken: "X-access-2", refreshToken: "X-refresh-2" });
        }
        seen.push(`push ${new Headers(init.headers).get("Authorization")}`);
        if (seen.length === 1) return json(401, { error: "unauthorized" });
        const body = JSON.parse(String(init.body)) as { mutations: Mutation[] };
        return json(200, all(body.mutations));
      }),
    );
    const kept = await applyOrgOfflineCachePolicy(false, X, { send: senderForCopy(client, wire, X, anyVault), server: "Family", mayWrite: anyVault });
    expect(seen).toEqual(["push Bearer X-access", "refresh"]);
    expect(seen.some((s) => s.includes("Y-access"))).toBe(false);
    expect(kept).toEqual({ server: "Family", unsent: 1, unsure: 0 });
  });
});

describe("item 1 (b): one limit for the whole attempt, sixty seconds from its start", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  /** Runs the policy's wipe on [clock], firing its timers until the run ends; resolves to the run and the time it ended. */
  async function drive(clock: DrivenClock, start: () => Promise<unknown>) {
    // When the wipe is asked for, on the driven clock.
    const real = indexedDB;
    const wipedAt: number[] = [];
    vi.stubGlobal(
      "indexedDB",
      new Proxy(real, {
        get(t, k) {
          const v = Reflect.get(t, k, t) as unknown;
          if (k === "deleteDatabase") wipedAt.push(clock.now());
          return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
        },
      }),
    );
    const run = start();
    let done = false;
    void run.finally(() => {
      done = true;
    });
    try {
      for (let i = 0; i < 1000 && !done; i++) {
        await settle();
        if (!done) clock.fireNext();
      }
    } finally {
      vi.stubGlobal("indexedDB", real);
    }
    expect(done, "the run ended").toBe(true);
    return { result: await run, wipedAt };
  }

  it("a long queue and a server that answers each request just in time: the wipe is made by the sixtieth second", async () => {
    const U = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    await copyWith(U, rows(1000));
    const clock = new DrivenClock();
    const sent: number[] = [];
    // Each request is answered (all taken) 29.999 s after it was sent: inside its own 30 s, and never past it.
    const send = (b: Mutation[], signal: AbortSignal) =>
      new Promise<PushResponse>((resolve, reject) => {
        sent.push(clock.now());
        const answer = clock.after(29_999, () => resolve(all(b)));
        signal.addEventListener("abort", () => {
          answer();
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        });
      });
    const { result, wipedAt } = await drive(clock, () => applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }, { clock }));
    expect(wipedAt, "wiped at the sixtieth second").toEqual([60_000]);
    expect(sent).toEqual([0, 29_999, 59_998]); // the third request is cut off at 60 s
    expect(await exists(U), "the copy is gone").toBe(false);
    // 400 taken; the third batch went out with no answer in time (may or may not have arrived); 400 never sent.
    expect(result).toEqual({ server: "Family", unsent: 400, unsure: 200 });
  });

  it("a request that never ends, a refresh of the session included (it ignores the signal): the wipe is made at the sixtieth second", async () => {
    const U = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    await copyWith(U, rows(3));
    const clock = new DrivenClock();
    const { result, wipedAt } = await drive(clock, () => applyOrgOfflineCachePolicy(false, U, { send: () => new Promise<PushResponse>(() => {}), server: "Family", mayWrite: anyVault }, { clock, requestMs: 90_000 }));
    expect(wipedAt, "wiped at the sixtieth second").toEqual([60_000]);
    expect(await exists(U)).toBe(false);
    expect(result).toEqual({ server: "Family", unsent: 0, unsure: 3 });
  });
});

describe("item 1 (c): one run per copy across the browser's tabs, and nothing new queued into it", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    vi.stubGlobal("navigator", { locks: webLocks() });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("the check's two-tab sequence: two tabs read the policy at once; one run sends, nothing is sent twice, the number is said once and right", async () => {
    const U = "12121212-1212-4121-8121-121212121212";
    await copyWith(U, rows(3));
    // Two tabs: two copies of the app's modules over one browser (its IndexedDB, its localStorage, its Web Locks).
    vi.resetModules();
    const tabA = await import("../ui/session");
    vi.resetModules();
    const tabB = await import("../ui/session");
    const pushed: string[] = [];
    const send = async (b: Mutation[]) => {
      pushed.push(...b.map((m) => m.mutationId));
      return all(b, "denied"); // refused for its vault: not sent, and counted
    };
    const [a, b] = await Promise.all([
      tabA.applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }),
      tabB.applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }),
    ]);
    expect(pushed, "sent once").toEqual(["m0", "m1", "m2"]);
    expect([a, b], "the run that wipes says it; the other finds the copy gone and says nothing").toEqual([{ server: "Family", unsent: 3, unsure: 0 }, null]);
    expect(takePolicyWipeNotice()).toEqual({ server: "Family", unsent: 3, unsure: 0 });
    expect(takePolicyWipeNotice(), "said once").toBeNull();
    expect(await exists(U)).toBe(false);
  });

  it("one tab's start and its unlock both read the policy: one run, the number said once", async () => {
    vi.stubGlobal("navigator", {}); // no Web Locks: one run per tab still holds
    const U = "13131313-1313-4131-8131-131313131313";
    await copyWith(U, rows(2));
    const send = vi.fn(async (b: Mutation[]) => all(b, "denied"));
    const [a, b] = await Promise.all([applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }), applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault })]);
    expect(send).toHaveBeenCalledTimes(1);
    expect([a, b]).toEqual([{ server: "Family", unsent: 2, unsure: 0 }, null]);
    expect(takePolicyWipeNotice()).toEqual({ server: "Family", unsent: 2, unsure: 0 });
  });
});

describe("item 2: the number said afterwards is true", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  it("the check's probe (a): a server that stored every change and answered after the limit: said as may or may not have arrived, never as lost", async () => {
    const U = "21212121-2121-4212-8212-212121212121";
    await copyWith(U, rows(20));
    const stored: string[] = [];
    const send = (b: Mutation[], signal: AbortSignal) =>
      new Promise<PushResponse>((resolve, reject) => {
        stored.push(...b.map((m) => m.mutationId)); // the server takes them at once ...
        const late = setTimeout(() => resolve(all(b)), 800); // ... and answers after the limit
        signal.addEventListener("abort", () => {
          clearTimeout(late);
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        });
      });
    const kept = await applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }, { requestMs: 50 });
    expect(stored).toHaveLength(20);
    expect(kept).toEqual({ server: "Family", unsent: 0, unsure: 20 });
    expect(policyWipeText(kept!)).toBe(`${fill(POLICY_WIPE_TRIED, "Family")} ${fill(POLICY_WIPE_UNSURE_MANY, "Family", "20")}`);
  });

  it("a conflict is counted by what the server did with it: a deletion over a newer edit is not made; a put over a newer version is sent", async () => {
    const U = "22222222-2222-4222-8222-222222222222";
    await copyWith(U, rows(2));
    const kept = await applyOrgOfflineCachePolicy(false, U, { send: async (b) => all(b, "conflict"), server: "Family", mayWrite: anyVault });
    expect(kept).toEqual({ server: "Family", unsent: 2, unsure: 0 });
    // Turned round from "a conflict is counted as not sent": puts the server answered with a conflict are stored.
    const P = "22222222-2222-4222-8222-222222222223";
    const puts: Mutation[] = [0, 1, 2].map((i) => ({ mutationId: `p${i}`, op: "put", itemId: `j${i}`, vaultId: "v1", baseItemRev: 1, item: { formatVersion: 1, attachmentIds: [], blob: "b" } }));
    await copyWith(P, puts);
    const sent = await applyOrgOfflineCachePolicy(false, P, { send: async (b) => all(b, "conflict"), server: "Family", mayWrite: anyVault });
    expect(sent).toEqual({ server: "Family", unsent: 0, unsure: 0 });
  });

  it("the check's probe (b): a copy that exists and cannot be opened is said as cannot tell, at the wipe and in the count before a sign-out", async () => {
    const U = "23232323-2323-4232-8232-232323232323";
    await unopenableCopy(U);
    expect(await unsentChangeCount(U), "the count before a sign-out cannot tell").toBeNull();
    expect(await exists(U), "counting did not delete it").toBe(true);
    const send = vi.fn();
    const kept = await applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault });
    expect(send).not.toHaveBeenCalled();
    expect(kept).toEqual({ server: "Family", unsent: null, unsure: 0 });
    expect(policyWipeText(kept!)).toBe(fill(POLICY_WIPE_UNSENT_UNKNOWN, "Family"));
    expect(await exists(U), "the wipe was made").toBe(false);
  });

  it("the count before a sign-out on a browser with no copy is 0, and asking makes none", async () => {
    const U = "24242424-2424-4242-8242-242424242424";
    expect(await unsentChangeCount(U)).toBe(0);
    expect(await exists(U)).toBe(false);
  });

  it("the check's probe (d): the number is read at the wipe; a row the store's queue lost meanwhile is not counted, one it gained is", async () => {
    const U = "25252525-2525-4252-8252-252525252525";
    await copyWith(U, [mutation(1), mutation(2)]);
    const send = async (b: Mutation[]) => {
      // While the push is on its way, another writer adds a row (the store refuses this now; the count must still be true).
      const c = await openVaultCache(U);
      await c.enqueue(mutation(3));
      c.close();
      return all(b);
    };
    const kept = await applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault });
    expect(kept).toEqual({ server: "Family", unsent: 1, unsure: 0 });
  });

  it("each number gets a sentence of its own", () => {
    expect(policyWipeText({ server: "Family", unsent: 0, unsure: 0 })).toBe(fill(POLICY_WIPE_NOTHING_LOST, "Family"));
    expect(policyWipeText({ server: "Family", unsent: 1, unsure: 0 })).toBe(fill(POLICY_WIPE_UNSENT_ONE, "Family"));
    expect(policyWipeText({ server: "Family", unsent: 5, unsure: 0 })).toBe(fill(POLICY_WIPE_UNSENT_MANY, "Family", "5"));
    expect(policyWipeText({ server: "Family", unsent: 0, unsure: 1 })).toBe(`${fill(POLICY_WIPE_TRIED, "Family")} ${fill(POLICY_WIPE_UNSURE_ONE, "Family")}`);
    expect(policyWipeText({ server: "Family", unsent: 2, unsure: 3 })).toBe(`${fill(POLICY_WIPE_UNSENT_MANY, "Family", "2")} ${fill(POLICY_WIPE_UNSURE_MANY, "Family", "3")}`);
    expect(policyWipeText({ server: "Family", unsent: null, unsure: 4 })).toBe(fill(POLICY_WIPE_UNSENT_UNKNOWN, "Family"));
  });
});

describe("the number is never read from a copy that is no longer there", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    vi.stubGlobal("navigator", { locks: webLocks() });
  });
  afterEach(() => vi.unstubAllGlobals());

  /** A push that waits until [release] is called, then fails as a request with no answer, or answers [answer]. */
  function heldPush() {
    let release: (outcome: "no_answer" | PushResponse) => void = () => {};
    const pushed: string[][] = [];
    const send = vi.fn(
      (b: Mutation[]) =>
        new Promise<PushResponse>((resolve, reject) => {
          pushed.push(b.map((m) => m.mutationId));
          release = (o) => (o === "no_answer" ? reject(new TypeError("Failed to fetch")) : resolve(o));
        }),
    );
    return { send, pushed, release: (o: "no_answer" | PushResponse) => release(o) };
  }

  it("the check's probe: twenty changes wait, a slow push, a sign-out in the middle (its wipe completes as far as it can), the push gets no answer: never 'nothing was lost'", async () => {
    const U = "41414141-4141-4414-8414-414141414141";
    await copyWith(U, rows(20));
    const p = heldPush();
    const run = applyOrgOfflineCachePolicy(false, U, { send: p.send, server: "Family", mayWrite: anyVault });
    await vi.waitFor(() => expect(p.send).toHaveBeenCalledTimes(1));
    // The person signs out from the unlock card while the push is out: the sign-out's wipe (App.signOut's) starts.
    const signOutWipe = wipeVaultCache(U);
    await settle();
    expect(await exists(U), "the sign-out's wipe waits for the policy's run").toBe(true);
    p.release("no_answer");
    const kept = await run;
    await signOutWipe;
    expect(kept).toEqual({ server: "Family", unsent: 0, unsure: 20 });
    expect(policyWipeText(kept!)).toBe(`${fill(POLICY_WIPE_TRIED, "Family")} ${fill(POLICY_WIPE_UNSURE_MANY, "Family", "20")}`);
    expect(policyWipeText(kept!)).not.toBe(fill(POLICY_WIPE_NOTHING_LOST, "Family"));
    expect(await exists(U), "the copy is gone").toBe(false);
  });

  it("the check's P1c: 250 changes, the tab signs out during the first push (pair dropped, the wipe started), 200 taken: the 50 never sent are said as lost", async () => {
    const U = "42424242-4242-4424-8424-424242424242";
    await copyWith(U, rows(250));
    let tokens: unknown = { accessToken: "x", refreshToken: "r" };
    const client = { getTokens: () => tokens, boundUserId: U as string | null };
    const p = heldPush();
    const send = senderForCopy(client, { pushMutations: (m) => p.send(m) }, U, anyVault);
    const run = applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault });
    await vi.waitFor(() => expect(p.send).toHaveBeenCalledTimes(1));
    tokens = null; // App.signOut: clearSession, setTokens(null) ...
    client.boundUserId = null;
    const signOutWipe = wipeVaultCache(U); // ... and the wipe
    await settle();
    p.release(all(rows(250).slice(0, 200)));
    const kept = await run;
    await signOutWipe;
    expect(p.pushed).toHaveLength(1);
    expect(kept).toEqual({ server: "Family", unsent: 50, unsure: 0 });
    expect(await exists(U)).toBe(false);
  });

  it("Settings turning the copy off and an account deletion wait for the run the same way", async () => {
    for (const [U, wipeBy] of [
      ["43434343-4343-4434-8434-434343434343", (u: string) => setOfflineCopyEnabled(u, false)],
      ["44444444-4444-4444-8444-444444444444", (u: string) => wipeLocalAccountState(u)],
    ] as const) {
      await copyWith(U, rows(3));
      const p = heldPush();
      const run = applyOrgOfflineCachePolicy(false, U, { send: p.send, server: "Family", mayWrite: anyVault });
      await vi.waitFor(() => expect(p.send).toHaveBeenCalledTimes(1));
      const other = wipeBy(U);
      await settle();
      expect(await exists(U)).toBe(true);
      p.release(all(rows(3), "denied"));
      expect(await run).toEqual({ server: "Family", unsent: 3, unsure: 0 });
      await other;
      expect(await exists(U)).toBe(false);
    }
  });

  it("a copy that vanishes under the run all the same (a wipe outside the lock) is counted from the run's first read and what the server took", async () => {
    const U = "45454545-4545-4454-8454-454545454545";
    await copyWith(U, rows(20));
    const p = heldPush();
    const run = applyOrgOfflineCachePolicy(false, U, { send: p.send, server: "Family", mayWrite: anyVault });
    await vi.waitFor(() => expect(p.send).toHaveBeenCalledTimes(1));
    await new Promise<void>((resolve) => {
      const r = indexedDB.deleteDatabase(vaultDbName(U)); // not through any wipe of the app: no lock
      r.onsuccess = () => resolve();
      r.onerror = () => resolve();
    });
    expect(await exists(U)).toBe(false);
    p.release({ rev: 1, results: rows(20).slice(0, 5).map((m) => ({ mutationId: m.mutationId, status: "applied" as const })) });
    // 5 taken; the other 15 have no result in the answer: may or may not have arrived. Never "nothing was lost".
    expect(await run).toEqual({ server: "Family", unsent: 0, unsure: 15 });
  });
});

describe("item 2 (c): a wipe that could not be made is not said as made", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  it("a connection that does not close holds the wipe: nothing is said; when it closes the wipe is made and the notice is said then", async () => {
    const U = "31313131-3131-4313-8313-313131313131";
    await copyWith(U, rows(2));
    // A connection that ignores the versionchange (no self-close): the deletion stays blocked while it is open.
    const blocker = await new Promise<IDBDatabase>((resolve) => {
      const r = indexedDB.open(vaultDbName(U));
      r.onsuccess = () => resolve(r.result);
    });
    const told = vi.fn();
    const stop = onPolicyWipeMadeLater(told);
    try {
      const kept = await applyOrgOfflineCachePolicy(false, U, { send: async (b) => all(b), server: "Family", mayWrite: anyVault }, { deleteWaitMs: 50 });
      expect(kept, "not said as made").toBeNull();
      expect(takePolicyWipeNotice(), "nothing to say yet").toBeNull();
      // The policy is read again (another start): nothing is sent again, only the wipe is tried again.
      const again = vi.fn();
      expect(await applyOrgOfflineCachePolicy(false, U, { send: again, server: "Family", mayWrite: anyVault }, { deleteWaitMs: 50 })).toBeNull();
      expect(again).not.toHaveBeenCalled();
      blocker.close(); // what held it up ends
      await vi.waitFor(() => expect(told).toHaveBeenCalled());
      expect(await exists(U)).toBe(false);
      expect(takePolicyWipeNotice()).toEqual({ server: "Family", unsent: 0, unsure: 0 });
    } finally {
      stop();
      blocker.close();
    }
  });

  it("a deletion the browser refuses is tried again at the next start; the notice is said only once the copy is gone", async () => {
    const U = "32323232-3232-4323-8323-323232323232";
    await copyWith(U, rows(1));
    const real = indexedDB;
    const refusing = new Proxy(real, {
      get(t, k) {
        if (k === "deleteDatabase")
          return () => {
            const req = {} as IDBOpenDBRequest & { onerror: (() => void) | null };
            setTimeout(() => req.onerror?.(), 0);
            return req;
          };
        const v = Reflect.get(t, k, t) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
    vi.stubGlobal("indexedDB", refusing);
    expect(await applyOrgOfflineCachePolicy(false, U, { send: async (b) => all(b, "denied"), server: "Family", mayWrite: anyVault })).toBeNull();
    expect(takePolicyWipeNotice()).toBeNull();
    vi.stubGlobal("indexedDB", real); // the next start
    await retryHeldPolicyWipes();
    expect(await exists(U)).toBe(false);
    expect(takePolicyWipeNotice()).toEqual({ server: "Family", unsent: 1, unsure: 0 });
  });
});

describe("a held wipe is tried again only while the policy still forbids the copy", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  /** [real], with every deletion refused by the browser. */
  function refusingDeletes(real: IDBFactory) {
    return new Proxy(real, {
      get(t, k) {
        if (k === "deleteDatabase")
          return () => {
            const req = {} as IDBOpenDBRequest & { onerror: (() => void) | null };
            setTimeout(() => req.onerror?.(), 0);
            return req;
          };
        const v = Reflect.get(t, k, t) as unknown;
        return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(t) : v;
      },
    });
  }

  it("the check's sequence: a held wipe of 2, the policy lifted, 5 new changes made in the copy, the next start: nothing is wiped and nothing is said", async () => {
    const U = "51515151-5151-4515-8515-515151515151";
    const real = indexedDB;
    await copyWith(U, rows(2));
    vi.stubGlobal("indexedDB", refusingDeletes(real));
    expect(await applyOrgOfflineCachePolicy(false, U, { send: async (b) => all(b, "denied"), server: "Family", mayWrite: anyVault })).toBeNull();
    vi.stubGlobal("indexedDB", real);
    expect(localStorage.getItem(POLICY_WIPE_NOTICE_KEY), "a held wipe with its notice").not.toBeNull();
    // The policy is lifted (a policy read that allows the copy): the held wipe and its notice end.
    expect(await applyOrgOfflineCachePolicy(true, U)).toBeNull();
    expect(localStorage.getItem(POLICY_WIPE_NOTICE_KEY)).toBeNull();
    // The person works in the copy again: five changes wait.
    await copyWith(U, [10, 11, 12, 13, 14].map((n) => mutation(n)));
    // The next start.
    await retryHeldPolicyWipes();
    expect(await exists(U), "the copy is still there").toBe(true);
    expect(await unsentChangeCount(U)).toBe(7);
    expect(takePolicyWipeNotice(), "nothing is said on the strength of the old policy").toBeNull();
    // The policy forbids the copy again later: a full attempt with a number read anew, never the old 2.
    const pushed: string[] = [];
    const kept = await applyOrgOfflineCachePolicy(false, U, {
      send: async (b) => {
        pushed.push(...b.map((m) => m.mutationId));
        return all(b);
      },
      server: "Family",
      mayWrite: anyVault,
    });
    expect(pushed).toHaveLength(7);
    expect(kept).toEqual({ server: "Family", unsent: 0, unsure: 0 });
  });

  it("a start whose policy still forbids the copy wipes it, and a lifted policy found under the run's lock ends the held wipe there too", async () => {
    const U = "52525252-5252-4525-8525-525252525252";
    const real = indexedDB;
    await copyWith(U, rows(1));
    vi.stubGlobal("indexedDB", refusingDeletes(real));
    await applyOrgOfflineCachePolicy(false, U, { send: async (b) => all(b, "denied"), server: "Family", mayWrite: anyVault });
    vi.stubGlobal("indexedDB", real);
    // The pin is removed by another tab's policy read without this tab's clean-up having run yet: the retry ends it.
    localStorage.removeItem("andvari.orgCacheOff");
    await retryHeldPolicyWipes();
    expect(await exists(U)).toBe(true);
    expect(localStorage.getItem(POLICY_WIPE_NOTICE_KEY)).toBeNull();
  });
});

describe("the notice, kept apart from the copy and said once", () => {
  it("one entry per copy, replaced rather than added; said only once its copy is gone; taken once", () => {
    const s = webStorage();
    keepPolicyWipeNotice("u1", { server: "Family", unsent: 2, unsure: 0 }, false, s);
    keepPolicyWipeNotice("u1", { server: "Family", unsent: 2, unsure: 1 }, false, s);
    expect(takePolicyWipeNotice(s), "its copy is not gone yet").toBeNull();
    keepPolicyWipeNotice("u1", { server: "Family", unsent: 2, unsure: 1 }, true, s);
    keepPolicyWipeNotice("u2", { server: "Family", unsent: 1, unsure: 0 }, true, s);
    expect(takePolicyWipeNotice(s)).toEqual({ server: "Family", unsent: 3, unsure: 1 });
    expect(takePolicyWipeNotice(s), "said once").toBeNull();
  });

  it("holds the server's name, the numbers and whether the copy is gone: nothing of the content", () => {
    const s = webStorage();
    keepPolicyWipeNotice("u1", { server: "Family", unsent: 4, unsure: 1 }, true, s);
    const kept = JSON.parse(s.getItem(POLICY_WIPE_NOTICE_KEY)!) as Record<string, object>;
    expect(Object.keys(kept.u1!).sort()).toEqual(["gone", "server", "unsent", "unsure"]);
  });
});

describe("a sign-out's own wipe is finished even if the tab is closed while it waits", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    vi.stubGlobal("navigator", { locks: webLocks() });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("a sign-out during a policy's run, the tab closed before the wipe: the next start removes the copy, with no session", async () => {
    const U = "51515151-5151-4515-8515-515151515151";
    await copyWith(U, rows(3));
    vi.resetModules();
    const tabA = await import("../ui/session");
    let release: () => void = () => {};
    const pushed = vi.fn(
      () =>
        new Promise<PushResponse>((_, reject) => {
          release = () => reject(new TypeError("Failed to fetch"));
        }),
    );
    const run = tabA.applyOrgOfflineCachePolicy(false, U, { send: pushed, server: "Family", mayWrite: anyVault });
    await vi.waitFor(() => expect(pushed).toHaveBeenCalledTimes(1));
    void tabA.wipeVaultCache(U); // App.signOut's wipe: it waits for the run's lock
    await settle();
    expect(await exists(U), "the sign-out's wipe waits for the policy's run").toBe(true);
    expect(tabA.owedWipes(), "the mark holds only which copy").toEqual([U]);
    expect(localStorage.getItem(tabA.WIPE_OWED_PREFIX + U)).toMatch(/^\d+$/);

    // The tab is closed: its run and its waiting wipe never go on, and the browser releases its Web Lock.
    vi.stubGlobal("navigator", { locks: webLocks() });
    vi.resetModules();
    const next = await import("../ui/session");
    expect(next.owedWipes()).toEqual([U]);
    await next.finishOwedWipes(); // the next start of the app in this browser (App's first effect), no session needed
    expect(await exists(U), "the copy is gone").toBe(false);
    expect(next.owedWipes(), "nothing is owed any more").toEqual([]);

    release(); // the closed tab's run is let go only to end this test cleanly
    await run;
  });

  it("a wipe made in its own tab owes nothing afterwards; a copy opened again after an owed wipe is a fresh one", async () => {
    const U = "52525252-5252-4525-8525-525252525252";
    await copyWith(U, rows(2));
    const session = await import("../ui/session");
    await session.wipeVaultCache(U);
    expect(session.owedWipes()).toEqual([]);

    await copyWith(U, rows(2));
    localStorage.setItem(session.WIPE_OWED_PREFIX + U, "1"); // owed by a tab closed while it waited
    await session.setOfflineCopyEnabled(U, true);
    const { cachedAccountKeys } = await import("../ui/opensession");
    expect(await cachedAccountKeys(U), "the owed wipe is made before the copy is read").toBeNull();
    expect(await unsentChangeCount(U), "the old queue is gone").toBe(0);
    expect(session.owedWipes()).toEqual([]);
  });

  it("a removal held up by a connection that does not close is marked as such, stays so at the next policy read, and the mark goes with the copy", async () => {
    const U = "53535353-5353-4535-8535-535353535353";
    await copyWith(U, rows(1));
    const blocker = await new Promise<IDBDatabase>((resolve) => {
      const r = indexedDB.open(vaultDbName(U));
      r.onsuccess = () => resolve(r.result);
    });
    try {
      const send = async (b: Mutation[]) => all(b);
      expect(await applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }, { deleteWaitMs: 50 })).toBeNull();
      expect(copyRemovalBlocked(U)).toBe(true);
      expect(new CopyBeingRemovedError(copyRemovalBlocked(U)).blocked).toBe(true);
      expect(await applyOrgOfflineCachePolicy(false, U, { send, server: "Family", mayWrite: anyVault }, { deleteWaitMs: 50 })).toBeNull();
      expect(copyRemovalBlocked(U), "a new read does not make it 'in a moment' again").toBe(true);
      blocker.close();
      await vi.waitFor(async () => expect(await exists(U)).toBe(false));
      expect(copyRemovalBlocked(U)).toBe(false);
      expect(copyIsBeingRemoved(U), "open for changes again").toBe(false);
    } finally {
      blocker.close();
    }
  });

  it("App's first effect finishes the owed wipes before anything else", () => {
    const app = readFileSync(fileURLToPath(new URL("../ui/App.tsx", import.meta.url)), "utf8");
    const boot = app.indexOf("void finishOwedWipes();");
    expect(boot).toBeGreaterThan(0);
    expect(boot).toBeLessThan(app.indexOf("await initSodium();"));
  });
});

describe("a change that did not happen and whose notice was not dismissed yet, when a server's policy wipes the copy", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
  });
  afterEach(() => vi.unstubAllGlobals());

  it("is not removed by the wipe: its settled record lives with the account, not in the copy, so its own notice comes at the next unlock", async () => {
    await initSodium();
    const U = "abababab-abab-4bab-8bab-abababababab";
    const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    // The log store's settled record of a removal that did not happen when it was sent again, as it keeps it at rest.
    const ls = { get: (k: string) => localStorage.getItem(k), set: (k: string, v: string) => localStorage.setItem(k, v), remove: (k: string) => localStorage.removeItem(k) };
    localStorage.setItem(`andvari.log2.${U}.${V}.settled`, JSON.stringify([{ pending: { vaultId: V, frame: "AAAA", heldAt: 1 }, outcome: { kind: "refused", vaultId: V, code: "not_owner" } }]));
    localStorage.setItem(`andvari.log2.${U}.settled-index`, V);
    const pair = { publicKey: new Uint8Array(32), secretKey: new Uint8Array(64), privateKey: new Uint8Array(32) } as never;
    const logs = () => new VaultLogStore(U, pair, pair, new Uint8Array(32), null as never, ls, null as never, null as never, new Map());
    expect(logs().settledChanges()).toHaveLength(1);
    await copyWith(U, rows(1));
    const client = new ApiClient("https://family.example");
    client.setTokens({ accessToken: "U-access", refreshToken: "U-refresh" });
    client.boundUserId = U;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: RequestInit) => json(200, all((JSON.parse(String(init.body)) as { mutations: Mutation[] }).mutations))));
    const kept = await applyOrgOfflineCachePolicy(false, U, { send: senderForCopy(client, new WireApi(client), U, anyVault), server: "Family", mayWrite: anyVault });
    expect(kept).toEqual({ server: "Family", unsent: 0, unsure: 0 });
    expect(await exists(U), "the copy is gone").toBe(false);
    // Still there after the wipe: the next unlock's store makes its notice from it (store.move-everything.test.ts,
    // "a tab closed right after the unlock loses nothing"), and it goes only when that notice is dismissed.
    const after = logs().settledChanges();
    expect(after).toHaveLength(1);
    expect(after[0]!.outcome).toEqual({ kind: "refused", vaultId: V, code: "not_owner" });
  });
});
