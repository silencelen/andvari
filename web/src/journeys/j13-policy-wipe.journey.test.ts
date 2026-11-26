import "fake-indexeddb/auto"; // the browser profile's IndexedDB, where the offline copy lives
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { fill, POLICY_WIPE_NOTHING_LOST, POLICY_WIPE_TRIED, POLICY_WIPE_UNSURE_ONE, policyWipeText } from "../ui/copy";
import type { PolicyWipeLimits } from "../vault/policywipe";
import { enterVault } from "../ui/opensession";
import { applyOrgOfflineCachePolicy, policyWipeQuestion } from "../ui/session";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import { senderForCopy, serverNameOf, takePolicyWipeNotice } from "../vault/policywipe";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 13: a server's policy that forbids the offline copy (decided on 2026-11-17: try once to send what waits, then
 * wipe as specified, and say afterwards how many changes could not be sent). Against the real server, with the operator
 * switching the policy while the journey runs (PolicyPeer.java, the shared code's own operator call): a change waits in
 * this browser's copy, the operator forbids the copy, the browser reads the policy and does what the app does with it
 * (App.loadPolicy): the change reaches the server, the copy is gone, and the notice says nothing was lost. Then the same
 * with the push getting no answer: the copy is gone all the same, and the notice says one change may or may not have
 * arrived (a request with no answer cannot be told). Last the worst case of the check: the server takes the change and
 * its answer comes too late: the notice says it may or may not have arrived (never that it is lost), and the server holds it.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

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

/** Whether this browser's IndexedDB holds a copy of [userId]'s account (asking makes none). */
function copyExists(userId: string): Promise<boolean> {
  return new Promise((resolve) => {
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
}

describe.skipIf(skip !== null)("journey 13: a policy that forbids the offline copy sends what waits once, wipes, and says what was lost", () => {
  let inst: TestInstance;
  let operator: SharePeerProcess;

  beforeAll(async () => {
    await initSodium();
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    // The browser has granted lasting storage, so a change made while the server is away waits in the copy (§D.2a).
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    inst = await TestInstance.start({ kind: "private", mode: "open", enrolOperator: false });
    operator = await inst.policyPeer("operator@example.org", "operator horse Battery 9 staple");
  }, HOOK.start);

  afterAll(async () => {
    await operator?.stop();
    vi.unstubAllGlobals();
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => inst.advance(61_000));

  /**
   * A person on this browser with an offline copy, and one change made while the server was away, waiting in it. The
   * policy allows the copy until the operator says otherwise.
   */
  async function personWithAChangeWaiting(email: string, password: string, name: string) {
    expect(await operator.cmd("offline-cache on")).toEqual({ offlineCacheAllowed: true });
    const browser = new Browser(inst, `Firefox at ${name}'s`);
    const signed = await browser.signUp(email, password, name);
    const userId = signed.session.userId;
    // The browser reads the policy that allows the copy again, as the app does at every start (it lifts the last-known pin).
    expect(await applyOrgOfflineCachePolicy((await browser.wire.clientPolicy()).offlineCacheAllowed !== false, userId)).toBeNull();
    const tab = await enterVault(browser.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email, pin: signed.pin, cardNotice: null, how: null }, (u) => openVaultCache(u));
    await tab.store.sync();
    await inst.halt();
    await tab.store.save(null, { type: "note", name: "Written while away", notes: "waits" });
    await inst.resume();
    const queue = await openVaultCache(userId);
    expect((await queue.pending()).length, "one change waits in the copy").toBe(1);
    queue.close();
    return { browser, userId };
  }

  /**
   * What App.loadPolicy does with a policy it read at a start, with no account open in the tab: the same call, with the
   * same sender, server name and question (the personal vault this browser's session record names).
   */
  async function applyAsTheApp(browser: Browser, userId: string, limits: PolicyWipeLimits = {}) {
    const p = await browser.wire.clientPolicy();
    const allowed = p.offlineCacheAllowed !== false;
    expect(allowed, "the browser reads the operator's policy").toBe(false);
    return applyOrgOfflineCachePolicy(allowed, userId, { send: senderForCopy(browser.client, browser.wire, userId, policyWipeQuestion(null, userId)), server: serverNameOf(browser.pins, browser.origin), mayWrite: policyWipeQuestion(null, userId) }, limits);
  }

  /** The note's names as a browser that never kept a copy reads them from the server. */
  async function namesAtTheServer(email: string, password: string): Promise<string[]> {
    const other = new Browser(inst, "Safari on a Mac");
    const r = await other.signIn(email, password);
    if (r.kind !== "opened") throw new Error(r.kind);
    const v = await other.openVault(r.opened, r.wrap);
    return v.store.list().map((i) => i.doc.name).sort();
  }

  it("the operator forbids the copy: the change that waited reaches the server, the copy is gone, and the notice says nothing was lost", async () => {
    const EMAIL = "kai@example.org";
    const PW = "kai's own Horse 3 battery";
    const { browser, userId } = await personWithAChangeWaiting(EMAIL, PW, "Kai");
    expect(await namesAtTheServer(EMAIL, PW), "the server does not have it yet").toEqual([]);

    expect(await operator.cmd("offline-cache off")).toEqual({ offlineCacheAllowed: false });
    const pushes: string[] = [];
    const real = globalThis.fetch;
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input instanceof Request ? input.url : input).endsWith("/sync/push")) pushes.push("push");
      return real(input, init);
    });
    let kept;
    try {
      kept = await applyAsTheApp(browser, userId);
    } finally {
      spy.mockRestore();
    }
    expect(pushes, "tried once").toEqual(["push"]);
    expect(kept).toEqual({ server: serverNameOf(browser.pins, browser.origin), unsent: 0, unsure: 0 });
    expect(await copyExists(userId), "the copy is gone").toBe(false);
    expect(await namesAtTheServer(EMAIL, PW), "the change arrived").toEqual(["Written while away"]);
    const notice = takePolicyWipeNotice();
    expect(notice).toEqual(kept);
    expect(policyWipeText(notice!)).toBe(fill(POLICY_WIPE_NOTHING_LOST, notice!.server));
    expect(takePolicyWipeNotice(), "said once").toBeNull();
  }, 600_000);

  it("the same with the push getting no answer: the copy is gone all the same, and the notice says one change may or may not have arrived", async () => {
    const EMAIL = "lou@example.org";
    const PW = "lou's own Horse 2 battery";
    const { browser, userId } = await personWithAChangeWaiting(EMAIL, PW, "Lou");

    expect(await operator.cmd("offline-cache off")).toEqual({ offlineCacheAllowed: false });
    const pushes: string[] = [];
    const real = globalThis.fetch;
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input instanceof Request ? input.url : input).endsWith("/sync/push")) {
        pushes.push("push");
        throw new TypeError("Failed to fetch"); // the push gets no answer
      }
      return real(input, init);
    });
    let kept;
    try {
      kept = await applyAsTheApp(browser, userId);
    } finally {
      spy.mockRestore();
    }
    expect(pushes, "tried once, no second try").toEqual(["push"]);
    expect(kept).toEqual({ server: serverNameOf(browser.pins, browser.origin), unsent: 0, unsure: 1 });
    expect(await copyExists(userId), "the copy is gone").toBe(false);
    expect(await namesAtTheServer(EMAIL, PW), "here it never arrived: the notice did not say it had").toEqual([]);
    const notice = takePolicyWipeNotice();
    expect(policyWipeText(notice!)).toBe(`${fill(POLICY_WIPE_TRIED, notice!.server)} ${fill(POLICY_WIPE_UNSURE_ONE, notice!.server)}`);
  }, 600_000);

  it("the check's worst case: the server takes the change and its answer comes too late: said as may or may not have arrived, and the server holds it", async () => {
    const EMAIL = "ash@example.org";
    const PW = "ash's own Horse 5 battery";
    const { browser, userId } = await personWithAChangeWaiting(EMAIL, PW, "Ash");

    expect(await operator.cmd("offline-cache off")).toEqual({ offlineCacheAllowed: false });
    const pushes: number[] = [];
    const real = globalThis.fetch;
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      if (!String(input instanceof Request ? input.url : input).endsWith("/sync/push")) return real(input, init);
      // The push reaches the real server, which takes the change and answers; the answer then comes past the limit.
      const { signal, ...rest } = init ?? {};
      const resp = await real(input, rest);
      pushes.push(resp.status);
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve());
      });
      throw new DOMException("The operation was aborted.", "AbortError");
    });
    let kept;
    try {
      kept = await applyAsTheApp(browser, userId, { requestMs: 3_000 });
    } finally {
      spy.mockRestore();
    }
    expect(pushes, "one push, and the server answered it (too late)").toEqual([200]);
    expect(kept).toEqual({ server: serverNameOf(browser.pins, browser.origin), unsent: 0, unsure: 1 });
    expect(await copyExists(userId), "the copy is gone").toBe(false);
    expect(await namesAtTheServer(EMAIL, PW), "the server holds the change").toEqual(["Written while away"]);
    const notice = takePolicyWipeNotice();
    expect(policyWipeText(notice!)).toBe(`${fill(POLICY_WIPE_TRIED, notice!.server)} ${fill(POLICY_WIPE_UNSURE_ONE, notice!.server)}`);
  }, 600_000);
});
