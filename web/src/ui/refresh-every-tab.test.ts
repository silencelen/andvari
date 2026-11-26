import "fake-indexeddb/auto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { unlockSession } from "../vault/onboardflow";
import { answerLimitText } from "./errors";
import { browserStorages, ORIGIN, pinnedStore } from "./forget-earlier.testkit";
import { at, bootTab, type Fate, fakeServer, keepSession, U, until } from "./refresh.testkit";
import { loadSession, makeClient, SESSION_STORAGE_KEY, TAB_TOKENS_KEY } from "./session";

/**
 * A refresh whose answer never came, across the tabs of one browser, each tab booted as App boots it (ui/session.ts
 * makeClient over this browser's storage). Each test is one of the sequences an independent check ran against the web
 * client and found broken: (a) another tab's sign-out or end of the session sent the token that one tab's refresh had
 * left unanswered, while the mark stood and after no try was left; (b) the request that set the refresh off came back as
 * its own 401, which the events connection and the unlock card read as the session's end; (c) a mark whose write failed
 * was taken as written, and a reload sent the token again later. The counts are of what left the browser.
 */
describe("a refresh whose answer never came, in every tab of the browser", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
    // The tab's own one more try runs on a timer: these tests move the clock themselves and run no timer.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  });
  afterEach(() => {
    vi.useRealTimers();
    st.restore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe("(a) a sign-out or an end of the session in another tab reads the mark and the kept token", () => {
    it("tab A's answer is lost; tab B, holding the same pair unmarked in its memory, signs out after the window: nothing spends the token", async () => {
      keepSession(true);
      const srv = fakeServer();
      srv.s.fates = ["lost"];
      at(srv, 1_000_000);
      const a = bootTab();
      const b = bootTab(); // the same pair, read before A's mark was written
      await a.sync();
      expect(srv.s.refreshes).toEqual(["r0"]);
      at(srv, 1_070_000);
      const resp = await b.client.logout();
      expect(srv.s.refreshes, "B sent no refresh").toEqual(["r0"]);
      expect(srv.s.endSessions).toEqual([]);
      expect(srv.s.reuse, "no theft recorded").toBe(0);
      expect(resp.ok, "the sign-out is not confirmed").toBe(false);
    });

    it("tab B signs out inside the window: B sends nothing, and no more than one more try ever leaves", async () => {
      keepSession(true);
      const srv = fakeServer();
      srv.s.fates = ["lost", "ok"];
      at(srv, 1_000_000);
      const a = bootTab();
      const b = bootTab();
      await a.sync();
      at(srv, 1_010_000);
      await b.client.logout();
      expect(srv.s.refreshes, "B sent no refresh").toEqual(["r0"]);
      // A's next request (App would have signed A out with B's sign-out; the transport alone is driven here).
      at(srv, 1_020_000);
      await a.sync();
      expect(srv.s.refreshes.length, "at most two sends in all, inside the window").toBeLessThanOrEqual(2);
      expect(srv.s.refreshAt.every((t) => t - 1_000_000 <= 50_000)).toBe(true);
      expect(srv.s.reuse).toBe(0);
    });

    it("after no try was left in tab A, tab B's sign-out sends nothing that spends the token", async () => {
      keepSession(true);
      const srv = fakeServer();
      srv.s.fates = ["lost"];
      at(srv, 1_000_000);
      const a = bootTab();
      const b = bootTab();
      await a.sync();
      at(srv, 1_070_000);
      await a.sync();
      expect(a.ends).toEqual(["not_confirmed"]);
      at(srv, 1_200_000);
      await b.client.logout();
      expect(srv.s.refreshes).toEqual(["r0"]);
      expect(srv.s.endSessions).toEqual([]);
      expect(srv.s.reuse).toBe(0);
    });

    it("tab B's end of the session (an unlock's way out) while the mark stands, and after no try is left: nothing is sent", async () => {
      keepSession(true);
      const srv = fakeServer();
      srv.s.fates = ["lost"];
      at(srv, 1_000_000);
      const a = bootTab();
      const b = bootTab();
      const c = bootTab();
      await a.sync();
      at(srv, 1_030_000);
      expect(await b.client.endSession(), "not confirmed").toBe(false);
      at(srv, 1_070_000);
      await a.sync();
      expect(await c.client.endSession(), "not confirmed").toBe(false);
      expect(srv.s.endSessions).toEqual([]);
      expect(srv.s.refreshes).toEqual(["r0"]);
      expect(srv.s.reuse).toBe(0);
    });
  });

  describe("(b) the request that set the refresh off is not handed back as the session's end", () => {
    it.each<Fate>(["page502", "page401html", "cut", "nullBody", "unreadable200", "lost"])(
      "a first try answered by %s: the events connection and the unlock card end nothing; the mark stands",
      async (fate) => {
        keepSession(true);
        const srv = fakeServer();
        srv.s.fates = [fate];
        at(srv, 1_000_000);
        const a = bootTab();
        const revoked: string[] = [];
        const close = a.client.events(
          () => {},
          (kind) => revoked.push(kind),
        );
        await until(() => srv.s.refreshes.length > 0);
        await until(() => revoked.length + a.ends.length > 0); // whatever the answer sets off, given its turns
        close();
        expect(srv.s.refreshes).toEqual(["r0"]);
        expect(revoked, "the events connection raised no end").toEqual([]);
        expect(a.ends, "no end raised").toEqual([]);
        expect(loadSession()?.tokens, "the pair stays, marked").toMatchObject({ refreshToken: "r0", refreshOutAt: 1_000_000 });
        // The unlock card's request, inside the window: the one more try goes (answered by the server's grace where it
        // took the token) and the unlock goes on; at no step is the session said as expired.
        srv.s.fates = [];
        at(srv, 1_010_000);
        const r = await unlockSession({ wire: new WireApi(a.client), pins: await pinnedStore(), origin: ORIGIN, userId: U, password: "pw", knownIdentityPub: null });
        expect(r.kind).not.toBe("expired");
        expect(a.ends).toEqual([]);
        expect(srv.s.reuse).toBe(0);
      },
    );

    it("a first try answered by a gateway's page: the request fails as one with no answer, never as the server's 401", async () => {
      keepSession(true);
      const srv = fakeServer();
      srv.s.fates = ["page502"];
      at(srv, 1_000_000);
      const a = bootTab();
      const e = await a.sync();
      expect(e instanceof ApiError && e.status === 401, "not the request's own 401").toBe(false);
      expect(e).toBeInstanceOf(TypeError);
    });

    it("no try left: exactly one end is raised, the browser's own; the events connection and the unlock card raise none", async () => {
      keepSession(true);
      const srv = fakeServer();
      srv.s.fates = ["lost"];
      at(srv, 1_000_000);
      const a = bootTab();
      await a.sync();
      at(srv, 1_070_000);
      const revoked: string[] = [];
      const close = a.client.events(
        () => {},
        (kind) => revoked.push(kind),
      );
      await until(() => a.ends.length > 0);
      await until(() => revoked.length > 0); // a second end, if any, given its turns
      close();
      expect(a.ends).toEqual(["not_confirmed"]);
      expect(revoked, "no second end from the events connection").toEqual([]);

      // The unlock card of a second tab that still held the pair: its request meets the kept token.
      const b = makeClient({ baseUrl: "http://server", userId: U, personalVaultId: "", email: "ola@example.org", tokens: { accessToken: "a-old", refreshToken: "r0" } }, "http://server");
      const bEnds: string[] = [];
      b.onRefreshRefused = (why) => bEnds.push(why);
      const r = await unlockSession({ wire: new WireApi(b), pins: await pinnedStore(), origin: ORIGIN, userId: U, password: "pw", knownIdentityPub: null });
      expect(r.kind, "the card raises no end of its own").not.toBe("expired");
      expect(bEnds.length, "one end in that tab, the browser's own").toBeLessThanOrEqual(1);
      expect(bEnds.every((x) => x === "not_confirmed")).toBe(true);
      expect(srv.s.refreshes).toEqual(["r0"]);
      expect(srv.s.reuse).toBe(0);
    });
  });

  describe("(c) a mark that could not be written is not a mark: nothing is sent", () => {
    it.each([
      ["without the offline copy: the tab's slot refuses the write", false],
      ["with the offline copy: the session every tab shares refuses the write", true],
    ] as const)("%s; a reload later sends the token once, as a first try, and no theft is recorded", async (_name, offlineCopy) => {
      keepSession(offlineCopy);
      const srv = fakeServer();
      srv.s.fates = ["lost"];
      const store = offlineCopy ? st.local : st.tab;
      const key = offlineCopy ? SESSION_STORAGE_KEY : TAB_TOKENS_KEY;
      const write = store.setItem.bind(store);
      let full = true;
      store.setItem = (k: string, v: string) => {
        if (full && k === key && v.includes("refreshOutAt")) throw new DOMException("the quota is full", "QuotaExceededError");
        write(k, v);
      };
      at(srv, 1_000_000);
      const a = bootTab();
      const e = await a.sync();
      expect(srv.s.refreshes, "nothing sent without the mark").toEqual([]);
      expect(e instanceof ApiError && e.status === 401, "not said as the session's end").toBe(false);
      expect(answerLimitText(e), "the person is told the renewal could not be saved").not.toBeNull();
      expect(a.ends).toEqual([]);
      // Storage works again; the tab is reloaded past what would have been the window.
      full = false;
      srv.s.fates = [];
      at(srv, 1_070_000);
      const reloaded = bootTab();
      expect(await reloaded.sync()).toBe("synced");
      expect(srv.s.refreshes, "the token left once").toEqual(["r0"]);
      expect(srv.s.reuse, "no theft recorded").toBe(0);
    });
  });
});
