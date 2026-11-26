import "fake-indexeddb/auto";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { WireApi } from "../api/wireclient";
import { unlockSession } from "../vault/onboardflow";
import { browserStorages, mapStorage, ORIGIN, pinnedStore } from "./forget-earlier.testkit";
import { at, bootTab, fakeServer, keepSession, OTHER, U, until } from "./refresh.testkit";
import { clearSession, dropKeptAtSignOut, followSignOuts, keepUnconfirmedRefresh, loadSession, saveSession, type Session, tellSignedOut, UNCONFIRMED_REFRESH_KEY, unconfirmedRefresh } from "./session";
import { answerLimitText } from "./errors";
import { RENEWAL_NOT_SAVED } from "./copy";
import { abandonSignIn, beginUnlock, endedInAnotherTabEvent, endedInAnotherTabLanding, storageVerdict } from "./tabsession";

/**
 * A person's own sign-out of an account whose renewal got no answer, seen from the browser's other tabs: with the offline
 * copy on a tab sends a refresh token only while this browser's record holds that same pair; on a browser where each tab
 * holds its own session every tab drops that account's kept token; a removal that could not be written is tried once
 * more, and where the token stays the sign-out says so.
 */
describe("a sign-out in one tab, seen from the others", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    st = browserStorages();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  });
  afterEach(() => {
    vi.useRealTimers();
    st.restore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  /** App's own sign-out of U (kind "user") in tab [a], in its order: the revocation, the kept token, the session. */
  async function signOutIn(a: ReturnType<typeof bootTab>): Promise<void> {
    expect((await a.client.logout()).ok, "not confirmed").toBe(false);
    expect(dropKeptAtSignOut(U), "the token kept by that sign-out goes with it").toBe(true);
    clearSession();
    a.client.setTokens(null);
  }

  /** Two tabs over the offline copy; A's renewal loses its answer (the shared record carries the mark); the person signs out in A. */
  async function twoTabsSignedOutInA() {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    const b = bootTab(); // holds r0 in its memory, unmarked, and will not have handled the `storage` event
    await a.sync();
    at(srv, 1_020_000);
    await signOutIn(a);
    return { srv, a, b };
  }

  it("W1: with the offline copy on, a tab that has not handled another tab's sign-out sends nothing at any later time, and ends as signed out elsewhere", async () => {
    const { srv, b } = await twoTabsSignedOutInA();
    let elsewhere = 0;
    b.client.onEndedElsewhere = () => elsewhere++;
    for (const t of [1_200_000, 1_000_000 + 86_400_000]) {
      at(srv, t);
      expect(await b.sync()).not.toBe("synced");
    }
    expect(srv.s.refreshes, "only A's renewal ever left").toEqual(["r0"]);
    expect(srv.s.endSessions).toEqual([]);
    expect(srv.s.reuse, "no theft recorded").toBe(0);
    expect(b.ends, "no end of the server's nor of its own renewal").toEqual([]);
    expect(elsewhere, "one end, as signed out elsewhere").toBe(1);
    expect(b.client.getTokens()).toBeNull();
    expect(unconfirmedRefresh(U), "no record of the removed token is kept").toBeNull();
    expect(JSON.stringify([...st.local.map, ...st.tab.map]), "nothing of the token in any storage").not.toContain('"r0"');
  });

  it("W1, the same tab on its unlock card: its way out ends nothing and keeps nothing", async () => {
    const { srv, b } = await twoTabsSignedOutInA();
    at(srv, 1_200_000);
    expect(await abandonSignIn(b.client, beginUnlock()), "not confirmed").toBe(false);
    expect(srv.s.endSessions).toEqual([]);
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
    expect(unconfirmedRefresh(U)).toBeNull();
  });

  it("W1, the same tab's unlock card takes that end as what it is and says no refusal's line before the landing", async () => {
    const { srv, b } = await twoTabsSignedOutInA();
    at(srv, 1_200_000);
    let elsewhere = 0;
    b.client.onEndedElsewhere = () => elsewhere++;
    const r = await unlockSession({ wire: new WireApi(b.client), pins: await pinnedStore(), origin: ORIGIN, userId: U, password: "pw", knownIdentityPub: null });
    expect(r.kind).toBe("ended_elsewhere");
    expect(elsewhere, "the one end, raised by the transport").toBe(1);
    expect(srv.s.refreshes).toEqual(["r0"]);
    const welcome = readFileSync(fileURLToPath(new URL("./Welcome.tsx", import.meta.url)), "utf-8");
    const arm = welcome.slice(welcome.indexOf('case "ended_elsewhere":'), welcome.indexOf('case "identity_fault":', welcome.indexOf('case "ended_elsewhere":')));
    expect(arm.length).toBeGreaterThan(0);
    expect(arm).not.toMatch(/setErr|onSessionEnded/);
  });

  it("W1, the same tab's own sign-out: no refresh token leaves, and nothing is kept", async () => {
    const { srv, b } = await twoTabsSignedOutInA();
    at(srv, 1_200_000);
    expect((await b.client.logout()).ok).toBe(false);
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
    expect(unconfirmedRefresh(U)).toBeNull();
  });

  it("where the shared record holds another pair, a tab's own stale token is never sent, not even by its sign-out", async () => {
    keepSession(true);
    const srv = fakeServer();
    at(srv, 1_000_000);
    const a = bootTab();
    const b = bootTab(); // r0 in its memory
    expect(await a.sync()).toBe("synced"); // A renews: the record holds r1, and A's request used a1
    expect(loadSession()?.tokens?.refreshToken).toBe("r1");
    at(srv, 1_030_000);
    expect((await b.client.logout()).ok, "not confirmed").toBe(false);
    expect(srv.s.refreshes, "r0 left once, from A").toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
    expect(unconfirmedRefresh(U), "nothing kept").toBeNull();
  });

  it("an answer that lands after the person's own sign-out keeps nothing", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["page502"]; // the server takes r0; a gateway's page comes back in its place
    at(srv, 1_000_000);
    const base = srv.fetchFn.getMockImplementation()!;
    let release!: () => void;
    const held = new Promise<void>((r) => (release = r));
    srv.fetchFn.mockImplementation(async (url: string | URL, init?: RequestInit) => {
      const r = await base(url, init);
      if (String(url).endsWith("/api/v1/auth/refresh")) await held;
      return r;
    });
    const a = bootTab();
    const syncing = a.sync();
    await until(() => srv.s.refreshes.length === 1);
    await signOutIn(a);
    release();
    await syncing;
    await until(() => false);
    expect(unconfirmedRefresh(U), "no record of the removed token comes back").toBeNull();
    expect(srv.s.reuse).toBe(0);
  });

  it("W1b: where each tab holds its own session, a sign-out in one tab makes another tab drop that account's kept token", async () => {
    keepSession(false);
    const tabA = st.tab;
    keepUnconfirmedRefresh(U, "r0"); // tab A's own kept token, in its own sessionStorage
    keepUnconfirmedRefresh(OTHER, "rO");
    const stop = followSignOuts(); // tab A's App follows sign-outs from its start
    try {
      // Tab B, with its own sessionStorage: the person's own sign-out of U there.
      const tabB = mapStorage();
      Object.defineProperty(globalThis, "sessionStorage", { value: tabB, configurable: true });
      expect(dropKeptAtSignOut(U), "B kept nothing of its own").toBe(false);
      tellSignedOut(U);
      clearSession();
      Object.defineProperty(globalThis, "sessionStorage", { value: tabA, configurable: true });
      await until(() => !(tabA.map.get(UNCONFIRMED_REFRESH_KEY) ?? "").includes('"r0"'));
      expect(tabA.map.get(UNCONFIRMED_REFRESH_KEY) ?? "", "A's kept token of U went").not.toContain('"r0"');
      expect(unconfirmedRefresh(OTHER), "another account's kept token stays").toEqual({ userId: OTHER, refreshToken: "rO" });
    } finally {
      stop();
    }
  });

  it("W1c: a removal that could not be written is tried once more", () => {
    keepSession(true);
    keepUnconfirmedRefresh(U, "r0");
    const remove = st.local.removeItem.bind(st.local);
    let tries = 0;
    st.local.removeItem = (k: string) => {
      if (k === UNCONFIRMED_REFRESH_KEY && ++tries === 1) throw new DOMException("refused", "SecurityError");
      remove(k);
    };
    expect(dropKeptAtSignOut(U)).toBe(true);
    expect(tries).toBe(2);
    expect(unconfirmedRefresh(U), "removed at the second try").toBeNull();
  });

  it("W1c: where the token still stays, the sign-out says that this browser still holds data of that session", () => {
    keepSession(true);
    keepUnconfirmedRefresh(U, "r0");
    const refuse = (k: string) => {
      if (k === UNCONFIRMED_REFRESH_KEY) throw new DOMException("refused", "SecurityError");
    };
    const set = st.local.setItem.bind(st.local);
    const remove = st.local.removeItem.bind(st.local);
    st.local.setItem = (k: string, v: string) => (refuse(k), set(k, v));
    st.local.removeItem = (k: string) => (refuse(k), remove(k));
    expect(dropKeptAtSignOut(U)).toBe(true);
    expect(unconfirmedRefresh(U), "it stays").toEqual({ userId: U, refreshToken: "r0" });
    // App reads it back after the drop and says the line for a token that stayed.
    const app = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf-8");
    const body = app.slice(app.indexOf("const signOut = useCallback("), app.indexOf("// Account deletion (spec 03 §13 client duty"));
    expect(body).toContain("const keptStays = keptDropped && uid !== null && unconfirmedRefresh(uid) !== null;");
    expect(body).toMatch(/keptStays \? \[lostCount, SIGN_OUT_KEPT_NOT_REMOVED\]/);
    expect(body.indexOf("tellSignedOut(uid)"), "the other tabs are told").toBeGreaterThan(body.indexOf("dropKeptAtSignOut(uid)"));
    expect(body).toContain('if (kind === "user" && uid !== null) tellSignedOut(uid);');
  });

  it("a tab whose own sign-in could not write the shared record says that the session could not be saved, not that another tab signed out", async () => {
    localStorage.setItem(`andvari.cacheOptIn.${U}`, "1");
    const write = st.local.setItem.bind(st.local);
    st.local.setItem = (k: string, v: string) => {
      if (k === "andvari.session") throw new DOMException("the quota is full", "QuotaExceededError");
      write(k, v);
    };
    const srv = fakeServer();
    at(srv, 1_000_000);
    // The tab's sign-in, as Welcome makes it: the pair installed, the client bound to the account, the record written.
    const tab = bootTab();
    tab.client.boundUserId = U;
    tab.client.useSessionTokens({ accessToken: "a-old", refreshToken: "r0" });
    saveSession({ baseUrl: "http://server", userId: U, personalVaultId: "", email: "ola@example.org", tokens: { accessToken: "a-old", refreshToken: "r0" } });
    expect(loadSession(), "the record was not written").toBeNull();
    let elsewhere = 0;
    tab.client.onEndedElsewhere = () => elsewhere++;
    const e = await tab.sync();
    expect(elsewhere, "not signed out in another tab").toBe(0);
    expect(answerLimitText(e), "the line for a session that could not be saved").toBe(RENEWAL_NOT_SAVED);
    expect(srv.s.refreshes, "nothing sent").toEqual([]);
    expect(tab.client.getTokens(), "the session stays in this tab").not.toBeNull();
  });

  it("a tab whose client found the shared session gone lands as the storage event lands it", () => {
    const ctx = (after: Session | null) => ({ activeUserId: U, have: null, after, keptAcrossLock: () => true });
    // Gone, or another account's record: another tab's sign-out (nothing of this tab's to revoke: the copy is on).
    expect(storageVerdict(endedInAnotherTabEvent(null, U), ctx(null))).toEqual({ kind: "signedOutElsewhere", revokeOwn: false });
    const other: Session = { baseUrl: "", userId: OTHER, personalVaultId: "", email: "o@example.org", tokens: { accessToken: "aO", refreshToken: "rO" } };
    expect(storageVerdict(endedInAnotherTabEvent(other, U), ctx(other)).kind).toBe("signedOutElsewhere");
    // This account's record kept with no pair: the server's end, which keeps the copy.
    const held: Session = { baseUrl: "", userId: U, personalVaultId: "", email: "u@example.org", tokens: null };
    expect(storageVerdict(endedInAnotherTabEvent(held, U), ctx(held))).toEqual({ kind: "endedElsewhere", meta: held });
    const app = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf-8");
    expect(app).toContain("client.onEndedElsewhere = () => endedInAnotherTabRef.current();");
    expect(app).toContain("const stopSignOuts = followSignOuts();");
  });

  it("where the shared record holds another account, the tab that ends says that another account is signed in, not that it was signed out", () => {
    const other: Session = { baseUrl: "", userId: OTHER, personalVaultId: "", email: "o@example.org", tokens: { accessToken: "aO", refreshToken: "rO" } };
    expect(endedInAnotherTabLanding(other, U)).toEqual({ kind: "another_account" });
    // Gone, or this account's own record: the storage event's landing.
    expect(endedInAnotherTabLanding(null, U)).toEqual({ kind: "event", event: endedInAnotherTabEvent(null, U) });
    const held: Session = { ...other, userId: U, tokens: null };
    expect(endedInAnotherTabLanding(held, U)).toEqual({ kind: "event", event: endedInAnotherTabEvent(held, U) });
    const app = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf-8");
    const landing = app.slice(app.indexOf("endedInAnotherTabRef.current = () => {"), app.indexOf('window.addEventListener("storage", onStorage);'));
    expect(landing).toContain("const landing = endedInAnotherTabLanding(loadSession(), activeUserIdRef.current);");
    expect(landing).toContain('if (landing.kind === "event") return onStorage(landing.event as StorageEvent);');
    expect(landing).toContain('{ kind: "welcome", notice: ANOTHER_ACCOUNT_SIGNED_IN }');
  });
});
