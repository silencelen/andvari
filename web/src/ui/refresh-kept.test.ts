import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { WireApi } from "../api/wireclient";
import { browserStorages } from "./forget-earlier.testkit";
import { at, BASE, bootTab, EMAIL, envelope, fakeServer, keepSession, OTHER, U, until } from "./refresh.testkit";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { clearSession, dropKeptAtSignOut, keepUnconfirmedRefresh, loadSession, makeClient, saveSession, tokensKeptAcrossLock, UNCONFIRMED_REFRESH_KEY, unconfirmedRefresh } from "./session";
import { endedUnconfirmed, endSessionByServer } from "./sessionend";
import { abandonSignIn, beginUnlock, lockTabTokens, replacedSession } from "./tabsession";

/**
 * What the browser keeps of a session whose refresh got no answer, and when: the token kept for the next sign-in's name
 * where a lock or a sign-out meets a standing mark, one per account; the tab's own one more try inside its window; an
 * answer nobody adopted read as a confirmation only where it is the server's own refusal; and the end said as this
 * browser's own where the kept token could not be written.
 */
describe("a refresh whose answer never came: what is kept, and the one more try", () => {
  let st: ReturnType<typeof browserStorages>;
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

  it("a per-tab lock that meets a standing mark sends nothing and keeps the token for the next sign-in's name", async () => {
    keepSession(false);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    await a.sync();
    const { revoked } = await lockTabTokens(a.client, { flush: null, flushWaitMs: 0, revoke: true });
    expect(await revoked, "not confirmed").toBe(false);
    expect(srv.s.endSessions).toEqual([]);
    expect(unconfirmedRefresh(U)).toEqual({ userId: U, refreshToken: "r0" });
    // The next sign-in in this tab names it.
    const fresh = makeClient(null, BASE);
    expect(JSON.stringify(replacedSession(fresh, tokensKeptAcrossLock))).toContain('"refreshToken":"r0"');
  });

  it("a sign-out that meets a standing mark sends nothing that spends the token and keeps it, past the session's removal", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    await a.sync();
    at(srv, 1_020_000);
    const resp = await a.client.logout();
    expect(resp.ok).toBe(false);
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(unconfirmedRefresh(U), "the logout itself keeps it").toEqual({ userId: U, refreshToken: "r0" });
  });

  it("a person's own sign-out removes that account's kept token and says so; another account's kept token stays", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    await a.sync();
    keepUnconfirmedRefresh(OTHER, "rO");
    at(srv, 1_020_000);
    expect((await a.client.logout()).ok).toBe(false);
    // App's sign-out of the person's own (kind "user"), in its order: the revocation, then this, then the session goes.
    expect(dropKeptAtSignOut(U), "one was kept: the line says the end was not confirmed").toBe(true);
    clearSession();
    a.client.setTokens(null);
    expect(unconfirmedRefresh(U), "nothing of that session stays in the browser").toBeNull();
    expect(unconfirmedRefresh(OTHER), "another account's kept token stays").toEqual({ userId: OTHER, refreshToken: "rO" });
    expect(dropKeptAtSignOut(U), "nothing kept: nothing to say").toBe(false);
    expect(srv.s.refreshes, "nothing was spent").toEqual(["r0"]);
  });

  it("App's own sign-out drops the kept token of the account it signs out and says the line; another kind of end does not", () => {
    const app = readFileSync(fileURLToPath(new URL("./App.tsx", import.meta.url)), "utf-8");
    const body = app.slice(app.indexOf("const signOut = useCallback("), app.indexOf("// Account deletion (spec 03 §13 client duty"));
    expect(body).toContain('const keptDropped = kind === "user" && dropKeptAtSignOut(uid);');
    expect(body.indexOf("dropKeptAtSignOut(uid)")).toBeGreaterThan(body.indexOf("await revokeForSignOut("));
    expect(body).toMatch(/keptDropped \? \[lostCount, SIGN_OUT_NOT_CONFIRMED\]/);
  });

  it("a lock that overtakes a refresh whose answer is a gateway's page keeps the spent token for the next sign-in's name", async () => {
    keepSession(false);
    const srv = fakeServer();
    srv.s.fates = ["page502"]; // the server takes r0 and rotates; a gateway's page comes back in its place
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
    const { revoked } = await lockTabTokens(a.client, { flush: null, flushWaitMs: 0, revoke: true });
    release();
    expect(await revoked, "not confirmed").toBe(false);
    await syncing;
    expect(srv.s.endSessions, "nothing sent").toEqual([]);
    expect(unconfirmedRefresh(U)).toEqual({ userId: U, refreshToken: "r0" });
    expect(srv.s.reuse).toBe(0);
  });

  it("an unlock's way out keeps the token of a refresh that got no answer for that account, before the binding resets", async () => {
    keepSession(false);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    await a.sync();
    const ended = await abandonSignIn(a.client, beginUnlock());
    expect(ended, "not confirmed").toBe(false);
    expect(srv.s.endSessions, "nothing sent").toEqual([]);
    expect(unconfirmedRefresh(U)).toEqual({ userId: U, refreshToken: "r0" });
    expect(a.client.getTokens()).toBeNull();
  });

  it("a kept token is held per account: another account's sign-in keeps it, and of five accounts the oldest goes", () => {
    keepUnconfirmedRefresh(U, "rU");
    saveSession({ baseUrl: BASE, userId: OTHER, personalVaultId: "", email: "other@example.org", tokens: { accessToken: "aO", refreshToken: "rO" } });
    expect(unconfirmedRefresh(U), "another account's sign-in keeps it").toEqual({ userId: U, refreshToken: "rU" });
    const ids = ["33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666"];
    ids.forEach((id, i) => keepUnconfirmedRefresh(id, `r${i}`));
    expect(unconfirmedRefresh(U), "the oldest of five goes").toBeNull();
    ids.forEach((id, i) => expect(unconfirmedRefresh(id)).toEqual({ userId: id, refreshToken: `r${i}` }));
    // The sign-in of an account names only its own kept token.
    saveSession({ baseUrl: BASE, userId: ids[1]!, personalVaultId: "", email: EMAIL, tokens: { accessToken: "a9", refreshToken: "r9" } });
    expect(unconfirmedRefresh(ids[1]!)).toBeNull();
    expect(unconfirmedRefresh(ids[0]!)).not.toBeNull();
    expect(sessionStorage.getItem(UNCONFIRMED_REFRESH_KEY)).not.toBeNull();
  });

  it("the tab makes the one more try by itself inside the window, with no request to set it off, and the session is renewed", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost", "ok"];
    at(srv, 1_000_000);
    const a = bootTab();
    await a.sync();
    expect(srv.s.refreshes).toEqual(["r0"]);
    at(srv, 1_025_000);
    await vi.advanceTimersByTimeAsync(25_000);
    await until(() => srv.s.refreshes.length > 1 && a.client.getTokens()?.refreshToken === "r1");
    expect(srv.s.refreshes).toEqual(["r0", "r0"]);
    expect(srv.s.refreshAt[1]! - srv.s.refreshAt[0]!, "inside the window").toBeLessThanOrEqual(50_000);
    expect(srv.s.graceAnswers).toBe(1);
    expect(a.client.getTokens()).toEqual({ accessToken: "a1", refreshToken: "r1" });
    expect(loadSession()?.tokens, "the server's answer cleared the mark").toEqual({ accessToken: "a1", refreshToken: "r1" });
    expect(a.ends).toEqual([]);
  });

  it.each([
    ["a gateway's 401 page", () => new Response("<html><body>401 Authorization Required</body></html>", { status: 401 }), false],
    ["the server's own refusal", () => envelope(401, "refresh_reuse"), true],
  ] as const)("a lock that overtook a refresh on its way: %s is a confirmation only where it is the server's", async (_name, answer, confirmed) => {
    let release: ((r: Response) => void) | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL) => {
        if (String(url).endsWith("/api/v1/auth/refresh")) return new Promise<Response>((r) => (release = r));
        return envelope(401, "unauthorized");
      }),
    );
    const c = new ApiClient(BASE, { accessToken: "a-old", refreshToken: "r0" });
    void new WireApi(c).sync(0).catch(() => null);
    await until(() => release !== null);
    const ended = c.endSession();
    c.setTokens(null);
    release!(answer());
    expect(await ended).toBe(confirmed);
  });

  it("where the kept token could not be written, the record of the session still says it ended here unconfirmed", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    const write = st.local.setItem.bind(st.local);
    st.local.setItem = (k: string, v: string) => {
      if (k === UNCONFIRMED_REFRESH_KEY) throw new DOMException("the quota is full", "QuotaExceededError");
      write(k, v);
    };
    at(srv, 1_000_000);
    const a = bootTab();
    await a.sync();
    at(srv, 1_070_000);
    await a.sync();
    expect(a.ends).toEqual(["not_confirmed"]);
    expect(st.local.map.has(UNCONFIRMED_REFRESH_KEY), "the kept token was not written").toBe(false);
    // App ends the session as this browser's own end (endByServer with kind "unconfirmed").
    const end = endSessionByServer(a.client, "unconfirmed");
    expect(end.kind).toBe("kept");
    expect(loadSession()?.endedUnconfirmed, "said in the record itself, read by every tab and after a reload").toBe(true);
    expect(endedUnconfirmed(U)).toBe(true);
    expect(srv.s.refreshes).toEqual(["r0"]);
  });
});
