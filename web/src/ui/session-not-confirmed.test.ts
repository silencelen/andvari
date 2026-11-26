import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WireApi } from "../api/wireclient";
import { SESSION_ENDED_HELD, SESSION_NOT_CONFIRMED } from "./copy";
import { browserStorages } from "./forget-earlier.testkit";
import { dropUnconfirmedRefresh, loadSession, makeClient, saveSession, TAB_TOKENS_KEY, UNCONFIRMED_REFRESH_KEY, unconfirmedRefresh, wipeLocalAccountState } from "./session";
import { endedUnconfirmed, sessionEndLine } from "./sessionend";
import { replacedSession, signInForm } from "./tabsession";

/**
 * The web app's side of a refresh whose answer never came (api/client.ts holds the rule): where the mark and the kept
 * token live in the browser, what removes each, what the next sign-in names, and what the screens say.
 */
const U = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const EMAIL = "ola@example.org";
const read = (src: string) => readFileSync(fileURLToPath(new URL(src, import.meta.url)), "utf8");

/** A server whose refresh answers are lost (it took the token), and whose data routes refuse the stale access token. */
function lostAnswers() {
  const refreshes: string[] = [];
  const sent: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL, init?: RequestInit) => {
      const u = String(url);
      sent.push(u);
      if (u.endsWith("/api/v1/auth/refresh")) {
        refreshes.push((JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken);
        throw new TypeError("Failed to fetch");
      }
      return new Response(JSON.stringify({ error: "unauthorized", message: "expired" }), { status: 401 });
    }),
  );
  return { refreshes, sent };
}

describe("a session this browser could not confirm", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeEach(() => {
    st = browserStorages();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] }); // the tab's own one more try runs no timer here
  });
  afterEach(() => {
    vi.useRealTimers();
    st.restore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  /** The tab's client over a kept session of U, as App builds it at boot. */
  const boot = (offlineCopy: boolean) => {
    if (offlineCopy) localStorage.setItem(`andvari.cacheOptIn.${U}`, "1");
    saveSession({ baseUrl: "http://server", userId: U, personalVaultId: "", email: EMAIL, tokens: { accessToken: "a-old", refreshToken: "r0" } });
    const client = makeClient(loadSession(), "http://server");
    const ends: string[] = [];
    client.onRefreshRefused = (why) => ends.push(why);
    return { client, ends, sync: () => new WireApi(client).sync(0).catch(() => null) };
  };

  it.each([
    ["without the offline copy: in the tab's slot, and the kept token in the tab's sessionStorage", false],
    ["with the offline copy: in the session every tab shares, and the kept token in localStorage", true],
  ] as const)("%s", async (_name, offlineCopy) => {
    const net = lostAnswers();
    const now = vi.spyOn(Date, "now").mockReturnValue(5_000_000);
    const t = boot(offlineCopy);
    await t.sync();
    // The mark, with the pair, where the pair lives: it survives the document (a reload reads it back).
    expect(loadSession()?.tokens).toMatchObject({ refreshToken: "r0", refreshOutAt: 5_000_000 });
    const pairHome = offlineCopy ? st.local.map.get("andvari.session")! : st.tab.map.get(TAB_TOKENS_KEY)!;
    expect(pairHome).toContain('"refreshOutAt":5000000');
    // A reload past the window: a new client over what the browser kept sends nothing and ends the session here.
    now.mockReturnValue(5_070_000);
    const reloaded = makeClient(loadSession(), "http://server");
    const ends: string[] = [];
    reloaded.onRefreshRefused = (why) => ends.push(why);
    await new WireApi(reloaded).sync(0).catch(() => null);
    expect(net.refreshes).toEqual(["r0"]);
    expect(ends).toEqual(["not_confirmed"]);
    expect(loadSession()?.tokens ?? null).toBeNull();
    // The token, kept for one use, where the pair was: never in localStorage for a browser without the offline copy.
    expect(unconfirmedRefresh(U)).toEqual({ userId: U, refreshToken: "r0" });
    expect((offlineCopy ? st.local : st.tab).map.has(UNCONFIRMED_REFRESH_KEY)).toBe(true);
    expect((offlineCopy ? st.tab : st.local).map.has(UNCONFIRMED_REFRESH_KEY)).toBe(false);
    expect(endedUnconfirmed(U)).toBe(true);
    expect(endedUnconfirmed(OTHER)).toBe(false);
    // Nothing that spends the token goes afterwards: not a refresh, not an end of the session.
    await new WireApi(reloaded).sync(0).catch(() => null);
    expect(net.refreshes).toEqual(["r0"]);
    expect(net.sent.some((u) => u.endsWith("/auth/end-session"))).toBe(false);
  });

  it("the next sign-in names the kept token as the session it replaces, at every submit, and a new session taken drops it", () => {
    sessionStorage.setItem(UNCONFIRMED_REFRESH_KEY, JSON.stringify([{ userId: U, refreshToken: "r0" }]));
    const client = makeClient(null, "http://server");
    expect(replacedSession(client, () => false)).toEqual([{ userId: U, refreshToken: "r0" }]);
    const form = signInForm(client, () => false);
    expect(form.submit().replaces).toEqual([{ userId: U, refreshToken: "r0" }]);
    expect(form.submit().replaces, "a second submit (the two-step code asked) names it too").toEqual([{ userId: U, refreshToken: "r0" }]);
    // The sign-in's session is kept: the token has had its one use.
    saveSession({ baseUrl: "http://server", userId: U, personalVaultId: "", email: EMAIL, tokens: { accessToken: "a9", refreshToken: "r9" } });
    expect(unconfirmedRefresh(U)).toBeNull();
  });

  it("it goes at a forgetting of that account (not another's)", async () => {
    localStorage.setItem(UNCONFIRMED_REFRESH_KEY, JSON.stringify([{ userId: U, refreshToken: "r0" }]));
    dropUnconfirmedRefresh();
    expect(unconfirmedRefresh(U)).toBeNull();
    sessionStorage.setItem(UNCONFIRMED_REFRESH_KEY, JSON.stringify([{ userId: U, refreshToken: "r0" }]));
    await wipeLocalAccountState(OTHER);
    expect(unconfirmedRefresh(U), "another account's forgetting keeps it").not.toBeNull();
    await wipeLocalAccountState(U, EMAIL, "unconfirmed");
    expect(unconfirmedRefresh(U)).toBeNull();
    expect([...st.local.map.keys(), ...st.tab.map.keys()].filter((k) => k === UNCONFIRMED_REFRESH_KEY)).toEqual([]);
  });

  it("the screens say the browser's own end, never the server's, nor a revocation", () => {
    expect(sessionEndLine("unconfirmed")).toBe(SESSION_NOT_CONFIRMED);
    expect(sessionEndLine("expired")).not.toBe(SESSION_NOT_CONFIRMED);
    const app = read("./App.tsx");
    expect(app).toContain('onRevoked(why === "not_confirmed" ? "unconfirmed" : "expired")');
    expect(app).toContain("const line = notice ?? sessionEndLine(kind);");
    expect(app).toContain('onRevoked(endedUnconfirmed(v.meta.userId) ? "unconfirmed" : "expired")');
    expect(read("./Welcome.tsx")).toContain("{session.endedUnconfirmed === true || endedUnconfirmed(session.userId) ? SESSION_NOT_CONFIRMED : SESSION_ENDED_HELD}");
    expect(read("./Vault.tsx")).toContain("{endedUnconfirmed(account.userId) ? SESSION_NOT_CONFIRMED_COPY : SESSION_ENDED_COPY}");
    expect(SESSION_ENDED_HELD).not.toBe(SESSION_NOT_CONFIRMED);
  });
});
