import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "./client";
import { WireApi } from "./wireclient";

/**
 * A refresh whose answer never came (spec 03 §2, the refresh's grace; the rule the shared code's session keeper has).
 * The server takes a refresh token once: it answers the new pair, and for sixty seconds from that moment it answers a
 * repeat of the replaced token with the same pair, while that pair has authenticated nothing. Any other repeat is read
 * as a stolen token: every session of the device ends and a theft is recorded. So a browser that lost the answer may try
 * once more, within fifty seconds of the first try's sending (ten seconds of margin for the road), and never again; where
 * no try is left it sends nothing and ends the session itself, keeping the token for the next sign-in to name.
 *
 * Driven against a stateful fake of that rule; the wall clock is `Date.now`, moved by the tests.
 */

const SYNC_BODY = { rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] };
const envelope = (status: number, error: string): Response =>
  new Response(JSON.stringify({ error, message: error }), { status, headers: { "Content-Type": "application/json" } });
const ok = (body: unknown): Response => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

/** The server's refresh rule, as the fake keeps it. */
function fakeServer() {
  const s = {
    now: 1_000_000,
    current: { accessToken: "a0", refreshToken: "r0" } as Tokens,
    n: 0,
    grace: new Map<string, { pair: Tokens; at: number }>(),
    used: new Set<string>(),
    /** Every refresh token that left the browser, in order (whatever answered it). */
    refreshes: [] as string[],
    /** Every token sent to end a session (`end-session`) or a logout's bearer. */
    ends: [] as string[],
    graceAnswers: 0,
    /** Reuses read as theft: every session of the device ended. */
    reuse: 0,
    revoked: false,
  };
  const consumed = (t: string) => s.grace.has(t);
  const theft = () => {
    s.reuse++;
    s.revoked = true;
  };
  const refresh = (token: string): Response => {
    if (s.revoked) return envelope(401, "session_revoked");
    if (token === s.current.refreshToken) {
      s.n++;
      const pair = { accessToken: `a${s.n}`, refreshToken: `r${s.n}` };
      s.grace.set(token, { pair, at: s.now });
      s.current = pair;
      return ok(pair);
    }
    const g = s.grace.get(token);
    if (g && s.now - g.at <= 60_000 && !s.used.has(g.pair.accessToken) && g.pair.refreshToken === s.current.refreshToken) {
      s.graceAnswers++;
      return ok(g.pair);
    }
    theft();
    return envelope(401, "refresh_reuse");
  };
  const endSession = (token: string): Response => {
    s.ends.push(token);
    if (consumed(token)) theft();
    return new Response("ok", { status: 200 });
  };
  const data = (auth: string): Response => {
    if (!s.revoked && auth === `Bearer ${s.current.accessToken}`) {
      s.used.add(s.current.accessToken);
      return ok(SYNC_BODY);
    }
    return envelope(401, "unauthorized");
  };
  return { s, refresh, endSession, data };
}

/**
 * What happens to a refresh on its way: `ok`; `lost` (the server took it, the answer never came); `page502` (the server
 * took it, a gateway answered with its own page); `unreadable200` (the server took it, a 200 whose body does not read);
 * `page401` (a gateway's 401 page, the server never saw it); `env503` (the server's own envelope, nothing taken);
 * `hang` (the server took it; the tab went away before any answer).
 */
type Fate = "ok" | "lost" | "page502" | "unreadable200" | "page401" | "env503" | "hang";

function transport(srv: ReturnType<typeof fakeServer>, fates: Fate[], onRefresh?: () => void) {
  return vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    if (u.endsWith("/api/v1/auth/refresh")) {
      onRefresh?.();
      const token = (JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken;
      srv.s.refreshes.push(token);
      const fate = fates.shift() ?? "ok";
      if (fate === "page401") return new Response("<html><body>401 Authorization Required</body></html>", { status: 401 });
      if (fate === "env503") return envelope(503, "unavailable");
      const answer = srv.refresh(token);
      if (fate === "lost") throw new TypeError("Failed to fetch");
      if (fate === "hang") return new Promise<Response>(() => {});
      if (fate === "page502") return new Response("<html><body>502 Bad Gateway</body></html>", { status: 502 });
      if (fate === "unreadable200") return new Response("<html><body>Welcome</body></html>", { status: 200 });
      return answer;
    }
    if (u.endsWith("/api/v1/auth/end-session")) return srv.endSession((JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken);
    const auth = ((init?.headers as Record<string, string> | undefined) ?? {})["Authorization"] ?? "";
    if (u.endsWith("/api/v1/auth/logout")) {
      srv.s.ends.push(auth);
      return auth === `Bearer ${srv.s.current.accessToken}` && !srv.s.revoked ? new Response(null, { status: 204 }) : envelope(401, "unauthorized");
    }
    return srv.data(auth);
  });
}

/** The pair a browser keeps (localStorage with the offline copy on, or the tab's slot): what every client of it reads. */
function keptStore(initial: Tokens) {
  // [kept]: the tokens kept from sessions that ended unconfirmed, which every tab of the browser reads.
  const box = { tokens: { ...initial } as Tokens | null, writes: [] as (Tokens | null)[], kept: [] as string[] };
  return {
    box,
    write: (t: Tokens | null) => {
      box.tokens = t === null ? null : { ...t };
      box.writes.push(box.tokens);
    },
    read: () => (box.tokens === null ? null : { ...box.tokens }),
  };
}

/** A tab's client over the browser's kept pair, as ui/session.ts makeClient wires it. */
function tab(store: ReturnType<typeof keptStore>) {
  const c = new ApiClient("http://server", store.read(), store.write, store.read);
  const ends: unknown[] = [];
  c.onRefreshRefused = (...why: unknown[]) => ends.push(why[0] ?? "refused");
  const kept: string[] = [];
  c.keepUnconfirmed = (t) => {
    kept.push(t);
    store.box.kept.push(t);
  };
  // As makeClient wires it: a kept token is never sent, by any tab of the browser.
  c.isKeptUnconfirmed = (t) => store.box.kept.includes(t);
  return { c, ends, kept, sync: () => new WireApi(c).sync(0).then(() => "synced" as const, (e: unknown) => e) };
}

/** The Web Lock every tab of one browser shares (`andvari-refresh`): one holder at a time. */
function sharedLocks() {
  let tail: Promise<unknown> = Promise.resolve();
  return {
    request: vi.fn((_name: string, _o: unknown, cb: (lock: unknown) => Promise<unknown>) => {
      const run = tail.then(() => cb({}));
      tail = run.catch(() => {});
      return run;
    }),
  };
}

const at = (srv: ReturnType<typeof fakeServer>, ms: number) => {
  srv.s.now = ms;
  vi.spyOn(Date, "now").mockReturnValue(ms);
};
const flush = async () => {
  for (let i = 0; i < 40; i++) await Promise.resolve();
};

describe("a refresh whose answer never came (web client)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("the mark that a refresh is out is written with the kept pair before the request goes", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    let seenAtSend: Tokens | null = null;
    vi.stubGlobal("fetch", transport(srv, ["lost"], () => (seenAtSend = store.read())));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(seenAtSend, "the kept pair when the refresh left").toMatchObject({ refreshToken: "r0", refreshOutAt: 1_000_000 });
    expect(store.read(), "a lost answer leaves the mark").toMatchObject({ refreshToken: "r0", refreshOutAt: 1_000_000 });
  });

  it("within fifty seconds the token is tried once more, and the server's grace answers it: no theft", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost", "ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    at(srv, 1_030_000);
    expect(await t.sync()).toBe("synced");
    expect(srv.s.refreshes).toEqual(["r0", "r0"]);
    expect(srv.s.graceAnswers).toBe(1);
    expect(srv.s.reuse).toBe(0);
    expect(store.read(), "the answer clears the mark").toEqual({ accessToken: "a1", refreshToken: "r1" });
  });

  it("past fifty seconds nothing is sent: the session ends here as not confirmed, never as the server's, and the token is kept for the next sign-in", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    at(srv, 1_070_000);
    await t.sync();
    expect(srv.s.refreshes, "nothing sent again").toEqual(["r0"]);
    expect(srv.s.reuse, "no theft recorded").toBe(0);
    expect(t.ends).toEqual(["not_confirmed"]);
    expect(t.kept, "the token, for the next sign-in's name").toEqual(["r0"]);
    expect(t.c.getTokens()).toBeNull();
    expect(store.read()).toBeNull();
  });

  it("the second try is the last: after it got no answer either, nothing more is sent, even inside the minute", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost", "lost", "ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    at(srv, 1_005_000);
    await t.sync();
    at(srv, 1_010_000);
    await t.sync();
    expect(srv.s.refreshes).toEqual(["r0", "r0"]);
    expect(t.ends).toEqual(["not_confirmed"]);
    expect(t.kept).toEqual(["r0"]);
  });

  it("a clock set back before the first try's sending leaves no try", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost", "ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    at(srv, 990_000);
    await t.sync();
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(t.ends).toEqual(["not_confirmed"]);
  });

  it("two tabs that need a refresh at the same moment send the token once: the second adopts the first's pair", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["ok"]));
    vi.stubGlobal("navigator", { locks: sharedLocks() });
    at(srv, 1_000_000);
    const a = tab(store);
    const b = tab(store);
    expect(await Promise.all([a.sync(), b.sync()])).toEqual(["synced", "synced"]);
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
  });

  it("two tabs of one kept pair: tab A's answer is lost, tab B's try is the one more, and then no tab sends it again", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost", "lost", "ok"]));
    vi.stubGlobal("navigator", { locks: sharedLocks() });
    at(srv, 1_000_000);
    const a = tab(store);
    const b = tab(store); // B read the pair before A's mark was written
    await a.sync();
    at(srv, 1_010_000);
    await b.sync();
    at(srv, 1_020_000);
    await a.sync();
    await b.sync();
    expect(srv.s.refreshes, "A's try and B's one more; nothing after").toEqual(["r0", "r0"]);
    expect(srv.s.reuse).toBe(0);
    expect([...a.ends, ...b.ends].every((e) => e === "not_confirmed")).toBe(true);
    expect(a.ends.length + b.ends.length).toBeGreaterThan(0);
  });

  it("a tab that went away while its refresh was out (closed, reloaded, asleep): the next document finds the mark", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["hang"]));
    at(srv, 1_000_000);
    const gone = tab(store);
    void gone.sync();
    await flush();
    expect(srv.s.refreshes).toEqual(["r0"]);
    // The reload: a new document, a new client over what the browser kept.
    at(srv, 1_070_000);
    const next = tab(store);
    await next.sync();
    expect(srv.s.refreshes, "nothing sent past the window").toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
    expect(next.ends).toEqual(["not_confirmed"]);
    expect(next.kept).toEqual(["r0"]);
  });

  it("a reload inside the window earns no extra try: the reloaded tab's try is the one more", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["hang", "lost", "ok"]));
    at(srv, 1_000_000);
    void tab(store).sync();
    await flush();
    at(srv, 1_010_000);
    const second = tab(store);
    await second.sync();
    at(srv, 1_015_000);
    const third = tab(store);
    await third.sync();
    expect(srv.s.refreshes).toEqual(["r0", "r0"]);
    expect(third.ends).toEqual(["not_confirmed"]);
  });

  it.each(["page502", "unreadable200"] as const)("an answer that is not the server's envelope (%s) leaves the mark: past the window nothing is sent", async (fate) => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, [fate]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    expect(store.read()).toMatchObject({ refreshToken: "r0", refreshOutAt: 1_000_000 });
    at(srv, 1_070_000);
    await t.sync();
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
    expect(t.ends).toEqual(["not_confirmed"]);
  });

  it("a gateway's 401 page is not the server ending the session: the pair stays, and the one more try goes", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["page401", "ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    expect(t.ends, "not said as the server's end").toEqual([]);
    expect(t.c.getTokens()?.refreshToken).toBe("r0");
    at(srv, 1_010_000);
    expect(await t.sync()).toBe("synced");
    expect(srv.s.refreshes).toEqual(["r0", "r0"]);
  });

  it("the server's own envelope clears the mark after a first try, not after a second", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["env503", "ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    expect(store.read()?.refreshOutAt, "cleared by the server's answer").toBeUndefined();
    at(srv, 1_200_000);
    expect(await t.sync()).toBe("synced");

    const srv2 = fakeServer();
    const store2 = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv2, ["lost", "env503", "ok"]));
    at(srv2, 1_000_000);
    const t2 = tab(store2);
    await t2.sync();
    at(srv2, 1_005_000);
    await t2.sync();
    at(srv2, 1_010_000);
    await t2.sync();
    expect(srv2.s.refreshes, "the first try is still unanswered: no third").toEqual(["r0", "r0"]);
    expect(t2.ends).toEqual(["not_confirmed"]);
  });

  it("a refresh the transport's own stop refused before it left leaves the pair as it was: nothing reached the server", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    let calls = 0;
    t.c.trafficGate = () => (calls++ === 0 ? null : "stopped"); // the data request goes, the refresh is stopped
    await t.sync();
    expect(srv.s.refreshes).toEqual([]);
    expect(store.read(), "no mark: nothing left").toEqual({ accessToken: "a-old", refreshToken: "r0" });
    expect(t.c.getTokens()).toEqual({ accessToken: "a-old", refreshToken: "r0" });
  });

  it("the server's own refusal still ends the session as the server's", async () => {
    const srv = fakeServer();
    srv.s.revoked = true;
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    expect(t.ends).toEqual(["refused"]);
    expect(t.kept).toEqual([]);
  });

  it("while the mark stands, a lock's end of the session sends nothing that spends the token", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    at(srv, 1_080_000);
    expect(await t.c.endSession(), "not confirmed").toBe(false);
    expect(srv.s.ends).toEqual([]);
    expect(srv.s.reuse).toBe(0);
  });

  it("while the mark stands, a sign-out's logout never refreshes the token", async () => {
    const srv = fakeServer();
    const store = keptStore({ accessToken: "a-old", refreshToken: "r0" });
    vi.stubGlobal("fetch", transport(srv, ["lost", "ok"]));
    at(srv, 1_000_000);
    const t = tab(store);
    await t.sync();
    at(srv, 1_080_000);
    const resp = await t.c.logout();
    expect(resp.ok).toBe(false);
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
  });
});
