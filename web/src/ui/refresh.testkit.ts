import { vi } from "vitest";
import type { Tokens } from "../api/client";
import { WireApi } from "../api/wireclient";
import { loadSession, makeClient, saveSession } from "./session";

/**
 * The server's rule for a refresh token, as tests of the web client's renewal keep it (spec 03 §2, established against
 * the real server: AuthRoutes, Sessions): a token is taken once and answered with a new pair; for sixty seconds from that
 * moment (inclusive) a repeat of the replaced token gets the same pair again, while that pair has authenticated nothing;
 * any other repeat is read as a stolen token: every session of the browser's row ends and a theft is recorded.
 * `end-session` with a replaced token is that theft at once. The logout ends every session of the row.
 */
export const U = "11111111-1111-4111-8111-111111111111";
export const OTHER = "22222222-2222-4222-8222-222222222222";
export const EMAIL = "ola@example.org";
export const BASE = "http://server";

const SYNC_BODY = { rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] };
const json = (status: number, body: unknown): Response => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
export const envelope = (status: number, error: string): Response => json(status, { error, message: error });

/**
 * What happens to a refresh on its way. `ok`; `lost` (the server took it, the answer never came); `page502`,
 * `page401html` (a gateway's page; the server took the token behind the 502, never saw it behind the 401); `cut` (the
 * server took it, the body broke off); `nullBody` (the server took it, a `200` whose body is `null`); `unreadable200`;
 * `env503` (the server's own envelope: nothing taken); `hang` (taken; no answer before the tab went away).
 */
export type Fate = "ok" | "lost" | "page502" | "page401html" | "cut" | "nullBody" | "unreadable200" | "env503" | "hang";

export function fakeServer(first: Tokens = { accessToken: "a0", refreshToken: "r0" }) {
  const s = {
    now: 1_000_000,
    current: { ...first } as Tokens,
    n: 0,
    grace: new Map<string, { pair: Tokens; at: number }>(),
    used: new Set<string>(),
    /** Every refresh token that left the browser, in order, with the server's clock. */
    refreshes: [] as string[],
    refreshAt: [] as number[],
    /** Every token sent to `end-session`. */
    endSessions: [] as string[],
    /** Every logout's bearer. */
    logouts: [] as string[],
    graceAnswers: 0,
    /** Repeats read as theft: every session of the row ended. */
    reuse: 0,
    revoked: false,
    fates: [] as Fate[],
  };
  const theft = () => {
    s.reuse++;
    s.revoked = true;
  };
  const refresh = (token: string): Response => {
    if (s.revoked) return envelope(401, "refresh_reuse");
    if (token === s.current.refreshToken) {
      s.n++;
      const pair = { accessToken: `a${s.n}`, refreshToken: `r${s.n}` };
      s.grace.set(token, { pair, at: s.now });
      s.current = pair;
      return json(200, pair);
    }
    const g = s.grace.get(token);
    if (g && s.now - g.at <= 60_000 && !s.used.has(g.pair.accessToken) && g.pair.refreshToken === s.current.refreshToken) {
      s.graceAnswers++;
      return json(200, g.pair);
    }
    theft();
    return envelope(401, "refresh_reuse");
  };
  const fetchFn = vi.fn(async (url: string | URL, init?: RequestInit): Promise<Response> => {
    const u = String(url);
    const auth = ((init?.headers as Record<string, string> | undefined) ?? {})["Authorization"] ?? "";
    if (u.endsWith("/api/v1/auth/refresh")) {
      const token = (JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken;
      s.refreshes.push(token);
      s.refreshAt.push(s.now);
      const fate = s.fates.shift() ?? "ok";
      if (fate === "page401html") return new Response("<html><body>401 Authorization Required</body></html>", { status: 401 });
      if (fate === "env503") return envelope(503, "unavailable");
      const answer = refresh(token);
      if (fate === "lost") throw new TypeError("Failed to fetch");
      if (fate === "hang") return new Promise<Response>(() => {});
      if (fate === "page502") return new Response("<html><body>502 Bad Gateway</body></html>", { status: 502 });
      if (fate === "unreadable200") return new Response("<html><body>Welcome</body></html>", { status: 200 });
      if (fate === "nullBody") return new Response("null", { status: 200 });
      if (fate === "cut") {
        const half = new TextEncoder().encode('{"accessToken":"a');
        return new Response(
          new ReadableStream<Uint8Array>({
            start(c) {
              c.enqueue(half);
              c.error(new TypeError("network error"));
            },
          }),
          { status: 200 },
        );
      }
      return answer;
    }
    if (u.endsWith("/api/v1/auth/end-session")) {
      const token = (JSON.parse(String(init?.body)) as { refreshToken: string }).refreshToken;
      s.endSessions.push(token);
      if (s.grace.has(token)) {
        theft();
        return envelope(401, "refresh_reuse");
      }
      return new Response("ok", { status: 200 });
    }
    if (u.endsWith("/api/v1/auth/logout")) {
      s.logouts.push(auth);
      if (!s.revoked && auth === `Bearer ${s.current.accessToken}`) {
        s.revoked = true;
        return new Response(null, { status: 204 });
      }
      return envelope(401, "unauthorized");
    }
    if (!s.revoked && auth === `Bearer ${s.current.accessToken}`) {
      s.used.add(s.current.accessToken);
      return u.endsWith("/api/v1/events/ticket") ? json(200, { ticket: "t" }) : json(200, SYNC_BODY);
    }
    return envelope(401, "unauthorized");
  });
  vi.stubGlobal("fetch", fetchFn);
  return { s, fetchFn };
}

/** Moves the wall clock of the browser and of the server to [ms]. */
export function at(srv: ReturnType<typeof fakeServer>, ms: number): void {
  srv.s.now = ms;
  vi.spyOn(Date, "now").mockReturnValue(ms);
}

export const flush = async (): Promise<void> => {
  for (let i = 0; i < 60; i++) await Promise.resolve();
};

/** Lets the page's work run (turns of the event loop, no timer) until [done] holds, or a bounded number of turns. */
export async function until(done: () => boolean): Promise<void> {
  for (let i = 0; i < 400 && !done(); i++) await new Promise<void>((r) => setImmediate(r));
}

/** The session of U kept in this browser, with the pair [pair]; the offline copy on or off for U. */
export function keepSession(offlineCopy: boolean, pair: Tokens = { accessToken: "a-old", refreshToken: "r0" }): void {
  if (offlineCopy) localStorage.setItem(`andvari.cacheOptIn.${U}`, "1");
  saveSession({ baseUrl: BASE, userId: U, personalVaultId: "", email: EMAIL, tokens: pair });
}

/** A tab of this browser, booted as App boots it: App's own client over what the browser keeps, with its end counted. */
export function bootTab() {
  const client = makeClient(loadSession(), BASE);
  const ends: string[] = [];
  client.onRefreshRefused = (why) => ends.push(why);
  return {
    client,
    ends,
    /** A request that needs the session: the vault's sync. Resolves to "synced" or to what it failed with. */
    sync: (): Promise<unknown> => new WireApi(client).sync(0).then(() => "synced", (e: unknown) => e),
  };
}
