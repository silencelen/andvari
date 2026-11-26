import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "../api/client";
import { DeviceIdentity } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { beginSignIn, replacedSession } from "../ui/tabsession";
import { signIn } from "../vault/onboardflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 16: a sign-in names the session it replaces (spec 03 §2 `replacesRefreshToken`). The sequence against the real
 * server: a tab keeps a session whose refresh was answered and the answer lost (so the tab holds a token the server has
 * already replaced); the unlock card's "Sign in" in the same tab names the token the tab holds. The new session lives;
 * the old one (its chain as the server rotated it) is ended by the server and recorded as replaced; no reuse is
 * recorded; another tab's session on the same browser row lives, and so does a phone's.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

/** Lets [handle] answer a request (or fall through to the real server with null). */
async function through<T>(handle: (path: string, real: () => Promise<Response>) => Promise<Response> | null, run: () => Promise<T>): Promise<{ value: T; sent: { path: string; body: string }[] }> {
  const sent: { path: string; body: string }[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    sent.push({ path: `${(init?.method ?? "GET").toUpperCase()} ${url.pathname}`, body: typeof init?.body === "string" ? init.body : "" });
    return handle(url.pathname, () => real(input, init)) ?? real(input, init);
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}

/** The server's audit rows of [type] for [userId], read from its own database (test mode). */
function auditRows(inst: TestInstance, type: string, userId: string): { meta: string | null }[] {
  const env = readFileSync(inst.envFile, "utf-8");
  const m = /^ANDVARI_DB=(.*)$/m.exec(env);
  const raw = (m?.[1] ?? "andvari.db").trim().replace(/^"|"$/g, "");
  const path = isAbsolute(raw) ? raw : [join(dirname(inst.envFile), raw), join(inst.dir, raw)].find((p) => existsSync(p))!;
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare("SELECT meta FROM audit WHERE type = ? AND userId = ? ORDER BY id").all(type, userId) as { meta: string | null }[];
  } finally {
    db.close();
  }
}

describe.skipIf(skip !== null)("journey 16: a sign-in names the session it replaces", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  /** Whether the session [h] holds is live at the server (as journey 11 looks: its own tokens, the rotation kept in [h]). */
  const live = async (h: { pair: Tokens | null }): Promise<boolean> => {
    if (h.pair === null) return false;
    const w = new WireApi(new ApiClient(inst.origin, { ...h.pair }, (t) => (h.pair = t)));
    try {
      await w.accountKeys();
      return true;
    } catch {
      return false;
    }
  };

  it("a lost refresh answer, then the unlock card's Sign in names the token the tab holds: the old session is ended as replaced, no reuse, the other tab lives", async () => {
    const EMAIL = "june@example.org";
    const PW = "june's own Horse 9 battery";
    const tab1 = new Browser(inst, "Firefox at June's");
    await tab1.signUp(EMAIL, PW);
    // The tab's client bound to the account of the session it keeps, as App binds it (ui/session.ts makeClient).
    const userId = new DeviceIdentity(tab1.storage).userIdFor(EMAIL)!;
    expect(userId).toMatch(/^[0-9a-f-]{36}$/);
    tab1.client.boundUserId = userId;
    // A second tab of the same browser (the same device storage: the same row) and a phone elsewhere.
    const tab2 = new Browser(inst, "Firefox at June's", tab1.storage);
    expect((await tab2.signIn(EMAIL, PW)).kind).toBe("opened");
    const phone = new Browser(inst, "June's phone");
    expect((await phone.signIn(EMAIL, PW)).kind).toBe("opened");
    const s2 = { pair: tab2.client.getTokens() };
    const s3 = { pair: phone.client.getTokens() };

    // The kept session's refresh: answered by the server, the answer lost on its way to tab 1.
    inst.advance(3_700_000);
    const spent = tab1.client.getTokens()!;
    let rotated: Tokens | null = null;
    await through(
      (path, real) =>
        path.endsWith("/auth/refresh")
          ? real().then(async (resp) => {
              rotated = (await resp.json()) as Tokens;
              throw new TypeError("Failed to fetch");
            })
          : null,
      () => tab1.wire.accountKeys().catch(() => null),
    );
    expect(rotated, "the server rotated the kept session").not.toBeNull();
    const s1b = { pair: rotated as Tokens | null };
    expect(tab1.client.getTokens()?.refreshToken).toBe(spent.refreshToken);
    // Past the refresh's grace, so that only the name can end the old chain.
    inst.advance(120_000);
    expect(await live(s1b), "the old session, as the server rotated it, is live before the sign-in").toBe(true);

    // What this tab names: its own pair (no offline copy: each tab holds its own), by the token it holds.
    const replaces = replacedSession(tab1.client, () => false);
    expect(replaces).toEqual({ userId, refreshToken: spent.refreshToken });
    // Another tab's pair is never named, nor a shared pair, nor a pair bound to no account.
    expect(replacedSession(tab1.client, () => true)).toBeNull();
    const flow = beginSignIn(tab1.client);
    expect(replacedSession(tab1.client, () => false), "after the flow rebinds the client, nothing is named").toBeNull();
    const { value: r, sent } = await through(
      () => null,
      () => signIn({ wire: tab1.wire, pins: tab1.pins, origin: tab1.origin, email: EMAIL, password: PW, deviceName: tab1.deviceName, session: null, knownIdentityPub: null, installed: flow.installed, replaces }),
    );
    expect(r.kind).toBe("opened");
    const login = sent.find((s) => s.path.endsWith("/auth/login"))!;
    expect((JSON.parse(login.body) as { replacesRefreshToken?: string }).replacesRefreshToken).toBe(spent.refreshToken);
    expect(sent.some((s) => s.path.endsWith("/auth/end-session") || s.path.endsWith("/auth/logout")), "nothing else is sent for the replaced session").toBe(false);

    const fresh = { pair: tab1.client.getTokens() };
    expect(fresh.pair?.refreshToken).not.toBe(spent.refreshToken);
    expect(await live(fresh), "the new session").toBe(true);
    expect(await live(s1b), "the replaced session, ended by the server").toBe(false);
    expect(await live(s2), "tab 2's session on the same browser row").toBe(true);
    expect(await live(s3), "the phone's session").toBe(true);
    expect(auditRows(inst, "session_end", userId).map((row) => row.meta)).toContain("sign_in_named_replaced");
    expect(auditRows(inst, "refresh_reuse", userId), "no reuse is recorded").toEqual([]);
  }, 300_000);
});
