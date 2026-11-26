import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "../api/client";
import { DeviceIdentity, memoryStorage } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { browserStorages } from "../ui/forget-earlier.testkit";
import { loadSession, makeClient, saveSession, tokensKeptAcrossLock, unconfirmedRefresh } from "../ui/session";
import { beginSignIn, replacedSession } from "../ui/tabsession";
import { signIn } from "../vault/onboardflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 24: a refresh whose answer never came, against the real server (spec 03 §2, the refresh's grace). The tab's
 * transport is App's own (ui/session.ts makeClient), over this browser's storage. First the answer is lost and the one
 * more try, inside the window, gets the server's grace: the same pair, no theft. Then the answer is lost again and the
 * tab's clock passes the fifty seconds: nothing is sent, the session ends in the browser as not confirmed, its token is
 * kept, and the next sign-in in the tab names it. The server ends that chain as replaced; no reuse is recorded anywhere.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

/** Lets [handle] answer a request (or fall through to the real server with null); records every request sent. */
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

describe.skipIf(skip !== null)("journey 24: a refresh whose answer never came", () => {
  let inst: TestInstance;
  let st: ReturnType<typeof browserStorages>;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => {
    st = browserStorages();
  });
  afterEach(() => {
    st.restore();
    vi.restoreAllMocks();
  });

  /** Whether the session whose pair is [pair] is live at the server. */
  const live = async (pair: Tokens | null): Promise<boolean> => {
    if (pair === null) return false;
    const h = { pair };
    const w = new WireApi(new ApiClient(inst.origin, { ...pair }, (t) => t && (h.pair = t)));
    try {
      await w.accountKeys();
      return true;
    } catch {
      return false;
    }
  };

  /** The tab's refresh, with its answer taken by the server and lost on its way back; the pair the server answered. */
  const loseTheAnswer = async (tab: Browser): Promise<Tokens> => {
    let rotated: Tokens | null = null;
    const { sent } = await through(
      (path, real) =>
        path.endsWith("/auth/refresh")
          ? real().then(async (resp) => {
              rotated = (await resp.json()) as Tokens;
              throw new TypeError("Failed to fetch");
            })
          : null,
      () => tab.wire.accountKeys().catch(() => null),
    );
    expect(sent.filter((s) => s.path.endsWith("/auth/refresh")), "one refresh sent").toHaveLength(1);
    expect(rotated, "the server took the token").not.toBeNull();
    return rotated!;
  };

  it("the one more try inside the window gets the server's grace; past it nothing is sent, the browser ends the session itself, and the next sign-in names its token", async () => {
    const EMAIL = "ines@example.org";
    const PW = "ines's own Kettle 7 harbour";
    // App's own transport, over this browser's storage (no offline copy: the tab holds its own pair).
    const storage = memoryStorage();
    const tab = new Browser(inst, "Firefox at Ines's", storage, makeClient(null, inst.origin));
    await tab.signUp(EMAIL, PW);
    const userId = new DeviceIdentity(storage).userIdFor(EMAIL)!;
    tab.client.boundUserId = userId;
    saveSession({ baseUrl: inst.origin, userId, personalVaultId: "", email: EMAIL, tokens: tab.client.getTokens() });
    const ends: string[] = [];
    tab.client.onRefreshRefused = (why) => ends.push(why);

    // 1. The access token expires; the refresh is taken and its answer lost. The mark stands, with the pair.
    inst.advance(3_700_000);
    const first = tab.client.getTokens()!;
    await loseTheAnswer(tab);
    expect(loadSession()?.tokens).toMatchObject({ refreshToken: first.refreshToken, refreshOutAt: expect.any(Number) });
    // The next request, inside the window: the one more try, answered by the server's grace with the same pair.
    const { value: again, sent: againSent } = await through(() => null, () => tab.wire.accountKeys().then(() => "opened", () => "failed"));
    expect(again).toBe("opened");
    expect(againSent.filter((s) => s.path.endsWith("/auth/refresh"))).toHaveLength(1);
    expect(tab.client.getTokens()?.refreshToken).not.toBe(first.refreshToken);
    expect(tab.client.getTokens()?.refreshOutAt, "the server's answer cleared the mark").toBeUndefined();
    expect(auditRows(inst, "refresh_grace", userId), "the server's grace answered it").toHaveLength(1);
    expect(auditRows(inst, "refresh_reuse", userId)).toEqual([]);

    // 2. The next expiry: taken and lost again; then the tab's clock passes the fifty seconds.
    inst.advance(3_700_000);
    const second = tab.client.getTokens()!;
    const orphan = await loseTheAnswer(tab);
    const outAt = tab.client.getTokens()!.refreshOutAt!;
    inst.advance(120_000);
    const clock = vi.spyOn(Date, "now").mockReturnValue(outAt + 70_000);
    const { sent: lateSent } = await through(() => null, () => tab.wire.accountKeys().catch(() => null));
    clock.mockRestore();
    expect(lateSent.some((s) => s.path.endsWith("/auth/refresh") || s.path.endsWith("/auth/end-session") || s.path.endsWith("/auth/logout")), "nothing that spends the token").toBe(false);
    expect(ends).toEqual(["not_confirmed"]);
    expect(tab.client.getTokens()).toBeNull();
    expect(unconfirmedRefresh(userId), "kept for the next sign-in").toEqual({ userId, refreshToken: second.refreshToken });
    expect(tokensKeptAcrossLock(userId)).toBe(false);
    expect(await live(orphan), "the session the server made is live, and no one holds it").toBe(true);

    // 3. The sign-in in the same tab names it; the server ends that chain as replaced.
    const replaces = replacedSession(tab.client, tokensKeptAcrossLock);
    expect(replaces).toEqual([{ userId, refreshToken: second.refreshToken }]);
    const flow = beginSignIn(tab.client);
    const { value: r, sent } = await through(
      () => null,
      () => signIn({ wire: tab.wire, pins: tab.pins, origin: tab.origin, email: EMAIL, password: PW, deviceName: tab.deviceName, session: null, knownIdentityPub: null, installed: flow.installed, replaces }),
    );
    expect(r.kind).toBe("opened");
    const login = sent.find((s) => s.path.endsWith("/auth/login"))!;
    expect((JSON.parse(login.body) as { replacesRefreshToken?: string }).replacesRefreshToken).toBe(second.refreshToken);
    expect(sent.some((s) => s.path.endsWith("/auth/refresh") || s.path.endsWith("/auth/end-session"))).toBe(false);
    tab.client.boundUserId = userId;
    saveSession({ baseUrl: inst.origin, userId, personalVaultId: "", email: EMAIL, tokens: tab.client.getTokens() });
    expect(unconfirmedRefresh(userId), "its one use is had").toBeNull();
    expect(await live(tab.client.getTokens()), "the new session").toBe(true);
    expect(await live(orphan), "the chain the lost answer made, ended by the server").toBe(false);
    expect(auditRows(inst, "session_end", userId).map((row) => row.meta)).toContain("sign_in_named_replaced");
    expect(auditRows(inst, "refresh_reuse", userId), "no theft recorded at any step").toEqual([]);
  }, 300_000);
});
