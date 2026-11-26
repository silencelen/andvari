import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { SIGN_IN_ANSWER_COST_ENDED, signInAnswerRefusedText } from "../ui/copy";
import { abandonSignIn, beginSignIn } from "../ui/tabsession";
import { signIn } from "../vault/onboardflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 17: a sign-in the browser refuses after the server accepted it ends the session it was given. The sequence
 * against the real server: a browser that does not know the account signs in, the server takes the password, issues a
 * session and makes a device row, and the answer reaches the browser with a password-hashing cost it does not take (the
 * server's real answer, its cost changed on the way). The browser ends that session by its own token before it says
 * anything, and says that the server took the sign-in and the browser ended it again. A second try names the device row
 * the first one made: two tries, one row, no live session. Once the answer is the server's own again, the sign-in opens
 * on that same row.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

/** Lets [handle] answer a request (or fall through to the real server with null); records each as "METHOD /path". */
async function through<T>(handle: (path: string, real: () => Promise<Response>) => Promise<Response> | null, run: () => Promise<T>): Promise<{ value: T; sent: string[] }> {
  const sent: string[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    sent.push(`${(init?.method ?? "GET").toUpperCase()} ${url.pathname}`);
    return handle(url.pathname, () => real(input, init)) ?? real(input, init);
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}

/** Rows of [sql] read from the server's own database (test mode). */
function rows<T>(inst: TestInstance, sql: string, ...args: string[]): T[] {
  const env = readFileSync(inst.envFile, "utf-8");
  const m = /^ANDVARI_DB=(.*)$/m.exec(env);
  const raw = (m?.[1] ?? "andvari.db").trim().replace(/^"|"$/g, "");
  const path = isAbsolute(raw) ? raw : [join(dirname(inst.envFile), raw), join(inst.dir, raw)].find((p) => existsSync(p))!;
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare(sql).all(...args) as T[];
  } finally {
    db.close();
  }
}

describe.skipIf(skip !== null)("journey 17: a sign-in whose answer the browser refuses ends the session it was given", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  it("an answered cost the browser does not take: the session is ended at the server, the line says so, and two tries make one device row", async () => {
    const EMAIL = "uma@example.org";
    const PW = "uma's own Lantern 4 harbour";
    const home = new Browser(inst, "Firefox at Uma's");
    const { session } = await home.signUp(EMAIL, PW);
    const userId = session.userId;

    // Another browser, which has never seen this account: the server makes a new device row for its first sign-in.
    const other = new Browser(inst, "Chromium at the library");
    await other.settle();
    /** The server's real login answer, its cost changed on the way to a memory cost that is not a whole number of KiB. */
    const costChanged = (path: string, real: () => Promise<Response>): Promise<Response> | null =>
      path.endsWith("/auth/login")
        ? real().then(async (resp) => {
            const body = (await resp.json()) as { accountKeys: { kdfParams: { memBytes: number } } };
            body.accountKeys.kdfParams.memBytes += 1;
            return new Response(JSON.stringify(body), { status: resp.status, headers: { "Content-Type": "application/json" } });
          })
        : null;

    const tryOnce = async () => {
      const flow = beginSignIn(other.client);
      const { value, sent } = await through(costChanged, async () => {
        const r = await signIn({ wire: other.wire, pins: other.pins, origin: other.origin, email: EMAIL, password: PW, deviceName: other.deviceName, session: null, knownIdentityPub: null, installed: flow.installed });
        // The screen's way out of this result (Welcome's SignIn): the session is ended before the line is chosen.
        if (r.kind !== "answer_refused") return { kind: r.kind, line: null, ended: null };
        const ended = (await abandonSignIn(other.client, flow)) === true;
        return { kind: r.kind, reason: r.reason, ended, line: signInAnswerRefusedText(r.reason, ended) };
      });
      return { ...value, sent };
    };

    const first = await tryOnce();
    expect(first.kind).toBe("answer_refused");
    expect(first.ended, "the server confirmed the end of the session it had issued").toBe(true);
    expect(first.line).toBe(SIGN_IN_ANSWER_COST_ENDED);
    expect(first.sent.filter((p) => p.endsWith("/auth/login"))).toHaveLength(1);
    expect(first.sent.filter((p) => p.endsWith("/auth/end-session"))).toHaveLength(1);
    expect(other.client.getTokens(), "nothing of that session is kept in the tab").toBeNull();

    const second = await tryOnce();
    expect(second.kind).toBe("answer_refused");
    expect(second.ended).toBe(true);

    // At the server: the browser that refused the answers has one device row (made by the first try, named by the
    // second), and no live session; the sign-up's own row and session are untouched.
    const passwordRows = rows<{ deviceId: string }>(inst, "SELECT deviceId FROM devices WHERE userId = ? AND how = 'password'", userId);
    expect(passwordRows, "two tries, one device row").toHaveLength(1);
    const deviceId = passwordRows[0]!.deviceId;
    const sessions = rows<{ revokedAt: number | null }>(inst, "SELECT revokedAt FROM sessions WHERE userId = ? AND deviceId = ?", userId, deviceId);
    expect(sessions, "each try was issued a session").toHaveLength(2);
    expect(sessions.filter((s) => s.revokedAt === null), "none of them is live").toHaveLength(0);
    const homeLive = rows<{ n: number }>(inst, "SELECT COUNT(*) AS n FROM sessions WHERE userId = ? AND deviceId <> ? AND revokedAt IS NULL", userId, deviceId);
    expect(homeLive[0]!.n, "the sign-up's session lives").toBeGreaterThan(0);

    // With the server's own answer, the same browser signs in on that same row.
    const flow = beginSignIn(other.client);
    const opened = await signIn({ wire: other.wire, pins: other.pins, origin: other.origin, email: EMAIL, password: PW, deviceName: other.deviceName, session: null, knownIdentityPub: null, installed: flow.installed });
    expect(opened.kind).toBe("opened");
    if (opened.kind === "opened") expect(opened.session.deviceId).toBe(deviceId);
    expect(rows(inst, "SELECT deviceId FROM devices WHERE userId = ? AND how = 'password'", userId)).toHaveLength(1);
  }, 300_000);
});
