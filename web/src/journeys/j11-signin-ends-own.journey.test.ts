import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "../api/client";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { abandonSignIn, beginSignIn } from "../ui/tabsession";
import { signIn } from "../vault/onboardflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 11: a sign-in that fails or is refused ends only a session it was itself given. The independent check's
 * sequence against the real server: a tab keeps a session whose refresh was answered and the answer lost (so the tab
 * holds a token the server has already replaced), the unlock card's "Sign in" is used, and the network fails. Ending
 * the pair the tab held then would send the replaced token, which the server reads as reuse and answers by ending every
 * session of the browser's device row. Afterwards the kept session and another tab's session on the same row are both
 * live. Then the same sign-in is given a session and refused: that session alone is ended, by its own token.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

/** Records every request as "METHOD /path" and lets [handle] answer it (or fall through to the real server with null). */
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

describe.skipIf(skip !== null)("journey 11: a sign-in that fails ends only a session it was given", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  /**
   * Whether the session [h] holds is live at the server: its own access token reads the account's keys, after a refresh
   * with its own refresh token on a 401. The rotated pair is kept in [h], so a later look never sends a spent token (the
   * reuse signal would end the whole row and spoil every later look). A refresh of an ended session is refused as
   * revoked, which ends nothing else.
   */
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

  it("a lost refresh answer, the unlock card's Sign in, the network fails: the kept session and another tab's session on the same row stay live; a refused session the sign-in got is ended alone", async () => {
    const EMAIL = "ivy@example.org";
    const PW = "ivy's own Horse 9 battery";
    const tab1 = new Browser(inst, "Firefox at Ivy's");
    await tab1.signUp(EMAIL, PW);
    // A second tab of the same browser (the same device storage, so the same device row) signs in; a phone elsewhere too.
    const tab2 = new Browser(inst, "Firefox at Ivy's", tab1.storage);
    expect((await tab2.signIn(EMAIL, PW)).kind).toBe("opened");
    const phone = new Browser(inst, "Ivy's phone");
    expect((await phone.signIn(EMAIL, PW)).kind).toBe("opened");
    const s2 = { pair: tab2.client.getTokens() };
    const s3 = { pair: phone.client.getTokens() };
    // From here the two tabs' sessions are looked at only through these holders (tab 2's own client never refreshes).

    // The kept session's refresh: answered by the server, the answer lost on its way to tab 1.
    inst.advance(3_700_000); // past the access token's hour
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
    expect(tab1.client.getTokens()?.refreshToken, "tab 1 still holds the token the server replaced").toBe(spent.refreshToken);

    // The unlock card's "Sign in" (Welcome's SignIn with the email fixed): the network fails before login answers.
    const flow1 = beginSignIn(tab1.client);
    const { value: failed, sent } = await through(
      (path) => (path.includes("/auth/") ? Promise.reject(new TypeError("Failed to fetch")) : null),
      async () => {
        const r = await signIn({ wire: tab1.wire, pins: tab1.pins, origin: tab1.origin, email: EMAIL, password: PW, deviceName: tab1.deviceName, session: null, knownIdentityPub: null, installed: flow1.installed });
        // The screen's way out of a failed sign-in.
        const ended = abandonSignIn(tab1.client, flow1);
        return { kind: r.kind, ended };
      },
    );
    expect(failed.kind).toBe("failed");
    expect(failed.ended, "nothing this sign-in was given, so nothing is ended").toBeNull();
    expect(sent.some((p) => p.endsWith("/auth/end-session") || p.endsWith("/auth/logout")), sent.join(", ")).toBe(false);
    expect(await live(s1b), "the kept session (as the server rotated it)").toBe(true);
    expect(await live(s2), "tab 2's session on the same device row").toBe(true);
    expect(await live(s3), "the phone's session").toBe(true);

    // The same "Sign in" given a session that the screen then refuses: that session alone is ended, by its own token.
    const flow2 = beginSignIn(tab1.client);
    const { value: given, sent: sent2 } = await through(
      () => null,
      async () => {
        const r = await signIn({ wire: tab1.wire, pins: tab1.pins, origin: tab1.origin, email: EMAIL, password: PW, deviceName: tab1.deviceName, session: null, knownIdentityPub: null, installed: flow2.installed });
        const pair = tab1.client.getTokens();
        const ended = await abandonSignIn(tab1.client, flow2);
        return { kind: r.kind, pair, ended };
      },
    );
    expect(given.kind).toBe("opened");
    expect(given.pair?.refreshToken).not.toBe(spent.refreshToken);
    expect(given.ended).toBe(true);
    expect(sent2.filter((p) => p.endsWith("/auth/end-session"))).toHaveLength(1);
    expect(sent2.some((p) => p.endsWith("/auth/logout"))).toBe(false);
    expect(tab1.client.getTokens()).toBeNull();
    expect(await live({ pair: given.pair }), "the refused session").toBe(false);
    expect(await live(s1b), "the kept session").toBe(true);
    expect(await live(s2), "tab 2's session").toBe(true);
    expect(await live(s3), "the phone's session").toBe(true);
  }, 300_000);
});
