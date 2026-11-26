import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient, type Tokens } from "../api/client";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { SESSION_STORAGE_KEY, type Session } from "../ui/session";
import { abandonSignIn, adoptSharedPair, beginSignIn, storageVerdict } from "../ui/tabsession";
import { signIn } from "../vault/onboardflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 12: a sign-in ends only the pair its OWN call was given, also where the tabs share a pair. The second reading's
 * sequence against the real server: the offline copy is on, so every tab of the browser rides one kept session. Tab 1 is
 * on the unlock card's "Sign in"; while its sign-in is under way tab 2 refreshes the shared pair, and tab 1's `storage`
 * listener adopts the rotated pair (App's `adopt` verdict). Tab 1's sign-in then fails. Before, its way out ended any pair
 * that differed from the one held when it began, which was the shared session every tab now rides; now it ends nothing,
 * and the shared session stays live at the server.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

/** Records every request as "METHOD /path" and lets [handle] answer it (or fall through to the real server with null). */
async function through<T>(handle: (path: string) => Promise<Response> | null, run: () => Promise<T>): Promise<{ value: T; sent: string[] }> {
  const sent: string[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    sent.push(`${(init?.method ?? "GET").toUpperCase()} ${url.pathname}`);
    return handle(url.pathname) ?? real(input, init);
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}

describe.skipIf(skip !== null)("journey 12: a sign-in ends only the pair its own call was given, where the tabs share one", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  /** Whether the session [h] holds is live at the server, read with its own tokens (a rotation is kept in [h]). */
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

  it("another tab rotates the shared pair during a sign-in, this tab adopts it, the sign-in fails: the shared session is not ended; a later sign-in's own refused session is ended alone", async () => {
    const EMAIL = "jo@example.org";
    const PW = "jo's own Horse 4 battery";
    const tab1 = new Browser(inst, "Firefox at Jo's");
    const up = await tab1.signUp(EMAIL, PW);
    const shared = tab1.client.getTokens()!;
    // Tab 2 of the same browser rides the same kept pair (the offline copy is on).
    const tab2 = { pair: { ...shared } as Tokens | null };

    // Tab 1: the unlock card's "Sign in" begins.
    const flow = beginSignIn(tab1.client);

    // Meanwhile tab 2's refresh rotates the shared pair at the real server; tab 1's listener reads the change.
    await inst.advance(3_700_000); // past the access token's hour
    expect(await live(tab2), "tab 2's call, after its refresh").toBe(true);
    const rotated = tab2.pair!;
    expect(rotated.refreshToken).not.toBe(shared.refreshToken);
    const meta = (tokens: Tokens): Session => ({ baseUrl: inst.origin, userId: up.session.userId, personalVaultId: "p", email: EMAIL, tokens });
    const verdict = storageVerdict(
      { key: SESSION_STORAGE_KEY, oldValue: JSON.stringify(meta(shared)), newValue: JSON.stringify(meta(rotated)) },
      { activeUserId: up.session.userId, have: tab1.client.getTokens(), after: meta(rotated), keptAcrossLock: () => true },
    );
    expect(verdict.kind).toBe("adopt");
    if (verdict.kind !== "adopt") return;
    adoptSharedPair(tab1.client, verdict.tokens, verdict.revokeOwnFirst);
    expect(tab1.client.getTokens()?.refreshToken).toBe(rotated.refreshToken);

    // Tab 1's sign-in fails before login answers; the screen takes its way out.
    const { value: failed, sent } = await through(
      (path) => (path.endsWith("/auth/prelogin") || path.endsWith("/auth/login") ? Promise.reject(new TypeError("Failed to fetch")) : null),
      async () => {
        const r = await signIn({ wire: tab1.wire, pins: tab1.pins, origin: tab1.origin, email: EMAIL, password: PW, deviceName: tab1.deviceName, session: null, knownIdentityPub: null, installed: flow.installed });
        return { kind: r.kind, ended: abandonSignIn(tab1.client, flow) };
      },
    );
    expect(failed.kind).toBe("failed");
    expect(failed.ended, "nothing this sign-in's own call was given").toBeNull();
    expect(sent.some((p) => p.endsWith("/auth/end-session") || p.endsWith("/auth/logout")), sent.join(", ")).toBe(false);
    expect(tab1.client.getTokens()?.refreshToken, "tab 1 still rides the shared pair").toBe(rotated.refreshToken);
    expect(await live(tab2), "the shared kept session, as tab 2 holds it").toBe(true);

    // A second "Sign in" whose own login answers and which the screen then refuses: that session alone is ended.
    const again = beginSignIn(tab1.client);
    const { value: given, sent: sent2 } = await through(
      () => null,
      async () => {
        const r = await signIn({ wire: tab1.wire, pins: tab1.pins, origin: tab1.origin, email: EMAIL, password: PW, deviceName: tab1.deviceName, session: null, knownIdentityPub: null, installed: again.installed });
        const pair = tab1.client.getTokens();
        return { kind: r.kind, pair, ended: await abandonSignIn(tab1.client, again) };
      },
    );
    expect(given.kind).toBe("opened");
    expect(given.ended).toBe(true);
    expect(sent2.filter((p) => p.endsWith("/auth/end-session"))).toHaveLength(1);
    expect(sent2.some((p) => p.endsWith("/auth/logout"))).toBe(false);
    expect(await live({ pair: given.pair }), "the refused session").toBe(false);
    expect(await live(tab2), "the shared kept session").toBe(true);
  }, 300_000);
});
