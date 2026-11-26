import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { toB64 } from "../crypto/bytes";
import { initSodium } from "../crypto/sodium";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import { abandonSignIn, beginSignIn } from "../ui/tabsession";
import { commitKitRecovery, parseKitInput, verifyKit } from "../vault/kitflow";
import { completeSignup, startSignup } from "../vault/onboardflow";
import { runPow } from "../vault/pow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 10: a write the server stores and whose answer this browser then refuses. A kit recovery's commit and a
 * registration, each passed on to the real server (which stores it) and answered to the browser with something it must
 * refuse. The browser hands on the kit the server now holds (the screens show it before anything is wiped), ends the
 * answered session by its own token (never the logout), and keeps nothing; the server's side is then checked directly:
 * the old kit is dead, the kit handed on and the new password work, the account exists.
 *
 * The web client's flow modules over real HTTP against the real server in its test mode; the lie is told by a fetch
 * that forwards every request and replaces one success answer.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

/**
 * Every request goes to the real server; for the route ending in [path], its real success answer is handed to [lie] and
 * the browser gets what that returns. Every request is recorded as "METHOD /path".
 */
async function answerLies<T>(path: string, lie: (answer: Record<string, unknown>) => unknown, run: () => Promise<T>): Promise<{ value: T; sent: string[] }> {
  const sent: string[] = [];
  const real = globalThis.fetch;
  const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    sent.push(`${(init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase()} ${url.pathname}`);
    const resp = await real(input, init);
    if (!url.pathname.endsWith(path)) return resp;
    if (!resp.ok) throw new Error(`the server did not store it: ${resp.status}`);
    const answer = (await resp.json()) as Record<string, unknown>;
    return new Response(JSON.stringify(lie(answer)), { status: 200, headers: { "content-type": "application/json" } });
  });
  try {
    return { value: await run(), sent };
  } finally {
    spy.mockRestore();
  }
}

describe.skipIf(skip !== null)("journey 10: a write the server stored and this browser refused keeps what the person needs", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => inst.advance(61_000));

  /** The verdict on a kit from a browser that holds nothing of the account. */
  const kitAnswers = async (secret: Uint8Array, email: string): Promise<string> => {
    await inst.advance(61_000);
    const probe = new Browser(inst);
    await probe.settle();
    const input = parseKitInput(kitDisplayForm(secret), email);
    if (input.kind !== "typed") throw new Error(input.kind);
    const r = await verifyKit({ wire: probe.wire, pins: probe.pins, origin: probe.origin, input, knownIdentityPub: () => null });
    if (r.kind === "verified") r.verified.uvk.fill(0);
    return r.kind === "refused" ? `refused:${r.error.code}` : r.kind;
  };

  it("a kit recovery the server stored and whose answer this browser refuses hands on the kit the server now holds; the old kit is dead, the session is ended alone", async () => {
    const EMAIL = "gil@example.org";
    const PG = "gil's first Horse 5 battery";
    const PG2 = "gil's second Horse 6 battery";
    const PG3 = "gil's third Horse 7 battery";
    const gil = new Browser(inst, "Firefox at Gil's");
    let kit = (await gil.signUp(EMAIL, PG, "Gil")).kit.slice();
    // Two lies after the commit is stored: an answer naming another account (not one only this server could give for
    // this recovery, so whether it was stored cannot be told: "unknown", the kit handed on all the same), then one in
    // a shape this browser cannot read that names the account (stored).
    const lies: [string, string | null, string, (answer: Record<string, unknown>) => unknown][] = [
      ["another account's id", null, PG2, (a) => ({ ...a, userId: "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b" })],
      ["an answer that cannot be read, naming the account", "bad_response", PG3, (a) => ({ userId: a.userId, nothing: "here" })],
    ];
    for (const [what, reason, password, lie] of lies) {
      await inst.advance(61_000);
      const fresh = new Browser(inst, "A borrowed laptop");
      await fresh.settle();
      const input = parseKitInput(kitDisplayForm(kit), EMAIL);
      if (input.kind !== "typed") throw new Error(input.kind);
      const v = await verifyKit({ wire: fresh.wire, pins: fresh.pins, origin: fresh.origin, input, knownIdentityPub: () => null });
      if (v.kind !== "verified") throw new Error(`${what}: ${v.kind}`);
      const policy = await fresh.wire.clientPolicy();
      const flow = beginSignIn(fresh.client); // as the screen's commit does: a way out ends only the pair this recovery was given
      const { value: c, sent } = await answerLies("/recovery/self/commit", lie, () =>
        commitKitRecovery({ wire: fresh.wire, pins: fresh.pins, origin: fresh.origin, verified: v.verified, newPassword: password, kdfParams: policy.kdfParams, deviceName: fresh.deviceName, installed: flow.installed }),
      );
      if (reason === null) {
        expect(c.kind, what).toBe("unknown");
        if (c.kind !== "unknown") return;
        expect(c.why, what).toBe("unreadable");
      } else {
        expect(c.kind, what).toBe("stored_unchecked");
        if (c.kind !== "stored_unchecked") return;
        expect(c.reason, what).toBe(reason);
      }
      expect([...v.verified.uvk].every((x) => x === 0), `${what}: the UVK is wiped`).toBe(true);
      expect(sent.filter((p) => p.endsWith("/recovery/self/commit")), what).toHaveLength(1);
      // The screen's way out: the answered session (when its pair could be read) is ended by its own token, never the logout.
      const held = fresh.client.getTokens() !== null;
      expect(held, `${what}: a pair is held only from an answer that could be read`).toBe(reason === null);
      const { value: ended, sent: ending } = await answerLies("/none", (a) => a, async () => abandonSignIn(fresh.client, flow));
      expect(await ended, what).toBe(held ? true : null);
      expect(ending.filter((p) => p.endsWith("/auth/end-session")), what).toHaveLength(held ? 1 : 0);
      expect(ending.some((p) => p.endsWith("/auth/logout")), what).toBe(false);
      expect(fresh.client.getTokens(), what).toBeNull();
      // The server holds the new password and the kit handed on; the kit typed here is dead.
      expect(await kitAnswers(kit, EMAIL), `${what}: the old kit`).toBe("invalid_credentials");
      expect(await kitAnswers(c.kit.secret, EMAIL), `${what}: the kit handed on`).toBe("verified");
      expect(await new Browser(inst).signInKind(EMAIL, password), `${what}: the new password`).toBe("opened");
      kit = c.kit.secret.slice();
    }
  }, 300_000);

  it("a registration the server stored and whose answer this browser refuses hands on the account's kit; the account exists", async () => {
    const EMAIL = "hal@example.org";
    const PH = "hal's own Horse 8 battery";
    const hal = new Browser(inst, "Chrome at Hal's");
    const pin = await hal.settle();
    const policy = await hal.wire.clientPolicy();
    const seen = inst.mailCount(EMAIL, "signup_code");
    const started = await startSignup({ wire: hal.wire, pins: hal.pins, origin: hal.origin, email: EMAIL, ageConfirmed: true, powBits: policy.signup.powBits, pow: (e, bits) => runPow(e, bits, hal.now()) });
    expect(started.kind).toBe("sent");
    const ticket = await hal.wire.signupVerify(EMAIL, await inst.awaitCode(EMAIL, "signup_code", seen));
    const salt = toB64(new Uint8Array(16).fill(9));
    const flow = beginSignIn(hal.client); // as the screen's registration does
    const { value: r } = await answerLies("/auth/register", (a) => ({ ...a, accountKeys: { ...(a.accountKeys as object), kdfSalt: salt } }), () =>
      completeSignup({ wire: hal.wire, pins: hal.pins, origin: hal.origin, pin, policy, email: EMAIL, displayName: "Hal", password: PH, signupTicket: ticket.signupTicket, ageConfirmed: true, deviceName: hal.deviceName, nowMs: hal.now(), installed: flow.installed }),
    );
    expect(r.kind).toBe("stored_unchecked");
    if (r.kind !== "stored_unchecked") return;
    expect(r.reason).toBe("bad_response");
    expect(hal.client.getTokens(), "the answered pair is held until the screen ends it").not.toBeNull();
    const { value: ended, sent: ending } = await answerLies("/none", (a) => a, async () => abandonSignIn(hal.client, flow));
    expect(await ended).toBe(true);
    expect(ending.filter((p) => p.endsWith("/auth/end-session"))).toHaveLength(1);
    expect(ending.some((p) => p.endsWith("/auth/logout"))).toBe(false);
    expect(hal.client.getTokens()).toBeNull();
    // The account exists with this address and password, and the kit handed on is the account's.
    expect(await new Browser(inst).signInKind(EMAIL, PH)).toBe("opened");
    expect(await kitAnswers(r.kit.secret, EMAIL)).toBe("verified");
  }, 300_000);
});
