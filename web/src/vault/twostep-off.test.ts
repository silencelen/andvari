import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient, ApiError, retryAfterSeconds } from "../api/client";
import { readFileSync } from "node:fs";
import { DeviceIdentity, memoryStorage } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { verifyCardChain } from "../crypto/trust/instancecard";
import { vector } from "../crypto/trust/vectors";
import { twoStepOffText, twoStepSetupText, waitText } from "../ui/reauthtext";
import { SERVER_REFUSED_PROOF, SIGNIN_BACKOFF, TOTP_OFF_DONE, TOTP_OFF_DONE_REQUIRED, TOTP_OFF_SESSION_ENDED, TOTP_OFF_UNKNOWN, TOTP_SETUP_SESSION_ENDED, TOTP_SETUP_UNKNOWN, TOTP_WRONG_CODE, TOTP_WRONG_PASSWORD } from "../ui/copy";
import { openAccount } from "./accountopen";
import { PinStore } from "./pinstore";
import { buildRegistration } from "./registration";
import { SessionWrap } from "./sessionwrap";
import { PROOF_REFUSED, type SettingsSession, setUpTwoStep, turnOffTwoStep, type TwoStepOff, type TwoStepSetup } from "./settingsflow";

/**
 * Turning two-step sign-in off (server rule of 2026-11-16, spec 03 §0.1 row 16): the request carries the password proof
 * beside the code. The password is proven on this device first, so a wrong one is said here and nothing is sent; every
 * answer of the server then says what it is.
 *
 * The fake below plays the server's route in its own order (the server's TotpNeedsPasswordTest and TotpCodeBackoffTest
 * pin the same): the session; the route's per-minute bucket (5); not enrolled; the proof (missing, then its back-off,
 * then wrong); the codes' back-off; the code; `ok`. It is reached through the real ApiClient and WireApi over a stubbed
 * `fetch`, so the body sent and the `Retry-After` read are the ones the browser would send and read.
 */
const rec = vector("recovery.json");
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery";
const NOW = 1_763_164_800_000;
const RIGHT = "246810";
const frames = rec.cardChains["rotated-once"].frames as string[];
let ORIGIN = "";

const reply = (status: number, body: unknown, headers: Record<string, string> = {}): Response =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { "Content-Type": typeof body === "string" ? "text/plain" : "application/json", ...headers },
  });

/** The server's `POST /account/totp/disable`, with the two back-offs' curve (5 free, then 2^(n-5) s, capped at 900 s). */
class TotpServer {
  now = NOW;
  enrolled = true;
  sessionLive = true;
  /** Answer every request with this status instead (a 5xx, or 0 for no answer at all). */
  down: number | null = null;
  authKey = "";
  minute: number[] = [];
  proofFails = 0;
  proofLockUntil = 0;
  codeFails = 0;
  codeLockUntil = 0;
  /** Every request that reached the server: its path and body. */
  seen: { path: string; body: unknown }[] = [];
  mails = 0;

  private static lock(fails: number, now: number): number {
    return fails < 5 ? 0 : now + Math.min(2 ** (fails - 5), 900) * 1000;
  }

  handle(url: string, init: RequestInit): Response {
    const path = new URL(url).pathname;
    const body = typeof init.body === "string" ? (JSON.parse(init.body) as unknown) : null;
    this.seen.push({ path, body });
    if (this.down === 0) throw new TypeError("Failed to fetch");
    if (this.down !== null) return reply(this.down, "<html>bad gateway</html>");
    if (path === "/api/v1/auth/refresh") return reply(401, { error: "invalid_refresh", message: "no" });
    if (path === "/api/v1/account/totp/setup") return this.setup(body);
    if (path !== "/api/v1/account/totp/disable") return reply(404, { error: "not_found", message: "no" });
    if (!this.sessionLive) return reply(401, { error: "unauthorized", message: "no" });
    const window = Math.floor(this.now / 60_000) * 60_000;
    this.minute = this.minute.filter((t) => t >= window);
    if (this.minute.length >= 5) return reply(429, { error: "rate_limited", message: "slow down" }, { "Retry-After": String(Math.ceil((window + 60_000 - this.now) / 1000)) });
    this.minute.push(this.now);
    const b = body as { code?: unknown; currentAuthKey?: unknown } | null;
    if (b === null || typeof b.code !== "string") return reply(400, { error: "bad_request", message: "no" });
    if (!this.enrolled) return reply(400, { error: "totp_not_enrolled", message: "no" });
    if (typeof b.currentAuthKey !== "string") return reply(403, { error: "reauth_required", message: "no" });
    if (this.now < this.proofLockUntil) return reply(429, { error: "rate_limited", message: "slow down" }, { "Retry-After": "60" });
    if (b.currentAuthKey !== this.authKey) {
      this.proofLockUntil = TotpServer.lock(++this.proofFails, this.now);
      return reply(403, { error: "reauth_failed", message: "no" });
    }
    this.proofFails = 0;
    if (this.now < this.codeLockUntil) return reply(429, { error: "rate_limited", message: "slow down" }, { "Retry-After": "60" });
    if (b.code !== RIGHT) {
      this.codeLockUntil = TotpServer.lock(++this.codeFails, this.now);
      return reply(400, { error: "bad_totp_code", message: "no" });
    }
    this.codeFails = 0;
    this.enrolled = false;
    this.mails++;
    return reply(200, "ok");
  }

  setupMinute: number[] = [];
  /** A secret made pending by a setup (the confirm step would make it the factor). */
  pendingSecret: string | null = null;

  /**
   * The server's `POST /account/totp/setup` for an account with no factor yet, by the rule of 2026-11-17: the proof is
   * asked at every setup (no exemption for a fresh session). The session, its own per-minute bucket (5), the proof
   * (missing, its back-off, wrong), then a new pending secret.
   */
  private setup(body: unknown): Response {
    if (!this.sessionLive) return reply(401, { error: "unauthorized", message: "no" });
    const window = Math.floor(this.now / 60_000) * 60_000;
    this.setupMinute = this.setupMinute.filter((t) => t >= window);
    if (this.setupMinute.length >= 5) return reply(429, { error: "rate_limited", message: "slow down" }, { "Retry-After": String(Math.ceil((window + 60_000 - this.now) / 1000)) });
    this.setupMinute.push(this.now);
    const b = body as { currentAuthKey?: unknown } | null;
    if (b === null || typeof b.currentAuthKey !== "string") return reply(403, { error: "reauth_required", message: "no" });
    if (this.now < this.proofLockUntil) return reply(429, { error: "rate_limited", message: "slow down" }, { "Retry-After": "60" });
    if (b.currentAuthKey !== this.authKey) {
      this.proofLockUntil = TotpServer.lock(++this.proofFails, this.now);
      return reply(403, { error: "reauth_failed", message: "no" });
    }
    this.proofFails = 0;
    this.pendingSecret = "JBSWY3DPEHPK3PXP";
    return reply(200, { secretBase32: this.pendingSecret, otpauthUri: `otpauth://totp/andvari:${EMAIL}?secret=${this.pendingSecret}&issuer=andvari` });
  }
}

async function setup(): Promise<{ server: TotpServer; s: SettingsSession }> {
  const storage = memoryStorage();
  const pins = new PinStore(storage, async () => ({ cards: frames, rotations: [rec.rotationFrames["A-to-B"]] }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  pins.confirmTrustGate(g.ticket);
  const pin = pins.pinFor(ORIGIN)!;
  const reg = await buildRegistration({
    email: EMAIL, displayName: "Alice", password: PASSWORD, kdfParams: KDF, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: NOW,
  });
  const r = reg.request;
  const keys = { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  const o = openAccount(reg.userId, reg.uvk.slice(), keys, pin.instanceId, null);
  if (o.kind !== "opened") throw new Error(o.reason);
  const server = new TotpServer();
  server.authKey = r.authKey;
  vi.stubGlobal("fetch", vi.fn(async (url: string | URL, init?: RequestInit) => server.handle(String(url), init ?? {})));
  const wire = new WireApi(new ApiClient("http://server.test", { accessToken: "acc", refreshToken: "ref" }), new DeviceIdentity(memoryStorage()));
  const s: SettingsSession = { wire, pins, origin: ORIGIN, account: EMAIL, opened: o.account, wrap: new SessionWrap({ kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk }) };
  return { server, s };
}

const text = (r: TwoStepOff, required = false) => twoStepOffText(r, required).text;

describe("turning two-step sign-in off asks for the master password", () => {
  beforeAll(async () => {
    await initSodium();
    ORIGIN = verifyCardChain(frames.map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
  });
  afterEach(() => vi.unstubAllGlobals());

  it("a wrong master password is said here and nothing is sent", async () => {
    const { server, s } = await setup();
    const r = await turnOffTwoStep(s, RIGHT, "not the password");
    expect(r).toEqual({ kind: "wrong_password" });
    expect(server.seen).toEqual([]);
    expect(text(r)).toBe(TOTP_WRONG_PASSWORD);
    expect(server.enrolled).toBe(true);
  }, 120_000);

  it("the right password sends the code with the proof, once; a wrong code is 'wrong code', the right one turns it off", async () => {
    const { server, s } = await setup();
    const wrong = await turnOffTwoStep(s, "111111", PASSWORD);
    expect(wrong).toEqual({ kind: "wrong_code" });
    expect(text(wrong)).toBe(TOTP_WRONG_CODE);
    // The old code sent `{code}` alone, which the server now answers `403 reauth_required` whatever the code.
    expect(server.seen).toEqual([{ path: "/api/v1/account/totp/disable", body: { code: "111111", currentAuthKey: server.authKey } }]);
    const done = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(done).toEqual({ kind: "done" });
    expect(server.enrolled).toBe(false);
    expect(server.mails).toBe(1);
    expect(server.seen).toHaveLength(2);
    expect(text(done)).toBe(TOTP_OFF_DONE);
    expect(text(done, true)).toBe(TOTP_OFF_DONE_REQUIRED);
  }, 120_000);

  it("a proof the server still refuses (its wrap changed elsewhere) is the server's refusal of a proof made here: never a wrong password, nor a wrong code", async () => {
    const { server, s } = await setup();
    server.authKey = "another-key";
    const r = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(r).toEqual({ kind: "refused", code: PROOF_REFUSED });
    expect(text(r)).toBe(SERVER_REFUSED_PROOF);
    expect(server.enrolled).toBe(true);
  }, 120_000);

  it("five wrong codes in a row make the sixth wait, with the wait the server names; nothing is sent again by itself", async () => {
    const { server, s } = await setup();
    // Four in one minute, the fifth and the sixth in the next, so the sixth meets the codes' back-off, not the bucket.
    for (let i = 0; i < 4; i++) expect(await turnOffTwoStep(s, "111111", PASSWORD), `code ${i + 1}`).toEqual({ kind: "wrong_code" });
    server.now += 61_000;
    expect(await turnOffTwoStep(s, "111111", PASSWORD)).toEqual({ kind: "wrong_code" });
    const sent = server.seen.length;
    const sixth = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(sixth).toEqual({ kind: "wait", retryAfterS: 60 });
    expect(text(sixth)).toBe("Too many tries. Wait 1 minute and try again.");
    expect(server.seen.length).toBe(sent + 1);
    expect(server.enrolled).toBe(true);
    // Once the lock lapses the right code is served.
    server.now += 2_000;
    expect(await turnOffTwoStep(s, RIGHT, PASSWORD)).toEqual({ kind: "done" });
  }, 120_000);

  it("the proofs' back-off and the per-minute limit answer the same way, each with its own wait", async () => {
    const { server, s } = await setup();
    server.proofLockUntil = server.now + 30_000;
    expect(await turnOffTwoStep(s, RIGHT, PASSWORD)).toEqual({ kind: "wait", retryAfterS: 60 });
    server.proofLockUntil = 0;
    // The bucket: five calls already in this minute, 20 s before it ends.
    server.now = Math.floor(server.now / 60_000) * 60_000 + 40_000;
    server.minute = [server.now, server.now, server.now, server.now, server.now];
    const r = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(r).toEqual({ kind: "wait", retryAfterS: 20 });
    expect(text(r)).toBe("Too many tries. Wait 20 seconds and try again.");
  }, 120_000);

  it("a session the server ended is said as such, after the one refresh the client tries", async () => {
    const { server, s } = await setup();
    server.sessionLive = false;
    const r = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(r).toEqual({ kind: "session_ended" });
    expect(text(r)).toBe(TOTP_OFF_SESSION_ENDED);
    expect(server.seen.map((x) => x.path)).toEqual(["/api/v1/account/totp/disable", "/api/v1/auth/refresh"]);
  }, 120_000);

  it("no answer, or a 5xx, may or may not have turned it off, and says so", async () => {
    const { server, s } = await setup();
    server.down = 0;
    const lost = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(lost.kind).toBe("unknown");
    expect(text(lost)).toBe(TOTP_OFF_UNKNOWN);
    server.down = 502;
    const bad = await turnOffTwoStep(s, RIGHT, PASSWORD);
    expect(bad.kind).toBe("unknown");
    expect(text(bad)).toBe(TOTP_OFF_UNKNOWN);
  }, 120_000);

  it("reads a Retry-After of plain seconds only, and says the wait in words", () => {
    expect([retryAfterSeconds("60"), retryAfterSeconds(" 7 "), retryAfterSeconds(null), retryAfterSeconds("0"), retryAfterSeconds("1.5"), retryAfterSeconds("Wed, 21 Oct 2026 07:28:00 GMT"), retryAfterSeconds("86401")]).toEqual([60, 7, null, null, null, null, null]);
    expect([waitText(1), waitText(59), waitText(60), waitText(61), waitText(900), waitText(null)]).toEqual([
      "Too many tries. Wait 1 second and try again.",
      "Too many tries. Wait 59 seconds and try again.",
      "Too many tries. Wait 1 minute and try again.",
      "Too many tries. Wait 2 minutes and try again.",
      "Too many tries. Wait 15 minutes and try again.",
      SIGNIN_BACKOFF,
    ]);
    const e = new ApiError(429, "rate_limited", "slow down");
    expect(e.retryAfterS).toBeNull();
  });

  it("the card asks for the master password beside the code, sends through the proof, and empties the field on every path", () => {
    const src = readFileSync(new URL("../ui/Settings.tsx", import.meta.url), "utf-8");
    const disable = src.slice(src.indexOf("const disable = () =>"), src.indexOf("return (", src.indexOf("const disable = () =>")));
    // The proof path, never the old code-only call; the field emptied in a finally, so a throw empties it too.
    expect(disable).toContain("await turnOffTwoStep(settings, code.replace(/\\s/g, \"\"), password)");
    expect(disable).toMatch(/\} finally \{\s*setPassword\(""\);\s*\}/);
    // A code the server answered is spent or stale: it is not left typed (the walk saw it kept after a wait).
    expect(disable).toContain('if (r.kind === "done" || r.kind === "wrong_code" || r.kind === "wait") setCode("");');
    expect(src).not.toContain("client.totpDisable(");
    // The enrolled branch: a password field labelled as such, and "Turn off" disabled until both are typed.
    const on = src.slice(src.indexOf("status.enrolled ? ("), src.indexOf(") : setup ? ("));
    expect(on).toContain('type="password"');
    expect(on).toContain("aria-label={TOTP_OFF_PASSWORD_LABEL}");
    expect(on).toContain("disabled={busy || !code.trim() || !password}");
  });
});

describe("setting two-step sign-in up sends the password proof (server rule of 2026-11-17)", () => {
  beforeAll(async () => {
    await initSodium();
    ORIGIN = verifyCardChain(frames.map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
  });
  afterEach(() => vi.unstubAllGlobals());
  const setupText = (r: TwoStepSetup): string => (r.kind === "setup" ? "" : twoStepSetupText(r));
  const fresh = async () => {
    const f = await setup();
    f.server.enrolled = false; // an account with no factor yet
    return f;
  };

  it("a wrong master password is said here and nothing is sent", async () => {
    const { server, s } = await fresh();
    const r = await setUpTwoStep(s, "not the password");
    expect(r).toEqual({ kind: "wrong_password" });
    expect(setupText(r)).toBe(TOTP_WRONG_PASSWORD);
    expect(server.seen).toEqual([]);
    expect(server.pendingSecret).toBeNull();
  }, 120_000);

  it("the right password sends the proof with the setup, once, also on an account with no factor; the secret comes back", async () => {
    const { server, s } = await fresh();
    const r = await setUpTwoStep(s, PASSWORD);
    expect(r.kind).toBe("setup");
    expect(r.kind === "setup" && r.setup.secretBase32).toBe("JBSWY3DPEHPK3PXP");
    expect(r.kind === "setup" && r.setup.otpauthUri).toContain("secret=JBSWY3DPEHPK3PXP");
    // The old card's bare setup is what the server now answers `403 reauth_required`.
    expect(server.seen).toEqual([{ path: "/api/v1/account/totp/setup", body: { currentAuthKey: server.authKey } }]);
  }, 120_000);

  it("a proof the server refuses is the server's refusal of a proof made here; its back-off is a wait with the server's time; neither is a wrong password", async () => {
    const { server, s } = await fresh();
    server.authKey = "another-key";
    const r = await setUpTwoStep(s, PASSWORD);
    expect(r).toEqual({ kind: "refused", code: PROOF_REFUSED });
    expect(setupText(r as Exclude<TwoStepSetup, { kind: "setup" }>)).toBe(SERVER_REFUSED_PROOF);
    server.proofLockUntil = server.now + 60_000;
    const w = await setUpTwoStep(s, PASSWORD);
    expect(w).toEqual({ kind: "wait", retryAfterS: 60 });
    expect(setupText(w)).toBe(waitText(60));
    expect(server.seen).toHaveLength(2);
  }, 120_000);

  it("the route's per-minute limit is a wait with the time it names, and nothing is sent again by itself", async () => {
    const { server, s } = await fresh();
    server.now = Math.floor(server.now / 60_000) * 60_000 + 40_000;
    for (let i = 0; i < 5; i++) expect((await setUpTwoStep(s, PASSWORD)).kind, `setup ${i + 1}`).toBe("setup");
    const w = await setUpTwoStep(s, PASSWORD);
    expect(w).toEqual({ kind: "wait", retryAfterS: 20 });
    expect(setupText(w)).toBe("Too many tries. Wait 20 seconds and try again.");
    expect(server.seen).toHaveLength(6);
  }, 120_000);

  it("a session that ended, and no answer or a server error, each say what they are", async () => {
    const { server, s } = await fresh();
    server.sessionLive = false;
    const ended = await setUpTwoStep(s, PASSWORD);
    expect(ended).toEqual({ kind: "session_ended" });
    expect(setupText(ended)).toBe(TOTP_SETUP_SESSION_ENDED);
    const f2 = await fresh();
    f2.server.down = 502;
    const bad = await setUpTwoStep(f2.s, PASSWORD);
    expect(bad.kind).toBe("unknown");
    expect(setupText(bad)).toBe(TOTP_SETUP_UNKNOWN);
    f2.server.down = 0;
    expect((await setUpTwoStep(f2.s, PASSWORD)).kind).toBe("unknown");
  }, 120_000);

  it("the card proves the password here first and sends through the proof; the field above “Turn on” is emptied on every path", () => {
    const src = readFileSync(new URL("../ui/Settings.tsx", import.meta.url), "utf-8");
    const card = src.slice(src.indexOf("function TotpCard("), src.indexOf("function PasswordCard("));
    const begin = card.slice(card.indexOf("const begin = () =>"), card.indexOf("const confirm = () =>"));
    expect(begin).toContain("await setUpTwoStep(settings, password)");
    expect(begin).toMatch(/\} finally \{\s*setPassword\(""\);\s*\}/);
    expect(begin).toContain("else setErr(twoStepSetupText(r));");
    expect(card).not.toContain("client.totpSetup(");
    expect(card).toContain('aria-label="Master password"');
    expect(card.indexOf('aria-label="Master password"')).toBeLessThan(card.indexOf("TWO_STEP_TURN_ON"));
  });
});
