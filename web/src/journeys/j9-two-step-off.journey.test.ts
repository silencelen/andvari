import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { parseOtpauthUri, totpCode } from "../crypto/totp";
import { fill, TOTP_OFF_DONE, TOTP_OFF_WAIT, TOTP_WAIT_MINUTE, TOTP_WAIT_MINUTES, TOTP_WAIT_SECOND, TOTP_WAIT_SECONDS, TOTP_WRONG_CODE, TOTP_WRONG_PASSWORD } from "../ui/copy";
import { twoStepOffText, twoStepSetupText } from "../ui/reauthtext";
import { SessionWrap } from "../vault/sessionwrap";
import { type SettingsSession, setUpTwoStep, turnOffTwoStep, type TwoStepSetup } from "../vault/settingsflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 9: turning two-step sign-in off asks for the master password (server rule of 2026-11-16, spec 03 §0.1
 * row 16). One person turns two-step sign-in on; a wrong master password is refused in the browser and sends nothing;
 * the right password with a wrong code is "wrong code"; with the right code it is off and the `two_step_off` mail
 * arrives; then, on again, five wrong codes in a row make the sixth wait.
 *
 * The web client's own flow (vault/settingsflow.ts turnOffTwoStep) over real HTTP against the real server in its test
 * mode, whose clock the journey moves.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "gus@example.org";
const PASSWORD = "gus's correct Horse 8 battery";

describe.skipIf(skip !== null)("journey 9: turning two-step sign-in off asks for the master password", () => {
  let inst: TestInstance;
  let gus: Browser;
  let s: SettingsSession;
  /** Every call the flow made on the wire, by name. */
  let calls: string[];

  /** The current code of [uri]'s secret, at the server's clock. */
  const codeAt = async (uri: string): Promise<string> => totpCode(parseOtpauthUri(uri), Math.floor(inst.now() / 1000));

  /** Turns two-step sign-in on, as the card does: setup (with the proof), then the current code. */
  const turnOn = async (): Promise<string> => {
    const r = await setUpTwoStep(s, PASSWORD);
    if (r.kind !== "setup") throw new Error(r.kind);
    const setup = r.setup;
    await gus.client.totpConfirm(await codeAt(setup.otpauthUri));
    expect(await gus.client.totpStatus()).toEqual({ enrolled: true, pendingSetup: false });
    // The confirm used this step: the next code is a later one.
    inst.advance(31_000);
    return setup.otpauthUri;
  };

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
    gus = new Browser(inst, "Firefox at home");
    const signed = await gus.signUp(EMAIL, PASSWORD, "Gus");
    const base = gus.settings(signed.opened, EMAIL, new SessionWrap(signed.wrap));
    calls = [];
    const wire = new Proxy(base.wire, {
      get: (t, n) => {
        const f = (t as unknown as Record<string | symbol, unknown>)[n];
        if (typeof f !== "function") return f;
        return (...a: unknown[]) => {
          calls.push(String(n));
          return (f as (...x: unknown[]) => unknown).apply(t, a);
        };
      },
    });
    s = { ...base, wire };
  }, HOOK.startThenSignUp);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  // The route's per-minute bucket is a fixed window on the server's test clock: each step starts in a new minute.
  beforeEach(() => inst.advance(61_000));

  let uri = "";

  it("setting it up asks for the master password (server rule of 2026-11-17): a wrong one sends nothing; the right one sends the proof, once, right after the sign-in too", async () => {
    calls = [];
    const wrong = await setUpTwoStep(s, "not the password");
    expect(wrong).toEqual({ kind: "wrong_password" });
    expect(twoStepSetupText(wrong as Exclude<TwoStepSetup, { kind: "setup" }>)).toBe(TOTP_WRONG_PASSWORD);
    expect(calls).toEqual([]);
    const r = await setUpTwoStep(s, PASSWORD);
    expect(r.kind).toBe("setup");
    expect(calls).toEqual(["totpSetup"]);
    expect(await gus.client.totpStatus()).toEqual({ enrolled: false, pendingSetup: true });
  }, 300_000);

  it("on: a wrong master password is refused here and sends nothing", async () => {
    uri = await turnOn();
    calls = [];
    const r = await turnOffTwoStep(s, await codeAt(uri), "not the password");
    expect(r).toEqual({ kind: "wrong_password" });
    expect(twoStepOffText(r, false).text).toBe(TOTP_WRONG_PASSWORD);
    expect(calls).toEqual([]);
    expect(await gus.client.totpStatus()).toEqual({ enrolled: true, pendingSetup: false });
  }, 300_000);

  it("the right password with a wrong code is 'wrong code'", async () => {
    const right = await codeAt(uri);
    const wrong = right === "000000" ? "000001" : "000000";
    calls = [];
    const r = await turnOffTwoStep(s, wrong, PASSWORD);
    expect(r).toEqual({ kind: "wrong_code" });
    expect(twoStepOffText(r, false).text).toBe(TOTP_WRONG_CODE);
    expect(calls).toEqual(["totpDisable"]);
    expect(await gus.client.totpStatus()).toEqual({ enrolled: true, pendingSetup: false });
  }, 300_000);

  it("with the right code it is off, and the mail that says so arrives", async () => {
    const seen = inst.mailCount(EMAIL, "two_step_off");
    calls = [];
    const r = await turnOffTwoStep(s, await codeAt(uri), PASSWORD);
    expect(r).toEqual({ kind: "done" });
    expect(twoStepOffText(r, false).text).toBe(TOTP_OFF_DONE);
    expect(calls).toEqual(["totpDisable"]);
    expect(await gus.client.totpStatus()).toEqual({ enrolled: false, pendingSetup: false });
    await inst.awaitMail(EMAIL, "two_step_off", seen);
  }, 300_000);

  it("on again: five wrong codes in a row make the sixth wait, and the wait is said", async () => {
    uri = await turnOn();
    const right = async () => codeAt(uri);
    const wrongOf = (c: string) => (c === "000000" ? "000001" : "000000");
    // Four in one minute and the fifth in the next, so the sixth meets the codes' back-off rather than the minute's limit.
    for (let i = 0; i < 4; i++) expect(await turnOffTwoStep(s, wrongOf(await right()), PASSWORD), `wrong code ${i + 1}`).toEqual({ kind: "wrong_code" });
    inst.advance(61_000);
    expect(await turnOffTwoStep(s, wrongOf(await right()), PASSWORD), "wrong code 5").toEqual({ kind: "wrong_code" });
    calls = [];
    const sixth = await turnOffTwoStep(s, await right(), PASSWORD);
    // The server names the real remaining wait of this device's back-off (no longer a fixed 60): the client takes it.
    expect(sixth.kind).toBe("wait");
    if (sixth.kind !== "wait") return;
    const n = sixth.retryAfterS;
    expect(typeof n === "number" && Number.isInteger(n) && n >= 1 && n <= 15 * 60, `the server's wait: ${n}`).toBe(true);
    const secs = n as number;
    // The screen says that number: seconds below a minute, whole minutes (rounded up) from a minute on.
    const mins = Math.ceil(secs / 60);
    const words = secs < 60 ? (secs === 1 ? TOTP_WAIT_SECOND : fill(TOTP_WAIT_SECONDS, String(secs))) : mins === 1 ? TOTP_WAIT_MINUTE : fill(TOTP_WAIT_MINUTES, String(mins));
    expect(twoStepOffText(sixth, false).text).toBe(fill(TOTP_OFF_WAIT, words));
    // Sent once, never again by itself, and nothing changed.
    expect(calls).toEqual(["totpDisable"]);
    expect(await gus.client.totpStatus()).toEqual({ enrolled: true, pendingSetup: false });
    // Once the wait it named lapses, the right code turns it off.
    inst.advance((secs + 1) * 1000);
    const seen = inst.mailCount(EMAIL, "two_step_off");
    expect(await turnOffTwoStep(s, await right(), PASSWORD)).toEqual({ kind: "done" });
    await inst.awaitMail(EMAIL, "two_step_off", seen);
  }, 300_000);
});
