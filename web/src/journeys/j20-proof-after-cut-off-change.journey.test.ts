import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { SessionWrap } from "../vault/sessionwrap";
import { changePassword, PASSWORD_CHANGE_UNCONFIRMED, rotateKitFor, type SettingsSession } from "../vault/settingsflow";
import { PASSWORD_CHANGE_NOT_CONFIRMED } from "../ui/copy";
import { kitRotateText } from "../ui/reauthtext";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 20: a change of the master password whose answer is cut off after the server made it. Until the browser has
 * read from the server's keys which password the server holds, it sends no proof of either; once it has, it proves with
 * that one only. Every step runs the web client's flow modules over real HTTP against the real server in its test mode.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "gil@example.org";
const P1 = "gil's first Horse 4 battery staple";
const P2 = "gil's second Horse 8 battery staple";

describe.skipIf(skip !== null)("journey 20: a proof after a password change whose answer was cut off", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
  }, HOOK.start);

  afterAll(async () => {
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => inst.advance(61_000));

  it("the change reaches the server and its answer is lost; no proof goes until the server's keys are read, and then only the new password's", async () => {
    const home = new Browser(inst, "Firefox at home");
    const signed = await home.signUp(EMAIL, P1, "Gil");
    const s = home.settings(signed.opened, EMAIL, new SessionWrap(signed.wrap));
    const calls: string[] = [];
    // The same session's wire, as seen through a connection: [cut] names what breaks.
    const through = (cut: (route: string) => "answer_lost" | "no_answer" | null): SettingsSession => ({
      ...s,
      wire: new Proxy(s.wire, {
        get: (t, n) => {
          const f = (t as unknown as Record<string | symbol, unknown>)[n];
          if (typeof f !== "function" || typeof n !== "string") return f;
          return async (...args: unknown[]) => {
            calls.push(n);
            const how = cut(n);
            if (how === "no_answer") throw new TypeError("the connection broke");
            const r = await (f as (...a: unknown[]) => Promise<unknown>).apply(t, args);
            if (how === "answer_lost") throw new TypeError("the connection broke");
            return r;
          };
        },
      }),
    });

    // The change is sent and made at the server; its answer never arrives.
    const policy = (await home.wire.clientPolicy()).kdfParams;
    const changed = await changePassword(through((n) => (n === "changePassword" ? "answer_lost" : null)), P1, P2, policy);
    expect(changed.kind).toBe("unknown");
    expect(s.wrap.pending).not.toBeNull();

    // The server's keys can't be read: nothing is sent, and the line says the change wasn't confirmed. On the code before,
    // the old password proved here and was sent, and the server's refusal read "That isn't a wrong password".
    calls.length = 0;
    const blind = await rotateKitFor(through((n) => (n === "accountKeys" ? "no_answer" : null)), P1);
    expect(blind).toEqual({ kind: "refused", code: PASSWORD_CHANGE_UNCONFIRMED });
    expect(kitRotateText(blind as Exclude<typeof blind, { kind: "done" }>)).toBe(PASSWORD_CHANGE_NOT_CONFIRMED);
    expect(calls).toEqual(["accountKeys"]);
    expect(s.wrap.pending).not.toBeNull();

    // Read: the server holds the new password. The old one proves nothing and sends nothing; the new one goes.
    calls.length = 0;
    const live = through(() => null);
    expect((await rotateKitFor(live, P1)).kind).toBe("wrong_password");
    expect(calls).toEqual(["accountKeys"]);
    expect(s.wrap.pendingAll).toEqual([]);
    calls.length = 0;
    expect((await rotateKitFor(live, P2)).kind).toBe("done");
    expect(calls).toEqual(["recoverySelfSetup"]);
  }, 300_000);
});
