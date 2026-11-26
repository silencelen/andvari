import { describe, expect, it } from "vitest";
import { PasswordRuleRefused } from "../vault/kitflow";
import { cardOutcomeOf } from "./account-delete";
import { CARD_CHANGED_UPDATE, CARD_KIND_CHANGED_RELOAD } from "./copy";
import { pinChangedText } from "./Welcome";
import { CARD_REFUSED, CONFIRM_SERVER_REFUSED, KIT_RECOVERY_CONFIRM_SERVER_REFUSED, passwordRuleText, SERVER_STOPPED_REFUSED, SIGNUP_CONFIRM_SERVER_REFUSED } from "./copy";
import { passwordChangeText } from "./reauthtext";
import { totpErrorText } from "./Settings";
import { kitAtSignInText, kitCommitScreen, stoppedBeforeSendingText } from "./Welcome";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * The wording check of 17 November: five places showed the card's refusal ("andvari couldn't verify this server's identity
 * card…") when the password rule refused an act of a signed-in person, where no identity card failed. Each now says the
 * rule's own line, by its decision: confirm the server first, or this browser stopped using it.
 */
describe("an act the password rule refused says the rule's line, never the card's refusal", () => {
  const decisions = [
    ["trust_gate", CONFIRM_SERVER_REFUSED],
    ["refuse_entry", SERVER_STOPPED_REFUSED],
  ] as const;

  it("the two lines are their own keys", () => {
    expect(new Set([CONFIRM_SERVER_REFUSED, SERVER_STOPPED_REFUSED, CARD_REFUSED]).size).toBe(3);
    for (const [d, line] of decisions) expect(passwordRuleText(d)).toBe(line);
  });

  for (const [d, line] of decisions) {
    it(`${d}: two-step setup, the kit at sign-in, deleting the account, changing the password`, () => {
      expect(totpErrorText(new PasswordRuleRefused(d))).toBe(line);
      expect(kitAtSignInText(new PasswordRuleRefused(d))).toBe(line);
      expect(cardOutcomeOf({ kind: "password_rule", decision: d } as never)).toEqual({ kind: "error", message: line, code: "password_rule" });
      expect(passwordChangeText({ kind: "password_rule", decision: d })).toBe(line);
    });
  }

  it("a sign-in, a sign-up (its code and its registration) and a kit's check that the rule stopped say the rule's line; only a failed card says the card's refusal", () => {
    for (const where of ["sign_in", "sign_up", "kit_recovery"] as const) {
      expect(stoppedBeforeSendingText({ kind: "pin" }, where)).toBe(CARD_REFUSED);
      expect(stoppedBeforeSendingText({ kind: "password_rule", decision: "refuse_entry" }, where)).toBe(SERVER_STOPPED_REFUSED);
    }
    expect(stoppedBeforeSendingText({ kind: "password_rule", decision: "trust_gate" }, "sign_in")).toBe(CONFIRM_SERVER_REFUSED);
    // No account yet, or no password: "sign in again" is not open there.
    expect(stoppedBeforeSendingText({ kind: "password_rule", decision: "trust_gate" }, "sign_up")).toBe(SIGNUP_CONFIRM_SERVER_REFUSED);
    expect(stoppedBeforeSendingText({ kind: "password_rule", decision: "trust_gate" }, "kit_recovery")).toBe(KIT_RECOVERY_CONFIRM_SERVER_REFUSED);
    expect(new Set([SIGNUP_CONFIRM_SERVER_REFUSED, CONFIRM_SERVER_REFUSED, KIT_RECOVERY_CONFIRM_SERVER_REFUSED]).size).toBe(3);
    // Each of the four places goes through it: no case of the rule in the first screens reaches the card's refusal.
    const welcome = readFileSync(fileURLToPath(new URL("./Welcome.tsx", import.meta.url)), "utf8");
    const cases = welcome.split('case "password_rule":').slice(1).map((rest) => rest.slice(0, rest.indexOf("return")));
    expect(cases.length).toBeGreaterThanOrEqual(4);
    for (const c of cases) expect(c.split("\n").filter((l) => !l.trim().startsWith("//")).join("\n")).not.toContain("CARD_REFUSED");
    // On the code before: the sign-in, the sign-up's code, its registration and the kit's check said CARD_REFUSED.
    expect(welcome).not.toContain("else setErr(CARD_REFUSED)");
    expect(welcome.split('stoppedBeforeSendingText(r, "').length - 1).toBe(4);
  });

  it("the first screen's stop for a card that verified and says the server changed its kind is not the card's refusal", () => {
    const pin = { origin: "https://vault.example.org" } as never;
    // On the code before: CARD_REFUSED ("couldn't verify this server's identity card"), though the card verified.
    expect(pinChangedText({ kind: "kind_changed", pinned: pin, newest: pin, mustUpdate: false })).toBe(CARD_KIND_CHANGED_RELOAD);
    expect(pinChangedText({ kind: "kind_changed", pinned: pin, newest: pin, mustUpdate: true })).toBe(CARD_CHANGED_UPDATE);
    expect(pinChangedText({ kind: "not_verified", pinned: pin, verdict: "bad_signature" })).toBe(CARD_REFUSED);
    expect(new Set([CARD_KIND_CHANGED_RELOAD, CARD_CHANGED_UPDATE, CARD_REFUSED]).size).toBe(3);
  });

  it("the kit recovery's commit: the person has no password to sign in with, so the confirmation gets a line of its own (never 'sign in again')", () => {
    expect(kitCommitScreen({ kind: "password_rule", decision: "trust_gate" })).toEqual({ show: "form", err: KIT_RECOVERY_CONFIRM_SERVER_REFUSED, endSession: false });
    expect(KIT_RECOVERY_CONFIRM_SERVER_REFUSED).not.toBe(CONFIRM_SERVER_REFUSED);
    // Stopping use of the server is true for anyone, signed in or not: the same line as elsewhere.
    expect(kitCommitScreen({ kind: "password_rule", decision: "refuse_entry" })).toEqual({ show: "form", err: SERVER_STOPPED_REFUSED, endSession: false });
  });
});
