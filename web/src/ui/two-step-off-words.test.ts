import { describe, expect, it } from "vitest";
import { TOTP_OFF_DONE, TOTP_OFF_DONE_REQUIRED } from "./copy";
import { twoStepOffText } from "./reauthtext";

/**
 * The two lines after two-step sign-in is turned off carry the approved words (decided on 2026-11-17), in the product's
 * term: "two-step sign-in", never "two-factor".
 */
describe("the two-step card after turning it off", () => {
  it("says the approved line, and the server-requires-it line where the server requires it", () => {
    expect(twoStepOffText({ kind: "done" }, false)).toEqual({ kind: "info", text: TOTP_OFF_DONE });
    expect(twoStepOffText({ kind: "done" }, true)).toEqual({ kind: "info", text: TOTP_OFF_DONE_REQUIRED });
    expect(TOTP_OFF_DONE).toBe("Two-step sign-in is off. Signing in now asks only for your master password.");
    expect(TOTP_OFF_DONE_REQUIRED).toBe("Two-step sign-in is off. This server requires it, so your next sign-in asks you to set it up again.");
  });
});
