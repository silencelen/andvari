import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { fill, SIGN_IN_WAIT, SIGNIN_BACKOFF, TOTP_OFF_WAIT, TOTP_WAIT_MINUTES } from "./copy";
import { waitText } from "./reauthtext";
import { refusalText, signInRefusalText } from "./Welcome";

/**
 * The sign-in's back-off has a line of its own (the wording page's FX3), apart from the wait a signed-in session is told.
 * The server answers a sign-in, whose caller has proven nothing, with a fixed 60 seconds: the line says "at least a
 * minute" and shows no number. A signed-in session is told its own device's real wait, and that line shows the number.
 */
describe("the sign-in's wait and a session's wait are two lines", () => {
  const backoff = Object.assign(new ApiError(429, "rate_limited", "slow down"), { retryAfterS: 60 });

  it("a sign-in the server holds back reads the sign-in's own line, whatever number the answer names", () => {
    expect(signInRefusalText(backoff)).toBe(SIGN_IN_WAIT);
    expect(signInRefusalText(Object.assign(new ApiError(429, "rate_limited", "x"), { retryAfterS: 900 }))).toBe(SIGN_IN_WAIT);
    expect(SIGN_IN_WAIT).not.toBe(SIGNIN_BACKOFF);
    expect(SIGN_IN_WAIT).not.toMatch(/\d|\{\d+\}/);
    // Every other refusal of a sign-in reads as before.
    const other = new ApiError(500, "server_error", "x");
    expect(signInRefusalText(other)).toBe(refusalText(other));
  });

  it("a signed-in session's wait still shows the number the server names", () => {
    expect(waitText(900)).toBe(fill(TOTP_OFF_WAIT, fill(TOTP_WAIT_MINUTES, "15")));
  });

  it("the sign-in form reads its refusals through that text", () => {
    const welcome = readFileSync(fileURLToPath(new URL("./Welcome.tsx", import.meta.url)), "utf8");
    const signIn = welcome.slice(welcome.indexOf("function SignIn("), welcome.indexOf("// ---- Unlock a session this browser holds"));
    expect(signIn).toContain("setErr(signInRefusalText(r.error));");
    expect(signIn).not.toContain("setErr(refusalText(r.error));");
  });
});
