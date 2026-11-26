import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { WEAK_KDF_MESSAGE } from "../crypto/keys";
import { CONFIRM_SERVER_REFUSED, PASSWORD_CHANGE_UNKNOWN, SERVER_STOPPED_REFUSED, SIGNIN_BACKOFF } from "./copy";
import { passwordChangeText } from "./reauthtext";

/** The Password card on the settings flow: each way the change did not land reads as its own sentence. */
describe("passwordChangeText", () => {
  it("maps every refusal, and never reads an unknown answer as a failure", () => {
    expect(passwordChangeText({ kind: "wrong_password" })).toBe("Current master password is wrong.");
    expect(passwordChangeText({ kind: "password_rule", decision: "refuse_entry" })).toBe(SERVER_STOPPED_REFUSED);
    expect(passwordChangeText({ kind: "password_rule", decision: "trust_gate" })).toBe(CONFIRM_SERVER_REFUSED);
    expect(passwordChangeText({ kind: "refused", code: "kdf_below_floor" })).toBe(WEAK_KDF_MESSAGE);
    // Server 2026-11-16: the back-off reads as the sign-in's sentence, both as the flows' own kind and as a raw code.
    expect(passwordChangeText({ kind: "rate_limited" })).toBe(SIGNIN_BACKOFF);
    expect(passwordChangeText({ kind: "refused", code: "rate_limited" })).toBe(SIGNIN_BACKOFF);
    expect(passwordChangeText({ kind: "refused", code: "kdf_too_weak" })).toContain("kdf_too_weak");
    expect(passwordChangeText({ kind: "unknown", error: new Error("x") })).toBe(PASSWORD_CHANGE_UNKNOWN);
    expect(passwordChangeText({ kind: "session_ended" })).toMatch(/sign in again/);
  });

  it("the card empties the current-password field after a refusal, the back-off's included", () => {
    const src = readFileSync(fileURLToPath(new URL("./Settings.tsx", import.meta.url)), "utf8");
    const card = src.slice(src.indexOf("function PasswordCard("), src.indexOf("return (", src.indexOf("function PasswordCard(")));
    expect(card).toMatch(/setErr\(passwordChangeText\(r\)\);\s*setCurrent\(""\);/);
    expect(card).toMatch(/setErr\(passwordChangeText\(\{ kind: "unknown", error: e \}\)\);\s*setCurrent\(""\);/);
  });
});
