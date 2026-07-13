import { describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { IdentityMismatchError } from "../vault/account";
import { NetworkError, UNREACHABLE } from "./errors";
import { resetErrorMessage, verifyErrorMessage } from "./Recover";

/**
 * design §F.9 — the Recover screen's error copy must fire on the SERVER's actual codes (pinned by
 * RecoveryTest.kt): the public-origin refusal is `recovery_public_disabled` (was the wrong
 * `recovery_disabled_public_origin`), and an expired/consumed ticket is `invalid_ticket` (was the
 * wrong `recovery_ticket_invalid`). The stale codes must no longer route to their branches.
 */

describe("verifyErrorMessage (phase 1) — public-origin refusal + anti-enumeration copy", () => {
  it("recovery_public_disabled → the 'not from this public address' copy", () => {
    expect(verifyErrorMessage(new ApiError(403, "recovery_public_disabled", ""))).toMatch(/public address/i);
  });
  it("the STALE code recovery_disabled_public_origin no longer hits that branch (generic server copy)", () => {
    expect(verifyErrorMessage(new ApiError(403, "recovery_disabled_public_origin", ""))).not.toMatch(/public address/i);
  });
  it("a 401 is the uniform anti-enumeration copy; a transport failure is UNREACHABLE", () => {
    expect(verifyErrorMessage(new ApiError(401, "unauthorized", ""))).toMatch(/couldn't verify/i);
    expect(verifyErrorMessage(new NetworkError())).toBe(UNREACHABLE);
  });
});

describe("resetErrorMessage (phase 2) — ticket + tampering + disabled-account copy", () => {
  it("invalid_ticket → the 'recovery session expired' copy", () => {
    expect(resetErrorMessage(new ApiError(400, "invalid_ticket", ""))).toMatch(/recovery session expired/i);
  });
  it("the STALE code recovery_ticket_invalid no longer hits the ticket branch (generic server copy)", () => {
    expect(resetErrorMessage(new ApiError(400, "recovery_ticket_invalid", ""))).toMatch(/server had a problem/i);
  });
  it("a bare 401 still reads as an expired recovery session", () => {
    expect(resetErrorMessage(new ApiError(401, "unauthorized", ""))).toMatch(/recovery session expired/i);
  });
  it("an identity mismatch stays a DISTINCT tampering signal — never softened into password/phrase copy", () => {
    const msg = resetErrorMessage(new IdentityMismatchError());
    expect(msg).toMatch(/tampering/i);
    expect(msg).not.toMatch(/password|phrase/i);
  });
  it("recovery_account_not_active → the disabled-account copy", () => {
    expect(resetErrorMessage(new ApiError(403, "recovery_account_not_active", ""))).toMatch(/disabled/i);
  });
});
