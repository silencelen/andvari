import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { enrollError } from "./Welcome";

/**
 * Audit F26: enrollment refusals were mapped THREE times (web here, desktop's enroll sheet,
 * android not at all) and had drifted — `escrow_required`, the refusal a bare-token invite hits
 * on the DEFAULT path, had no curated sentence on any client and web printed the raw wire code,
 * because the sentence that fits it was keyed to `recovery_required`, a different server
 * condition. The table now lives ONCE in core HouseholdCopy's `apiCopy` code map; this pins web
 * to it the token-lockstep way (vault-copy.test.ts pattern) so a one-sided reword fails here
 * instead of drifting again.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const householdKt = readFileSync(
  here("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/HouseholdCopy.kt"),
  "utf8",
);

/** The curated sentence on HouseholdCopy's `"<code>" -> "…"` row. */
function canonRow(code: string): string {
  const m = householdKt.match(new RegExp(`"${code}" -> "([^"]+)"`));
  expect(m, `HouseholdCopy's ${code} row moved or was renamed — update the pin`).not.toBeNull();
  return m![1]!;
}

/** Every BadRequest `Service.register` can throw (core RegisterRefusalCoverageTest asserts
 *  that list stays complete against the server source; this asserts web renders it). */
const REGISTER_REFUSALS = [
  "invalid_invite",
  "invite_used",
  "invite_expired",
  "invite_email_mismatch",
  "email_taken",
  "escrow_required",
  "escrow_not_allowed_when_waived",
  "escrow_not_configured",
  "escrow_fingerprint_mismatch",
  "recovery_required",
];

describe("Welcome.enrollError — the core HouseholdCopy twin", () => {
  for (const code of REGISTER_REFUSALS) {
    it(`${code} renders the canon sentence`, () => {
      expect(enrollError(code)).toBe(canonRow(code));
    });
  }

  it("no register refusal falls through to the raw wire code", () => {
    for (const code of REGISTER_REFUSALS) {
      expect(enrollError(code), code).not.toContain(code);
      expect(enrollError(code), code).not.toContain("Enrollment failed (");
    }
  });

  it("escrow_required and recovery_required stay DIFFERENT sentences", () => {
    // The F26 mis-keying: one sentence served the posture gate under the wrong code.
    expect(enrollError("escrow_required")).not.toBe(enrollError("recovery_required"));
    expect(enrollError("escrow_required")).toContain("admin backstop");
    expect(enrollError("recovery_required")).not.toContain("admin backstop");
  });

  it("keeps the code visible for anything core does NOT curate", () => {
    expect(enrollError("some_new_server_code")).toBe("Enrollment failed (some_new_server_code).");
  });
});
