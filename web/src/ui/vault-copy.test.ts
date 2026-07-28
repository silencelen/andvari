import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * ux-copy--2 (polish audit 2026-07-27): three Vault.tsx catches rendered raw wire text — the
 * editor's 413 interpolated the server's message into "Save rejected: …", the MoveCopy 403
 * showed the literal body "forbidden", and the re-seal catch showed any Error.message verbatim
 * ("Failed to fetch"). Each now shows a canon sentence. The sentences are byte-twins of core
 * HouseholdCopy's rows (the natives render the same ones), so pin them against the Kotlin
 * source the token-lockstep way — a one-sided reword fails here instead of drifting.
 */

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");
const householdKt = readFileSync(
  here("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/HouseholdCopy.kt"),
  "utf8",
);

/** The curated sentence on HouseholdCopy's `e.status == <status>` row. */
function canonStatusRow(status: number): string {
  const m = householdKt.match(new RegExp(`e\\.status == ${status} -> "([^"]+)"`));
  expect(m, `HouseholdCopy's ${status} row moved — update the pin`).not.toBeNull();
  return m![1]!;
}

describe("Vault.tsx error copy — canon sentences, never wire text", () => {
  it("the editor's 413 shows core HouseholdCopy's 413 row, byte-equal", () => {
    expect(vaultTsx).toContain(`"${canonStatusRow(413)}"`);
    // The audited defect — the server's raw message interpolated into the error bar.
    expect(vaultTsx).not.toContain("Save rejected: ${");
  });

  it("the MoveCopy 403 shows core HouseholdCopy's 403 row, byte-equal", () => {
    expect(vaultTsx).toContain(`"${canonStatusRow(403)}"`);
  });

  it("the re-seal catch maps ApiError to the canon SERVER_PROBLEM twin and never e.message", () => {
    const m = householdKt.match(/const val SERVER_PROBLEM = "([^"]+)"/);
    expect(m).not.toBeNull();
    expect(vaultTsx).toContain(`"${m![1]}"`);
    expect(vaultTsx).not.toContain('e.message : "re-seal failed');
  });
});
