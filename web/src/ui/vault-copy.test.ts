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

/**
 * The two branch literals of HouseholdCopy.replayDeniedNotice, in source order (singular first).
 * Read off the function BODY, not its KDoc — the KDoc quotes the retired wordings on purpose.
 */
function canonReplayDenied(): { one: string; many: string } {
  const fn = householdKt.match(/fun replayDeniedNotice\([\s\S]*?\n\n/);
  expect(fn, "HouseholdCopy.replayDeniedNotice moved or was renamed — update the pin").not.toBeNull();
  const literals = [...fn![0].matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
  expect(literals, "expected exactly the two count branches").toHaveLength(2);
  return { one: literals[0]!, many: literals[1]! };
}

/** Kotlin `$name` interpolation → the JS template expression Vault.tsx interpolates there. */
const asTemplate = (kotlin: string) =>
  "`" + kotlin.replace("$vaultName", "${name}").replace("$count", "${count}") + "`";

/**
 * ux-copy--3 (polish audit 2026-07-27): the §11 "replay-denied" notice was the one lifecycle
 * sentence with interpolation, so no constant carried it and all three surfaces hand-wrote it —
 * web and the natives had drifted three ways at once (clause order, "your access may have changed
 * while it was deleted" vs "your role may have changed", "A recovered edit" vs "1 recovered
 * edit"), each side's comment claiming to mirror the other. It now lives in core HouseholdCopy;
 * android/desktop call it, and web's byte-equal templates are pinned here the same token-lockstep
 * way as the sentences above.
 */
describe("Vault.tsx §11 replay-denied notice — the core HouseholdCopy twin", () => {
  it("carries both count branches byte-equal to the canon", () => {
    const { one, many } = canonReplayDenied();
    expect(vaultTsx).toContain(asTemplate(one));
    expect(vaultTsx).toContain(asTemplate(many));
  });

  it("no longer carries either drifted wording", () => {
    expect(vaultTsx).not.toContain("your role may have changed");
    expect(vaultTsx).not.toContain("while it was deleted");
  });
});

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
