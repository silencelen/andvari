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

/**
 * Audit 2026-09-13 H03/H19: the "write-rejected" notice (queue rows the server definitively
 * refused and the drain dropped instead of re-sending forever). Its LEAD + reason clauses are
 * core HouseholdCopy.writeRejectedNotice, rendered directly by the natives; web appends a
 * revert tail of its own (only web applies writes optimistically) but every canon literal must
 * appear byte-equal — the lead as the interpolated template, each reason clause verbatim.
 */
describe("Vault.tsx write-rejected notice — the core HouseholdCopy twin", () => {
  it("carries the lead (both counts) and every reason clause byte-equal to the canon", () => {
    const fn = householdKt.match(/fun writeRejectedNotice\([\s\S]*?\n\n/);
    expect(fn, "HouseholdCopy.writeRejectedNotice moved or was renamed — update the pin").not.toBeNull();
    const literals = [...fn![0].matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
    const leads = literals.filter((l) => l.includes("couldn't be applied"));
    const clauses = literals.filter((l) => l.endsWith("."));
    expect(leads, "one lead per count branch").toHaveLength(2);
    expect(clauses, "two clauses per reason class: attachment gone / too large / other").toHaveLength(6);
    for (const lead of leads) expect(vaultTsx).toContain(asTemplate(lead));
    for (const clause of clauses) expect(vaultTsx).toContain(`"${clause}"`);
  });

  it("never re-uses the permission (write-refused) explanation for a rejected row", () => {
    const branch = vaultTsx.match(/case "write-rejected": \{[\s\S]*?\n    \}/);
    expect(branch).not.toBeNull();
    expect(branch![0]).not.toContain("no longer have permission");
  });
});

describe("Vault.tsx error copy — canon sentences, never wire text", () => {
  it("the editor's 413 shows core HouseholdCopy's 413 row, byte-equal", () => {
    expect(vaultTsx).toContain(`"${canonStatusRow(413)}"`);
    // The audited defect — the server's raw message interpolated into the error bar.
    expect(vaultTsx).not.toContain("Save rejected: ${");
  });

  it("the editor's rejected-attachment save shows core HouseholdCopy.SAVE_REJECTED_ATTACHMENT, byte-equal (R38)", () => {
    const m = householdKt.match(/const val SAVE_REJECTED_ATTACHMENT = "([^"]+)"/);
    expect(m, "HouseholdCopy.SAVE_REJECTED_ATTACHMENT moved — update the pin").not.toBeNull();
    expect(vaultTsx).toContain(`"${m![1]}"`);
    // The branch is keyed on the server's two attachment refusal codes, ahead of the 413 row.
    const branch = vaultTsx.match(/const rejectedAttachment = [^\n]+/);
    expect(branch).not.toBeNull();
    expect(branch![0]).toContain('err.code === "unknown_attachment"');
    expect(branch![0]).toContain('err.code === "attachment_mismatch"');
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

/**
 * R10 (H134's web half): H134 gave the browser EXTENSION its own Appearance choice because the
 * web app's sentence promised a pick that "keeps andvari that way in this browser" and the popup
 * — a separate origin with its own store — ignored it. Adding the extension row does not make the
 * web sentence true on its own: forcing Light here still leaves the popup dark until it is set
 * over there too. So the two sentences are one claim split across two surfaces, and each must
 * scope itself to its own surface and point at the other. Pinned as a pair, here, because a
 * reword of either side alone is exactly how the promise broke the first time.
 */
describe("R10 — the Appearance promise is scoped, on both surfaces", () => {
  const settingsTsx = readFileSync(here("./Settings.tsx"), "utf8");
  const optionsHtml = readFileSync(here("../../../extension/options.html"), "utf8");

  it("the web app scopes its pick to the web app and names the extension's own setting", () => {
    expect(settingsTsx).toContain("keeps the andvari\n        web app that way in this browser only");
    expect(settingsTsx).toContain("the browser extension has its own Appearance\n        setting");
    // The unscoped claim is the defect — it must not come back.
    expect(settingsTsx).not.toContain("Picking one keeps\n        andvari that way in this browser only");
  });

  it("the extension scopes its pick to the extension and names the web vault's own setting", () => {
    expect(optionsHtml).toContain("keeps the\n          andvari extension that way in this browser");
    expect(optionsHtml).toContain("The web vault keeps its own setting.");
  });
});

/**
 * Security review 2026-10, root cause A §3.1: the two key-precedence notices are canon in core
 * HouseholdCopy (the natives render it directly); web's copies are pinned byte-equal here.
 */
describe("Vault.tsx key-precedence notices — the core HouseholdCopy twins", () => {
  it("vk-mismatch carries HouseholdCopy.vkMismatchNotice byte-equal", () => {
    const fn = householdKt.match(/fun vkMismatchNotice\([^)]*\): String =\s*"([^"]+)"/);
    expect(fn, "HouseholdCopy.vkMismatchNotice moved or was renamed — update the pin").not.toBeNull();
    expect(vaultTsx).toContain(asTemplate(fn![1]!));
  });

  it("grant-anomaly carries HouseholdCopy.GRANT_ANOMALY_NOTICE byte-equal (A6)", () => {
    const m = householdKt.match(/const val GRANT_ANOMALY_NOTICE: String =\s*"([^"]+)"/);
    expect(m, "HouseholdCopy.GRANT_ANOMALY_NOTICE moved — update the pin").not.toBeNull();
    expect(vaultTsx).toContain(JSON.stringify(m![1]!));
  });

  it("grant-anomaly vk_mismatch carries HouseholdCopy.GRANT_VK_MISMATCH_NOTICE byte-equal, with the recovery path (A6 re-review LOW-C)", () => {
    const m = householdKt.match(/const val GRANT_VK_MISMATCH_NOTICE: String =\s*"([^"]+)"/);
    expect(m, "HouseholdCopy.GRANT_VK_MISMATCH_NOTICE missing — update the pin").not.toBeNull();
    expect(m![1]!).toContain("leave it and ask its owner to add you again");
    expect(vaultTsx).toContain(JSON.stringify(m![1]!));
  });

  it("added carries both branches of HouseholdCopy.addedNotice byte-equal (A6)", () => {
    const fn = householdKt.match(/fun addedNotice\(vaultName: String, byLabel: String\?\): String =\s*if \(byLabel\.isNullOrBlank\(\)\) "([^"]+)" else "([^"]+)"/);
    expect(fn, "HouseholdCopy.addedNotice moved or was renamed — update the pin").not.toBeNull();
    const plain = fn![1]!.replace("$vaultName", "${name}");
    const by = fn![2]!.replace("$vaultName", "${name}").replace("$byLabel", "${n.byLabel}");
    expect(vaultTsx).toContain("`" + plain + "`");
    expect(vaultTsx).toContain("`" + by + "`");
  });

  it("key-unreadable carries HouseholdCopy.KEY_UNREADABLE_NOTICE byte-equal", () => {
    const m = householdKt.match(/const val KEY_UNREADABLE_NOTICE: String =\s*"([^"]+)"/);
    expect(m, "HouseholdCopy.KEY_UNREADABLE_NOTICE moved — update the pin").not.toBeNull();
    expect(vaultTsx).toContain(JSON.stringify(m![1]!));
  });
});

/**
 * Root cause A §6.3/§8.6 (branch A7): the two new removal-verdict sentences live in core HouseholdCopy
 * (removalReplayDeniedNotice, leftUnprovenNotice) and the natives render them directly; web's templates are pinned
 * byte-equal here, the same way as the replay-denied pair above.
 */
describe("Vault.tsx removal-proof v2 notices — the core HouseholdCopy twins", () => {
  it("carries the replayed-removal sentence byte-equal to the canon", () => {
    const fn = householdKt.match(/fun removalReplayDeniedNotice\([\s\S]*?\n\n/);
    expect(fn, "HouseholdCopy.removalReplayDeniedNotice moved or was renamed — update the pin").not.toBeNull();
    const literals = [...fn![0].matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
    expect(literals).toHaveLength(3);
    expect(vaultTsx).toContain(asTemplate(literals[0]!));
    expect(vaultTsx).toContain("`" + literals[1]! + "`");
    expect(vaultTsx).toContain("`" + literals[2]! + "`");
  });

  it("carries the proof-less leave sentence byte-equal to the canon", () => {
    const m = householdKt.match(/fun leftUnprovenNotice\(vaultName: String\): String = "([^"]+)"/);
    expect(m, "HouseholdCopy.leftUnprovenNotice moved or was renamed — update the pin").not.toBeNull();
    expect(vaultTsx).toContain(asTemplate(m![1]!));
  });
});

/** A7 review MEDIUM-2 / LOW-3: the already-recorded (both kinds) and legacy-removal sentences, byte-equal to core. */
describe("Vault.tsx A7 review notices — the core HouseholdCopy twins", () => {
  for (const fn of ["removalAlreadyRecordedNotice", "leftAlreadyRecordedNotice", "removedLegacyNotice"]) {
    it(`carries ${fn} byte-equal to the canon`, () => {
      const m = householdKt.match(new RegExp(`fun ${fn}\\(vaultName: String\\): String = "([^"]+)"`));
      expect(m, `HouseholdCopy.${fn} moved or was renamed — update the pin`).not.toBeNull();
      expect(vaultTsx).toContain(asTemplate(m![1]!));
    });
  }
});

/**
 * Root cause A §5.1 (branch A1b): the item-home sentences live in core HouseholdCopy and the natives render them
 * directly; web's twins are pinned byte-equal here. The two reauth sentences (A6b carry-forward) are the error messages
 * of store.ts's ReauthFailedError / ReauthStaleSessionError, and the INV-EDIT refusal is itemhome.ts's constant.
 */
describe("A1b item home + reauth copy — the core HouseholdCopy twins", () => {
  const storeTs = readFileSync(here("../vault/store.ts"), "utf8");
  const accountTs = readFileSync(here("../vault/account.ts"), "utf8"); // A9: ReauthStaleSessionError lives beside reauthAuthKey
  const itemHomeTs = readFileSync(here("../vault/itemhome.ts"), "utf8");
  const kt = (name: string): string => {
    const m = householdKt.match(new RegExp(`const val ${name}(?:: String)? =\\s*"([^"]+)"`));
    expect(m, `HouseholdCopy.${name} moved — update the pin`).not.toBeNull();
    return m![1]!;
  };

  it("wrong-vault carries HouseholdCopy.WRONG_VAULT_NOTICE byte-equal", () => {
    expect(vaultTsx).toContain(JSON.stringify(kt("WRONG_VAULT_NOTICE")));
  });

  it("the INV-EDIT refusal is HouseholdCopy.ITEM_CHANGED_VAULTS byte-equal", () => {
    expect(itemHomeTs).toContain(`export const ITEM_CHANGED_VAULTS = ${JSON.stringify(kt("ITEM_CHANGED_VAULTS"))};`);
  });

  it("the stale-salt reauth says how to recover, byte-equal with HouseholdCopy.REAUTH_STALE_SESSION", () => {
    expect(kt("REAUTH_STALE_SESSION")).toBe("Lock and unlock andvari, then try again.");
    expect(accountTs).toContain(`super(${JSON.stringify(kt("REAUTH_STALE_SESSION"))});`);
    expect(storeTs).toContain("export { ReauthFailedError, ReauthStaleSessionError };");
  });

  it("the wrong-password reauth is HouseholdCopy.REAUTH_FAILED byte-equal", () => {
    expect(accountTs).toContain(`super(${JSON.stringify(kt("REAUTH_FAILED"))});`); // A9 review: beside reauthAuthKey
    expect(storeTs).toContain("export { ReauthFailedError, ReauthStaleSessionError };");
  });

  it("the no-personal-vault refusal is HouseholdCopy.NO_PERSONAL_VAULT byte-equal (A9 review LOW-2)", () => {
    expect(kt("NO_PERSONAL_VAULT")).toBe("Choose a vault for this item.");
    expect(storeTs).toContain(`super(${JSON.stringify(kt("NO_PERSONAL_VAULT"))});`);
  });
});
