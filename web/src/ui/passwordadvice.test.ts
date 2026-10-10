import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { passwordAdvice } from "./passwordadvice";
import { PATTERN_WARNING } from "./strength";

/**
 * Audit F31, the WIRING half.
 *
 * The estimator and the pattern collapse shipped with tests and did not reach a user: the gate
 * and the label became different functions without anyone reconciling what the hint SAYS. These
 * pin what the hint decides, plus the four call sites, because "the module is correct" was
 * already true when it did nothing. (The breach half of F31 — a k-anonymity lookup on these
 * fields — was removed in security review 2026-10; master-breach-no-relay.test.ts pins that.)
 */

describe("passwordAdvice — the gate and the label can no longer contradict each other", () => {
  it("a pattern-weak password that CLEARS the floor is never affirmed", () => {
    // The F31 exemplar: raw proxy 4 (so the master-password gate passes, by design — a stricter
    // estimate must never lock someone out of changing their password), pattern-aware 2.
    const a = passwordAdvice("Password1!Password1!");
    expect(a.meetsFloor).toBe(true); // still submittable — this warns, it does not block
    expect(a.label).toBe("fair"); // the honest label, not the proxy's "strong"
    expect(a.pattern).toBe(PATTERN_WARNING);
    expect(a.affirmed).toBe(false); // ← the defect: it used to render "strength: fair ✓"
  });

  it("a clean, strong password still gets the affirmative treatment", () => {
    const a = passwordAdvice("correct-horse-battery-staple");
    expect(a).toMatchObject({ meetsFloor: true, affirmed: true, pattern: null, nonAscii: false });
  });

  it("below the floor is a refusal, not a caution — the affirmation is off for a different reason", () => {
    const a = passwordAdvice("hunter2");
    expect(a.meetsFloor).toBe(false);
    expect(a.affirmed).toBe(false);
  });

  it("the two roles keep their different floors (strength.ts module doc)", () => {
    // A pattern-weak passphrase clears the MASTER floor (pre-pattern proxy) and misses the
    // BACKUP one (pattern-aware estimate) — deliberately opposite directions.
    expect(passwordAdvice("Password1!Password1!", "master").meetsFloor).toBe(true);
    expect(passwordAdvice("Password1!Password1!", "backup").meetsFloor).toBe(false);
  });

  it("non-ASCII is reported but never withholds the affirmation (spec 01 §1 SHOULD-warn)", () => {
    const a = passwordAdvice("café-très-long-passphrase-2024");
    expect(a.nonAscii).toBe(true);
    expect(a.affirmed).toBe(true);
  });
});

/**
 * The call sites — pinned on their source (the trash-purge/health-rows idiom; these cards read
 * window/module singletons and cannot render in the node env).
 */
describe("F31 — every surface where a master password or backup passphrase is CHOSEN", () => {
  const src = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf8");
  const welcome = src("./Welcome.tsx");
  const settings = src("./Settings.tsx");
  const recover = src("./Recover.tsx");
  const exportPanel = src("./ExportPanel.tsx");
  const vault = src("./Vault.tsx");

  it("enrollment, change-password and the recovery reset all render the shared hint", () => {
    expect(welcome).toContain("<MasterPasswordHint password={password} />");
    expect(settings).toContain("<MasterPasswordHint password={next} />");
    expect(recover).toContain("<MasterPasswordHint password={password} />");
    // …and all three take it from the one component, so a fix lands on all three at once.
    for (const [name, s] of [["Welcome", welcome], ["Settings", settings], ["Recover", recover]] as const) {
      expect(s, `${name} must import the shared hint`).toContain('from "./passwordadvice"');
    }
  });

  it("the backup passphrase gets the same pattern caution", () => {
    expect(exportPanel).toContain('const advice = passwordAdvice(pw, "backup");');
    expect(exportPanel).toContain("<PasswordCautions advice={advice} />");
  });

  it("the backup bar withholds green for a caution, but never promotes a below-floor passphrase", () => {
    // `!advice.affirmed` alone would paint a score-0 passphrase gold — softer than the red it
    // already earned. The caution is a DEMOTION from the affirmative, so it is gated on the floor.
    expect(exportPanel).toContain("<StrengthBar password={pw} caution={advice.meetsFloor && !advice.affirmed} />");
  });

  it("the item-password bar's divergence from its declared twin is a decision, not drift", () => {
    // Vault's editor bar is the original the export panel copied, and it takes NO `caution`. It
    // renders no caution SENTENCE either — an item password's breach exposure is on demand
    // (HealthLine / the Health panel), not bound to the field — so holding the bar out of green
    // would be a signal with nothing beside it to explain itself. Pinned with the reasoning it
    // carries, because the next reader's instinct will be to "fix" the drift.
    expect(vault).toContain("function StrengthBar({ password }: { password: string }) {");
    expect(vault).toContain("<StrengthBar password={login.password} />");
    expect(vault).toContain("deliberately does NOT take");
  });

  it("nothing on these surfaces blocks on a caution — the floors are unchanged", () => {
    // The gates stay exactly what they were; F31 may only add sentences.
    expect(welcome).toContain("const pwStrongEnough = meetsMasterPasswordFloor(password);");
    expect(settings).toContain("const canSubmit = current && meetsMasterPasswordFloor(next) && next === confirm;");
    expect(recover).toContain("const pwStrongEnough = meetsMasterPasswordFloor(password);");
    expect(exportPanel).toContain("const passOk = pw.length > 0 && strength >= BACKUP_FLOOR && pw === confirm;");
  });
});
