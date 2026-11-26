import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H117 (audit 2026-09-13): design 2026-08-22-login-health-staleness-verification §4 has promised,
 * since the owner ratified "four verdicts, not two" ("each maps to a different next action"),
 * that a `bad` verdict offers to open the item or generate a new password. Only `gone` (delete)
 * and `blocked` (snooze) ever shipped, so the user who told andvari the saved password was
 * REFUSED — the single most actionable thing the run can learn — was advanced to the next login
 * with no path back to the broken one. This pins both offers on the web run card; the Android
 * twin is built from the same design text and must carry the same two labels.
 *
 * Pinned on the source, not a render: Staleness's run card is a component closure with no seam
 * (the trash-purge / signout-revoke idiom), and the thing that regresses is the wiring.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const staleness = readFileSync(here("./Staleness.tsx"), "utf8");
const vault = readFileSync(here("./Vault.tsx"), "utf8");

describe("H117 — the post-'Wrong password' offer row", () => {
  it("a `bad` verdict arms the offer, and every other verdict clears it", () => {
    expect(staleness).toContain('setOfferBad(result === "bad" ? itemId : null);');
    // The gone offer keeps its own slot and is likewise exclusive — one "what now?" at a time.
    expect(staleness).toContain('setOfferDelete(result === "gone" ? itemId : null);');
  });

  it("offers exactly the two follow-ups the design names, plus a way out", () => {
    expect(staleness).toContain("Open the item");
    expect(staleness).toContain("Generate a new password");
    expect(staleness).toContain("Not now");
  });

  it("the sentence NAMES the login — the card has already advanced to the next one (G27)", () => {
    expect(staleness).toContain(
      '`“${badName}” is marked as having the wrong password. Change it?`',
    );
  });

  it("the offer is announced — a conditionally-mounted row is silent to a screen reader (BL-1)", () => {
    const announcer = staleness.slice(staleness.indexOf("<Announcer"), staleness.indexOf("H30: the run's position"));
    expect(announcer).toContain("badSentence");
  });

  it("neither offer writes anything: one opens the item, the other opens its editor", () => {
    expect(staleness).toContain("onClick={() => onOpenItem(offerBad)}");
    expect(staleness).toContain("onClick={() => onOpenItem(offerBad, { generate: true })}");
    // The doctrine this view exists to hold: andvari never changes a password on the site, and
    // never saves a new one here without the user pressing Save.
    expect(staleness).not.toMatch(/generatePassword\(/);
  });

  it("Vault honours the generate leg by opening the EDITOR with a fresh password, login items only", () => {
    const goTo = vault.slice(vault.indexOf("const goToItem = "), vault.indexOf("const navBtn = "));
    expect(goTo).toContain("if (opts?.generate)");
    expect(goTo).toContain('it.doc.type === "login"');
    expect(goTo).toContain("setEditorGenerate(true)");
    // The editor generates once at mount and says so; nothing is persisted until Save.
    expect(vault).toContain("if (!generateOnOpen || !isLogin) return;");
    expect(vault).toContain("a new password is ready — change it on the site, then press Save to keep it here");
  });

  // R03/R14/R15: this file also pinned the Android twin (the same sentence, the same three labels
  // and a "Generate a new password" that really generates), because both clients once wrote this
  // offer from the design text and drifted apart. That half is retired for now: the old Android
  // health screen was deleted when the app moved to the new design's screens, which show visible
  // placeholders until the product's wording is approved. The behaviour is tested on Android's side
  // (the new health screen's own tests: the refused-password offer opens the item, or its editor
  // with a new password shown and not saved). Bring the wording half back here, against the new
  // screen or one shared sentence, when the approved wording lands on Android.

  it("the generate flag cannot leak into the NEXT editor the user opens", () => {
    // closeLayers (every navigation), Cancel and a completed save all clear it — otherwise the
    // next "+ Login" would silently arrive pre-generated.
    expect(vault).toContain("setEditing(null);\n    setEditorGenerate(false);");
    expect(vault).toContain("onCancel={() => { setEditing(null); setEditorGenerate(false); }}");
    expect(vault).toContain("setEditorGenerate(false);\n    setEditing(null);");
  });
});
