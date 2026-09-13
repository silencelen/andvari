import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Three stylesheet rules from the 2026-09-13 audit (H49, H51, H52) that no runtime check can
 * catch — the app renders, only the paint is wrong — pinned on styles.css the contrast.test.ts
 * way, plus the Field opt-in that makes a sentence-length label render as a sentence.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const css = readFileSync(here("./styles.css"), "utf8");
/** The declaration body of the first rule whose selector list matches `selector` exactly. */
function rule(selector: string): string {
  const m = new RegExp(`(^|\\n)${selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\{([^}]*)\\}`).exec(css);
  expect(m, `rule "${selector}" is missing from styles.css`).toBeTruthy();
  return m![2]!;
}

describe("H49 — the caption caps are scoped OUT of sentence-length labels", () => {
  it("the element rule still carries the caption paint (short captions keep it)", () => {
    expect(rule("label")).toContain("text-transform: uppercase");
  });

  it(".check / .inline-check / label.prompt reset text-transform and letter-spacing", () => {
    const body = rule(".check, .inline-check, label.prompt");
    expect(body).toContain("text-transform: none");
    expect(body).toContain("letter-spacing: 0");
  });

  it("every sentence-length Field prompt opts in — DERIVED from the sources, so a new long label fails here instead of slipping past", () => {
    // R05: the hand-listed version of this pin named three labels while the H49 evidence had
    // five; the fifth (Admin.tsx's recovery-sheet confirm) shipped without the opt-in and the
    // pin stayed green. Scan every `label="…"` in src/ui/*.tsx instead: anything over the caption
    // length must carry `prompt` in its opening tag. The threshold sits above the longest caption
    // ("Per item", "Display name", …) and below the shortest sentence in the set.
    const SENTENCE_LEN = 45;
    const found: string[] = [];
    for (const file of readdirSync(here("./")).filter((f) => f.endsWith(".tsx"))) {
      const src = readFileSync(here(`./${file}`), "utf8");
      for (const m of src.matchAll(/label="([^"]*)"/g)) {
        if (m[1]!.length <= SENTENCE_LEN) continue;
        found.push(`${file}: ${m[1]}`);
        const tagStart = src.lastIndexOf("<", m.index!);
        const tagEnd = src.indexOf(">", m.index! + m[0].length);
        const tag = src.slice(tagStart, tagEnd + 1);
        expect(tag, `${file}: sentence-length label must carry the prompt opt-in — ${m[1]}`).toMatch(/\sprompt(?=[\s>])/);
      }
    }
    // The five the H49 evidence enumerated are all still in the scan (a threshold change that
    // silently drops them would make the loop above vacuous for exactly the labels it exists for).
    for (const known of [
      "Vault.tsx: Type the FIRST 16 characters of the fingerprint on your printed recovery sheet",
      "Welcome.tsx: Recovery check — type the FIRST 16 characters of the fingerprint on your printed recovery sheet",
      "Welcome.tsx: Type your recovery phrase back to confirm you saved it",
      "Admin.tsx: Confirm your recovery sheet (first 16 characters) to stamp a scannable code into the QR",
      "Admin.tsx: KDF (read-only — changing it requires a coordinated re-enrollment)",
    ]) {
      expect(found, known).toContain(known);
    }
    const sharing = readFileSync(here("./Sharing.tsx"), "utf8");
    expect(sharing).toContain('<label className="prompt" style={{ marginTop: 10 }}>Type the vault\'s name to delete it:</label>');
  });

  it("Field forwards the opt-in as label.prompt", () => {
    const field = readFileSync(here("./Field.tsx"), "utf8");
    expect(field).toContain('<label htmlFor={id} className={prompt ? "prompt" : undefined}>');
  });
});

describe("H51 — every disabled control looks and hovers disabled, not just button.primary", () => {
  it("ghost buttons and link-buttons carry the primary's opacity + cursor treatment", () => {
    const body = rule("button.ghost:disabled, .link:disabled");
    expect(body).toContain("opacity: 0.55");
    expect(body).toContain("cursor: not-allowed");
  });

  it("the hover lift is pinned back to the resting colours while disabled", () => {
    expect(rule("button.ghost:disabled:hover")).toContain("color: var(--ink-dim)");
    expect(rule("button.ghost:disabled:hover")).toContain("border-color: var(--edge)");
    expect(rule(".link:disabled:hover")).toContain("text-decoration: none");
  });

  it("inputs, selects and textareas — whose author colours override the UA greying — get their own rule", () => {
    const body = rule("input:disabled, select:disabled, textarea:disabled");
    expect(body).toContain("opacity: 0.6");
    expect(body).toContain("cursor: not-allowed");
  });

  it("the primary's own rule is untouched (the sibling that was right)", () => {
    expect(rule("button.primary:disabled")).toContain("filter: saturate(0.3)");
  });
});

describe("H52 — placeholders are painted with --ink-dim (the popup's a11y 7b rule, ported)", () => {
  it("input and textarea placeholders name the token, at full opacity", () => {
    const body = rule("input::placeholder, textarea::placeholder");
    expect(body).toContain("color: var(--ink-dim)");
    expect(body).toContain("opacity: 1");
  });

  it("the popup twin still carries its own rule (lockstep by convention)", () => {
    const popup = readFileSync(here("../../../extension/popup.css"), "utf8");
    expect(popup).toMatch(/input::placeholder\s*\{[^}]*var\(--ink-dim\)/);
  });

  it("no view re-colours a placeholder inline (the rule is the one source)", () => {
    for (const f of readdirSync(here(".")).filter((f) => f.endsWith(".tsx"))) {
      expect(readFileSync(here(`./${f}`), "utf8"), f).not.toMatch(/::placeholder/);
    }
  });
});
