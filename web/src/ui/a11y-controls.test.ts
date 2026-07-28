import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Polish audit 2026-07-27, a11y:webext cut. Three controls whose ARIA contract was wrong in a
 * way no runtime check catches (the app renders correctly; only what AT is TOLD is broken), so
 * they are pinned on the source the trash-purge/token-lockstep way — the components are closures
 * inside 2000-line view files with no seam to render in this node env.
 *
 * Parity note: --6's target shape is the extension popup's own totpChip (popup.ts), which solved
 * the same problem first; the web side was the drifted twin, so the pin quotes the popup's
 * strings deliberately.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const healthTsx = readFileSync(here("./Health.tsx"), "utf8");
const vaultTsx = readFileSync(here("./Vault.tsx"), "utf8");
const welcomeTsx = readFileSync(here("./Welcome.tsx"), "utf8");
const stylesCss = readFileSync(here("./styles.css"), "utf8");

/**
 * Comments are stripped from every slice below: these pins assert the ABSENCE of shapes the
 * fixes removed, and each fix's own comment names the shape it removed. Line comments only —
 * nothing sliced here carries a `//` inside a string.
 */
function code(src: string): string {
  return src
    .replace(/\{\/\*[\s\S]*?\*\/\}/g, "")
    .split("\n")
    .filter((l) => !l.trim().startsWith("//"))
    .join("\n");
}

/** The Health table body, from the row map to the closing tbody. */
function healthRowSource(): string {
  const start = healthTsx.indexOf("{sorted.map((r) => {");
  const end = healthTsx.indexOf("</tbody>", start);
  expect(start, "Health's row map moved — update the pin").toBeGreaterThan(-1);
  return code(healthTsx.slice(start, end));
}

describe("a11y-webext--2 — Health rows keep table semantics", () => {
  it("the <tr> carries no role/name override (which orphaned every <td> and hid the row's data)", () => {
    const row = healthRowSource();
    expect(row).not.toContain('role="button"');
    expect(row).not.toContain("aria-label={`Open ");
    // A focusable <tr> with no role is its own defect — the affordance moved into the cell.
    expect(row).not.toContain("tabIndex={0}");
  });

  it("the first cell holds a real, natively-keyboard-operable button naming the item", () => {
    const row = healthRowSource();
    expect(row).toMatch(/<td>\s*<button type="button" className="link" onClick=/);
    expect(row).toContain("{r.name}");
    // The row-level pointer target survives, so the click affordance is unchanged for mice…
    expect(row).toContain('<tr key={r.itemId} className="rowlink" onClick=');
    // …and the in-cell button must not fire it twice.
    expect(row).toContain("e.stopPropagation()");
  });

  it("the row's focus style follows the focus INTO the cell", () => {
    // Nothing in the row is focusable any more, so :focus-visible on the <tr> would be dead CSS.
    expect(stylesCss).not.toContain(".table tr.rowlink:focus-visible");
    expect(stylesCss).toContain(".table tr.rowlink:focus-within");
  });
});

/** TotpView's source, sliced to the component that follows it. */
function totpSource(): string {
  const start = vaultTsx.indexOf("function TotpView(");
  const end = vaultTsx.indexOf("function HealthLine(", start);
  expect(start, "TotpView moved — update the pin").toBeGreaterThan(-1);
  expect(end, "HealthLine moved — update the pin").toBeGreaterThan(start);
  return code(vaultTsx.slice(start, end));
}

describe("a11y-webext--6 — the TOTP chip's name is stable, its countdown is readable", () => {
  it("the accessible name never carries the live code (it changed every 30 s, mid-focus)", () => {
    const src = totpSource();
    expect(src).not.toContain("aria-label={`One-time code ${code");
    expect(src).toContain('"Copy one-time code"'); // the extension popup's exact stable name
  });

  it("the digits are aria-hidden, exactly as the popup's .code span is", () => {
    expect(totpSource()).toMatch(/<span aria-hidden="true">\{code\.replace/);
  });

  it("seconds-left reaches AT as a description, not as a per-tick live region", () => {
    const src = totpSource();
    expect(src).toContain("aria-describedby={secsId}");
    expect(src).toMatch(/className="visually-hidden" id=\{secsId\}>\{remaining\} seconds left/);
    // The ring stays decorative — announcing it every second is the bug the description avoids.
    expect(src).toContain('<div className="ring" aria-hidden="true"');
  });

  it("an unreadable secret still says so in the name (the old name conveyed it by accident)", () => {
    expect(totpSource()).toContain('code === "invalid" ? "One-time code — unreadable"');
  });
});

describe("a11y-webext--11 — the ~6 s Argon2id unseal is not silent", () => {
  it("both password forms speak the busy state off a persistent polite region", () => {
    // Announcer must be UNCONDITIONAL (BL-1): a role=status mounted already-populated is silent.
    expect(welcomeTsx).toContain("const UNSEALING_NOTICE =");
    const announces = welcomeTsx.match(/<Announcer text=\{busy \? UNSEALING_NOTICE : ""\} \/>/g);
    expect(announces, "one for the Unlock card, one for Sign in").toHaveLength(2);
  });

  it("the visible half is the house busy affordance, not a bare label swap", () => {
    const busies = welcomeTsx.match(/busy \? <Busy>Unsealing…<\/Busy>/g);
    expect(busies).toHaveLength(2);
    expect(welcomeTsx).not.toContain('busy ? "Unsealing…"');
  });
});
