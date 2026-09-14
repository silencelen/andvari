import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H137 (audit 2026-09-13): the web app shipped with NO print stylesheet, so Ctrl+P printed a
 * revealed password, the live one-time code, a card number and the whole Vault-health table
 * verbatim. Print is not screen: the job crosses a queue on a machine the vault knows nothing
 * about (frequently a shared or networked one) and the PDF path drops the same plaintext into a
 * file andvari never sees again. Pinned on the stylesheet — the app renders perfectly with this
 * missing, so no runtime check can catch a regression; only reading the CSS can (the
 * contrast.test.ts / styles-affordance.test.ts idiom).
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const css = readFileSync(here("./styles.css"), "utf8");

/** The body of the `@media print` block (brace-matched — the block contains nested rules). */
function printBlock(): string {
  const start = css.indexOf("@media print");
  expect(start, "styles.css has no @media print block").toBeGreaterThan(-1);
  let depth = 0;
  for (let i = css.indexOf("{", start); i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) return css.slice(start, i + 1);
  }
  throw new Error("unterminated @media print block");
}

describe("H137 — secrets are blanked on paper", () => {
  const block = printBlock();

  it("hides every surface that renders a secret: reveals, the live code, notes, and the tables", () => {
    // The selector list that carries `visibility: hidden`.
    const hidden = /([^{}]*)\{\s*visibility:\s*hidden;?\s*\}/.exec(block);
    expect(hidden, "no `visibility: hidden` rule in @media print").toBeTruthy();
    const selectors = hidden![1]!;
    for (const sel of [".secret-row input", ".secret-row textarea", "textarea", ".totp", ".table", ".qr-card"]) {
      expect(selectors, `${sel} must be blanked when printing`).toContain(sel);
    }
  });

  it("blanks the QR plates too — a printed QR is a machine-readable copy of the same secret", () => {
    // The TOTP enrollment QR encodes the otpauth URI (seed and all) and the admin enroll QR encodes
    // a live invite token. Blanking their text rows while printing the picture is strictly worse
    // than printing the text: a scanner reads it and a human proof-reading the sheet cannot tell.
    const hidden = /([^{}]*)\{\s*visibility:\s*hidden;?\s*\}/.exec(block)![1]!;
    expect(hidden, ".qr-card must be blanked when printing").toContain(".qr-card");
    // QrSvg owns the wrapper, so one selector covers every call site — and every QR in the app is
    // rendered through it, so no surface can hand-roll a bare <svg> outside the blanked ancestor.
    // If QrSvg ever drops the wrapper this goes red rather than silently printing a scannable secret.
    const qr = readFileSync(here("./QrSvg.tsx"), "utf8");
    expect(qr, "QrSvg must keep rendering the .qr-card wrapper the print rule targets").toContain(
      'className="qr-card"',
    );
  });

  it("blanks by visibility, not display — the printed page shows the field with an obvious gap", () => {
    // display:none would silently re-flow the page into something that looks complete.
    expect(block).toContain("visibility: hidden");
    expect(block).not.toMatch(/\.secret-row input[^{]*\{[^}]*display:\s*none/);
  });

  it("keeps the ONE exception visible: the recovery phrase, which printing is a way to save", () => {
    expect(block).toMatch(/\.print-keep,\s*\n?\s*\.print-keep \*\s*\{\s*visibility:\s*visible/);
  });

  it("the exception is applied by hand at the reveal, never by a blanket selector", () => {
    const welcome = readFileSync(here("./Welcome.tsx"), "utf8");
    expect(welcome).toContain('className="mono print-keep"');
    // Exactly one surface claims it — an exception that spreads stops being an exception.
    expect(welcome.match(/className="[^"]*print-keep/g)?.length).toBe(1);
    for (const file of ["Vault.tsx", "Health.tsx", "Staleness.tsx", "Admin.tsx", "Settings.tsx"]) {
      expect(readFileSync(here(`./${file}`), "utf8"), `${file} must not opt out of print blanking`).not.toMatch(
        /className="[^"]*print-keep/,
      );
    }
  });

  it("a print-only notice explains the blanks, and never shows on screen", () => {
    expect(block).toMatch(/\.print-note\s*\{[^}]*display:\s*block/);
    expect(css).toMatch(/\.print-note\s*\{\s*display:\s*none;?\s*\}/);
    // ORDER, not presence: a media query adds no specificity, so the screen rule and the print
    // override both match at (0,1,0) in the print medium and source order decides. Declared after
    // the block, `display: none` wins and the notice never prints — which is exactly the bug this
    // pins. Asserting only that both rules exist keeps that regression green, so assert the order.
    expect(
      css.lastIndexOf(".print-note { display: none"),
      "the screen `display: none` must be declared BEFORE the print block, or it beats the print override",
    ).toBeLessThan(css.indexOf("@media print"));
    const app = readFileSync(here("./App.tsx"), "utf8");
    expect(app).toContain('className="print-note"');
    expect(app).toContain("Secrets are hidden when printing");
  });
});
