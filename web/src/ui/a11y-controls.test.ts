import { readdirSync, readFileSync } from "node:fs";
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

/**
 * Audit F10 — every text input has an accessible name. The two recovery gates (Vault's
 * ReSealBanner, Welcome's shown-once type-back) and Admin's invite/link boxes shipped with a bare
 * `<label>` beside an `<input>`: no `htmlFor`, no `aria-label`, no `Field` wrapper, so in forms
 * mode a screen reader hears "edit, blank" at three one-shot, high-consequence prompts. The house
 * already has both idioms — `Field` for a lone labelable control, an `aria-label` on the inner
 * input of a multi-child `.secret-row` (BL-2) — so this is a scan, not a judgement call.
 * WCAG 1.3.1 / 3.3.2 / 4.1.2.
 */
describe("F10 — no unnamed <input> anywhere under web/src/ui", () => {
  const files = readdirSync(fileURLToPath(new URL(".", import.meta.url)))
    .filter((f) => f.endsWith(".tsx"))
    .sort();

  it("scans every view file (guard: the scan itself must not silently cover nothing)", () => {
    expect(files.length).toBeGreaterThan(10);
    expect(files).toContain("Vault.tsx");
    expect(files).toContain("Welcome.tsx");
    expect(files).toContain("Admin.tsx");
  });

  for (const file of files) {
    it(`${file} names every input (Field wrapper, wrapping <label>, or aria-label)`, () => {
      const lines = readFileSync(here(`./${file}`), "utf8").split("\n");
      const unnamed: string[] = [];
      // Depth-track the two wrappers that name a control implicitly: <Field> (injects htmlFor)
      // and a wrapping <label> (the .check checkbox rows). Neither is ever self-closing.
      let fieldDepth = 0;
      let labelDepth = 0;
      lines.forEach((line, i) => {
        fieldDepth -= (line.match(/<\/Field>/g) ?? []).length;
        labelDepth -= (line.match(/<\/label>/g) ?? []).length;
        const opensField = (line.match(/<Field\b/g) ?? []).length;
        const opensLabel = (line.match(/<label\b/g) ?? []).length;
        if (line.includes("<input")) {
          // The whole tag, which may span lines up to its "/>".
          let tag = "";
          for (let j = i; j < lines.length; j++) {
            tag += lines[j] + " ";
            if (lines[j]!.includes("/>")) break;
          }
          const named = tag.includes("aria-label") || tag.includes("aria-labelledby");
          if (!named && fieldDepth + opensField <= 0 && labelDepth + opensLabel <= 0) {
            unnamed.push(`${file}:${i + 1} ${line.trim().slice(0, 80)}`);
          }
        }
        fieldDepth += opensField;
        labelDepth += opensLabel;
      });
      expect(unnamed, "an input with no accessible name — wrap it in Field or give it an aria-label").toEqual([]);
    });
  }

  it("the two one-shot recovery gates are wrapped in Field, not a bare label", () => {
    // Vault's re-seal banner (the household recovery key rotated) …
    expect(vaultTsx).toContain('label="Type the FIRST 16 characters of the fingerprint on your printed recovery sheet"');
    expect(vaultTsx).not.toContain("<label>Type the FIRST 16 characters");
    // … and the shown-once phrase type-back, which blocks entry to the vault entirely.
    expect(welcomeTsx).toContain('label="Type your recovery phrase back to confirm you saved it"');
    expect(welcomeTsx).not.toContain("<label>Type your recovery phrase back");
  });

  it("a <label> heading no control at all is a heading, not a label", () => {
    const stylesHasHead = stylesCss.includes(".field-head {");
    expect(stylesHasHead, ".field-head must exist — it is what these headings paint with").toBe(true);
    const adminTsx = readFileSync(here("./Admin.tsx"), "utf8");
    const exportTsx = readFileSync(here("./ExportPanel.tsx"), "utf8");
    const sharingTsx = readFileSync(here("./Sharing.tsx"), "utf8");
    expect(adminTsx).toContain('<div className="field-head" style={{ marginBottom: 8 }}>Minimum client versions</div>');
    expect(exportTsx).toContain('<div className="field-head">What gets exported</div>');
    expect(sharingTsx).toContain('className="field-head">{found.displayName}\'s identity code</div>');
    expect(welcomeTsx).toContain('<div className="field-head">Your recovery phrase</div>');
  });
});

/**
 * Audit F11 — the signed-in app had no landmarks but `nav`, no `<h1>`, and no skip link, so AT
 * had no "main" to jump to and heading navigation started at level 2 with nothing naming the
 * page. The extension's own options page already ships header/main/section + h1; this is the web
 * twin of that shape. WCAG 2.4.1 / 1.3.1 / 2.4.6.
 */
describe("a11y F11 — landmarks, one page heading, and a skip link", () => {
  it("the appbar is a <header> and the content container is the app's <main>", () => {
    expect(vaultTsx).toContain('<header className="appbar">');
    // G28: tabIndex={-1} is what lets the intercepted skip link focus() the landmark directly.
    expect(vaultTsx).toContain('<main className="wrap" id={MAIN_ID} tabIndex={-1}>');
    expect(vaultTsx).not.toContain('<div className="appbar">');
  });

  it("the skip link is the first focusable node and reveals itself on focus", () => {
    // G28: the activation is INTERCEPTED — a default #main-content jump would clobber the route
    // fragment (routes.ts reads any non-#/ hash as the vault list, so refresh loses your place)
    // and mint a history entry outside useBackGuard's sentinel accounting.
    expect(vaultTsx).toContain(
      '<a className="skip-link" href={`#${MAIN_ID}`} onClick={(e) => { e.preventDefault(); document.getElementById(MAIN_ID)?.focus(); }}>Skip to content</a>',
    );
    expect(stylesCss).toContain(".skip-link:focus");
  });

  it("each view's title is the <h1> — ViewHeader owns it, and the two title-less branches supply their own", () => {
    const viewHeader = readFileSync(here("./ViewHeader.tsx"), "utf8");
    expect(viewHeader).toContain('<h1 className="view-title">{title}</h1>');
    expect(code(viewHeader), "the title must not fall back to an <h2>").not.toContain("<h2 className=\"view-title\">");
    expect(vaultTsx).toContain('<h1 className="visually-hidden">{VIEW_TITLES[view]}</h1>');
  });

  it("the tab title tracks the mounted view instead of being 'andvari' everywhere", () => {
    expect(vaultTsx).toContain('document.title = view === "vault" ? "andvari" : `${VIEW_TITLES[view]} · andvari`');
  });
});

/**
 * Audit F12 — Msg.tsx states the rule: an info box mounting already-populated is NOT reliably
 * announced, so async info surfaces drive a persistent <Announcer>. Every view file paired them
 * except the three that set an info message from an awaited handler: Health's duplicate merge
 * (shipped the day before the audit), Recover's verify→reset step change, and Sharing's
 * rescue-copy confirmation. The class recurs with every new async surface, so pin the pairing
 * file-wide rather than per call site. WCAG 4.1.3.
 */
describe("a11y F12 — every file with an info message also mounts an Announcer", () => {
  const files = readdirSync(fileURLToPath(new URL(".", import.meta.url)))
    .filter((f) => f.endsWith(".tsx"))
    .sort();

  for (const file of files) {
    const src = readFileSync(here(`./${file}`), "utf8");
    if (!/<Msg kind="info"|className="msg info"/.test(code(src))) continue;
    it(`${file} pairs its info surface with a persistent live region`, () => {
      expect(src, "an async info message with no <Announcer> is silent to screen readers").toContain("<Announcer");
    });
  }

  it("the three that were missing it now have it, driven by the value that lands asynchronously", () => {
    expect(healthTsx).toContain('<Announcer text={msg && msg.kind === "info" ? msg.text : ""} />');
    expect(healthTsx).toContain('import { Announcer, Msg } from "./Msg"');
    const recoverTsx = readFileSync(here("./Recover.tsx"), "utf8");
    expect(recoverTsx).toContain('<Announcer text={step === "reset"');
    const sharingTsx = readFileSync(here("./Sharing.tsx"), "utf8");
    expect(sharingTsx).toContain("<Announcer text={copiedNote} />");
  });
});
