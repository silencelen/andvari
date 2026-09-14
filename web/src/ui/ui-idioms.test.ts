import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H132 + H133 (audit 2026-09-13): the web app said the same three things in several voices.
 *
 *  - WAITING was four idioms: the shared `<Busy>` dial on some views, a bare `<p className="muted">`
 *    on others, and the label itself spelled "loading…", "Loading…", "Checking…" and
 *    "syncing your vault…" depending on who wrote the view. The same wait therefore looked like
 *    progress on one screen and like a hang on the next — and the longest of them (the export's
 *    pre-sync, a full store.sync()) was one of the ones showing nothing moving.
 *  - EMPTY was two idioms: `.empty` + the sigil + a full sentence on the views the UI-audit
 *    touched, and a bare `.muted` line on Trash, version history and the audit log.
 *  - The BACK affordance was two glyphs and two casings ("← back to vault" vs "‹ Back to vaults").
 *
 * None of it is a bug and all of it is why a 1.0 reads as several hands. These pins are DERIVED
 * from the sources rather than hand-listed (the R05 lesson in styles-affordance.test.ts: a hand
 * list goes stale the moment someone adds a fifth call site and stays green while doing it).
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const files = readdirSync(here("./")).filter((f) => f.endsWith(".tsx"));
const src = (f: string) => readFileSync(here(`./${f}`), "utf8");
/** Source with comments removed — these pins are about what the app RENDERS, and every one of
 *  these notes quotes the retired string it exists to explain. Line comments are matched only at
 *  the start of a line so a `https://` inside JSX is never mistaken for one. */
const code = (f: string) =>
  src(f)
    .replace(/\/\*[^]*?\*\//g, "")
    .replace(/^\s*\/\/[^\n]*$/gm, "");

describe("H132 — one waiting idiom: the Busy dial, sentence case", () => {
  it("every wait label is inside <Busy> — a bare muted line is the idiom this replaced", () => {
    // Any occurrence of a wait label must be immediately preceded by the Busy open tag (or be
    // the expression inside one, e.g. `{busy ? <Busy>…`). Scanning for the LABELS (not the
    // component) is what makes a newly hand-rolled wait fail here.
    // Case-INSENSITIVE (R05): the editor's breach check hand-rolled `setStatus("checking…")` and
    // sailed through a case-sensitive list — the pin missed the exact idiom it exists to catch,
    // twice over, because the label was lower case AND lived in a string literal rather than JSX
    // text. Matching any casing means a newly hand-rolled wait fails here whichever way it is spelt.
    const label = /(?:Loading|Checking|Unsealing|Syncing your vault|Saving your confirmation|Preparing your recovery phrase)…/gi;
    for (const f of files) {
      const s = code(f);
      for (const m of s.matchAll(label)) {
        // Inside a <Busy> means: an unclosed open tag stands before this label (the ternary form
        // `<Busy>{a ? "x…" : "y…"}</Busy>` puts the second label well past the tag).
        const before = s.slice(0, m.index!);
        // The ONE carve-out, and it is the house rule rather than an escape hatch: Busy.tsx says
        // the dial is aria-hidden and "async announcements stay on the persistent Announcer idiom
        // (BL-1)", so a wait that is announced spells its label twice — once in the dial the eye
        // sees and once in the live region AT hears. A label inside an `<Announcer …/>` tag is
        // therefore the SAME wait, not a second hand-rolled one.
        if (before.lastIndexOf("<Announcer") > before.lastIndexOf("/>")) continue;
        const open = before.lastIndexOf("<Busy>");
        const close = before.lastIndexOf("</Busy>");
        expect(open > close, `${f}: "${m[0]}" is not wrapped in <Busy>`).toBe(true);
      }
    }
  });

  it("one casing — no view says 'loading…' or 'unsealing…' in lower case any more", () => {
    for (const f of files) {
      // R05: string literals as well as JSX text. `setStatus("checking…")` is exactly how the
      // idiom came back, and a pin that only looked at `>label…` could not see it.
      expect(code(f), `${f}: lower-case wait label`).not.toMatch(/["'>](loading|unsealing|checking|syncing|preparing)…/);
    }
  });
});

describe("H132 — one empty-state idiom: the Empty component", () => {
  it("no view hand-rolls `className=\"empty\"` — they all go through <Empty>", () => {
    for (const f of files) {
      if (f === "Empty.tsx") continue;
      expect(src(f), `${f}: hand-rolled empty state`).not.toContain('className="empty"');
    }
  });

  it("Empty owns the sigil, so no caller can ship an empty state without one", () => {
    const empty = src("Empty.tsx");
    expect(empty).toContain("EmptySigil");
    expect(empty).toContain('className="empty"');
  });

  it("the views that had bare `.muted` empties now use it (Trash, version history, audit log)", () => {
    expect(src("Vault.tsx")).toContain("<Empty><p>Nothing here — deleted items you can recover will show up in this list.</p></Empty>");
    expect(src("Vault.tsx")).toContain("<Empty><p>No earlier versions yet — history starts from the next change.</p></Empty>");
    expect(src("Admin.tsx")).toContain("<Empty><p>No audit events");
  });

  it("every empty-state sentence ends in terminal punctuation", () => {
    // The popup's un-punctuated empties are the extension half of H133; on web the rule holds
    // for every sentence handed to <Empty>.
    for (const f of files) {
      const s = src(f);
      for (const m of s.matchAll(/<Empty>[^]*?<\/Empty>/g)) {
        for (const p of m[0].matchAll(/<p>([^<{]+)<\/p>/g)) {
          expect(p[1]!.trim(), `${f}: empty-state sentence without terminal punctuation`).toMatch(/[.!?]$/);
        }
      }
    }
  });
});

describe("H133 — one back affordance", () => {
  it("the old arrow glyph is gone from every view", () => {
    for (const f of files) {
      expect(code(f), `${f}: still uses the ← back glyph`).not.toContain("←");
    }
  });

  it("BackLink is the only definition of the glyph, and the sites use it", () => {
    expect(src("BackLink.tsx")).toContain('export const BACK_GLYPH = "‹";');
    for (const f of files) {
      if (f === "BackLink.tsx" || f === "Vault.tsx") continue; // Vault's Editor cancel composes it
      expect(code(f), `${f}: hard-codes the back glyph instead of using BackLink`).not.toContain("‹");
    }
    for (const [file, label] of [
      ["Vault.tsx", 'label="Back to vault"'],
      ["ExportPanel.tsx", 'label="Back to vault"'],
      ["Sharing.tsx", 'label="Back to vaults"'],
      ["Settings.tsx", 'label="Back to settings"'],
    ] as const) {
      expect(src(file)).toContain(`<BackLink ${label}`);
    }
  });
});

describe("H133 — initialisms in the audit table read as initialisms", () => {
  it("the admin audit headers are ID and IP, not Id and Ip", () => {
    const admin = src("Admin.tsx");
    expect(admin).toContain("<th>ID</th>");
    expect(admin).toContain("<th>IP</th>");
    expect(admin).not.toContain("<th>Id</th>");
    expect(admin).not.toContain("<th>Ip</th>");
  });
});
