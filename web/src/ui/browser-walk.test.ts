import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Faults the 2026-11-16 walk of every screen in a real browser found, each pinned where a source or a function can
 * hold it (the walk itself drives headless Chrome against a test server and lives outside the repository).
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const read = (p: string) => readFileSync(here(p), "utf8");
const css = read("./styles.css");

/** The body of the block opened by [head] (brace-matched). */
function block(src: string, head: string, from = 0): string {
  const start = src.indexOf(head, from);
  expect(start, `no ${head}`).toBeGreaterThan(-1);
  let depth = 0;
  for (let i = src.indexOf("{", start); i < src.length; i++) {
    if (src[i] === "{") depth++;
    else if (src[i] === "}" && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(`unterminated ${head}`);
}

describe("every button has a style of its own", () => {
  it("no <button> in the UI is left without a class (it would fall to the browser's small grey button)", () => {
    const bare: string[] = [];
    for (const f of readdirSync(here(".")).filter((n) => n.endsWith(".tsx"))) {
      const src = read(`./${f}`);
      for (const m of src.matchAll(/<button\b((?:=>|[^>])*)>/g)) {
        const attrs = m[1]!;
        const line = src.slice(0, m.index).split("\n").length;
        const lineStart = src.lastIndexOf("\n", m.index) + 1;
        if (/\/\/|\/\*|^\s*\*/.test(src.slice(lineStart, m.index))) continue; // a comment that names <button>
        if (/role="menuitem"/.test(attrs)) continue; // `.menu button` styles a menu's items
        if (!/\bclassName=/.test(attrs)) bare.push(`${f}:${line}`);
        // A literal class must be one the stylesheet styles ("btn" was not, so three sharing buttons fell bare).
        const lit = /className="([^"]*)"/.exec(attrs);
        for (const cls of lit ? lit[1]!.split(/\s+/).filter(Boolean) : []) {
          if (!new RegExp(`\\.${cls}(?![\\w-])`).test(css)) bare.push(`${f}:${line} (.${cls} is not in styles.css)`);
        }
        if (/className=\{[^}]*\?\s*""\s*:|:\s*""\s*\}/.test(attrs) && !/active/.test(attrs)) bare.push(`${f}:${line} (an empty class)`);
      }
    }
    expect(bare).toEqual([]);
  });

  it("button.secondary and .stack exist, and the first screen's Sign in uses the first", () => {
    expect(css).toMatch(/button\.secondary\s*\{[^}]*width:\s*100%/);
    expect(css).toMatch(/\.stack\s*\{[^}]*display:\s*flex[^}]*gap:/);
    expect(read("./Welcome.tsx")).toContain('className={create === "hidden" ? "primary" : "secondary"}');
    expect(read("./KitCard.tsx")).toContain('className="secondary" onClick={() => window.print()}');
  });

  it("two link buttons side by side stand apart", () => {
    expect(css).toMatch(/button\.link \+ button\.link\s*\{[^}]*margin-left/);
  });
});

describe("the phone appbar keeps the views reachable", () => {
  it("at phone width the nav gets a row of its own", () => {
    const phone = block(css, "@media (max-width: 560px)");
    expect(phone).toMatch(/\.appbar\s*\{[^}]*flex-wrap:\s*wrap/);
    expect(phone).toMatch(/\.appbar > \.row:first-child\s*\{[^}]*display:\s*contents/);
    expect(phone).toMatch(/\.nav\s*\{[^}]*order:\s*3;[^}]*flex:\s*1 1 100%/);
  });
});

describe("the recovery kit (§10)", () => {
  it("the grouped secret is monospace, and the account ID may break rather than overflow a phone", () => {
    expect(css).toMatch(/\.kit-secret\s*\{[^}]*font-family:\s*var\(--mono\)/);
    expect(css).toMatch(/\.kit-document\s*\{[^}]*overflow-wrap:\s*anywhere/);
  });

  it("Print puts the kit document on paper and nothing else, in dark ink", () => {
    const print = block(css, "@media print");
    expect(print).toContain("body:has(.kit-document) * { visibility: hidden; }");
    expect(print).toMatch(/body:has\(\.kit-document\) \.kit-document \*\s*\{[^}]*visibility:\s*visible;[^}]*color:\s*#000/);
  });

  it("no Back to the first screen once the account exists and its kit waits to be confirmed", () => {
    const welcome = read("./Welcome.tsx");
    expect(welcome.match(/\{!committed && back\}/g)).toHaveLength(2);
    // A write the server stored and this browser refused shows its kit the same way: no Back while it is on screen.
    expect(welcome).toContain('const committed = step.kind === "record" || step.kind === "kit" || step.kind === "stored";');
    expect(welcome).toContain('const committed = step.kind === "kit" || step.kind === "stored";');
    expect(welcome.match(/onCommitted=\{setCommitted\}/g)).toHaveLength(2);
  });
});

describe("what the first walk left as still wrong", () => {
  it("with the server gone, the unlock and sign-in cards say \"can't reach\" once, not as a notice and an error both", () => {
    const welcome = read("./Welcome.tsx");
    expect(welcome).toContain("cardNoticeText(cardNotice) && lockedEmail && cardNoticeText(cardNotice) !== err && <Msg kind=\"info\">");
    expect(welcome).toContain("cardNoticeText(cardNotice) && cardNoticeText(cardNotice) !== err && <Msg kind=\"info\">");
    expect(welcome).not.toMatch(/cardNoticeText\(cardNotice\) && <Msg/);
  });

  it("the stop screen shows a sentence and no raw verdict code under it", () => {
    const welcome = read("./Welcome.tsx");
    const stop = block(welcome, "function PinStop(");
    expect(stop).not.toMatch(/\{verdict\}/);
    expect(stop).not.toContain("muted mono");
  });

  it("no \"tap\" in the web's words (the generator's ask is read on a desktop)", () => {
    for (const f of readdirSync(here(".")).filter((n) => /\.(tsx|ts)$/.test(n) && !n.endsWith(".test.ts"))) {
      const src = read(`./${f}`).replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, "");
      for (const m of src.matchAll(/"[^"\n]*\btap\b[^"\n]*"|>[^<>{}\n]*\btap\b[^<>{}\n]*</g)) {
        if (/click, tap, or press/.test(m[0])) continue; // the idle warning names every way to stay unlocked
        throw new Error(`${f}: ${m[0]}`);
      }
    }
  });
});

