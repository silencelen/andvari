// node --test (see version.test.ts). H133, audit 2026-09-13 — the extension half of the micro-copy
// drift sweep. vault-copy.test.ts (web) pins the canon SENTENCES; nothing pinned the CHROME, so the
// two surfaces a user has open at the same time — the web vault in a tab, the popup in the toolbar —
// drifted into different house styles: the popup's empty states were the only user-facing empties in
// the product without terminal punctuation, and the extension's page titles used a third title
// scheme ("andvari — Options") after the web had settled on "<Surface> · andvari".
//
// These are source pins, deliberately: the strings are the product's voice, and a voice regression
// is not something a type or a DOM assertion can catch.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf-8");
const popupTs = read("./popup.ts");
const pages = { popup: read("../popup.html"), options: read("../options.html"), connector: read("../connector.html") };

/** Split an argument list on TOP-LEVEL commas (quotes, template literals and nesting respected). */
function splitArgs(src: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote = "";
  let start = 0;
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
      continue;
    }
    if (c === '"' || c === "'" || c === "`") quote = c;
    else if (c === "(" || c === "[" || c === "{") depth++;
    else if (c === ")" || c === "]" || c === "}") depth--;
    else if (c === "," && depth === 0) {
      out.push(src.slice(start, i));
      start = i + 1;
    }
  }
  out.push(src.slice(start));
  return out;
}

// The third argument of renderList() is the empty-state text — one literal, or two behind a ternary
// (search-vs-bare). Every one of them must read as a sentence, like the web empties do.
test("H133: every popup empty state is a sentence with terminal punctuation", () => {
  // Lookbehind skips the DECLARATION (whose parameter list also ends in `);` once the body's
  // first statement is swallowed) — only real call sites carry copy.
  const calls = [...popupTs.matchAll(/(?<!function )renderList\(([^;]*?)\);/g)];
  assert.ok(calls.length >= 3, `expected the popup's renderList call sites, found ${calls.length}`);
  let checked = 0;
  for (const call of calls) {
    const emptyArg = splitArgs(call[1]!)[2];
    assert.ok(emptyArg, `renderList call has no empty-state argument: ${call[0]}`);
    const literals = [...emptyArg!.matchAll(/(["`])((?:[^"`\\]|\\.)*)\1/g)].map((m) => m[2]!);
    assert.ok(literals.length >= 1, `no empty-state literal in: ${emptyArg}`);
    for (const lit of literals) {
      checked++;
      assert.match(lit, /[.?!]$/, `popup empty state must end in terminal punctuation: "${lit}"`);
    }
  }
  assert.ok(checked >= 4, `expected at least 4 empty-state literals, saw ${checked}`);
});

// One title scheme across the product (web Vault.tsx: `${VIEW_TITLES[view]} · andvari`, with the
// ROOT surface titled bare "andvari"). The popup is the extension's root surface; the options tab
// and the connector window are named surfaces. Sentence case, middle dot, brand last — never the
// old "andvari — Options" / "andvari — quick unlock" pair, which were neither.
const EXPECTED_TITLES = { popup: "andvari", options: "Options · andvari", connector: "Quick unlock · andvari" } as const;

test("H133: extension page titles all follow the web's <Surface> · andvari scheme", () => {
  for (const [name, html] of Object.entries(pages)) {
    const m = /<title>([^<]*)<\/title>/.exec(html);
    assert.ok(m, `${name}.html has no <title>`);
    const title = m![1]!;
    assert.equal(title, EXPECTED_TITLES[name as keyof typeof EXPECTED_TITLES], `${name}.html title`);
    assert.ok(!title.includes(" — "), `${name}.html: the em-dash title scheme is retired`);
    if (title !== "andvari") {
      const surface = title.slice(0, title.indexOf(" · "));
      // Sentence case: capital first, and no Title Case Second Word.
      assert.match(surface, /^[A-Z][a-z]*(?: [a-z]+)*$/, `${name}.html surface name must be sentence case: "${surface}"`);
      assert.ok(title.endsWith(" · andvari"), `${name}.html must end with the brand`);
    }
  }
});

// The back affordance: the product settled on "‹ Back to <destination>" (web's BackLink is the
// canonical sibling); the "←" glyph and the bare gesture-word are the drift. The popup's is the
// only one in the extension.
test("H133: the popup's back affordance uses the ‹ glyph, sentence case, never ←", () => {
  assert.ok(pages.popup.includes("‹ Back"), "popup.html lost its ‹ Back button");
  // R13: and it names the destination, like every web call site. A bare "‹ Back" is the gesture,
  // which is precisely the exception BackLink.tsx's comment says does not exist.
  assert.match(pages.popup, /‹ Back to [a-z]/, "the popup's back label must name where it goes, not the gesture");
  for (const [name, html] of Object.entries(pages)) {
    assert.ok(!html.includes("←"), `${name}.html: the ← back glyph is retired in favour of ‹`);
  }
  assert.ok(!popupTs.includes("←"), "popup.ts: the ← back glyph is retired in favour of ‹");
});
