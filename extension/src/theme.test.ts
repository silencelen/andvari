// node --test (see version.test.ts). H134, audit 2026-09-13 — the extension's user theme override.
//
// Three things have to stay true for a forced Light/Dark to mean the same thing in the popup, the
// options tab, the connector window and the web vault, and NONE of them is reachable by tsc:
//  1. popup.css's `:root[data-theme=…]` blocks must be palette twins of the two scheme blocks — a
//     forced theme that has drifted from Auto is a worse bug than no override at all, because it
//     only shows up for the users who touched the setting;
//  2. they must sit BELOW the base `:root` and the light-scheme @media, because every parser over
//     this stylesheet (contrast.test.ts here, token-lockstep.test.ts in the web tree) keys on the
//     FIRST occurrence of those two anchors — a well-meaning "move the overrides up next to the
//     palette" would silently retarget the a11y gates onto the override blocks;
//  3. theme-boot.js (plain, unbundled, CSP-safe, render-blocking) must stay a faithful twin of
//     src/theme.ts. No import graph reaches theme-boot.js, so a one-sided edit is invisible until
//     a user reports the popup flashing the wrong palette — which is precisely what it exists to
//     prevent. Same source-substring idiom as web/src/ui/theme-boot.test.ts.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const read = (p: string) => readFileSync(fileURLToPath(new URL(p, import.meta.url)), "utf-8");
const css = read("../popup.css");
const boot = read("../theme-boot.js");
const theme = read("./theme.ts");
const pages = { popup: read("../popup.html"), options: read("../options.html"), connector: read("../connector.html") };

/**
 * The custom-property map of the block opening at/after `from`.
 *
 * R12: ANY declaration value, not just `#hex`. The hex-only pattern (inherited from
 * token-lockstep.test.ts, where the palette really is all hex) silently skipped `--shadow`, the one
 * non-hex palette value duplicated into both forced blocks — so editing it in the base block alone
 * would have left everyone who ever picked Light or Dark on the old shadow with this suite green,
 * which is the exact class of drift these twin assertions exist to catch. `color-scheme` is the
 * only deliberate exclusion: it is a per-block DIRECTIVE that must differ (light vs dark), and the
 * next test asserts it separately. Values are trimmed and lower-cased so whitespace or `RGBA(` vs
 * `rgba(` never reads as a divergence.
 */
function tokens(src: string, from: number): Record<string, string> {
  const open = src.indexOf("{", from);
  const close = src.indexOf("}", open);
  const map: Record<string, string> = {};
  for (const m of src.slice(open + 1, close).matchAll(/(--[\w-]+):\s*([^;]+);/g)) map[m[1]!] = m[2]!.trim().toLowerCase();
  return map;
}

const baseAt = css.indexOf(":root {");
const lightMediaAt = css.indexOf("@media (prefers-color-scheme: light)");
const lightSchemeRootAt = css.indexOf(":root", lightMediaAt);
const forcedLightAt = css.indexOf(':root[data-theme="light"]');
const forcedDarkAt = css.indexOf(':root[data-theme="dark"]');

test("H134: both forced-theme blocks exist, BELOW the two parser-keyed scheme blocks", () => {
  assert.ok(forcedLightAt > 0, ':root[data-theme="light"] block missing');
  assert.ok(forcedDarkAt > 0, ':root[data-theme="dark"] block missing');
  assert.ok(forcedLightAt > lightSchemeRootAt, "forced light must come after the light-scheme block");
  assert.ok(forcedDarkAt > lightSchemeRootAt, "forced dark must come after the light-scheme block");
  // …and the base block stays the FIRST :root in the file.
  assert.ok(baseAt < lightMediaAt, "the bare `:root {` must stay the first :root in popup.css");
});

test('H134: [data-theme="light"] is a palette twin of the light-scheme block', () => {
  assert.deepEqual(tokens(css, forcedLightAt), tokens(css, lightSchemeRootAt));
});

test('H134: [data-theme="dark"] is a palette twin of the base (dark) block', () => {
  // R12 widened tokens() to every declaration value, which exposed a real asymmetry: the base
  // `:root` also declares the STRUCTURAL tokens (--serif/--sans/--mono/--radius) that no theme
  // overrides, so a whole-map equality would demand the forced block re-state them. The invariant
  // that actually matters is per-token: every value the forced-dark block declares must be the
  // base's value for that token — including --shadow, the non-hex one the old parser skipped.
  const base = tokens(css, baseAt);
  const forced = tokens(css, forcedDarkAt);
  for (const [tok, val] of Object.entries(forced)) {
    assert.equal(val, base[tok], `${tok} in [data-theme="dark"] diverged from the base dark block`);
  }
  assert.ok(forced["--shadow"], "--shadow is duplicated into the forced blocks and must be compared, not skipped");
});

test("H134: the two forced blocks override the SAME set of tokens", () => {
  // A token the light-scheme block re-declares but a forced block forgets is left at the base
  // (dark) value for anyone who picked a theme explicitly — a half-themed popup no scheme test
  // can see, because both scheme blocks would still be correct.
  const scheme = Object.keys(tokens(css, lightSchemeRootAt)).sort();
  assert.deepEqual(Object.keys(tokens(css, forcedLightAt)).sort(), scheme);
  assert.deepEqual(Object.keys(tokens(css, forcedDarkAt)).sort(), scheme);
});

test("H134: the forced blocks pin color-scheme too (UA-painted surfaces follow the override)", () => {
  assert.match(css.slice(forcedLightAt, forcedLightAt + 1200), /color-scheme:\s*light;/);
  assert.match(css.slice(forcedDarkAt, forcedDarkAt + 1200), /color-scheme:\s*dark;/);
});

// The popup used to freeze only its ONE keyframe animation (the KDF sweep) while every transition —
// row hover, the fill pill's gradient swap, the hover-revealed copy actions, the focus ring — kept
// running for a user who had asked their OS for less motion. The universal block is the web's.
test("H134: popup.css honours prefers-reduced-motion for TRANSITIONS, not just the KDF sweep", () => {
  const blocks = [...css.matchAll(/@media \(prefers-reduced-motion: reduce\)\s*\{([\s\S]*?)\n\}/g)].map((m) => m[1]!);
  assert.ok(blocks.length >= 1, "no prefers-reduced-motion block in popup.css");
  const universal = blocks.find((b) => /\*,\s*\*::before,\s*\*::after/.test(b));
  assert.ok(universal, "no universal *, ::before, ::after reduced-motion rule");
  assert.match(universal!, /transition-duration:\s*0\.01ms\s*!important/);
  assert.match(universal!, /animation-duration:\s*0\.01ms\s*!important/);
});

test("H134: theme-boot.js reads the same storage key as theme.ts", () => {
  const m = /THEME_STORAGE_KEY\s*=\s*"([^"]+)"/.exec(theme);
  assert.ok(m, "THEME_STORAGE_KEY literal not found in theme.ts");
  assert.equal(m![1], "andvari.theme");
  assert.ok(boot.includes(`"${m![1]}"`), "theme-boot.js must read the same key");
  assert.ok(boot.includes("localStorage.getItem(KEY)"));
});

test("H134: both twins parse the stored value with the same light|dark|else-auto rule", () => {
  for (const [name, src] of [["theme-boot.js", boot], ["theme.ts", theme]] as const) {
    assert.match(src, /raw === "light" \|\| raw === "dark" \? raw : "auto"/, name);
  }
});

test("H134: both twins stamp data-theme with Auto = REMOVE, and pin color-scheme", () => {
  for (const [name, src] of [["theme-boot.js", boot], ["theme.ts", theme]] as const) {
    // Auto must REMOVE the attribute rather than writing the OS's current value, or an OS-level
    // light/dark flip stops taking effect for anyone who ever opened the setting.
    assert.ok(src.includes('removeAttribute("data-theme")'), name);
    assert.ok(src.includes('setAttribute("data-theme", pref)'), name);
    assert.match(src, /colorScheme = ""/, name);
    assert.match(src, /colorScheme = pref/, name);
  }
});

test("H134: theme-boot.js fails safe — it can never throw out of a pre-paint script", () => {
  // outer try/catch around everything, inner one around the storage read (private mode / locked
  // profiles throw on localStorage access itself, not just return null).
  assert.ok(boot.split("try {").length - 1 >= 2, "theme-boot.js needs the outer + storage try/catch");
});

test("H134: every extension page loads theme-boot.js as a CLASSIC script, before its module bundle", () => {
  for (const [name, html] of Object.entries(pages)) {
    const bootAt = html.indexOf('<script src="theme-boot.js"></script>');
    assert.ok(bootAt > 0, `${name}.html does not load theme-boot.js`);
    assert.ok(bootAt < html.indexOf("</head>"), `${name}.html must load it in <head> (pre-paint)`);
    // A module script is deferred, which is the flash this file exists to kill.
    assert.ok(!/<script[^>]*theme-boot\.js[^>]*type="module"/.test(html), `${name}.html must not defer it`);
  }
});
