import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * UI-audit Cut C (action plan v2 #12): the treasury palette is declared in FIVE disjoint
 * sources — web styles.css, extension popup.css, the content-script overlay (content-ui.ts),
 * Android Theme.kt, and desktop Main.kt — historically synced by comments alone, and the
 * audit found drift had already shipped three separate ways (the overlay's pre-AA ink-faint,
 * the never-ported --link token, native light-scheme gaps). This test parses ALL FIVE real
 * sources and asserts the shared palette byte-matches web (the de-facto origin), so any
 * one-sided edit fails CI here instead of shipping.
 *
 * Documented, DELIBERATE divergences (asserted as such, not skipped):
 *  - native light `primary` = web light --gold-hi (#8f6b16), NOT --gold: native primary
 *    paints filled buttons + primary text, which need the darker AA-safe gold; web keeps
 *    #9a7420 for decorative/large-text uses the native role doesn't have.
 *  - native `outline` (#80714f / #857857) intentionally DIVERGES from web --edge: M3
 *    outline borders text fields (needs ≥3:1), web --edge is a hairline divider. The
 *    divider-weight native role is outlineVariant, which must equal --edge.
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const webCss = readFileSync(here("./styles.css"), "utf8");
const popupCss = readFileSync(here("../../../extension/popup.css"), "utf8");
const overlayTs = readFileSync(here("../../../extension/src/content-ui.ts"), "utf8");
const themeKt = readFileSync(here("../../../app-android/src/main/kotlin/io/silencelen/andvari/app/Theme.kt"), "utf8");
const mainKt = readFileSync(here("../../../app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Main.kt"), "utf8");

/** CSS custom-prop map from the block opening at/after `from`. */
function cssBlock(src: string, from: number): Record<string, string> {
  const open = src.indexOf("{", from);
  const close = src.indexOf("}", open);
  const map: Record<string, string> = {};
  for (const m of src.slice(open + 1, close).matchAll(/(--[\w-]+):\s*(#[0-9a-fA-F]{3,8})\s*;/g)) {
    map[m[1]!] = m[2]!.toLowerCase();
  }
  return map;
}
const web = {
  dark: cssBlock(webCss, webCss.indexOf(":root")),
  light: cssBlock(webCss, webCss.indexOf(":root", webCss.indexOf("prefers-color-scheme: light"))),
};
const popup = {
  dark: cssBlock(popupCss, popupCss.indexOf(":root")),
  light: cssBlock(popupCss, popupCss.indexOf(":root", popupCss.indexOf("prefers-color-scheme: light"))),
};

/** Overlay --anv-* maps: dark = declarations before the light @media; light = inside it. */
function anvMap(src: string): Record<string, string> {
  const map: Record<string, string> = {};
  for (const m of src.matchAll(/(--anv-[\w-]+):\s*(#[0-9a-fA-F]{3,8})\s*;/g)) map[m[1]!] = m[2]!.toLowerCase();
  return map;
}
const anvLightAt = overlayTs.indexOf("@media (prefers-color-scheme: light)");
const overlay = { dark: anvMap(overlayTs.slice(0, anvLightAt)), light: anvMap(overlayTs.slice(anvLightAt)) };

/**
 * Kotlin colorScheme parser: resolves `private val X = Color(0xFF…)` constants, then maps
 * each `role = <Color(0xFF…)|ConstName|Color.White>` inside the named scheme call.
 */
function kotlinScheme(src: string, fn: "darkColorScheme" | "lightColorScheme"): Record<string, string> {
  const consts: Record<string, string> = {};
  for (const m of src.matchAll(/val\s+(\w+)\s*=\s*Color\(0xFF([0-9a-fA-F]{6})\)/g)) consts[m[1]!] = "#" + m[2]!.toLowerCase();
  const start = src.indexOf(fn + "(");
  expect(start, `${fn} not found`).toBeGreaterThan(-1);
  let depth = 0;
  let end = start;
  for (let i = src.indexOf("(", start); i < src.length; i++) {
    if (src[i] === "(") depth++;
    else if (src[i] === ")" && --depth === 0) { end = i; break; }
  }
  const body = src.slice(src.indexOf("(", start) + 1, end);
  const map: Record<string, string> = {};
  for (const m of body.matchAll(/(\w+)\s*=\s*(Color\(0xFF([0-9a-fA-F]{6})\)|Color\.White|\w+)/g)) {
    const [, role, expr, hex] = m;
    if (hex) map[role!] = "#" + hex.toLowerCase();
    else if (expr === "Color.White") map[role!] = "#ffffff";
    else if (consts[expr!]) map[role!] = consts[expr!]!;
  }
  return map;
}
const android = { dark: kotlinScheme(themeKt, "darkColorScheme"), light: kotlinScheme(themeKt, "lightColorScheme") };
const desktop = { dark: kotlinScheme(mainKt, "darkColorScheme"), light: kotlinScheme(mainKt, "lightColorScheme") };

describe("token lockstep — one palette, five sources", () => {
  // web ↔ popup: the popup is a verbatim port; every shared token must byte-match.
  const POPUP_TOKENS = [
    "--bg", "--bg-raised", "--bg-input", "--edge", "--edge-strong", "--ink", "--ink-dim",
    "--ink-faint", "--gold", "--gold-bright", "--gold-deep", "--link", "--gold-text",
    "--focus", "--gold-hi", "--gold-lo", "--danger", "--ok", "--btn-ink",
  ];
  for (const theme of ["dark", "light"] as const) {
    it(`popup.css ${theme} tokens byte-match styles.css`, () => {
      for (const t of POPUP_TOKENS) {
        expect(popup[theme][t], `${t} (${theme})`).toBe(web[theme][t]);
      }
    });

    it(`overlay --anv-* ${theme} tokens match styles.css`, () => {
      const pairs: Array<[string, string]> = [
        ["--anv-bg", "--bg-raised"], // overlay names its RAISED tone "bg" (naming trap — see audit)
        ["--anv-bg-deep", "--bg"],
        ["--anv-bg-input", "--bg-input"],
        ["--anv-edge", "--edge"],
        ["--anv-edge-strong", "--edge-strong"],
        ["--anv-ink", "--ink"],
        ["--anv-ink-dim", "--ink-dim"],
        ["--anv-ink-faint", "--ink-faint"],
        ["--anv-gold", "--gold"],
        ["--anv-gold-bright", "--gold-bright"],
        ["--anv-gold-text", "--gold-text"],
        ["--anv-btn-ink", "--btn-ink"],
        ["--anv-danger", "--danger"],
        ["--anv-ok", "--ok"],
      ];
      for (const [a, w] of pairs) expect(overlay[theme][a], `${a} (${theme})`).toBe(web[theme][w]);
    });
  }

  // native ↔ web: role mapping (M3 roles ↔ CSS tokens), asserted for BOTH Compose clients.
  for (const [name, native] of [["android Theme.kt", android], ["desktop Main.kt", desktop]] as const) {
    it(`${name} dark scheme matches the web dark tokens`, () => {
      const w = web.dark;
      expect(native.dark.primary).toBe(w["--gold"]);
      expect(native.dark.secondary).toBe(w["--gold-bright"]);
      expect(native.dark.background).toBe(w["--bg"]);
      expect(native.dark.surface).toBe(w["--bg-raised"]);
      expect(native.dark.onBackground).toBe(w["--ink"]);
      expect(native.dark.onSurfaceVariant).toBe(w["--ink-dim"]);
      expect(native.dark.error).toBe(w["--danger"]);
      expect(native.dark.tertiary).toBe(w["--ok"]);
      expect(native.dark.outlineVariant).toBe(w["--edge"]);
    });

    it(`${name} light scheme matches the web light tokens (primary = --gold-hi, documented)`, () => {
      const w = web.light;
      expect(native.light.primary).toBe(w["--gold-hi"]); // deliberate: AA-safe filled-button gold
      expect(native.light.secondary).toBe(w["--gold-bright"]);
      expect(native.light.background).toBe(w["--bg"]);
      expect(native.light.surface).toBe(w["--bg-raised"]);
      expect(native.light.onBackground).toBe(w["--ink"]);
      expect(native.light.onSurfaceVariant).toBe(w["--ink-dim"]);
      expect(native.light.error).toBe(w["--danger"]);
      expect(native.light.tertiary).toBe(w["--ok"]);
      expect(native.light.outlineVariant).toBe(w["--edge"]);
    });

    it(`${name} declares the full audited role set in both schemes`, () => {
      // Cut B's whole point: un-declared roles render Material-baseline lavender.
      const REQUIRED = [
        "primary", "onPrimary", "primaryContainer", "onPrimaryContainer",
        "secondary", "onSecondary", "secondaryContainer", "onSecondaryContainer",
        "tertiary", "onTertiary", "tertiaryContainer", "onTertiaryContainer",
        "background", "onBackground", "surface", "onSurface", "surfaceVariant", "onSurfaceVariant",
        "error", "onError", "errorContainer", "onErrorContainer",
        "outline", "outlineVariant", "scrim", "surfaceTint",
        "inverseSurface", "inverseOnSurface", "inversePrimary",
        "surfaceBright", "surfaceDim", "surfaceContainerLowest", "surfaceContainerLow",
        "surfaceContainer", "surfaceContainerHigh", "surfaceContainerHighest",
      ];
      for (const scheme of ["dark", "light"] as const) {
        for (const role of REQUIRED) expect(native[scheme][role], `${role} (${scheme})`).toMatch(/^#[0-9a-f]{6}$/);
      }
    });
  }

  it("android and desktop schemes are value-identical to each other", () => {
    for (const scheme of ["dark", "light"] as const) {
      for (const role of Object.keys(android[scheme])) {
        expect(desktop[scheme][role], `${role} (${scheme})`).toBe(android[scheme][role]);
      }
    }
  });
});
