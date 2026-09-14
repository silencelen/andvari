import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * H138 + H136 (audit 2026-09-13), the brand-asset pins.
 *
 * H138: 0.26.3 shipped the mark in TWO geometries. The tile icons — web favicon, desktop
 * .ico/.png, extension icon16-128 — drew a 14-unit inset stave (`M12 5v14`) at stroke 1.8, a
 * stroke-to-height ratio of 0.129, while BrandSigil, the extension popup/options headers and the
 * Android launcher drew the 18-unit wordmark stave (`M12 3v18`) at ratio 0.100. Same product,
 * two runes, ~29 % apart in weight, visible side by side on one screen. The owner picked the
 * wordmark and every raster is now rendered from assets/brand/andvari-mark.svg by
 * scripts/gen-brand-icons.sh. The pin below is deliberately a THREE-way agreement — shared SVG,
 * BrandSigil, Android vector drawable — because the failure mode is not "the icon is wrong", it
 * is "one of the four surfaces quietly drifted again while the other three stayed put", and only
 * a comparison catches that. It reads every file that CANNOT be generated — eight of them (R48),
 * not the two the first cut claimed: BrandSigil, the Android vector drawable, the extension popup
 * and options headers, the popup's and the content overlay's path builders, the Android Compose
 * ImageVector and the desktop Canvas — and asserts each carries the source's numbers in its own
 * spelling. Staleness of the GENERATED rasters is a different question, and a different mechanism
 * answers it: `scripts/gen-brand-icons.sh --check` re-renders and diffs, from the release gate
 * (R49) — a raster's bytes are not derivable here, so this file can only assert they exist.
 *
 * H136: no web app manifest existed, so Chromium's install path had nothing to key on and "Add
 * to Home screen" produced a generic letter icon named after the URL, opening in a browser tab.
 * These assertions fail if the link is dropped from index.html, if the manifest loses standalone
 * display / the brand colours, or if an icon it advertises is missing from web/public (a 404 in
 * the manifest silently downgrades the install prompt — the sort of thing nobody notices until a
 * household member pins the vault on a phone).
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const read = (p: string) => readFileSync(here(p), "utf8");

const SOURCE = "../../../assets/brand/andvari-mark.svg";

/** The single geometry, spelled the way each surface has to spell it. */
const STAVE_SVG = 'd="M12 3v18"';
const FALL_SVG = 'd="M5.5 8.5l13 6"';
const GOLD = /#d0a94a/i;
const APP_DARK = /#14120e/i;

describe("the brand mark has exactly one geometry (H138)", () => {
  const source = read(SOURCE);

  it("the shared source is the wordmark stave on the dark tile, not the old inset stave", () => {
    expect(source).toContain(STAVE_SVG);
    expect(source).toContain(FALL_SVG);
    expect(source).toMatch(GOLD);
    expect(source).toMatch(APP_DARK);
    expect(source).toContain('stroke-width="1.8"');
    expect(source).toContain('stroke-linecap="round"');
    // The geometry that was retired. If it comes back anywhere, the fleet has two marks again.
    expect(source).not.toContain("M12 5v14");
    expect(source).not.toContain("M6.5 9.2l11 5");
  });

  it("BrandSigil draws the source's paths", () => {
    const sigil = read("./Sigil.tsx");
    expect(sigil).toContain('d="M12 3v18"');
    expect(sigil).toContain('d="M5.5 8.5l13 6"');
    expect(sigil).toContain("strokeWidth={1.8}");
  });

  it("the Android adaptive foreground draws the source's paths", () => {
    const vector = read("../../../app-android/src/main/res/drawable/ic_launcher_foreground.xml");
    // Same two strokes in vector-drawable spelling: absolute L instead of the relative l.
    expect(vector).toContain("M12,3 L12,21");
    expect(vector).toContain("M5.5,8.5 L18.5,14.5");
    expect(vector).toMatch(GOLD);
    expect(vector).toContain('android:strokeWidth="1.8"');
  });

  /**
   * R48 — ALL EIGHT hand-drawn copies, not two.
   *
   * The block above called itself "a THREE-way agreement … the two files that cannot be
   * generated", and CONTRIBUTING.md repeated the claim to contributors. It is not two: six more
   * production surfaces re-draw the same stave by hand — the extension popup and options headers
   * (inline SVG in the HTML), the popup's and the content overlay's programmatic path builders,
   * the Android Compose ImageVector, and the desktop's Canvas draw. None of them was read by any
   * test in the tree, so re-drawing the mark on any of them shipped green — which is the drift
   * H138 was raised about, one surface at a time.
   *
   * Each is asserted in its OWN spelling (that is what "hand-drawn" means here): SVG/TS carry the
   * literal path data, the Kotlin ones carry the same numbers as floats. No generator can reach
   * these — a Compose Canvas and an inline <svg> in a store-listing HTML page are code — so a
   * comparison is the only mechanism available.
   */
  it("every hand-drawn copy of the mark carries the source's two strokes (R48)", () => {
    // The path-literal surfaces: the source's own spelling, verbatim.
    for (const rel of [
      "../../../extension/popup.html",
      "../../../extension/options.html",
      "../../../extension/src/popup.ts",
      "../../../extension/src/content-ui.ts",
    ]) {
      const src = read(rel);
      expect(src, `${rel}: the stave`).toContain("M12 3v18");
      expect(src, `${rel}: the falling stroke`).toContain("M5.5 8.5l13 6");
      expect(src, `${rel}: the retired inset stave must not come back`).not.toContain("M12 5v14");
    }

    // Android: a Compose ImageVector path built from the same numbers.
    const theme = read("../../../app-android/src/main/kotlin/io/silencelen/andvari/app/Theme.kt");
    expect(theme).toContain("moveTo(12f, 3f); verticalLineToRelative(18f)");
    expect(theme).toContain("moveTo(5.5f, 8.5f); lineToRelative(13f, 6f)");

    // Desktop: two drawLine calls on a 24-unit canvas — the relative stroke resolved to absolute
    // endpoints (3 → 21 and 5.5,8.5 → 18.5,14.5), which is the same geometry in Canvas spelling.
    const ui = read("../../../app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt");
    expect(ui).toContain("Offset(12f * u, 3f * u), Offset(12f * u, 21f * u)");
    expect(ui).toContain("Offset(5.5f * u, 8.5f * u), Offset(18.5f * u, 14.5f * u)");

    // …and one stroke weight everywhere: the ratio is what made the two marks look different.
    for (const [rel, needle] of [
      ["../../../extension/popup.html", 'stroke-width="1.8"'],
      ["../../../extension/options.html", 'stroke-width="1.8"'],
      ["../../../app-android/src/main/kotlin/io/silencelen/andvari/app/Theme.kt", "1.8f"],
    ] as const) {
      expect(read(rel), `${rel}: stroke 1.8`).toContain(needle);
    }
  });

  it("the served favicon and the desktop copy are the source verbatim", () => {
    // Copies, not re-drawings: `cp` in the generator. Byte equality is the cheapest possible
    // guard against someone editing the derivative that happens to be open in their editor.
    expect(read("../../public/favicon.svg")).toBe(source);
    expect(read("../../../app-desktop/icons/andvari.svg")).toBe(source);
  });

  it("every rendered tile the surfaces load is present", () => {
    // Presence only, deliberately: a PNG's bytes cannot be derived in JS, so STALENESS is checked
    // by `scripts/gen-brand-icons.sh --check` in the release gate (R49), which re-renders from the
    // source and diffs. Do not mistake a green here for "these are current".
    for (const p of [
      "../../public/apple-touch-icon.png",
      "../../../extension/icons/icon16.png",
      "../../../extension/icons/icon32.png",
      "../../../extension/icons/icon48.png",
      "../../../extension/icons/icon128.png",
      "../../../app-desktop/icons/andvari.ico",
      "../../../app-desktop/icons/andvari.png",
      "../../../app-desktop/src/main/resources/andvari.png",
    ]) {
      expect(statSync(here(p)).size, p).toBeGreaterThan(0);
    }
  });

  it("the appbar carries the mark, in the popup's lockup", () => {
    const vault = readFileSync(here("./Vault.tsx"), "utf8");
    // The sigil must sit INSIDE .brand and before the wordmark spans, with no whitespace
    // between them — the spans are in inline flow, so a stray newline renders as a gap.
    expect(vault).toContain(
      '<span className="brand"><span className="sigil-sm"><BrandSigil size={18} /></span><span className="a-mark">and</span>vari</span>',
    );
    expect(read("./styles.css")).toContain(".brand .sigil-sm");
  });
});

describe("the web app manifest (H136)", () => {
  const html = read("../../index.html");
  const manifest = JSON.parse(read("../../public/manifest.webmanifest")) as {
    name: string;
    short_name: string;
    start_url: string;
    display: string;
    theme_color: string;
    background_color: string;
    icons: { src: string; sizes: string; type: string; purpose: string }[];
  };

  it("is linked from the document", () => {
    expect(html).toContain('<link rel="manifest" href="/manifest.webmanifest" />');
  });

  it("names the app, installs standalone, and paints in the brand colours", () => {
    expect(manifest.name).toBe("andvari");
    expect(manifest.short_name).toBe("andvari");
    expect(manifest.start_url).toBe("/");
    expect(manifest.display).toBe("standalone");
    expect(manifest.theme_color).toMatch(APP_DARK);
    expect(manifest.background_color).toMatch(APP_DARK);
  });

  it("advertises 192 and 512 'any' icons plus a maskable one, and all of them exist", () => {
    const bySize = new Map(manifest.icons.map((i) => [`${i.sizes}:${i.purpose}`, i]));
    expect(bySize.has("192x192:any")).toBe(true);
    expect(bySize.has("512x512:any")).toBe(true);
    // Without a maskable entry Android pads the "any" icon inside a white-ish shim rather than
    // filling its mask — the branded launcher icon this row exists to produce would still look
    // like a pasted screenshot on most phones.
    expect(bySize.has("512x512:maskable")).toBe(true);
    for (const icon of manifest.icons) {
      expect(icon.type).toBe("image/png");
      expect(icon.src.startsWith("/")).toBe(true);
      expect(statSync(here(`../../public${icon.src}`)).size, icon.src).toBeGreaterThan(0);
    }
  });
});
