import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { BrandSigil, WORDMARK_PATH, WORDMARK_VIEWBOX, Wordmark } from "./Sigil";

/**
 * The brand's pins: one source for the mark and the name.
 *
 * The mark once shipped in two geometries at the same time (the browser tab's icon drawn from one set of numbers, the
 * extension's header from another), so the same product's rune looked different on two surfaces side by side. The
 * failure is never "the icon is wrong" but "one copy quietly drifted while the others stayed put", and only a
 * comparison with the source catches it. So every drawing of the rune and of the name in the tree is read here, in
 * its own spelling (SVG path data, Android path data, Kotlin path calls), and compared with the files under
 * assets/brand/: the rune with andvari-rune.svg (flat: two polygons) and, for the Android launcher's foreground,
 * andvari-rune-gilded.svg (four facets in two golds); the name with wordmark.svg. Each check is also run on a copy of
 * its file with one number changed, and must then fail.
 *
 * The rendered icons are a different question with a different answer: `scripts/gen-brand-icons.sh --check` renders
 * them from the sources and compares the pixels, from the release gate. A picture's pixels cannot be worked out
 * here, so this file only says that each one exists.
 *
 * The web app manifest: without one, Chromium's install path has nothing to key on and "Add to Home screen" makes a
 * generic letter icon named after the address. The pins below fail if the link leaves index.html, if the manifest
 * loses standalone display or the brand colors, or if an icon it names is missing from web/public (a 404 there
 * silently downgrades the install prompt).
 */
const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));
const read = (p: string) => readFileSync(here(p), "utf8");

const ROOT = "../../../";
const BRAND = `${ROOT}assets/brand/`;
const GOLD = /#d0a94a/i;
const APP_DARK = /#14120e/i;

type Pt = [number, number];
type Poly = Pt[];

/** Polygons written as "M x y L x y … Z": SVG path data, or Android path data with commas. */
function pathPolys(text: string): Poly[] {
  const out: Poly[] = [];
  const pair = String.raw`(-?\d+(?:\.\d+)?)[ ,](-?\d+(?:\.\d+)?)`;
  const anyPair = String.raw`-?\d+(?:\.\d+)?[ ,]-?\d+(?:\.\d+)?`;
  for (const m of text.matchAll(new RegExp(String.raw`M\s*${pair}((?:\s*L\s*${anyPair})+)\s*Z`, "g"))) {
    const poly: Poly = [[Number(m[1]), Number(m[2])]];
    for (const l of m[3]!.matchAll(new RegExp(String.raw`L\s*${pair}`, "g"))) poly.push([Number(l[1]), Number(l[2])]);
    out.push(poly);
  }
  return out;
}

/** Polygons written as Compose path calls: moveTo(x, y), lineTo(x, y) … close(), Float literals, optionally "* u". */
function kotlinPolys(text: string): Poly[] {
  const out: Poly[] = [];
  let cur: Poly | null = null;
  const num = String.raw`(-?\d+(?:\.\d+)?)f(?:\s*\*\s*u)?`;
  for (const m of text.matchAll(new RegExp(String.raw`\b(moveTo|lineTo)\(\s*${num}\s*,\s*${num}\s*\)|\bclose\(\)`, "g"))) {
    if (m[1] === "moveTo") cur = [[Number(m[2]), Number(m[3])]];
    else if (m[1] === "lineTo") cur?.push([Number(m[2]), Number(m[3])]);
    else if (cur) {
      out.push(cur);
      cur = null;
    }
  }
  return out;
}

const samePoly = (a: Poly, b: Poly) => a.length === b.length && a.every(([x, y], i) => x === b[i]![0] && y === b[i]![1]);

/** How many times [rune]'s polygons stand in [polys] one after the other, in their order. */
function count(polys: Poly[], rune: Poly[]): number {
  let n = 0;
  for (let i = 0; i + rune.length <= polys.length; i++) if (rune.every((p, k) => samePoly(polys[i + k]!, p))) n++;
  return n;
}

/** Android path data and fill colors in drawing order, as `#RRGGBB fill` pairs (an `#AARRGGBB` loses its alpha). */
function androidFills(xml: string): [string, Poly][] {
  const out: [string, Poly][] = [];
  for (const m of xml.matchAll(/android:fillColor="#(?:[0-9A-Fa-f]{2})?([0-9A-Fa-f]{6})"\s*android:pathData="([^"]+)"/g)) out.push([`#${m[1]!.toUpperCase()}`, pathPolys(m[2]!)[0]!]);
  return out;
}
function svgFills(svg: string): [string, Poly][] {
  const out: [string, Poly][] = [];
  for (const m of svg.matchAll(/<path d="([^"]+)" fill="(#[0-9A-Fa-f]{6})"\/>/g)) out.push([m[2]!.toUpperCase(), pathPolys(m[1]!)[0]!]);
  return out;
}

const RUNE = pathPolys(read(`${BRAND}andvari-rune.svg`));
const GILDED = svgFills(read(`${BRAND}andvari-rune-gilded.svg`));
const MASTER = read(`${BRAND}andvari-mark-gilded.svg`);
const WORDMARK_SVG = read(`${BRAND}wordmark.svg`);
const SOURCE_D = /<path d="([^"]+)" fill="currentColor"\/>/.exec(WORDMARK_SVG)![1]!;
const SOURCE_VIEWBOX = /viewBox="([^"]+)"/.exec(WORDMARK_SVG)![1]!;

/** Every drawing of the flat rune in the tree, the spelling it is written in, and how many times the file draws it. */
const RUNE_DRAWINGS: { file: string; spelling: "path" | "kotlin"; times: number }[] = [
  { file: "web/src/ui/Sigil.tsx", spelling: "path", times: 1 },
  { file: "extension/popup.html", spelling: "path", times: 2 },
  { file: "extension/options.html", spelling: "path", times: 1 },
  { file: "extension/src/brand.ts", spelling: "path", times: 1 },
  { file: "app-android/src/main/kotlin/io/silencelen/andvari/app/Theme.kt", spelling: "kotlin", times: 1 },
  { file: "app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt", spelling: "kotlin", times: 1 },
  { file: "app-android/src/main/res/drawable/ic_launcher_monochrome.xml", spelling: "path", times: 1 },
  // The brand's own compositions draw the same rune: the small tile, the flat tile and the lockups.
  { file: "assets/brand/andvari-mark.svg", spelling: "path", times: 1 },
  { file: "assets/brand/andvari-mark-flat.svg", spelling: "path", times: 1 },
  { file: "assets/brand/lockup-horizontal-dark.svg", spelling: "path", times: 1 },
  { file: "assets/brand/lockup-horizontal-light.svg", spelling: "path", times: 1 },
  { file: "assets/brand/lockup-stacked-dark.svg", spelling: "path", times: 1 },
  { file: "assets/brand/lockup-stacked-light.svg", spelling: "path", times: 1 },
  { file: "assets/brand/lockup-stacked-line-dark.svg", spelling: "path", times: 1 },
  { file: "assets/brand/lockup-stacked-line-light.svg", spelling: "path", times: 1 },
];

const runeCount = (text: string, spelling: "path" | "kotlin") => count(spelling === "path" ? pathPolys(text) : kotlinPolys(text), RUNE);
/** The same file with the falling stroke's right end moved: every spelling writes 19.15. */
const moved = (text: string) => text.replace("19.15", "19.25");

/** The gilded launcher foreground: the four facets in their golds, placed in the 108 box as the icon master places them. */
function foregroundAgrees(xml: string): boolean {
  const fills = androidFills(xml);
  const facetsAgree = fills.length === GILDED.length && fills.every(([c, p], i) => c === GILDED[i]![0] && samePoly(p, GILDED[i]![1]));
  const t = /translate\(54 54\) scale\(([\d.]+)\) translate\((-?[\d.]+) (-?[\d.]+)\)/.exec(MASTER)!;
  const k = Number(t[1]);
  const num = (attr: string) => Number(new RegExp(`android:${attr}="(-?[\\d.]+)"`).exec(xml)?.[1]);
  const close = (a: number, b: number) => Math.abs(a - b) < 5e-4;
  const placed = num("scaleX") === k && num("scaleY") === k && close(num("translateX"), 54 + k * Number(t[2])) && close(num("translateY"), 54 + k * Number(t[3]));
  return facetsAgree && placed;
}

/** The launcher background: the master's polished-hardwood gradient (its center and radius in the 108 box, its stops). */
function backgroundAgrees(xml: string): boolean {
  const g = /<radialGradient id="pg" cx="([\d.]+)" cy="([\d.]+)" r="([\d.]+)">(.*?)<\/radialGradient>/.exec(MASTER)!;
  const stops = [...g[4]!.matchAll(/offset="([\d.]+)" stop-color="#([0-9A-Fa-f]{6})"/g)].map((m) => [Number(m[1]), m[2]!.toUpperCase()]);
  const items = [...xml.matchAll(/android:offset="([\d.]+)" android:color="#FF([0-9A-Fa-f]{6})"/g)].map((m) => [Number(m[1]), m[2]!.toUpperCase()]);
  const num = (attr: string) => Number(new RegExp(`android:${attr}="([\\d.]+)"`).exec(xml)?.[1]);
  const close = (a: number, b: number) => Math.abs(a - b) < 1e-6;
  return (
    close(num("centerX"), Number(g[1]) * 108) && close(num("centerY"), Number(g[2]) * 108) && close(num("gradientRadius"), Number(g[3]) * 108) &&
    JSON.stringify(items) === JSON.stringify(stops)
  );
}

describe("the rune has one geometry: assets/brand/andvari-rune.svg", () => {
  it("the source is two filled bands: the falling stroke, then the stave over it", () => {
    expect(RUNE).toEqual([
      [[4.85, 6.768], [19.15, 13.368], [19.15, 16.232], [4.85, 9.632]],
      [[10.7, 2.35], [13.3, 3.55], [13.3, 21.25], [10.7, 20.05]],
    ]);
    expect(GILDED.map(([c]) => c)).toEqual(["#E9C978", "#A8832F", "#E9C978", "#A8832F"]);
    // The gilded facets cut the same two bands along their center lines: together they cover the flat rune's corners.
    const corners = (polys: Poly[]) => new Set(polys.flat().map(([x, y]) => `${x},${y}`));
    for (const c of corners(RUNE)) expect(corners(GILDED.map(([, p]) => p)).has(c), c).toBe(true);
    // The icon master draws the gilded rune, facet for facet.
    expect(svgFills(MASTER)).toEqual(GILDED);
  });

  it.each(RUNE_DRAWINGS)("$file draws the source's rune ($times), and fails with one number moved", ({ file, spelling, times }) => {
    const text = read(ROOT + file);
    expect(runeCount(text, spelling)).toBe(times);
    expect(runeCount(moved(text), spelling)).toBe(times - 1);
  });

  it("the extension's script-built runes are brand.ts's: the popup's list and the in-page panel draw nothing of their own", () => {
    for (const f of ["extension/src/popup.ts", "extension/src/content-ui.ts"]) {
      const text = read(ROOT + f);
      expect(text, f).toMatch(/import \{[^}]*\brunesvg\b[^}]*\} from "\.\/brand";/i);
      expect(pathPolys(text), f).toEqual([]);
    }
    expect(read(`${ROOT}extension/src/popup.ts`)).toContain('if (mark === "brand") return runeSvg(size);');
    expect(read(`${ROOT}extension/src/content-ui.ts`)).toContain("s.append(runeSvg(size));");
  });

  it("the Android launcher's foreground is the gilded rune, placed as the icon master places it", () => {
    const xml = read(`${ROOT}app-android/src/main/res/drawable/ic_launcher_foreground.xml`);
    expect(foregroundAgrees(xml)).toBe(true);
    expect(foregroundAgrees(moved(xml))).toBe(false);
    expect(foregroundAgrees(xml.replace("#E9C978", "#E9C979"))).toBe(false);
    expect(foregroundAgrees(xml.replace("13.3651", "13.4651"))).toBe(false);
  });

  it("the Android launcher's background is the master's polished hardwood, and the adaptive icon uses all three layers", () => {
    const xml = read(`${ROOT}app-android/src/main/res/drawable/ic_launcher_background.xml`);
    expect(backgroundAgrees(xml)).toBe(true);
    expect(backgroundAgrees(xml.replace("#FF33261A", "#FF33261B"))).toBe(false);
    expect(backgroundAgrees(xml.replace('android:centerX="30.24"', 'android:centerX="31.24"'))).toBe(false);
    for (const f of ["ic_launcher.xml", "ic_launcher_round.xml"]) {
      const adaptive = read(`${ROOT}app-android/src/main/res/mipmap-anydpi-v26/${f}`);
      expect(adaptive).toContain('<background android:drawable="@drawable/ic_launcher_background" />');
      expect(adaptive).toContain('<foreground android:drawable="@drawable/ic_launcher_foreground" />');
      expect(adaptive).toContain('<monochrome android:drawable="@drawable/ic_launcher_monochrome" />');
    }
  });

  it("the earlier two-stroke rune is gone from every drawing", () => {
    for (const { file } of RUNE_DRAWINGS) {
      const text = read(ROOT + file);
      for (const old of ["M12 3v18", "M5.5 8.5l13 6", "M12,3 L12,21", "moveTo(12f, 3f)", "Offset(12f * u, 3f * u)", "M12 5v14"]) expect(text, `${file}: ${old}`).not.toContain(old);
    }
  });

  it("BrandSigil renders the two bands filled in currentColor, hidden from a screen reader", () => {
    const html = renderToStaticMarkup(createElement(BrandSigil, { size: 18 }));
    expect(html).toContain('fill="currentColor"');
    expect(html).toContain('aria-hidden="true"');
    expect(html).not.toContain("stroke");
    expect(count(pathPolys(html), RUNE)).toBe(1);
  });

  it("the served favicon and the desktop's copy are the small tile verbatim, and the small tile is gold on hardwood", () => {
    const tile = read(`${BRAND}andvari-mark.svg`);
    expect(read("../../public/favicon.svg")).toBe(tile);
    expect(read(`${ROOT}app-desktop/icons/andvari.svg`)).toBe(tile);
    expect(tile).toMatch(GOLD);
    expect(tile).toMatch(/#1f1711/i);
  });

  it("every rendered icon the surfaces load is present", () => {
    // Presence only: a picture's pixels cannot be worked out here; `scripts/gen-brand-icons.sh --check` (the release
    // gate) renders them from the sources and compares. Do not mistake a green here for "these are current".
    for (const p of [
      "web/public/apple-touch-icon.png",
      "web/public/icon-192.png",
      "web/public/icon-512.png",
      "web/public/icon-512-maskable.png",
      "extension/icons/icon16.png",
      "extension/icons/icon32.png",
      "extension/icons/icon48.png",
      "extension/icons/icon128.png",
      "app-desktop/icons/andvari.ico",
      "app-desktop/icons/andvari.png",
      "app-desktop/src/main/resources/andvari.png",
      "app-ios/Andvari/Assets.xcassets/AppIcon.appiconset/icon-1024.png",
    ]) {
      expect(statSync(here(ROOT + p)).size, p).toBeGreaterThan(0);
    }
  });
});

describe("the name has one drawing: assets/brand/wordmark.svg", () => {
  /** Every copy of the outline in the tree, and how to find it in its file. */
  const COPIES: { file: string; find: RegExp }[] = [
    { file: "web/src/ui/Sigil.tsx", find: /WORDMARK_PATH =\s*"([^"]+)"/ },
    { file: "extension/src/brand.ts", find: /WORDMARK_PATH =\s*"([^"]+)"/ },
    { file: "app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt", find: /WORDMARK_PATH =\s*"([^"]+)"/ },
    { file: "app-android/src/main/res/drawable/andvari_wordmark.xml", find: /android:pathData="([^"]+)"/ },
  ];

  it("the source is one outline in currentColor, 1000 units to the em, the baseline at y = 0", () => {
    expect(SOURCE_VIEWBOX).toBe("0 -740 3017 980");
    expect(WORDMARK_SVG.match(/<path /g)).toHaveLength(1);
  });

  it.each(COPIES)("$file carries the source's outline verbatim, and fails with one number changed", ({ file, find }) => {
    const text = read(ROOT + file);
    expect(find.exec(text)?.[1]).toBe(SOURCE_D);
    expect(find.exec(text.replace("M126 14Q101", "M126 15Q101"))?.[1]).not.toBe(SOURCE_D);
  });

  it("every copy keeps the source's box", () => {
    expect(WORDMARK_VIEWBOX).toBe(SOURCE_VIEWBOX);
    expect(read(`${ROOT}extension/src/brand.ts`)).toContain(`export const WORDMARK_VIEWBOX = "${SOURCE_VIEWBOX}";`);
    const ui = read(`${ROOT}app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt`);
    for (const c of ["WORDMARK_WIDTH = 3017f", "WORDMARK_HEIGHT = 980f", "WORDMARK_BASELINE = 740f"]) expect(ui).toContain(c);
    const xml = read(`${ROOT}app-android/src/main/res/drawable/andvari_wordmark.xml`);
    for (const c of ['android:viewportWidth="3017"', 'android:viewportHeight="980"', 'android:translateY="740"']) expect(xml).toContain(c);
  });

  it("the web app's drawing is an image named andvari, in currentColor, and the outline is the source's", () => {
    const html = renderToStaticMarkup(createElement(Wordmark));
    expect(html).toContain('role="img"');
    expect(html).toContain('aria-label="andvari"');
    expect(html).toContain('fill="currentColor"');
    expect(html).toContain(`viewBox="${SOURCE_VIEWBOX}"`);
    expect(html).toContain(`d="${SOURCE_D}"`);
    expect(WORDMARK_PATH).toBe(SOURCE_D);
  });

  it("the first screen's heading is the drawing, so the heading is still named andvari", () => {
    expect(read("./Welcome.tsx")).toContain("<h1><Wordmark /></h1>");
    expect(read("./Welcome.tsx")).not.toContain("<h1>andvari</h1>");
  });

  it("the appbar carries the lockup: the rune, then the drawn name, with no whitespace between them", () => {
    // The parts are in inline flow, so a stray newline renders as a gap.
    expect(read("./Vault.tsx")).toContain('<span className="brand"><span className="sigil-sm"><BrandSigil size={18} /></span><Wordmark /></span>');
    const css = read("./styles.css");
    expect(css).toContain(".brand .sigil-sm svg { width: 0.913em; height: 0.913em; vertical-align: -0.105em;");
    expect(css).toContain(".wordmark { height: 0.98em; width: 3.017em; vertical-align: -0.24em; }");
  });

  it("the extension's pages carry named shells that their scripts fill with brand.ts's outline", () => {
    const shell = `<svg class="wordmark" role="img" aria-label="andvari" viewBox="${SOURCE_VIEWBOX}"><path data-wordmark="" fill="currentColor"/></svg>`;
    expect(read(`${ROOT}extension/popup.html`).split(shell).length - 1).toBe(2);
    expect(read(`${ROOT}extension/options.html`).split(shell).length - 1).toBe(1);
    expect(read(`${ROOT}extension/src/popup.ts`)).toContain("drawWordmarks(document);");
    expect(read(`${ROOT}extension/src/options.ts`)).toContain("drawWordmarks(document);");
    expect(read(`${ROOT}extension/src/brand.ts`)).toContain('root.querySelectorAll(".wordmark path[data-wordmark]")');
  });

  it("the in-page panel's head keeps the name as text, in one color: the content script has no room for the outline", () => {
    // The outline is 7 KB and the release content script must stay under its packaging cap (cardfillflag.test.ts).
    const ui = read(`${ROOT}extension/src/content-ui.ts`);
    expect(ui).toContain('brand.textContent = "andvari";');
    expect(ui).toContain("hdr.append(sigilSpan(14), brand);");
    expect(ui).not.toContain("WORDMARK_PATH");
  });

  it("the name is never set in two colors: the gold 'and' is gone from every surface", () => {
    for (const f of ["web/src/ui/Vault.tsx", "web/src/ui/styles.css", "extension/popup.html", "extension/options.html", "extension/popup.css", "extension/src/content-ui.ts", "extension/build.mjs"]) {
      expect(read(ROOT + f), f).not.toContain("a-mark");
    }
  });
});

describe("the web app manifest", () => {
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

  it("names the app, installs standalone, and paints in the brand colors", () => {
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
    // Without a maskable entry Android pads the "any" icon inside a white-ish shim rather than filling its mask.
    expect(bySize.has("512x512:maskable")).toBe(true);
    for (const icon of manifest.icons) {
      expect(icon.type).toBe("image/png");
      expect(icon.src.startsWith("/")).toBe(true);
      expect(statSync(here(`../../public${icon.src}`)).size, icon.src).toBeGreaterThan(0);
    }
  });
});
