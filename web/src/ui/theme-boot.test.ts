import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

/**
 * Drift guard: `web/public/theme-boot.js` is the render-blocking, CSP-safe pre-paint twin of
 * `readThemePref()`/`applyThemePref()`/`syncThemeColorMetas()` in `useTheme.ts` (the cold-load
 * FOUC fix). It is plain JS in /public — NO import graph reaches it, so tsc/vitest can't catch a
 * one-sided edit that would silently reintroduce the theme flash. These source-substring pins (the
 * extension-pins.test.ts / token-lockstep.test.ts idiom) fail loudly if the two desync on the
 * load-bearing invariants: the storage key, the light|dark|auto parse, the data-theme set/remove +
 * color-scheme pin, and the theme-color <meta> media stash.
 */
const boot = readFileSync(fileURLToPath(new URL("../../public/theme-boot.js", import.meta.url)), "utf-8");
const useTheme = readFileSync(fileURLToPath(new URL("./useTheme.ts", import.meta.url)), "utf-8");

describe("theme-boot.js stays a faithful twin of useTheme.ts", () => {
  it("uses the exact THEME_STORAGE_KEY literal from useTheme.ts", () => {
    const m = useTheme.match(/THEME_STORAGE_KEY\s*=\s*"([^"]+)"/);
    expect(m, "THEME_STORAGE_KEY literal not found in useTheme.ts").toBeTruthy();
    const key = m![1];
    expect(key).toBe("andvari.theme");
    // the boot script must read from the SAME key
    expect(boot).toContain(`"${key}"`);
    expect(boot).toContain("localStorage.getItem(KEY)");
  });

  it("parses the persisted value with the same light|dark|else-auto rule", () => {
    // useTheme: raw === "light" || raw === "dark" ? raw : "auto"
    expect(boot).toMatch(/raw === "light" \|\| raw === "dark" \? raw : "auto"/);
  });

  it("stamps data-theme + color-scheme with Auto=remove semantics (both sides)", () => {
    for (const src of [boot, useTheme]) {
      expect(src).toContain('removeAttribute("data-theme")');
      expect(src).toContain('setAttribute("data-theme", pref)');
      // Auto clears color-scheme; a forced value pins it
      expect(src).toMatch(/colorScheme = ""/);
      expect(src).toMatch(/colorScheme = pref/);
    }
  });

  it("syncs the theme-color <meta> pair via the same data-auto-media stash + media flip", () => {
    // both walk meta[name="theme-color"] and stash the original media in dataset.autoMedia
    for (const src of [boot, useTheme]) {
      expect(src).toContain(`querySelectorAll`);
      expect(src).toContain(`meta[name="theme-color"]`);
      expect(src).toMatch(/dataset\.autoMedia/);
      // forced theme: matching meta -> "all", other -> "not all"
      expect(src).toContain('"all"');
      expect(src).toContain('"not all"');
    }
    // the boot twin uses indexOf (no String.prototype.includes assumptions pre-bundle);
    // useTheme uses includes — both express "original contains pref"
    expect(boot).toMatch(/original\.indexOf\(pref\) !== -1/);
    expect(useTheme).toMatch(/original\.includes\(pref\)/);
  });

  it("fails safe to Auto/OS on storage error (never throws out of the pre-paint script)", () => {
    // outer + inner try/catch so a blocked localStorage falls back to auto, boot never breaks
    expect(boot.match(/try\s*\{/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
  });
});
