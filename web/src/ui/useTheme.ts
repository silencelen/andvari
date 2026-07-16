import { useState } from "react";

/**
 * UI-audit #26 (docs/design/2026-07-12-frontend-ui-audit.md): user theme override
 * (Auto / Light / Dark). The OS media query stays the default; a persisted, per-browser
 * preference stamps `<html data-theme="light|dark">`, which the two `[data-theme]` blocks
 * at the top of styles.css (byte-twins of the scheme blocks, pinned by
 * token-lockstep.test.ts) turn into a full palette flip. "Auto" REMOVES the attribute —
 * the override never mirrors the OS value, so an OS-level flip keeps working live.
 *
 * Per-browser, not per-account, on purpose: the theme must apply to the signed-out
 * Welcome/Unlock cards too, before we know who is signing in. Node-import-safe: nothing
 * here touches the DOM or storage at module scope (the web vitest suite runs in node).
 */

export type ThemePref = "auto" | "light" | "dark";

/** Own key (session.ts idiom): survives sign-out, which clears only the session key. */
export const THEME_STORAGE_KEY = "andvari.theme";

export function readThemePref(): ThemePref {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    return raw === "light" || raw === "dark" ? raw : "auto";
  } catch {
    return "auto"; // storage absent/blocked — the OS preference rules
  }
}

/**
 * Stamp the preference onto the document. Also pins `color-scheme` (so UA-painted
 * surfaces — scrollbars, form-control popups — follow the forced theme, not the OS)
 * and the index.html `<meta name="theme-color">` pair (the browser-chrome tint).
 */
export function applyThemePref(pref: ThemePref): void {
  const el = document.documentElement;
  if (pref === "auto") {
    el.removeAttribute("data-theme");
    el.style.colorScheme = "";
  } else {
    el.setAttribute("data-theme", pref);
    el.style.colorScheme = pref;
  }
  syncThemeColorMetas(pref);
}

/**
 * index.html carries one theme-color meta per scheme, each scoped by a `media`
 * attribute. A forced theme pins the matching meta on (`all`) and the other off
 * (`not all`); Auto restores the original media queries, stashed on the element the
 * first time we touch it — no color literal is duplicated here (lockstep hygiene).
 */
function syncThemeColorMetas(pref: ThemePref): void {
  for (const m of Array.from(document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]'))) {
    let original = m.dataset.autoMedia;
    if (original === undefined) {
      original = m.getAttribute("media") ?? "";
      m.dataset.autoMedia = original;
    }
    if (pref === "auto") {
      if (original) m.setAttribute("media", original);
      else m.removeAttribute("media");
    } else {
      m.setAttribute("media", original.includes(pref) ? "all" : "not all");
    }
  }
}

/** Boot-time application of the persisted preference — App calls this once, pre-paint
 *  (useLayoutEffect). A cold load stamps the attribute even EARLIER via the classic
 *  same-origin `/theme-boot.js` (public/, referenced in index.html <head> — inline JS is
 *  CSP-barred), a faithful twin of applyThemePref/readThemePref that kills the forced-theme
 *  FOUC; this call re-runs the identical logic idempotently once React mounts. Keep the two
 *  in lockstep — if you change applyThemePref/readThemePref/syncThemeColorMetas, mirror it
 *  in theme-boot.js. */
export function initTheme(): void {
  applyThemePref(readThemePref());
}

/** The Settings-facing hook: current preference + a setter that persists and applies.
 *  The attribute lives on <html> (outside React), so no other component needs to
 *  re-render when it changes. */
export function useThemePref(): [ThemePref, (pref: ThemePref) => void] {
  const [pref, setPrefState] = useState<ThemePref>(readThemePref);
  const setPref = (p: ThemePref) => {
    setPrefState(p);
    try {
      if (p === "auto") localStorage.removeItem(THEME_STORAGE_KEY);
      else localStorage.setItem(THEME_STORAGE_KEY, p);
    } catch {
      // storage blocked — the stamp below still themes this tab for its lifetime
    }
    applyThemePref(p);
  };
  return [pref, setPref];
}
