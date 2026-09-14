/**
 * User theme override for the extension's own pages (H134, audit 2026-09-13) — the twin of
 * web/src/ui/useTheme.ts, and of the pre-paint classic script theme-boot.js next to it.
 *
 * The web app persists Auto/Light/Dark per browser and stamps <html data-theme="light|dark">,
 * which the two `:root[data-theme=…]` blocks in popup.css turn into a full palette flip. The
 * extension lives on its own origin and CANNOT read the web app's localStorage, so a user who
 * forced Light in the web vault still got a dark popup in the same browser — the drift H134
 * names. The fix is parity, not sharing: the same mechanism, the same key name, the same
 * Auto-removes-the-attribute semantics, chosen once in Options → Appearance and applied to the
 * popup, the options tab and the connector window (one extension origin, one localStorage).
 *
 * Keep this file, theme-boot.js and web/src/ui/useTheme.ts in lockstep — theme.test.ts asserts
 * the shared invariants across this file and theme-boot.js.
 */

export type ThemePref = "auto" | "light" | "dark";

/** Own key, matching the web app's (different origin, so no collision — just one vocabulary). */
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
 * Stamp the preference onto the document. Auto REMOVES the attribute rather than writing the
 * OS's current value, so an OS-level light/dark flip keeps working live under Auto. Also pins
 * `color-scheme` so UA-painted surfaces (scrollbars, form-control popups) follow a forced theme.
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
}

/** Persist + apply. A blocked store still themes the current page for its lifetime. */
export function setThemePref(pref: ThemePref): void {
  try {
    if (pref === "auto") localStorage.removeItem(THEME_STORAGE_KEY);
    else localStorage.setItem(THEME_STORAGE_KEY, pref);
  } catch {
    // storage blocked — the stamp below still themes this page
  }
  applyThemePref(pref);
}
