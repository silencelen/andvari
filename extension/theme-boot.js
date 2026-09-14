/*
 * theme-boot.js — pre-paint forced-theme applier for the extension's own pages
 * (popup.html, options.html, connector.html). H134, audit 2026-09-13.
 *
 * FAITHFUL TWIN of web/public/theme-boot.js and of readThemePref()/applyThemePref() in
 * src/theme.ts — keep all three in lockstep; theme.test.ts pins the shared invariants (the
 * storage key, the light|dark|auto parse, and Auto = REMOVE the attribute). The extension
 * runs on its own origin (chrome-extension://<id>) and cannot read the web app's
 * localStorage, so the preference is stored, and chosen, separately here; the MECHANISM is
 * identical so the two surfaces can never drift into different palettes for the same pick.
 *
 * Why a classic, render-blocking, same-origin script rather than doing this inside popup.js:
 *  - The MV3 extension_pages CSP is `script-src 'self'` — inline JS is barred outright.
 *  - The bundles are ES modules, which are DEFERRED: they run after the document is parsed,
 *    so a forced-Light user would see the dark popup flash first, every single time the
 *    toolbar popup opens. This runs before first paint. It is the same reason the web app
 *    carries public/theme-boot.js alongside useTheme.ts.
 *
 * Why localStorage and not chrome.storage.local, which the rest of the extension uses:
 *  chrome.storage is ASYNC, which cannot beat first paint — the flash this file exists to
 *  kill. localStorage is synchronous and, on an extension page, is scoped to the extension's
 *  own origin, so the popup, the options tab and the connector window all read the one value.
 *  Safe here because a theme preference is NOT secret: the storage.local-holds-no-secrets rule
 *  (background.ts) is about key material, and none of it is involved.
 *
 * Everything is wrapped: a failure (private-mode storage, a locked-down profile) falls back to
 * Auto/OS. Theming must never break a page whose job is unlocking the vault.
 */
(function () {
  try {
    var KEY = "andvari.theme"; // === THEME_STORAGE_KEY (src/theme.ts)
    var raw = null;
    try {
      raw = localStorage.getItem(KEY);
    } catch (e) {
      raw = null; // storage absent/blocked — the OS preference rules (readThemePref -> "auto")
    }
    var pref = raw === "light" || raw === "dark" ? raw : "auto";

    // applyThemePref: Auto REMOVES the attribute (the override never mirrors the OS value, so an
    // OS-level flip keeps working live); a forced value SETS it and pins color-scheme, so
    // UA-painted surfaces (scrollbars, form-control popups, the autofill dropdown) follow it too.
    var el = document.documentElement;
    if (pref === "auto") {
      el.removeAttribute("data-theme");
      el.style.colorScheme = "";
    } else {
      el.setAttribute("data-theme", pref);
      el.style.colorScheme = pref;
    }
  } catch (e) {
    /* never break a page over theming */
  }
})();
