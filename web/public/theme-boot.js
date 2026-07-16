/*
 * theme-boot.js — pre-paint forced-theme applier (cold-load FOUC fix).
 *
 * A user who forces Light/Dark in Settings persists that choice in localStorage; the JS
 * bundle applies it in a useLayoutEffect (initTheme -> applyThemePref), which runs AFTER
 * first paint — so on a cold load they briefly see the OTHER (OS) theme flash. The server
 * CSP is `script-src 'self'` (NO inline JS — see index.html), so the fix is THIS external,
 * same-origin, classic (render-blocking) script referenced in <head> before the module
 * bundle: it stamps <html data-theme> + color-scheme (and the theme-color <meta> pair)
 * BEFORE first paint. initTheme re-runs the identical logic on mount, so this is an
 * idempotent pre-run, never a divergent path.
 *
 * FAITHFUL TWIN of readThemePref() / applyThemePref() / syncThemeColorMetas() in
 * src/ui/useTheme.ts — keep the two in lockstep (token-lockstep.test.ts pins the CSS
 * data-theme blocks as byte-twins of the scheme blocks; a forced theme must not drift from
 * Auto). Everything is wrapped so a failure (e.g. localStorage blocked in private mode)
 * falls back to Auto/OS and lets the bundle re-apply on mount — booting never breaks over
 * theming.
 */
(function () {
  try {
    var KEY = "andvari.theme"; // === THEME_STORAGE_KEY (useTheme.ts)
    var raw = null;
    try {
      raw = localStorage.getItem(KEY);
    } catch (e) {
      raw = null; // storage absent/blocked — the OS preference rules (readThemePref -> "auto")
    }
    var pref = raw === "light" || raw === "dark" ? raw : "auto";

    // applyThemePref: Auto REMOVES the attribute (the override never mirrors the OS value);
    // a forced value SETS it, and pins color-scheme so UA-painted surfaces follow the theme.
    var el = document.documentElement;
    if (pref === "auto") {
      el.removeAttribute("data-theme");
      el.style.colorScheme = "";
    } else {
      el.setAttribute("data-theme", pref);
      el.style.colorScheme = pref;
    }

    // syncThemeColorMetas: pin the matching theme-color <meta> on (media="all") and the
    // other off (media="not all") for a forced theme; Auto restores the original media
    // query stashed in data-auto-media the first time it is touched (so initTheme's later
    // re-run reads the same original and stays idempotent).
    var metas = document.querySelectorAll('meta[name="theme-color"]');
    for (var i = 0; i < metas.length; i++) {
      var m = metas[i];
      var original = m.dataset.autoMedia;
      if (original === undefined) {
        original = m.getAttribute("media") || "";
        m.dataset.autoMedia = original;
      }
      if (pref === "auto") {
        if (original) m.setAttribute("media", original);
        else m.removeAttribute("media");
      } else {
        m.setAttribute("media", original.indexOf(pref) !== -1 ? "all" : "not all");
      }
    }
  } catch (e) {
    /* never break boot over theming — initTheme re-applies the persisted preference on mount */
  }
})();
