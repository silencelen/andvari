/**
 * §2.3 R8: a SERVER-DECLARED url is untrusted decoration. The client renders one as a raw link
 * ONLY when it is a real http(s) URL, so a hostile (or merely misconfigured) server cannot slip a
 * `javascript:` / `data:` href in front of the user. Both helpers return the url VERBATIM when it
 * is safe and null when it is not — and every caller must treat null exactly like "absent", never
 * like "render it anyway".
 *
 * Shared (audit F14) rather than private to Welcome: the rule was stated and enforced for the
 * landing's `selfHostDocsUrl` and skipped for all five hrefs the Devices card takes from
 * /downloads/manifest.json — the same class of value, from the same source, with the safety
 * resting entirely on a CSP nobody re-checks when that component changes.
 */

/** ABSOLUTE http(s) only — for a url that must point somewhere off this app (the landing's
 *  self-host docs link). Anything without a parseable absolute http(s) scheme is refused. */
export function safeHttpUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const scheme = new URL(url).protocol;
    return scheme === "https:" || scheme === "http:" ? url : null;
  } catch {
    return null;
  }
}

/**
 * Same rule for a url that MAY legitimately be relative — the downloads manifest's own artifacts
 * are served as same-origin paths ("/downloads/andvari-0.6.0.msi") alongside absolute store
 * listings. Resolution happens against this document, and the check is on the RESULT, so a
 * relative path inherits the page's http(s) scheme and passes while `javascript:` / `data:` /
 * `blob:` still cannot. The returned string is the ORIGINAL, so a relative href stays relative.
 */
export function safeHttpHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    // The fallback base only matters in the node test env (no document): it is never used for
    // navigation — only to decide the scheme a relative path would inherit.
    const base = typeof location !== "undefined" && location.href ? location.href : "https://localhost/";
    const scheme = new URL(url, base).protocol;
    return scheme === "https:" || scheme === "http:" ? url : null;
  } catch {
    return null;
  }
}
