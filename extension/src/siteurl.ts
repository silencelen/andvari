// Sanitize a saved login URI into a safe, openable web link for the popup's detail view.
// A saved uri is user data and can be anything — `javascript:`, `data:`, `file:`,
// `chrome:` — so rendering one as a clickable <a href> without this guard is an
// exec/exfil vector. ONLY http/https survive; everything else renders as inert text.
// Pure + chrome-free so the extension test harness (node --test) can pin the guarantees.

/** A safe, absolute http(s) URL for [raw], or null if it cannot be one. A scheme-less uri
 *  ("example.com/login") defaults to https; any non-http(s) scheme returns null. */
export function safeSiteUrl(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  if (s.startsWith("/")) return null; // a site uri never starts with a slash (kills "//host" protocol-relative)
  // Only a real "<scheme>://" prefix is honored; a bare "javascript:" / "data:" (no //)
  // therefore gets an https:// prefix and fails to parse as a host — inert, not executable.
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  let u: URL;
  try {
    u = new URL(candidate);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (!u.hostname) return null; // e.g. "//x" → "https:////x" parses with an empty host
  return u.href;
}

/** Compact, host-first display text for a site link — never the query string, truncated so a
 *  long path can't blow out the popup. Falls back to [raw] when it isn't a safe URL. */
export function displaySite(raw: string, max = 44): string {
  const safe = safeSiteUrl(raw);
  if (!safe) return raw.length > max ? raw.slice(0, max - 1) + "…" : raw;
  const u = new URL(safe);
  const shown = u.host + (u.pathname !== "/" ? u.pathname : "");
  return shown.length > max ? shown.slice(0, max - 1) + "…" : shown;
}
