// Who is asking — from the BROWSER, never from the page (security review 2026-10, root cause E).
//
// A content script runs inside the page it reports on, so anything it sends about where it is
// (`location.href`, `location.hostname`) is page-influenced: a sandboxed frame keeps its URL host
// while its origin is opaque, and a hostile frame's script can say anything. `sender.origin` is set
// by the browser on every message. Every capture and match decision for a TAB sender derives its
// host here; only the popup (no tab) names a host itself, from `activeTabHost()` under activeTab.
// Pure and chrome-free so node --test pins it (senderorigin.test.ts).
import { capturedSiteUri } from "./siteurl.ts";
import { normalizeHost } from "./urimatch.ts";

/** The normalized host of a browser-set `sender.origin`, or null when it is missing, empty, the
 *  opaque "null" of a sandboxed frame, or unparseable — and null never matches a host. */
export function originHost(origin: unknown): string | null {
  if (typeof origin !== "string" || origin === "" || origin === "null") return null;
  try {
    return normalizeHost(new URL(origin).host);
  } catch {
    return null;
  }
}

/** The host a request is about: a tab sender's browser-set origin (its `claimed` host is ignored),
 *  or, for the popup, the host it named. */
export function requestHost(isTabSender: boolean, origin: unknown, claimed: string): string | null {
  return isTabSender ? originHost(origin) : normalizeHost(claimed);
}

/** A captured login's binding: the site host and the uri a NEW item stores (H124: the origin's own
 *  scheme and port for plain http, else `https://<host>`) — both from the browser-set origin. */
export function captureBinding(origin: unknown): { host: string; uri: string } | null {
  const host = originHost(origin);
  if (host === null) return null;
  return { host, uri: capturedSiteUri(origin as string, host) };
}
