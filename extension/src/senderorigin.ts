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

/** Where a tab sender's origin was read: the browser's own `origin`, the frame's own `url`, or nowhere. */
export type OriginSource = "origin" | "url" | "none";

/** The origin of an http(s) URL, or null for any other scheme (about:, blob:, data:, an extension page) or a non-URL. */
export function webOriginOfUrl(u: unknown): string | null {
  if (typeof u !== "string") return null;
  try {
    const url = new URL(u);
    return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "" ? url.origin : null;
  } catch {
    return null;
  }
}

/**
 * Safari on iOS (L8): Safari does not promise `sender.origin`. When an engine sets none at all, every origin check here
 * would fail closed and card fill would silently never work there. This reads the TOP frame's origin from the
 * browser-set URL of the frame that sent the message; every handler then applies its usual checks to it. Rules, each
 * fail-closed:
 *  - an engine that sets an origin is believed, the opaque "null" of a sandboxed frame included: its URL is then never
 *    consulted (root cause E: a sandboxed frame keeps a real URL host);
 *  - only the top frame (`frameId` exactly 0): a sub-frame's URL fallback could not be told from a sandboxed frame's;
 *  - only the frame's OWN URL, never the tab's: the tab's URL is what the handlers compare the sender against (the
 *    current top-level origin), so deriving the sender from it would make that check circular, and mid-navigation it
 *    may already name the next document (round-5 review C3). No frame URL: no origin;
 *  - only http(s).
 * The remaining trade-off: on such an engine, a top document the site itself serves sandboxed (a CSP `sandbox`
 * response) is taken as its site. It is said in the popup's Details which source was used.
 */
export function derivedPageOrigin(sender: { origin?: unknown; url?: unknown; frameId?: unknown }): { origin: string | null; source: OriginSource } {
  if (sender.origin !== undefined) return { origin: typeof sender.origin === "string" ? sender.origin : null, source: "origin" };
  if (sender.frameId !== 0) return { origin: null, source: "none" };
  const fromUrl = webOriginOfUrl(sender.url);
  return fromUrl !== null ? { origin: fromUrl, source: "url" } : { origin: null, source: "none" };
}
