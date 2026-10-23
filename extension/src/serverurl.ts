import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { trustedStore, type KvArea } from "./trustedkv.ts";

/**
 * Server endpoint selection (design 2026-07-15-multi-tenant-endpoints §5.1) — the extension is
 * endpoint-agnostic: every consumer (api construction, WS URL, downloads absolutization, the
 * popup's open-vault tabs, the dynamic content-script exclusions) derives from ONE per-device
 * choice, preconfigured for the reference instance.
 *
 * LEAF module by design (updateverify.ts discipline): no chrome import, no chrome types — the
 * store is injected (tests pass a plain object), so `node --test` loads it directly and the web pin
 * suite can compile it.
 *
 * Where the choice lives (security review 2026-10, branch A15): the TRUSTED store (trustedkv.ts, the
 * extension origin's IndexedDB), written only by the service worker on the options page's
 * `setServerUrl` message after the Trust Gate. NEVER chrome.storage.local: content scripts can write
 * that area (Chrome before 140, Firefox always), and before A15 a write of this key there repointed
 * the extension with no Trust Gate. NEVER storage.sync either (§5.1, binding): the server choice is a
 * PER-DEVICE trust decision, and syncing it would let one phished device repoint every synced browser.
 * serverurl.test.ts pins both: a planted local or sync value is never read.
 */

export const DEFAULT_SERVER_URL = "https://andvari.monahanhosting.com";

/** The trusted-store slot. Written only via setServerUrl, by the service worker's `setServerUrl` message handler
 *  (the options page's Trust-Gate commit), which then runs the origin-clean server switch (§4.1). */
export const SERVER_URL_KEY = "serverUrl";

/** Enroll-link origin rule — web/src/enroll/enrolllink.ts ORIGIN_RE, mirrored verbatim (design §3):
 *  scheme EXACTLY http|https (kills javascript:/data:/file:), lowercase host[:port] only, no
 *  path/slash/userinfo. Well-formedness + scheme safety only; trust judgment is the Trust Gate's. */
const ORIGIN_RE = /^https?:\/\/(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:[0-9]{1,5})?$/;

/**
 * Normalize user/storage input to the canonical origin form `scheme://host[:non-default port]`
 * (§4.2 — the exact string the originKey namespace hashes), or null when the input is not a plain
 * http(s) origin. WHATWG URL does the normalization work: lowercases scheme+host, punycodes IDN
 * hosts (the trust gate renders the xn-- form — IDN defense), drops default ports (:443/:80), and
 * canonicalizes IPv6 literals. A path beyond "/", query, fragment, or userinfo is a pasted page
 * URL or a hand-mangled value — reject rather than guess (the enroll-link parser's posture).
 */
export function canonicalizeServerUrl(input: string): string | null {
  let u: URL;
  try {
    u = new URL(input.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.pathname !== "/" && u.pathname !== "") return null;
  if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") return null;
  const origin = `${u.protocol}//${u.hostname}${u.port ? `:${u.port}` : ""}`;
  return ORIGIN_RE.test(origin) ? origin : null;
}

/** The store surface used here — structural (a [KvArea] subset), so tests inject a plain object. */
export type ServerUrlArea = Pick<KvArea, "get" | "set">;

/**
 * The configured server origin: the trusted store's `serverUrl ?? DEFAULT_SERVER_URL` (§5.1). The stored
 * value is re-canonicalized defensively on every read so a hand-edited/legacy value resolves to
 * the same canonical form — and therefore the same originKey namespace — every time, or falls back
 * to the default. A store that cannot be opened (no IndexedDB: Firefox private browsing) also falls
 * back to the default (the owner-run reference instance): fail-safe, never a crash loop, and never a
 * read of chrome.storage.local instead.
 */
export async function getServerUrl(area: ServerUrlArea | null = trustedStore()): Promise<string> {
  if (!area) return DEFAULT_SERVER_URL; // non-extension context (tests inject their own area)
  try {
    const v = (await area.get(SERVER_URL_KEY))[SERVER_URL_KEY];
    return (typeof v === "string" ? canonicalizeServerUrl(v) : null) ?? DEFAULT_SERVER_URL;
  } catch {
    return DEFAULT_SERVER_URL;
  }
}

/**
 * Persist a new server origin (canonicalized first — the stored value is ALWAYS canonical, so
 * every reader derives the same originKey). Throws on a non-origin input (the worker's handler
 * canonicalizes before calling, so a throw here is a caller bug), and rethrows a store failure
 * (TrustedStoreUnavailable) so the options page can say the choice was not kept. Trusted store only.
 */
export async function setServerUrl(url: string, area: ServerUrlArea | null = trustedStore()): Promise<string> {
  const canonical = canonicalizeServerUrl(url);
  if (canonical === null) throw new Error("not a valid server origin (need https://host[:port])");
  if (!area) throw new Error("trusted store unavailable");
  await area.set({ [SERVER_URL_KEY]: canonical });
  return canonical;
}

/** Per-origin namespace key: hex(sha256(canonical origin)).take(16) — the SAME scheme as the
 *  native clients (§4.2), stable and path-safe. Callers pass a CANONICAL origin (getServerUrl /
 *  canonicalizeServerUrl output); the 16-hex prefix is fixed-width, so namespaces can never
 *  prefix-collide. */
export function originKeyFor(canonicalOrigin: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalOrigin))).slice(0, 16);
}

/** Compose a per-origin storage key: `ns.<originKey>.<key>` (§4.2/B2-7). Namespaced material is
 *  PRESERVED across server switches — an A→B→A round trip keeps A's quick-unlock/PIN material,
 *  bounded by the quick-unlock staleness ceiling — and wiped ONLY by that origin's own
 *  policy-forbid or the explicit wave-3 "remove data for this server" action
 *  (background.purgeOriginNamespace). */
export function nsKey(originKey: string, key: string): string {
  return `ns.${originKey}.${key}`;
}

/**
 * A canonical origin → the match pattern covering its host (for the dynamic content script's
 * excludeMatches, B2-5). Match patterns cannot carry a port, so the pattern matches the host on
 * EVERY port — over-excluding, which is the safe direction for a vault origin. Null when the
 * origin cannot be expressed as a pattern (bracketed IPv6 literal): the caller must fail CLOSED —
 * registering no autofill at all beats injecting it into a vault UI we failed to exclude.
 */
export function originMatchPattern(origin: string): string | null {
  const m = /^(https?):\/\/([a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:[0-9]{1,5})?$/.exec(origin);
  const scheme = m?.[1];
  const host = m?.[2];
  return scheme && host ? `${scheme}://${host}/*` : null;
}

/**
 * Middle-truncate an origin for the popup header's persistent anti-phishing display (design §5.1):
 * the RAW origin is always shown, but a long self-host URL is elided in the MIDDLE (keeping the
 * scheme + start AND the tail) rather than the end — so the host's most impersonation-prone parts,
 * its beginning and its final labels, both stay visible. The full origin rides the element's
 * title/aria-label for hover/focus. `max` is the visible character budget; an origin already within
 * it is returned unchanged. The ellipsis is the single-char U+2026 so it never itself reads as a dot.
 */
export function middleTruncateOrigin(origin: string, max = 34): string {
  if (max < 5 || origin.length <= max) return origin;
  const keep = max - 1; // one char goes to the ellipsis
  const head = Math.ceil(keep / 2);
  const tail = Math.floor(keep / 2);
  return origin.slice(0, head) + "…" + origin.slice(origin.length - tail);
}
