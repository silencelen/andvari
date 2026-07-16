import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

/**
 * Server endpoint selection (design 2026-07-15-multi-tenant-endpoints §5.1) — the extension is
 * endpoint-agnostic: every consumer (api construction, WS URL, downloads absolutization, the
 * popup's open-vault tabs, the dynamic content-script exclusions) derives from ONE per-device
 * choice stored in chrome.storage.local, preconfigured for the reference instance.
 *
 * LEAF module by design (updateverify.ts discipline): no chrome import, no chrome types — the
 * storage area is resolved structurally from globalThis (or injected by tests), so `node --test`
 * loads it directly and the web pin suite can compile it.
 *
 * `storage.local`, NEVER `storage.sync` (§5.1, binding): the server choice is a PER-DEVICE trust
 * decision. Syncing it would let one phished/compromised device silently repoint every synced
 * browser at a hostile server; keeping it local bounds the blast radius to the device that made
 * the choice. serverurl.test.ts pins this — the sync area is never touched.
 */

export const DEFAULT_SERVER_URL = "https://andvari.monahanhosting.com";

/** The storage.local slot. Written only via setServerUrl (the wave-3 options page's Trust-Gate
 *  commit); background.ts treats ANY change of this key as an origin-clean server switch (§4.1). */
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

/** The minimal chrome.storage area surface used here — structural, so this leaf carries no chrome
 *  types and tests inject a plain object. */
export interface ServerUrlArea {
  get(keys: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

/** Resolve the REAL chrome.storage.local lazily and structurally (no top-level chrome reference —
 *  the module must evaluate under plain node). */
function chromeLocal(): ServerUrlArea | null {
  const g = globalThis as { chrome?: { storage?: { local?: ServerUrlArea } } };
  return g.chrome?.storage?.local ?? null;
}

/**
 * The configured server origin: `storage.local.serverUrl ?? DEFAULT_SERVER_URL` (§5.1). The stored
 * value is re-canonicalized defensively on every read so a hand-edited/legacy value resolves to
 * the same canonical form — and therefore the same originKey namespace — every time, or falls back
 * to the default. Storage failure also falls back to the default (the owner-run reference
 * instance): fail-safe against a wedged storage layer, never a crash loop.
 */
export async function getServerUrl(area: ServerUrlArea | null = chromeLocal()): Promise<string> {
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
 * every reader derives the same originKey). Throws on a non-origin input: the wave-3 options page
 * validates with canonicalizeServerUrl before ever reaching the Trust Gate, so a throw here is a
 * caller bug, not a user path. The write lands in storage.local only (per-device — see header).
 */
export async function setServerUrl(url: string, area: ServerUrlArea | null = chromeLocal()): Promise<string> {
  const canonical = canonicalizeServerUrl(url);
  if (canonical === null) throw new Error("not a valid server origin (need https://host[:port])");
  if (!area) throw new Error("storage.local unavailable");
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
