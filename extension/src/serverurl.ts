import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { isOrigin } from "./statement.ts";
import { trustedStore, type KvArea } from "./trustedkv.ts";

/**
 * Server endpoint selection. Every consumer (api construction, WS URL, the popup's open-vault tabs, the dynamic
 * content-script exclusions) derives from ONE per-device choice.
 *
 * No build has a default server (design 2026-11-15-onboarding-trust §0.2 O, §15 `extension` row): until the person
 * chooses "andvari" (the baked public instance, publicinstance.ts) or their own server behind the Trust Gate, the
 * worker holds [NO_SERVER_ORIGIN], a name that can never resolve (RFC 6761 `.invalid`), and dials nothing.
 *
 * Every origin the extension stores, dials or shows passes the §2.2 `origin` grammar (statement.ts `isOrigin`), the
 * single source (R4): https with a domain name, or plain http only for localhost and 127.0.0.1. Anything it cannot
 * carry is refused with "andvari needs an https address with a domain name for this server."
 *
 * LEAF module (no chrome import): the store is injected, so `node --test` loads it directly.
 *
 * Where the choice lives: the TRUSTED store (trustedkv.ts, the extension origin's IndexedDB), written only by the
 * service worker after a verified pin (pinstore.ts). Never chrome.storage.local (content scripts can write it) and
 * never storage.sync (the server choice is a per-device trust decision).
 */

/** The origin the worker holds while no server is chosen. In the §2.2 grammar, so it can be namespaced; never dialed. */
export const NO_SERVER_ORIGIN = "https://no-server.invalid";

/** Approved wording (decided on 2026-11-17): the refusal for an address the §2.2 grammar cannot carry (R4). */
export const ORIGIN_REFUSED = "andvari needs an https address with a domain name for this server.";

/** The trusted-store slot of the server choice. */
export const SERVER_URL_KEY = "serverUrl";

/**
 * Normalize typed or stored input to the canonical origin form, or null when the result is not in the §2.2 grammar.
 * A bare host is read as https. WHATWG URL lowercases, writes an IDN host as its `xn--` A-labels and drops a default
 * port; then the grammar decides, so an IP literal, a single-label host, a trailing dot, a path, a query, a fragment
 * or userinfo is refused rather than guessed at.
 */
export function canonicalizeServerUrl(input: string): string | null {
  const trimmed = input.trim();
  // Already in the grammar: kept as written. An `xn--` label is a plain label there, never decoded (VR-5), whereas
  // WHATWG URL would refuse an `xn--` label that is not valid punycode.
  if (isOrigin(trimmed)) return trimmed;
  let u: URL;
  try {
    u = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.pathname !== "/" && u.pathname !== "") return null;
  if (u.search !== "" || u.hash !== "" || u.username !== "" || u.password !== "") return null;
  const origin = `${u.protocol}//${u.hostname}${u.port ? `:${u.port}` : ""}`;
  return isOrigin(origin) ? origin : null;
}

/** The store surface used here — structural (a [KvArea] subset), so tests inject a plain object. */
export type ServerUrlArea = Pick<KvArea, "get" | "set">;

/**
 * The configured server origin, or [NO_SERVER_ORIGIN] when none is chosen, the stored value is not in the grammar, or
 * the store cannot be read. The stored value is re-canonicalized on every read, so it always maps to one namespace.
 */
export async function getServerUrl(area: ServerUrlArea | null = trustedStore()): Promise<string> {
  if (!area) return NO_SERVER_ORIGIN;
  try {
    const v = (await area.get(SERVER_URL_KEY))[SERVER_URL_KEY];
    return (typeof v === "string" ? canonicalizeServerUrl(v) : null) ?? NO_SERVER_ORIGIN;
  } catch {
    return NO_SERVER_ORIGIN;
  }
}

/** Persist a server origin (canonical first). Throws on an origin outside the grammar and rethrows a store failure. */
export async function setServerUrl(url: string, area: ServerUrlArea | null = trustedStore()): Promise<string> {
  const canonical = canonicalizeServerUrl(url);
  if (canonical === null || canonical === NO_SERVER_ORIGIN) throw new Error(ORIGIN_REFUSED);
  if (!area) throw new Error("trusted store unavailable");
  await area.set({ [SERVER_URL_KEY]: canonical });
  return canonical;
}

/** Per-origin namespace key: hex(sha256(canonical origin)).take(16), the scheme the native clients use. */
export function originKeyFor(canonicalOrigin: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(canonicalOrigin))).slice(0, 16);
}

/** Compose a per-origin storage key: `ns.<originKey>.<key>`. */
export function nsKey(originKey: string, key: string): string {
  return `ns.${originKey}.${key}`;
}

/**
 * A canonical origin → the match pattern covering its host (the dynamic content script's excludeMatches). Match
 * patterns cannot carry a port, so the pattern matches the host on every port: over-excluding, the safe direction for
 * a vault origin. Null when the origin is not in the grammar: the caller fails closed.
 */
export function originMatchPattern(origin: string): string | null {
  if (!isOrigin(origin)) return null;
  const u = new URL(origin);
  return `${u.protocol}//${u.hostname}/*`;
}

/**
 * Middle-truncate an origin for the popup header's anti-phishing display: the raw origin is always shown, but a long
 * one is elided in the MIDDLE, so its beginning and its final labels both stay visible. The full origin rides the
 * element's title/aria-label. The ellipsis is the single-char U+2026, so it never reads as a dot.
 */
export function middleTruncateOrigin(origin: string, max = 34): string {
  if (max < 5 || origin.length <= max) return origin;
  const keep = max - 1;
  const head = Math.ceil(keep / 2);
  const tail = Math.floor(keep / 2);
  return origin.slice(0, head) + "…" + origin.slice(origin.length - tail);
}
