/**
 * Enroll-link compose/parse — one of two byte-identical twins (the other is core
 * EnrollLink.kt), pinned to spec/test-vectors/enrolllink.json. Any behavioral divergence
 * between the twins is a vector failure, so every rule below is mirrored verbatim and
 * pinned by a row:
 *
 *  - Link shape: `<origin>/enroll#a1.<b64url-nopad(compact {"v":1,"o","t","e"})>`.
 *  - parseEnrollLink is TOTAL: null on ANY malformed input, never throws — it runs in UI
 *    layers on three platforms and a throwing parser is a crash primitive.
 *  - composeEnrollLink rejects (null) ill-formed UTF-16 input: on a lone surrogate the
 *    twins' JSON encoders genuinely diverge (ES2019+ JSON.stringify escapes as \udXXX;
 *    plain Kotlin encoding U+FFFD-replaces) — identical input, different links — so
 *    reject is the only pinnable agreement (composeRejects vectors). Well-formed astral
 *    pairs (emoji) pass through as raw 4-byte UTF-8 on both twins (roundTrips vectors).
 *  - Normalize before decode: strip ASCII whitespace (chat apps hard-wrap b64), then
 *    trailing '=' padding (core's decoder tolerates padding, a URLSAFE_NO_PADDING decoder
 *    does not — the strip makes them agree), then require the b64url alphabet and that
 *    the decoded bytes RE-ENCODE to the same body (canonical-form pin — masks
 *    decoder-leniency differences such as nonzero trailing bits).
 *  - JSON: unknown keys are ACCEPTED (forward compat — JSON.parse ignores them; the
 *    Kotlin twin sets ignoreUnknownKeys=true to match). DUPLICATE top-level keys are
 *    REJECTED on both twins via a shared lexical scan (JSON.parse is silently last-wins,
 *    kotlinx is version-dependent — reject is the only pinnable agreement); a backslash
 *    escape inside a key also rejects, so a unicode-escaped key cannot alias a plain `t`.
 *    Raw control chars anywhere in the decoded text reject (parsers disagree about them
 *    in places; compose never emits any).
 *  - v compares NUMERICALLY (`1.0` parses to 1 — after JSON.parse they are the same
 *    number, so the Kotlin twin matches); the STRING "1" rejects.
 *  - `o` must be a canonical lowercase http(s) origin — scheme EXACTLY http or https
 *    (kills javascript:/data:/file:), host[:port] only, no path/slash/userinfo. This is
 *    well-formedness + scheme safety ONLY; private-vs-public judgment is the consumer's
 *    (the web consumer additionally requires payload.o === location.origin).
 *  - Total input length is capped at MAX_LEN (QR payloads are ~3 KB at most; the cap
 *    bounds the regex/scan work on hostile input). `t` and `e` must be non-empty.
 *
 * This module is deliberately self-contained (atob/btoa + TextDecoder, no crypto/bytes.ts
 * import): captureEnrollFromLocation runs at module load in main.tsx, BEFORE initSodium()
 * resolves, so the sodium-backed helpers would throw. No React imports either.
 */

export type EnrollPayload = { v: number; o: string; t: string; e: string };

const PREFIX = "a1.";
const MAX_LEN = 8192;
const WS_RE = /[ \t\n\r\v\f]/g; // \v\f mirror the Kotlin twin's U+000B/U+000C
const PAD_RE = /=+$/;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;
const ORIGIN_RE = /^https?:\/\/(\[[0-9a-f:.]+\]|[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:[0-9]{1,5})?$/;
// Well-formed UTF-16 = a sequence of (non-surrogate | high+low pair) code units. Anchored
// alternation with disjoint first-chars: linear, no lookbehind (pre-16.4 Safari), and no
// reliance on String.isWellFormed (ES2024).
const WELL_FORMED_UTF16_RE = /^(?:[\u0000-\uD7FF\uE000-\uFFFF]|[\uD800-\uDBFF][\uDC00-\uDFFF])*$/;

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(PAD_RE, "");
}

function b64urlDecode(body: string): Uint8Array | null {
  const b64 = body.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (body.length % 4)) % 4);
  let bin: string;
  try {
    bin = atob(b64);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Build `<origin>/enroll#a1.<b64url(payload)>`, or null when any input carries ill-formed
 * UTF-16 (a lone/unpaired surrogate) — see the header: a lone surrogate would mint
 * DIFFERENT links on the two twins, so rejection is the pinned agreement, and null
 * mirrors parseEnrollLink's failure convention. The scan runs on each RAW input (never
 * their concatenation — that could pair surrogates across a boundary; and by
 * JSON.stringify time a lone surrogate is already escaped to ASCII and undetectable).
 * No other validation: origin is the minting client's location.origin (a non-canonical
 * origin simply produces a link parseEnrollLink refuses). JSON.stringify emits the
 * pinned compact key order v,o,t,e.
 */
export function composeEnrollLink(origin: string, token: string, email: string): string | null {
  for (const s of [origin, token, email]) if (!WELL_FORMED_UTF16_RE.test(s)) return null;
  const payload = JSON.stringify({ v: 1, o: origin, t: token, e: email });
  return `${origin}/enroll#${PREFIX}${b64urlEncode(new TextEncoder().encode(payload))}`;
}

/** Parse any string containing an enroll fragment. Null on any malformed input; never throws. */
export function parseEnrollLink(input: string): EnrollPayload | null {
  try {
    return parseInner(input);
  } catch {
    return null; // TOTAL by contract — any unanticipated throw is a malformed input, not a crash
  }
}

function parseInner(input: string): EnrollPayload | null {
  if (input.length > MAX_LEN) return null;
  const hash = input.indexOf("#");
  if (hash < 0) return null;
  const fragment = input.slice(hash + 1);
  if (!fragment.startsWith(PREFIX)) return null;
  const body = fragment.slice(PREFIX.length).replace(WS_RE, "").replace(PAD_RE, "");
  if (!B64URL_RE.test(body)) return null;
  const bytes = b64urlDecode(body);
  if (bytes === null) return null;
  if (b64urlEncode(bytes) !== body) return null; // canonical-form pin
  let text: string;
  try {
    // ignoreBOM keeps a leading BOM in the output (the default silently STRIPS it,
    // which the Kotlin twin's decodeToString does not) so the guard below can reject it.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  if (text.charCodeAt(0) === 0xfeff) return null; // BOM rejects on both twins (pinned)
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) < 0x20) return null;
  if (hasHostileTopLevelKeys(text)) return null;
  let p: unknown;
  try {
    p = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof p !== "object" || p === null || Array.isArray(p)) return null;
  const r = p as Record<string, unknown>;
  if (typeof r.v !== "number" || r.v !== 1) return null;
  if (typeof r.o !== "string" || !ORIGIN_RE.test(r.o)) return null;
  if (typeof r.t !== "string" || r.t.length === 0) return null;
  if (typeof r.e !== "string" || r.e.length === 0) return null;
  return { v: 1, o: r.o, t: r.t, e: r.e };
}

/**
 * True when the top-level JSON object literal repeats a key, or uses a backslash escape
 * inside a key. Purely lexical and deliberately lenient about malformedness — anything
 * else is left for JSON.parse to reject. Mirrored line-for-line in the Kotlin twin.
 */
function hasHostileTopLevelKeys(text: string): boolean {
  let i = 0;
  const n = text.length;
  while (i < n && text.charAt(i) === " ") i++; // controls were pre-rejected; only spaces remain
  if (i >= n || text.charAt(i) !== "{") return false; // not an object — JSON.parse rejects it
  i++;
  let depth = 1;
  let inString = false;
  let escaped = false;
  let readingKey = false;
  let expectKey = true;
  const keys = new Set<string>();
  let cur = "";
  while (i < n) {
    const c = text.charAt(i);
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (c === "\\") {
        if (readingKey) return true; // escaped keys could alias across the twins' parsers
        escaped = true;
      } else if (c === '"') {
        inString = false;
        if (readingKey) {
          if (keys.has(cur)) return true;
          keys.add(cur);
          readingKey = false;
        }
      } else if (readingKey) {
        cur += c;
      }
    } else {
      if (c === '"') {
        inString = true;
        if (depth === 1 && expectKey) {
          readingKey = true;
          expectKey = false;
          cur = "";
        }
      } else if (c === "{" || c === "[") {
        depth++;
      } else if (c === "}" || c === "]") {
        depth--;
        if (depth === 0) return false; // past the top object; trailing garbage is JSON.parse's problem
      } else if (c === ",") {
        if (depth === 1) expectKey = true;
      }
    }
    i++;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Location capture (web consumer plumbing — consume semantics rule 1: the link's
// origin lives ONLY in this transient module singleton, never in persisted prefs).

let pendingEnroll: EnrollPayload | null = null;
let captured = false;
let listenerInstalled = false;

/**
 * Read window.location.hash, and if it is a valid enroll fragment, store the payload in
 * the module singleton and strip the fragment from the address bar + history (the invite
 * token must not linger in history/Referer). Called ONCE at module load in main.tsx,
 * before React renders — immune to StrictMode double-effects. Captures at most once: a
 * later call with an empty/invalid/already-stripped hash is a no-op that never clobbers
 * the stored value. A non-enroll hash is left untouched.
 *
 * Also installs a one-time hashchange listener: opening a RE-MINTED link in the same
 * already-loaded /enroll tab is a fragment-only (same-document) navigation — no reload, no
 * module re-eval — so the new token would otherwise be silently ignored. On a NEW valid
 * enroll fragment we reload, letting module-load capture run fresh against it. replaceState
 * (the strip below) never fires hashchange, and a same-token navigation is a no-op, so this
 * cannot loop.
 */
export function captureEnrollFromLocation(): void {
  if (typeof window === "undefined") return;
  if (!listenerInstalled && typeof window.addEventListener === "function") {
    listenerInstalled = true;
    window.addEventListener("hashchange", () => {
      const next = parseEnrollLink(window.location.hash);
      if (next && next.t !== pendingEnroll?.t) window.location.reload();
    });
  }
  if (captured) return;
  const p = parseEnrollLink(window.location.hash);
  if (p === null) return;
  pendingEnroll = p;
  captured = true;
  try {
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
  } catch {
    // History API refusal (e.g. exotic embeddings) must not take the app down; the
    // fragment merely stays visible.
  }
}

/**
 * Return the captured payload WITHOUT clearing it (React StrictMode double-invokes
 * useState lazy initializers — a consuming read would lose the prefill on the second
 * invoke). Consume-once is enforced at the component-state level by the caller.
 */
export function peekPendingEnroll(): EnrollPayload | null {
  return pendingEnroll;
}

/**
 * Drop the captured payload. Call after a successful enrollment so a later FreshStart mount
 * (e.g. after sign-out on a shared family computer) does not resurface the now-spent
 * single-use token with a locked-in email. Also called when the user declines the consent
 * step. Pure module-state; safe to call more than once.
 */
export function clearPendingEnroll(): void {
  pendingEnroll = null;
}

/**
 * The captured link applies to THIS page only if it was minted for this exact origin
 * (payload.o === the origin serving the page). A mismatch means a redirect or a
 * hand-mangled link — return null so the caller falls through to manual entry rather than
 * enrolling against the wrong server. Pure, for unit tests + the FreshStart gate.
 */
export function enrollPrefillFor(pending: EnrollPayload | null, origin: string): EnrollPayload | null {
  return pending && pending.o === origin ? pending : null;
}
