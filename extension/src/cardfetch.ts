import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { b64Strict } from "./statement.ts";
import { readCappedBody } from "./updateverify.ts";

/**
 * `GET {origin}/api/v1/instance` (spec 03 §17.1; design 2026-11-15-onboarding-trust §4.3): the served card chain, card
 * 0 first. Unauthenticated: it carries no token and nothing derived from a secret, so the Trust Gate can fetch it
 * before any pin exists. The answer is capped and parsed strictly; a body that is not `{cards: [b64 frame…]}` with
 * canonical base64url frames is `card_invalid`, never an empty chain. Before card 0 the server answers `{cards: [],
 * setup}`: an empty chain, which every root reads as `withheld`.
 *
 * Also here: the operator key's 32-hex short form for the Trust Gate (§4.4), which spec 01 §5 defines over the key's
 * X25519 image. The extension verifies nothing with it (it has no Montgomery map for verification, §12.2): the image is
 * computed by the birational map u = (1 + y) / (1 − y) mod p, for display only, and graded against the vectors' key
 * pairs (serverchoice.test.ts, "the Trust Gate's operator key short form").
 *
 * LEAF module: `fetch` is injected.
 */

export const INSTANCE_BODY_MAX_BYTES = 512 * 1024;

/** How long one `/instance` fetch may take, answer and body together. */
export const INSTANCE_FETCH_TIMEOUT_MS = 15_000;

export type FetchLike = (url: string, init: { method: string; headers: Record<string, string>; cache?: RequestCache; signal?: AbortSignal; redirect?: RequestRedirect }) => Promise<Response>;

export type ChainFetch =
  | { ok: true; frames: Uint8Array[] }
  | { ok: false; code: "unavailable" | "card_invalid" }
  /** The address answered with a redirect, which is not followed (the server never answers with one). [to]: the address it
   *  points to, when the browser lets the extension read it (an http(s) address, at most 2,048 characters), else null. */
  | { ok: false; code: "redirected"; to: string | null };

/** The statuses a redirect comes as, and the opaque answer a browser gives for one under `redirect: "manual"`. */
function isRedirect(resp: Response): boolean {
  return resp.type === "opaqueredirect" || resp.redirected === true || [301, 302, 303, 307, 308].includes(resp.status);
}

/** Where a redirect answer to [url] points, when it can be read; null otherwise (a browser hides it from `redirect: "manual"`). */
export function redirectTarget(resp: Response, url: string): string | null {
  let loc: string | null;
  try {
    loc = resp.redirected === true && resp.url ? resp.url : resp.headers.get("location");
  } catch {
    return null;
  }
  if (loc === null || loc === "") return null;
  try {
    const u = new URL(loc, url);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    const s = u.href;
    return s.length <= 2048 ? s : null;
  } catch {
    return null;
  }
}

/**
 * The served chain. The body is read through the capped reader (updateverify.ts), so a
 * body over [INSTANCE_BODY_MAX_BYTES] is refused as it streams in, never buffered whole first; and the whole fetch is
 * bounded by [timeoutMs] (a server that answers slowly, or trickles its body, is `unavailable`).
 */
export async function fetchInstanceChain(origin: string, clientHeader: string, doFetch: FetchLike = fetch, timeoutMs: number = INSTANCE_FETCH_TIMEOUT_MS): Promise<ChainFetch> {
  const abort = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => {
      abort.abort();
      resolve("timeout");
    }, timeoutMs);
  });
  try {
    let resp: Response;
    const url = `${origin}/api/v1/instance`;
    try {
      // No redirect is followed (review of 2026-11-17): the first contact with a typed address reads the card from that
      // address only, never from wherever an answer points.
      const r = await Promise.race([doFetch(url, { method: "GET", headers: { "X-Andvari-Client": clientHeader }, cache: "no-store", signal: abort.signal, redirect: "manual" }), timedOut]);
      if (r === "timeout") return { ok: false, code: "unavailable" };
      resp = r;
    } catch {
      return { ok: false, code: "unavailable" };
    }
    if (isRedirect(resp)) return { ok: false, code: "redirected", to: redirectTarget(resp, url) };
    if (!resp.ok) return { ok: false, code: "unavailable" };
    let text: string;
    try {
      const buf = await Promise.race([readCappedBody(resp, INSTANCE_BODY_MAX_BYTES), timedOut]);
      if (buf === "timeout") return { ok: false, code: "unavailable" };
      if (buf === null) return { ok: false, code: "card_invalid" };
      text = new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } catch {
      return { ok: false, code: "card_invalid" };
    }
    return parseInstanceBody(text);
  } finally {
    clearTimeout(timer);
  }
}

/** The frames of an `/instance` body, strictly. */
export function parseInstanceBody(text: string): ChainFetch {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return { ok: false, code: "card_invalid" };
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return { ok: false, code: "card_invalid" };
  const cards = (body as { cards?: unknown }).cards;
  if (!Array.isArray(cards) || cards.length > 4096) return { ok: false, code: "card_invalid" };
  const frames: Uint8Array[] = [];
  for (const c of cards) {
    const f = typeof c === "string" ? b64Strict(c) : null;
    if (f === null) return { ok: false, code: "card_invalid" };
    frames.push(f);
  }
  return { ok: true, frames };
}

const P = 2n ** 255n - 19n;

function modPow(base: bigint, exp: bigint): bigint {
  let r = 1n;
  let b = base % P;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return r;
}

/** The X25519 (Montgomery u) image of an Ed25519 public key, for display only. Null for a degenerate point. */
export function displayX25519Image(edPub: Uint8Array): Uint8Array | null {
  if (edPub.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? edPub[i]! & 0x7f : edPub[i]!);
  if (y >= P) return null;
  const den = (1n - y + P) % P;
  if (den === 0n) return null;
  let u = ((1n + y) * modPow(den, P - 2n)) % P;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(u & 0xffn);
    u >>= 8n;
  }
  return out;
}

/** The operator key's short form shown in the Trust Gate: the first 32 hex of SHA-256 over its X25519 image. */
export function operatorShortFp(operatorSignKeyB64: string): string {
  const ed = b64Strict(operatorSignKeyB64);
  const image = ed === null ? null : displayX25519Image(ed);
  return image === null ? "" : bytesToHex(sha256(image)).slice(0, 32);
}
