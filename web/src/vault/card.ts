// Pure card-value normalization + display helpers — TS mirror of
// core/.../client/autofill/CardNormalize.kt (the extension carries the same port). Both
// impls run the SAME spec/test-vectors/card.json (card.test.ts). Storage canonical form
// (spec 02 CardData): digits-only number, expMonth "01".."12", expYear 4-digit. Brand is
// display-only and recomputed at every save from the IIN, so it can never go stale
// against an edited number.
//
// "Digit" throughout means ASCII '0'..'9' ONLY (explicit charCode checks — never \d,
// parseInt, or Number(), which accept Unicode digits or exotic forms): Eastern-Arabic/
// Devanagari/full-width digits are stripped by digitsOnly and REJECTED by luhnValid/
// padMonth/yearTo4/yearTo2 — the Luhn loop does ASCII `code - 48` arithmetic, so a
// Unicode digit slipping through would compute garbage that could spuriously validate.

import type { CardData, ItemDoc } from "../api/types";

/**
 * Option A rollout gate (design 2026-07-09, "the one owner decision"): card CREATION stays
 * dark until the fielded 0.2.x desktop MSI is retired — that client rebuilds docs
 * field-by-field, so any card it can touch becomes ghost rows + denied writes. Flipping
 * this to true (one line) + redeploy enables the "+ Card" button; everything else —
 * render/edit/detail/history/trash of EXISTING cards — ships live regardless. Test-pinned
 * to false (like the extension's fv pin) so the flip is always deliberate, never an accident.
 */
export const CARD_CREATE_ENABLED: boolean = false;

/** Canonical expiry: [expMonth] "01".."12" zero-padded, [expYear] 4-digit. */
export interface Expiry {
  expMonth: string;
  expYear: string;
}

function isAsciiDigitCode(c: number): boolean {
  return c >= 48 && c <= 57;
}

/** Cross-port determinism: the adapters trim ONLY this pinned ASCII whitespace set.
 *  Platform trims disagree at the Unicode margins (JS String.trim strips U+FEFF, JVM
 *  strips U+001C..U+001F) and the same string must parse identically on every client —
 *  vector-pinned in card.json. */
const TRIMMABLE = " \t\n\r\u000B\u000C";
function trimAscii(raw: string): string {
  let start = 0;
  let end = raw.length;
  while (start < end && TRIMMABLE.includes(raw.charAt(start))) start++;
  while (end > start && TRIMMABLE.includes(raw.charAt(end - 1))) end--;
  return raw.slice(start, end);
}

/** Digit-run → int for PRE-VERIFIED ASCII digits only (never Number(): no exotic forms). */
function intOf(digits: string): number {
  let n = 0;
  for (let i = 0; i < digits.length; i++) n = n * 10 + (digits.charCodeAt(i) - 48);
  return n;
}

/** Storage canonicalization: strip everything but ASCII digits ("4111 1111-1111.1111" → PAN). */
export function digitsOnly(raw: string): string {
  let out = "";
  for (let i = 0; i < raw.length; i++) if (isAsciiDigitCode(raw.charCodeAt(i))) out += raw.charAt(i);
  return out;
}

/**
 * Luhn gate for save/update flows. Accepts digit groups separated by spaces/dashes/dots;
 * any other character fails, as does a digit count outside 12..19 (ISO/IEC 7812) — so a
 * lone "0" or a phone number can never look like a savable card.
 */
export function luhnValid(raw: string): boolean {
  for (let i = 0; i < raw.length; i++) {
    const ch = raw.charAt(i);
    if (!isAsciiDigitCode(raw.charCodeAt(i)) && ch !== " " && ch !== "-" && ch !== ".") return false;
  }
  const d = digitsOnly(raw);
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    // i counts from the RIGHT end (the Kotlin reversed().withIndex() loop).
    let v = d.charCodeAt(d.length - 1 - i) - 48;
    if (i % 2 === 1) {
      v *= 2;
      if (v > 9) v -= 9;
    }
    sum += v;
  }
  return sum % 10 === 0;
}

/**
 * IIN → brand: visa | mastercard | amex | discover, null when unknown OR while the typed
 * prefix is still ambiguous (e.g. "62" could be inside or outside the Discover range) —
 * decisive-prefix semantics so a live editor badge can appear as early as the first digit.
 */
export function brand(raw: string): string | null {
  const d = digitsOnly(raw);
  if (d.startsWith("4")) return "visa";
  if (d.length >= 2 && (d.startsWith("34") || d.startsWith("37"))) return "amex";
  if (d.length >= 2) {
    const p2 = intOf(d.slice(0, 2));
    if (p2 >= 51 && p2 <= 55) return "mastercard";
  }
  if (d.length >= 4) {
    const p4 = intOf(d.slice(0, 4));
    if (p4 >= 2221 && p4 <= 2720) return "mastercard";
  }
  if (d.startsWith("6011") || d.startsWith("65")) return "discover";
  if (d.length >= 3) {
    const p3 = intOf(d.slice(0, 3));
    if (p3 >= 644 && p3 <= 649) return "discover";
  }
  if (d.length >= 6) {
    const p6 = intOf(d.slice(0, 6));
    if (p6 >= 622126 && p6 <= 622925) return "discover";
  }
  return null;
}

/**
 * Expiry text → canonical, or null. Accepts M[M]<sep>YY|YYYY (sep = any non-digit run, so
 * "12/27", "12-2027", "12 . 27" all parse) and the separator-free runs MYY/MMYY/MYYYY/MMYYYY;
 * 2-digit years pivot into 2000–2099 (fixed window — card expiries cannot reach 2100).
 */
export function parseExpiry(raw: string): Expiry | null {
  const groups = raw.match(/[0-9]+/g) ?? []; // [0-9] = ASCII-only, deliberately not \d
  let m: string;
  let y: string;
  if (groups.length === 2) {
    const g0 = groups[0]!;
    const g1 = groups[1]!;
    if (g0.length < 1 || g0.length > 2 || (g1.length !== 2 && g1.length !== 4)) return null;
    m = g0;
    y = g1;
  } else if (groups.length === 1) {
    const g = groups[0]!;
    if (g.length === 3 || g.length === 5) {
      m = g.slice(0, 1);
      y = g.slice(1);
    } else if (g.length === 4 || g.length === 6) {
      m = g.slice(0, 2);
      y = g.slice(2);
    } else return null;
  } else return null;
  const expMonth = padMonth(m);
  if (expMonth === null) return null;
  const expYear = yearTo4(y);
  if (expYear === null) return null;
  return { expMonth, expYear };
}

/** Month adapter: "1"/"01".."12" → zero-padded canonical; null otherwise. */
export function padMonth(raw: string): string | null {
  const t = trimAscii(raw);
  if (t.length === 0 || t.length > 2) return null;
  for (let i = 0; i < t.length; i++) if (!isAsciiDigitCode(t.charCodeAt(i))) return null;
  const m = intOf(t);
  if (m < 1 || m > 12) return null;
  return m < 10 ? `0${m}` : String(m);
}

/** Year adapter for 4-digit targets: "27" pivots to "2027", 4-digit passes through; null otherwise. */
export function yearTo4(raw: string): string | null {
  const t = trimAscii(raw);
  for (let i = 0; i < t.length; i++) if (!isAsciiDigitCode(t.charCodeAt(i))) return null;
  if (t.length === 2) return `20${t}`;
  if (t.length === 4) return t;
  return null;
}

/** Year adapter for 2-digit targets: "2027" → "27", 2-digit passes through; null otherwise. */
export function yearTo2(raw: string): string | null {
  const t = trimAscii(raw);
  for (let i = 0; i < t.length; i++) if (!isAsciiDigitCode(t.charCodeAt(i))) return null;
  if (t.length === 2) return t;
  if (t.length === 4) return t.slice(2);
  return null;
}

/** Fill adapter for combined expiry targets: canonical month + year → "MM/YY". */
export function composeShortExpiry(expMonth: string, expYear: string): string | null {
  const m = padMonth(expMonth);
  if (m === null) return null;
  const y = yearTo2(expYear);
  if (y === null) return null;
  return `${m}/${y}`;
}

// ---- display helpers (web-only; the canonical forms above are the cross-client contract) ----

/** Human-readable brand ("Visa"), null for unknown/absent — callers pick their own fallback. */
export function brandLabel(b: string | null | undefined): string | null {
  switch (b) {
    case "visa":
      return "Visa";
    case "mastercard":
      return "Mastercard";
    case "amex":
      return "Amex";
    case "discover":
      return "Discover";
    default:
      return null;
  }
}

/**
 * Display grouping for a (digits-only) number: 4-4-4-… generally, Amex 4-6-5 — sliced
 * progressively so a partially typed number groups sanely too. Sanitizes via digitsOnly,
 * so it is safe on raw editor text; display only, never a storage form.
 */
export function groupNumber(digits: string): string {
  const d = digitsOnly(digits);
  if (d === "") return "";
  if (brand(d) === "amex") {
    return [d.slice(0, 4), d.slice(4, 10), d.slice(10)].filter((g) => g !== "").join(" ");
  }
  return d.match(/.{1,4}/g)!.join(" ");
}

/** "••1234" — last (up to) four digits behind a mask; never more of the PAN than that. */
export function maskedLast4(digits: string): string {
  return `••${digitsOnly(digits).slice(-4)}`;
}

/**
 * List-row subtitle: "Visa ••4242"; unknown IIN falls back to "Card ••4242"; no number at
 * all → "card" (mirrors the login row's "login" fallback). Brand is recomputed from the
 * number here — never read from the stored field, which is display-only and could be stale
 * if another writer skipped the recompute.
 */
export function cardSubtitle(doc: ItemDoc): string {
  const d = digitsOnly(doc.card?.number ?? "");
  if (d === "") return "card";
  return `${brandLabel(brand(d)) ?? "Card"} ${maskedLast4(d)}`;
}

/** "MM/YYYY" for the detail view; a missing half renders as "—"; null when neither is set. */
export function expiryLabel(card: CardData | undefined): string | null {
  const m = card?.expMonth;
  const y = card?.expYear;
  if (!m && !y) return null;
  return `${m || "—"}/${y || "—"}`;
}

/**
 * Expired = strictly AFTER the last moment of the expiry month (a card is good THROUGH its
 * printed month). Missing or garbled fields → false: absent data must never scare the user
 * with a red chip. Tolerates 2-digit years via the same yearTo4 pivot as everything else.
 */
export function isExpired(expMonth?: string, expYear?: string, now?: Date): boolean {
  const m = padMonth(expMonth ?? "");
  const y = yearTo4(expYear ?? "");
  if (m === null || y === null) return false;
  // JS Date months are 0-based, so the 1-based canonical month lands exactly on the NEXT
  // month's index: this is the first instant after the expiry month (local time).
  const firstAfter = new Date(intOf(y), intOf(m), 1);
  return (now ?? new Date()).getTime() >= firstAfter.getTime();
}
