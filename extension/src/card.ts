// Minimal card display/copy + fill-adapter helpers — the extension's port of web/src/vault/card.ts
// (itself the TS mirror of core CardNormalize.kt). ONLY what the extension port needs rides
// here: digitsOnly/brand/brandLabel/maskedLast4/cardSubtitle for the popup's masked identity
// line, composeShortExpiry (+ its yearTo2/trimAscii innards) for the MM/YY copy, and the
// padMonth/yearTo4 canonicalizers the Tier-1 fill layer (cardfill.ts) adapts values with.
// The IIN table and the ASCII-digit discipline match the web/core ports EXACTLY — cross-port
// parity is pinned against spec/test-vectors/card.json by web/src/extension-pins.test.ts
// (padMonth/yearTo4 included). No editor, no Luhn, no parseExpiry: the extension neither
// creates nor edits cards (cardfill.ts carries its own read-back parse for verify only).
//
// "Digit" throughout means ASCII '0'..'9' ONLY (explicit charCode checks — never \d,
// parseInt, or Number()): Unicode digits are stripped by digitsOnly and REJECTED by the
// adapters, exactly like the other ports.

function isAsciiDigitCode(c: number): boolean {
  return c >= 48 && c <= 57;
}

/** Cross-port determinism: the adapters trim ONLY this pinned ASCII whitespace set (platform
 *  trims disagree at the Unicode margins — vector-pinned in card.json). */
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

/** Strip everything but ASCII digits ("4111 1111-1111.1111" → the bare PAN). */
export function digitsOnly(raw: string): string {
  let out = "";
  for (let i = 0; i < raw.length; i++) if (isAsciiDigitCode(raw.charCodeAt(i))) out += raw.charAt(i);
  return out;
}

/**
 * IIN → brand: visa | mastercard | amex | discover, null when unknown OR while the typed
 * prefix is still ambiguous — decisive-prefix semantics, byte-for-byte the web/core table.
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
function yearTo2(raw: string): string | null {
  const t = trimAscii(raw);
  for (let i = 0; i < t.length; i++) if (!isAsciiDigitCode(t.charCodeAt(i))) return null;
  if (t.length === 2) return t;
  if (t.length === 4) return t.slice(2);
  return null;
}

/** Copy adapter for the popup's expiry button: canonical month + year → "MM/YY", or null when
 *  either stored half doesn't parse — the button only renders when this succeeds. */
export function composeShortExpiry(expMonth: string, expYear: string): string | null {
  const m = padMonth(expMonth);
  if (m === null) return null;
  const y = yearTo2(expYear);
  if (y === null) return null;
  return `${m}/${y}`;
}

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

/** "••1234" — the last (up to) four digits behind a mask; never more of the PAN than that. */
export function maskedLast4(digits: string): string {
  return `••${digitsOnly(digits).slice(-4)}`;
}

/**
 * Popup-row identity line: "Visa ••4242"; unknown IIN falls back to "Card ••4242"; no number
 * at all → "card" (web cardSubtitle semantics). Brand is recomputed from the number here —
 * never read from the stored field, which is display-only and could be stale.
 */
export function cardSubtitle(number: string | null | undefined): string {
  const d = digitsOnly(number ?? "");
  if (d === "") return "card";
  return `${brandLabel(brand(d)) ?? "Card"} ${maskedLast4(d)}`;
}
