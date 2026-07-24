/**
 * Pure card-fill value layer (Tier 1, design 2026-07-23-card-autofill-tier1 §4) — the TS twin of
 * core `CardFill`'s value half. NO chrome imports, NO DOM, NO pslData ([A10]: this module rides
 * in content.js against the 60 KiB bundle cap; the PSL snapshot is background-only); node-tested
 * against spec/test-vectors/cardfill.json, the vector file BOTH engines consume ([T14] lockstep).
 *
 * ── Wiring contract (content.ts `applyCardFill` builds against THIS surface) ──
 * Per detected field ref the executor calls
 *     deriveCardWrite(kind, target, values) → CardWrite | null
 *   target: CardTargetMeta read off the live element —
 *     tag         "input" | "select"
 *     type        el.type (carried for symmetry with the detection signal; no §4 rule keys off it)
 *     maxLength   HTMLInputElement.maxLength with the DOM's `-1 == undeclared` MAPPED TO NULL by
 *                 the CALLER (this module never sees -1); selects: null
 *     placeholder el.placeholder or null; selects: null
 *     options     selects only, [{value, text}] in document order — `opt.value` keeps the DOM's
 *                 attr-absent→text fallback ([T8]: that is what makes the value pass ≡ the text
 *                 pass on label-only options, and the `shared` vector section coherent)
 *   values: the revealCardForFill response (CardFillFields v2, §6) — CardFillValues below is its
 *     structural twin; this module deliberately does NOT import messages.ts (the pure leaf must
 *     not couple to the chrome-typed protocol file).
 *   → {kind:"text",  value}  write via setValue (native prototype value setter + composed events)
 *   → {kind:"index", index}  write via the native HTMLSelectElement selectedIndex setter ([T8]:
 *                            a `.value` write binds to the FIRST option with a duplicate value)
 *   → null                   no faithful representation exists in this target — SKIP the field
 *                            and file the kind missed (fit-guard: partial beats wrong, never
 *                            truncate, never guess).
 * After writing, the executor reads the control back and calls
 *     verifyLanded(kind, intended, observed)
 * with observed = {kind:"text", value: el.value} for inputs, {kind:"index", index:
 * sel.selectedIndex} for selects. false ⇒ leave the page's residue in place (never auto-clear —
 * the field may hold user-typed data) and file the kind missed. Read-back is point-in-time: a
 * framework revert after this tick goes unseen (accepted residual, §4).
 */
import { brandLabel, digitsOnly, padMonth, yearTo4 } from "./card.ts";
import type { CardFieldKind } from "./detect.ts";

/** [T14] the compiled-in synonym/contains/month/keyword tables — the NORMATIVE copy lives in
 *  cardfill.json's `tables` section; each engine deep-equals its compiled-in copy against the
 *  vector, so drift on either side reds that side. Never edit here without editing the vector
 *  (and core) in the same change. */
export const TABLES: {
  synonyms: Record<string, readonly string[]>;
  containsWords: Record<string, readonly string[]>;
  monthNames: readonly string[];
  monthAbbreviations: Record<string, readonly string[]>;
  keywords: readonly { kind: string; keywords: readonly string[] }[];
} = {
  synonyms: {
    visa: ["visa", "vi", "v", "001"],
    mastercard: ["mastercard", "mc", "002"],
    amex: ["amex", "americanexpress", "ax", "amx", "003"],
    discover: ["discover", "disc", "di", "004"],
  },
  containsWords: {
    visa: ["visa"],
    mastercard: ["mastercard"],
    amex: ["americanexpress", "amex"],
    discover: ["discover"],
  },
  monthNames: ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"],
  monthAbbreviations: {
    "01": ["jan"],
    "02": ["feb"],
    "03": ["mar"],
    "04": ["apr"],
    "05": ["may"],
    "06": ["jun"],
    "07": ["jul"],
    "08": ["aug"],
    "09": ["sep", "sept"],
    "10": ["oct"],
    "11": ["nov"],
    "12": ["dec"],
  },
  // [U8] the ORDERED card name/id/label keyword groups — the single normative in-bundle copy
  // (detect.ts imports it; kinds ride the engine-neutral autocomplete spellings). Sequence is
  // load-bearing: exp-month/-year before the generic exp group, and the trailing bare
  // `creditcard` group ([U1]) fires only when no specific kind matched — `credit_card_cvv`
  // must never collapse to a PAN verdict. "pan" stays absent; no bare "exp"/"expires" ([U4]);
  // `securitynumber`/`verificationnumber`/`cid` deliberately dropped ([U2]/[U3]).
  keywords: [
    { kind: "cc-number", keywords: ["cardnumber", "ccnumber", "ccnum", "cardno", "cardnum", "ccno", "kartennummer", "kreditkartennummer", "numerocarte", "numerotarjeta", "numerocartao"] },
    { kind: "cc-exp-month", keywords: ["expmonth", "expmm", "expirationmonth", "expirymonth", "cardmonth"] },
    { kind: "cc-exp-year", keywords: ["expyear", "expyy", "expirationyear", "expiryyear", "cardyear"] },
    { kind: "cc-exp", keywords: ["expiry", "expdate", "ccexp", "expiration", "expirationdate", "expiredate", "expirydate", "validthru", "validthrough", "goodthru", "goodthrough", "validuntil", "ablaufdatum", "gueltigbis", "dateexpiration", "vencimiento"] },
    { kind: "cc-csc", keywords: ["cvv", "cvc", "csc", "securitycode", "cvn", "cardcode", "xcardcode", "verificationvalue", "cardverificationcode", "cardverificationvalue", "cryptogramme", "pruefnummer", "kartenpruefnummer", "codigoseguridad"] },
    { kind: "cc-name", keywords: ["cardholder", "nameoncard", "ccname", "holdername", "cardholdername", "cardholdersname", "titulaire", "titular", "karteninhaber"] },
    { kind: "cc-type", keywords: ["cardtype", "cctype", "cardbrand", "ccbrand", "cbtype"] },
    { kind: "cc-number", keywords: ["creditcard"] },
  ],
};

/** The one write shape crossing to the executor — text for inputs, INDEX for selects ([T8]). */
export type CardWrite = { kind: "text"; value: string } | { kind: "index"; index: number };

export interface SelectOptionMeta {
  value: string;
  text: string;
}

export interface CardTargetMeta {
  tag: "input" | "select";
  type: string;
  maxLength: number | null;
  placeholder: string | null;
  options: SelectOptionMeta[] | null;
}

/** Structural twin of messages.ts `CardFillFields` v2 (§6). Halves ride INDEPENDENTLY — a
 *  parseable month with a junk year still fills month-only targets; combined targets need both.
 *  `brand` is composed SW-side and present ONLY when cardtype AND cardnumber were declared
 *  ([T9]) — never derived here (this module never sees enough of the PAN to derive it). */
export interface CardFillValues {
  number?: string;
  name?: string;
  cvv?: string;
  /** canonical "MM" (padMonth). */
  expMonth?: string;
  expYear2?: string;
  expYear4?: string;
  /** composed MM/YY back-compat (popup copy path) — the fill adapters use the halves. */
  expiry?: string;
  brand?: string;
}

// ---- §4 text-target adapters ----------------------------------------------------------------

/** Month text targets: canonical "MM" or nothing — maxLength 1 cannot hold a truthful month
 *  (stripping the pad would write "7" where the page may pattern-validate "07"; core parity
 *  keeps MM canonical, fit-guard skips). */
export function monthTextFor(v: string | null | undefined, maxLength: number | null): string | null {
  const mm = padMonth(v ?? "");
  if (mm === null) return null;
  return maxLength !== null && maxLength < 2 ? null : mm;
}

/** Year text targets: a declared 2/4 is the page's own contract and beats any placeholder hint;
 *  otherwise the placeholder decides (yyyy → YYYY, yy → YY) with default YYYY (core parity — a
 *  deliberate flip of the shipped always-YY slice), fit-guard shrinking 4→2 when only 2 fits. */
export function yearTextFor(v: string | null | undefined, maxLength: number | null, placeholder: string | null): string | null {
  const y4 = yearTo4(v ?? "");
  if (y4 === null) return null;
  const y2 = y4.slice(2);
  if (maxLength === 2) return y2;
  if (maxLength === 4) return y4;
  const p = (placeholder ?? "").toLowerCase();
  const want = p.includes("yyyy") ? y4 : p.includes("yy") ? y2 : y4;
  if (maxLength === null || want.length <= maxLength) return want;
  return y2.length <= maxLength ? y2 : null;
}

/** [T16] the separator sniff is ANCHORED — the separator must sit between an m-run and a y
 *  ("MM-YY" → "-", "MM / YY" → "/"); a bare contains-scan would let "e.g. 12/28" pick "." off
 *  the "e.g.". No match → "/", honored in every separator-bearing branch below. */
const EXPIRY_SEP_RX = /m{1,2}\s*([-/.])\s*y/i;
function expirySep(placeholder: string | null): string {
  const m = EXPIRY_SEP_RX.exec(placeholder ?? "");
  return m ? m[1]! : "/";
}

/** Combined expiry text targets (§4 maxLength table; F10/F11) — needs BOTH halves (a combined
 *  string with a fabricated half is a wrong value, not a partial one). maxLength 7 is
 *  placeholder-corroborated ([T16]): " MM / YY " space-masks are exactly 7 chars, so only an
 *  explicit yy placeholder picks the short form there — bare 7 takes Chromium's MM/YYYY. */
export function expiryTextFor(
  month: string | null | undefined,
  year: string | null | undefined,
  maxLength: number | null,
  placeholder: string | null,
): string | null {
  const mm = padMonth(month ?? "");
  const y4 = yearTo4(year ?? "");
  if (mm === null || y4 === null) return null;
  const y2 = y4.slice(2);
  const sep = expirySep(placeholder);
  const p = (placeholder ?? "").toLowerCase();
  if (maxLength !== null) {
    if (maxLength <= 3) return null; // no truthful MM+year packing exists below 4 chars
    if (maxLength === 4) return mm + y2;
    if (maxLength === 5) return mm + sep + y2;
    if (maxLength === 6) return mm + y4;
    if (maxLength === 7) return p.includes("yyyy") || !p.includes("yy") ? mm + sep + y4 : mm + sep + y2;
  }
  // undeclared / ≥8: the placeholder is the only signal — yyyy widens, default MM<sep>YY.
  return p.includes("yyyy") ? mm + sep + y4 : mm + sep + y2;
}

/** PAN text targets: digits-only (spaces/dashes are display sugar; checkout inputs routinely
 *  pattern-validate), fit-guarded — longer than declared maxLength → skipped, never truncated. */
export function numberTextFor(v: string | null | undefined, maxLength: number | null): string | null {
  const d = digitsOnly(v ?? "");
  if (d === "") return null;
  return maxLength !== null && d.length > maxLength ? null : d;
}

/** CVV/name text targets: the stored value verbatim, fit-guarded (never truncated). */
export function cvvTextFor(v: string | null | undefined, maxLength: number | null): string | null {
  const s = v ?? "";
  if (s === "") return null;
  return maxLength !== null && s.length > maxLength ? null : s;
}

export function nameTextFor(v: string | null | undefined, maxLength: number | null): string | null {
  const s = v ?? "";
  if (s === "") return null;
  return maxLength !== null && s.length > maxLength ? null : s;
}

/** Card-type text targets (§2): the human label of the SW-derived brand ("Visa") — never a
 *  stored field, never a guess (unknown IIN → no brand rode the wire → the kind files missed). */
export function typeTextFor(brand: string | null | undefined, maxLength: number | null): string | null {
  const label = brandLabel(brand);
  if (label === null) return null;
  return maxLength !== null && label.length > maxLength ? null : label;
}

// ---- §4 split PAN (F18) ----------------------------------------------------------------------

/** Multi-box PAN chunk table (§4; `applyCardFill`'s >1-cardnumber pre-pass): eligible only when
 *  EVERY box declares maxLength 1..8 and the boxes jointly fit the whole PAN (sum ≥ digits) —
 *  otherwise null, and the caller's whole-PAN-to-first-box fallback runs under the fit-guard
 *  ([U19]: a declared-but-insufficient box set nulls the write there, truthful miss; the
 *  fallback only ever lands for undeclared-maxLength shapes). Chunks are sequential digit runs;
 *  the FINAL box may take a short remainder — 4-4-4-4 and Amex 4-6-5 fall out of the same rule. */
export function splitPan(pan: string | null | undefined, maxLengths: readonly (number | null)[]): string[] | null {
  const d = digitsOnly(pan ?? "");
  if (d === "" || maxLengths.length < 2) return null; // one box is not a split
  const lens: number[] = [];
  let sum = 0;
  for (const m of maxLengths) {
    if (m === null || !Number.isInteger(m) || m < 1 || m > 8) return null;
    lens.push(m);
    sum += m;
  }
  if (sum < d.length) return null;
  const chunks: string[] = [];
  let at = 0;
  for (const m of lens) {
    chunks.push(d.slice(at, at + m));
    at += m;
  }
  return chunks;
}

/** [U19] split read-back: auto-advance maskers redistribute digits ACROSS boxes, so landed-ness
 *  is the concatenation of every box's digitsOnly equalling the full PAN (per-box chunk equality
 *  is merely the executor's fast path). Any shortfall or residue fails the whole split — the
 *  kind files missed, nothing is auto-cleared (partial beats wrong). */
export function verifySplitPanLanded(pan: string, observed: readonly string[]): boolean {
  const want = digitsOnly(pan);
  if (want === "") return false;
  let got = "";
  for (const s of observed) got += digitsOnly(s);
  return got === want;
}

// ---- select matching -------------------------------------------------------------------------

type OptionPredicate = (s: string) => boolean;

/** [T3] the month-name candidate: the FIRST maximal ASCII-letter run, lowercased — leading
 *  digits/punctuation skipped ("01 - January" → "january"); no letters → no candidate. */
function firstLetterRun(s: string): string | null {
  const m = /[A-Za-z]+/.exec(s);
  return m ? m[0]!.toLowerCase() : null;
}

/** cc-type normalization: lowercase + strip non-alphanumerics ("American Express" →
 *  "americanexpress"; value codes like "001" pass through). */
function normalizeType(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** "01".."12" (padMonth-verified ASCII) → 1..12 — charCode arithmetic, house digit discipline. */
function monthNumber(mm: string): number {
  return (mm.charCodeAt(0) - 48) * 10 + (mm.charCodeAt(1) - 48);
}

/** The ordered pass list for one kind, closed over the canonicalized wanted value — null when
 *  the wanted value itself doesn't canonicalize (nothing derivable → safe miss). */
function passesFor(kind: CardFieldKind, v: CardFillValues): OptionPredicate[] | null {
  const year = v.expYear4 ?? v.expYear2 ?? null;
  switch (kind) {
    case "cardexpmonth": {
      const mm = padMonth(v.expMonth ?? "");
      if (mm === null) return null;
      const full = TABLES.monthNames[monthNumber(mm) - 1]!;
      const abbr = TABLES.monthAbbreviations[mm]!;
      return [
        (s) => padMonth(s) === mm,
        (s) => padMonth(digitsOnly(s)) === mm,
        // [T3] letter-run EQUALITY against fullName/abbreviation — prefix matching is FORBIDDEN
        // (fi "marraskuu" starts with "mar" but is November; it must degrade to a safe miss).
        (s) => {
          const run = firstLetterRun(s);
          return run !== null && (run === full || abbr.includes(run));
        },
      ];
    }
    case "cardexpyear": {
      const y4 = yearTo4(year ?? "");
      if (y4 === null) return null;
      return [(s) => yearTo4(s) === y4, (s) => yearTo4(digitsOnly(s)) === y4];
    }
    case "cardexpiry": {
      const mm = padMonth(v.expMonth ?? "");
      const y4 = yearTo4(year ?? "");
      if (mm === null || y4 === null) return null; // combined targets need BOTH halves
      const mmyy = mm + y4.slice(2);
      const mmyyyy = mm + y4;
      return [
        (s) => {
          const d = digitsOnly(s);
          return d === mmyy || d === mmyyyy;
        },
      ];
    }
    case "cardtype": {
      const syn = v.brand !== undefined ? TABLES.synonyms[v.brand] : undefined;
      const words = v.brand !== undefined ? TABLES.containsWords[v.brand] : undefined;
      if (!syn || !words) return null; // unknown/absent brand → missed, never guessed
      // TWO ordered passes (core CC_TYPE parity: exact-synonym across ALL options BEFORE any
      // contains match). Folding them into one per-option predicate would let an earlier
      // contains-only row — a brand-enumerating header ("Card type (Visa, …)") or "Visa
      // Electron" — outrank the real exact "Visa" row below it: the [T2] option-major bug in
      // miniature, and verifyLanded would bless the wrong pick (index equality).
      return [
        (s) => syn.includes(normalizeType(s)),
        (s) => {
          const n = normalizeType(s);
          return n !== "" && words.some((w) => n.includes(w));
        },
      ];
    }
    default:
      return null; // cardnumber/cardcvv/cardname can never be selects (§0 invariant)
  }
}

/** [T2] PASS-MAJOR select matching (core `listIndexFor` parity): the passes are the OUTER loop —
 *  within a pass, options in document order; within an option, `value` then `text`; the earliest
 *  pass with ANY match wins. Option-major would let a digit-bearing placeholder ("Month (12)")
 *  outrank the real "12" row — core's CardFillTest pins exactly this. Passes (§4): 1 whole-parse
 *  · 2 digit-extraction · 3 month-name ([T3], month kind only) · 4 combined-expiry digits ·
 *  5a cc-type synonym-exact · 5b cc-type contains-primary (two REAL passes — exact must sweep
 *  all options before any contains match, core parity). null = safe miss, never a guess. */
export function selectIndexFor(kind: CardFieldKind, options: readonly SelectOptionMeta[], v: CardFillValues): number | null {
  const passes = passesFor(kind, v);
  if (passes === null) return null;
  for (const pass of passes) {
    for (let i = 0; i < options.length; i++) {
      const o = options[i]!;
      if (pass(o.value) || pass(o.text)) return i;
    }
  }
  return null;
}

// ---- read-back verify ------------------------------------------------------------------------

/** parseExpiry-equivalent for the [T7] read-back compare (web vault/card.ts parity — kept local:
 *  card.ts stays parseExpiry-free, the extension still neither creates nor edits cards). Accepts
 *  M[M]<sep>YY|YYYY (sep = any non-digit run) and the separator-free MYY/MMYY/MYYYY/MMYYYY runs;
 *  2-digit years pivot 2000–2099. */
function parseExpiryParts(raw: string): { expMonth: string; expYear: string } | null {
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

/** [T7]/F16 truthful read-back: CANONICALIZED comparison — a masker auto-expanding
 *  "07/27"→"07/2027" or stripping a leading zero is a successful fill; truncation ("07/20") is
 *  not. number/cvv compare digitsOnly-equal (re-spacing masks pass); name/type trimmed
 *  case-insensitive; selects by INDEX equality — a duplicate-value select that landed a
 *  different index files missed (truthful, fail-safe). A shape mismatch (the SPA swapped the
 *  control between write and read-back) is a miss. */
export function verifyLanded(kind: CardFieldKind, intended: CardWrite, observed: CardWrite): boolean {
  if (intended.kind === "index" || observed.kind === "index")
    return intended.kind === "index" && observed.kind === "index" && intended.index === observed.index;
  const want = intended.value;
  const got = observed.value;
  switch (kind) {
    case "cardnumber":
    case "cardcvv": {
      const d = digitsOnly(want);
      return d !== "" && d === digitsOnly(got);
    }
    case "cardexpmonth": {
      const m = padMonth(want);
      return m !== null && padMonth(got) === m;
    }
    case "cardexpyear": {
      const y = yearTo4(want);
      return y !== null && yearTo4(got) === y;
    }
    case "cardexpiry": {
      const a = parseExpiryParts(want);
      const b = parseExpiryParts(got);
      return a !== null && b !== null && a.expMonth === b.expMonth && a.expYear === b.expYear;
    }
    case "cardname":
    case "cardtype":
      return want.trim().toLowerCase() === got.trim().toLowerCase();
  }
}

// ---- the wiring entry point -------------------------------------------------------------------

/** kind + live-target metadata + revealed values → the ONE faithful write, or null (skip + file
 *  missed). Select targets admit only the select-meaningful kinds — a PAN/CVV/name "select"
 *  derives nothing (§0: a <select> can never anchor nor be a PAN/CVV/name field); detection
 *  already never produces such a ref, so the null here is belt-and-braces. */
export function deriveCardWrite(kind: CardFieldKind, target: CardTargetMeta, v: CardFillValues): CardWrite | null {
  if (target.tag === "select") {
    const idx = selectIndexFor(kind, target.options ?? [], v);
    return idx === null ? null : { kind: "index", index: idx };
  }
  const year = v.expYear4 ?? v.expYear2 ?? null;
  let value: string | null;
  switch (kind) {
    case "cardnumber":
      value = numberTextFor(v.number, target.maxLength);
      break;
    case "cardcvv":
      value = cvvTextFor(v.cvv, target.maxLength);
      break;
    case "cardname":
      value = nameTextFor(v.name, target.maxLength);
      break;
    case "cardexpmonth":
      value = monthTextFor(v.expMonth, target.maxLength);
      break;
    case "cardexpyear":
      value = yearTextFor(year, target.maxLength, target.placeholder);
      break;
    case "cardexpiry":
      value = expiryTextFor(v.expMonth, year, target.maxLength, target.placeholder);
      break;
    case "cardtype":
      value = typeTextFor(v.brand, target.maxLength);
      break;
  }
  return value === null ? null : { kind: "text", value };
}
