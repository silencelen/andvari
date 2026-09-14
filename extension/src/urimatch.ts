// Autofill URI matching + field classification (spec 02 §3.1) — verbatim port of
// web/src/vault/urimatch.ts (itself the TS mirror of core/.../client/autofill/UriMatch.kt +
// FieldClassifier.kt). All impls run the SAME spec/test-vectors/urimatch.json — keep in lockstep.

const ANDROID_APP_SCHEME = "androidapp://";

export type SavedUri = { kind: "web"; host: string } | { kind: "app"; pkg: string };

export interface FillTarget {
  webHost: string | null; // set only when the requester is a trusted browser
  packageName: string;
}

// ---- H22 (2026-09-13 audit): A-label (punycode) canonicalization ----
//
// Every browser reports a page host in ASCII (`location.hostname`, `sender.origin`, Android's
// getWebDomain() all carry `xn--bcher-kva.de`), while the household TYPES the Unicode form the
// omnibox shows. normalizeHost compared the two byte-wise, so an IDN login never filled on any
// client, silently — and the PSL resolver treats non-ASCII as unknown, so not even the suffix
// fallback could bridge it. Both sides now canonicalize to the A-label.
//
// Hand-rolled on purpose, NOT `new URL()`: the Kotlin twin cannot use the browser's UTS46 and
// `java.net.IDN` is IDNA2003 (transitional: `ß` → `ss`, which browsers abandoned in 2023), so one
// verbatim algorithm in all three engines is the only way the shared vectors can pin them. It is
// deliberately MINIMAL and matches what a modern browser reports for real-world hosts: the host is
// already lowercased; each label is NFC-normalized and a label with any non-ASCII code point
// becomes `xn--` + RFC 3492 punycode. No UTS46 mapping table (full-width forms, ligatures) and
// no bidi/joiner validity — such spellings still canonicalize deterministically on every client,
// they just do not match the browser's spelling, and encode to a label no registry can hold: an
// under-match. The ONE omitted mapping that would NOT stay an under-match is `ẞ` (U+1E9E) → "ss":
// the lowercase step turns it into `ß`, a deviation character browsers keep, so `straẞe.de` would
// canonicalize to `xn--strae-oqa.de` (straße.de) — a real, different registrable domain from the
// `strasse.de` the browser reports. normalizeHost therefore REJECTS a host carrying U+1E9E (R44,
// graded by urimatch-idna.json). The one runtime failure — arithmetic overflow on an absurd label
// — returns null, which matches nothing. Twin of core Idna.kt / Punycode.

const PUNY_BASE = 36;
const PUNY_T_MIN = 1;
const PUNY_T_MAX = 26;
const PUNY_SKEW = 38;
const PUNY_DAMP = 700;
const PUNY_INITIAL_BIAS = 72;
const PUNY_INITIAL_N = 128;
const PUNY_MAX_INT = 0x7fffffff;

function punyAdapt(deltaIn: number, numPoints: number, firstTime: boolean): number {
  let delta = firstTime ? Math.floor(deltaIn / PUNY_DAMP) : Math.floor(deltaIn / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > Math.floor(((PUNY_BASE - PUNY_T_MIN) * PUNY_T_MAX) / 2)) {
    delta = Math.floor(delta / (PUNY_BASE - PUNY_T_MIN));
    k += PUNY_BASE;
  }
  return k + Math.floor(((PUNY_BASE - PUNY_T_MIN + 1) * delta) / (delta + PUNY_SKEW));
}

function punyDigit(d: number): string {
  return d < 26 ? String.fromCharCode(97 + d) : String.fromCharCode(48 + (d - 26));
}

/** RFC 3492 §6.3 encoder — the encoded label WITHOUT `xn--`, or null on overflow (§6.4). */
export function punycodeEncode(label: string): string | null {
  const input = Array.from(label, (ch) => ch.codePointAt(0) as number);
  let out = "";
  for (const cp of input) if (cp < PUNY_INITIAL_N) out += String.fromCharCode(cp);
  const basicCount = out.length;
  let handled = basicCount;
  if (basicCount > 0) out += "-";
  let n = PUNY_INITIAL_N;
  let delta = 0;
  let bias = PUNY_INITIAL_BIAS;
  while (handled < input.length) {
    let m = PUNY_MAX_INT;
    for (const cp of input) if (cp >= n && cp < m) m = cp;
    if (m - n > Math.floor((PUNY_MAX_INT - delta) / (handled + 1))) return null;
    delta += (m - n) * (handled + 1);
    n = m;
    for (const cp of input) {
      if (cp < n) {
        delta++;
        if (delta > PUNY_MAX_INT) return null;
      }
      if (cp === n) {
        let q = delta;
        for (let k = PUNY_BASE; ; k += PUNY_BASE) {
          const t = k <= bias ? PUNY_T_MIN : k >= bias + PUNY_T_MAX ? PUNY_T_MAX : k - bias;
          if (q < t) break;
          out += punyDigit(t + ((q - t) % (PUNY_BASE - t)));
          q = Math.floor((q - t) / (PUNY_BASE - t));
        }
        out += punyDigit(q);
        bias = punyAdapt(delta, handled + 1, handled === basicCount);
        delta = 0;
        handled++;
      }
    }
    delta++;
    n++;
  }
  return out;
}

// eslint-disable-next-line no-control-regex
const ASCII_ONLY = /^[\x00-\x7f]*$/;

/** An already-normalized host → its A-label form; ASCII passes through unchanged (idempotent). */
export function idnaToAscii(host: string): string | null {
  if (ASCII_ONLY.test(host)) return host;
  const out: string[] = [];
  for (const label of host.split(".")) {
    if (ASCII_ONLY.test(label)) {
      out.push(label);
    } else {
      const encoded = punycodeEncode(label.normalize("NFC"));
      if (encoded === null) return null;
      out.push("xn--" + encoded);
    }
  }
  return out.join(".");
}

export function normalizeHost(raw: string): string | null {
  const u = normalizeHostUnicode(raw);
  return u === null ? null : idnaToAscii(u);
}

/** R46: the SAME normalizer stopped before the A-label step — every ASCII rule applied, the
 *  U-label kept. DISPLAY only (the Health duplicate clusters show what the member typed); never
 *  a matching input — normalizeHost's A-label is the only thing matches() compares. Core twin. */
export function normalizeHostUnicode(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  s = s.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "");
  const cut = s.search(/[/?#]/);
  if (cut >= 0) s = s.slice(0, cut);
  const at = s.lastIndexOf("@");
  if (at >= 0) s = s.slice(at + 1);
  if (s.startsWith("[")) {
    const close = s.indexOf("]");
    s = close >= 0 ? s.slice(1, close) : s.slice(1); // IPv6
  } else {
    // Strip a numeric port ONLY when there is exactly one colon: a bare (unbracketed) IPv6
    // literal carries >=2 colons and must survive re-normalization intact — the old
    // lastIndexOf rule turned "2001:db8::1" into "2001:db8:" on a second pass.
    // (Idempotence matters: callers may normalize before matches() normalizes again.)
    const colon = s.lastIndexOf(":");
    const oneColon = colon >= 0 && s.indexOf(":") === colon;
    if (oneColon && colon < s.length - 1 && /^\d+$/.test(s.slice(colon + 1))) s = s.slice(0, colon);
  }
  // R44 (H22 recheck): U+1E9E CAPITAL SHARP S is refused BEFORE the lowercase step, because
  // toLowerCase() maps it to ß (U+00DF) while UTS46 — what every browser applies — maps it to
  // "ss". A saved `straẞe.de` would otherwise canonicalize to `xn--strae-oqa.de` (straße.de), a
  // DIFFERENT registrable domain from the `strasse.de` the browser reports: not an under-match
  // but a cross-origin fill. Every other omitted UTS46 mapping encodes to a label no registry
  // can hold (an under-match); this is the one that lands on a real one. Core UriMatch.kt twin.
  if (s.includes("\u1E9E")) return null;
  s = s.trim().replace(/\.+$/, "").toLowerCase();
  // Strip EVERY leading "www." label (not just one) — normalizeHost must be idempotent,
  // and a single-strip made normalize(normalize("www.www.x")) != normalize("www.www.x"),
  // which had the extension (which pre-normalizes) disagreeing with core/Android.
  while (s.startsWith("www.")) s = s.slice(4);
  if (!s) return null;
  // A5: an empty label (".example.com", "a..example.com") is garbage that must not match
  // ANYTHING — the eTLD+1 resolver would otherwise resolve it to its rightmost real family
  // and quietly grant it the new equality rule. (IPv6 hosts have no dots between groups.)
  if (s.split(".").some((l) => !l)) return null;
  // H22: normalizeHost canonicalizes to the A-label LAST, after every ASCII rule above has run.
  // Symmetric (matches() normalizes the page host through here too), idempotent (ASCII in →
  // unchanged), fail-closed (encoder overflow → null → matches nothing). Core UriMatch.kt parity.
  return s;
}

export function parseSavedUri(raw: string): SavedUri | null {
  const s = raw.trim();
  if (!s) return null;
  if (s.startsWith(ANDROID_APP_SCHEME)) {
    const pkg = s.slice(ANDROID_APP_SCHEME.length).trim();
    return pkg ? { kind: "app", pkg } : null;
  }
  const host = normalizeHost(s);
  return host ? { kind: "web", host } : null;
}

function isIpLiteral(host: string): boolean {
  if (host.includes(":")) return true; // IPv6 (brackets stripped)
  const parts = host.split(".");
  return parts.length === 4 && parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

// ---- eTLD+1 (spec 02 §3.1 amendment 2026-07-10; design A1/A3/A8) ----

/** Three-state PSL resolution (A1). "public-suffix" covers exact, wildcard-derived, AND
 *  exception-derived suffixes; "unknown" = no explicit rule / non-ASCII / IP / garbage. */
export type PslResult = { kind: "registrable"; domain: string } | { kind: "public-suffix" } | { kind: "unknown" };
export type PslResolve = (host: string) => PslResult;

/** A8 bundle placement: the REAL resolver lives in psl.ts (the only importer of the ~144 KB
 *  pslData blob). This module stays data-free so content-script bundles that need only
 *  classify()/normalizeHost() never carry the list. Callers without PSL needs (or in
 *  PSL-free bundles) pass RESOLVE_UNKNOWN and get the pre-amendment rules bit-for-bit. */
export const RESOLVE_UNKNOWN: PslResolve = () => ({ kind: "unknown" });

export function matches(saved: SavedUri, target: FillTarget, resolve: PslResolve): boolean {
  if (saved.kind === "app") return saved.pkg === target.packageName;
  // Normalize the page host symmetrically with saved.host (case / www. / port / trailing
  // dot) — the browser reports it raw (core UriMatch.kt parity).
  const page = target.webHost === null ? null : normalizeHost(target.webHost);
  if (page === null) return false;
  if (saved.host === page) return true;
  if (isIpLiteral(saved.host) || isIpLiteral(page)) return false;
  const sr = resolve(saved.host);
  const pr = resolve(page);
  // R-SUFFIX-BARE: a bare public suffix is exact-only in BOTH roles — saved "github.io"
  // fills no tenant; a page AT "b.kawasaki.jp" gets no "kawasaki.jp" item.
  if (sr.kind === "public-suffix" || pr.kind === "public-suffix") return false;
  // R-EQ: both positively resolved → EQUALITY decides. Grants the reverse/sibling matches
  // the old suffix rule missed; refuses every known-registrable-boundary crossing.
  if (sr.kind === "registrable" && pr.kind === "registrable") return sr.domain === pr.domain;
  // R-OLD: ≥1 side unknown (intranet TLDs, snapshot staleness) → pre-amendment rule.
  return saved.host.includes(".") && page.endsWith("." + saved.host);
}

export function matchLogins(uris: string[], target: FillTarget, resolve: PslResolve): boolean {
  return uris.some((u) => {
    const s = parseSavedUri(u);
    return s !== null && matches(s, target, resolve);
  });
}

// ---- field classification ----

export type FieldKind = "username" | "password" | "none";

export interface FieldSignal {
  hints?: string[];
  inputTypeClass?: number;
  inputTypeVariation?: number;
  htmlType?: string | null;
  htmlNameOrId?: string | null;
}

const CLASS_TEXT = 0x1;
const CLASS_NUMBER = 0x2;
const V_PW = 0x80;
const V_WEBPW = 0xe0;
const V_VISPW = 0x90;
const V_EMAIL = 0x20;
const V_WEBEMAIL = 0xd0;
const N_PW = 0x10;

const USERNAME_HINTS = new Set(["username", "emailaddress", "email", "newusername", "personname"]);
const PASSWORD_HINTS = new Set(["password", "newpassword", "currentpassword"]);
// F11: "onetimecode" joins the negatives (lockstep with core + web) so a password is never
// offered into a one-time-code box — pinned by urimatch.vectors.test.ts's classify run (G20).
const NEGATIVE_HINTS = new Set(["smsotpcode", "otpcode", "onetimecode", "cardnumber", "creditcardnumber", "postalcode", "creditcardsecuritycode"]);
const NAME_POSITIVE_USER = ["user", "email", "login", "account", "userid"];
const NAME_POSITIVE_PASS = ["pass", "pwd", "passwd"];
const NAME_NEGATIVE = ["search", "otp", "captcha", "code", "query", "phone"];
// H65 (spec 02 §3.1, 2026-09-13 amendment) — two-factor name spellings that carry no otp/code
// token, read ONLY by the one-time-code override in classify() below. Deliberately NOT folded
// into NAME_NEGATIVE, which also gates the frozen USERNAME legs (an `email` type, the InputType
// email variations, the bare name/id fallbacks): widening that list would flip verdicts on
// fields this amendment never looked at. Core FieldClassifier.TWO_FACTOR_NAMES twin.
const TWO_FACTOR_NAMES = ["2fa", "mfa", "twofactor"];
// H65 — the ONE exception to the override: a masked CVV box. Core resolves this by ORDER (its
// step-2 CSC demotion runs before the override and returns CC_CSC); this 3-kind engine has no
// card verdict to return, so it must instead LEAVE the field on "password", which is exactly
// what keeps detect.ts's form-level demoteCsc able to reach a `<input type=password
// name=securityCode>` on a checkout — dropping it to "none" would delete the field from
// collect() and silently break masked-CVV card fill. The regex mirrors core's whole-token-RUN
// CSC_DEMOTION over the only spellings that can also carry a NAME_NEGATIVE token: a leading
// boundary and a trailing non-letter keep `cscode`/`cvvcode`/`mysecuritycode` OUT (core's
// tokenMatch refuses those mid-token hits too, so both engines send them to "none"). Web has no
// card path of its own; it carries the rule verbatim because the two urimatch.ts copies are
// behaviour twins.
//
// R32-class correction (R35): the regex is tested against a CAMEL-AWARE probe, never against the
// lower-cased name. Lowercasing destroys exactly the boundary core's tokenizer splits on, so
// `cardSecurityCode`, `cvvCode` and `cardVerificationCode` — the ordinary JS/React spellings —
// found no separator, failed the carve-out, and were demoted to "none" by the `code` token while
// core returned CC_CSC for the same field. collect() then dropped the field and masked-CVV card
// fill silently broke on those checkouts, in direct contradiction of the spec text this override
// shipped with. [cscProbe] re-inserts the boundaries (camelCase both ways, plus the letter↔digit
// split core also makes) so the two engines agree token-for-token; the mid-token refusals above
// are untouched, because a name with no boundary to restore comes back unchanged.
const CSC_NAME_RX = /(^|[^a-z0-9])(cvv|cvc|csc|security[^a-z0-9]?code|card[^a-z0-9]?verification)([^a-z]|$)/;

/** The raw name with core's tokenizer boundaries re-inserted as spaces, then lower-cased —
 *  "cardSecurityCode" → "card security code", "CVVCode" → "cvv code", "cvv2" → "cvv 2". Feed
 *  this to [CSC_NAME_RX], never the already-lower-cased nameId (R35). */
function cscProbe(raw: string): string {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2") // fooBar
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2") // CVVCode
    .replace(/([a-zA-Z])([0-9])/g, "$1 $2") // cvv2
    .replace(/([0-9])([a-zA-Z])/g, "$1 $2") // 3dsecure
    .toLowerCase();
}

export function classify(s: FieldSignal): FieldKind {
  const hints = (s.hints ?? []).map((h) => h.toLowerCase().replace(/[_-]/g, ""));
  if (hints.some((h) => NEGATIVE_HINTS.has(h))) return "none";
  if (hints.some((h) => PASSWORD_HINTS.has(h))) return "password";
  if (hints.some((h) => USERNAME_HINTS.has(h))) return "username";

  const nameId = (s.htmlNameOrId ?? "").toLowerCase();
  const negativeName = NAME_NEGATIVE.some((k) => nameId.includes(k));

  switch ((s.htmlType ?? "").toLowerCase()) {
    case "password":
      // H65 (2026-09-13 audit; spec 02 §3.1 amendment) — the one-time-code override. F11 kept the
      // vault password out of a one-time-code box only when the page said so with an autofill
      // hint (NEGATIVE_HINTS above). A site that masks its 2FA entry as
      // `<input type="password" name="otp">` and omits `autocomplete` fell through to this rule,
      // so the account password was offered into the code box — and because the extension's
      // capture engine reads back whatever the fill target holds on submit, six digits could
      // then overwrite the stored credential. The field's own name carrying a NAME_NEGATIVE
      // token is the page saying what the hint would have said, so it outranks the type. Same
      // scope and the same NONE verdict as the hinted box, in lockstep with core's step 2b and
      // pinned by the urimatch.json classify vectors. Accepted, one-directional cost: a genuine
      // password box named `…code` (`passcode`) stops being OFFERED a fill — never the reverse —
      // and the engine already refused to read that name as a login field on a text input.
      if ((negativeName || TWO_FACTOR_NAMES.some((k) => nameId.includes(k))) && !CSC_NAME_RX.test(cscProbe(s.htmlNameOrId ?? ""))) return "none";
      return "password";
    case "email":
      if (!negativeName) return "username";
      break;
    case "search":
    case "tel":
    case "number":
      return "none";
    case "text":
    case "":
      if (!negativeName && NAME_POSITIVE_PASS.some((k) => nameId.includes(k))) return "password";
      if (!negativeName && NAME_POSITIVE_USER.some((k) => nameId.includes(k))) return "username";
      break;
  }

  const cls = s.inputTypeClass ?? 0;
  const varn = s.inputTypeVariation ?? 0;
  if (cls === CLASS_TEXT) {
    if (varn === V_PW || varn === V_WEBPW || varn === V_VISPW) return "password";
    if ((varn === V_EMAIL || varn === V_WEBEMAIL) && !negativeName) return "username";
  }
  if (cls === CLASS_NUMBER && varn === N_PW) return "password";

  if (!negativeName && NAME_POSITIVE_PASS.some((k) => nameId.includes(k))) return "password";
  if (!negativeName && NAME_POSITIVE_USER.some((k) => nameId.includes(k))) return "username";
  return "none";
}
