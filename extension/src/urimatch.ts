// Autofill URI matching + field classification (spec 02 §3.1) — verbatim port of
// web/src/vault/urimatch.ts (itself the TS mirror of core/.../client/autofill/UriMatch.kt +
// FieldClassifier.kt). All impls run the SAME spec/test-vectors/urimatch.json — keep in lockstep.

const ANDROID_APP_SCHEME = "androidapp://";

export type SavedUri = { kind: "web"; host: string } | { kind: "app"; pkg: string };

export interface FillTarget {
  webHost: string | null; // set only when the requester is a trusted browser
  packageName: string;
}

export function normalizeHost(raw: string): string | null {
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
// offered into a one-time-code box — the extension has no vector test, so keep this in sync by hand.
const NEGATIVE_HINTS = new Set(["smsotpcode", "otpcode", "onetimecode", "cardnumber", "creditcardnumber", "postalcode", "creditcardsecuritycode"]);
const NAME_POSITIVE_USER = ["user", "email", "login", "account", "userid"];
const NAME_POSITIVE_PASS = ["pass", "pwd", "passwd"];
const NAME_NEGATIVE = ["search", "otp", "captcha", "code", "query", "phone"];

export function classify(s: FieldSignal): FieldKind {
  const hints = (s.hints ?? []).map((h) => h.toLowerCase().replace(/[_-]/g, ""));
  if (hints.some((h) => NEGATIVE_HINTS.has(h))) return "none";
  if (hints.some((h) => PASSWORD_HINTS.has(h))) return "password";
  if (hints.some((h) => USERNAME_HINTS.has(h))) return "username";

  const nameId = (s.htmlNameOrId ?? "").toLowerCase();
  const negativeName = NAME_NEGATIVE.some((k) => nameId.includes(k));

  switch ((s.htmlType ?? "").toLowerCase()) {
    case "password":
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
