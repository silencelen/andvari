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
    const colon = s.lastIndexOf(":");
    if (colon >= 0 && colon < s.length - 1 && /^\d+$/.test(s.slice(colon + 1))) s = s.slice(0, colon);
  }
  s = s.trim().replace(/\.+$/, "").toLowerCase();
  if (s.startsWith("www.")) s = s.slice(4);
  return s || null;
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

export function matches(saved: SavedUri, target: FillTarget): boolean {
  if (saved.kind === "app") return saved.pkg === target.packageName;
  const page = target.webHost;
  if (page === null) return false;
  if (saved.host === page) return true;
  if (isIpLiteral(saved.host) || isIpLiteral(page)) return false;
  if (saved.host.includes(".") && page.endsWith("." + saved.host)) return true; // ≥2-label suffix
  return false;
}

export function matchLogins(uris: string[], target: FillTarget): boolean {
  return uris.some((u) => {
    const s = parseSavedUri(u);
    return s !== null && matches(s, target);
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
