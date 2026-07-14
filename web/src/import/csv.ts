import type { ItemDoc } from "../api/types";
import { normalizeTotp, parseOtpauthUri } from "../crypto/totp";
import { parseSavedUri } from "../vault/urimatch";

/**
 * Password-manager CSV import (spec 06 + design 2026-07-09 guided importers) — 100%
 * client-side, pure (no DOM, no crypto operations; TOTP handling is string/parse work
 * only). The TS twin of core/.../client/CsvImport.kt (the Kotlin REFERENCE that emits
 * the vectors). Both MUST parse identically — web/src/import/csv.test.ts and the Kotlin
 * ImportVectorsTest consume the SAME spec/test-vectors/import.json (byte-frozen) and
 * import-foreign.json (Bitwarden/LastPass/1Password + the F75 vault-aware plan).
 */

/**
 * Cross-port determinism (the card.ts TRIMMABLE precedent): every adapter-level trim
 * uses ONLY this pinned set, never platform trim()/`\s`/isWhitespace — those disagree
 * at the Unicode margins (JS String.trim()/`\s` strips U+FEFF where the JVM keeps it;
 * JVM isWhitespace strips U+001C..U+001F where JS keeps them), and the same bytes must
 * parse identically on every client. U+FEFF joins the set here (unlike the card set)
 * because a residual BOM from a re-saved/concatenated export lands INSIDE header and
 * data cells and must trim identically everywhere (a `http://sn<FEFF>` url is a NOTE on
 * every client, never a credential-less login whose body is dropped). Vector-pinned in
 * import-foreign.json; Kotlin twin: CsvImport.TRIMMABLE/csvTrim.
 */
const TRIMMABLE = " \t\n\r\u000B\u000C\uFEFF";
function csvTrim(raw: string): string {
  let start = 0;
  let end = raw.length;
  while (start < end && TRIMMABLE.includes(raw.charAt(start))) start++;
  while (end > start && TRIMMABLE.includes(raw.charAt(end - 1))) end--;
  return start === 0 && end === raw.length ? raw : raw.slice(start, end);
}

export const MAX_BYTES = 10 * 1024 * 1024;
export const MAX_ROWS = 10_000;

export type ImportFormat = "chrome" | "firefox" | "bitwarden" | "1password" | "lastpass";

/** Kotlin enum RowKind LOGIN/NOTE — the vectors encode these lowercase strings. */
export type RowKind = "login" | "note";

/** too_large | too_many_rows | unrecognized_header — thrown by parseCsvImport. */
export class ImportError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.name = "ImportError";
    this.code = code;
  }
}

export interface ParsedRow {
  kind: RowKind;
  name: string;
  /** The row's primary url (= uris[0] or "") — dedupe + name fallback key on it. */
  url: string;
  /** Full uri list for the planned doc — Bitwarden comma-joins multi-URI logins (A4). */
  uris: string[];
  username: string;
  password: string;
  notes: string;
  /** A6 truthiness, pinned once for all formats; browser CSVs have no such column → false. */
  favorite: boolean;
  timePasswordChangedMs: number | null;
  /** chrome round-trip: the cell VERBATIM (frozen import.json behavior). New-format
   *  adapters: the NORMALIZED otpauth URI, present ONLY when the shared parse accepts
   *  it (A5 reject-don't-corrupt) — rejects live in notes + [totpUnsupported]. */
  totp: string | null;
  /** The totp cell was rejected → kept as text in [notes]; the report enumerates the
   *  row (by its FINAL planned name) under totpUnsupported. */
  totpUnsupported: boolean;
}

/** wrong_field_count | bad_quote, at the 1-based physical line of the row's first char. */
export interface RowError {
  line: number;
  code: string;
}

export interface Parsed {
  format: ImportFormat;
  rows: ParsedRow[];
  errors: RowError[];
  /** False when the file has NO totp column → totp is a WILDCARD in vault rules 1–2 (A7). */
  totpColumn: boolean;
  /** 1Password archived-truthy rows, by name — skipped at parse, never resurrected. */
  archivedSkipped: string[];
  /** Bitwarden non-login/note rows, by name — skipped at parse + enumerated. */
  unknownTypeSkipped: string[];
}

/**
 * Light projections of the TARGET (personal) vault, decrypted by the caller — the F75
 * vault-aware plan input (design §dedupe, A7/A8). Built ONLY by the store's
 * `importProjections()` (A8: one owned builder; refuse — never degrade — when unsynced):
 * personal vault only, absent fields mapped to ""/[]/null, `names` = ALL personal
 * display names (every item type) — the A9 rename-until-free pool.
 */
export interface ImportProjections {
  logins: { name: string; uris: string[]; username: string; password: string; totp: string | null }[];
  notes: { name: string; notes: string }[];
  names: string[];
}

export interface ImportReport {
  imported: number;
  skippedEmpty: number;
  collapsed: number;
  /** Renamed "(k)" purely for IN-FILE duplicates — rows renamed because they differ from
   *  a VAULT item are enumerated under passwordDiffers/totpDiffers instead (exclusive). */
  flagged: string[];
  /** Vault rule 1: exact matches of a personal item — skipped, never re-imported. */
  alreadyInVault: string[];
  /** Vault rule 2, split per A9: same site+user but the password differs (a row
   *  differing in BOTH password and totp goes here, not to totpDiffers)… */
  passwordDiffers: string[];
  /** …vs same site+user+password but the 2FA secret differs. */
  totpDiffers: string[];
  archivedSkipped: string[];
  unknownTypeSkipped: string[];
  /** Rows whose totp cell was kept as text (A5), by FINAL planned name. */
  totpUnsupported: string[];
  /** Imported note items, by (final) name — a LIST, not a count (A9). */
  noteItems: string[];
  errors: RowError[];
}

/** itemId minted ONCE at plan time so a retried import replays idempotently (spec 06 §4). */
export interface PlannedItem {
  itemId: string;
  doc: ItemDoc;
}

export interface ImportPlan {
  items: PlannedItem[];
  report: ImportReport;
}

// ---- parse ----

/** bytes → text exactly like Kotlin decodeToString(): lenient UTF-8 (invalid → U+FFFD),
 *  then precisely ONE leading BOM stripped. */
function decodeCsvText(bytes: Uint8Array): string {
  let text = new TextDecoder("utf-8", { ignoreBOM: true, fatal: false }).decode(bytes);
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return text;
}

export function parseCsvImport(bytes: Uint8Array): Parsed {
  if (bytes.length > MAX_BYTES) throw new ImportError("too_large");
  const text = decodeCsvText(bytes);

  const records = parseRecords(text);
  if (records.length === 0) throw new ImportError("unrecognized_header");
  const header = records[0]!.fields.map((s) => csvTrim(s).toLowerCase()); // pinned trim: a 2nd-BOM header cell must detect identically cross-impl
  const format = detectFormat(header);
  if (!format) throw new ImportError("unrecognized_header");

  // Drop blank lines (a record that is a single empty field).
  const dataRecords = records.slice(1).filter((r) => !(r.fields.length === 1 && r.fields[0] === ""));
  if (dataRecords.length > MAX_ROWS) throw new ImportError("too_many_rows");

  switch (format) {
    case "chrome":
    case "firefox":
      return parseBrowser(format, header, dataRecords);
    case "bitwarden":
      return parseBitwarden(header, dataRecords);
    case "lastpass":
      return parseLastPass(header, dataRecords);
    default:
      return parseOnePassword(header, dataRecords);
  }
}

/**
 * Detection = SPECIFICITY-ORDERED required-subset matching (design A3; the order is
 * load-bearing: LastPass's header is a superset of Chrome's required set). Header
 * detection stays authoritative over whatever source the user PICKED in the guided UI.
 */
function detectFormat(header: string[]): ImportFormat | null {
  const h = new Set(header);
  const all = (ks: string[]) => ks.every((k) => h.has(k));
  if (all(BITWARDEN_REQUIRED)) return "bitwarden";
  if (all(LASTPASS_REQUIRED)) return "lastpass";
  if (all(ONE_PASSWORD_REQUIRED)) return "1password";
  if (all(["url", "username", "password"]) && ["guid", "httprealm", "formactionorigin"].some((k) => h.has(k))) {
    return "firefox";
  }
  if (all(["name", "url", "username", "password"])) return "chrome";
  return null;
}

const BITWARDEN_REQUIRED = ["type", "name", "login_uri", "login_username", "login_password"];
const LASTPASS_REQUIRED = ["url", "username", "password", "extra", "name", "grouping"]; // totp/fav optional (pre-2023 files)
const ONE_PASSWORD_REQUIRED = ["title", "url", "username", "password", "otpauth"]; // favorite/archived/tags/notes optional

/** Per-record guard shared by every format loop: bad quoting and field-count mismatches
 *  keep the existing RowError taxonomy; good rows reach [body]. */
function eachRow(dataRecords: RawRecord[], headerSize: number, errors: RowError[], body: (f: string[]) => void): void {
  for (const rec of dataRecords) {
    if (rec.badQuote) {
      errors.push({ line: rec.line, code: "bad_quote" });
      continue;
    }
    if (rec.fields.length !== headerSize) {
      errors.push({ line: rec.line, code: "wrong_field_count" });
      continue;
    }
    body(rec.fields);
  }
}

/** Chrome/Edge + Firefox — the original (vector-frozen) mapping, unchanged. */
function parseBrowser(format: "chrome" | "firefox", header: string[], dataRecords: RawRecord[]): Parsed {
  const col = (name: string) => header.indexOf(name);
  const iName = col("name");
  const iUrl = col("url");
  const iUser = col("username");
  const iPass = col("password");
  const iNote = col("note") >= 0 ? col("note") : col("notes");
  const iRealm = col("httprealm");
  const iPwChanged = col("timepasswordchanged");
  const iTotp = col("totp"); // andvari CSV round-trip column (spec 06 §1 / 07 §1); browsers lack it

  const rows: ParsedRow[] = [];
  const errors: RowError[] = [];
  eachRow(dataRecords, header.length, errors, (f) => {
    const url = getOr(f, iUrl);
    const username = getOr(f, iUser);
    const password = getOr(f, iPass);
    let notes = iNote >= 0 ? getOr(f, iNote) : "";
    if (format === "firefox" && iRealm >= 0) {
      const realm = getOr(f, iRealm);
      if (realm.length > 0) notes = notes.length === 0 ? `HTTP realm: ${realm}` : `${notes}\nHTTP realm: ${realm}`;
    }
    const rawName = format === "chrome" && iName >= 0 ? getOr(f, iName) : "";
    const name = rawName.length > 0 ? rawName : nameFallback(url);
    const pwChanged = iPwChanged >= 0 ? toLongOrNull(csvTrim(getOr(f, iPwChanged))) : null;
    const totp = iTotp >= 0 ? csvTrim(getOr(f, iTotp)) || null : null;
    rows.push({
      kind: "login",
      name,
      url,
      uris: url.length > 0 ? [url] : [],
      username,
      password,
      notes,
      favorite: false,
      timePasswordChangedMs: pwChanged,
      totp,
      totpUnsupported: false,
    });
  });
  return { format, rows, errors, totpColumn: iTotp >= 0, archivedSkipped: [], unknownTypeSkipped: [] };
}

/** Bitwarden personal/org CSV (spec 06 §6): type=login|note rows; `fields` append (A2),
 *  multi-uri split (A4), truthy favorite (A6), totp via the shared normalize (A5). */
function parseBitwarden(header: string[], dataRecords: RawRecord[]): Parsed {
  const col = (name: string) => header.indexOf(name);
  const iType = col("type");
  const iName = col("name");
  const iNotes = col("notes");
  const iFields = col("fields");
  const iFav = col("favorite");
  const iUri = col("login_uri");
  const iUser = col("login_username");
  const iPass = col("login_password");
  const iTotp = col("login_totp"); // folder/reprompt/collections ignored

  const rows: ParsedRow[] = [];
  const errors: RowError[] = [];
  const unknownTypeSkipped: string[] = [];
  eachRow(dataRecords, header.length, errors, (f) => {
    const name = getOr(f, iName);
    const favorite = truthy(getOr(f, iFav));
    const notesCell = getOr(f, iNotes);
    const fieldsCell = getOr(f, iFields);
    const type = csvTrim(getOr(f, iType)).toLowerCase();
    if (type === "note") {
      rows.push({
        kind: "note",
        name,
        url: "",
        uris: [],
        username: "",
        password: "",
        notes: assembleNotes(notesCell, fieldsCell, null),
        favorite,
        timePasswordChangedMs: null,
        totp: null,
        totpUnsupported: false,
      });
    } else if (type === "login") {
      const uris = splitUris(getOr(f, iUri));
      const url = uris[0] ?? "";
      const t = adaptTotp(getOr(f, iTotp));
      rows.push({
        kind: "login",
        name: name.length > 0 ? name : nameFallback(url),
        url,
        uris,
        username: getOr(f, iUser),
        password: getOr(f, iPass),
        notes: assembleNotes(notesCell, fieldsCell, t.noteLine),
        favorite,
        timePasswordChangedMs: null,
        totp: t.totp,
        totpUnsupported: t.unsupported,
      });
    } else {
      unknownTypeSkipped.push(name); // cards/identities/…: skipped + enumerated
    }
  });
  return { format: "bitwarden", rows, errors, totpColumn: iTotp >= 0, archivedSkipped: [], unknownTypeSkipped };
}

/** LastPass CSV (spec 06 §7): url=="http://sn" rows are secure notes (extra = the body,
 *  templated blobs imported verbatim); grouping ignored; pre-2023 files lack totp. */
function parseLastPass(header: string[], dataRecords: RawRecord[]): Parsed {
  const col = (name: string) => header.indexOf(name);
  const iUrl = col("url");
  const iUser = col("username");
  const iPass = col("password");
  const iExtra = col("extra");
  const iName = col("name");
  const iFav = col("fav");
  const iTotp = col("totp");

  const rows: ParsedRow[] = [];
  const errors: RowError[] = [];
  eachRow(dataRecords, header.length, errors, (f) => {
    const url = getOr(f, iUrl);
    const name = getOr(f, iName);
    const extra = getOr(f, iExtra);
    const favorite = truthy(getOr(f, iFav));
    if (csvTrim(url) === "http://sn") { // pinned trim: `http://sn<FEFF>` is a NOTE on every client
      rows.push({
        kind: "note",
        name,
        url: "",
        uris: [],
        username: "",
        password: "",
        notes: extra,
        favorite,
        timePasswordChangedMs: null,
        totp: null,
        totpUnsupported: false,
      });
    } else {
      const t = adaptTotp(getOr(f, iTotp));
      rows.push({
        kind: "login",
        name: name.length > 0 ? name : nameFallback(url),
        url,
        uris: url.length > 0 ? [url] : [],
        username: getOr(f, iUser),
        password: getOr(f, iPass),
        notes: assembleNotes(extra, "", t.noteLine),
        favorite,
        timePasswordChangedMs: null,
        totp: t.totp,
        totpUnsupported: t.unsupported,
      });
    }
  });
  return { format: "lastpass", rows, errors, totpColumn: iTotp >= 0, archivedSkipped: [], unknownTypeSkipped: [] };
}

/** 1Password-8 CSV (spec 06 §8) — also matches Apple/Safari exports (pinned free win).
 *  archived-truthy rows are skipped + enumerated (deliberately shelved by the user). */
function parseOnePassword(header: string[], dataRecords: RawRecord[]): Parsed {
  const col = (name: string) => header.indexOf(name);
  const iTitle = col("title");
  const iUrl = col("url");
  const iUser = col("username");
  const iPass = col("password");
  const iOtp = col("otpauth");
  const iFav = col("favorite");
  const iArch = col("archived");
  const iNotes = col("notes"); // tags ignored

  const rows: ParsedRow[] = [];
  const errors: RowError[] = [];
  const archivedSkipped: string[] = [];
  eachRow(dataRecords, header.length, errors, (f) => {
    const url = getOr(f, iUrl);
    const rawName = getOr(f, iTitle);
    const name = rawName.length > 0 ? rawName : nameFallback(url);
    if (truthy(getOr(f, iArch))) {
      archivedSkipped.push(name);
      return;
    }
    const t = adaptTotp(getOr(f, iOtp));
    rows.push({
      kind: "login",
      name,
      url,
      uris: url.length > 0 ? [url] : [],
      username: getOr(f, iUser),
      password: getOr(f, iPass),
      notes: assembleNotes(getOr(f, iNotes), "", t.noteLine),
      favorite: truthy(getOr(f, iFav)),
      timePasswordChangedMs: null,
      totp: t.totp,
      totpUnsupported: t.unsupported,
    });
  });
  return { format: "1password", rows, errors, totpColumn: iOtp >= 0, archivedSkipped, unknownTypeSkipped: [] };
}

// ---- adapter helpers (spec 06 §9) ----

/** A6 — the ONE truthiness predicate for favorite/archived flags across all formats:
 *  trim().lowercase() ∈ {"1","true","y","yes"}; everything else — including "0", "",
 *  "false" — is falsy (LastPass writes fav=0 on EVERY row; `Boolean("0")` is the trap). */
function truthy(cell: string): boolean {
  // Pinned csvTrim: `1<U+001C>` and `1<FEFF>` are falsy on EVERY client, identically.
  const t = csvTrim(cell).toLowerCase();
  return t === "1" || t === "true" || t === "y" || t === "yes";
}

interface AdaptedTotp {
  totp: string | null;
  noteLine: string | null;
  unsupported: boolean;
}

/** A5 reject-don't-corrupt: normalize via the ONE shared normalizeTotp; a value the
 *  otpauth parser refuses (steam://, hotp, junk) is NEVER stored in login.totp — it is
 *  preserved as a notes line and enumerated (report bucket `totpUnsupported`). */
function adaptTotp(cell: string): AdaptedTotp {
  const raw = csvTrim(cell);
  if (raw.length === 0) return { totp: null, noteLine: null, unsupported: false };
  const normalized = normalizeTotp(raw);
  if (parsesAsOtpauth(normalized)) return { totp: normalized, noteLine: null, unsupported: false };
  return { totp: null, noteLine: `Unsupported TOTP (kept as text): ${raw}`, unsupported: true };
}

function parsesAsOtpauth(value: string): boolean {
  try {
    parseOtpauthUri(value);
    return true;
  } catch {
    return false;
  }
}

/** Notes assembly (pinned order): base notes, then the Bitwarden custom-fields block
 *  (A2 — note rows too), then the unsupported-TOTP line; parts joined by "\n". */
function assembleNotes(base: string, fields: string, totpLine: string | null): string {
  const parts: string[] = [];
  if (base.length > 0) parts.push(base);
  if (fields.length > 0) parts.push(`— custom fields —\n${fields}`);
  if (totpLine !== null) parts.push(totpLine);
  return parts.join("\n");
}

/** A4 — Bitwarden comma-joins multi-uri logins; verbatim storage would kill UriMatch.
 *  Segments are trimmed, empties dropped (a literal comma inside one uri is accepted loss). */
function splitUris(cell: string): string[] {
  return cell.split(",").map((u) => csvTrim(u)).filter((u) => u.length > 0);
}

// ---- plan (skip / dedupe / rename), vault-aware (F75 + A1/A7/A9) ----

/** The "no url class" token (empty/unparseable) — [] and [""] uris key identically (A7). */
const NO_URI = "-";

/** The A9 rename shape, pinned ASCII (never platform \d classes): `base (k)` -> base,
 *  else null. Strips ONE suffix (matching what one freeName mint appends); Kotlin twin:
 *  CsvImport.baseNameOf. */
const RENAMED = /^(.+) \(([0-9]+)\)$/;
function baseNameOf(name: string): string | null {
  const m = RENAMED.exec(name);
  return m ? m[1]! : null;
}

/** The spec 02 §3.1 equivalence class of ONE uri (normalizeHost/parseSavedUri), or null
 *  when the uri is EMPTY (no class). A non-empty uri that fails to parse (A5 junk like
 *  ".example.com" — parseable before 2026-07-10) keys a verbatim `j:` class instead of
 *  dropping to null: silently dropping it collapsed junk-uri-only items into the NO_URI
 *  class, where a re-import could false-merge rows that differ only by that junk uri.
 *  Entry trim is the pinned csvTrim, never platform trim() — JS trim() strips U+FEFF
 *  where the JVM keeps it, so a uri cell carrying a residual BOM landed in DIFFERENT
 *  equality classes per impl, flipping alreadyInVault/passwordDiffers verdicts. */
function uriClass(raw: string): string | null {
  const trimmed = csvTrim(raw);
  if (!trimmed) return null;
  const s = parseSavedUri(trimmed);
  if (s === null) return `j:${trimmed.toLowerCase()}`;
  return s.kind === "app" ? `a:${s.pkg}` : `w:${s.host}`;
}

/**
 * A7: the TOTP fingerprint used by vault rules 1–2 — PARSED parameters (secret bytes +
 * algorithm + digits + period) of the shared-normalized value, so labels/case/bare-base32
 * spelling never discriminate. Absent/empty → the distinguished "-" (no-totp matches
 * no-totp); a value that still doesn't parse → null (unmatchable — never stored by the
 * adapters, but possible on the chrome verbatim path or an old vault row).
 */
function totpFp(raw: string | null): string | null {
  if (raw === null || raw.length === 0) return "-";
  try {
    const c = parseOtpauthUri(normalizeTotp(raw));
    return `p\u0001${Array.from(c.secret).join(",")}\u0001${c.algorithm}\u0001${c.digits}\u0001${c.periodSeconds}`;
  } catch {
    return null;
  }
}

/** Vault-side note text may carry CRLF / lone CR (written by other clients); the CSV
 *  reader already emits LF on the row side — normalize before the note rule-1 key (A7). */
function toLf(s: string): string {
  return s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

export function planImport(parsed: Parsed, existing: ImportProjections, newId: () => string): ImportPlan {
  // -- vault-side index (built once; the guard excludes url-less+username-less items
  //    from the site/user maps — they match through the (name, password[, totp]) alt key) --
  const exactFps = new Map<string, Set<string>>(); // class NUL user NUL pass → totp fingerprints
  const siteUser = new Map<string, number>(); // class NUL user → existing item count (rule 2 + seed)
  const altExact = new Map<string, Set<string>>(); // name NUL pass → fingerprints (guard items)
  const noteExact = new Set<string>(); // name NUL notes (vault side CRLF/CR → LF)
  for (const l of existing.logins) {
    const mapped = [...new Set(l.uris.map(uriClass).filter((c): c is string => c !== null))];
    const classes = mapped.length > 0 ? mapped : [NO_URI];
    const fp = totpFp(l.totp ?? null);
    if (classes.length === 1 && classes[0] === NO_URI && l.username.length === 0) {
      const key = `${l.name}\u0000${l.password}`;
      const set = altExact.get(key) ?? new Set<string>();
      if (fp !== null) set.add(fp);
      altExact.set(key, set);
      // Rename-aware rule 1 (A9 inverse; 2026-07-09 review): a guard item stored as
      // "base (k)" — the shape an earlier import's rename minted — ALSO registers under
      // its stripped base name, so re-importing the same file resolves to alreadyInVault
      // instead of duplicating. Content (password[, totp]) equality is still required, so
      // a user's own literal "X (2)" can only skip a row that is content-identical anyway.
      const base = baseNameOf(l.name);
      if (base !== null) {
        const bkey = `${base}\u0000${l.password}`;
        const bset = altExact.get(bkey) ?? new Set<string>();
        if (fp !== null) bset.add(fp);
        altExact.set(bkey, bset);
      }
    } else {
      for (const c of classes) {
        const key = `${c}\u0000${l.username}\u0000${l.password}`;
        const set = exactFps.get(key) ?? new Set<string>();
        if (fp !== null) set.add(fp);
        exactFps.set(key, set);
        const su = `${c}\u0000${l.username}`;
        siteUser.set(su, (siteUser.get(su) ?? 0) + 1);
      }
    }
  }
  for (const n of existing.notes) {
    noteExact.add(`${n.name}\u0000${toLf(n.notes)}`);
    // Rename-aware rule 1 for notes (same rationale as the guard-login base key).
    const base = baseNameOf(n.name);
    if (base !== null) noteExact.add(`${base}\u0000${toLf(n.notes)}`);
  }
  const existingNames = new Set(existing.names);

  // -- in-file state --
  let skippedEmpty = 0;
  let collapsed = 0;
  const flagged: string[] = [];
  const alreadyInVault: string[] = [];
  const passwordDiffers: string[] = [];
  const totpDiffers: string[] = [];
  const totpUnsupported: string[] = [];
  const noteItems: string[] = [];
  const loginExactSeen = new Set<string>(); // uris,user,pass,totp — totp included so a row differing
  //                                           ONLY by its TOTP seed is not dropped as an exact dup
  const noteExactSeen = new Set<string>(); // name,notes (A1)
  const groupCount = new Map<string, number>(); // raw url NUL user → last k used (lazy vault seed)
  const noteGroupCount = new Map<string, number>(); // name → last k used
  const plannedNames = new Set<string>();
  // A9 (2026-07-09 review): every literal row name in the FILE also blocks a mint — a
  // k=1 row keeps its name unconditionally (spec 06 §4), so a rename that fires BEFORE a
  // later row literally named "base (k)" must skip past it or one plan would emit two
  // identical display names. Includes rows that later skip (collapsed/alreadyInVault/
  // skippedEmpty) — an over-skip gap in the (k) sequence is the already-tolerated
  // freeName behavior.
  const fileLiteralNames = new Set(parsed.rows.map((r) => r.name));
  const items: PlannedItem[] = [];

  /** A9 — bump (k) until the display name is free in the vault, this plan, AND the file's literals. */
  const freeName = (base: string, startK: number): { name: string; k: number } => {
    let k = startK;
    for (;;) {
      const cand = `${base} (${k})`;
      if (!existingNames.has(cand) && !plannedNames.has(cand) && !fileLiteralNames.has(cand)) return { name: cand, k };
      k++;
    }
  };

  for (const row of parsed.rows) {
    if (row.kind === "note") {
      // A1 kind-scoped emptiness: a note is empty only when name AND notes both are.
      if (row.name.length === 0 && row.notes.length === 0) {
        skippedEmpty++;
        continue;
      }
      const key = `${row.name}\u0000${row.notes}`;
      if (noteExact.has(key)) {
        alreadyInVault.push(row.name); // vault rule 1 (notes)
        continue;
      }
      if (noteExactSeen.has(key)) {
        collapsed++;
        continue;
      }
      noteExactSeen.add(key);
      let k = (noteGroupCount.get(row.name) ?? 0) + 1;
      let name = row.name;
      if (k >= 2) {
        const free = freeName(row.name, k);
        name = free.name;
        k = free.k;
        flagged.push(name);
      }
      noteGroupCount.set(row.name, k);
      plannedNames.add(name);
      noteItems.push(name);
      items.push({
        itemId: newId(),
        doc: {
          type: "note",
          name,
          notes: row.notes.length > 0 ? row.notes : undefined,
          ...(row.favorite ? { favorite: true } : {}),
        },
      });
      continue;
    }

    // ---- kind = login ----
    if (row.username.length === 0 && row.password.length === 0) {
      skippedEmpty++;
      continue;
    }
    const rowClass = uriClass(row.url) ?? NO_URI;
    const bothEmpty = rowClass === NO_URI && row.username.length === 0; // A7 empty-discriminator guard
    const fpRow = totpFp(row.totp);
    const fpSet = bothEmpty
      ? altExact.get(`${row.name}\u0000${row.password}`)
      : exactFps.get(`${rowClass}\u0000${row.username}\u0000${row.password}`);
    // Vault rule 1 — exact match (totp wildcard when the file has no totp column).
    if (fpSet !== undefined && (!parsed.totpColumn || (fpRow !== null && fpSet.has(fpRow)))) {
      alreadyInVault.push(row.name);
      continue;
    }
    // Vault rule 2 — same site+user, different secret (never fires under the guard).
    const vaultDiffers: "totp" | "password" | null =
      !bothEmpty && siteUser.has(`${rowClass}\u0000${row.username}`)
        ? exactFps.has(`${rowClass}\u0000${row.username}\u0000${row.password}`)
          ? "totp"
          : "password"
        : null;
    // In-file exact collapse (raw values, NUL/SOH-joined).
    const exactKey = `${row.uris.join("\u0001")}\u0000${row.username}\u0000${row.password}\u0000${row.totp ?? ""}`;
    if (loginExactSeen.has(exactKey)) {
      collapsed++;
      continue;
    }
    loginExactSeen.add(exactKey);
    // In-file group (rule 3), seeded from the vault so renames continue the visible sequence.
    const gkey = `${row.url}\u0000${row.username}`;
    let k = (groupCount.get(gkey) ?? (bothEmpty ? 0 : siteUser.get(`${rowClass}\u0000${row.username}`) ?? 0)) + 1;
    let name = row.name;
    if (k >= 2) {
      const free = freeName(row.name, k);
      name = free.name;
      k = free.k;
      if (vaultDiffers === "totp") totpDiffers.push(name); // password matched an existing item; only the seed differs
      else if (vaultDiffers === "password") passwordDiffers.push(name); // includes rows where BOTH differ (pinned)
      else flagged.push(name); // purely in-file duplicate
    }
    groupCount.set(gkey, k);
    plannedNames.add(name);
    if (row.totpUnsupported) totpUnsupported.push(name);
    items.push({
      itemId: newId(),
      doc: {
        type: "login",
        name,
        notes: row.notes.length > 0 ? row.notes : undefined,
        ...(row.favorite ? { favorite: true } : {}),
        login: {
          username: row.username,
          password: row.password,
          uris: row.uris,
          ...(row.totp ? { totp: row.totp } : {}),
        },
      },
    });
  }

  return {
    items,
    report: {
      imported: items.length,
      skippedEmpty,
      collapsed,
      flagged,
      alreadyInVault,
      passwordDiffers,
      totpDiffers,
      archivedSkipped: [...parsed.archivedSkipped],
      unknownTypeSkipped: [...parsed.unknownTypeSkipped],
      totpUnsupported,
      noteItems,
      errors: parsed.errors,
    },
  };
}

/** spec 06 §4.7 — pinned host extraction (no URL library). */
export function nameFallback(url: string): string {
  let s = csvTrim(url);
  if (s.length === 0) return "Imported login";
  s = s.replace(/^[A-Za-z][A-Za-z0-9+.\-]*:\/\//, ""); // strip scheme://
  let cut = -1;
  for (let k = 0; k < s.length; k++) {
    const ch = s.charAt(k);
    if (ch === "/" || ch === "?" || ch === "#") {
      cut = k;
      break;
    }
  }
  if (cut >= 0) s = s.substring(0, cut);
  const at = s.lastIndexOf("@");
  if (at >= 0) s = s.substring(at + 1);
  if (s.startsWith("[")) {
    const close = s.indexOf("]");
    s = close >= 0 ? s.substring(1, close) : s.substring(1); // IPv6 bracket contents
  } else {
    const colon = s.lastIndexOf(":"); // strip a trailing :digits port only
    if (colon >= 0 && colon < s.length - 1 && allAsciiDigits(s.substring(colon + 1))) {
      s = s.substring(0, colon);
    }
  }
  s = s.toLowerCase();
  if (s.length > 0) return s;
  const raw = csvTrim(url);
  return raw.length > 0 ? raw : "Imported login";
}

// ---- helpers ----

function getOr(arr: string[], idx: number): string {
  return idx >= 0 && idx < arr.length ? arr[idx]! : "";
}

function allAsciiDigits(s: string): boolean {
  if (s.length === 0) return true; // matches Kotlin `all {}` on an empty range
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

/** Mirror of Kotlin String.toLongOrNull (radix 10): optional sign, then decimal digits. */
function toLongOrNull(s: string): number | null {
  if (!/^[+-]?[0-9]+$/.test(s)) return null;
  return Number(s);
}

/**
 * Web-UI helper (NOT part of the twin surface — the vectors never see it): the 1-based
 * DATA-ROW ordinal for each data record's starting physical line, derived with the same
 * reader, so row errors can render "row N (file line M)" (A9) without the panel
 * re-implementing the quote-aware line accounting. Blank lines are excluded exactly like
 * parseCsvImport; record start lines are unique (every record ends by consuming its
 * newline), so the map is total over error lines.
 */
export function rowOrdinalsByLine(bytes: Uint8Array): Map<number, number> {
  const records = parseRecords(decodeCsvText(bytes));
  const out = new Map<number, number>();
  let ordinal = 0;
  for (const rec of records.slice(1)) {
    if (rec.fields.length === 1 && rec.fields[0] === "") continue;
    ordinal++;
    out.set(rec.line, ordinal);
  }
  return out;
}

/** RFC 4180 state machine (spec 06 §4.3) with the pinned lenient rules. */
interface RawRecord {
  fields: string[];
  line: number;
  badQuote: boolean;
}

/** Length of a newline at [i]: 2 (CRLF), 1 (lone CR / LF), 0 (none). */
function nl(text: string, i: number): number {
  const c = text.charAt(i);
  if (c === "\r") return i + 1 < text.length && text.charAt(i + 1) === "\n" ? 2 : 1;
  if (c === "\n") return 1;
  return 0;
}

function parseRecords(text: string): RawRecord[] {
  const out: RawRecord[] = [];
  let i = 0;
  const n = text.length;
  let line = 1;
  while (i < n) {
    const recLine = line;
    const fields: string[] = [];
    let f = "";
    let badQuote = false;
    let endOfRecord = false;
    while (!endOfRecord) {
      if (i >= n) {
        fields.push(f);
        endOfRecord = true;
        break;
      }
      const c = text.charAt(i);
      if (c === '"' && f.length === 0) {
        i++; // opening quote
        let closed = false;
        while (i < n) {
          const q = text.charAt(i);
          if (q === '"') {
            if (i + 1 < n && text.charAt(i + 1) === '"') {
              f += '"';
              i += 2;
            } else {
              i++;
              closed = true;
              break;
            }
          } else {
            const len = nl(text, i);
            if (len > 0) {
              f += "\n";
              line++;
              i += len;
            } else {
              f += q;
              i++;
            }
          }
        }
        if (!closed) badQuote = true; // EOF inside a quoted field
        if (closed) {
          // junk after a close quote before the next delimiter → bad_quote
          while (i < n && nl(text, i) === 0 && text.charAt(i) !== ",") {
            badQuote = true;
            i++;
          }
        }
        if (i < n && text.charAt(i) === ",") {
          fields.push(f);
          f = "";
          i++;
        } else {
          fields.push(f);
          f = "";
          const len = i < n ? nl(text, i) : 0;
          if (len > 0) {
            line++;
            i += len;
          }
          endOfRecord = true;
        }
      } else if (c === ",") {
        fields.push(f);
        f = "";
        i++;
      } else {
        const len = nl(text, i);
        if (len > 0) {
          fields.push(f);
          f = "";
          line++;
          i += len;
          endOfRecord = true;
        } else {
          f += c;
          i++;
        }
      }
    }
    out.push({ fields, line: recLine, badQuote });
  }
  return out;
}
