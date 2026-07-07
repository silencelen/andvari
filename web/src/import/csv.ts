import type { ItemDoc } from "../api/types";

/**
 * Browser-CSV import (spec 06) — 100% client-side, pure (no DOM, no crypto). The TS
 * twin of core/.../client/CsvImport.kt (the Kotlin REFERENCE that emits import.json).
 * Both MUST parse identically — web/src/import/csv.test.ts and the Kotlin
 * ImportVectorsTest consume the SAME spec/test-vectors/import.json. Chrome/Edge + Firefox.
 */

export const MAX_BYTES = 10 * 1024 * 1024;
export const MAX_ROWS = 10_000;

export type ImportFormat = "chrome" | "firefox";

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
  name: string;
  url: string;
  username: string;
  password: string;
  notes: string;
  timePasswordChangedMs: number | null;
  totp: string | null;
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
}

export interface ImportReport {
  imported: number;
  skippedEmpty: number;
  collapsed: number;
  flagged: string[];
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

export function parseCsvImport(bytes: Uint8Array): Parsed {
  if (bytes.length > MAX_BYTES) throw new ImportError("too_large");
  // Lenient UTF-8 (invalid → U+FFFD). ignoreBOM keeps the BOM in the string, exactly
  // like Kotlin decodeToString(), so we then strip precisely ONE below.
  let text = new TextDecoder("utf-8", { ignoreBOM: true, fatal: false }).decode(bytes);
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) text = text.slice(1); // strip one BOM

  const records = parseRecords(text);
  if (records.length === 0) throw new ImportError("unrecognized_header");
  const header = records[0]!.fields.map((s) => s.trim().toLowerCase());
  const format = detectFormat(header);
  if (!format) throw new ImportError("unrecognized_header");

  // Drop blank lines (a record that is a single empty field).
  const dataRecords = records.slice(1).filter((r) => !(r.fields.length === 1 && r.fields[0] === ""));
  if (dataRecords.length > MAX_ROWS) throw new ImportError("too_many_rows");

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
  for (const rec of dataRecords) {
    if (rec.badQuote) {
      errors.push({ line: rec.line, code: "bad_quote" });
      continue;
    }
    if (rec.fields.length !== header.length) {
      errors.push({ line: rec.line, code: "wrong_field_count" });
      continue;
    }
    const f = rec.fields;
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
    const pwChanged = iPwChanged >= 0 ? toLongOrNull(getOr(f, iPwChanged).trim()) : null;
    const totp = iTotp >= 0 ? getOr(f, iTotp).trim() || null : null;
    rows.push({ name, url, username, password, notes, timePasswordChangedMs: pwChanged, totp });
  }
  return { format, rows, errors };
}

function detectFormat(header: string[]): ImportFormat | null {
  const h = new Set(header);
  if (["name", "url", "username", "password"].every((k) => h.has(k))) return "chrome";
  if (
    ["url", "username", "password"].every((k) => h.has(k)) &&
    ["guid", "httprealm", "formactionorigin"].some((k) => h.has(k))
  ) {
    return "firefox";
  }
  return null;
}

// ---- plan (skip / dedupe / rename) ----

export function planImport(parsed: Parsed, newId: () => string): ImportPlan {
  let skippedEmpty = 0;
  let collapsed = 0;
  const flagged: string[] = [];
  const exactSeen = new Set<string>(); // url user pass totp — totp included so a row that differs
  //                                       ONLY by its TOTP seed is not dropped as an exact dup
  const groupCount = new Map<string, number>(); // url user → count so far (distinct passwords)
  const items: PlannedItem[] = [];
  for (const row of parsed.rows) {
    if (row.username.length === 0 && row.password.length === 0) {
      skippedEmpty++;
      continue;
    }
    const exact = `${row.url} ${row.username} ${row.password} ${row.totp ?? ""}`;
    if (exactSeen.has(exact)) {
      collapsed++;
      continue;
    } // exact repeat dropped
    exactSeen.add(exact);
    const key = `${row.url} ${row.username}`;
    const k = (groupCount.get(key) ?? 0) + 1;
    groupCount.set(key, k);
    const name = k >= 2 ? `${row.name} (${k})` : row.name;
    if (k >= 2) flagged.push(name);
    const doc: ItemDoc = {
      type: "login",
      name,
      notes: row.notes.length > 0 ? row.notes : undefined,
      login: {
        username: row.username,
        password: row.password,
        uris: row.url.length > 0 ? [row.url] : [],
        ...(row.totp ? { totp: row.totp } : {}),
      },
    };
    items.push({ itemId: newId(), doc });
  }
  return {
    items,
    report: { imported: items.length, skippedEmpty, collapsed, flagged, errors: parsed.errors },
  };
}

/** spec 06 §4.7 — pinned host extraction (no URL library). */
export function nameFallback(url: string): string {
  let s = url.trim();
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
  const raw = url.trim();
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
