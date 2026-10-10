/**
 * The shape check every client applies to a decrypted document BEFORE using it (spec 02 §3.2,
 * security review 2026-10) — a verbatim port of web/src/vault/itemdoc-shape.ts (twin of core
 * `ItemDocShape.kt`); all three are graded by `spec/test-vectors/itemdoc-validate.json`. A document
 * that opens under a vault key was still WRITTEN by whoever holds that key — any writer of a shared
 * vault — and a `{"name": null}` or bare `null` doc used to throw in byName() on every
 * status/matches/allItems dispatch. background.ts decryptItems skips a failing doc exactly as it
 * skips an undecryptable one. Unknown keys are never inspected (spec 02 §3).
 */

/** A path segment every client may put into an authenticated URL (web api/client.ts pathSeg). */
export const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isInt = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v);

/** An optional string field: absent and JSON null are fine, anything but a string is not. */
const optStr = (o: Obj, k: string): string | null => (k in o && o[k] !== null && !isStr(o[k]) ? k : null);

function loginProblem(v: unknown): string | null {
  if (!isObj(v)) return "not an object";
  for (const k of ["username", "password", "totp"]) {
    const p = optStr(v, k);
    if (p) return p;
  }
  if ("uris" in v && !(Array.isArray(v.uris) && v.uris.every(isStr))) return "uris";
  if ("passwordHistory" in v) {
    if (!Array.isArray(v.passwordHistory)) return "passwordHistory";
    for (const e of v.passwordHistory) {
      if (!isObj(e) || !isStr(e.password) || !isInt(e.retiredAt)) return "passwordHistory";
    }
  }
  return null;
}

function cardProblem(v: unknown): string | null {
  if (!isObj(v)) return "not an object";
  for (const k of ["cardholderName", "number", "expMonth", "expYear", "securityCode", "brand", "postalCode"]) {
    const p = optStr(v, k);
    if (p) return p;
  }
  return null;
}

function checkProblem(v: unknown): string | null {
  if (!isObj(v)) return "not an object";
  if (!isInt(v.at)) return "at";
  if (!isStr(v.result)) return "result";
  for (const k of ["okAt", "until"]) if (k in v && v[k] !== null && !isInt(v[k])) return k;
  return null;
}

function attachmentProblem(v: unknown): string | null {
  if (!isObj(v)) return "not an object";
  if (!isStr(v.id) || !SAFE_ID.test(v.id)) return "id";
  if (!isStr(v.name)) return "name";
  if (!isStr(v.fileKey)) return "fileKey";
  if (!isInt(v.size) || v.size < 0) return "size";
  return null;
}

/** Null when `doc` is a well-formed item document; otherwise the first problem found. */
export function itemDocProblem(doc: unknown): string | null {
  if (!isObj(doc)) return "doc is not an object";
  if (!isStr(doc.type)) return "type";
  if (!isStr(doc.name)) return "name";
  const notes = optStr(doc, "notes");
  if (notes) return notes;
  if ("favorite" in doc && typeof doc.favorite !== "boolean") return "favorite";
  const ack = optStr(doc, "dupeAck");
  if (ack) return ack;
  for (const [k, check] of [
    ["login", loginProblem],
    ["card", cardProblem],
    ["check", checkProblem],
  ] as const) {
    if (k in doc && doc[k] !== null) {
      const p = check(doc[k]);
      if (p) return `${k}.${p}`;
    }
  }
  if ("attachments" in doc) {
    if (!Array.isArray(doc.attachments)) return "attachments";
    for (let i = 0; i < doc.attachments.length; i++) {
      const p = attachmentProblem(doc.attachments[i]);
      if (p) return `attachments[${i}].${p}`;
    }
  }
  return null;
}
