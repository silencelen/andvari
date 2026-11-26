import { isB64_16, isB64_32, isHex64, isInt, isMs, isPlatform } from "../crypto/trust/grammar";
import { isNilUserId, UUID_RE, type Refusal } from "./wireids";

/**
 * Response decoding at the wire boundary (spec 03 §0.1). A served body is checked field by field before
 * any caller sees it: a known field of the wrong type refuses the whole response (`bad_response`), and a
 * field the client does not know is ignored, as §0.1 requires. List rows whose id is malformed are
 * dropped and reported instead (the A10 rule of wireids.ts), so one bad row never hides the rest.
 *
 * Nothing here trusts a value: a decoded field is only well-formed. Whether it may become a pin, a key,
 * an owner or "accepted" is decided by the check the design names, elsewhere.
 */
export class WireShapeError extends Error {
  constructor(readonly endpoint: string, readonly field: string) {
    super(`the server's answer to ${endpoint} has a malformed ${field}`);
    this.name = "WireShapeError";
  }
}

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
export type JsonObject = { [k: string]: Json };

/** One decode pass over one response: knows the endpoint for its errors and collects dropped rows. */
export class Reader {
  readonly refused: Refusal[] = [];
  constructor(readonly endpoint: string) {}

  fail(field: string): never {
    throw new WireShapeError(this.endpoint, field);
  }

  obj(v: unknown, field: string): JsonObject {
    if (v === null || typeof v !== "object" || Array.isArray(v)) this.fail(field);
    return v as JsonObject;
  }

  arr(v: unknown, field: string): Json[] {
    if (!Array.isArray(v)) this.fail(field);
    return v as Json[];
  }

  str(v: unknown, field: string): string {
    if (typeof v !== "string") this.fail(field);
    return v;
  }

  optStr(v: unknown, field: string): string | null {
    return v === undefined || v === null ? null : this.str(v, field);
  }

  bool(v: unknown, field: string): boolean {
    if (typeof v !== "boolean") this.fail(field);
    return v;
  }

  /** A 64-bit integer field (spec 03 §0.1 numeric widths), as far as a JS number can carry it exactly. */
  int(v: unknown, field: string): number {
    if (typeof v !== "number" || !isInt(v)) this.fail(field);
    return v;
  }

  optInt(v: unknown, field: string): number | null {
    return v === undefined || v === null ? null : this.int(v, field);
  }

  ms(v: unknown, field: string): number {
    if (typeof v !== "number" || !isMs(v)) this.fail(field);
    return v;
  }

  uuid(v: unknown, field: string): string {
    if (typeof v !== "string" || !UUID_RE.test(v)) this.fail(field);
    return v;
  }

  /** A user id: a UUID that is not the all-zero id, which is never an account (core `UserIds.isNil`). */
  userId(v: unknown, field: string): string {
    const s = this.uuid(v, field);
    if (isNilUserId(s)) this.fail(field);
    return s;
  }

  hex64(v: unknown, field: string): string {
    if (typeof v !== "string" || !isHex64(v)) this.fail(field);
    return v;
  }

  b64_16(v: unknown, field: string): string {
    if (typeof v !== "string" || !isB64_16(v)) this.fail(field);
    return v;
  }

  b64_32(v: unknown, field: string): string {
    if (typeof v !== "string" || !isB64_32(v)) this.fail(field);
    return v;
  }

  /** Unpadded base64url text (the `b64`, `frame`, `envelope` and `sealed` types), bounded by [max] characters. */
  b64(v: unknown, field: string, max = 4 * 1024 * 1024): string {
    if (typeof v !== "string" || v.length === 0 || v.length > max || !/^[A-Za-z0-9_-]+$/.test(v)) this.fail(field);
    return v;
  }

  platform(v: unknown, field: string): string {
    if (typeof v !== "string" || !isPlatform(v)) this.fail(field);
    return v;
  }

  oneOf<T extends string>(v: unknown, field: string, values: readonly T[]): T {
    if (typeof v !== "string" || !(values as readonly string[]).includes(v)) this.fail(field);
    return v as T;
  }

  /**
   * The rows of a list, each decoded by [row]. A row whose id is malformed is dropped and reported
   * ([idField] names it); a row malformed in any other way refuses the response.
   */
  rows<T>(v: unknown, field: string, idFields: readonly string[], row: (o: JsonObject, i: number) => T): T[] {
    const out: T[] = [];
    this.arr(v, field).forEach((raw, i) => {
      const o = this.obj(raw, `${field}[${i}]`);
      const bad = idFields.filter((k) => o[k] !== undefined && o[k] !== null && !(typeof o[k] === "string" && UUID_RE.test(o[k] as string)));
      if (bad.length > 0) {
        for (const k of bad) this.refused.push({ field: `${field}.${k}`, value: String(o[k]) });
        return;
      }
      out.push(row(o, i));
    });
    return out;
  }
}

/** Parses a JSON text into a value; a body that is not JSON is a malformed answer. */
export function parseJson(endpoint: string, text: string): Json {
  try {
    return JSON.parse(text) as Json;
  } catch {
    throw new WireShapeError(endpoint, "body");
  }
}
