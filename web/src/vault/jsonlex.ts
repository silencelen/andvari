/**
 * A strict RFC 8259 JSON reader that keeps every number as the text it was written in, and a compact
 * writer for what it read.
 *
 * Why not JSON.parse: the account-state document's integer fields follow the grammar's `int` type, which
 * is a question about the TEXT (`7` is an int, `7.0` and `7e0` are not; spec 01 §5.1), and JSON.parse
 * answers 7 for all three. It would also round a large number in a field this build does not know, which
 * the document must keep "as written" (design §5.4 "Edges"). The core engine reads the same lexemes
 * (kotlinx JsonPrimitive.content), so both engines refuse and keep the same things.
 */
export type JValue =
  | { readonly t: "null" }
  | { readonly t: "bool"; readonly v: boolean }
  | { readonly t: "num"; readonly raw: string }
  | { readonly t: "str"; readonly v: string }
  | { readonly t: "arr"; readonly v: readonly JValue[] }
  | { readonly t: "obj"; readonly v: ReadonlyMap<string, JValue> };

/** Deeper nesting is refused rather than recursed into (the extras are never deep in a valid document). */
export const MAX_DEPTH = 64;

class Lexer {
  i = 0;
  constructor(readonly s: string) {}

  ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  value(depth: number): JValue {
    if (depth > MAX_DEPTH) throw new Error("depth");
    this.ws();
    const c = this.s[this.i];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return { t: "str", v: this.string() };
    if (this.s.startsWith("true", this.i)) return (this.i += 4), { t: "bool", v: true };
    if (this.s.startsWith("false", this.i)) return (this.i += 5), { t: "bool", v: false };
    if (this.s.startsWith("null", this.i)) return (this.i += 4), { t: "null" };
    return this.number();
  }

  object(depth: number): JValue {
    this.i++;
    const out = new Map<string, JValue>();
    this.ws();
    if (this.s[this.i] === "}") return this.i++, { t: "obj", v: out };
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') throw new Error("key");
      const k = this.string();
      this.ws();
      if (this.s[this.i++] !== ":") throw new Error("colon");
      // A repeated key keeps its last value, as the core engine's parser does.
      out.delete(k);
      out.set(k, this.value(depth + 1));
      this.ws();
      const c = this.s[this.i++];
      if (c === "}") return { t: "obj", v: out };
      if (c !== ",") throw new Error("object");
    }
  }

  array(depth: number): JValue {
    this.i++;
    const out: JValue[] = [];
    this.ws();
    if (this.s[this.i] === "]") return this.i++, { t: "arr", v: out };
    for (;;) {
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.i++];
      if (c === "]") return { t: "arr", v: out };
      if (c !== ",") throw new Error("array");
    }
  }

  string(): string {
    // Find the closing quote, then let JSON.parse decode the escapes of that one literal: it is strict about them.
    let j = this.i + 1;
    for (;;) {
      if (j >= this.s.length) throw new Error("string");
      const c = this.s.charCodeAt(j);
      if (c === 0x22) break;
      if (c < 0x20) throw new Error("control");
      j += c === 0x5c ? 2 : 1;
    }
    const lit = this.s.slice(this.i, j + 1);
    this.i = j + 1;
    return JSON.parse(lit) as string;
  }

  number(): JValue {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.s.slice(this.i, this.i + 400));
    if (!m || m[0].length === 0) throw new Error("token");
    this.i += m[0].length;
    return { t: "num", raw: m[0] };
  }
}

/** Parses [text] as one JSON value with nothing after it; null for anything RFC 8259 refuses. */
export function parseJValue(text: string): JValue | null {
  try {
    const lx = new Lexer(text);
    const v = lx.value(0);
    lx.ws();
    return lx.i === text.length ? v : null;
  } catch {
    return null;
  }
}

/** Compact JSON for [v]: no white space, object keys in the order held, numbers as written. */
export function writeJValue(v: JValue): string {
  switch (v.t) {
    case "null":
      return "null";
    case "bool":
      return v.v ? "true" : "false";
    case "num":
      return v.raw;
    case "str":
      return JSON.stringify(v.v);
    case "arr":
      return "[" + v.v.map(writeJValue).join(",") + "]";
    case "obj":
      return "{" + [...v.v].map(([k, x]) => JSON.stringify(k) + ":" + writeJValue(x)).join(",") + "}";
  }
}

/** The `int` type of the statement grammar, read off the lexeme: `0` or `[1-9][0-9]*`, below 2^53. */
export function intOf(v: JValue | undefined): number | null {
  if (!v || v.t !== "num") return null;
  const t = v.raw;
  if (t.length === 0 || t.length > 16 || !/^(0|[1-9][0-9]*)$/.test(t)) return null;
  const n = Number(t);
  return Number.isSafeInteger(n) ? n : null;
}

export function strOf(v: JValue | undefined): string | null {
  return v && v.t === "str" ? v.v : null;
}

export function boolOf(v: JValue | undefined): boolean | null {
  return v && v.t === "bool" ? v.v : null;
}

export function objOf(v: JValue | undefined): ReadonlyMap<string, JValue> | null {
  return v && v.t === "obj" ? v.v : null;
}

/** A JValue as the plain JS value JSON.parse would give (numbers rounded as JSON.parse rounds them). For tests and display only. */
export function plainOf(v: JValue): unknown {
  switch (v.t) {
    case "null":
      return null;
    case "bool":
    case "str":
      return v.v;
    case "num":
      return Number(v.raw);
    case "arr":
      return v.v.map(plainOf);
    case "obj":
      return Object.fromEntries([...v.v].map(([k, x]) => [k, plainOf(x)]));
  }
}
