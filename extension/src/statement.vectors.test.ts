// The extension's strict statement parser (statement.ts), graded by the shared vectors (design
// 2026-11-15-onboarding-trust §12.2 rule 5, §17): the rows of statement-v2.json whose purposeCode is 4 or 5,
// in every section, and the `origin` and `name` rows of encodings.json. A section or a row this suite should
// grade that goes ungraded fails it: each section's graded count is asserted against the file's own count.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import nacl from "tweetnacl";
import { boxKeypairFromSeed } from "./crypto.ts";
import {
  b64Strict,
  frameHash,
  isFlatStatement,
  isOrigin,
  nameText,
  parseFrame,
  parseStatement,
  PURPOSE_CODES,
  signatureValid,
  signedMessage,
  signerIs,
  type ExtPurpose,
} from "./statement.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const load = (name: string) => JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
const sv = load("statement-v2.json");
const enc = load("encodings.json");

const b64 = (s: string): Uint8Array => {
  const out = b64Strict(s);
  assert.ok(out !== null, `vector base64url decodes: ${s.slice(0, 20)}`);
  return out;
};
const hex = (u: Uint8Array): string => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
const PURPOSE_OF: Record<number, ExtPurpose> = { 4: "instance-card", 5: "account-genesis" };
const ours = (code: unknown): code is 4 | 5 => code === 4 || code === 5;

/** The extension binds a key in its X25519 form only through the seed it was derived from (it has no
 *  Montgomery map): the cast account whose identity key is `x25519B64`, its own Ed25519 key from tweetnacl. */
function boundThroughSeed(signerPub: Uint8Array, x25519B64: string): boolean {
  const cast = Object.values(sv.keys as Record<string, { seedB64?: string; identityPubB64?: string }>).find((k) => k.identityPubB64 === x25519B64);
  assert.ok(cast?.seedB64, `an X25519 key the vectors cast: ${x25519B64}`);
  const seed = b64(cast.seedB64);
  assert.equal(hex(boxKeypairFromSeed(seed).publicKey), hex(b64(x25519B64)), "the seed yields that X25519 key");
  return signerIs(signerPub, nacl.sign.keyPair.fromSeed(seed).publicKey);
}

test("statement-v2.json: the purpose table and frame bounds the parser uses", () => {
  for (const [name, code] of Object.entries(sv.purposeCodes as Record<string, number>)) assert.equal(PURPOSE_CODES[name], code, name);
  assert.equal(sv.domainAscii, "andvari/v2|signed-statement");
  assert.equal(sv.magicHex, "61767302");
  assert.deepEqual(sv.statementBytes, { min: 2, max: 1024 });
  assert.deepEqual(sv.frameBytes, { min: 103, max: 1125 });
  assert.match(sv._about.join(" "), /The extension grades the rows whose purposeCode is 4 or 5/);
});

test("statement-v2.json valid: every 0x04 and 0x05 frame parses, hashes, binds and verifies", () => {
  const rows = sv.valid.filter((r: { purposeCode: number }) => ours(r.purposeCode));
  assert.equal(rows.length, 4, "three cards and one genesis");
  for (const r of rows) {
    const frame = b64(r.frameB64);
    const parsed = parseFrame(frame, PURPOSE_OF[r.purposeCode]!);
    assert.ok(parsed.ok, r.name);
    assert.equal(new TextDecoder().decode(parsed.value.statement), r.statementUtf8, r.name);
    assert.equal(frameHash(frame), r.frameHash, r.name);
    assert.equal(hex(signedMessage(r.purposeCode, parsed.value.signerPub, parsed.value.statement)), r.messageHex, r.name);
    assert.ok(signatureValid(r.purposeCode, parsed.value.signerPub, parsed.value.signature, parsed.value.statement), r.name);
    for (const k of r.expectedKeys) {
      const binds = k.form === "ed25519" ? signerIs(parsed.value.signerPub, b64(k.keyB64)) : boundThroughSeed(parsed.value.signerPub, k.keyB64);
      assert.ok(binds, `${r.name}: ${k.form}`);
    }
  }
});

test("statement-v2.json grammar: every row of an instance-card or account-genesis template", () => {
  const rows = sv.grammar.filter((r: { purposeCode: number | null }) => ours(r.purposeCode));
  assert.ok(rows.length >= 150, `grammar rows for 0x04/0x05: ${rows.length}`);
  let graded = 0;
  for (const r of rows) {
    const got = parseStatement(PURPOSE_OF[r.purposeCode]!, b64(r.statementB64));
    assert.equal(got.ok ? "ok" : got.verdict, r.verdict, `${r.template} ${r.field}=${r.token}: ${r.why}`);
    assert.equal(r.verdict === "ok", r.valid, `the row's own valid flag agrees: ${r.why}`);
    graded++;
  }
  assert.equal(graded, rows.length);
});

test("statement-v2.json parse: every 0x04 and 0x05 row", () => {
  const rows = sv.parse.filter((r: { purposeCode: number | null }) => ours(r.purposeCode));
  assert.ok(rows.length >= 50, `parse rows for 0x04/0x05: ${rows.length}`);
  for (const r of rows) {
    const got = parseStatement(PURPOSE_OF[r.purposeCode]!, b64(r.statementB64));
    assert.equal(got.ok ? "ok" : got.verdict, r.verdict, `${r.template}: ${r.why}`);
  }
});

test("statement-v2.json frames: every row read by the 0x04 or 0x05 helper, in §2.4's order", () => {
  const rows = sv.frames.filter((r: { expectedPurposeCode: number }) => ours(r.expectedPurposeCode));
  assert.ok(rows.length >= 30, `frame rows for 0x04/0x05: ${rows.length}`);
  for (const r of rows) {
    // The vectors' own frames: decode with the lenient decoder, since a frame row may be any bytes at all.
    const frame = Uint8Array.from(atob(r.frameB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const got = parseFrame(frame, PURPOSE_OF[r.expectedPurposeCode]!);
    assert.equal(got.ok ? "ok" : got.verdict, r.verdict, r.why);
  }
});

test("statement-v2.json binding: both predicates for every 0x04 and 0x05 row", () => {
  const rows = sv.binding.filter((r: { purposeCode: number }) => ours(r.purposeCode));
  assert.equal(rows.length, 8);
  for (const r of rows) {
    const frame = b64(r.frameB64);
    const signerPub = frame.slice(5, 37);
    const signature = frame.slice(37, 101);
    const statement = frame.slice(101);
    const binds = r.form === "ed25519" ? signerIs(signerPub, b64(r.expectedKeyB64)) : boundThroughSeed(signerPub, r.expectedKeyB64);
    assert.equal(binds, r.signerBinds, `signerBinds: ${r.why}`);
    assert.equal(signatureValid(frame[4]!, signerPub, signature, statement), r.signatureValid, `signatureValid: ${r.why}`);
  }
});

test("§2.2 no nesting (statement-v2.json parse 104–109, frames[45]): refused on the bytes, before any JSON parser sees the text", () => {
  const nested = sv.parse.filter((r: { purposeCode: number | null; why: string }) => ours(r.purposeCode) && r.why.startsWith("no nesting"));
  const frames = sv.frames.filter((r: { expectedPurposeCode: number; why: string }) => ours(r.expectedPurposeCode) && /no nesting/.test(r.why));
  assert.ok(nested.length >= 5 && frames.length >= 1, `nested rows: ${nested.length} parse, ${frames.length} frames`);
  const realParse = JSON.parse;
  let calls = 0;
  JSON.parse = ((text: string, reviver?: (this: unknown, key: string, value: unknown) => unknown) => {
    calls++;
    return realParse(text, reviver);
  }) as typeof JSON.parse;
  try {
    for (const r of nested) {
      const got = parseStatement(PURPOSE_OF[r.purposeCode]!, b64(r.statementB64));
      assert.equal(got.ok ? "ok" : got.verdict, "non_canonical", r.why);
    }
    for (const r of frames) {
      const frame = Uint8Array.from(atob(r.frameB64.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      const got = parseFrame(frame, PURPOSE_OF[r.expectedPurposeCode]!);
      assert.equal(got.ok ? "ok" : got.verdict, "non_canonical", r.why);
    }
  } finally {
    JSON.parse = realParse;
  }
  assert.equal(calls, 0, "JSON.parse never saw a nested statement");
  // The byte rule itself (core isFlatStatement's twin): one `{`, no `[`; nothing canonical contains either.
  const u = (s: string) => new TextEncoder().encode(s);
  assert.equal(isFlatStatement(u('{"a":"b"}')), true);
  assert.equal(isFlatStatement(u('{"a":[]}')), false);
  assert.equal(isFlatStatement(u('{"a":{}}')), false);
  assert.equal(isFlatStatement(u("[")), false);
});

test("statement-v2.json: no 0x04 or 0x05 section is left out of this suite", () => {
  const sections = ["valid", "grammar", "parse", "frames", "binding"];
  for (const k of Object.keys(sv)) {
    if (!Array.isArray(sv[k]) || k === "_about") continue;
    const rows = sv[k] as { purposeCode?: number | null; expectedPurposeCode?: number }[];
    if (rows.some((r) => ours(r.purposeCode ?? r.expectedPurposeCode))) assert.ok(sections.includes(k), `section ${k} holds 0x04/0x05 rows this suite does not grade`);
  }
});

test("encodings.json origin: every row, through the extension's one origin grammar", () => {
  assert.ok(enc.origin.length >= 90, `origin rows: ${enc.origin.length}`);
  for (const r of enc.origin) assert.equal(isOrigin(r.origin), r.valid, `${r.origin}: ${r.why}`);
});

test("encodings.json name: every row (the card's name is a parsed field)", () => {
  assert.ok(enc.name.length >= 70, `name rows: ${enc.name.length}`);
  for (const r of enc.name) {
    const text = nameText(r.name);
    assert.equal(text !== null, r.valid, `${r.name}: ${r.why}`);
    if (text !== null) assert.equal(hex(new TextEncoder().encode(text)), r.textHex, r.why);
  }
});
