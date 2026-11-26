import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64, toHexLower } from "../bytes";
import { boxKeypairFromSeed, ed25519PkToCurve25519, signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { verdictOf } from "./checked";
import { encodeStatement, parseFrame, parseHostOffer, parseStatement, secretOf } from "./codec";
import {
  DOMAIN, frameHash, MAGIC, MAX_FRAME_BYTES, MAX_STATEMENT_BYTES, MIN_STATEMENT_BYTES, type Purpose, PURPOSE_CODES, purposeOfCode,
  signatureValid, signedMessage, signerIs, signerMapsTo, signFrame, splitFrame, STATEMENT_OFFSET,
} from "./frame";
import { expectSections, gradeEvery, vector } from "./vectors";

/**
 * The frame and the canonical statement grammar of design 2026-11-15 §2.1, §2.2 and §2.4, graded off
 * the SAME `statement-v2.json` core's `StatementV2VectorTest` consumes. The bytes come from the
 * independent oracle, so these pin "correct", not "the engines agree".
 */
const v = vector("statement-v2.json");

beforeAll(async () => {
  await initSodium();
});

const fieldsOf = (fields: Record<string, string | number>): Record<string, string> =>
  Object.fromEntries(Object.entries(fields).map(([k, x]) => [k, String(x)]));

/** The fields that carry a key: the codec takes them as bytes, never as text. */
const SECRET_FIELDS = ["vk", "uvk"];

describe("statement-v2.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, [
      "_about", "domainAscii", "magicHex", "purposeCodes", "statementBytes", "frameBytes", "keys", "templates", "valid", "grammar", "parse", "frames",
      "binding",
    ]);
  });

  it("constants match the file", () => {
    expect(DOMAIN).toBe(v.domainAscii);
    expect(toHexLower(MAGIC)).toBe(v.magicHex);
    expect(PURPOSE_CODES).toEqual(v.purposeCodes);
    expect([MIN_STATEMENT_BYTES, MAX_STATEMENT_BYTES]).toEqual([v.statementBytes.min, v.statementBytes.max]);
    expect([STATEMENT_OFFSET + MIN_STATEMENT_BYTES, MAX_FRAME_BYTES]).toEqual([v.frameBytes.min, v.frameBytes.max]);
  });

  it("the cast's joint keys and recovery keys derive as the file says", () => {
    for (const [name, k] of Object.entries<Record<string, string>>(v.keys)) {
      const seed = fromB64(k.seedB64!);
      const sign = signKeypairFromSeed(seed);
      const box = boxKeypairFromSeed(seed);
      expect(toB64(sign.publicKey), name).toBe(k.signPubB64);
      expect(toB64(box.publicKey), name).toBe(k.identityPubB64 ?? k.publicKeyB64);
      expect(toB64(ed25519PkToCurve25519(sign.publicKey)), name).toBe(toB64(box.publicKey));
    }
  });

  it("valid: every template encodes, signs, hashes and binds", () => {
    const seen = new Set<number>();
    gradeEvery("statement-v2.valid", v.valid, (r: any) => {
      const purpose = purposeOfCode(r.purposeCode)!;
      seen.add(r.purposeCode);
      expect(purpose, r.name).toBe(r.purpose);
      // A key (a grant's `vk`, an assisted recovery's `uvk`) is handed to the codec as bytes and read back as bytes.
      const all = fieldsOf(r.fields);
      const fields = Object.fromEntries(Object.entries(all).filter(([k]) => !SECRET_FIELDS.includes(k)));
      const secrets = Object.fromEntries(Object.entries(all).filter(([k]) => SECRET_FIELDS.includes(k)).map(([k, x]) => [k, fromB64(x)]));

      const statement = encodeStatement(purpose, fields, secrets);
      expect(new TextDecoder().decode(statement), `${r.name}: canonical statement`).toBe(r.statementUtf8);
      const parsed = parseStatement(purpose, statement);
      expect(parsed.ok, r.name).toBe(true);
      if (parsed.ok) {
        for (const [k, x] of Object.entries(fields)) expect(parsed.value[k], `${r.name}: field ${k}`).toBe(x);
        for (const k of Object.keys(secrets)) expect(k in parsed.value, `${r.name}: ${k} is not among the plain values`).toBe(false);
      }

      const signer = signKeypairFromSeed(fromB64(v.keys[r.signer].seedB64));
      expect(toB64(signer.publicKey), `${r.name}: signer key`).toBe(r.signerPubB64);
      expect(toHexLower(signedMessage(r.purposeCode, signer.publicKey, statement)), `${r.name}: M`).toBe(r.messageHex);
      const frame = signFrame(signer, purpose, statement);
      expect(toB64(frame), `${r.name}: frame bytes`).toBe(r.frameB64);
      expect(frameHash(frame), `${r.name}: H(frame)`).toBe(r.frameHash);

      const whole = parseFrame(frame, purpose);
      expect(whole.ok, r.name).toBe(true);
      if (!whole.ok) return;
      for (const [k, key] of Object.entries(secrets)) expect(secretOf(whole.value, k), `${r.name}: ${k}`).toEqual(key);
      expect(toB64(whole.value.parts.signature), `${r.name}: signature`).toBe(r.signatureB64);
      expect(signatureValid(whole.value.parts), r.name).toBe(true);
      for (const key of r.expectedKeys) {
        const bytes = fromB64(key.keyB64);
        if (key.form === "x25519") expect(signerMapsTo(whole.value.parts, bytes), `${r.name}: X25519 binding`).toBe(true);
        else expect(signerIs(whole.value.parts, bytes), `${r.name}: Ed25519 binding`).toBe(true);
      }
    });
    expect([...seen].sort((a, b) => a - b)).toEqual([3, 4, 5, 6, 7, 8, 9, 10]);
  });

  it("templates: each is exercised by statements this parser accepts, with exactly its keys in order", () => {
    // `templates` describes each template's keys and types; the valid, grammar and parse rows grade them.
    // Here every template must be met by at least one accepted statement whose keys are the template's.
    const accepted: { name: string; statement: Uint8Array; purposeCode: number | null }[] = [
      ...v.valid.map((r: any) => ({ name: r.name, statement: new TextEncoder().encode(r.statementUtf8), purposeCode: r.purposeCode })),
      ...[...v.grammar, ...v.parse].filter((r: any) => r.verdict === "ok")
        .map((r: any) => ({ name: r.why, statement: fromB64(r.statementB64), purposeCode: r.purposeCode })),
    ];
    const met = new Map<string, number>();
    for (const s of accepted) {
      const obj = JSON.parse(new TextDecoder().decode(s.statement)) as Record<string, unknown>;
      const name = obj.purpose === "vault-log" ? `vault-log/${String(obj.kind)}` : String(obj.purpose);
      met.set(name, (met.get(name) ?? 0) + 1);
    }
    gradeEvery("statement-v2.templates", Object.entries<[string, string][]>(v.templates), ([name, keys]) => {
      expect(met.get(name) ?? 0, `${name}: an accepted statement of this template`).toBeGreaterThan(0);
      for (const s of accepted) {
        const text = new TextDecoder().decode(s.statement);
        const obj = JSON.parse(text) as Record<string, unknown>;
        const of = obj.purpose === "vault-log" ? `vault-log/${String(obj.kind)}` : String(obj.purpose);
        if (of !== name) continue;
        expect(Object.keys(obj), `${name}: ${s.name}`).toEqual(keys.map(([k]) => k));
        const parsed = s.purposeCode === null ? parseHostOffer(s.statement) : parseStatement(purposeOfCode(s.purposeCode)!, s.statement);
        expect(verdictOf(parsed), `${name}: ${s.name}`).toBe("ok");
      }
    });
    expect([...met.keys()].filter((name) => !(name in v.templates)), "statements of no listed template").toEqual([]);
  });

  it("grammar and parse: every row gets its exact verdict", () => {
    const grade = (r: any) => {
      const statement = fromB64(r.statementB64);
      // Rows with no purpose code are the host-minted offers of §6.4, which have no frame.
      const got = r.purposeCode === null ? parseHostOffer(statement) : parseStatement(purposeOfCode(r.purposeCode)!, statement);
      expect(verdictOf(got), `${r.template}: ${r.why}`).toBe(r.verdict);
    };
    gradeEvery("statement-v2.grammar", v.grammar, grade);
    gradeEvery("statement-v2.parse", v.parse, grade);
  });

  it("frames: the whole parse, in order", () => {
    gradeEvery("statement-v2.frames", v.frames, (r: any) => {
      expect(verdictOf(parseFrame(fromB64(r.frameB64), purposeOfCode(r.expectedPurposeCode)!)), r.why).toBe(r.verdict);
    });
  });

  it("binding: the two forms and the signature", () => {
    gradeEvery("statement-v2.binding", v.binding, (r: any) => {
      const split = splitFrame(fromB64(r.frameB64));
      expect(split.ok, r.why).toBe(true);
      if (!split.ok) return;
      expect(PURPOSE_CODES[split.value.purpose], r.why).toBe(r.purposeCode);
      const key = fromB64(r.expectedKeyB64);
      const binds = r.form === "x25519" ? signerMapsTo(split.value, key) : signerIs(split.value, key);
      expect(binds, `binds: ${r.why}`).toBe(r.signerBinds);
      expect(signatureValid(split.value), `signature: ${r.why}`).toBe(r.signatureValid);
    });
  });

  it("encode refuses what the parse would refuse", () => {
    const genesis = fieldsOf(v.valid.find((r: { name: string }) => r.name === "vault-log/genesis").fields);
    const bad = (change: Record<string, string>, purpose: Purpose = "vault-log") => () => encodeStatement(purpose, { ...genesis, ...change });
    expect(bad({ vaultId: genesis.vaultId!.toUpperCase() })).toThrow();
    expect(bad({ seq: "1" })).toThrow(); // a genesis sits at seq 0
    expect(bad({ at: "0" })).toThrow();
    expect(bad({ member: genesis.actor! })).toThrow(); // not a field of this template
    expect(bad({ actor: 'x","at":1,"z":"' })).toThrow();
    expect(bad({ kind: "nonsense" })).toThrow();
    expect(bad({ kind: "__proto__" })).toThrow();
    expect(bad({}, "escrow-uvk")).toThrow();
    const { ownerKey: _dropped, ...withoutKey } = genesis;
    expect(() => encodeStatement("vault-log", withoutKey)).toThrow();
  });
});
