import { beforeAll, describe, expect, it, vi } from "vitest";
import { concat, utf8 } from "../bytes";
import { openCanary, openEscrow, UNANCHORED_ACK } from "../escrow";
import { boxKeypairFromSeed, sealTo } from "../provider";
import { parseStatement as parseSpec01Statement, SignedStatementError } from "../signedstatement";
import { CryptoError, initSodium } from "../sodium";
import { verdictOf } from "./checked";
import { parseFrame, parseHostOffer, parseStatement, withinJsonDepth } from "./codec";
import { MAGIC, MAX_STATEMENT_BYTES, PURPOSE_CODES, PURPOSES } from "./frame";
import { parseCard } from "./instancecard";
import { NONE_HELD, verifyLogEntry } from "./vaultlog";
import { vector } from "./vectors";

/**
 * Design 2026-11-15 §2.2: "a statement is one flat object, so a `[` anywhere, or a second `{`, is
 * `non_canonical`, and an implementation refuses it BEFORE handing the text to any general JSON parser".
 * A parser that recurses once per level can be made to overflow its stack by a thousand brackets, and
 * on some targets that is a crash, not a verdict.
 *
 * These tests feed every reader of untrusted text in `web/src/crypto` its deepest input and watch
 * `JSON.parse`: for a framed statement it must never be called at all, and where a reader does use it
 * (the host offer, the two v1 payloads) the answer must be a refusal, never a thrown `RangeError`.
 */
const VAULT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const brackets = (n: number): Uint8Array => new Uint8Array(n).fill(0x5b);
const frameOf = (purposeCode: number, statement: Uint8Array): Uint8Array =>
  concat(MAGIC, Uint8Array.of(purposeCode), new Uint8Array(32), new Uint8Array(64), statement);

/** Runs `body` with `JSON.parse` watched, and returns how often it was called. */
function parserCalls(body: () => void): number {
  const spy = vi.spyOn(JSON, "parse");
  try {
    body();
    return spy.mock.calls.length;
  } finally {
    spy.mockRestore();
  }
}

beforeAll(async () => {
  await initSodium();
});

describe("nesting never reaches a JSON parser", () => {
  it("a statement of 1,024 brackets is non_canonical under every purpose, with no parser called", () => {
    const deepest = brackets(MAX_STATEMENT_BYTES);
    const calls = parserCalls(() => {
      for (const purpose of PURPOSES) {
        // 0x02 has no template in this directory: escrow.ts verifies those, and the frame is refused first.
        const expected = purpose === "escrow-uvk" ? "bad_frame" : "non_canonical";
        expect(verdictOf(parseStatement(purpose, deepest)), purpose).toBe(expected);
        expect(verdictOf(parseFrame(frameOf(PURPOSE_CODES[purpose], deepest), purpose)), purpose).toBe(expected);
      }
      expect(verdictOf(verifyLogEntry(VAULT, null, frameOf(0x03, deepest), NONE_HELD))).toBe("non_canonical");
      expect(verdictOf(parseCard(frameOf(0x04, deepest)))).toBe("non_canonical");
    });
    expect(calls).toBe(0);
  });

  it("a `[` anywhere, or a second `{`, is non_canonical: inside a value, as a value, and as nested objects", () => {
    const valid: { purpose: (typeof PURPOSES)[number]; statementUtf8: string }[] = vector("statement-v2.json").valid;
    const calls = parserCalls(() => {
      for (const row of valid) {
        const text = row.statementUtf8;
        expect(verdictOf(parseStatement(row.purpose, utf8(text))), row.purpose).toBe("ok");
        const firstValue = text.indexOf(":") + 1; // `{"v":` and then the 2
        const variants = [
          text.replace('"purpose":"', '"purpose":"['), // inside a string value
          text.replace('"purpose":"', '"purpose":"{'),
          `${text.slice(0, firstValue)}[2]${text.slice(firstValue + 1)}`, // an array where a number belongs
          `${text.slice(0, firstValue)}{"v":2}${text.slice(firstValue + 1)}`, // an object where a number belongs
          `[${text}]`,
          `{"v":${text}}`,
        ];
        for (const nested of variants) expect(verdictOf(parseStatement(row.purpose, utf8(nested))), nested).toBe("non_canonical");
      }
      // As deep as 1,024 bytes allow with objects: `{"a":` repeated.
      const deepObjects = utf8('{"a":'.repeat(204) + "1");
      expect(deepObjects.length).toBeLessThanOrEqual(MAX_STATEMENT_BYTES);
      for (const purpose of PURPOSES) {
        if (purpose !== "escrow-uvk") expect(verdictOf(parseStatement(purpose, deepObjects)), purpose).toBe("non_canonical");
      }
    });
    expect(calls).toBe(0);
  });

  it("the host-offer reader refuses its deepest inputs before the parser sees them", () => {
    const hostVerdict = (text: string): string => verdictOf(parseHostOffer(utf8(text)));
    const refusedUnparsed = [
      "[".repeat(2_000_000), // megabytes of open arrays
      '{"a":'.repeat(400_000),
      `{"purpose":"setup-offer","x":${"[".repeat(32)}${"]".repeat(32)}}`, // 33 containers open at once
      `${"]".repeat(1000)}${"[".repeat(1032)}`, // closers first must not buy the depth back
      `{"purpose":"setup-offer"}${"}".repeat(40)}${"[".repeat(60)}`,
    ];
    for (const text of refusedUnparsed) {
      const calls = parserCalls(() => expect(hostVerdict(text), text.slice(0, 40)).toBe("non_canonical"));
      expect(calls, text.slice(0, 40)).toBe(0);
    }
    expect(withinJsonDepth("]".repeat(3) + "[".repeat(34))).toBe(false);
    expect(withinJsonDepth("{}}{")).toBe(false);
    // At the bound the parser is asked, once, and the purpose decides.
    const atTheBound = `{"purpose":"other","x":${"[".repeat(31)}${"]".repeat(31)}}`;
    expect(parserCalls(() => expect(hostVerdict(atTheBound)).toBe("unknown_format"))).toBeGreaterThan(0);
  });

  it("the spec 01 codec of purposes 0x01 and 0x02 refuses nesting before the parser too", () => {
    const refusal = (purposeCode: number, statement: Uint8Array): string => {
      try {
        parseSpec01Statement(purposeCode, statement);
        return "ok";
      } catch (e) {
        if (e instanceof SignedStatementError) return e.verdict;
        throw e;
      }
    };
    const calls = parserCalls(() => {
      for (const code of [1, 2]) {
        expect(refusal(code, brackets(MAX_STATEMENT_BYTES)), `0x0${code}`).toBe("non_canonical");
        expect(refusal(code, utf8('{"a":'.repeat(204) + "1")), `0x0${code}`).toBe("non_canonical");
        expect(refusal(code, utf8('{"v":2,"purpose":"vault-grant","from":["x"]}')), `0x0${code}`).toBe("non_canonical");
        expect(refusal(code, utf8('{"v":2,"purpose":{"x":1}}')), `0x0${code}`).toBe("non_canonical");
      }
    });
    expect(calls).toBe(0);
    // A flat statement still reaches the parser and its own checks.
    expect(parserCalls(() => expect(refusal(1, utf8('{"v":2}'))).toBe("non_canonical"))).toBe(1);
  });

  it("the v1 payload readers answer deep nesting with a refusal, never a RangeError", async () => {
    const keys = boxKeypairFromSeed(new Uint8Array(32).fill(0x21));
    const deepTexts = ["[".repeat(1_000_000), "[".repeat(200_000) + "]".repeat(200_000), '{"a":'.repeat(200_000) + "1" + "}".repeat(200_000)];
    for (const text of deepTexts) {
      const sealed = sealTo(keys.publicKey, utf8(text));
      await expect(openCanary(keys, sealed), text.slice(0, 12)).rejects.toThrow(CryptoError);
    }
    // The v1 escrow payload starts with `{`; anything else is refused by its first byte.
    const identityCheck = { encryptedIdentitySeedB64: "AAAA", identityPubB64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
    for (const text of ['{"a":'.repeat(200_000), '{"v":1,"x":' + "[".repeat(200_000) + "]".repeat(200_000) + "}"]) {
      const opened = openEscrow({
        recoveryKeypair: keys, sealed: sealTo(keys.publicKey, utf8(text)), expectedUserId: VAULT, expectedIdentityFpPrefix: null,
        identityCheck, unanchoredAcknowledgment: UNANCHORED_ACK,
      });
      await expect(opened, text.slice(0, 12)).rejects.toMatchObject({ name: "EscrowOpenError", verdict: "v1_malformed" });
    }
  });
});
