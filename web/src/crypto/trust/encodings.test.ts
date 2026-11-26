import { beforeAll, describe, expect, it } from "vitest";
import { toHexLower } from "../bytes";
import { initSodium } from "../sodium";
import { decodeEmail, decodeName, emailNorm, encodeEmail, encodeName, isName, isOrigin, isPlatform } from "./grammar";
import { leadingZeroBits, powAccepts, powDigest, powInput, powSearch } from "./signup";
import { expectSections, gradeEvery, hexBytes, vector } from "./vectors";

/**
 * The encodings of design 2026-11-15 §2.2 and §2.3, graded off `encodings.json` from the independent
 * oracle: the same file core's `EncodingsVectorTest` consumes. Every row must give exactly its verdict.
 */
const v = vector("encodings.json");

beforeAll(async () => {
  await initSodium();
});

describe("encodings.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, ["_about", "emailNorm", "platform", "powLeadingZeroBits", "powInput", "name", "origin"]);
  });

  it("emailNorm: every row", () => {
    gradeEvery("encodings.emailNorm", v.emailNorm, (r: any) => {
      // Every input and expectation key is one this grader reads: a key the oracle adds later fails here.
      expect(Object.keys(r).sort(), r.why).toEqual(["expect", "input", "why"]);
      expect(Object.keys(r.expect).sort(), r.why).toEqual(r.expect.verdict === "ok" ? ["emailNorm", "verdict"] : ["verdict"]);
      const got = emailNorm(r.input);
      if (r.expect.verdict === "ok") expect(got, r.why).toBe(r.expect.emailNorm);
      else {
        expect(r.expect.verdict, r.why).toBe("invalid_email");
        expect(got, r.why).toBeNull();
      }
      if (got !== null) {
        // A fixed point, and what an email_b64n field must decode to (VR-7).
        expect(emailNorm(got), r.why).toBe(got);
        expect(decodeEmail(encodeEmail(got)!), r.why).toEqual({ email: got });
      }
    });
  });

  it("platform: the closed enum", () => {
    gradeEvery("encodings.platform", v.platform, (r: any) => expect(isPlatform(r.value), r.value).toBe(r.valid));
  });

  it("proof of work: bit order and the hashed string", () => {
    gradeEvery("encodings.powLeadingZeroBits", v.powLeadingZeroBits, (r: any) => {
      expect(leadingZeroBits(hexBytes(r.digestHex)), r.why).toBe(r.leadingZeroBits);
    });
    gradeEvery("encodings.powInput", v.powInput, (r: any) => {
      expect(powInput(r.emailNorm, r.utcDate, r.nonce), r.why).toBe(r.inputUtf8);
      const digest = powDigest(r.emailNorm, r.utcDate, r.nonce);
      expect(toHexLower(digest), r.why).toBe(r.digestHex);
      expect(leadingZeroBits(digest), r.why).toBe(r.leadingZeroBits);
      expect(powAccepts(r.emailNorm, r.utcDate, r.nonce, r.leadingZeroBits), r.why).toBe(true);
      expect(powAccepts(r.emailNorm, r.utcDate, r.nonce, r.leadingZeroBits + 1), r.why).toBe(false);
    });
    const nonce = powSearch("alice@example.com", "2026-11-15", 8, 0, 100_000)!;
    expect(powAccepts("alice@example.com", "2026-11-15", nonce, 8)).toBe(true);
    for (let n = 0; n < nonce; n++) expect(powAccepts("alice@example.com", "2026-11-15", n, 8)).toBe(false);
    expect(powSearch("alice@example.com", "2026-11-15", 250, 0, 50)).toBeNull();
    expect(() => powInput("Alice@example.com", "2026-11-15", 0)).toThrow();
    expect(() => powInput("alice@example.com", "2026-11-5", 0)).toThrow();
    expect(() => powInput("alice@example.com", "2026-11-15", -1)).toThrow();
  });

  it("name: every row", () => {
    gradeEvery("encodings.name", v.name, (r: any) => {
      const text = decodeName(r.name);
      expect(text !== null, r.why).toBe(r.valid);
      expect(isName(r.name), r.why).toBe(r.valid);
      if (text !== null) {
        // No normalisation: the text is exactly the bytes, and it encodes back to the same field.
        expect(toHexLower(new TextEncoder().encode(text)), r.why).toBe(r.textHex);
        expect(encodeName(text), r.why).toBe(r.name);
      }
    });
    expect(encodeName("a\ud800b")).toBeNull(); // a lone surrogate never becomes U+FFFD
  });

  it("origin: every row", () => {
    gradeEvery("encodings.origin", v.origin, (r: any) => expect(isOrigin(r.origin), `${r.why}: ${r.origin}`).toBe(r.valid));
  });
});
