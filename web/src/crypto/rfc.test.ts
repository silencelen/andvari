import { beforeAll, describe, expect, it } from "vitest";
import { toHexLower, utf8 } from "./bytes";
import { hkdfSha256 } from "./hkdf";
import { initSodium } from "./sodium";
import { totpCode, type TotpAlgorithm, type TotpConfig } from "./totp";

/** Independent RFC pins — protect against vector-gen self-blessing a broken impl. */

beforeAll(async () => {
  await initSodium();
});

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("RFC 5869 HKDF-SHA-256", () => {
  it("case 1", async () => {
    const okm = await hkdfSha256(
      hex("0b".repeat(22)),
      hex("000102030405060708090a0b0c"),
      hex("f0f1f2f3f4f5f6f7f8f9"),
      42,
    );
    expect(toHexLower(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("case 3 (empty salt & info)", async () => {
    const okm = await hkdfSha256(hex("0b".repeat(22)), new Uint8Array(0), new Uint8Array(0), 42);
    expect(toHexLower(okm)).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
  });
});

describe("RFC 6238 TOTP", () => {
  const secrets: Record<TotpAlgorithm, Uint8Array> = {
    SHA1: utf8("12345678901234567890"),
    SHA256: utf8("12345678901234567890123456789012"),
    SHA512: utf8("1234567890123456789012345678901234567890123456789012345678901234"),
  };
  const cases: Array<[number, TotpAlgorithm, string]> = [
    [59, "SHA1", "94287082"],
    [59, "SHA256", "46119246"],
    [59, "SHA512", "90693936"],
    [1111111109, "SHA1", "07081804"],
    [1234567890, "SHA256", "91819424"],
    [2000000000, "SHA512", "38618901"],
    [20000000000, "SHA1", "65353130"],
  ];
  it("appendix B vectors", async () => {
    for (const [time, alg, expected] of cases) {
      const config: TotpConfig = {
        secret: secrets[alg],
        algorithm: alg,
        digits: 8,
        periodSeconds: 30,
        label: "",
        issuer: "",
      };
      expect(await totpCode(config, time), `T=${time} ${alg}`).toBe(expected);
    }
  });
});
