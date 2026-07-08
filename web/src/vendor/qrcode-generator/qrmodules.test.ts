import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { qrModules } from "./index";

/**
 * Golden otpauth URI — a realistic server-TOTP enrollment string. The matrix sha256 is
 * a TAMPER PIN on the vendored encoder (./qrcode.esm.js): a swapped or upgraded encoder
 * that changes output breaks this. The value + the fact that this exact matrix scans
 * back to GOLDEN were produced by the batch v6-QW1 jsqr decode harness (scratch-only;
 * jsqr never entered web/package.json) — see the batch log qw1-impl/decode-roundtrip.log.
 */
const GOLDEN =
  "otpauth://totp/andvari:jacob@example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari&algorithm=SHA1&digits=6&period=30";
const GOLDEN_SHA = "f29a2c01c6bd68786c72bd3b7dcd383925dd1cd0ea1c745fa893148a089a9056";

function matrixSha(modules: boolean[][]): string {
  const flat = modules.map((row) => row.map((d) => (d ? "1" : "0")).join("")).join("\n");
  return createHash("sha256").update(flat).digest("hex");
}

describe("qrModules (vendored qrcode-generator wrapper)", () => {
  it("emits the pinned golden matrix for a fixed otpauth URI", () => {
    const m = qrModules(GOLDEN, "M");
    expect(m.length).toBe(45); // version 7 at ECC-M for this length
    expect(matrixSha(m)).toBe(GOLDEN_SHA);
  });

  it("returns a square, all-boolean matrix", () => {
    const m = qrModules("andvari", "M");
    expect(m.length).toBeGreaterThan(0);
    for (const row of m) {
      expect(row.length).toBe(m.length);
      for (const cell of row) expect(typeof cell).toBe("boolean");
    }
  });

  it("a stronger ECC level never shrinks the symbol", () => {
    expect(qrModules(GOLDEN, "H").length).toBeGreaterThanOrEqual(qrModules(GOLDEN, "L").length);
  });

  it("encodes a UTF-8 label without throwing (pinned stringToBytes byte mode)", () => {
    expect(() =>
      qrModules("otpauth://totp/andvari:José@example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari", "M"),
    ).not.toThrow();
  });
});
