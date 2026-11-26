import { beforeAll, describe, expect, it } from "vitest";
import { adVkPersonal, adVkShared } from "./ad";
import { fromB64, toB64 } from "./bytes";
import { open, sealWithNonce } from "./envelope";
import { initSodium } from "./sodium";
import { expectSections, gradeEvery, vector } from "./trust/vectors";

/**
 * The genesis-bound shared-vault wrap AD (design 2026-11-15 §2.3, T-B3), graded off the `ad`, `seal`
 * and `open` rows of `wrapad.json` from the independent oracle: a wrap made for genesis A is refused
 * under genesis B, and the personal wrap is unchanged. The file's `adopt` rows belong to `web/src/vault`.
 */
const v = vector("wrapad.json");
const utf8 = (s: string) => new TextEncoder().encode(s);

beforeAll(async () => {
  await initSodium();
});

describe("wrapad.json", () => {
  it("the file has the sections this suite grades, and the adoption rows that are web/src/vault's", () => {
    expectSections(v, ["_about", "vaultId", "vkB64", "vkCommitHex", "accounts", "logs", "ad", "seal", "open", "adopt"]);
  });

  it("ad: a shared wrap names the genesis; the personal wrap is unchanged", () => {
    gradeEvery("wrapad.ad", v.ad, (r: any) => {
      expect(["shared", "personal"], r.why).toContain(r.kind);
      const ad = r.kind === "shared" ? adVkShared(r.vaultId, r.userId, r.genesisHash) : adVkPersonal(r.vaultId, r.userId);
      expect(new TextDecoder().decode(ad), r.why).toBe(r.adUtf8);
    });
    expect(() => adVkShared("a|b", "u", "h")).toThrow();
  });

  it("seal is byte-exact", () => {
    gradeEvery("wrapad.seal", v.seal, (r: any) => {
      expect(toB64(sealWithNonce(fromB64(r.uvkB64), fromB64(r.nonceB64), fromB64(r.vkB64), utf8(r.adUtf8))), r.name).toBe(r.wrappedVkB64);
    });
  });

  it("open: only under its own AD", () => {
    gradeEvery("wrapad.open", v.open, (r: any) => {
      let opened: Uint8Array | null;
      try {
        opened = open(fromB64(r.uvkB64), fromB64(r.wrappedVkB64), utf8(r.adUtf8));
      } catch {
        opened = null;
      }
      expect(opened !== null, `${r.name}: ${r.why}`).toBe(r.expect.opens);
      if (opened !== null) expect(toB64(opened), r.name).toBe(r.expect.vkB64);
    });
  });
});
