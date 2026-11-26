import { beforeAll, describe, expect, it } from "vitest";
import { toB64 } from "./bytes";
import { canonicalPayload, KEY_TYPE_UVK } from "./escrow";
import { sha256 } from "./provider";
import { CryptoError, initSodium } from "./sodium";

/**
 * Audit F33, web half — the twin of core's CanonAndLengthGuardsTest F33 cases.
 *
 * The escrow payload (spec 04 §3) is a hand-composed string template on BOTH sides (the v1
 * shared-grant payload went with the v1 seal, design 2026-11-15 §15), because the bytes are sealed here and re-parsed by the other impl and
 * by recovery-cli, and an encoder is free to reorder keys or escape differently. The cost is that
 * every id they interpolate is SERVER-SUPPLIED: without a precondition a hostile server picks the
 * JSON structure of the blob this client seals. core got the guard; these pin that web did too,
 * with the same two escape characters and the same conforming-id byte output.
 */
describe("canonical-JSON composition guards (F33)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const userId = "44444444-4444-4444-8444-444444444444";
  const key = new Uint8Array(32);

  it("the escrow payload refuses an id that would rewrite the structure", async () => {
    // The exact shape a hostile server would return to turn a `uvk` blob into a `canary` one:
    // the id closes its own string and opens a new key.
    await expect(canonicalPayload('x","keyType":"canary', KEY_TYPE_UVK, key)).rejects.toBeInstanceOf(CryptoError);
    // A backslash is the other escape into the string grammar.
    await expect(canonicalPayload("x\\", KEY_TYPE_UVK, key)).rejects.toBeInstanceOf(CryptoError);
    await expect(canonicalPayload(userId, 'uvk","key":"', key)).rejects.toBeInstanceOf(CryptoError);
  });

  it("a conforming (lowercase-UUID) id still produces the EXACT canonical bytes", async () => {
    const shaB64 = toB64(await sha256(key));
    expect(new TextDecoder().decode(await canonicalPayload(userId, KEY_TYPE_UVK, key))).toBe(
      `{"v":1,"userId":"${userId}","keyType":"uvk","key":"${toB64(key)}","sha256":"${shaB64}"}`,
    );
  });
});
