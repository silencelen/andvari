import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { toB64 } from "./bytes";
import {
  acceptProof,
  deleteProof,
  lifecycleKey,
  offerProof,
  removeProof,
  restoreProof,
  verifyProof,
} from "./lifecycleproof";
import { initSodium } from "./sodium";

/**
 * Consumes spec/test-vectors/lifecycleproof.json — the SAME file the Kotlin
 * LifecycleProofVectorTest checks. The lifecycleKey derivation and every op's HMAC
 * domain string must match core byte-for-byte (spec 03 §11), or a member's client would
 * reject a genuine owner action.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "lifecycleproof.json", "utf-8"));

const fromB64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

beforeAll(async () => {
  await initSodium();
});

describe("lifecycle-proof vectors", () => {
  it("derives the lifecycleKey identically", async () => {
    expect(toB64(await lifecycleKey(fromB64(v.vk)))).toBe(v.lifecycleKey);
  });

  it("mints every op proof identically to core", async () => {
    const key = await lifecycleKey(fromB64(v.vk));
    for (const c of v.cases as Record<string, string | number>[]) {
      let actual: string;
      switch (c.op) {
        case "delete": actual = await deleteProof(key, c.vaultId as string, c.deleteId as string); break;
        case "restore": actual = await restoreProof(key, c.vaultId as string, c.deleteId as string); break;
        case "offer": actual = await offerProof(key, c.vaultId as string, c.offerId as string, c.toUserId as string, c.expiresAt as number, c.seq as number); break;
        case "accept": actual = await acceptProof(key, c.vaultId as string, c.offerId as string, c.newOwnerUserId as string, c.seq as number, c.wrappedVk as string); break;
        case "remove": actual = await removeProof(key, c.vaultId as string, c.targetUserId as string, c.nonce as string); break;
        default: throw new Error(`unknown op ${c.op}`);
      }
      expect(actual, `proof for op=${c.op}`).toBe(c.proof);
      expect(verifyProof(c.proof as string, actual), `verify accepts op=${c.op}`).toBe(true);
    }
  });

  it("verify rejects tamper and garbage without throwing", () => {
    const a = (v.cases[0] as { proof: string }).proof;
    expect(verifyProof(a, a.slice(0, -1) + (a.slice(-1) === "A" ? "B" : "A"))).toBe(false);
    expect(verifyProof(a, "")).toBe(false);
    expect(verifyProof(a, "!!not base64!!")).toBe(false);
  });
});
