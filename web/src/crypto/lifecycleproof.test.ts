import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { toB64 } from "./bytes";
import {
  REMOVAL_SKEW_MS,
  acceptProof,
  decideRemoval,
  deleteProof,
  isV2Nonce,
  leaveProof,
  lifecycleKey,
  offerProof,
  removeProof,
  removeV2Proof,
  restoreProof,
  verifyProof,
} from "./lifecycleproof";
import { hmacSha256 } from "./provider";
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

  // Branch A7 (root cause A §6.1): both v2 domains, byte-exact, and a valid MAC for each.
  it("mints both v2 domains identically to core (remove-v2, leave)", async () => {
    const key = await lifecycleKey(fromB64(v.vk));
    const cases = v.v2Cases as Record<string, string | number>[];
    expect(new Set(cases.map((c) => c.op))).toEqual(new Set(["remove-v2", "leave"]));
    for (const c of cases) {
      const actual =
        c.op === "remove-v2"
          ? await removeV2Proof(key, c.vaultId as string, c.targetUserId as string, c.nonce as string, c.issuedAt as number)
          : await leaveProof(key, c.vaultId as string, c.userId as string, c.nonce as string, c.issuedAt as number);
      expect(actual, `v2 proof for op=${c.op}`).toBe(c.proof);
      expect(toB64(await hmacSha256(key, new TextEncoder().encode(c.domain as string))), `domain pinned (${c.op})`).toBe(c.proof);
      expect(isV2Nonce(c.nonce as string)).toBe(true);
    }
  });

  // Branch A7 (root cause A §6.3, §8.6): the verdict table, graded against decideRemoval — THE function
  // store.ts calls on every removed/left row (A6's lesson: never grade a helper production does not call).
  it("decides every verdict-table row exactly as core does", async () => {
    const key = await lifecycleKey(fromB64(v.vk));
    const t = v.verdicts as { vaultId: string; myUserId: string; skewMs: number; cases: Record<string, unknown>[] };
    expect(t.skewMs).toBe(REMOVAL_SKEW_MS);
    expect(t.cases.length).toBeGreaterThanOrEqual(20);
    for (const c of t.cases) {
      const d = await decideRemoval({
        lifecycleKey: key,
        vaultId: t.vaultId,
        myUserId: t.myUserId,
        reason: c.reason as string,
        proofV: c.proofV as number | null,
        proof: c.proof as string | null,
        nonce: c.nonce as string | null,
        issuedAt: c.issuedAt as number | null,
        consumed: new Set(c.consumed as string[]),
        consumedAccount: new Set(c.consumedAccount as string[]),
        liveSince: c.liveSince as number | null,
        now: c.now as number,
      });
      expect(d.verdict, `verdict: ${c.name}`).toBe(c.expect);
      expect(d.step, `deciding step: ${c.name}`).toBe(c.step);
      expect(d.consume ?? null, `consume: ${c.name}`).toEqual((c.consume as [string, number] | undefined) ?? null);
    }
  });

  it("verify rejects tamper and garbage without throwing", () => {
    const a = (v.cases[0] as { proof: string }).proof;
    expect(verifyProof(a, a.slice(0, -1) + (a.slice(-1) === "A" ? "B" : "A"))).toBe(false);
    expect(verifyProof(a, "")).toBe(false);
    expect(verifyProof(a, "!!not base64!!")).toBe(false);
  });
});
