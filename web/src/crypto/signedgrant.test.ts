import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64 } from "./bytes";
import { boxKeypairFromSeed, signKeypairFromSeed } from "./provider";
import { buildGrantFrame, decideLegacyGrant, openSignedGrant, type GrantPin } from "./signedgrant";
import { initSodium } from "./sodium";

/**
 * Signed vault grants, format v2 (security review 2026-10, root cause A §1.4–§1.5, branch A6) — web twin of core
 * `SharedGrantV2VectorTest`, graded off the SAME spec/test-vectors/sharedgrant-v2.json (blobs from an independent
 * oracle). Every row is a §1.4 decision: the FIRST failing step decides the verdict. The rows that matter most:
 * `signer-other-pinned-member` (the pin is chosen by contacts[from]) and `pending-*` (an unpinned sender, or a pin
 * that is not current on this device, is a pending invitation, never an adoption).
 */

const dir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(dir + "sharedgrant-v2.json", "utf-8"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v1: any = JSON.parse(readFileSync(dir + "sharedgrant.json", "utf-8"));

describe("sharedgrant-v2.json", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("parties match their seeds", () => {
    for (const who of ["owner", "member", "third"]) {
      const p = v[who];
      expect(toB64(boxKeypairFromSeed(fromB64(p.seedB64)).publicKey)).toBe(p.identityPubB64);
      expect(toB64(signKeypairFromSeed(fromB64(p.seedB64)).publicKey)).toBe(p.signPubB64);
    }
  });

  it("every decision row has its verdict", () => {
    const me = boxKeypairFromSeed(fromB64(v.member.seedB64));
    const anomalies = new Set<string>(v.anomalyVerdicts);
    expect(v.cases.length).toBeGreaterThanOrEqual(20);
    for (const c of v.cases) {
      const pins = c.pins as Record<string, string>;
      const outcome = openSignedGrant({
        myUserId: v.member.userId,
        myIdentityPub: me.publicKey,
        myIdentityPriv: me.privateKey,
        rowVaultId: c.rowVaultId,
        sealed: fromB64(c.sealedB64),
        pinFor: (uid: string): GrantPin | null => (pins[uid] ? { identityPub: fromB64(pins[uid]!), current: c.pinsCurrent } : null),
        heldVk: c.heldVkB64 ? fromB64(c.heldVkB64) : null,
      });
      const e = c.expect;
      expect(outcome.verdict, `${c.name}: ${c.why}`).toBe(e.verdict);
      expect(outcome.anomaly, `${c.name} anomaly`).toBe(anomalies.has(e.verdict));
      if (e.verdict === "adopt") {
        if (outcome.verdict !== "adopt") throw new Error(c.name);
        expect(toB64(outcome.vk), c.name).toBe(e.vkB64);
        expect(outcome.from).toBe(e.from);
        expect(outcome.grantIdB64).toBe(e.grantIdB64);
        expect(outcome.issuedAt).toBe(e.issuedAt);
      } else if (e.verdict === "pending_invitation") {
        if (outcome.verdict !== "pending_invitation") throw new Error(c.name);
        expect(outcome.from).toBe(e.from);
        expect("vk" in outcome).toBe(false);
      } else {
        expect("vk" in outcome, c.name).toBe(false);
      }
    }
  });

  it("the sender builds the vector frame byte-identically", () => {
    const signer = signKeypairFromSeed(fromB64(v.owner.seedB64));
    const frame = buildGrantFrame(signer, {
      purpose: "vault-grant",
      from: v.owner.userId,
      to: v.member.userId,
      toKey: fromB64(v.member.identityPubB64),
      vaultId: v.vaultId,
      grantId: fromB64("AAECAwQFBgcICQoLDA0ODw"),
      issuedAt: 1791590400000,
      vk: fromB64(v.vkB64),
    });
    expect(toB64(frame)).toBe(v.frameB64);
  });

  it("sharedgrant.json legacyMode rows", () => {
    for (const r of v1.legacyMode.rows) {
      expect(decideLegacyGrant(r.window === "in_window", r.evidence, r.confirmed), JSON.stringify(r)).toBe(r.expect);
    }
  });
});
