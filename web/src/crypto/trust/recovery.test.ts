import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64, toHexLower } from "../bytes";
import { boxKeypairFromSeed, sha256Sync, signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { NONE } from "./grammar";
import { verifyCardChain } from "./instancecard";
import {
  groupedRequestCode, openAssistedRecovery, requestCode, rotationChain, rotationsLink, signVeto, unsignedChanges, verifyRotation, verifyRotationChain, verifyVeto,
} from "./recovery";
import { expectSections, gradeEvery, vector } from "./vectors";

/**
 * The recovery statements of design 2026-11-15 §4.5 and §9.3, graded off the SAME `recovery.json`
 * core's `RecoveryVectorTest` consumes: rotations (0x08) one by one and as the escrow chain of
 * `PUT /escrow/self`, the first-consent walk from card 0, the request code, assisted recovery (0x09)
 * and the veto (0x0A), each with the verdicts and order of §2.4.
 */
const v = vector("recovery.json");
const rotationFrame = (name: string): Uint8Array => fromB64(v.rotationFrames[name]);
let rPub: Uint8Array;
let rSec: Uint8Array;

beforeAll(async () => {
  await initSodium();
  rPub = fromB64(v.requestKey.rPubB64);
  rSec = fromB64(v.requestKey.rSecB64);
});

describe("recovery.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, [
      "_about", "instanceId", "keys", "requestKey", "rotation", "rotationFrames", "escrowRotations", "cardChains", "firstConsent", "requestCode",
      "assisted", "veto",
    ]);
  });

  it("keys: one seed gives the recovery key, its signing key and its fingerprint", () => {
    for (const name of ["recoveryA", "recoveryB", "recoveryC"]) {
      const k = v.keys[name];
      const seed = fromB64(k.seedB64);
      expect(toB64(boxKeypairFromSeed(seed).publicKey), name).toBe(k.publicKeyB64);
      expect(toB64(signKeypairFromSeed(seed).publicKey), name).toBe(k.signPubB64);
      expect(toHexLower(sha256Sync(fromB64(k.publicKeyB64))), name).toBe(k.fingerprint);
    }
  });

  it("rotation: every row gets its exact verdict", () => {
    gradeEvery("recovery.rotation", v.rotation, (r: any) => {
      // The row hands the key currentFp names; the helper is handed the fingerprint, which names it.
      expect(toHexLower(sha256Sync(fromB64(r.recoveryPubB64))), r.name).toBe(r.currentFp);
      const result = verifyRotation(fromB64(r.frameB64), r.instanceId, r.currentFp);
      expect(result.ok ? "ok" : result.verdict, `${r.name}: ${r.why}`).toBe(r.expect.verdict);
      if (result.ok) {
        expect(result.value.fields.toFp, r.name).toBe(r.expect.toFp);
        // A verified rotation cannot be changed after the fact: the value and its fields are frozen.
        expect(Object.isFrozen(result.value) && Object.isFrozen(result.value.fields), r.name).toBe(true);
        expect(() => { (result.value.fields as { toFp: string }).toFp = "0".repeat(64); }, r.name).toThrow(TypeError);
      }
    });
  });

  it("escrowRotations: the chain of PUT /escrow/self", () => {
    gradeEvery("recovery.escrowRotations", v.escrowRotations, (r: any) => {
      const result = verifyRotationChain(r.rotations.map(rotationFrame), r.instanceId, r.currentEscrowFp, r.fingerprint);
      expect(result.verdict === null, `${r.name}: ${r.why}`).toBe(r.expect.accepted);
      if (r.expect.failedAt !== undefined) {
        expect([result.failedAt, result.verdict], r.name).toEqual([r.expect.failedAt, r.expect.linkVerdict]);
      } else if (!r.expect.accepted) {
        expect([result.failedAt, result.verdict], `${r.name}: every link verifies, the end does not match`).toEqual([null, "fp_mismatch"]);
      }
    });
  });

  it("rotationChain finds, in any served order, a chain PUT /escrow/self accepts, and only such a chain", () => {
    gradeEvery("recovery.escrowRotations (search)", v.escrowRotations, (r: any) => {
      const served = [...r.rotations].reverse().map(rotationFrame);
      const found = rotationChain(served, r.instanceId, r.currentEscrowFp, r.fingerprint);
      if (r.expect.accepted) expect(found, `${r.name}: a chain exists`).not.toBeNull();
      if (found !== null) expect(verifyRotationChain(found, r.instanceId, r.currentEscrowFp, r.fingerprint).verdict, r.name).toBeNull();
    });
    expect(rotationChain([], v.instanceId, "a".repeat(64), "a".repeat(64))).toEqual([]);
    expect(rotationChain([rotationFrame("B-to-C"), rotationFrame("A-to-B")], v.instanceId, v.keys.recoveryA.fingerprint, v.keys.recoveryC.fingerprint)!.map(toB64)).toEqual(
      [rotationFrame("A-to-B"), rotationFrame("B-to-C")].map(toB64),
    );
  });

  it("firstConsent: the walk from card 0 names every uncovered change", () => {
    gradeEvery("recovery.firstConsent", v.firstConsent, (r: any) => {
      const served = v.cardChains[r.cards];
      expect(served, `${r.name}: cardChains.${r.cards}`).toBeDefined();
      const chain = verifyCardChain(served.frames.map(fromB64));
      expect(chain.verdict, r.name).toBeNull();
      expect(chain.cards.map((c) => c.fields.recoveryFp ?? NONE), r.name).toEqual(served.recoveryFps);
      const uncovered = unsignedChanges(chain.cards, r.rotations.map(rotationFrame));
      expect(uncovered.map((c) => ({ seq: c.seq, from: c.fromFp ?? NONE, to: c.toFp ?? NONE })), `${r.name}: ${r.why}`).toEqual(r.expect.uncovered);
      expect(uncovered.length > 0, r.name).toBe(r.expect.warning);
    });
  });

  it("consent follows a chain of rotations served in any order, and nothing else", () => {
    const [a, b, c] = ["recoveryA", "recoveryB", "recoveryC"].map((k) => v.keys[k].fingerprint as string);
    const all = Object.keys(v.rotationFrames).map(rotationFrame);
    expect(rotationsLink([rotationFrame("B-to-C"), rotationFrame("A-to-B")], v.instanceId, a!, c!)).toBe(true);
    expect(rotationsLink([], v.instanceId, a!, a!)).toBe(true);
    expect(rotationsLink(all, v.instanceId, c!, a!)).toBe(false);
    expect(rotationsLink([rotationFrame("A-to-B-signed-by-B"), rotationFrame("A-to-B-for-another-instance")], v.instanceId, a!, b!)).toBe(false);
  });

  it("requestCode: 96 bits of the request key, six groups of four", () => {
    gradeEvery("recovery.requestCode", v.requestCode, (r: any) => {
      expect(r.inputUtf8, r.why).toBe(`andvari/v2|recovery-request|code|${r.rPubB64}`);
      const code = requestCode(fromB64(r.rPubB64));
      expect(code, r.why).toBe(r.code);
      expect(groupedRequestCode(code), r.why).toBe(r.grouped);
    });
  });

  it("assisted: every row gets its exact verdict", () => {
    gradeEvery("recovery.assisted", v.assisted, (r: any) => {
      expect(r.request.requestKey, r.name).toBe(v.requestKey.rPubB64);
      expect(toHexLower(sha256Sync(fromB64(r.recoveryPubB64))), r.name).toBe(r.cardRecoveryFp);
      const result = openAssistedRecovery(
        { instanceId: r.request.instanceId, userId: r.request.userId, requestId: r.request.requestId, rPub, rSec },
        fromB64(r.sealedB64),
        r.cardRecoveryFp,
        { encryptedIdentitySeed: fromB64(r.encryptedIdentitySeedB64), identityPub: fromB64(r.identityPubB64) },
      );
      expect(result.ok ? "ok" : result.verdict, `${r.name}: ${r.why}`).toBe(r.expect.verdict);
      if (result.ok) {
        expect(toB64(result.value.uvk), r.name).toBe(r.expect.uvkB64);
        // A fresh install (request.userId null) learns the userId from the payload, which the seed's AD bound.
        expect(result.value.userId, r.name).toBe(r.request.userId ?? v.keys.alice.userId);
      }
    });
  });

  it("assisted: a fresh install with no userId skips that comparison, and the seed's AD still binds the account; a card with none admits no signer", () => {
    const run = (name: string, pinnedFp?: string | null) => {
      const r = v.assisted.find((x: { name: string }) => x.name === name);
      const result = openAssistedRecovery(
        { instanceId: r.request.instanceId, userId: null, requestId: r.request.requestId, rPub, rSec },
        fromB64(r.sealedB64),
        pinnedFp === undefined ? r.cardRecoveryFp : pinnedFp,
        { encryptedIdentitySeed: fromB64(r.encryptedIdentitySeedB64), identityPub: fromB64(r.identityPubB64) },
      );
      return result.ok ? "ok" : result.verdict;
    };
    expect(run("valid")).toBe("ok");
    expect(run("user-differs")).toBe("identity_mismatch");
    // Skipping the comparison takes an explicit null: a request built without the field is refused, not waved through.
    const valid = v.assisted.find((x: { name: string }) => x.name === "valid");
    const withoutUserId = openAssistedRecovery(
      { instanceId: valid.request.instanceId, requestId: valid.request.requestId, rPub, rSec } as unknown as Parameters<typeof openAssistedRecovery>[0],
      fromB64(valid.sealedB64), valid.cardRecoveryFp,
      { encryptedIdentitySeed: fromB64(valid.encryptedIdentitySeedB64), identityPub: fromB64(valid.identityPubB64) },
    );
    expect(withoutUserId.ok ? "ok" : withoutUserId.verdict).toBe("request_mismatch");
    expect(run("valid", null)).toBe("signer_not_pinned_key"); // the pinned card says none
    expect(run("valid", "0".repeat(64))).toBe("signer_not_pinned_key");
  });

  it("veto: every row gets its exact verdict", () => {
    gradeEvery("recovery.veto", v.veto, (r: any) => {
      const result = verifyVeto(fromB64(r.frameB64), fromB64(r.storedIdentityPubB64), r.sessionUserId, r.requestId);
      expect(result.ok ? "ok" : result.verdict, `${r.name}: ${r.why}`).toBe(r.expect.verdict);
    });
  });

  it("a veto this client signs verifies against the account's key", () => {
    const alice = v.keys.alice;
    const veto = { requestId: "kevsyZmgCVPO8TTl-1oqKQ", userId: alice.userId as string, issuedAt: 1_763_164_800_000 };
    const frame = signVeto(signKeypairFromSeed(fromB64(alice.seedB64)), veto);
    const back = verifyVeto(frame, fromB64(alice.identityPubB64), alice.userId, veto.requestId);
    expect(back.ok && back.value).toEqual(veto);
    expect(() => signVeto(signKeypairFromSeed(fromB64(alice.seedB64)), { ...veto, requestId: "not-a-request-id" })).toThrow();
  });
});
