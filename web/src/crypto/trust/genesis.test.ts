import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64 } from "../bytes";
import { boxKeypairFromSeed, ed25519PkToCurve25519, signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { signatureValid, splitFrame } from "./frame";
import { personalWrapInForce, signGenesis, verifyGenesis } from "./genesis";
import { expectSections, gradeEvery, vector } from "./vectors";

/**
 * The account genesis of design 2026-11-15 §5, graded off the SAME `accountgenesis.json` core's
 * `AccountGenesisVectorTest` consumes: one unlock of alice's account per row, one verdict per check in
 * §2.4's order (VR-13), and §5.3's personal wrap in force. Every client binds the signer to the
 * seed-derived Ed25519 key byte for byte (§2.4, row 0x05), so `expect.extensionVerdict` must equal
 * `expect.verdict` on every row, and this suite checks that it does.
 */
const v = vector("accountgenesis.json");

beforeAll(async () => {
  await initSodium();
});

describe("accountgenesis.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, ["_about", "account", "instanceId", "personalVaultId", "personalVkB64", "rows"]);
  });

  it("the account's keys are the seed's", () => {
    const seed = fromB64(v.account.seedB64);
    expect(toB64(boxKeypairFromSeed(seed).publicKey)).toBe(v.account.identityPubB64);
    expect(toB64(signKeypairFromSeed(seed).publicKey)).toBe(v.account.signPubB64);
  });

  it("every row gets its exact verdict, and ok rows their personal vault", () => {
    const identityPub = boxKeypairFromSeed(fromB64(v.account.seedB64)).publicKey;
    const signPub = signKeypairFromSeed(fromB64(v.account.seedB64)).publicKey;
    const uvk = fromB64(v.account.uvkB64);
    gradeEvery("accountgenesis.rows", v.rows, (r: any) => {
      expect(r.expect.extensionVerdict, `${r.name}: every client binds the signer the same way`).toBe(r.expect.verdict);
      // The expectations this grader checks, and no other: a key the oracle adds later fails here.
      const graded = r.expect.verdict === "ok" ? ["extensionVerdict", "personalVaultInForce", "verdict"] : ["extensionVerdict", "verdict"];
      expect(Object.keys(r.expect).sort(), r.name).toEqual(graded);
      const wrap = r.personalWrap as { vaultId: string; wrappedVkB64: string } | null;
      const result = verifyGenesis(fromB64(r.genesisB64), {
        signPub, identityPub, userId: r.sessionUserId, instanceId: r.pinnedInstanceId, personalVaultId: wrap?.vaultId ?? null,
      });
      expect(result.ok ? "ok" : result.verdict, `${r.name}: ${r.why}`).toBe(r.expect.verdict);
      if (!result.ok) return;
      expect(result.value.fields.personalVaultId, r.name).toBe(v.personalVaultId);
      expect(result.value.fields.instanceId, r.name).toBe(v.instanceId);
      const vk = personalWrapInForce(result.value, uvk, wrap === null ? null : { vaultId: wrap.vaultId, wrappedVk: fromB64(wrap.wrappedVkB64) });
      expect(vk !== null, `${r.name}: personalVaultInForce`).toBe(r.expect.personalVaultInForce);
      if (vk !== null) expect(toB64(vk), r.name).toBe(v.personalVkB64);
    });
  });

  it("a genesis this client signs verifies, and only for the key it names", () => {
    const seed = fromB64(v.account.seedB64);
    const identityPub = boxKeypairFromSeed(seed).publicKey;
    const fields = {
      userId: v.account.userId, identityKey: v.account.identityPubB64, instanceId: v.instanceId, personalVaultId: v.personalVaultId,
      createdAt: 1_763_164_800_000,
    };
    const signer = signKeypairFromSeed(seed);
    const frame = signGenesis(signer, fields);
    const back = verifyGenesis(frame, { signPub: signer.publicKey, identityPub, userId: fields.userId, instanceId: fields.instanceId, personalVaultId: null });
    expect(back.ok && back.value.fields).toEqual(fields);
    // A verified genesis cannot be changed after the fact: the value and its fields are frozen.
    if (back.ok) {
      expect(Object.isFrozen(back.value) && Object.isFrozen(back.value.fields)).toBe(true);
      expect(() => { (back.value.fields as { personalVaultId: string }).personalVaultId = "ffffffff-ffff-4fff-8fff-ffffffffffff"; }).toThrow(TypeError);
      expect(back.value.fields.personalVaultId).toBe(fields.personalVaultId);
    }
    const other = signKeypairFromSeed(new Uint8Array(32).fill(7));
    expect(() => signGenesis(other, fields)).toThrow();
    // The X25519 key in the Ed25519 key's place binds nothing.
    const swapped = verifyGenesis(frame, { signPub: identityPub, identityPub, userId: fields.userId, instanceId: fields.instanceId, personalVaultId: null });
    expect(swapped.ok ? "ok" : swapped.verdict).toBe("signer_not_pinned_key");
  });

  it("a genesis validly signed under the negated key is refused (§2.4, Signer binding row 0x05)", () => {
    // The `valid` row re-signed with the scalar L - s, built outside andvari; its signer maps to alice's X25519 key.
    const frame = fromB64(NEGATED_KEY_GENESIS);
    const seed = fromB64(v.account.seedB64);
    const signPub = signKeypairFromSeed(seed).publicKey;
    const identityPub = boxKeypairFromSeed(seed).publicKey;
    const parts = splitFrame(frame);
    if (!parts.ok) throw new Error("the fixture splits");
    expect(toB64(parts.value.signerPub)).not.toBe(toB64(signPub));
    expect(toB64(ed25519PkToCurve25519(parts.value.signerPub))).toBe(toB64(identityPub));
    expect(signatureValid(parts.value)).toBe(true);
    const result = verifyGenesis(frame, { signPub, identityPub, userId: v.account.userId, instanceId: v.instanceId, personalVaultId: null });
    expect(result.ok ? "ok" : result.verdict).toBe("signer_not_pinned_key");
  });
});

/** `/tmp/l1-handover/negsig.json` `frameB64`; byte-equal to the row `genesis-signed-under-the-negated-key`. */
const NEGATED_KEY_GENESIS =
  "YXZzAgWcerokfUuai3m1bqsYJXTl-M2VQCiaH4laBp4AW1izSqGs-9Ewb-VVNZ7WZRKWT1n0zgzaVUdIdIP6ZJpsZZP4MyLLo71GPbP4wCLMmrfKLlQlJKcV5yw9mev3hXAjAwx7InYiOjIsInB1cnBvc2UiOiJhY2NvdW50LWdlbmVzaXMiLCJ1c2VySWQiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEiLCJpZGVudGl0eUtleSI6ImRtbjVUSTEtanRFUmRSVk1ab1dHNVFGcjNMWFBHcmVWSmNIRGF5TW5HaW8iLCJpbnN0YW5jZUlkIjoiZWVlZWVlZWUtZWVlZS00ZWVlLThlZWUtZWVlZWVlZWVlZWVlIiwicGVyc29uYWxWYXVsdElkIjoiY2NjY2NjY2MtY2NjYy00Y2NjLThjY2MtY2NjY2NjY2NjY2NjIiwiY3JlYXRlZEF0IjoxNzYzMTY0ODAwMDAwfQ";
