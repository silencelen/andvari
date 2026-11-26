import { beforeAll, describe, expect, it } from "vitest";
import type { NewDevice } from "../api/wire";
import { fromB64, toB64, toHexLower } from "../crypto/bytes";
import { copyOf } from "../crypto/escrow-v3.testkit";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes, sha256Sync } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { WebPin } from "./pinstore";
import { buildRegistration } from "./registration";

/**
 * The recovery choice at sign-up (design §7.7): "the operator may restore" seals the new UVK to the offered key
 * inside buildRegistration, the only place the UVK and the signing key both exist before the account does.
 */
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const pin = { instanceId: "11111111-1111-4111-8111-111111111111" } as unknown as WebPin;

const base = () => ({
  email: "dana@example.org", displayName: "Dana", password: "correct horse Battery 9 staple", kdfParams: KDF as KdfParams, signupTicket: "t", pin, ageConfirmed: true,
  device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) } as NewDevice, nowMs: 1_763_164_800_000,
});

describe("buildRegistration and the operator-recovery choice", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("without a choice the account registers private, with no escrow", async () => {
    const reg = await buildRegistration(base());
    expect(reg.request.recovery).toEqual({ posture: "private" });
  }, 60_000);

  it("with the offered key the escrow is sealed and named by the key's full fingerprint", async () => {
    const key = boxKeypairFromSeed(randomBytes(32)).publicKey;
    const fp = toHexLower(sha256Sync(key));
    const reg = await buildRegistration({ ...base(), operatorEscrow: { recoveryPub: key, fp } });
    expect(reg.request.recovery.posture).toBe("operator");
    const r = reg.request.recovery as { posture: "operator"; escrow: { sealed: string; fingerprint: string } };
    expect(r.escrow.fingerprint).toBe(fp);
    expect(r.escrow.sealed.length).toBeGreaterThan(100);
  }, 60_000);

  it("spec 04 §3: the copy is version 3 and names the address this registration sends, in its emailNorm", async () => {
    const kp = boxKeypairFromSeed(randomBytes(32));
    const fp = toHexLower(sha256Sync(kp.publicKey));
    for (const [typed, named] of [["dana@example.org", "dana@example.org"], [" Dana@Example.ORG", "dana@example.org"]] as const) {
      const reg = await buildRegistration({ ...base(), email: typed, operatorEscrow: { recoveryPub: kp.publicKey, fp } });
      const r = reg.request.recovery as { posture: "operator"; escrow: { sealed: string } };
      expect(copyOf(r.escrow.sealed, kp)).toEqual({ v: 3, email: named });
      // The copy's size with a 13-digit issuedAt: 455 + E bytes, E the characters of the address's base64url (478 for E = 23).
      expect(fromB64(r.escrow.sealed).length).toBe(455 + toB64(new TextEncoder().encode(named)).length);
    }
  }, 120_000);

  it("a key that does not hash to the verified fingerprint registers nothing", async () => {
    const key = boxKeypairFromSeed(randomBytes(32)).publicKey;
    const other = toHexLower(sha256Sync(randomBytes(32)));
    await expect(buildRegistration({ ...base(), operatorEscrow: { recoveryPub: key, fp: other } })).rejects.toThrow();
  }, 60_000);
});
