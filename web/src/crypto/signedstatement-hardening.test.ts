import { beforeAll, describe, expect, it } from "vitest";
import { Account } from "../vault/account";
import type { KdfParams } from "./keys";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "./provider";
import {
  buildSignedStatement,
  type EscrowUvkStatement,
  parseStatement,
  SignedStatementError,
  type Statement,
  type UnverifiedStatement,
  VerifiedStatement,
  verifyEscrowStatement,
  verifySignedStatement,
} from "./signedstatement";
import { initSodium } from "./sodium";

/**
 * The A3-review hardening A4 (the codec's first caller) had to land (security review 2026-10), web twin
 * of core SignedStatementHardeningTest: escrow fields bound to the OUT-OF-BAND anchor, unverified parse
 * output a distinct type, verified data read-only, and no public `Account.signStatement`.
 */
const USER = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const ORG_FP = "14f1bf4220e132f39314cabd75e7fa8d88348a699154a7965e64e76321b54f49";

function member() {
  const seed = randomBytes(32);
  return { signer: signKeypairFromSeed(seed), identityPub: boxKeypairFromSeed(seed).publicKey };
}
const escrow = (identityKey: Uint8Array, userId = USER): EscrowUvkStatement => ({
  purpose: "escrow-uvk", userId, identityKey, recoveryFp: ORG_FP, issuedAt: 1791590400000, key: randomBytes(32),
});
const verdictOf = (f: () => unknown) => {
  try {
    f();
  } catch (e) {
    if (e instanceof SignedStatementError) return e.verdict;
    throw e;
  }
  return null;
};

describe("SignedStatement hardening (A3 review, landed in A4)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("an escrow statement whose embedded identity differs from the anchor is rejected despite a valid signature", () => {
    const m = member();
    const other = member();
    const frame = buildSignedStatement(m.signer, escrow(other.identityPub));
    expect(verdictOf(() => verifyEscrowStatement(frame, USER, m.identityPub, ORG_FP))).toBe("identity_mismatch");
    // Using the statement's OWN identity as the pin (self-pinning) fails too: the signer is not that key.
    expect(verdictOf(() => verifyEscrowStatement(frame, USER, other.identityPub, ORG_FP))).toBe("signer_not_pinned_key");
  });

  it("is bound to the expected account and recovery key; the generic helper refuses escrow", () => {
    const m = member();
    const frame = buildSignedStatement(m.signer, escrow(m.identityPub));
    expect(verdictOf(() => verifyEscrowStatement(frame, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", m.identityPub, ORG_FP))).toBe("user_mismatch");
    expect(verdictOf(() => verifyEscrowStatement(frame, USER, m.identityPub, "0".repeat(64)))).toBe("recovery_fp_mismatch");
    expect(verifyEscrowStatement(frame, USER, m.identityPub, ORG_FP).statement.purpose).toBe("escrow-uvk");
    expect(() => verifySignedStatement(frame, 2 as 1, m.identityPub)).toThrow(/verifyEscrowStatement/);
  });

  it("unverified parse output is a distinct type, not assignable where a verified value is required", () => {
    const m = member();
    const frame = buildSignedStatement(m.signer, escrow(m.identityPub));
    const parsed: UnverifiedStatement = parseStatement(2, frame.subarray(101));
    // @ts-expect-error — an UnverifiedStatement is not a Statement (no key material, branded)
    const asStatement: Statement = parsed;
    // @ts-expect-error — nor a VerifiedStatement (nominal: private fields + module-private mint token)
    const asVerified: VerifiedStatement = parsed;
    void asStatement;
    void asVerified;
    expect(parsed instanceof VerifiedStatement).toBe(false);
    expect(Object.keys(parsed).sort()).toEqual(["purpose", "recoveryFp", "userId"]);
    // A VerifiedStatement cannot be minted outside the module.
    // @ts-expect-error — the constructor needs the module-private token
    expect(() => new VerifiedStatement(Symbol("verified-statement"), escrow(m.identityPub), m.signer.publicKey)).toThrow();
  });

  it("verified data is read-only", () => {
    const m = member();
    const st = escrow(m.identityPub);
    const verified = verifyEscrowStatement(buildSignedStatement(m.signer, st), USER, m.identityPub, ORG_FP);
    const held = (verified.statement as EscrowUvkStatement).key;
    (verified.statement as EscrowUvkStatement).key.fill(0);
    (verified.statement as EscrowUvkStatement).identityKey.fill(0);
    verified.signerPub.fill(0);
    st.key.fill(0); // mutating the caller's input after verify cannot reach the verified copy either
    expect((verified.statement as EscrowUvkStatement).key).toEqual(held);
    expect((verified.statement as EscrowUvkStatement).identityKey).toEqual(m.identityPub);
    expect(verified.signerPub).toEqual(m.signer.publicKey);
    expect(Object.isFrozen(verified.statement)).toBe(true);
  });

  it("Account exposes no signStatement (module-private, core `internal` parity)", async () => {
    const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
    const { account } = await Account.enroll({ inviteToken: "inv", email: "a@x.com", displayName: "a", password: "pw", kdfParams: KDF });
    // @ts-expect-error — no public signing method on Account
    expect(account.signStatement).toBeUndefined();
    expect("signStatement" in account).toBe(false);
  });
});
