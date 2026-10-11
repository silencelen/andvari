import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { Account } from "../vault/account";
import { fromB64, toB64 } from "./bytes";
import type { KdfParams } from "./keys";
import { boxKeypairFromSeed, ed25519PkToCurve25519, randomBytes, signDetached, signKeypairFromSeed, signVerifyDetached } from "./provider";
import {
  type BlobFormat,
  buildSignedStatement,
  encodeStatement,
  formatOf,
  parseStatement,
  type Statement,
  SignedStatementError,
  signedMessage,
  verifySignedStatement,
  type EscrowStatementVerifier,
} from "./signedstatement";
import { fingerprint as orgFingerprint } from "./escrow";
import { sealOpen } from "./provider";
import { CryptoError, initSodium } from "./sodium";

/**
 * The anchored escrow verifier is module-private (security review 2026-10, A5): escrow.ts claims it once.
 * This suite grades it in an ISOLATED module registry (fresh signedstatement + sodium instances) where no
 * escrow.ts has claimed it yet. Verdicts are read duck-typed, since the fresh SignedStatementError is a
 * different class object.
 */
let verifyEscrowStatement: EscrowStatementVerifier;
async function claimIsolatedEscrowVerifier(): Promise<EscrowStatementVerifier> {
  vi.resetModules();
  const sodium = await import("./sodium");
  await sodium.initSodium();
  const mod = await import("./signedstatement");
  return mod.claimEscrowVerifier();
}


/**
 * SignedStatement v2 + the joint Ed25519 signing key (security review 2026-10, root cause A §1.1–§1.3),
 * graded off the SAME spec/test-vectors/signedstatement.json the Kotlin engine consumes
 * (core/src/jvmTest/.../crypto/SignedStatementVectorTest.kt). The vector's bytes come from an
 * independent oracle; the rejection rows are the point, each must fail closed with its exact verdict.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "signedstatement.json", "utf-8"));
const sg = JSON.parse(readFileSync(vectorsDir + "sharedgrant.json", "utf-8"));

const hex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const enc = (s: string) => new TextEncoder().encode(s);

/** Escrow statements verify only through the ANCHORED wrapper (A4 / A3 review); the vector rows use the
 *  valid escrow case's own account and org key as the anchor, which is what an honest recovery supplies. */
function verifyAny(frame: Uint8Array, code: number, pin: Uint8Array) {
  if (code === 2) return verifyEscrowStatement(frame, v.valid[1].fields.userId, pin, v.valid[1].fields.recoveryFp);
  return verifySignedStatement(frame, code as 1, pin);
}

function statementOf(f: Record<string, string>, purposeCode: number): Statement {
  if (purposeCode === 1) {
    return {
      purpose: "vault-grant", from: f.from!, to: f.to!, toKey: fromB64(f.toKey!), vaultId: f.vaultId!,
      grantId: fromB64(f.grantId!), issuedAt: Number(f.issuedAt), vk: fromB64(f.vk!),
    };
  }
  return {
    purpose: "escrow-uvk", userId: f.userId!, identityKey: fromB64(f.identityKey!), recoveryFp: f.recoveryFp!,
    issuedAt: Number(f.issuedAt), key: fromB64(f.key!),
  };
}

function verdictOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    if (e instanceof SignedStatementError) return e.verdict;
    if (e && typeof (e as { verdict?: unknown }).verdict === "string") return (e as { verdict: string }).verdict;
    throw e;
  }
  return "ACCEPTED";
}

describe("signedstatement.json — joint key + SignedStatement v2", () => {
  beforeAll(async () => {
    await initSodium();
    verifyEscrowStatement ??= await claimIsolatedEscrowVerifier();
  });

  it("the joint signing key maps to the EXISTING identityPub (sharedgrant.json member)", () => {
    const jk = v.jointKey;
    expect(jk.seedB64).toBe(sg.memberSeedB64);
    expect(jk.identityPubB64).toBe(sg.memberIdentityPubB64);
    const seed = fromB64(jk.seedB64);
    const sign = signKeypairFromSeed(seed);
    expect(sign.publicKey).toEqual(fromB64(jk.signPubB64));
    expect(sign.privateKey).toEqual(fromB64(jk.signSecretB64));
    expect(ed25519PkToCurve25519(sign.publicKey)).toEqual(fromB64(jk.curveOfSignPubB64));
    expect(ed25519PkToCurve25519(sign.publicKey)).toEqual(boxKeypairFromSeed(seed).publicKey);
    // −A maps to the same u: only the signature can tell them apart.
    expect(ed25519PkToCurve25519(fromB64(jk.negatedSignPubB64))).toEqual(fromB64(jk.identityPubB64));
    expect(signKeypairFromSeed(fromB64(jk.other.seedB64)).publicKey).toEqual(fromB64(jk.other.signPubB64));
    expect(ed25519PkToCurve25519(fromB64(jk.other.signPubB64))).toEqual(fromB64(jk.other.identityPubB64));
  });

  it("the mapping holds for random seeds", () => {
    for (let i = 0; i < 32; i++) {
      const seed = randomBytes(32);
      expect(ed25519PkToCurve25519(signKeypairFromSeed(seed).publicKey)).toEqual(boxKeypairFromSeed(seed).publicKey);
    }
  });

  it("primitives fail closed on bad input", () => {
    expect(() => ed25519PkToCurve25519(new Uint8Array(31))).toThrow(CryptoError);
    expect(() => ed25519PkToCurve25519(new Uint8Array(33))).toThrow(CryptoError);
    expect(() => ed25519PkToCurve25519(new Uint8Array(32))).toThrow(CryptoError); // small order
    expect(() => signKeypairFromSeed(new Uint8Array(31))).toThrow(CryptoError);
    expect(() => signDetached(new Uint8Array(63), enc("m"))).toThrow(CryptoError);
    const kp = signKeypairFromSeed(randomBytes(32));
    const sig = signDetached(kp.privateKey, enc("m"));
    expect(sig.length).toBe(64);
    expect(signVerifyDetached(kp.publicKey, sig, enc("m"))).toBe(true);
    expect(signVerifyDetached(kp.publicKey, sig, enc("m\0"))).toBe(false);
    expect(signVerifyDetached(kp.publicKey, sig.subarray(0, 63), enc("m"))).toBe(false);
    expect(signVerifyDetached(new Uint8Array(31), sig, enc("m"))).toBe(false);
  });

  it("valid cases: encode, M, deterministic signature, frame and verify are byte-exact", () => {
    const signer = signKeypairFromSeed(fromB64(v.jointKey.seedB64));
    const pin = fromB64(v.pinnedIdentityPubB64);
    for (const c of v.valid) {
      const st = statementOf(c.fields, c.purposeCode);
      const bytes = enc(c.statementUtf8);
      expect(encodeStatement(st), `${c.name}: canonical bytes`).toEqual(bytes);
      const m = signedMessage(c.purposeCode, signer.publicKey, bytes);
      expect(m, `${c.name}: M`).toEqual(hex(c.messageHex));
      expect(signDetached(signer.privateKey, m), `${c.name}: deterministic Ed25519`).toEqual(fromB64(c.signatureB64));
      expect(buildSignedStatement(signer, st), `${c.name}: frame bytes`).toEqual(fromB64(c.frameB64));
      const parsed = parseStatement(c.purposeCode, bytes);
      expect(parsed.purpose).toBe(st.purpose);
      if (parsed.purpose === "escrow-uvk" && st.purpose === "escrow-uvk") expect(parsed.userId).toBe(st.userId);
      if (parsed.purpose === "vault-grant" && st.purpose === "vault-grant") expect(parsed.from).toBe(st.from);
      const verified = verifyAny(fromB64(c.frameB64), c.purposeCode, pin);
      expect(verified.statement).toEqual(st);
      expect(verified.signerPub).toEqual(signer.publicKey);
    }
  });

  it("format detection", () => {
    for (const c of v.formatDetect) {
      const want: BlobFormat = c.format === "v1" ? "v1-json" : c.format === "v2" ? "v2-signed" : "unknown";
      expect(formatOf(hex(c.firstBytesHex)), c.firstBytesHex).toBe(want);
    }
  });

  it("rejectStatement: every strictness rule fails closed with its verdict", () => {
    expect(v.rejectStatement.length).toBeGreaterThanOrEqual(40);
    for (const c of v.rejectStatement) {
      expect(verdictOf(() => parseStatement(c.purposeCode, fromB64(c.statementB64))), c.why).toBe(c.verdict);
    }
  });

  it("reject: the one binding helper fails closed with the exact verdict", () => {
    const pinned = fromB64(v.pinnedIdentityPubB64);
    for (const c of v.reject) {
      const pin = c.pinnedIdentityPubB64 !== undefined ? fromB64(c.pinnedIdentityPubB64) : pinned;
      expect(verdictOf(() => verifyAny(fromB64(c.frameB64), c.expectedPurposeCode, pin)), c.why).toBe(c.verdict);
    }
  });

  it("encode refuses values outside the closed grammar", () => {
    const good = statementOf(v.valid[0].fields, 1) as Extract<Statement, { purpose: "vault-grant" }>;
    expect(() => encodeStatement({ ...good, vaultId: good.vaultId.toUpperCase() })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, from: 'x","role":"owner' })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, vk: new Uint8Array(31) })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, toKey: new Uint8Array(33) })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, grantId: new Uint8Array(32) })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, issuedAt: 0 })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, issuedAt: 2 ** 53 })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, issuedAt: 1.5 })).toThrow(CryptoError);
    expect(() => encodeStatement({ ...good, to: good.from })).toThrow(CryptoError);
    const esc = statementOf(v.valid[1].fields, 2) as Extract<Statement, { purpose: "escrow-uvk" }>;
    expect(() => encodeStatement({ ...esc, recoveryFp: esc.recoveryFp.toUpperCase() })).toThrow(CryptoError);
  });

  it("fresh keys verify only under their own pin", () => {
    const seed = randomBytes(32);
    const signer = signKeypairFromSeed(seed);
    const st = statementOf(v.valid[0].fields, 1);
    const frame = buildSignedStatement(signer, st);
    expect(verifySignedStatement(frame, 1, boxKeypairFromSeed(seed).publicKey).statement).toEqual(st);
    expect(verdictOf(() => verifySignedStatement(frame, 1, fromB64(v.pinnedIdentityPubB64)))).toBe("signer_not_pinned_key");
  });
});

describe("Account — joint signing key (owner decision: joint key)", () => {
  const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
  const PASSWORD = "correct horse battery staple";
  beforeAll(async () => {
    await initSodium();
    verifyEscrowStatement ??= await claimIsolatedEscrowVerifier();
  });

  it("is derived at enrol and unlock and maps to identityPub; its statements verify only under its own pin", async () => {
    const a = await Account.enroll({ inviteToken: "inv", email: "a@x.com", displayName: "a", password: PASSWORD, kdfParams: KDF });
    const b = await Account.enroll({ inviteToken: "inv", email: "b@x.com", displayName: "b", password: PASSWORD, kdfParams: KDF });
    expect(ed25519PkToCurve25519(a.account.signPub)).toEqual(a.account.identityPub);
    const unlocked = await Account.unlock(a.request.userId, PASSWORD, {
      kdfSalt: a.request.kdfSalt,
      kdfParams: a.request.kdfParams,
      wrappedUvk: a.request.wrappedUvk,
      encryptedIdentitySeed: a.request.encryptedIdentitySeed,
      identityPub: a.request.identityPub,
      escrowFingerprint: "",
    });
    expect(unlocked.signPub).toEqual(a.account.signPub);

    // The account's only signing path is escrow v2 (A4): the joint key signs the statement the
    // re-seal produces, which verifies under the account's own identity and no other.
    const org = boxKeypairFromSeed(randomBytes(32));
    const orgFp = await orgFingerprint(org.publicKey);
    const { sealed } = await unlocked.resealEscrowFor(toB64(org.publicKey), orgFp);
    const frame = sealOpen(org.publicKey, org.privateKey, fromB64(sealed));
    const verified = verifyEscrowStatement(frame, a.request.userId, a.account.identityPub, orgFp);
    expect(verified.signerPub).toEqual(a.account.signPub);
    expect(verdictOf(() => verifyEscrowStatement(frame, a.request.userId, b.account.identityPub, orgFp))).toBe("signer_not_pinned_key");
  });
});
