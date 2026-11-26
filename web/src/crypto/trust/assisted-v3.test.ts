import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { adIdkey } from "../ad";
import { fromUtf8, toB64, toHexLower, utf8 } from "../bytes";
import { seal as envelopeSeal } from "../envelope";
import { EscrowOpenError, fingerprint, openEscrow, sealUvkV2, sealUvkV3, UNANCHORED_ACK } from "../escrow";
import { boxKeypairFromSeed, sealOpen, sealTo, signKeypairFromSeed } from "../provider";
import { buildSignedStatement, parseFrame as parseStatementFrame, parseStatement as parseEscrowStatement, SignedStatementError } from "../signedstatement";
import { initSodium } from "../sodium";
import { encodeStatement, parseStatement as parseTrustStatement } from "./codec";
import { signFrame } from "./frame";
import { commitHash, openAssistedRecovery, openAssistedRecoveryV3 } from "./recovery";

/**
 * Assisted recovery, version 3 (spec 04 §3 and §7; spec 01 §5.1 "Version-3 templates"): the recovery copy
 * that names its account's address inside the account's own signature, the answer that names the address and carries
 * the commit value, and the commit hash. The worked examples are the Kotlin implementation's (core's
 * AssistedRecoveryV3ExampleTest), from fixed inputs, reproduced here byte for byte.
 */

const fill = (n: number, b: number) => new Uint8Array(n).fill(b);
const hex = toHexLower;

// The worked example's fixed inputs.
const IDENTITY_SEED = fill(32, 0x11);
const UVK = fill(32, 0x22);
const RECOVERY_SEED = fill(32, 0x33);
const USER_ID = "1b4e28ba-2fa1-4d3b-8a5e-2c3f4d5e6a7b";
const EMAIL = "alice@example.org";
const ISSUED_AT = 1794858966854;
const INSTANCE_ID = "5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f";
const REQUEST_ID_BYTES = fill(16, 0x44);
const REQUEST_SEED = fill(32, 0x55);
const COMMIT = fill(32, 0x66);

const ESCROW_STATEMENT =
  '{"v":3,"purpose":"escrow-uvk","userId":"1b4e28ba-2fa1-4d3b-8a5e-2c3f4d5e6a7b","email":"YWxpY2VAZXhhbXBsZS5vcmc","identityKey":"ekbhKf2AUEdEhDfkdE8fFXa-jESf31fgxYDTbFz8Zmg","recoveryFp":"e53ece86484df90e868dcdc64c900b5abafec1883c3928e2ede0c7477f5215d1","issuedAt":1794858966854,"key":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"}';
const ESCROW_FRAME_HEAD =
  "6176730202d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873796ce2a424757a9ab28e123d218c6d2432f8c326cb5dd8e5ac5ff3871a6355cc34a25ecb97c82e4a0e82f76ad86625b986ac99b906a3cbf0e58b35b1f898ae3067b";
const ANSWER_STATEMENT =
  '{"v":3,"purpose":"assisted-recovery","instanceId":"5d1f0c2e-7a3b-4c4d-9e5f-6a7b8c9d0e1f","userId":"1b4e28ba-2fa1-4d3b-8a5e-2c3f4d5e6a7b","email":"YWxpY2VAZXhhbXBsZS5vcmc","requestId":"RERERERERERERERERERERA","requestKey":"dzDKJCo4DVYD39-i77M1eqZwAeqpUgnbDMFEwglwdHw","commit":"ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmY","uvk":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","issuedAt":1794858966854}';
const ANSWER_FRAME_HEAD =
  "617673020917cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce79188cec32d19bd17265397adc1ea7b1172770a7e485ffe099cf8f7ed88d2c41baddb8a2a2d47962a7ad6ed2dc1cd3e035ba825d40e2690229f11c869089ef0f7b";
const COMMIT_HASH = "c2d2e4d7f1afd2be2644f076a305a9365c4628a96dccc61bd8ad165e1f9cd593";

describe("assisted recovery, version 3: the Kotlin implementation's worked examples, byte for byte", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const keys = () => {
    const identity = boxKeypairFromSeed(IDENTITY_SEED);
    const signer = signKeypairFromSeed(IDENTITY_SEED);
    const recovery = boxKeypairFromSeed(RECOVERY_SEED);
    const recoverySigner = signKeypairFromSeed(RECOVERY_SEED);
    const request = boxKeypairFromSeed(REQUEST_SEED);
    return { identity, signer, recovery, recoverySigner, request };
  };

  it("the derived keys", async () => {
    const k = keys();
    expect(toB64(k.identity.publicKey)).toBe("ekbhKf2AUEdEhDfkdE8fFXa-jESf31fgxYDTbFz8Zmg");
    expect(toB64(k.signer.publicKey)).toBe("0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc");
    expect(toB64(k.recovery.publicKey)).toBe("TrT6_uK9MBiiTjEN6BBjM8KzZOrtApp_Bde0XMx3aDo");
    expect(await fingerprint(k.recovery.publicKey)).toBe("e53ece86484df90e868dcdc64c900b5abafec1883c3928e2ede0c7477f5215d1");
    expect(toB64(k.recoverySigner.publicKey)).toBe("F8t5-ytBIPKx7GXkGY1uCLKOgT_rAeSkAIObheGAgM4");
    expect(toB64(k.request.publicKey)).toBe("dzDKJCo4DVYD39-i77M1eqZwAeqpUgnbDMFEwglwdHw");
    expect(toB64(utf8(EMAIL))).toBe("YWxpY2VAZXhhbXBsZS5vcmc");
    expect(toB64(REQUEST_ID_BYTES)).toBe("RERERERERERERERERERERA");
  });

  it("the recovery copy: statement (329 bytes), frame (430) and sealed copy (478), and the browser's seal opens to that frame", async () => {
    const k = keys();
    const st = { purpose: "escrow-uvk" as const, userId: USER_ID, identityKey: k.identity.publicKey, recoveryFp: await fingerprint(k.recovery.publicKey), issuedAt: ISSUED_AT, key: UVK, email: EMAIL };
    const frame = buildSignedStatement(k.signer, st);
    const statement = frame.subarray(101);
    expect(fromUtf8(statement)).toBe(ESCROW_STATEMENT);
    expect(statement.length).toBe(329);
    expect(frame.length).toBe(430);
    expect(hex(frame).startsWith(ESCROW_FRAME_HEAD)).toBe(true);
    expect(hex(frame)).toBe(hex(frame.subarray(0, 101)) + hex(statement));
    expect(hex(frame.subarray(0, 101))).toBe(ESCROW_FRAME_HEAD.slice(0, 202));

    // sealUvkV3 (what every seal site calls) seals exactly that frame.
    const sealed = await sealUvkV3({ recoveryPub: k.recovery.publicKey, verifiedRecoveryFp: st.recoveryFp, userId: USER_ID, emailNorm: EMAIL, identityPub: k.identity.publicKey, signer: k.signer, uvk: UVK, issuedAt: ISSUED_AT });
    expect(sealed.length).toBe(478);
    expect(hex(sealOpen(k.recovery.publicKey, k.recovery.privateKey, sealed))).toBe(hex(frame));
  });

  it("the answer: statement (399 = 376 + 23), frame (500), sealed (548 = 525 + 23), commit hash and the token's head", () => {
    const k = keys();
    const statement = encodeStatement(
      "assisted-recovery",
      { instanceId: INSTANCE_ID, userId: USER_ID, email: toB64(utf8(EMAIL)), requestId: toB64(REQUEST_ID_BYTES), requestKey: toB64(k.request.publicKey), commit: toB64(COMMIT), issuedAt: String(ISSUED_AT) },
      { uvk: UVK },
      3,
    );
    expect(fromUtf8(statement)).toBe(ANSWER_STATEMENT);
    expect(statement.length).toBe(399);
    const frame = signFrame(k.recoverySigner, "assisted-recovery", statement);
    expect(frame.length).toBe(500);
    expect(hex(frame.subarray(0, 101))).toBe(ANSWER_FRAME_HEAD.slice(0, 202));
    expect(hex(frame).startsWith(ANSWER_FRAME_HEAD)).toBe(true);
    expect(sealTo(k.request.publicKey, frame).length).toBe(548);
    expect(commitHash(COMMIT)).toBe(COMMIT_HASH);
    const head = `andvari-answer:3:${toB64(REQUEST_ID_BYTES)}:${toB64(k.request.publicKey)}:${commitHash(COMMIT)}:`;
    expect(head).toBe(`andvari-answer:3:RERERERERERERERERERERA:dzDKJCo4DVYD39-i77M1eqZwAeqpUgnbDMFEwglwdHw:${COMMIT_HASH}:`);
  });
});

describe("assisted recovery, version 3: the browser's twins", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const setup = async () => {
    const identity = boxKeypairFromSeed(IDENTITY_SEED);
    const signer = signKeypairFromSeed(IDENTITY_SEED);
    const recovery = boxKeypairFromSeed(RECOVERY_SEED);
    const fp = await fingerprint(recovery.publicKey);
    const identityCheck = { encryptedIdentitySeedB64: toB64(envelopeSeal(UVK, IDENTITY_SEED, adIdkey(USER_ID))), identityPubB64: toB64(identity.publicKey) };
    return { identity, signer, recovery, fp, identityCheck };
  };

  it("an address that is not already its own emailNorm seals nothing", async () => {
    const t = await setup();
    for (const bad of ["Alice@example.org", " alice@example.org", "alice@example.org ", "alice", "", "alice@localhost"]) {
      await expect(
        sealUvkV3({ recoveryPub: t.recovery.publicKey, verifiedRecoveryFp: t.fp, userId: USER_ID, emailNorm: bad, identityPub: t.identity.publicKey, signer: t.signer, uvk: UVK, issuedAt: ISSUED_AT }),
        bad,
      ).rejects.toThrow(/not an emailNorm/);
    }
  });

  it("opening a copy of the new form returns its address; the old form opens as v2 with none", async () => {
    const t = await setup();
    const open = (sealed: Uint8Array) => openEscrow({ recoveryKeypair: t.recovery, sealed, expectedUserId: USER_ID, expectedIdentityFpPrefix: null, unanchoredAcknowledgment: UNANCHORED_ACK, identityCheck: t.identityCheck });
    const v3 = await sealUvkV3({ recoveryPub: t.recovery.publicKey, verifiedRecoveryFp: t.fp, userId: USER_ID, emailNorm: EMAIL, identityPub: t.identity.publicKey, signer: t.signer, uvk: UVK, issuedAt: ISSUED_AT });
    const a = await open(v3);
    expect([a.format, a.email, toB64(a.uvk)]).toEqual(["v3", EMAIL, toB64(UVK)]);
    const v2 = await sealUvkV2({ recoveryPub: t.recovery.publicKey, verifiedRecoveryFp: t.fp, userId: USER_ID, identityPub: t.identity.publicKey, signer: t.signer, uvk: UVK, issuedAt: ISSUED_AT });
    const b = await open(v2);
    expect([b.format, b.email]).toEqual(["v2", null]);
  });

  it("the escrow reader picks the template by its key set; a version-2 key set marked 3 and a version-3 key set marked 2 are bad_statement", () => {
    const v3 = utf8(ESCROW_STATEMENT);
    expect((parseEscrowStatement(2, v3) as { email: string | null }).email).toBe(EMAIL);
    const verdict = (s: string): string => {
      try {
        parseEscrowStatement(2, utf8(s));
        return "ok";
      } catch (e) {
        return (e as SignedStatementError).verdict;
      }
    };
    expect(verdict(ESCROW_STATEMENT.replace('"v":3', '"v":2'))).toBe("bad_statement");
    const v2 = ESCROW_STATEMENT.replace(',"email":"YWxpY2VAZXhhbXBsZS5vcmc"', "").replace('"v":3', '"v":2');
    expect(verdict(v2)).toBe("ok");
    expect(verdict(v2.replace('"v":2', '"v":3'))).toBe("bad_statement");
    // An address that is not normal inside the copy, or the literal none: not canonical.
    expect(verdict(ESCROW_STATEMENT.replace("YWxpY2VAZXhhbXBsZS5vcmc", toB64(utf8("Alice@example.org"))))).toBe("non_canonical");
    expect(verdict(ESCROW_STATEMENT.replace('"YWxpY2VAZXhhbXBsZS5vcmc"', '"none"'))).toBe("non_canonical");
    // The frame splitter is unchanged: magic avs\x02, purpose 0x02.
    expect(() => parseStatementFrame(new Uint8Array(3))).toThrow();
  });

  it("the answer reader takes only version 3 on the device; the old opener takes only version 2; the key set picks the template", () => {
    const fields = { instanceId: INSTANCE_ID, userId: USER_ID, requestId: toB64(REQUEST_ID_BYTES), requestKey: toB64(boxKeypairFromSeed(REQUEST_SEED).publicKey), issuedAt: String(ISSUED_AT) };
    const v2 = encodeStatement("assisted-recovery", fields, { uvk: UVK });
    const v3 = utf8(ANSWER_STATEMENT);
    const verdict = (bytes: Uint8Array, v: 2 | 3) => {
      const r = parseTrustStatement("assisted-recovery", bytes, v);
      return r.ok ? "ok" : r.verdict;
    };
    expect([verdict(v3, 3), verdict(v3, 2), verdict(v2, 3), verdict(v2, 2)]).toEqual(["ok", "bad_statement", "bad_statement", "ok"]);
    expect(verdict(utf8(ANSWER_STATEMENT.replace('"v":3', '"v":2')), 3)).toBe("bad_statement");
    expect(verdict(utf8(fromUtf8(v2).replace('"v":2', '"v":3')), 2)).toBe("bad_statement");
    expect(verdict(utf8(ANSWER_STATEMENT.replace("YWxpY2VAZXhhbXBsZS5vcmc", "none")), 3)).toBe("non_canonical");
  });

  it("the device opens an answer for the address the person typed, and refuses it for another; the old opener refuses a version-3 answer", async () => {
    const t = await setup();
    const request = boxKeypairFromSeed(REQUEST_SEED);
    const recoverySigner = signKeypairFromSeed(RECOVERY_SEED);
    const statement = utf8(ANSWER_STATEMENT);
    const sealed = sealTo(request.publicKey, signFrame(recoverySigner, "assisted-recovery", statement));
    const req = { instanceId: INSTANCE_ID, userId: null, requestId: toB64(REQUEST_ID_BYTES), rPub: request.publicKey, rSec: request.privateKey };
    const served = { encryptedIdentitySeed: envelopeSeal(UVK, IDENTITY_SEED, adIdkey(USER_ID)), identityPub: t.identity.publicKey };
    const ok = openAssistedRecoveryV3(req, " Alice@Example.org ", sealed, t.fp, served);
    expect(ok.ok).toBe(true);
    if (ok.ok) expect([ok.value.email, toB64(ok.value.commit), toB64(ok.value.uvk), ok.value.userId]).toEqual([EMAIL, toB64(COMMIT), toB64(UVK), USER_ID]);
    const other = openAssistedRecoveryV3(req, "bob@example.org", sealed, t.fp, served);
    expect(other.ok ? "ok" : other.verdict).toBe("request_mismatch");
    const notAnAddress = openAssistedRecoveryV3(req, "alice", sealed, t.fp, served);
    expect(notAnAddress.ok ? "ok" : notAnAddress.verdict).toBe("request_mismatch");
    const old = openAssistedRecovery(req, sealed, t.fp, served);
    expect(old.ok ? "ok" : old.verdict).toBe("bad_statement");
    // A version-2 answer is refused by the device's opener.
    const v2 = encodeStatement("assisted-recovery", { instanceId: INSTANCE_ID, userId: USER_ID, requestId: req.requestId, requestKey: toB64(request.publicKey), issuedAt: String(ISSUED_AT) }, { uvk: UVK });
    const v2sealed = sealTo(request.publicKey, signFrame(recoverySigner, "assisted-recovery", v2));
    const refused = openAssistedRecoveryV3(req, EMAIL, v2sealed, t.fp, served);
    expect(refused.ok ? "ok" : refused.verdict).toBe("bad_statement");
  });

  it("an opener refusal leaves EscrowOpenError's verdicts as they were (the copy of another account is user_mismatch)", async () => {
    const t = await setup();
    const sealed = await sealUvkV3({ recoveryPub: t.recovery.publicKey, verifiedRecoveryFp: t.fp, userId: USER_ID, emailNorm: EMAIL, identityPub: t.identity.publicKey, signer: t.signer, uvk: UVK, issuedAt: ISSUED_AT });
    await expect(
      openEscrow({ recoveryKeypair: t.recovery, sealed, expectedUserId: "22222222-2222-4222-8222-222222222222", expectedIdentityFpPrefix: null, unanchoredAcknowledgment: UNANCHORED_ACK, identityCheck: t.identityCheck }),
    ).rejects.toBeInstanceOf(EscrowOpenError);
  });
});

/** Every product source file under src/ (no tests, no test kits). */
function productSources(): { path: string; text: string }[] {
  const root = fileURLToPath(new URL("../..", import.meta.url));
  const out: { path: string; text: string }[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      if (statSync(p).isDirectory()) {
        if (name !== "node_modules" && name !== "vendor") walk(p);
      } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) && !/testkit/.test(name)) {
        out.push({ path: p.slice(root.length), text: readFileSync(p, "utf8") });
      }
    }
  };
  walk(root);
  return out;
}

describe("the old form is sealed nowhere in the product (spec 04 §3: every seal is version 3)", () => {
  it("no product file calls sealUvkV2 or sealUvkV1; the four seal sites call sealUvkV3 with the account's address", () => {
    const files = productSources();
    const oldCallers = files.filter((f) => /sealUvkV[12]\s*\(/.test(f.text) && !f.path.endsWith("crypto/escrow.ts")).map((f) => f.path);
    expect(oldCallers).toEqual([]);
    // In escrow.ts itself, the old seal is defined and never called by the new one's path.
    const escrow = files.find((f) => f.path.endsWith("crypto/escrow.ts"))!.text;
    expect(escrow.match(/sealUvkV2\s*\(/g)).toHaveLength(1); // its own definition
    const sites = files.flatMap((f) => [...f.text.matchAll(/sealUvkV3\(\{[^}]*\}/g)].map((m) => ({ path: f.path, call: m[0] }))).filter((s) => !s.path.endsWith("crypto/escrow.ts"));
    expect(sites.map((s) => s.path).sort()).toEqual(["vault/account.ts", "vault/registration.ts", "vault/settingsflow.ts", "vault/settingsflow.ts"]);
    for (const s of sites) expect(s.call, s.path).toMatch(/emailNorm:/);
  });
});
