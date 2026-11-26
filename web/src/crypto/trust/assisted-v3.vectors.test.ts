import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { concat, fromB64, fromUtf8, toB64, toHexLower, utf8 } from "../bytes";
import { EscrowOpenError, fingerprint, openEscrow, sealUvkV3 } from "../escrow";
import { boxKeypairFromSeed, sealOpen, signKeypairFromSeed } from "../provider";
import { buildSignedStatement, signedMessage } from "../signedstatement";
import { initSodium, sodium } from "../sodium";
import { encodeStatement } from "./codec";
import { signFrame } from "./frame";
import { emailNorm } from "./grammar";
import { commitHash, openAssistedRecoveryV3 } from "./recovery";
import { expectSections, gradeEvery, gradeEveryAsync, hexBytes } from "./vectors";

/**
 * The version-3 vectors of assisted recovery (spec 04 §3, §4, §7; spec 01 §5.1 and §5.5), written by the independent
 * oracle: `escrow-v3.json`, `recovery-v3.json` and `answer-reader.json`. Every row is graded here, or named as a row
 * that belongs to another client (the offline tool `recovery-cli`, the server, the operator consoles' shared reader):
 * the web seals and opens copies and opens answers, and has no tool, no server check and no operator console.
 *
 * The files are read from `spec/test-vectors/`; `ANDVARI_V3_VECTORS_DIR` points elsewhere only while they are not on
 * this branch yet. Without either, each file's suite says so by name instead of passing.
 */
const repoDir = fileURLToPath(new URL("../../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any | null {
  for (const dir of [repoDir, process.env.ANDVARI_V3_VECTORS_DIR]) {
    if (dir && existsSync(`${dir.replace(/\/?$/, "/")}${name}`)) return JSON.parse(readFileSync(`${dir.replace(/\/?$/, "/")}${name}`, "utf-8"));
  }
  return null;
}

/** crypto_box_seal with the row's fixed ephemeral secret, so the sealed bytes reproduce (a real seal draws it at random). */
function sealWithEphemeral(ephemeralSecret: Uint8Array, recipient: Uint8Array, message: Uint8Array): Uint8Array {
  const s = sodium();
  const epk = s.crypto_scalarmult_base(ephemeralSecret);
  const nonce = s.crypto_generichash(24, concat(epk, recipient));
  return concat(epk, s.crypto_box_easy(message, nonce, recipient, ephemeralSecret));
}

/** Rows of other clients: each named, counted, and checked to carry a name and an expectation. */
function nameForeign(owner: string, table: string, rows: readonly { name?: string; expect?: unknown }[]): string[] {
  expect(rows.length, `${table}: empty`).toBeGreaterThan(0);
  const names = rows.map((r, i) => r.name ?? `${table}[${i}]`);
  for (const r of rows) expect(r.expect, `${table} ${r.name}`).toBeDefined();
  console.info(`${table}: ${rows.length} rows belong to ${owner}, not this client: ${names.join(", ")}`);
  return names;
}

const escrowV3 = load("escrow-v3.json");
const recoveryV3 = load("recovery-v3.json");
const reader = load("answer-reader.json");

beforeAll(async () => {
  await initSodium();
});

(escrowV3 === null ? describe.skip : describe)(`escrow-v3.json${escrowV3 === null ? " is not on this branch yet: nothing graded" : ""}`, () => {
  const j = escrowV3;
  const account = (name: string) => j.accounts[name];

  it("sections: exactly the ones graded or named here", () => {
    expectSections(j, ["_about", "templates", "unanchoredAck", "sheet", "accounts", "identityFiles", "seal", "sealRefuse", "requestKey", "open", "assist"]);
  });

  it("templates: the version-3 and version-2 key orders are this client's", () => {
    expect(j.templates["escrow-uvk v3"].map((f: string[]) => f[0])).toEqual(["v", "purpose", "userId", "email", "identityKey", "recoveryFp", "issuedAt", "key"]);
    expect(j.templates["escrow-uvk v2"].map((f: string[]) => f[0])).toEqual(["v", "purpose", "userId", "identityKey", "recoveryFp", "issuedAt", "key"]);
  });

  it("seal: every row's statement, message, signature and frame byte for byte; the sealed copy too, with the row's ephemeral key; sealUvkV3 seals the same frame", async () => {
    const sheet = boxKeypairFromSeed(fromB64(j.sheet.seedB64));
    await gradeEveryAsync("escrow-v3 seal", j.seal, async (row: { name: string; input: Record<string, string | number>; expect: Record<string, string | number> }) => {
      const a = account(row.input.account as string);
      const seed = fromB64(a.seedB64);
      const identity = boxKeypairFromSeed(seed);
      const signer = signKeypairFromSeed(seed);
      const recoveryPub = fromB64(row.input.recoveryPubB64 as string);
      const fp = await fingerprint(recoveryPub);
      const norm = emailNorm(row.input.address as string);
      expect(norm, row.name).toBe(row.expect.emailNorm);
      const frame = buildSignedStatement(signer, { purpose: "escrow-uvk", userId: row.input.userId as string, identityKey: identity.publicKey, recoveryFp: fp, issuedAt: row.input.issuedAt as number, key: fromB64(row.input.uvkB64 as string), email: norm });
      const statement = frame.subarray(101);
      expect(fromUtf8(statement), row.name).toBe(row.expect.statementUtf8);
      expect(statement.length).toBe(row.expect.statementBytes);
      expect(toHexLower(signedMessage(2, signer.publicKey, statement)), row.name).toBe(row.expect.messageHex);
      expect(toB64(frame.subarray(37, 101)), row.name).toBe(row.expect.signatureB64);
      expect(toB64(frame), row.name).toBe(row.expect.frameB64);
      expect(frame.length).toBe(row.expect.frameBytes);
      const sealed = sealWithEphemeral(fromB64(row.input.ephemeralSecretB64 as string), recoveryPub, frame);
      expect(toB64(sealed), row.name).toBe(row.expect.sealedB64);
      expect(sealed.length).toBe(row.expect.sealedBytes);
      // What the seal sites call: the same frame inside a randomised seal.
      const live = await sealUvkV3({ recoveryPub, verifiedRecoveryFp: fp, userId: row.input.userId as string, emailNorm: norm!, identityPub: identity.publicKey, signer, uvk: fromB64(row.input.uvkB64 as string), issuedAt: row.input.issuedAt as number });
      if (toB64(recoveryPub) === toB64(sheet.publicKey)) expect(toB64(sealOpen(sheet.publicKey, sheet.privateKey, live)), row.name).toBe(row.expect.frameB64);
      expect(live.length).toBe(row.expect.sealedBytes);
    });
  });

  it("sealRefuse: an address with no emailNorm seals nothing", async () => {
    const a = account("alice");
    const seed = fromB64(a.seedB64);
    const recoveryPub = fromB64(j.sheet.recoveryPubB64);
    await gradeEveryAsync("escrow-v3 sealRefuse", j.sealRefuse, async (row: { name: string; address: string; expect: { sealed: boolean } }) => {
      expect(row.expect.sealed).toBe(false);
      expect(emailNorm(row.address), row.name).toBeNull();
      await expect(
        sealUvkV3({ recoveryPub, verifiedRecoveryFp: j.sheet.recoveryFp, userId: a.userId, emailNorm: row.address, identityPub: boxKeypairFromSeed(seed).publicKey, signer: signKeypairFromSeed(seed), uvk: fromB64(a.uvkB64), issuedAt: 1763524800000 }),
        row.name,
      ).rejects.toThrow(/not an emailNorm/);
    });
  });

  it("open: every row with an expectOpener is graded on the shared opener; the others are the tool's whole check (recovery-cli assist / verify), named", async () => {
    const sheet = boxKeypairFromSeed(fromB64(j.sheet.seedB64));
    type OpenRow = { name: string; input: Record<string, unknown>; expectOpener?: Record<string, unknown> };
    const mine = (j.open as OpenRow[]).filter((r) => r.expectOpener !== undefined);
    const theTools = (j.open as OpenRow[]).filter((r) => r.expectOpener === undefined);
    await gradeEveryAsync("escrow-v3 open (opener)", mine, async (row) => {
      const input = row.input;
      const file = input.identityFile === null || input.identityFile === undefined ? null : j.identityFiles[input.identityFile as string];
      let got: Record<string, unknown>;
      try {
        const o = await openEscrow({
          recoveryKeypair: sheet,
          sealed: fromB64(input.sealedB64 as string),
          expectedUserId: input.user as string,
          // The opener's null anchor IS unanchored mode; an anchor not given without --no-identity-anchor is an empty anchor
          // "as given" (the oracle: "takes the anchor as given (32..64 lowercase hex, else bad_anchor)").
          expectedIdentityFpPrefix: input.noIdentityAnchor === true ? null : ((input.identityFp as string | null | undefined) ?? ""),
          unanchoredAcknowledgment: (input.unanchoredAck as string | null | undefined) ?? null,
          identityCheck: file === null ? null : { encryptedIdentitySeedB64: file.encryptedIdentitySeedB64, identityPubB64: file.identityPubB64 },
        });
        got = { verdict: "ok", format: o.format, userId: o.userId, ...(o.email !== null ? { email: o.email } : {}), uvkB64: toB64(o.uvk), identityKeyB64: toB64(o.identityKey), anchored: o.anchored };
      } catch (e) {
        if (!(e instanceof EscrowOpenError)) throw e;
        got = { verdict: e.verdict };
      }
      expect(got, row.name).toEqual(row.expectOpener);
    });
    nameForeign("recovery-cli (the tool's whole check, no expectOpener)", "escrow-v3 open", theTools.map((r) => ({ name: r.name, expect: (r as unknown as { expect: unknown }).expect })));
  });

  it("assist: the whole recovery-cli assist run is the offline tool's, named", () => {
    nameForeign("recovery-cli assist", "escrow-v3 assist", j.assist);
  });
});

(recoveryV3 === null ? describe.skip : describe)(`recovery-v3.json${recoveryV3 === null ? " is not on this branch yet: nothing graded" : ""}`, () => {
  const j = recoveryV3;
  const signerOf = (name: string) => signKeypairFromSeed(fromB64(j.keys[name].seedB64));

  it("sections: exactly the ones graded or named here", () => {
    expectSections(j, ["_about", "_aboutWorkedExample", "templates", "instanceId", "keys", "requestKey", "answers", "sizes", "commitHash", "open", "commitCheck", "fulfil", "workedExample"]);
  });

  it("templates: the version-3 and version-2 key orders are this client's", () => {
    expect(j.templates["assisted-recovery v3"].map((f: string[]) => f[0])).toEqual(["v", "purpose", "instanceId", "userId", "email", "requestId", "requestKey", "commit", "uvk", "issuedAt"]);
    expect(j.templates["assisted-recovery v2"].map((f: string[]) => f[0])).toEqual(["v", "purpose", "instanceId", "userId", "requestId", "requestKey", "uvk", "issuedAt"]);
  });

  it("answers: statement, message, signature, frame, sealed answer, commit hash and token byte for byte", () => {
    gradeEvery("recovery-v3 answers", j.answers, (row: { name: string; input: Record<string, string | number>; expect: Record<string, string | number> }) => {
      const i = row.input;
      const statement = encodeStatement(
        "assisted-recovery",
        { instanceId: i.instanceId as string, userId: i.userId as string, email: i.emailB64 as string, requestId: i.requestId as string, requestKey: i.requestKey as string, commit: i.commitB64 as string, issuedAt: String(i.issuedAt) },
        { uvk: fromB64(i.uvkB64 as string) },
        3,
      );
      expect(toB64(utf8(emailNorm(i.address as string)!)), row.name).toBe(i.emailB64);
      expect(fromUtf8(statement), row.name).toBe(row.expect.statementUtf8);
      expect(statement.length).toBe(row.expect.statementBytes);
      const signer = signerOf(i.signer as string);
      expect(toHexLower(signedMessage(9, signer.publicKey, statement)), row.name).toBe(row.expect.messageHex);
      const frame = signFrame(signer, "assisted-recovery", statement);
      expect(toB64(frame.subarray(37, 101)), row.name).toBe(row.expect.signatureB64);
      expect(toB64(frame), row.name).toBe(row.expect.frameB64);
      expect(frame.length).toBe(row.expect.frameBytes);
      const sealed = sealWithEphemeral(fromB64(i.ephemeralSecretB64 as string), fromB64(i.requestKey as string), frame);
      expect(toB64(sealed), row.name).toBe(row.expect.sealedB64);
      expect(sealed.length).toBe(row.expect.sealedBytes);
      const hash = commitHash(fromB64(i.commitB64 as string));
      expect(`andvari/v2|recovery-request|commit|${i.commitB64}`).toBe(row.expect.commitHashInputUtf8);
      expect(hash, row.name).toBe(row.expect.commitHash);
      expect(`andvari-answer:3:${i.requestId}:${i.requestKey}:${hash}:${toB64(sealed)}`, row.name).toBe(row.expect.token);
    });
  });

  it("sizes: 376 + E, 477 + E and 525 + E, and an answer built for each checked address has exactly those sizes", () => {
    const signer = signerOf("recoveryA");
    const rPub = fromB64(j.requestKey.rPubB64);
    gradeEvery("recovery-v3 sizes", j.sizes, (row: { emailOctets: number; emailChars: number; statement: number; frame: number; sealed: number; checkedWith?: string }) => {
      expect(row.emailChars).toBe(Math.ceil((4 * row.emailOctets) / 3));
      expect([row.statement, row.frame, row.sealed]).toEqual([376 + row.emailChars, 477 + row.emailChars, 525 + row.emailChars]);
      if (row.checkedWith === undefined) return; // n = 3: no emailNorm is that short
      expect(utf8(row.checkedWith).length).toBe(row.emailOctets);
      const statement = encodeStatement(
        "assisted-recovery",
        { instanceId: j.instanceId, userId: j.keys.alice.userId, email: toB64(utf8(row.checkedWith)), requestId: "kevsyZmgCVPO8TTl-1oqKQ", requestKey: j.requestKey.rPubB64, commit: toB64(new Uint8Array(32).fill(1)), issuedAt: "1763884800000" },
        { uvk: new Uint8Array(32).fill(2) },
        3,
      );
      const frame = signFrame(signer, "assisted-recovery", statement);
      expect([statement.length, frame.length, sealWithEphemeral(new Uint8Array(32).fill(3), rPub, frame).length]).toEqual([row.statement, row.frame, row.sealed]);
    });
  });

  it("commitHash: every row", () => {
    gradeEvery("recovery-v3 commitHash", j.commitHash, (row: { commitB64: string; inputUtf8: string; commitHash: string }) => {
      expect(`andvari/v2|recovery-request|commit|${row.commitB64}`).toBe(row.inputUtf8);
      expect(commitHash(fromB64(row.commitB64))).toBe(row.commitHash);
    });
  });

  it("open: the device's opener of a version-3 answer, every row", () => {
    const rPub = fromB64(j.requestKey.rPubB64);
    const rSec = fromB64(j.requestKey.rSecB64);
    expect(toB64(boxKeypairFromSeed(rSec).publicKey) === j.requestKey.rPubB64 || toB64(sodium().crypto_scalarmult_base(rSec)) === j.requestKey.rPubB64).toBe(true);
    type Row = { name: string; sealedB64: string; cardRecoveryFp: string | null; request: { instanceId: string; userId: string | null; requestId: string; requestKey: string; typedEmail: string }; encryptedIdentitySeedB64: string; identityPubB64: string; expect: { verdict: string; uvkB64?: string; commitB64?: string } };
    gradeEvery("recovery-v3 open", j.open, (row: Row) => {
      const req = { instanceId: row.request.instanceId, userId: row.request.userId, requestId: row.request.requestId, rPub: row.request.requestKey === j.requestKey.rPubB64 ? rPub : fromB64(row.request.requestKey), rSec };
      const r = openAssistedRecoveryV3(req, row.request.typedEmail, fromB64(row.sealedB64), row.cardRecoveryFp, { encryptedIdentitySeed: fromB64(row.encryptedIdentitySeedB64), identityPub: fromB64(row.identityPubB64) });
      const got = r.ok ? { verdict: "ok", uvkB64: toB64(r.value.uvk), commitB64: toB64(r.value.commit) } : { verdict: r.verdict };
      expect(got, row.name).toEqual(row.expect);
    });
  });

  it("workedExample: the Kotlin implementation's worked example, recomputed from its inputs", async () => {
    await gradeEveryAsync("recovery-v3 workedExample", j.workedExample, async (row: { input: Record<string, string | number>; expect: Record<string, string | number> }) => {
      const i = row.input;
      const seed = hexBytes(i.identitySeedHex as string);
      const identity = boxKeypairFromSeed(seed);
      const signer = signKeypairFromSeed(seed);
      const recovery = boxKeypairFromSeed(hexBytes(i.recoverySeedHex as string));
      const recoverySigner = signKeypairFromSeed(hexBytes(i.recoverySeedHex as string));
      const request = boxKeypairFromSeed(hexBytes(i.requestSeedHex as string));
      const fp = await fingerprint(recovery.publicKey);
      expect([toB64(identity.publicKey), toB64(signer.publicKey), toB64(recovery.publicKey), fp, toB64(recoverySigner.publicKey), toB64(request.publicKey)]).toEqual([
        row.expect.identityPubB64, row.expect.signerPubB64, row.expect.recoveryPubB64, row.expect.recoveryFp, row.expect.recoverySignerPubB64, row.expect.rPubB64,
      ]);
      const uvk = hexBytes(i.uvkHex as string);
      const escrowFrame = buildSignedStatement(signer, { purpose: "escrow-uvk", userId: i.userId as string, identityKey: identity.publicKey, recoveryFp: fp, issuedAt: i.issuedAt as number, key: uvk, email: i.address as string });
      expect(fromUtf8(escrowFrame.subarray(101))).toBe(row.expect.escrowStatementUtf8);
      expect(toHexLower(escrowFrame)).toBe(row.expect.escrowFrameHex);
      const sealedCopy = await sealUvkV3({ recoveryPub: recovery.publicKey, verifiedRecoveryFp: fp, userId: i.userId as string, emailNorm: i.address as string, identityPub: identity.publicKey, signer, uvk, issuedAt: i.issuedAt as number });
      expect(sealedCopy.length).toBe(row.expect.escrowSealedBytes);
      const commit = hexBytes(i.commitHex as string);
      const statement = encodeStatement(
        "assisted-recovery",
        { instanceId: i.instanceId as string, userId: i.userId as string, email: toB64(utf8(i.address as string)), requestId: i.requestId as string, requestKey: toB64(request.publicKey), commit: toB64(commit), issuedAt: String(i.issuedAt) },
        { uvk },
        3,
      );
      expect(fromUtf8(statement)).toBe(row.expect.answerStatementUtf8);
      const answerFrame = signFrame(recoverySigner, "assisted-recovery", statement);
      expect(toHexLower(answerFrame)).toBe(row.expect.answerFrameHex);
      expect(sealWithEphemeral(new Uint8Array(32).fill(9), request.publicKey, answerFrame).length).toBe(row.expect.answerSealedBytes);
      expect(commitHash(commit)).toBe(row.expect.commitHash);
      expect(`andvari-answer:3:${i.requestId}:${toB64(request.publicKey)}:${commitHash(commit)}:`).toBe(row.expect.tokenHead);
    });
  });

  it("commitCheck and fulfil are the server's checks (spec 03 §18.5, §18.6), named", () => {
    nameForeign("the server (POST /recovery/requests/{id}/commit)", "recovery-v3 commitCheck", j.commitCheck);
    nameForeign("the server (POST /admin/recovery-requests/{id}/fulfil)", "recovery-v3 fulfil", j.fulfil);
  });
});

(reader === null ? describe.skip : describe)(`answer-reader.json${reader === null ? " is not on this branch yet: nothing graded" : ""}`, () => {
  const j = reader;

  it("sections: exactly the ones graded or named here", () => {
    expectSections(j, ["_about", "request", "requestKeys", "token", "bareMinChars", "read", "readFile"]);
  });

  it("the token it reads is recovery-v3.json's answer for alice, and this client's commit hash of it", () => {
    if (recoveryV3 === null) return;
    const alice = recoveryV3.answers.find((a: { name: string }) => a.name === "alice");
    expect(j.token.text).toBe(alice.expect.token);
    expect([j.token.requestId, j.token.requestKey, j.token.commitHash, j.token.sealedB64]).toEqual([alice.input.requestId, alice.input.requestKey, alice.expect.commitHash, alice.expect.sealedB64]);
    expect(fromB64(j.token.sealedB64).length).toBe(j.token.sealedBytes);
  });

  it("read and readFile: the shared reader of the desktop console and andvari-cli operator fulfil (the web has no operator console), named", () => {
    nameForeign("the operator consoles' shared reader (desktop console, andvari-cli operator fulfil)", "answer-reader read", j.read);
    nameForeign("the operator consoles' shared reader (desktop console, andvari-cli operator fulfil)", "answer-reader readFile", j.readFile);
  });
});
