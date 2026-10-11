import { concat, ctEquals, fromB64, toB64 } from "./bytes";
import { ed25519PkToCurve25519, type KeyPairBytes, signDetached, signVerifyDetached } from "./provider";
import { CryptoError } from "./sodium";

/**
 * The v2 `SignedStatement` envelope and its canonical statement (security review 2026-10, root cause A
 * §1.1–§1.3; spec 01 §5.1). Byte-for-byte twin of core `SignedStatement.kt`, graded off the same
 * spec/test-vectors/signedstatement.json. First caller: escrow v2 (escrow.ts, branch A4).
 *
 * ```
 * 0    4   magic        61 76 73 02   ("avs" + version 0x02)
 * 4    1   purposeCode  01 vault-grant | 02 escrow-uvk   (others reserved → bad_frame)
 * 5    32  signerPub    Ed25519 public key
 * 37   64  signature    Ed25519 over M = "andvari/v2|signed-statement" ‖ 0x00 ‖ P[0..5) ‖ signerPub ‖ statement
 * 101  N   statement    canonical JSON, printable ASCII, 2 <= N <= 1024
 * ```
 */

export type StatementVerdict =
  | "unknown_format"
  | "bad_frame"
  | "non_canonical"
  | "bad_statement"
  | "signer_not_pinned_key"
  | "bad_signature"
  // escrow anchoring (verifyEscrowStatement only; security review 2026-10, A4)
  | "user_mismatch"
  | "recovery_fp_mismatch"
  | "identity_mismatch";

/** Why a statement was refused; the first failing step decides {@link verdict}. */
export class SignedStatementError extends Error {
  constructor(readonly verdict: StatementVerdict, detail: string) {
    super(`signed statement refused: ${verdict} (${detail})`);
    this.name = "SignedStatementError";
  }
}

export type PurposeCode = 1 | 2;
const PURPOSE_LITERAL: Record<PurposeCode, "vault-grant" | "escrow-uvk"> = { 1: "vault-grant", 2: "escrow-uvk" };

/**
 * A v2 statement's fields (spec 01 §5.1): what a SENDER builds for {@link buildSignedStatement}.
 * A parse result is NOT one of these: {@link parseStatement} returns an {@link UnverifiedStatement},
 * and received bytes become a `Statement` only through a {@link VerifiedStatement}.
 */
export interface VaultGrantStatement {
  readonly purpose: "vault-grant";
  readonly from: string;
  readonly to: string;
  readonly toKey: Uint8Array;
  readonly vaultId: string;
  readonly grantId: Uint8Array;
  readonly issuedAt: number;
  readonly vk: Uint8Array;
}

export interface EscrowUvkStatement {
  readonly purpose: "escrow-uvk";
  readonly userId: string;
  readonly identityKey: Uint8Array;
  readonly recoveryFp: string;
  readonly issuedAt: number;
  readonly key: Uint8Array;
}

export type Statement = VaultGrantStatement | EscrowUvkStatement;

/** A frozen deep copy: byte fields are fresh arrays, so no holder can alter another holder's view. */
function copyStatement(st: Statement): Statement {
  if (st.purpose === "vault-grant") {
    return Object.freeze({ ...st, toKey: st.toKey.slice(), grantId: st.grantId.slice(), vk: st.vk.slice() });
  }
  return Object.freeze({ ...st, identityKey: st.identityKey.slice(), key: st.key.slice() });
}

declare const unverifiedBrand: unique symbol;
/**
 * The output of a STRICT parse that has NOT been authenticated (security review 2026-10, A3 review:
 * separate unverified from verified data at the type level). It is neither a {@link Statement} nor a
 * {@link VerifiedStatement}, so the compiler refuses it wherever either is required, and it carries
 * only the plain routing fields a caller may need before verifying — no key material.
 */
export type UnverifiedStatement =
  | { readonly [unverifiedBrand]: true; readonly purpose: "vault-grant"; readonly from: string; readonly to: string; readonly vaultId: string }
  | { readonly [unverifiedBrand]: true; readonly purpose: "escrow-uvk"; readonly userId: string; readonly recoveryFp: string };

const verifiedToken: unique symbol = Symbol("verified-statement");
/**
 * A statement that passed EVERY step of {@link verifySignedStatement} or {@link verifyEscrowStatement}.
 * Nominal (private `#` fields) and minted only with a module-private token, so nothing outside this
 * module can produce one. Read-only: `statement` returns a frozen deep copy and `signerPub` a copy, so
 * a caller cannot alter the verified key material after the fact.
 */
export class VerifiedStatement {
  readonly #statement: Statement;
  readonly #signerPub: Uint8Array;
  constructor(token: typeof verifiedToken, statement: Statement, signerPub: Uint8Array) {
    if (token !== verifiedToken) throw new Error("VerifiedStatement is minted only by the verify helpers");
    this.#statement = copyStatement(statement);
    this.#signerPub = signerPub.slice();
  }
  get statement(): Statement {
    return copyStatement(this.#statement);
  }
  get signerPub(): Uint8Array {
    return this.#signerPub.slice();
  }
}

export interface SignedStatementFrame {
  purposeCode: PurposeCode;
  signerPub: Uint8Array;
  signature: Uint8Array;
  statement: Uint8Array;
}

export type BlobFormat = "v1-json" | "v2-signed" | "unknown";

export const MAGIC = Uint8Array.of(0x61, 0x76, 0x73, 0x02);
export const DOMAIN = "andvari/v2|signed-statement";
const HEADER_BYTES = 5;
const SIGNER_BYTES = 32;
const SIGNATURE_BYTES = 64;
const STATEMENT_OFFSET = HEADER_BYTES + SIGNER_BYTES + SIGNATURE_BYTES; // 101
const MIN_STATEMENT_BYTES = 2;
export const MAX_STATEMENT_BYTES = 1024;
const MS_CEILING = 2 ** 53;
const V_MAX = 999_999_999; // core's `0|[1-9][0-9]{0,8}` token grammar, as a value bound

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const B64_22_RE = /^[A-Za-z0-9_-]{22}$/;
const B64_43_RE = /^[A-Za-z0-9_-]{43}$/;

const GRANT_KEYS = ["v", "purpose", "from", "to", "toKey", "vaultId", "grantId", "issuedAt", "vk"];
const ESCROW_KEYS = ["v", "purpose", "userId", "identityKey", "recoveryFp", "issuedAt", "key"];

const ascii = (s: string) => new TextEncoder().encode(s);
const refuse = (verdict: StatementVerdict, detail: string): never => {
  throw new SignedStatementError(verdict, detail);
};
const need = (ok: boolean, what: string) => {
  if (!ok) throw new CryptoError(`signed statement: ${what}`);
};
const isMs = (x: number) => Number.isSafeInteger(x) && x >= 1 && x < MS_CEILING;
const isPurposeCode = (c: number): c is PurposeCode => c === 1 || c === 2;

/** `{` → a v1 legacy JSON payload; the v2 magic → a signed statement; anything else → unknown (refuse). */
export function formatOf(plaintext: Uint8Array): BlobFormat {
  if (plaintext.length > 0 && plaintext[0] === 0x7b) return "v1-json";
  if (plaintext.length >= MAGIC.length && ctEquals(plaintext.subarray(0, MAGIC.length), MAGIC)) return "v2-signed";
  return "unknown";
}

const grantTemplate = (v: number, purpose: string, from: string, to: string, toKey: string, vaultId: string, grantId: string, issuedAt: number, vk: string) =>
  `{"v":${v},"purpose":"${purpose}","from":"${from}","to":"${to}","toKey":"${toKey}","vaultId":"${vaultId}","grantId":"${grantId}","issuedAt":${issuedAt},"vk":"${vk}"}`;

const escrowTemplate = (v: number, purpose: string, userId: string, identityKey: string, recoveryFp: string, issuedAt: number, key: string) =>
  `{"v":${v},"purpose":"${purpose}","userId":"${userId}","identityKey":"${identityKey}","recoveryFp":"${recoveryFp}","issuedAt":${issuedAt},"key":"${key}"}`;

/**
 * The canonical statement bytes. Throws {@link CryptoError} for any value outside the closed grammar
 * and for a vault grant with `from == to`, so a statement this client signs always parses back.
 */
export function encodeStatement(st: Statement): Uint8Array {
  let text: string;
  if (st.purpose === "vault-grant") {
    need(UUID_RE.test(st.from), "from is not a lowercase uuid");
    need(UUID_RE.test(st.to), "to is not a lowercase uuid");
    need(st.from !== st.to, "a vault grant cannot be addressed to its sender");
    need(st.toKey.length === 32, "toKey must be 32 bytes");
    need(UUID_RE.test(st.vaultId), "vaultId is not a lowercase uuid");
    need(st.grantId.length === 16, "grantId must be 16 bytes");
    need(isMs(st.issuedAt), "issuedAt out of range");
    need(st.vk.length === 32, "vk must be 32 bytes");
    text = grantTemplate(2, "vault-grant", st.from, st.to, toB64(st.toKey), st.vaultId, toB64(st.grantId), st.issuedAt, toB64(st.vk));
  } else if (st.purpose === "escrow-uvk") {
    need(UUID_RE.test(st.userId), "userId is not a lowercase uuid");
    need(st.identityKey.length === 32, "identityKey must be 32 bytes");
    need(HEX64_RE.test(st.recoveryFp), "recoveryFp is not 64 lowercase hex");
    need(isMs(st.issuedAt), "issuedAt out of range");
    need(st.key.length === 32, "key must be 32 bytes");
    text = escrowTemplate(2, "escrow-uvk", st.userId, toB64(st.identityKey), st.recoveryFp, st.issuedAt, toB64(st.key));
  } else {
    throw new CryptoError("signed statement: unknown purpose");
  }
  const bytes = ascii(text);
  need(bytes.length >= MIN_STATEMENT_BYTES && bytes.length <= MAX_STATEMENT_BYTES, "statement length out of range");
  return bytes;
}

function str(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string") refuse("non_canonical", `${key} is not a string`);
  return v as string;
}

function num(obj: Record<string, unknown>, key: string): number {
  const v = obj[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v)) refuse("non_canonical", `${key} grammar`);
  return v as number;
}

function uuid(obj: Record<string, unknown>, key: string): string {
  const s = str(obj, key);
  if (!UUID_RE.test(s)) refuse("non_canonical", `${key} grammar`);
  return s;
}

function b64(obj: Record<string, unknown>, key: string, len: 16 | 32): Uint8Array {
  const s = str(obj, key);
  if (!(len === 16 ? B64_22_RE : B64_43_RE).test(s)) refuse("non_canonical", `${key} grammar`);
  let bytes: Uint8Array;
  try {
    bytes = fromB64(s);
  } catch {
    return refuse("non_canonical", `${key} is not base64url`);
  }
  if (bytes.length !== len || toB64(bytes) !== s) refuse("non_canonical", `${key} is not canonical base64url`);
  return bytes;
}

/**
 * STRICT parse of a statement under `purposeCode` — the same six steps, in the same order, as core
 * `SignedStatement.parseStatement` (spec 01 §5.1). The result is NOT authenticated and is typed so
 * ({@link UnverifiedStatement}): a caller may read its routing fields only to choose which pin to verify
 * against; trust comes from {@link verifySignedStatement} / {@link verifyEscrowStatement} alone.
 */
export function parseStatement(purposeCode: number, statement: Uint8Array): UnverifiedStatement {
  const st = parseFields(purposeCode, statement);
  const routing =
    st.purpose === "vault-grant"
      ? { purpose: st.purpose, from: st.from, to: st.to, vaultId: st.vaultId }
      : { purpose: st.purpose, userId: st.userId, recoveryFp: st.recoveryFp };
  return Object.freeze(routing) as UnverifiedStatement;
}

function parseFields(purposeCode: number, statement: Uint8Array): Statement {
  if (!isPurposeCode(purposeCode)) return refuse("bad_frame", "unknown purpose code");
  if (statement.length < MIN_STATEMENT_BYTES || statement.length > MAX_STATEMENT_BYTES) refuse("bad_frame", "statement length");
  for (const b of statement) if (b < 0x20 || b > 0x7e) refuse("non_canonical", "not printable ASCII");
  const text = String.fromCharCode(...statement);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return refuse("non_canonical", "not JSON");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return refuse("non_canonical", "not a JSON object");
  const obj = parsed as Record<string, unknown>;
  const expected = purposeCode === 1 ? GRANT_KEYS : ESCROW_KEYS;
  const keys = Object.keys(obj);
  if (keys.length !== expected.length || !expected.every((k) => Object.prototype.hasOwnProperty.call(obj, k))) {
    refuse("non_canonical", "key set");
  }

  const v = num(obj, "v");
  if (v < 0 || v > V_MAX) refuse("non_canonical", "v grammar");
  const purposeLiteral = str(obj, "purpose");
  if (purposeLiteral !== "vault-grant" && purposeLiteral !== "escrow-uvk") refuse("non_canonical", "purpose literal");
  const issuedAt = num(obj, "issuedAt");
  if (!isMs(issuedAt)) refuse("non_canonical", "issuedAt out of range");

  let st: Statement;
  let reEncoded: string;
  if (purposeCode === 1) {
    const g: VaultGrantStatement = {
      purpose: "vault-grant", from: uuid(obj, "from"), to: uuid(obj, "to"), toKey: b64(obj, "toKey", 32),
      vaultId: uuid(obj, "vaultId"), grantId: b64(obj, "grantId", 16), issuedAt, vk: b64(obj, "vk", 32),
    };
    reEncoded = grantTemplate(v, purposeLiteral, g.from, g.to, toB64(g.toKey), g.vaultId, toB64(g.grantId), g.issuedAt, toB64(g.vk));
    st = g;
  } else {
    const recoveryFp = str(obj, "recoveryFp");
    if (!HEX64_RE.test(recoveryFp)) refuse("non_canonical", "recoveryFp grammar");
    const e: EscrowUvkStatement = {
      purpose: "escrow-uvk", userId: uuid(obj, "userId"), identityKey: b64(obj, "identityKey", 32), recoveryFp, issuedAt,
      key: b64(obj, "key", 32),
    };
    reEncoded = escrowTemplate(v, purposeLiteral, e.userId, toB64(e.identityKey), e.recoveryFp, e.issuedAt, toB64(e.key));
    st = e;
  }
  const re = ascii(reEncoded);
  if (re.length !== statement.length || !re.every((b, i) => b === statement[i])) refuse("non_canonical", "not the canonical encoding");

  if (v !== 2) refuse("bad_statement", `statement version ${v}`);
  if (purposeLiteral !== PURPOSE_LITERAL[purposeCode]) refuse("bad_statement", "purpose literal does not match the purpose code");
  if (st.purpose === "vault-grant" && st.from === st.to) refuse("bad_statement", "grant from == to");
  return st;
}

/** The signed message M (design §1.2). */
export function signedMessage(purposeCode: number, signerPub: Uint8Array, statement: Uint8Array): Uint8Array {
  return concat(ascii(DOMAIN), Uint8Array.of(0), MAGIC, Uint8Array.of(purposeCode), signerPub, statement);
}

/** Encode, sign with the joint key `signer` (from `signKeypairFromSeed`) and frame. */
export function buildSignedStatement(signer: KeyPairBytes, st: Statement): Uint8Array {
  need(signer.publicKey.length === SIGNER_BYTES, "signer public key must be 32 bytes");
  const body = encodeStatement(st);
  const code: PurposeCode = st.purpose === "vault-grant" ? 1 : 2;
  const sig = signDetached(signer.privateKey, signedMessage(code, signer.publicKey, body));
  return concat(MAGIC, Uint8Array.of(code), signer.publicKey, sig, body);
}

/** Split a frame. Refuses (`bad_frame` / `unknown_format`) before any field is looked at. */
export function parseFrame(frame: Uint8Array): SignedStatementFrame {
  if (frame.length < MAGIC.length) refuse("bad_frame", "shorter than the magic");
  if (!ctEquals(frame.subarray(0, MAGIC.length), MAGIC)) refuse("unknown_format", "magic");
  if (frame.length < STATEMENT_OFFSET + MIN_STATEMENT_BYTES || frame.length > STATEMENT_OFFSET + MAX_STATEMENT_BYTES) {
    refuse("bad_frame", `frame length ${frame.length}`);
  }
  const code = frame[4]!;
  if (!isPurposeCode(code)) return refuse("bad_frame", `reserved purpose code ${code}`);
  return {
    purposeCode: code,
    signerPub: frame.slice(HEADER_BYTES, HEADER_BYTES + SIGNER_BYTES),
    signature: frame.slice(HEADER_BYTES + SIGNER_BYTES, STATEMENT_OFFSET),
    statement: frame.slice(STATEMENT_OFFSET),
  };
}

function frameFor(frame: Uint8Array, expectedPurposeCode: PurposeCode): SignedStatementFrame {
  const f = parseFrame(frame);
  if (f.purposeCode !== expectedPurposeCode) refuse("bad_frame", `purpose code ${f.purposeCode}, expected ${expectedPurposeCode}`);
  return f;
}

function verifySigner(f: SignedStatementFrame, statement: Statement, pinnedIdentityPub: Uint8Array): VerifiedStatement {
  if (pinnedIdentityPub.length !== 32) refuse("signer_not_pinned_key", "pinned identity key is not 32 bytes");
  let curve: Uint8Array;
  try {
    curve = ed25519PkToCurve25519(f.signerPub);
  } catch {
    return refuse("signer_not_pinned_key", "signerPub is not a usable Ed25519 point");
  }
  if (!ctEquals(curve, pinnedIdentityPub)) refuse("signer_not_pinned_key", "signerPub does not map to the pinned identity");
  if (!signVerifyDetached(f.signerPub, f.signature, signedMessage(f.purposeCode, f.signerPub, f.statement))) {
    refuse("bad_signature", "signature does not verify");
  }
  return new VerifiedStatement(verifiedToken, statement, f.signerPub);
}

/**
 * THE signer-key binding helper for VAULT GRANTS. Twin of core `SignedStatement.verify`; fails closed,
 * first failing step decides the verdict (design §1.4 steps 2, 3, 8, 9): frame + expected purpose
 * (`bad_frame`), strict canonical parse (`non_canonical` / `bad_statement`),
 * `ed25519PkToCurve25519(signerPub) == pinnedIdentityPub` (`signer_not_pinned_key`; the pin MUST come
 * from out of band, never a server response), then the signature (`bad_signature`).
 *
 * Escrow statements are REFUSED here: they verify only through the module-private `verifyEscrowStatement`,
 * which only the escrow open path holds and which cannot be called without the out-of-band anchor
 * (security review 2026-10, A3 review; A5).
 */
export function verifySignedStatement(frame: Uint8Array, expectedPurposeCode: PurposeCode, pinnedIdentityPub: Uint8Array): VerifiedStatement {
  if (expectedPurposeCode === 2) throw new Error("escrow statements verify only through verifyEscrowStatement (anchored)");
  const f = frameFor(frame, expectedPurposeCode);
  return verifySigner(f, parseFields(f.purposeCode, f.statement), pinnedIdentityPub);
}

/**
 * The ESCROW-specific binding helper (security review 2026-10, root cause A §2.3; A3 review "bind
 * statement fields to the anchor, not to themselves"). Twin of core `SignedStatement.verifyEscrow`.
 * Every input is the caller's OUT-OF-BAND anchor, never a value read from the statement: the account
 * the admin named, the identity key the anchor vouches for, and the fingerprint of the org key whose
 * secret opened the seal. Order: frame + strict parse; the UNVERIFIED `userId` / `recoveryFp` routing
 * fields (`user_mismatch` / `recovery_fp_mismatch`, a refusal only); signer → anchor
 * (`signer_not_pinned_key`), signature (`bad_signature`); then the VERIFIED `userId`, `identityKey` and
 * `recoveryFp` must EQUAL the anchor (`user_mismatch` / `identity_mismatch` / `recovery_fp_mismatch`).
 *
 * MODULE-PRIVATE (security review 2026-10, root cause A, A4 review carry-forward closed in A5): not
 * exported. The escrow open path (escrow.ts) takes it ONCE through {@link claimEscrowVerifier} at module
 * load, so no other caller can verify an escrow frame against an anchor it derived itself (for instance
 * from a public `parseFrame(...).signerPub`, which would be a self-pin). Core twin: `internal fun
 * SignedStatement.verifyEscrow`.
 */
function verifyEscrowStatement(
  frame: Uint8Array,
  expectedUserId: string,
  anchoredIdentityPub: Uint8Array,
  expectedRecoveryFp: string,
): VerifiedStatement {
  const f = frameFor(frame, 2);
  const unverified = parseFields(f.purposeCode, f.statement) as EscrowUvkStatement;
  if (unverified.userId !== expectedUserId) refuse("user_mismatch", "statement names another account");
  if (unverified.recoveryFp !== expectedRecoveryFp) refuse("recovery_fp_mismatch", "statement names another recovery key");
  const verified = verifySigner(f, unverified, anchoredIdentityPub);
  const st = verified.statement as EscrowUvkStatement;
  if (st.userId !== expectedUserId) refuse("user_mismatch", "verified statement names another account");
  if (!ctEquals(st.identityKey, anchoredIdentityPub)) refuse("identity_mismatch", "statement identityKey is not the anchored identity");
  if (st.recoveryFp !== expectedRecoveryFp) refuse("recovery_fp_mismatch", "verified statement names another recovery key");
  return verified;
}

export type EscrowStatementVerifier = typeof verifyEscrowStatement;

let escrowVerifierClaimed = false;

/**
 * Hands the anchored escrow verifier to THE escrow open path, exactly once per module instance: escrow.ts
 * claims it at load, and any later claim throws. That is the web form of core's `internal`: the verifier
 * is reachable from the escrow open path and nowhere else. Do not call it from anywhere but escrow.ts (a
 * source-scan test pins that); tests that grade the verifier claim it in an isolated module registry.
 */
export function claimEscrowVerifier(): EscrowStatementVerifier {
  if (escrowVerifierClaimed) throw new Error("the escrow verifier belongs to the escrow open path (escrow.ts) and is already claimed");
  escrowVerifierClaimed = true;
  return verifyEscrowStatement;
}
