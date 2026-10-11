import { concat, ctEquals, fromB64, toB64 } from "./bytes";
import { ed25519PkToCurve25519, type KeyPairBytes, signDetached, signVerifyDetached } from "./provider";
import { CryptoError } from "./sodium";

/**
 * The v2 `SignedStatement` envelope and its canonical statement (security review 2026-10, root cause A
 * §1.1–§1.3; spec 01 §5.1). Byte-for-byte twin of core `SignedStatement.kt`, graded off the same
 * spec/test-vectors/signedstatement.json. A3 ships the codec and the verify helper with NO caller.
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
  | "bad_signature";

/** Why a statement was refused; the first failing step decides {@link verdict}. */
export class SignedStatementError extends Error {
  constructor(readonly verdict: StatementVerdict, detail: string) {
    super(`signed statement refused: ${verdict} (${detail})`);
    this.name = "SignedStatementError";
  }
}

export type PurposeCode = 1 | 2;
const PURPOSE_LITERAL: Record<PurposeCode, "vault-grant" | "escrow-uvk"> = { 1: "vault-grant", 2: "escrow-uvk" };

export interface VaultGrantStatement {
  purpose: "vault-grant";
  from: string;
  to: string;
  toKey: Uint8Array;
  vaultId: string;
  grantId: Uint8Array;
  issuedAt: number;
  vk: Uint8Array;
}

export interface EscrowUvkStatement {
  purpose: "escrow-uvk";
  userId: string;
  identityKey: Uint8Array;
  recoveryFp: string;
  issuedAt: number;
  key: Uint8Array;
}

export type Statement = VaultGrantStatement | EscrowUvkStatement;

declare const verifiedBrand: unique symbol;
/**
 * A statement that passed EVERY step of {@link verifySignedStatement}. The brand symbol is not
 * exported, so nothing outside this module can produce the type without a cast.
 */
export interface VerifiedStatement {
  readonly [verifiedBrand]: true;
  readonly statement: Statement;
  readonly signerPub: Uint8Array;
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
 * `SignedStatement.parseStatement` (spec 01 §5.1). The result is NOT authenticated: a caller may read
 * it only to choose which pin to verify against; trust comes from {@link verifySignedStatement} alone.
 */
export function parseStatement(purposeCode: number, statement: Uint8Array): Statement {
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

/**
 * THE signer-key binding helper — the only way to get a {@link VerifiedStatement}. Twin of core
 * `SignedStatement.verify`; fails closed, first failing step decides the verdict (design §1.4 steps
 * 2, 3, 8, 9): frame + expected purpose (`bad_frame`), strict canonical parse (`non_canonical` /
 * `bad_statement`), `ed25519PkToCurve25519(signerPub) == pinnedIdentityPub` (`signer_not_pinned_key`;
 * the pin MUST come from out of band, never a server response), then the signature (`bad_signature`).
 */
export function verifySignedStatement(frame: Uint8Array, expectedPurposeCode: PurposeCode, pinnedIdentityPub: Uint8Array): VerifiedStatement {
  const f = parseFrame(frame);
  if (f.purposeCode !== expectedPurposeCode) refuse("bad_frame", `purpose code ${f.purposeCode}, expected ${expectedPurposeCode}`);
  const statement = parseStatement(f.purposeCode, f.statement);
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
  return { statement, signerPub: f.signerPub } as VerifiedStatement;
}
