import type { ItemDoc } from "../api/types";
import { adExport } from "../crypto/ad";
import {
  HEADER_BYTES as ATTACHMENT_HEADER_BYTES,
  decryptAttachment,
  encryptAttachment,
} from "../crypto/attachments";
import { fromB64, fromUtf8, toB64, utf8 } from "../crypto/bytes";
import { open as envelopeOpen, seal as envelopeSeal, sealWithNonce } from "../crypto/envelope";
import { hkdfSha256 } from "../crypto/hkdf";
import { KDF_SALT_BYTES, KEY_BYTES, masterKey, type KdfParams } from "../crypto/keys";
import { CryptoError } from "../crypto/sodium";

/**
 * spec 07 — export & backup (the TS twin of core/.../client/Export.kt, the Kotlin
 * REFERENCE that emits spec/test-vectors/export.json). Both impls must write
 * byte-identical CSVs and produce/open byte-identical backup containers — keep the two
 * files in lockstep.
 *
 * Pure and platform-free by design: no clock (exportedAt is caller-supplied), no DOM,
 * no HTTP (attachment plaintext arrives via caller suppliers). The UI drives these
 * entry points with already-decrypted docs and feeds the returned parts to `new Blob`.
 */

// ---------------------------------------------------------------------------
// §1 — CSV export (plaintext, lossy — the migration escape hatch)
// ---------------------------------------------------------------------------

/** Chrome superset: browsers ignore the extra totp column; andvari's importer maps it. */
export const CSV_HEADER = "name,url,username,password,note,totp";

/**
 * spec 07 §1 writer — byte-identical across impls (vector-pinned).
 *
 * [items] must arrive PRE-ORDERED by the caller: vault order, then `updatedAt` order
 * within a vault (ItemDoc carries neither, the caller's wire metadata does). The
 * writer itself only filters to login items and preserves the given order.
 *
 * Rules: UTF-8 (callers encode without BOM), CRLF record terminator (header row
 * included), a field is quoted iff it contains `,` `"` CR or LF with `"` escaped as
 * `""`, CRLF/lone-CR inside values normalized to LF before writing, no trimming, no
 * formula-injection mangling (leading =+-@ verbatim — warn in UI instead). Rows with
 * empty username AND password are still WRITTEN (only a reimport skips them, spec 06
 * §1); note-type items are skipped (enumerate them via [csvWarnings]).
 */
export function writeCsv(items: ItemDoc[]): string {
  let out = CSV_HEADER + "\r\n";
  for (const doc of items) {
    if (doc.type !== "login") continue;
    const login = doc.login;
    const fields = [
      doc.name,
      login?.uris?.[0] ?? "",
      login?.username ?? "",
      login?.password ?? "",
      doc.notes ?? "",
      login?.totp ?? "",
    ];
    out += fields.map(csvField).join(",") + "\r\n";
  }
  return out;
}

/** What a CSV export drops, BY NAME (spec 07 §1 — the UI must enumerate names, never
 *  counts). Categories are independent: one item may appear in several lists. */
export interface CsvWarnings {
  /** Non-login (note-type) items — not written at all. */
  noteItems: string[];
  /** Items carrying attachments — attachments are not representable in CSV. */
  withAttachments: string[];
  /** Login items with more than one URI — the tail is dropped (only uris[0] exports). */
  extraUris: string[];
  /** Login items with empty username AND password — written, but a reimport skips them. */
  emptyUsernameAndPassword: string[];
}

export function csvWarnings(items: ItemDoc[]): CsvWarnings {
  const noteItems: string[] = [];
  const withAttachments: string[] = [];
  const extraUris: string[] = [];
  const emptyUsernameAndPassword: string[] = [];
  for (const doc of items) {
    if (doc.type !== "login") noteItems.push(doc.name);
    if ((doc.attachments?.length ?? 0) > 0) withAttachments.push(doc.name);
    if (doc.type === "login") {
      if ((doc.login?.uris?.length ?? 0) > 1) extraUris.push(doc.name);
      if (!doc.login?.username && !doc.login?.password) emptyUsernameAndPassword.push(doc.name);
    }
  }
  return { noteItems, withAttachments, extraUris, emptyUsernameAndPassword };
}

function csvField(value: string): string {
  // CR-normalization first (spec 07 §1): CRLF and lone CR → LF inside values, so the
  // spec 06 §4.3 parser round-trips exactly by construction.
  const n = value.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return /[",\n\r]/.test(n) ? '"' + n.replace(/"/g, '""') + '"' : n;
}

// ---------------------------------------------------------------------------
// §2 — backup container (`.andvari`) — binary-framed, encrypted
// ---------------------------------------------------------------------------

/** Raised with a stable [code]; AEAD failure is deliberately the combined
 *  `wrong_passphrase_or_corrupt` (indistinguishable by design, spec 07 §2.2). */
export class BackupError extends Error {
  readonly code: string;
  constructor(code: string, message: string = code) {
    super(message);
    this.name = "BackupError";
    this.code = code;
  }
}

export const BACKUP_FORMAT = "andvari-backup";
export const BACKUP_VERSION = 1;
export const MAGIC: Uint8Array = utf8("ANDVBK01");

// §2.2 ceilings/caps — an attacker-supplied file must not OOM the client. There is
// deliberately NO strength floor (a weakened header only breaks that file's own tag);
// the sub-libsodium-minimum guard below rejects params argon2id cannot even run.
export const MAX_FILE_BYTES = 256 * 1024 * 1024;
export const MAX_HEADER_BYTES = 64 * 1024;
export const MAX_KDF_MEM_BYTES = 256 * 1024 * 1024;
export const MAX_KDF_OPS = 16;
const MIN_KDF_MEM_BYTES = 8 * 1024; // libsodium crypto_pwhash minima,
const MIN_KDF_OPS = 1; //              not a policy floor

/** §2.5: total embedded attachment PLAINTEXT cap — enforced by the producing caller
 *  when planning sections (over-cap attachments are skipped by name). */
export const MAX_TOTAL_ATTACHMENT_PLAINTEXT = 64 * 1024 * 1024;

// Error codes — MUST match core Backup.ERR_* exactly (cross-impl contract).
export const ERR_UNKNOWN_FORMAT = "unknown_format";
export const ERR_UNKNOWN_VERSION = "unknown_version";
export const ERR_UNSUPPORTED_KDF = "unsupported_kdf";
export const ERR_TOO_LARGE = "too_large";
export const ERR_TRUNCATED = "truncated";
export const ERR_WRONG_PASSPHRASE_OR_CORRUPT = "wrong_passphrase_or_corrupt";
export const ERR_BAD_PAYLOAD = "bad_payload";

const INFO_EXPORT = utf8("andvari/v1/export");

/**
 * Header kdfParams (spec 07 §2.2). NOTE the key is `opsLimit` — the backup header
 * shape — not spec 01's wire `ops`. Foreign alg/v values decode without throwing so
 * [openBackup] can reject them with `unsupported_kdf` instead of a parse error.
 */
export interface BackupKdfParams {
  v: number;
  alg: string;
  opsLimit: number;
  memBytes: number;
}

/** Plaintext header (spec 07 §2.2). The §2.2 listing IS the canonical key order —
 *  the container vectors pin the exact bytes, so both impls must emit
 *  `format,v,fileId,kdfSalt,kdfParams{v,alg,opsLimit,memBytes}` compactly, in order
 *  (a JSON.stringify of an in-order literal matches — see buildBackupWithPayloadBytes). */
export interface BackupHeader {
  format: string;
  v: number;
  fileId: string;
  kdfSalt: string;
  kdfParams: BackupKdfParams;
}

// --- §2.4 payload model. Mirrors core's BackupPayload; unknown payload-level keys are
// tolerated (dropped) on open, doc-level unknowns are PRESERVED — docs stay the raw
// parsed JSON objects, the same guarantee Account.decryptItem gives (spec 02 §3).

export interface BackupVault {
  vaultId: string;
  type: string;
  name: string;
  role: string;
}

export interface BackupItem {
  itemId: string;
  vaultId: string;
  formatVersion: number;
  /** Informational only (spec 07 §3) — restore mints fresh server revisions/timestamps. */
  updatedAt: number;
  doc: ItemDoc;
}

/** Manifest entry: `fileKey` is a FRESH per-attachment key for THIS file's own section —
 *  the docs' own attachments[] refs keep their original (server-blob) fileKeys verbatim. */
export interface BackupAttachmentEntry {
  section: number;
  attachmentId: string;
  itemId: string;
  name: string;
  size: number;
  fileKey: string;
}

export interface BackupSkippedItem {
  itemId: string;
  vaultId: string;
  formatVersion: number;
}

/** §2.4 skips — the CALLER decides these (undecryptable items, over-cap or fetch-failed
 *  attachments); this module just serializes them so restore can enumerate by name. */
export interface BackupSkipped {
  undecryptable: BackupSkippedItem[];
  attachmentsOverCap: string[];
  attachmentFetchFailed: string[];
}

export interface BackupPayload {
  v: number;
  /** Unix ms, CALLER-supplied (no clock in here) — the only authenticated creation time. */
  exportedAt: number;
  origin: string;
  userId: string;
  identityFingerprint: string;
  vaults: BackupVault[];
  items: BackupItem[];
  attachments: BackupAttachmentEntry[];
  skipped: BackupSkipped;
}

/** One attachment section source. [plaintext] is invoked exactly once, when its
 *  section is written — sections stream one at a time (bounded memory, §2 rationale);
 *  the returned buffer is zeroed after encryption (best-effort). */
export interface AttachmentSection {
  fileKey: Uint8Array;
  plaintext: () => Uint8Array;
}

// ---- build ----

/**
 * Produce a `.andvari` container (spec 07 §2) as an ordered array of byte runs — the
 * UI hands them straight to `new Blob(parts)` (never one giant string, never base64).
 * The passphrase is taken AS TYPED (spec 01 §1 — no normalization; UI warns on
 * non-ASCII and enforces the strength floor). [kdfSalt] must be 16 fresh random bytes
 * and [fileId] a fresh UUIDv4 per export — both caller-minted so this stays
 * deterministic under test. [attachments] must line up 1:1, in order, with
 * `payload.attachments` (manifest section i+1 ↔ attachments[i]; fileKeys FRESH per
 * attachment and equal to the manifest's).
 *
 * MKx, exportKey and the serialized payload buffer are zeroed after sealing
 * (best-effort — the runtime may have copied; passphrase strings are immutable and
 * explicitly out of scope, spec 07 §2.3).
 *
 * [envelopeNonce] is the vector/test hook (fixed section-0 nonce); production callers
 * leave it undefined for a random nonce.
 */
export async function buildBackup(
  passphrase: string,
  fileId: string,
  kdfSalt: Uint8Array,
  kdfParams: KdfParams,
  payload: BackupPayload,
  attachments: AttachmentSection[] = [],
  envelopeNonce?: Uint8Array,
): Promise<Uint8Array[]> {
  if (payload.attachments.length !== attachments.length) {
    throw new Error(
      `manifest lists ${payload.attachments.length} attachments but ${attachments.length} sections were supplied`,
    );
  }
  payload.attachments.forEach((entry, i) => {
    if (entry.section !== i + 1) {
      throw new Error(`manifest section numbers must be 1..N in order (got ${entry.section} at index ${i})`);
    }
    if (entry.fileKey !== toB64(attachments[i]!.fileKey)) {
      throw new Error(`manifest fileKey mismatch for section ${entry.section}`);
    }
  });
  const payloadUtf8 = utf8(JSON.stringify(payload));
  return buildBackupWithPayloadBytes(passphrase, fileId, kdfSalt, kdfParams, payloadUtf8, attachments, envelopeNonce);
}

/**
 * [buildBackup] with pre-serialized payload bytes — the vector path (pinned payloadUtf8
 * → byte-exact container). CONSUMES [payloadUtf8]: the buffer is zeroed after sealing.
 */
export async function buildBackupWithPayloadBytes(
  passphrase: string,
  fileId: string,
  kdfSalt: Uint8Array,
  kdfParams: KdfParams,
  payloadUtf8: Uint8Array,
  attachments: AttachmentSection[] = [],
  envelopeNonce?: Uint8Array,
): Promise<Uint8Array[]> {
  // Canonical header bytes: compact JSON in the §2.2 key order — JSON.stringify emits
  // string keys in insertion order, so this in-order literal IS the pinned encoding.
  const headerBytes = utf8(
    JSON.stringify({
      format: BACKUP_FORMAT,
      v: BACKUP_VERSION,
      fileId,
      kdfSalt: toB64(kdfSalt),
      kdfParams: { v: kdfParams.v, alg: kdfParams.alg, opsLimit: kdfParams.ops, memBytes: kdfParams.memBytes },
    }),
  );
  const parts: Uint8Array[] = [MAGIC.slice(), u32le(headerBytes.length), headerBytes];

  const exportKey = await deriveExportKey(passphrase, kdfSalt, kdfParams);
  try {
    const ad = adExport(BACKUP_VERSION, fileId);
    const envelope = envelopeNonce
      ? sealWithNonce(exportKey, envelopeNonce, payloadUtf8, ad)
      : envelopeSeal(exportKey, payloadUtf8, ad);
    payloadUtf8.fill(0);
    parts.push(u64le(envelope.length), envelope);

    for (const a of attachments) {
      const plain = a.plaintext();
      let enc;
      try {
        enc = encryptAttachment(a.fileKey, plain);
      } finally {
        plain.fill(0);
      }
      parts.push(u64le(enc.header.length + enc.ciphertext.length), enc.header, enc.ciphertext);
    }
  } finally {
    exportKey.fill(0);
  }
  return parts;
}

// ---- open ----

/** An opened container: validated header, authenticated payload, and on-demand
 *  attachment-section decryption (one section in memory at a time). */
export class OpenedBackup {
  constructor(
    readonly header: BackupHeader,
    readonly payload: BackupPayload,
    private readonly file: Uint8Array,
    /** [offset, length] per section, section 0 first. */
    private readonly sections: [number, number][],
  ) {}

  get attachmentSectionCount(): number {
    return this.sections.length - 1;
  }

  /** Decrypt attachment section [section] (1-based, manifest numbering) with the
   *  manifest's fresh [fileKey]. Fails hard (`wrong_passphrase_or_corrupt`) on any
   *  tag failure, truncation, or reorder — spec 02 §6 discipline. */
  readAttachmentSection(section: number, fileKey: Uint8Array): Uint8Array {
    if (!(section >= 1 && section < this.sections.length)) {
      throw new BackupError(ERR_TRUNCATED, `no such attachment section ${section} (file has ${this.attachmentSectionCount})`);
    }
    const [off, len] = this.sections[section]!;
    if (len <= ATTACHMENT_HEADER_BYTES) {
      throw new BackupError(ERR_WRONG_PASSPHRASE_OR_CORRUPT, `attachment section ${section} too short`);
    }
    const header = this.file.subarray(off, off + ATTACHMENT_HEADER_BYTES);
    const ciphertext = this.file.subarray(off + ATTACHMENT_HEADER_BYTES, off + len);
    try {
      return decryptAttachment(fileKey, header, ciphertext);
    } catch (e) {
      if (e instanceof CryptoError) {
        throw new BackupError(ERR_WRONG_PASSPHRASE_OR_CORRUPT, `attachment section ${section} failed to decrypt`);
      }
      throw e;
    }
  }

  /** Convenience over [readAttachmentSection] driven by a §2.4 manifest entry. */
  readAttachment(entry: BackupAttachmentEntry): Uint8Array {
    return this.readAttachmentSection(entry.section, fromB64(entry.fileKey));
  }
}

/**
 * Open a container. Enforces the §2.2 validation ladder — every check BEFORE Argon2
 * runs — with distinct error codes (mirrors core Backup.open):
 *
 *  0. total size ≤ 256 MiB (`too_large`)
 *  1. magic == ANDVBK01 (`unknown_format`)
 *  2. headerLen ≤ 64 KiB (`too_large`), header parses/shapes as backup JSON
 *     (`unknown_format`), `format` (`unknown_format`), `v` (`unknown_version` — fail
 *     closed, never downgrade-parse)
 *  3. kdfParams v/alg (`unsupported_kdf`), ceilings memBytes ≤ 256 MiB & opsLimit ≤ 16
 *     (`unsupported_kdf`); params below libsodium's own minima are also
 *     `unsupported_kdf` (argon2id cannot run them — not a policy floor)
 *  4. section framing complete, section 0 present (`truncated`)
 *
 * then derives MKx/exportKey and opens section 0; ANY AEAD failure — wrong passphrase,
 * corruption, or an AD/fileId mismatch — is the single combined
 * `wrong_passphrase_or_corrupt` (indistinguishable by design). Key material and the
 * decrypted payload buffer are zeroed before return (best-effort).
 */
export async function openBackup(passphrase: string, file: Uint8Array): Promise<OpenedBackup> {
  if (file.length > MAX_FILE_BYTES) throw new BackupError(ERR_TOO_LARGE, "file exceeds 256 MiB");
  if (file.length < MAGIC.length || !bytesEqual(file.subarray(0, MAGIC.length), MAGIC)) {
    throw new BackupError(ERR_UNKNOWN_FORMAT, "not an andvari backup (bad magic)");
  }
  if (file.length < MAGIC.length + 4) throw new BackupError(ERR_TRUNCATED, "file ends inside headerLen");
  const dv = new DataView(file.buffer, file.byteOffset, file.byteLength);
  const headerLen = dv.getUint32(MAGIC.length, true);
  if (headerLen > MAX_HEADER_BYTES) throw new BackupError(ERR_TOO_LARGE, "headerLen exceeds 64 KiB");
  const headerStart = MAGIC.length + 4;
  if (headerStart + headerLen > file.length) throw new BackupError(ERR_TRUNCATED, "file ends inside header");
  let header: BackupHeader;
  try {
    header = decodeBackupHeader(JSON.parse(fromUtf8(file.subarray(headerStart, headerStart + headerLen))));
  } catch {
    throw new BackupError(ERR_UNKNOWN_FORMAT, "header is not valid backup JSON");
  }
  if (header.format !== BACKUP_FORMAT) throw new BackupError(ERR_UNKNOWN_FORMAT, `unknown format '${header.format}'`);
  if (header.v !== BACKUP_VERSION) throw new BackupError(ERR_UNKNOWN_VERSION, `unknown backup version ${header.v}`);
  const kp = header.kdfParams;
  if (kp.v !== 1 || kp.alg !== "argon2id13") throw new BackupError(ERR_UNSUPPORTED_KDF, `unsupported kdf ${kp.alg} v${kp.v}`);
  if (kp.memBytes > MAX_KDF_MEM_BYTES || kp.opsLimit > MAX_KDF_OPS) {
    throw new BackupError(ERR_UNSUPPORTED_KDF, "kdfParams exceed ceilings");
  }
  if (kp.memBytes < MIN_KDF_MEM_BYTES || kp.opsLimit < MIN_KDF_OPS) {
    throw new BackupError(ERR_UNSUPPORTED_KDF, "kdfParams below libsodium minima");
  }
  let kdfSalt: Uint8Array;
  try {
    kdfSalt = fromB64(header.kdfSalt);
  } catch {
    throw new BackupError(ERR_UNKNOWN_FORMAT, "kdfSalt is not base64url");
  }
  if (kdfSalt.length !== KDF_SALT_BYTES) throw new BackupError(ERR_UNSUPPORTED_KDF, `kdfSalt must be ${KDF_SALT_BYTES} bytes`);

  // Frame every section before any crypto: a tampered/truncated length fails here.
  // Lengths are u64 LE — read via BigInt so nothing is silently rounded; any length
  // that runs past EOF (incl. bit-63 garbage) is `truncated` before Number() narrowing.
  const sections: [number, number][] = [];
  let off = headerStart + headerLen;
  while (off < file.length) {
    if (off + 8 > file.length) throw new BackupError(ERR_TRUNCATED, "file ends inside a section length");
    const len = dv.getBigUint64(off, true);
    if (BigInt(off) + 8n + len > BigInt(file.length)) throw new BackupError(ERR_TRUNCATED, "section extends past end of file");
    sections.push([off + 8, Number(len)]);
    off += 8 + Number(len);
  }
  if (sections.length === 0) throw new BackupError(ERR_TRUNCATED, "missing items section");

  const exportKey = await deriveExportKey(passphrase, kdfSalt, {
    v: kp.v,
    alg: kp.alg,
    ops: kp.opsLimit,
    memBytes: kp.memBytes,
  });
  let plain: Uint8Array;
  try {
    const [s0off, s0len] = sections[0]!;
    plain = envelopeOpen(exportKey, file.subarray(s0off, s0off + s0len), adExport(header.v, header.fileId));
  } catch (e) {
    if (e instanceof CryptoError) throw new BackupError(ERR_WRONG_PASSPHRASE_OR_CORRUPT, "wrong passphrase or corrupted file");
    throw e;
  } finally {
    exportKey.fill(0);
  }
  let payload: BackupPayload;
  try {
    payload = decodeBackupPayload(JSON.parse(fromUtf8(plain)));
  } catch {
    throw new BackupError(ERR_BAD_PAYLOAD, "authenticated payload is not valid backup JSON");
  } finally {
    plain.fill(0);
  }
  return new OpenedBackup(header, payload, file, sections);
}

// ---- decode helpers (the TS stand-in for kotlinx typed decode) ----

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}
function str(x: unknown): string {
  if (typeof x !== "string") throw new Error("expected string");
  return x;
}
function int(x: unknown): number {
  if (typeof x !== "number" || !Number.isInteger(x)) throw new Error("expected integer");
  return x;
}

/** §2.2 header decode: all fields required, correct types, unknown keys tolerated —
 *  exactly what kotlinx gives the Kotlin reference. Throws plain Error; the caller
 *  maps it to `unknown_format`. */
function decodeBackupHeader(x: unknown): BackupHeader {
  if (!isObj(x)) throw new Error("header is not an object");
  const kp = x.kdfParams;
  if (!isObj(kp)) throw new Error("kdfParams is not an object");
  return {
    format: str(x.format),
    v: int(x.v),
    fileId: str(x.fileId),
    kdfSalt: str(x.kdfSalt),
    kdfParams: { v: int(kp.v), alg: str(kp.alg), opsLimit: int(kp.opsLimit), memBytes: int(kp.memBytes) },
  };
}

/**
 * §2.4 payload decode, mirroring core's `Json { ignoreUnknownKeys=true;
 * encodeDefaults=true }` semantics: `exportedAt` required; everything else defaults;
 * unknown payload-level keys tolerated but NOT preserved; each `doc` is kept as the
 * raw parsed object (unknown DOC fields are preserved — spec 02 §3). Exported for the
 * vector test (own-impl payload equality after open).
 */
export function decodeBackupPayload(x: unknown): BackupPayload {
  if (!isObj(x)) throw new Error("payload is not an object");
  const vaults = (x.vaults === undefined ? [] : arr(x.vaults)).map((e): BackupVault => {
    if (!isObj(e)) throw new Error("vault entry is not an object");
    return { vaultId: str(e.vaultId), type: str(e.type), name: str(e.name), role: str(e.role) };
  });
  const items = (x.items === undefined ? [] : arr(x.items)).map((e): BackupItem => {
    if (!isObj(e)) throw new Error("item entry is not an object");
    if (!isObj(e.doc)) throw new Error("item doc is not an object");
    return {
      itemId: str(e.itemId),
      vaultId: str(e.vaultId),
      formatVersion: int(e.formatVersion),
      updatedAt: int(e.updatedAt),
      doc: e.doc as unknown as ItemDoc, // verbatim — unknown doc fields survive (spec 02 §3)
    };
  });
  const attachments = (x.attachments === undefined ? [] : arr(x.attachments)).map((e): BackupAttachmentEntry => {
    if (!isObj(e)) throw new Error("attachment entry is not an object");
    return {
      section: int(e.section),
      attachmentId: str(e.attachmentId),
      itemId: str(e.itemId),
      name: str(e.name),
      size: int(e.size),
      fileKey: str(e.fileKey),
    };
  });
  let skipped: BackupSkipped = { undecryptable: [], attachmentsOverCap: [], attachmentFetchFailed: [] };
  if (x.skipped !== undefined) {
    if (!isObj(x.skipped)) throw new Error("skipped is not an object");
    const s = x.skipped;
    skipped = {
      undecryptable: (s.undecryptable === undefined ? [] : arr(s.undecryptable)).map((e): BackupSkippedItem => {
        if (!isObj(e)) throw new Error("skipped item is not an object");
        return { itemId: str(e.itemId), vaultId: str(e.vaultId), formatVersion: int(e.formatVersion) };
      }),
      attachmentsOverCap: (s.attachmentsOverCap === undefined ? [] : arr(s.attachmentsOverCap)).map(str),
      attachmentFetchFailed: (s.attachmentFetchFailed === undefined ? [] : arr(s.attachmentFetchFailed)).map(str),
    };
  }
  return {
    v: x.v === undefined ? 1 : int(x.v),
    exportedAt: int(x.exportedAt), // the only REQUIRED field (no default in the reference)
    origin: x.origin === undefined ? "" : str(x.origin),
    userId: x.userId === undefined ? "" : str(x.userId),
    identityFingerprint: x.identityFingerprint === undefined ? "" : str(x.identityFingerprint),
    vaults,
    items,
    attachments,
    skipped,
  };
}

function arr(x: unknown): unknown[] {
  if (!Array.isArray(x)) throw new Error("expected array");
  return x;
}

// ---- helpers ----

/** §2.3: MKx = Argon2id(passphrase as typed) → exportKey = HKDF(info="andvari/v1/export"). */
async function deriveExportKey(passphrase: string, kdfSalt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  const mkx = masterKey(passphrase, kdfSalt, params);
  try {
    return await hkdfSha256(mkx, new Uint8Array(0), INFO_EXPORT, KEY_BYTES);
  } finally {
    mkx.fill(0);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
}

function u64le(v: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
  return b;
}
