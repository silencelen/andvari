package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * spec 07 — export & backup (the Kotlin REFERENCE implementation; tools/vector-gen emits
 * export.json from this code and the web TS twin must produce/open identically).
 *
 * Pure and platform-free by design: no clock (exportedAt is caller-supplied), no IO
 * (output goes to a caller sink), no HTTP (attachment plaintext arrives via caller
 * suppliers), no AndvariApi/SyncEngine coupling — every client plus tools/backup-cli
 * drives these entry points with already-decrypted docs.
 */

// ---------------------------------------------------------------------------
// §1 — CSV export (plaintext, lossy — the migration escape hatch)
// ---------------------------------------------------------------------------

object ExportCsv {
    /** Chrome superset: browsers ignore the extra totp column; andvari's importer maps it. */
    const val HEADER = "name,url,username,password,note,totp"

    /**
     * spec 07 §1 writer — byte-identical across impls (vector-pinned).
     *
     * [items] must arrive PRE-ORDERED by the caller: vault order, then `updatedAt` order
     * within a vault (ItemDoc carries neither, the caller's wire metadata does). The
     * writer itself only filters to login items and preserves the given order, so output
     * is deterministic for a given input list.
     *
     * Rules: UTF-8 (callers encode without BOM), CRLF record terminator (header row
     * included), a field is quoted iff it contains `,` `"` CR or LF with `"` escaped as
     * `""`, CRLF/lone-CR inside values normalized to LF before writing, no trimming, no
     * formula-injection mangling (leading =+-@ verbatim — warn in UI instead). Rows with
     * empty username AND password are still WRITTEN (only a reimport skips them, spec 06
     * §1); non-login items (notes AND cards — CSV has no card columns) are skipped
     * (enumerate them via [warnings]).
     */
    fun write(items: List<ItemDoc>): String {
        val sb = StringBuilder()
        sb.append(HEADER).append("\r\n")
        for (doc in items) {
            if (doc.type != "login") continue
            val login = doc.login
            val fields = listOf(
                doc.name,
                login?.uris?.firstOrNull() ?: "",
                login?.username ?: "",
                login?.password ?: "",
                doc.notes ?: "",
                login?.totp ?: "",
            )
            fields.joinTo(sb, ",") { field(it) }
            sb.append("\r\n")
        }
        return sb.toString()
    }

    /** What a CSV export drops, BY NAME (spec 07 §1 — the UI must enumerate names, never
     *  counts). Categories are independent: one item may appear in several lists. */
    data class Warnings(
        /** Non-login, non-card (note-type) items — not written at all. */
        val noteItems: List<String>,
        /** Card-type items — not written at all (only a `.andvari` backup carries them);
         *  split out of [noteItems] so the UI can point at the backup path specifically. */
        val cardItems: List<String>,
        /** Items carrying attachments — attachments are not representable in CSV. */
        val withAttachments: List<String>,
        /** Login items with more than one URI — the tail is dropped (only uris[0] exports). */
        val extraUris: List<String>,
        /** Login items with empty username AND password — written, but a reimport skips them. */
        val emptyUsernameAndPassword: List<String>,
    )

    fun warnings(items: List<ItemDoc>): Warnings {
        val notes = ArrayList<String>()
        val cards = ArrayList<String>()
        val attach = ArrayList<String>()
        val uris = ArrayList<String>()
        val empty = ArrayList<String>()
        for (doc in items) {
            // Cards interact with the other lists exactly as notes always have: still eligible
            // for [Warnings.withAttachments] (that check is type-blind), never for the login-only lists.
            if (doc.type == "card") cards.add(doc.name)
            else if (doc.type != "login") notes.add(doc.name)
            if (doc.attachments.isNotEmpty()) attach.add(doc.name)
            if (doc.type == "login") {
                if ((doc.login?.uris?.size ?: 0) > 1) uris.add(doc.name)
                if (doc.login?.username.isNullOrEmpty() && doc.login?.password.isNullOrEmpty()) empty.add(doc.name)
            }
        }
        return Warnings(notes, cards, attach, uris, empty)
    }

    private fun field(value: String): String {
        // CR-normalization first (spec 07 §1): CRLF and lone CR → LF inside values, so
        // the spec 06 §4.3 parser round-trips exactly by construction.
        val n = buildString(value.length) {
            var i = 0
            while (i < value.length) {
                val c = value[i]
                if (c == '\r') {
                    append('\n')
                    if (i + 1 < value.length && value[i + 1] == '\n') i++
                } else {
                    append(c)
                }
                i++
            }
        }
        return if (n.any { it == ',' || it == '"' || it == '\n' || it == '\r' }) {
            "\"" + n.replace("\"", "\"\"") + "\""
        } else {
            n
        }
    }
}

// ---------------------------------------------------------------------------
// §2 — backup container (`.andvari`) — binary-framed, encrypted
// ---------------------------------------------------------------------------

/** Raised by [Backup] with a stable [code]; AEAD failure is deliberately the combined
 *  `wrong_passphrase_or_corrupt` (indistinguishable by design, spec 07 §2.2). */
class BackupException(val code: String, message: String = code) : Exception(message)

/**
 * Header kdfParams (spec 07 §2.2). NOTE the key is `opsLimit` — the backup header shape —
 * not spec 01's wire `ops`. Unlike the typed core [KdfParams], this class decodes foreign
 * alg/v values without throwing, so [Backup.open] can reject them with `unsupported_kdf`
 * instead of a parse error (the §2.2 ladder).
 */
@Serializable
data class BackupKdfParams(
    val v: Int,
    val alg: String,
    val opsLimit: Long,
    val memBytes: Long,
)

/** Plaintext header (spec 07 §2.2). Field declaration order IS the canonical key order
 *  (spec 00 canonical JSON + the §2.2 listing) — the container vectors pin the exact
 *  bytes, so both impls must emit `format,v,fileId,kdfSalt,kdfParams{v,alg,opsLimit,
 *  memBytes}` compactly, in this order. All fields required on decode (no silent
 *  defaulting of a missing `format`/`v`). */
@Serializable
data class BackupHeader(
    val format: String,
    val v: Int,
    val fileId: String,
    val kdfSalt: String,
    val kdfParams: BackupKdfParams,
)

// --- §2.4 payload model. Serialized with the SAME Json config as Account's item docs
// (ignoreUnknownKeys=true, encodeDefaults=true); the nested ItemDoc rides the
// ExtrasOverlaySerializer, so unknown doc fields at every level survive build→open.
// Restore tolerates unknown payload-level keys (ignoreUnknownKeys) without preserving
// them — preservation is a doc-level guarantee (spec 02 §3), not a payload one.

@Serializable
data class BackupVault(
    val vaultId: String,
    val type: String,
    val name: String,
    val role: String,
)

@Serializable
data class BackupItem(
    val itemId: String,
    val vaultId: String,
    val formatVersion: Int,
    /** Informational only (spec 07 §3) — restore mints fresh server revisions/timestamps. */
    val updatedAt: Long,
    val doc: ItemDoc,
)

/** Manifest entry: `fileKey` is a FRESH per-attachment key for THIS file's own section —
 *  the docs' own attachments[] refs keep their original (server-blob) fileKeys verbatim. */
@Serializable
data class BackupAttachmentEntry(
    val section: Int,
    val attachmentId: String,
    val itemId: String,
    val name: String,
    val size: Long,
    val fileKey: String,
)

@Serializable
data class BackupSkippedItem(val itemId: String, val vaultId: String, val formatVersion: Int)

/** §2.4 skips — the CALLER decides these (undecryptable items, over-cap or fetch-failed
 *  attachments); Backup just serializes them so restore can enumerate by name. */
@Serializable
data class BackupSkipped(
    val undecryptable: List<BackupSkippedItem> = emptyList(),
    val attachmentsOverCap: List<String> = emptyList(),
    val attachmentFetchFailed: List<String> = emptyList(),
)

@Serializable
data class BackupPayload(
    val v: Int = 1,
    /** Unix ms, CALLER-supplied (no clock in here) — the only authenticated creation time. */
    val exportedAt: Long,
    val origin: String = "",
    val userId: String = "",
    val identityFingerprint: String = "",
    val vaults: List<BackupVault> = emptyList(),
    val items: List<BackupItem> = emptyList(),
    val attachments: List<BackupAttachmentEntry> = emptyList(),
    val skipped: BackupSkipped = BackupSkipped(),
)

object Backup {
    const val FORMAT = "andvari-backup"
    const val VERSION = 1
    val MAGIC: ByteArray = "ANDVBK01".encodeToByteArray()

    // §2.2 ceilings/caps — an attacker-supplied file must not OOM the client. There is
    // deliberately NO strength floor (a weakened header only breaks that file's own tag);
    // the sub-libsodium-minimum guard below rejects params argon2id cannot even run.
    const val MAX_FILE_BYTES = 256L * 1024 * 1024
    const val MAX_HEADER_BYTES = 64 * 1024
    const val MAX_KDF_MEM_BYTES = 256L * 1024 * 1024
    const val MAX_KDF_OPS = 16L
    private const val MIN_KDF_MEM_BYTES = 8L * 1024 // libsodium crypto_pwhash minima,
    private const val MIN_KDF_OPS = 1L //              not a policy floor

    /** §2.5: total embedded attachment PLAINTEXT cap — enforced by the producing caller
     *  when planning sections (over-cap attachments are skipped by name). */
    const val MAX_TOTAL_ATTACHMENT_PLAINTEXT = 64L * 1024 * 1024

    const val ERR_UNKNOWN_FORMAT = "unknown_format"
    const val ERR_UNKNOWN_VERSION = "unknown_version"
    const val ERR_UNSUPPORTED_KDF = "unsupported_kdf"
    const val ERR_TOO_LARGE = "too_large"
    const val ERR_TRUNCATED = "truncated"
    const val ERR_WRONG_PASSPHRASE_OR_CORRUPT = "wrong_passphrase_or_corrupt"
    const val ERR_BAD_PAYLOAD = "bad_payload"

    private val INFO_EXPORT = "andvari/v1/export".encodeToByteArray()

    /** The standard item Json config (mirrors Account) — payload docs must (de)serialize
     *  through the exact same shape the vault uses. */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** One attachment section source. [plaintext] is invoked exactly once, when its
     *  section is written — sections stream one at a time (bounded memory, §2 rationale);
     *  the returned buffer is zeroed after encryption (best-effort). */
    class AttachmentSection(val fileKey: ByteArray, val plaintext: () -> ByteArray)

    // ---- build ----

    /**
     * Produce a `.andvari` container (spec 07 §2), emitting byte runs to [sink] in file
     * order. The passphrase is taken AS TYPED (spec 01 §1 — no normalization; UI warns on
     * non-ASCII and enforces the strength floor). [kdfSalt] must be 16 fresh random
     * bytes and [fileId] a fresh UUIDv4 per export — both caller-minted so this stays
     * deterministic under test. [attachments] must line up 1:1, in order, with
     * `payload.attachments` (manifest section i+1 ↔ attachments[i]; fileKeys FRESH per
     * attachment and equal to the manifest's).
     *
     * MKx, exportKey and the serialized payload buffer are zeroed after sealing
     * (best-effort — the JVM may have copied; passphrase strings are immutable and
     * explicitly out of scope, spec 07 §2.3).
     *
     * [envelopeNonce] is the vector/test hook (fixed section-0 nonce); production callers
     * leave it null for a random nonce.
     */
    fun build(
        crypto: CryptoProvider,
        passphrase: String,
        fileId: String,
        kdfSalt: ByteArray,
        kdfParams: KdfParams,
        payload: BackupPayload,
        attachments: List<AttachmentSection> = emptyList(),
        envelopeNonce: ByteArray? = null,
        sink: (ByteArray) -> Unit,
    ) {
        require(payload.attachments.size == attachments.size) {
            "manifest lists ${payload.attachments.size} attachments but ${attachments.size} sections were supplied"
        }
        payload.attachments.forEachIndexed { i, entry ->
            require(entry.section == i + 1) { "manifest section numbers must be 1..N in order (got ${entry.section} at index $i)" }
            require(entry.fileKey == Bytes.toB64(attachments[i].fileKey)) { "manifest fileKey mismatch for section ${entry.section}" }
        }
        val payloadUtf8 = json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray()
        buildWithPayloadBytes(crypto, passphrase, fileId, kdfSalt, kdfParams, payloadUtf8, attachments, envelopeNonce, sink)
    }

    /**
     * [build] with pre-serialized payload bytes — the vector path (pinned payloadUtf8 →
     * byte-exact container) and an escape hatch for producers that stream their own
     * payload. CONSUMES [payloadUtf8]: the buffer is zeroed after sealing.
     */
    fun buildWithPayloadBytes(
        crypto: CryptoProvider,
        passphrase: String,
        fileId: String,
        kdfSalt: ByteArray,
        kdfParams: KdfParams,
        payloadUtf8: ByteArray,
        attachments: List<AttachmentSection> = emptyList(),
        envelopeNonce: ByteArray? = null,
        sink: (ByteArray) -> Unit,
    ) {
        val header = BackupHeader(
            format = FORMAT,
            v = VERSION,
            fileId = fileId,
            kdfSalt = Bytes.toB64(kdfSalt),
            kdfParams = BackupKdfParams(v = kdfParams.v, alg = kdfParams.alg, opsLimit = kdfParams.ops, memBytes = kdfParams.memBytes),
        )
        val headerBytes = json.encodeToString(BackupHeader.serializer(), header).encodeToByteArray()
        sink(MAGIC.copyOf())
        sink(u32le(headerBytes.size))
        sink(headerBytes)

        val exportKey = deriveExportKey(crypto, passphrase, kdfSalt, kdfParams)
        try {
            val envelope = if (envelopeNonce != null) {
                Envelope.sealWithNonce(crypto, exportKey, envelopeNonce, payloadUtf8, Ad.export(VERSION, fileId))
            } else {
                Envelope.seal(crypto, exportKey, payloadUtf8, Ad.export(VERSION, fileId))
            }
            payloadUtf8.fill(0)
            sink(u64le(envelope.size.toLong()))
            sink(envelope)

            for (a in attachments) {
                val plain = a.plaintext()
                val enc = try {
                    Attachments.encrypt(crypto, a.fileKey, plain)
                } finally {
                    plain.fill(0)
                }
                sink(u64le((enc.header.size + enc.ciphertext.size).toLong()))
                sink(enc.header)
                sink(enc.ciphertext)
            }
        } finally {
            exportKey.fill(0)
        }
    }

    // ---- open ----

    /** An opened container: validated header, authenticated payload, and on-demand
     *  attachment-section decryption (one section in memory at a time). */
    class OpenedBackup internal constructor(
        val header: BackupHeader,
        val payload: BackupPayload,
        private val crypto: CryptoProvider,
        private val file: ByteArray,
        /** (offset, length) per section, section 0 first. */
        private val sections: List<Pair<Int, Int>>,
    ) {
        val attachmentSectionCount: Int get() = sections.size - 1

        /** Decrypt attachment section [section] (1-based, manifest numbering) with the
         *  manifest's fresh [fileKey]. Fails hard (`wrong_passphrase_or_corrupt`) on any
         *  tag failure, truncation, or reorder — spec 02 §6 discipline. */
        fun readAttachmentSection(section: Int, fileKey: ByteArray): ByteArray {
            if (section !in 1 until sections.size) {
                throw BackupException(ERR_TRUNCATED, "no such attachment section $section (file has $attachmentSectionCount)")
            }
            val (off, len) = sections[section]
            if (len <= Attachments.HEADER_BYTES) throw BackupException(ERR_WRONG_PASSPHRASE_OR_CORRUPT, "attachment section $section too short")
            val header = file.copyOfRange(off, off + Attachments.HEADER_BYTES)
            val ciphertext = file.copyOfRange(off + Attachments.HEADER_BYTES, off + len)
            return try {
                Attachments.decrypt(crypto, fileKey, header, ciphertext)
            } catch (e: CryptoException) {
                throw BackupException(ERR_WRONG_PASSPHRASE_OR_CORRUPT, "attachment section $section failed to decrypt")
            }
        }

        /** Convenience over [readAttachmentSection] driven by a §2.4 manifest entry. */
        fun readAttachment(entry: BackupAttachmentEntry): ByteArray =
            readAttachmentSection(entry.section, Bytes.fromB64(entry.fileKey))
    }

    /**
     * Open a container. Enforces the §2.2 validation ladder — every check BEFORE Argon2
     * runs — with distinct error codes:
     *
     *  0. total size ≤ 256 MiB (`too_large`; the spec's "before any JSON parse" cap)
     *  1. magic == ANDVBK01 (`unknown_format`)
     *  2. headerLen ≤ 64 KiB (`too_large`), header parses as JSON (`unknown_format`),
     *     `format` (`unknown_format`), `v` (`unknown_version` — fail closed, never
     *     downgrade-parse)
     *  3. kdfParams v/alg (`unsupported_kdf`), ceilings memBytes ≤ 256 MiB и opsLimit ≤ 16
     *     (`unsupported_kdf`); params below libsodium's own minima are also
     *     `unsupported_kdf` (argon2id cannot run them — not a policy floor)
     *  4. section framing complete, section 0 present (`truncated`)
     *
     * then derives MKx/exportKey and opens section 0; ANY AEAD failure — wrong
     * passphrase, corruption, or an AD/fileId mismatch — is the single combined
     * `wrong_passphrase_or_corrupt` (indistinguishable by design). Key material and the
     * decrypted payload buffer are zeroed before return (best-effort).
     */
    fun open(crypto: CryptoProvider, passphrase: String, file: ByteArray): OpenedBackup {
        if (file.size.toLong() > MAX_FILE_BYTES) throw BackupException(ERR_TOO_LARGE, "file exceeds 256 MiB")
        if (file.size < MAGIC.size || !file.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            throw BackupException(ERR_UNKNOWN_FORMAT, "not an andvari backup (bad magic)")
        }
        if (file.size < MAGIC.size + 4) throw BackupException(ERR_TRUNCATED, "file ends inside headerLen")
        val headerLen = u32leAt(file, MAGIC.size)
        if (headerLen > MAX_HEADER_BYTES) throw BackupException(ERR_TOO_LARGE, "headerLen exceeds 64 KiB")
        val headerStart = MAGIC.size + 4
        if (headerStart + headerLen > file.size) throw BackupException(ERR_TRUNCATED, "file ends inside header")
        val header = try {
            json.decodeFromString(BackupHeader.serializer(), file.copyOfRange(headerStart, headerStart + headerLen).decodeToString())
        } catch (e: Exception) {
            throw BackupException(ERR_UNKNOWN_FORMAT, "header is not valid backup JSON")
        }
        if (header.format != FORMAT) throw BackupException(ERR_UNKNOWN_FORMAT, "unknown format '${header.format}'")
        if (header.v != VERSION) throw BackupException(ERR_UNKNOWN_VERSION, "unknown backup version ${header.v}")
        val kp = header.kdfParams
        if (kp.v != 1 || kp.alg != "argon2id13") throw BackupException(ERR_UNSUPPORTED_KDF, "unsupported kdf ${kp.alg} v${kp.v}")
        if (kp.memBytes > MAX_KDF_MEM_BYTES || kp.opsLimit > MAX_KDF_OPS) throw BackupException(ERR_UNSUPPORTED_KDF, "kdfParams exceed ceilings")
        if (kp.memBytes < MIN_KDF_MEM_BYTES || kp.opsLimit < MIN_KDF_OPS) throw BackupException(ERR_UNSUPPORTED_KDF, "kdfParams below libsodium minima")
        val kdfSalt = try {
            Bytes.fromB64(header.kdfSalt)
        } catch (e: CryptoException) {
            throw BackupException(ERR_UNKNOWN_FORMAT, "kdfSalt is not base64url")
        }
        if (kdfSalt.size != KdfParams.SALT_BYTES) throw BackupException(ERR_UNSUPPORTED_KDF, "kdfSalt must be ${KdfParams.SALT_BYTES} bytes")

        // Frame every section before any crypto: a tampered/truncated length fails here.
        val sections = ArrayList<Pair<Int, Int>>()
        var off = headerStart + headerLen
        while (off < file.size) {
            if (off + 8 > file.size) throw BackupException(ERR_TRUNCATED, "file ends inside a section length")
            val len = u64leAt(file, off)
            // Compare against the remaining byte count (a non-negative Int, since off+8 ≤ size
            // was just checked) rather than off+8+len — the latter overflows Long for a crafted
            // length near 2^63 and slips past the guard, after which len.toInt() truncates to garbage.
            val remaining = (file.size - off - 8).toLong()
            if (len < 0 || len > remaining) throw BackupException(ERR_TRUNCATED, "section extends past end of file")
            sections.add((off + 8) to len.toInt())
            off += 8 + len.toInt()
        }
        if (sections.isEmpty()) throw BackupException(ERR_TRUNCATED, "missing items section")

        val exportKey = deriveExportKey(crypto, passphrase, kdfSalt, KdfParams(v = kp.v, alg = kp.alg, ops = kp.opsLimit, memBytes = kp.memBytes))
        val plain = try {
            val (s0off, s0len) = sections[0]
            Envelope.open(crypto, exportKey, file.copyOfRange(s0off, s0off + s0len), Ad.export(header.v, header.fileId))
        } catch (e: CryptoException) {
            throw BackupException(ERR_WRONG_PASSPHRASE_OR_CORRUPT, "wrong passphrase or corrupted file")
        } finally {
            exportKey.fill(0)
        }
        val payload = try {
            json.decodeFromString(BackupPayload.serializer(), plain.decodeToString())
        } catch (e: Exception) {
            throw BackupException(ERR_BAD_PAYLOAD, "authenticated payload is not valid backup JSON")
        } finally {
            plain.fill(0)
        }
        return OpenedBackup(header, payload, crypto, file, sections)
    }

    // ---- helpers ----

    /** §2.3: MKx = Argon2id(passphrase as typed) → exportKey = HKDF(info="andvari/v1/export"). */
    private fun deriveExportKey(crypto: CryptoProvider, passphrase: String, kdfSalt: ByteArray, params: KdfParams): ByteArray {
        val mkx = Keys.masterKey(crypto, passphrase, kdfSalt, params)
        val exportKey = Hkdf.sha256(crypto, mkx, ByteArray(0), INFO_EXPORT, Keys.KEY_BYTES)
        mkx.fill(0)
        return exportKey
    }

    private fun u32le(v: Int): ByteArray =
        byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())

    private fun u64le(v: Long): ByteArray =
        ByteArray(8) { i -> ((v ushr (8 * i)) and 0xFF).toByte() }

    private fun u32leAt(b: ByteArray, off: Int): Int {
        var v = 0L
        for (i in 0 until 4) v = v or ((b[off + i].toLong() and 0xFF) shl (8 * i))
        if (v > Int.MAX_VALUE) throw BackupException(ERR_TOO_LARGE, "headerLen exceeds 64 KiB")
        return v.toInt()
    }

    /** Reads a u64 LE; values with bit 63 set come back negative and are rejected by the
     *  caller's bounds check (a real section can never approach 2^63 under the file cap). */
    private fun u64leAt(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[off + i].toLong() and 0xFF) shl (8 * i))
        return v
    }
}
