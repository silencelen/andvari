package io.silencelen.andvari.core.crypto

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Why a [SignedStatement] was refused (spec 01 §5.1). The wire [code] is shared with the web twin
 * and pinned by `spec/test-vectors/signedstatement.json`; the first failing step decides it.
 */
enum class StatementVerdict(val code: String) {
    /** Not a v2 frame: the first four bytes are not `avs\x02` (a v1 JSON blob, another version, garbage). */
    UNKNOWN_FORMAT("unknown_format"),
    /** A v2 frame with a bad length, a reserved purpose code, or not the purpose the caller expects. */
    BAD_FRAME("bad_frame"),
    /** The statement is not byte-identical to its canonical re-encoding (any grammar or shape breach). */
    NON_CANONICAL("non_canonical"),
    /** Canonical, but semantically refused: `v != 2`, purpose literal ≠ purpose code, grant `from == to`. */
    BAD_STATEMENT("bad_statement"),
    /** The shipped signerPub does not map to the PINNED identityPub (or is not a usable point). */
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key"),
    /** The Ed25519 signature does not verify over M under signerPub. */
    BAD_SIGNATURE("bad_signature"),
}

class SignedStatementException(val verdict: StatementVerdict, detail: String) :
    Exception("signed statement refused: ${verdict.code} ($detail)")

/** The purpose code in byte 4 of the frame and the matching `purpose` literal inside the statement. */
enum class StatementPurpose(val code: Int, val literal: String) {
    VAULT_GRANT(0x01, "vault-grant"),
    ESCROW_UVK(0x02, "escrow-uvk"),
    ;

    companion object {
        fun fromCode(code: Int): StatementPurpose? = entries.firstOrNull { it.code == code }
    }
}

/** What the first bytes of a grant/escrow seal's plaintext say it is (design §1.2 format detection). */
enum class BlobFormat { V1_JSON, V2_SIGNED, UNKNOWN }

/**
 * A v2 statement's fields (spec 01 §5.1). Construct freely; only [SignedStatement.encode] decides
 * whether the values are inside the closed grammar, and only [SignedStatement.verify] yields one
 * that may be trusted (wrapped in [VerifiedStatement]).
 */
sealed class Statement {
    abstract val purpose: StatementPurpose
    abstract val issuedAt: Long

    /** `purpose = vault-grant`: [from] grants [vk] for [vaultId] to [to], whose X25519 identity key is [toKey]. */
    class VaultGrant(
        val from: String,
        val to: String,
        val toKey: ByteArray,
        val vaultId: String,
        val grantId: ByteArray,
        override val issuedAt: Long,
        val vk: ByteArray,
    ) : Statement() {
        override val purpose get() = StatementPurpose.VAULT_GRANT
    }

    /** `purpose = escrow-uvk`: [userId]'s UVK ([key]) sealed to the org key whose full fingerprint is [recoveryFp]. */
    class EscrowUvk(
        val userId: String,
        val identityKey: ByteArray,
        val recoveryFp: String,
        override val issuedAt: Long,
        val key: ByteArray,
    ) : Statement() {
        override val purpose get() = StatementPurpose.ESCROW_UVK
    }
}

/**
 * A statement that passed EVERY step of [SignedStatement.verify]: frame, strict canonical parse,
 * signer-key → pinned-identity mapping, signature. The constructor is internal, so code outside
 * core cannot mint one; it exists only as the output of that one helper.
 */
class VerifiedStatement internal constructor(val statement: Statement, val signerPub: ByteArray)

/** The four parts of a v2 frame, split but NOT verified. */
class SignedStatementFrame internal constructor(
    val purposeCode: Int,
    val signerPub: ByteArray,
    val signature: ByteArray,
    val statement: ByteArray,
)

/**
 * The v2 `SignedStatement` envelope and its canonical statement (security review 2026-10, root cause A
 * §1.1–§1.3; spec 01 §5.1). Plaintext layout, sealed later with crypto_box_seal by the callers that
 * arrive in later branches (escrow v2, signed grants); A3 ships the codec and the verify helper only:
 *
 * ```
 * 0    4   magic        61 76 73 02   ("avs" + version 0x02)
 * 4    1   purposeCode  01 vault-grant | 02 escrow-uvk   (others reserved → bad_frame)
 * 5    32  signerPub    Ed25519 public key
 * 37   64  signature    Ed25519 over M = "andvari/v2|signed-statement" ‖ 0x00 ‖ P[0..5) ‖ signerPub ‖ statement
 * 101  N   statement    canonical JSON, printable ASCII, 2 <= N <= 1024
 * ```
 *
 * Every value in a statement comes from a closed grammar that never needs escaping, and the parser is
 * STRICT: platform JSON parse, exact key set, per-field grammar, then re-encode through the same
 * template and byte-compare. Whitespace, key order, duplicate or unknown keys, escapes, number forms,
 * non-canonical base64, trailing bytes: all land on [StatementVerdict.NON_CANONICAL], identically in
 * the web twin (web/src/crypto/signedstatement.ts), because the decisive check is a byte compare.
 */
object SignedStatement {
    val MAGIC: ByteArray = byteArrayOf(0x61, 0x76, 0x73, 0x02)
    const val DOMAIN = "andvari/v2|signed-statement"
    const val HEADER_BYTES = 5
    const val SIGNER_BYTES = 32
    const val SIGNATURE_BYTES = 64
    const val STATEMENT_OFFSET = HEADER_BYTES + SIGNER_BYTES + SIGNATURE_BYTES // 101
    const val MIN_STATEMENT_BYTES = 2
    const val MAX_STATEMENT_BYTES = 1024

    /** 2^53: `issuedAt` is a JS-safe integer, `1 <= x < 2^53`. */
    private const val MS_CEILING = 9007199254740992L

    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val HEX64_RE = Regex("^[0-9a-f]{64}$")
    private val B64_22_RE = Regex("^[A-Za-z0-9_-]{22}$")
    private val B64_43_RE = Regex("^[A-Za-z0-9_-]{43}$")
    private val MS_RE = Regex("^[1-9][0-9]{0,15}$")
    private val V_RE = Regex("^(0|[1-9][0-9]{0,8})$")

    private val GRANT_KEYS = listOf("v", "purpose", "from", "to", "toKey", "vaultId", "grantId", "issuedAt", "vk")
    private val ESCROW_KEYS = listOf("v", "purpose", "userId", "identityKey", "recoveryFp", "issuedAt", "key")

    private val json = Json // strict defaults: no lenient parsing, no comments, no trailing commas

    // ---- format detection -------------------------------------------------------------------------

    /** `{` → a v1 legacy JSON payload; the v2 magic → a signed statement; anything else → unknown (refuse). */
    fun formatOf(plaintext: ByteArray): BlobFormat = when {
        plaintext.isNotEmpty() && plaintext[0] == '{'.code.toByte() -> BlobFormat.V1_JSON
        plaintext.size >= MAGIC.size && plaintext.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) -> BlobFormat.V2_SIGNED
        else -> BlobFormat.UNKNOWN
    }

    // ---- canonical statement ----------------------------------------------------------------------

    /**
     * The canonical statement bytes. Refuses ([CryptoException]) any value outside the closed grammar
     * and a vault grant with `from == to`, so a statement this client signs always parses back.
     */
    fun encode(statement: Statement): ByteArray {
        val bytes = when (statement) {
            is Statement.VaultGrant -> {
                need(isUuid(statement.from), "from is not a lowercase uuid")
                need(isUuid(statement.to), "to is not a lowercase uuid")
                need(statement.from != statement.to, "a vault grant cannot be addressed to its sender")
                need(statement.toKey.size == 32, "toKey must be 32 bytes")
                need(isUuid(statement.vaultId), "vaultId is not a lowercase uuid")
                need(statement.grantId.size == 16, "grantId must be 16 bytes")
                need(isMs(statement.issuedAt), "issuedAt out of range")
                need(statement.vk.size == 32, "vk must be 32 bytes")
                grantTemplate(
                    2, StatementPurpose.VAULT_GRANT.literal, statement.from, statement.to, Bytes.toB64(statement.toKey),
                    statement.vaultId, Bytes.toB64(statement.grantId), statement.issuedAt, Bytes.toB64(statement.vk),
                )
            }
            is Statement.EscrowUvk -> {
                need(isUuid(statement.userId), "userId is not a lowercase uuid")
                need(statement.identityKey.size == 32, "identityKey must be 32 bytes")
                need(HEX64_RE.matches(statement.recoveryFp), "recoveryFp is not 64 lowercase hex")
                need(isMs(statement.issuedAt), "issuedAt out of range")
                need(statement.key.size == 32, "key must be 32 bytes")
                escrowTemplate(
                    2, StatementPurpose.ESCROW_UVK.literal, statement.userId, Bytes.toB64(statement.identityKey),
                    statement.recoveryFp, statement.issuedAt, Bytes.toB64(statement.key),
                )
            }
        }.encodeToByteArray()
        need(bytes.size in MIN_STATEMENT_BYTES..MAX_STATEMENT_BYTES, "statement length out of range")
        return bytes
    }

    private fun grantTemplate(
        v: Int, purpose: String, from: String, to: String, toKey: String, vaultId: String, grantId: String, issuedAt: Long, vk: String,
    ) = """{"v":$v,"purpose":"$purpose","from":"$from","to":"$to","toKey":"$toKey","vaultId":"$vaultId","grantId":"$grantId","issuedAt":$issuedAt,"vk":"$vk"}"""

    private fun escrowTemplate(
        v: Int, purpose: String, userId: String, identityKey: String, recoveryFp: String, issuedAt: Long, key: String,
    ) = """{"v":$v,"purpose":"$purpose","userId":"$userId","identityKey":"$identityKey","recoveryFp":"$recoveryFp","issuedAt":$issuedAt,"key":"$key"}"""

    /**
     * STRICT parse of a statement under [purposeCode] (spec 01 §5.1 steps, in order):
     * 1. length 2..1024 and a known purpose code, else `bad_frame`;
     * 2. every byte printable ASCII (0x20..0x7E), else `non_canonical`;
     * 3. platform JSON parse to an object with EXACTLY the purpose's key set, else `non_canonical`;
     * 4. every value inside its grammar, else `non_canonical`;
     * 5. re-encode through the template and byte-compare with the input, else `non_canonical`
     *    (this is what catches whitespace, order, duplicates, escapes and number forms on every engine);
     * 6. `v == 2`, purpose literal == purpose code, grant `from != to`, else `bad_statement`.
     *
     * The result is NOT authenticated. A caller may read it only to choose which pin to verify
     * against; trust comes from [verify] alone.
     */
    fun parseStatement(purposeCode: Int, statement: ByteArray): Statement {
        val purpose = StatementPurpose.fromCode(purposeCode) ?: refuse(StatementVerdict.BAD_FRAME, "unknown purpose code")
        if (statement.size !in MIN_STATEMENT_BYTES..MAX_STATEMENT_BYTES) refuse(StatementVerdict.BAD_FRAME, "statement length")
        if (statement.any { it < 0x20 || it > 0x7E }) refuse(StatementVerdict.NON_CANONICAL, "not printable ASCII")
        val text = statement.decodeToString()
        val obj = try {
            json.parseToJsonElement(text) as? JsonObject
        } catch (e: Exception) {
            null
        } ?: refuse(StatementVerdict.NON_CANONICAL, "not a JSON object")

        val keys = if (purpose == StatementPurpose.VAULT_GRANT) GRANT_KEYS else ESCROW_KEYS
        if (obj.keys != keys.toSet() || obj.size != keys.size) refuse(StatementVerdict.NON_CANONICAL, "key set")

        val v = number(obj, "v", V_RE).toInt()
        val purposeLiteral = string(obj, "purpose")
        if (StatementPurpose.entries.none { it.literal == purposeLiteral }) refuse(StatementVerdict.NON_CANONICAL, "purpose literal")
        val issuedAt = number(obj, "issuedAt", MS_RE)
        if (issuedAt >= MS_CEILING) refuse(StatementVerdict.NON_CANONICAL, "issuedAt out of range")

        val parsed: Statement
        val reEncoded: String
        when (purpose) {
            StatementPurpose.VAULT_GRANT -> {
                val g = Statement.VaultGrant(
                    from = uuid(obj, "from"), to = uuid(obj, "to"), toKey = b64(obj, "toKey", 32),
                    vaultId = uuid(obj, "vaultId"), grantId = b64(obj, "grantId", 16), issuedAt = issuedAt, vk = b64(obj, "vk", 32),
                )
                reEncoded = grantTemplate(
                    v, purposeLiteral, g.from, g.to, Bytes.toB64(g.toKey), g.vaultId, Bytes.toB64(g.grantId), g.issuedAt, Bytes.toB64(g.vk),
                )
                parsed = g
            }
            StatementPurpose.ESCROW_UVK -> {
                val recoveryFp = string(obj, "recoveryFp")
                if (!HEX64_RE.matches(recoveryFp)) refuse(StatementVerdict.NON_CANONICAL, "recoveryFp grammar")
                val e = Statement.EscrowUvk(
                    userId = uuid(obj, "userId"), identityKey = b64(obj, "identityKey", 32), recoveryFp = recoveryFp,
                    issuedAt = issuedAt, key = b64(obj, "key", 32),
                )
                reEncoded = escrowTemplate(v, purposeLiteral, e.userId, Bytes.toB64(e.identityKey), e.recoveryFp, e.issuedAt, Bytes.toB64(e.key))
                parsed = e
            }
        }
        if (!reEncoded.encodeToByteArray().contentEquals(statement)) refuse(StatementVerdict.NON_CANONICAL, "not the canonical encoding")

        if (v != 2) refuse(StatementVerdict.BAD_STATEMENT, "statement version $v")
        if (purposeLiteral != purpose.literal) refuse(StatementVerdict.BAD_STATEMENT, "purpose literal does not match the purpose code")
        if (parsed is Statement.VaultGrant && parsed.from == parsed.to) refuse(StatementVerdict.BAD_STATEMENT, "grant from == to")
        return parsed
    }

    // ---- frame ------------------------------------------------------------------------------------

    /** The signed message M (design §1.2). */
    fun signedMessage(purposeCode: Int, signerPub: ByteArray, statement: ByteArray): ByteArray =
        DOMAIN.encodeToByteArray() + byteArrayOf(0) + MAGIC + byteArrayOf(purposeCode.toByte()) + signerPub + statement

    /** Encode, sign with the joint key [signer] (from [CryptoProvider.signKeypairFromSeed]) and frame. */
    fun build(crypto: CryptoProvider, signer: KeyPairBytes, statement: Statement): ByteArray {
        need(signer.publicKey.size == SIGNER_BYTES, "signer public key must be 32 bytes")
        val body = encode(statement)
        val code = statement.purpose.code
        val sig = crypto.signDetached(signer.privateKey, signedMessage(code, signer.publicKey, body))
        return MAGIC + byteArrayOf(code.toByte()) + signer.publicKey + sig + body
    }

    /** Split a frame. Refuses (`bad_frame` / `unknown_format`) before any field is looked at. */
    fun parseFrame(frame: ByteArray): SignedStatementFrame {
        if (frame.size < MAGIC.size) refuse(StatementVerdict.BAD_FRAME, "shorter than the magic")
        if (!frame.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) refuse(StatementVerdict.UNKNOWN_FORMAT, "magic")
        if (frame.size < STATEMENT_OFFSET + MIN_STATEMENT_BYTES || frame.size > STATEMENT_OFFSET + MAX_STATEMENT_BYTES) {
            refuse(StatementVerdict.BAD_FRAME, "frame length ${frame.size}")
        }
        val code = frame[4].toInt() and 0xFF
        if (StatementPurpose.fromCode(code) == null) refuse(StatementVerdict.BAD_FRAME, "reserved purpose code $code")
        return SignedStatementFrame(
            purposeCode = code,
            signerPub = frame.copyOfRange(HEADER_BYTES, HEADER_BYTES + SIGNER_BYTES),
            signature = frame.copyOfRange(HEADER_BYTES + SIGNER_BYTES, STATEMENT_OFFSET),
            statement = frame.copyOfRange(STATEMENT_OFFSET, frame.size),
        )
    }

    /**
     * THE signer-key binding helper — the only way to get a [VerifiedStatement]. Fails closed, first
     * failing step decides the verdict (design §1.4 steps 2, 3, 8, 9):
     * 1. [parseFrame]; the frame's purpose code must be [expectedPurpose] (`bad_frame`);
     * 2. [parseStatement] — strict canonical parse (`non_canonical` / `bad_statement`);
     * 3. `ed25519PkToCurve25519(signerPub) == pinnedIdentityPub` (`signer_not_pinned_key`);
     *    [pinnedIdentityPub] MUST come from an out-of-band pin, never from a server response;
     * 4. `crypto_sign_verify_detached(signature, M, signerPub)` (`bad_signature`).
     *
     * Field checks that depend on the caller (`to == me`, `vaultId == row`, held-key compare) are the
     * caller's, AFTER this returns.
     */
    fun verify(
        crypto: CryptoProvider,
        frame: ByteArray,
        expectedPurpose: StatementPurpose,
        pinnedIdentityPub: ByteArray,
    ): VerifiedStatement {
        val f = parseFrame(frame)
        if (f.purposeCode != expectedPurpose.code) refuse(StatementVerdict.BAD_FRAME, "purpose code ${f.purposeCode}, expected ${expectedPurpose.code}")
        val statement = parseStatement(f.purposeCode, f.statement)
        if (pinnedIdentityPub.size != 32) refuse(StatementVerdict.SIGNER_NOT_PINNED_KEY, "pinned identity key is not 32 bytes")
        val curve = try {
            crypto.ed25519PkToCurve25519(f.signerPub)
        } catch (e: CryptoException) {
            refuse(StatementVerdict.SIGNER_NOT_PINNED_KEY, "signerPub is not a usable Ed25519 point")
        }
        if (!Bytes.ctEquals(curve, pinnedIdentityPub)) refuse(StatementVerdict.SIGNER_NOT_PINNED_KEY, "signerPub does not map to the pinned identity")
        if (!crypto.signVerifyDetached(f.signerPub, f.signature, signedMessage(f.purposeCode, f.signerPub, f.statement))) {
            refuse(StatementVerdict.BAD_SIGNATURE, "signature does not verify")
        }
        return VerifiedStatement(statement, f.signerPub)
    }

    // ---- helpers ----------------------------------------------------------------------------------

    private fun refuse(verdict: StatementVerdict, detail: String): Nothing = throw SignedStatementException(verdict, detail)

    private fun need(ok: Boolean, what: String) {
        if (!ok) throw CryptoException("signed statement: $what")
    }

    private fun isUuid(s: String) = UUID_RE.matches(s)
    private fun isMs(x: Long) = x in 1 until MS_CEILING

    private fun string(obj: JsonObject, key: String): String {
        val p = obj[key] as? JsonPrimitive
        if (p == null || !p.isString) refuse(StatementVerdict.NON_CANONICAL, "$key is not a string")
        return p.content
    }

    private fun number(obj: JsonObject, key: String, re: Regex): Long {
        val p = obj[key] as? JsonPrimitive
        if (p == null || p.isString || !re.matches(p.content)) refuse(StatementVerdict.NON_CANONICAL, "$key grammar")
        return p.content.toLong()
    }

    private fun uuid(obj: JsonObject, key: String): String =
        string(obj, key).also { if (!isUuid(it)) refuse(StatementVerdict.NON_CANONICAL, "$key grammar") }

    private fun b64(obj: JsonObject, key: String, len: Int): ByteArray {
        val s = string(obj, key)
        val re = if (len == 16) B64_22_RE else B64_43_RE
        if (!re.matches(s)) refuse(StatementVerdict.NON_CANONICAL, "$key grammar")
        val bytes = try {
            Bytes.fromB64(s)
        } catch (e: CryptoException) {
            refuse(StatementVerdict.NON_CANONICAL, "$key is not base64url")
        }
        if (bytes.size != len || Bytes.toB64(bytes) != s) refuse(StatementVerdict.NON_CANONICAL, "$key is not canonical base64url")
        return bytes
    }
}
