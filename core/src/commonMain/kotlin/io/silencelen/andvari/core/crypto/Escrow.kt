package io.silencelen.andvari.core.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** spec 04 §3 — sealed escrow payload (canonical JSON: exact key order, no whitespace). */
@Serializable
data class EscrowPayload(
    @SerialName("v") val v: Int,
    @SerialName("userId") val userId: String,
    @SerialName("keyType") val keyType: String,
    @SerialName("key") val key: String,
    @SerialName("sha256") val sha256: String,
)

/** Which escrow format [Escrow.open] accepted. A v1 blob is LEGACY and never reported as v2-equivalent. */
enum class EscrowFormat(val code: String) { V2("v2"), V1_LEGACY("v1_legacy") }

/**
 * Why [Escrow.open] refused (spec 04 §4). The wire [code] is shared with the web twin and pinned by
 * `spec/test-vectors/escrow-v2.json`; the first failing step decides it.
 */
enum class EscrowVerdict(val code: String) {
    BAD_USER_ID("bad_user_id"),
    BAD_ANCHOR("bad_anchor"),
    UNANCHORED_NOT_ACKNOWLEDGED("unanchored_not_acknowledged"),
    IDENTITY_CHECK_REQUIRED("identity_check_required"),
    IDENTITY_FP_MISMATCH("identity_fp_mismatch"),
    UNOPENABLE("unopenable"),
    UNKNOWN_FORMAT("unknown_format"),
    BAD_FRAME("bad_frame"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),
    USER_MISMATCH("user_mismatch"),
    RECOVERY_FP_MISMATCH("recovery_fp_mismatch"),
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key"),
    BAD_SIGNATURE("bad_signature"),
    IDENTITY_MISMATCH("identity_mismatch"),
    V1_MALFORMED("v1_malformed"),
    V1_SELF_CHECK_FAILED("v1_self_check_failed"),
    IDENTITY_CHECK_FAILED("identity_check_failed"),
    ;

    companion object {
        internal fun fromStatement(v: StatementVerdict): EscrowVerdict = when (v) {
            StatementVerdict.UNKNOWN_FORMAT -> UNKNOWN_FORMAT
            StatementVerdict.BAD_FRAME -> BAD_FRAME
            StatementVerdict.NON_CANONICAL -> NON_CANONICAL
            StatementVerdict.BAD_STATEMENT -> BAD_STATEMENT
            StatementVerdict.SIGNER_NOT_PINNED_KEY -> SIGNER_NOT_PINNED_KEY
            StatementVerdict.BAD_SIGNATURE -> BAD_SIGNATURE
            StatementVerdict.USER_MISMATCH -> USER_MISMATCH
            StatementVerdict.RECOVERY_FP_MISMATCH -> RECOVERY_FP_MISMATCH
            StatementVerdict.IDENTITY_MISMATCH -> IDENTITY_MISMATCH
        }
    }
}

class EscrowOpenException(val verdict: EscrowVerdict, detail: String) :
    Exception("escrow refused: ${verdict.code} ($detail)")

/**
 * The server-supplied identity file from the admin escrow download (design §2.5): the account's
 * UVK-sealed identity seed and its claimed X25519 identity public key. Never trusted on its own;
 * [Escrow.open] checks it against the out-of-band anchor and the escrowed key.
 */
class IdentityCheck(val encryptedIdentitySeedB64: String, val identityPubB64: String)

/** The checks [Escrow.open] ran and passed, in order (printed by the recovery CLI). */
enum class EscrowCheck {
    IDENTITY_ANCHOR,
    UNANCHORED_ACKNOWLEDGED,
    SEALED_TO_RECOVERY_KEY,
    V1_SELF_CHECK,
    USER_ID,
    RECOVERY_FP,
    SIGNER_IS_IDENTITY,
    SIGNATURE,
    IDENTITY_BOUND,
    IDENTITY_SEED,
}

/**
 * A successfully opened escrow blob. Read-only: [uvk] and [identityKey] hand out copies; [wipe]
 * zeroes the held UVK once the caller has re-wrapped it. [userId] is always the caller's
 * `expectedUserId` (the blob was proven to be issued for it), never a value read from the payload.
 */
class EscrowOpened internal constructor(
    val format: EscrowFormat,
    val userId: String,
    uvk: ByteArray,
    identityKey: ByteArray,
    /** False only in the acknowledged unanchored mode (Q2): the bundle must then say UNANCHORED. */
    val anchored: Boolean,
    val checks: List<EscrowCheck>,
) {
    private val uvkBytes = uvk.copyOf()
    private val identityKeyBytes = identityKey.copyOf()
    val uvk: ByteArray get() = uvkBytes.copyOf()
    val identityKey: ByteArray get() = identityKeyBytes.copyOf()
    fun wipe() = uvkBytes.fill(0)
}

object Escrow {
    const val KEY_TYPE_UVK = "uvk"
    const val KEY_TYPE_CANARY = "canary"
    const val CANARY_USER_ID = "00000000-0000-0000-0000-000000000000"

    /** spec 04 §4 — the fixed canary key: 32 bytes of 0x5A. */
    val CANARY_KEY: ByteArray get() = ByteArray(32) { 0x5A }

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Canonical bytes — built by string template to guarantee key order and no whitespace.
     *
     * [userId] is SERVER-SUPPLIED (it arrives on the session response), so the template is
     * composed under the same precondition [Ad.join] applies to its own separator: a conforming
     * id is a lowercase UUID and cannot contain `"` or `\`. Without it a hostile server could
     * return `x","keyType":"canary` and choose the JSON STRUCTURE of the blob the enrolling
     * client seals — no secret leaks (it is sealed to the org recovery public key the attacker
     * does not hold), but the member's recovery blob decodes as the wrong keyType or not at all,
     * and nobody finds out until the drill or the real recovery. Refusing to seal is the honest
     * failure: an availability denial the server could mount anyway (spec 05 T1), surfaced now
     * instead of at the worst possible moment.
     */
    fun canonicalPayload(userId: String, keyType: String, keyBytes: ByteArray, crypto: CryptoProvider): ByteArray {
        requireJsonSafe(userId, "escrow userId")
        requireJsonSafe(keyType, "escrow keyType")
        val keyB64 = Bytes.toB64(keyBytes)
        val shaB64 = Bytes.toB64(crypto.sha256(keyBytes))
        return """{"v":1,"userId":"$userId","keyType":"$keyType","key":"$keyB64","sha256":"$shaB64"}"""
            .encodeToByteArray()
    }

    /**
     * The v1 (legacy) escrow seal: canonical JSON with a sha256 self-check, sealed anonymously. No
     * client seals this since the escrow v2 branch (security review 2026-10, root cause A): enrolment,
     * re-seal and migration all call [sealUvkV2]. It stays for the vector generator and for tests that
     * need a legacy blob, because v1 blobs remain recoverable indefinitely (owner decision Q3) through
     * [open]'s mandatory identity check.
     */
    fun sealUvkV1(crypto: CryptoProvider, recoveryPub: ByteArray, userId: String, uvk: ByteArray): ByteArray =
        crypto.sealTo(recoveryPub, canonicalPayload(userId, KEY_TYPE_UVK, uvk, crypto))

    fun sealCanary(crypto: CryptoProvider, recoveryPub: ByteArray): ByteArray =
        crypto.sealTo(recoveryPub, canonicalPayload(CANARY_USER_ID, KEY_TYPE_CANARY, CANARY_KEY, crypto))

    /**
     * Escrow v2 seal (security review 2026-10, root cause A §2.1; spec 04 §3): an `escrow-uvk`
     * [SignedStatement] binding [userId], the member's seed-derived X25519 identity key, the FULL org
     * recovery fingerprint and the UVK, signed with the member's joint Ed25519 key ([signer], from
     * [CryptoProvider.signKeypairFromSeed] over the identity seed) and sealed to [recoveryPub].
     *
     * REFUSES ([CryptoException]) unless `hex(SHA-256(recoveryPub)) == verifiedRecoveryFp` IN FULL
     * (64 lowercase hex). [verifiedRecoveryFp] must come from a human (the typed 32-hex sheet check
     * against it) or the build, never straight from a server response; a 32-hex short form is not
     * enough here, because a machine compare is always full length (design §7.1).
     *
     * [identityPub] must be the key [signer] maps to; a mismatch is refused too, so a client can never
     * seal a statement its own anchor check would reject. The canary stays v1 ([sealCanary]).
     */
    fun sealUvkV2(
        crypto: CryptoProvider,
        recoveryPub: ByteArray,
        verifiedRecoveryFp: String,
        userId: String,
        identityPub: ByteArray,
        signer: KeyPairBytes,
        uvk: ByteArray,
        issuedAt: Long,
    ): ByteArray {
        if (recoveryPub.size != 32) throw CryptoException("recovery public key must be 32 bytes")
        if (!FULL_FP_RE.matches(verifiedRecoveryFp) || fingerprint(crypto, recoveryPub) != verifiedRecoveryFp) {
            throw CryptoException("recovery public key does not match the verified fingerprint (full compare) — refusing to seal escrow")
        }
        if (uvk.size != 32) throw CryptoException("escrow uvk must be 32 bytes")
        val mapped = try {
            crypto.ed25519PkToCurve25519(signer.publicKey)
        } catch (e: CryptoException) {
            throw CryptoException("escrow signer is not a usable Ed25519 key", e)
        }
        if (!Bytes.ctEquals(mapped, identityPub)) throw CryptoException("escrow signer does not map to the identity key it would name")
        val frame = SignedStatement.build(crypto, signer, Statement.EscrowUvk(userId, identityPub, verifiedRecoveryFp, issuedAt, uvk))
        return try {
            crypto.sealTo(recoveryPub, frame)
        } finally {
            frame.fill(0) // the frame carries the UVK in base64; the sealed box is all that leaves
        }
    }

    // ---- open (spec 04 §4; design §2.2–§2.3) -------------------------------------------------------

    /** The typed acknowledgment an admin gives for an UNANCHORED recovery (owner decision Q2). */
    const val UNANCHORED_ACK = "I understand this recovery is UNANCHORED"

    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val ANCHOR_RE = Regex("^[0-9a-f]{32,64}$")
    private val FULL_FP_RE = Regex("^[0-9a-f]{64}$")

    /**
     * Open a member's escrow blob for recovery (or the fleet drill), FAIL CLOSED. This is the ONLY
     * opener for a member blob: the bare `open(…, sealed)` that adopted whatever account the payload
     * named is gone, so no caller can take the in-payload identity unchecked.
     *
     * Inputs that decide trust, all OUT OF BAND or checked here:
     * - [expectedUserId] (REQUIRED, lowercase uuid): the account the admin named. No overload without it.
     * - [expectedIdentityFpPrefix]: >= 32 lowercase hex of `SHA-256(identityPub)`, from a human (the
     *   admin's own pin, the member's sheet, a co-member's pin). `null` ONLY in unanchored mode, which
     *   also needs [unanchoredAcknowledgment] == [UNANCHORED_ACK] (owner decision Q2).
     * - [identityCheck] (REQUIRED): the server-supplied `{encryptedIdentitySeed, identityPub}` from the
     *   admin download. It is used only as something to check against: the anchor must vouch for its
     *   identityPub, and the escrowed UVK must open its seed to that same key.
     *
     * Order — the first failing step decides the [EscrowVerdict]:
     * 0. inputs: `bad_user_id`, `bad_anchor`, `unanchored_not_acknowledged`, `identity_check_required`,
     *    `identity_check_failed` (identityPub not 32 bytes);
     * 1. anchor: `hex(SHA-256(identityCheck.identityPub))` starts with the prefix (`identity_fp_mismatch`).
     *    This is the ONLY place an identity enters the trust path, and it never comes from the blob;
     * 2. `crypto_box_seal_open` (`unopenable`); 3. format (`unknown_format`);
     * v2: 4–9. [SignedStatement.verifyEscrow] with the anchored identity, `expectedUserId` and the
     *    opening key's own fingerprint (`bad_frame`, `non_canonical`, `bad_statement`, `user_mismatch`,
     *    `recovery_fp_mismatch`, `signer_not_pinned_key`, `bad_signature`, `identity_mismatch`);
     * v1: 4′. legacy JSON, `v == 1`, `keyType == "uvk"`, 32-byte key (`v1_malformed`), sha256 self-check
     *    — integrity only (`v1_self_check_failed`); 5′. `userId` (`user_mismatch`);
     * 10. identity check: open `encryptedIdentitySeed` under the escrowed key with `Ad.idkey(expectedUserId)`,
     *    derive the X25519 public key, require it == the anchored identity (`identity_check_failed`).
     *    Mandatory for BOTH formats; for v1 it is what makes the blob authentic at all (a forged UVK'
     *    cannot open the real seed, and a forged seed cannot derive the anchored key).
     *
     * A v1 blob yields [EscrowFormat.V1_LEGACY], never a v2-equivalent result.
     */
    fun open(
        crypto: CryptoProvider,
        recoveryKeypair: KeyPairBytes,
        sealed: ByteArray,
        expectedUserId: String,
        expectedIdentityFpPrefix: String?,
        identityCheck: IdentityCheck?,
        unanchoredAcknowledgment: String? = null,
    ): EscrowOpened {
        val checks = mutableListOf<EscrowCheck>()
        // 0. inputs
        if (!UUID_RE.matches(expectedUserId)) refuse(EscrowVerdict.BAD_USER_ID, "expectedUserId is not a lowercase uuid")
        val anchored = expectedIdentityFpPrefix != null
        if (anchored) {
            if (!ANCHOR_RE.matches(expectedIdentityFpPrefix!!)) refuse(EscrowVerdict.BAD_ANCHOR, "identity anchor must be 32..64 lowercase hex")
        } else if (unanchoredAcknowledgment != UNANCHORED_ACK) {
            refuse(EscrowVerdict.UNANCHORED_NOT_ACKNOWLEDGED, "an unanchored recovery needs the typed acknowledgment")
        }
        if (identityCheck == null) refuse(EscrowVerdict.IDENTITY_CHECK_REQUIRED, "recovery needs the identity file (encryptedIdentitySeed + identityPub)")
        val identityPub = runCatching { Bytes.fromB64(identityCheck.identityPubB64) }.getOrNull()
        if (identityPub == null || identityPub.size != 32) refuse(EscrowVerdict.IDENTITY_CHECK_FAILED, "identity file identityPub is not a 32-byte key")

        // 1. anchor — the identity is vouched for out of band, before anything is read from the blob.
        if (anchored) {
            if (!fingerprint(crypto, identityPub).startsWith(expectedIdentityFpPrefix!!)) {
                refuse(EscrowVerdict.IDENTITY_FP_MISMATCH, "identity does not match the fingerprint you were given")
            }
            checks += EscrowCheck.IDENTITY_ANCHOR
        } else {
            checks += EscrowCheck.UNANCHORED_ACKNOWLEDGED
        }

        // 2. seal
        val plaintext = try {
            crypto.sealOpen(recoveryKeypair.publicKey, recoveryKeypair.privateKey, sealed)
        } catch (e: CryptoException) {
            refuse(EscrowVerdict.UNOPENABLE, "not sealed to this recovery key")
        }
        checks += EscrowCheck.SEALED_TO_RECOVERY_KEY
        val orgFp = fingerprint(crypto, recoveryKeypair.publicKey)

        try {
            // 3. format
            val format: EscrowFormat
            val uvk: ByteArray
            when (SignedStatement.formatOf(plaintext)) {
                BlobFormat.V2_SIGNED -> {
                    val verified = try {
                        SignedStatement.verifyEscrow(crypto, plaintext, expectedUserId, identityPub, orgFp)
                    } catch (e: SignedStatementException) {
                        refuse(EscrowVerdict.fromStatement(e.verdict), e.message ?: e.verdict.code)
                    }
                    checks += listOf(EscrowCheck.USER_ID, EscrowCheck.RECOVERY_FP, EscrowCheck.SIGNER_IS_IDENTITY, EscrowCheck.SIGNATURE, EscrowCheck.IDENTITY_BOUND)
                    format = EscrowFormat.V2
                    uvk = (verified.statement as Statement.EscrowUvk).key
                }
                BlobFormat.V1_JSON -> {
                    val payload = parseV1(crypto, plaintext)
                    checks += EscrowCheck.V1_SELF_CHECK
                    if (payload.userId != expectedUserId) refuse(EscrowVerdict.USER_MISMATCH, "this backstop key belongs to another account")
                    checks += EscrowCheck.USER_ID
                    format = EscrowFormat.V1_LEGACY
                    uvk = Bytes.fromB64(payload.key)
                }
                BlobFormat.UNKNOWN -> refuse(EscrowVerdict.UNKNOWN_FORMAT, "unknown backstop key format")
            }

            // 10. identity check (both formats).
            try {
                val derived = try {
                    val seed = Envelope.openB64(crypto, uvk, identityCheck.encryptedIdentitySeedB64, Ad.idkey(expectedUserId))
                    try {
                        crypto.boxKeypairFromSeed(seed)
                    } finally {
                        seed.fill(0)
                    }
                } catch (e: CryptoException) {
                    refuse(EscrowVerdict.IDENTITY_CHECK_FAILED, "the escrowed key does not open this account's identity")
                }
                derived.privateKey.fill(0)
                if (!Bytes.ctEquals(derived.publicKey, identityPub)) {
                    refuse(EscrowVerdict.IDENTITY_CHECK_FAILED, "the escrowed key does not open this account's identity")
                }
                checks += EscrowCheck.IDENTITY_SEED
                return EscrowOpened(format, expectedUserId, uvk, identityPub, anchored, checks.toList())
            } finally {
                uvk.fill(0)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    /**
     * Open the fixed canary blob (spec 04 §4) and prove the sheet works. A canary belongs to no
     * member and yields no key anyone uses, so it has its own opener; [open] refuses a canary.
     */
    fun openCanary(crypto: CryptoProvider, recoveryKeypair: KeyPairBytes, sealed: ByteArray) {
        val plaintext = crypto.sealOpen(recoveryKeypair.publicKey, recoveryKeypair.privateKey, sealed)
        val payload = try {
            json.decodeFromString<EscrowPayload>(plaintext.decodeToString())
        } catch (e: Exception) {
            throw CryptoException("canary payload is not v1 JSON", e)
        }
        if (payload.v != 1 || payload.keyType != KEY_TYPE_CANARY || payload.userId != CANARY_USER_ID) {
            throw CryptoException("not the canary blob")
        }
        val key = Bytes.fromB64(payload.key)
        if (!key.contentEquals(CANARY_KEY) || payload.sha256 != Bytes.toB64(crypto.sha256(key))) throw CryptoException("canary payload mismatch")
    }

    /**
     * Legacy v1 payload parse (spec 04 §3, integrity only): `v == 1`, `keyType == "uvk"`, a 32-byte key
     * (audit F32: a short key would reach libsodium through JNA later), and the sha256 self-check. The
     * self-check proves only internal consistency, never authenticity; [open]'s identity check does that.
     */
    internal fun parseV1(crypto: CryptoProvider, plaintext: ByteArray): EscrowPayload {
        val payload = try {
            json.decodeFromString<EscrowPayload>(plaintext.decodeToString())
        } catch (e: Exception) {
            refuse(EscrowVerdict.V1_MALFORMED, "malformed v1 backstop key")
        }
        if (payload.v != 1 || payload.keyType != KEY_TYPE_UVK) refuse(EscrowVerdict.V1_MALFORMED, "not a v1 uvk backstop key")
        val keyBytes = try {
            Bytes.fromB64(payload.key)
        } catch (e: CryptoException) {
            refuse(EscrowVerdict.V1_MALFORMED, "v1 key is not base64url")
        }
        if (keyBytes.size != 32) refuse(EscrowVerdict.V1_MALFORMED, "v1 key is not 32 bytes")
        val expected = Bytes.toB64(crypto.sha256(keyBytes))
        keyBytes.fill(0)
        if (!Bytes.ctEquals(expected.encodeToByteArray(), payload.sha256.encodeToByteArray())) {
            refuse(EscrowVerdict.V1_SELF_CHECK_FAILED, "escrow payload self-check failed (sha256 mismatch)")
        }
        return payload
    }

    private fun refuse(verdict: EscrowVerdict, detail: String): Nothing = throw EscrowOpenException(verdict, detail)

    /** spec 04 §1 — full fingerprint: lowercase hex SHA-256 of the 32-byte public key. */
    fun fingerprint(crypto: CryptoProvider, publicKey: ByteArray): String =
        Bytes.toHexLower(crypto.sha256(publicKey))

    /**
     * The 16-hex (64-bit) short id of the org recovery key. NOT the 32-hex human short form used by
     * the typed enrolment path ([shortFormMatches] / [Fingerprint]). It is STILL used, at 16 hex, by
     * the recovery-cli operator display (read aloud), the admin sheet-confirm (typed), and the
     * in-person-QR `rfp` compare. Those paths have not been widened yet; moving them to a full-length
     * compare is tracked for a later branch of this security review.
     */
    fun shortFingerprint(crypto: CryptoProvider, publicKey: ByteArray): String =
        fingerprint(crypto, publicKey).take(16)

    /**
     * spec 04 §2(3): the user TYPES the first 32 hex chars (128 bits) of the org recovery
     * fingerprint from the PRINTED sheet (the UI must NOT display them first, so a compromised
     * server can't get a lazy eyeball-match). Separators / whitespace / case are tolerated; exactly
     * 32 hex chars required. One shared helper ([Fingerprint.matchesShort]) backs both the recovery
     * (here) and identity short forms; the web twin is `web/src/crypto/escrow.ts`.
     */
    fun shortFormMatches(entry: String, fullFingerprintHex: String): Boolean =
        Fingerprint.matchesShort(entry, fullFingerprintHex)
}
