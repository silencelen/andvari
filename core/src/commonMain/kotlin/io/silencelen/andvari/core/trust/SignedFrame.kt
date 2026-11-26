package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes

/**
 * The purpose code in byte 4 of a signed-statement frame and the `"purpose"` literal the statement
 * must carry (design 2026-11-15 §2.1). Domain separation comes from the purpose byte inside the signed
 * message `M`, so a statement signed for one purpose never verifies as another.
 */
enum class TrustPurpose(val code: Int, val literal: String) {
    /** 0x01, sealed to the recipient. Template unchanged (spec 01 §6); binding amended in §3.5 ([VaultGrant]). */
    VAULT_GRANT(0x01, "vault-grant"),

    /** 0x02, sealed to the instance recovery key (spec 04 §3). Verified only by `crypto.Escrow.open`, never here. */
    ESCROW_UVK(0x02, "escrow-uvk"),

    /** 0x03, in the clear: one entry of a shared vault's log (§3, [VaultLog]). */
    VAULT_LOG(0x03, "vault-log"),

    /** 0x04, in the clear: one instance card (§4, [InstanceCard]). */
    INSTANCE_CARD(0x04, "instance-card"),

    /** 0x05, in the clear: the account genesis record (§5, [AccountGenesis]). */
    ACCOUNT_GENESIS(0x05, "account-genesis"),

    /** 0x06, in an AEAD envelope under the link's offer key (§6.3, [LinkOffer]). */
    LINK_OFFER(0x06, "link-offer"),

    /** 0x07, in an AEAD envelope under the link's answer key (§6.5, [LinkAnswer]). */
    LINK_ANSWER(0x07, "link-answer"),

    /** 0x08, in the clear, served with the card chain (§4.5, [RecoveryRotation]). */
    RECOVERY_ROTATION(0x08, "recovery-rotation"),

    /** 0x09, sealed to the requesting device's one-time key (§9.3, [AssistedRecovery]). */
    ASSISTED_RECOVERY(0x09, "assisted-recovery"),

    /** 0x0A, in the clear, posted to the server (§9.3, [RecoveryVeto]). */
    RECOVERY_VETO(0x0A, "recovery-veto"),
    ;

    companion object {
        /** The purpose for a frame's byte 4, or null for a reserved code (a parser then answers `bad_frame`). */
        fun fromCode(code: Int): TrustPurpose? = entries.firstOrNull { it.code == code }

        internal val LITERALS: Set<String> = entries.map { it.literal }.toSet()
    }
}

/**
 * The verdicts of the §2 parse (design §2.1, §2.2; spec 01 §5.1), shared by every statement verifier.
 * Each verifier's own enum repeats these four under the same `code`, in this order of checks:
 *
 * 1. the frame: shorter than the magic is `bad_frame`; another magic or version byte is
 *    `unknown_format`; a total length outside 103..1125, a reserved purpose code, or a purpose other
 *    than the one the verifier is for is `bad_frame`;
 * 2. every statement byte is printable ASCII (0x20..0x7E), the statement is ONE FLAT JSON object (a `[`
 *    anywhere, or a second `{`, is refused before any JSON parser sees the text, §2.2) with exactly
 *    its template's keys, every value is inside its type's grammar, and the statement is byte-identical
 *    to its template re-encoded: any breach is `non_canonical`;
 * 3. `v` is 2, the `purpose` literal is the purpose code's, and the template rules of the owning section
 *    hold (a vault grant has `from != to`; a log entry has `seq = 0` exactly when it is `genesis`, and
 *    a `genesis` has `prev` = 64 zeros, VR-1): any breach is `bad_statement`.
 *
 * The order is normative (§2.4, VR-8): the magic is read before the length, so a short frame with
 * another version byte is `unknown_format`.
 */
enum class FrameVerdict(val code: String) {
    /** Not a usable frame: too short, a bad total length, a reserved purpose code, or the wrong purpose. */
    BAD_FRAME("bad_frame"),

    /** The first four bytes are not `61 76 73 02`: another format or version. */
    UNKNOWN_FORMAT("unknown_format"),

    /** The statement is not the canonical encoding of its template (§2.2: "a JSON value that fails its type"). */
    NON_CANONICAL("non_canonical"),

    /** Canonical, but it breaks a rule of its section (§2.2: "well-formed but violate a rule of its section"). */
    BAD_STATEMENT("bad_statement"),
}

/**
 * The four parts of a frame, split and NOT verified: nothing in it is authenticated. A caller may read
 * [signerPub] only to refuse precisely; no key read from a frame may ever be used as the key that frame
 * is checked against (that would be a self-pin).
 */
class FrameParts internal constructor(
    val purpose: TrustPurpose,
    signerPub: ByteArray,
    signature: ByteArray,
    statement: ByteArray,
) {
    // The constructor is internal and [SignedFrame.split] hands it three arrays it just cut from the frame.
    // They are KEPT, not copied again: a second copy would leave the first one behind, unwiped, and the
    // statement of a grant or of an assisted recovery holds a key.
    private val signerPubBytes = signerPub
    private val signatureBytes = signature
    private val statementBytes = statement

    /** The 32-byte Ed25519 key the frame says signed it. */
    val signerPub: ByteArray get() = signerPubBytes.copyOf()
    val signature: ByteArray get() = signatureBytes.copyOf()

    /** The statement bytes (canonical JSON once a verifier parsed them). A copy: for a grant it holds the vault key, and it is the caller's to wipe. */
    val statement: ByteArray get() = statementBytes.copyOf()

    internal fun signerPubRaw(): ByteArray = signerPubBytes
    internal fun signatureRaw(): ByteArray = signatureBytes
    internal fun statementRaw(): ByteArray = statementBytes

    /**
     * Zero the parts. The opener of a frame that holds a key (a grant's `vk`, an assisted recovery's
     * `uvk`) calls it when it is done, whatever the outcome; a secret field can no longer be read from
     * the statement afterwards.
     */
    internal fun wipe() {
        statementBytes.fill(0)
        signatureBytes.fill(0)
        signerPubBytes.fill(0)
    }
}

/**
 * The signed-statement frame (design 2026-11-15 §2.1; layout unchanged from spec 01 §5.1), for every
 * purpose 0x01–0x0A:
 *
 * ```
 * offset  len  field
 * 0       4    magic        61 76 73 02
 * 4       1    purposeCode
 * 5       32   signerPub    Ed25519 public key
 * 37      64   signature    Ed25519 over M
 * 101     N    statement    canonical JSON, printable ASCII, 2 <= N <= 1024
 *
 * M = "andvari/v2|signed-statement" || 0x00 || frame[0..5) || signerPub || statement
 * ```
 *
 * This object splits a frame and hashes it. It verifies nothing by itself: each purpose has its own
 * verifier ([VaultLog], [InstanceCard], [AccountGenesis], [LinkOffer], [LinkAnswer],
 * [RecoveryRotation], [AssistedRecovery], [RecoveryVeto], [VaultGrant]), and none of them can be called
 * without the key its context says must have signed. There is no "sign any statement" function: signing
 * is `internal`, reached only through each purpose's own builder.
 */
object SignedFrame {
    val MAGIC: ByteArray get() = byteArrayOf(0x61, 0x76, 0x73, 0x02)
    const val DOMAIN = "andvari/v2|signed-statement"
    const val HEADER_BYTES = 5
    const val SIGNER_BYTES = 32
    const val SIGNATURE_BYTES = 64
    const val STATEMENT_OFFSET = HEADER_BYTES + SIGNER_BYTES + SIGNATURE_BYTES // 101
    const val MIN_STATEMENT_BYTES = 2
    const val MAX_STATEMENT_BYTES = 1024

    /** The largest frame: 1125 bytes, 1500 characters of base64url. */
    const val MAX_FRAME_BYTES = STATEMENT_OFFSET + MAX_STATEMENT_BYTES

    private val magic = byteArrayOf(0x61, 0x76, 0x73, 0x02)

    /** True when [bytes] start with the frame magic (§6.4: "a plaintext starting with `61 76 73 02` is a signed frame"). */
    fun hasMagic(bytes: ByteArray): Boolean =
        bytes.size >= magic.size && bytes[0] == magic[0] && bytes[1] == magic[1] && bytes[2] == magic[2] && bytes[3] == magic[3]

    /**
     * Split [frame] (§2.1). Verdicts, in order: shorter than the magic `bad_frame`; another magic
     * `unknown_format`; a total length outside 103..1125 `bad_frame`; a reserved purpose code `bad_frame`.
     */
    fun split(frame: ByteArray): Checked<FrameParts, FrameVerdict> {
        if (frame.size < magic.size) return Checked.Refused(FrameVerdict.BAD_FRAME)
        if (!hasMagic(frame)) return Checked.Refused(FrameVerdict.UNKNOWN_FORMAT)
        if (frame.size < STATEMENT_OFFSET + MIN_STATEMENT_BYTES || frame.size > MAX_FRAME_BYTES) {
            return Checked.Refused(FrameVerdict.BAD_FRAME)
        }
        val purpose = TrustPurpose.fromCode(frame[4].toInt() and 0xFF) ?: return Checked.Refused(FrameVerdict.BAD_FRAME)
        return Checked.Ok(
            FrameParts(
                purpose = purpose,
                signerPub = frame.copyOfRange(HEADER_BYTES, HEADER_BYTES + SIGNER_BYTES),
                signature = frame.copyOfRange(HEADER_BYTES + SIGNER_BYTES, STATEMENT_OFFSET),
                statement = frame.copyOfRange(STATEMENT_OFFSET, frame.size),
            ),
        )
    }

    /**
     * The frame hash `H(frame)` (§2.1): lowercase hex SHA-256 of the full frame bytes, magic through
     * statement. The frame is already domain-separated, so no prefix is added. Log `prev`, card `prev`,
     * `genesisHash`, `cardHash`, `offerHash` and `answerHash` are all this value.
     */
    fun hash(crypto: CryptoProvider, frame: ByteArray): String = Bytes.toHexLower(crypto.sha256(frame))

    /** The signed message `M` (§2.1). */
    fun signedMessage(purposeCode: Int, signerPub: ByteArray, statement: ByteArray): ByteArray =
        DOMAIN.encodeToByteArray() + byteArrayOf(0) + magic + byteArrayOf(purposeCode.toByte()) + signerPub + statement

    /**
     * Frame [statement] under [purpose], signed by [signer] (an Ed25519 pair from
     * `CryptoProvider.signKeypairFromSeed`). Internal: only the per-purpose builders of this package
     * call it, each after it encoded a statement of its own template.
     */
    internal fun sign(crypto: CryptoProvider, signer: KeyPairBytes, purpose: TrustPurpose, statement: ByteArray): ByteArray {
        require(signer.publicKey.size == SIGNER_BYTES) { "signer public key must be 32 bytes" }
        require(statement.size in MIN_STATEMENT_BYTES..MAX_STATEMENT_BYTES) { "statement length out of range" }
        // Nothing is signed with a wiped key: KeysGoneException.
        io.silencelen.andvari.core.crypto.KeyFloor.requireSigningKey(signer.privateKey)
        val message = signedMessage(purpose.code, signer.publicKey, statement)
        val sig = try {
            crypto.signDetached(signer.privateKey, message)
        } finally {
            message.fill(0) // M repeats the statement, which for a grant holds the vault key
        }
        return magic + byteArrayOf(purpose.code.toByte()) + signer.publicKey + sig + statement
    }

    /**
     * Signer binding, the X25519 form (§2.1): `ed25519_pk_to_curve25519(signerPub) == key`. Used for the
     * vault log, grants, links, the genesis in full clients, and (for 0x08 and 0x09) the instance
     * recovery key. A [signerPub] with no curve image (a non-point or a small-order point) binds to
     * nothing. `A` and `-A` share an image, so this is never authentication alone: [signatureValid]
     * always follows it.
     */
    internal fun signerMapsTo(crypto: CryptoProvider, parts: FrameParts, x25519Key: ByteArray): Boolean {
        if (x25519Key.size != 32) return false
        val image = signerImage(crypto, parts) ?: return false
        return Bytes.ctEquals(image, x25519Key)
    }

    /** The X25519 image of the frame's signer key, or null when it has none. */
    internal fun signerImage(crypto: CryptoProvider, parts: FrameParts): ByteArray? = try {
        crypto.ed25519PkToCurve25519(parts.signerPubRaw())
    } catch (e: CryptoException) {
        null
    }

    /** Signer binding, the Ed25519 form (§2.1): `signerPub == key`, byte for byte (the card's `operatorSignKey`). */
    internal fun signerIs(parts: FrameParts, ed25519Key: ByteArray): Boolean =
        ed25519Key.size == SIGNER_BYTES && Bytes.ctEquals(parts.signerPubRaw(), ed25519Key)

    /**
     * `crypto_sign_verify_detached` over `M` under the frame's own `signerPub` (§2.1). `M` repeats the
     * statement, so it is zeroed here; the provider's own copy of it, on the way to libsodium, is out of
     * this code's reach.
     */
    internal fun signatureValid(crypto: CryptoProvider, parts: FrameParts): Boolean {
        val message = signedMessage(parts.purpose.code, parts.signerPubRaw(), parts.statementRaw())
        try {
            return crypto.signVerifyDetached(parts.signerPubRaw(), parts.signatureRaw(), message)
        } finally {
            message.fill(0)
        }
    }
}
