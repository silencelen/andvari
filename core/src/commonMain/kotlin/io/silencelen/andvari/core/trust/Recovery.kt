package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KeyFloor
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.X25519

/**
 * Why a recovery statement (purposes 0x08, 0x09, 0x0A) was refused. Every name is §2.4's ("Rotation",
 * "Veto", "Assisted recovery", "Small cases the vectors needed named", and the signer-binding table,
 * VR-9); each verifier documents its own order, and `recovery.json` grades it row by row.
 */
enum class RecoveryVerdict(val code: String) {
    /** 0x09 only: the sealed box does not open with the request key pair. */
    UNOPENABLE("unopenable"),

    /** The §2 parse: see [FrameVerdict]. */
    BAD_FRAME("bad_frame"),
    UNKNOWN_FORMAT("unknown_format"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),

    /** 0x08: `fromFp` is not the verifier's current fingerprint (its consent, the card's, or the previous link's `toFp`); or a chain does not end at the expected fingerprint. */
    FP_MISMATCH("fp_mismatch"),

    /**
     * The signer does not map to the key the helper was handed: for 0x08 the recovery key the current
     * fingerprint names, for 0x09 the recovery key the pinned card's `recoveryFp` names, for 0x0A the
     * account's stored identity key.
     */
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key"),

    /** The Ed25519 signature does not verify. */
    BAD_SIGNATURE("bad_signature"),

    /** 0x08: the statement's `instanceId` is not the instance the verifier pins (on the server, its own). */
    INSTANCE_MISMATCH("instance_mismatch"),

    /** 0x0A: `userId` is not the session's account. */
    USER_MISMATCH("user_mismatch"),

    /** 0x09: `instanceId`, `userId`, `requestId` or `requestKey` is not this request's. 0x0A: `requestId` is not the path's. */
    REQUEST_MISMATCH("request_mismatch"),

    /** 0x09: the identity seed does not open under the delivered UVK, or its key is not the served `identityPub` (R27). */
    IDENTITY_MISMATCH("identity_mismatch"),
    ;

    companion object {
        internal fun of(v: FrameVerdict): RecoveryVerdict = when (v) {
            FrameVerdict.BAD_FRAME -> BAD_FRAME
            FrameVerdict.UNKNOWN_FORMAT -> UNKNOWN_FORMAT
            FrameVerdict.NON_CANONICAL -> NON_CANONICAL
            FrameVerdict.BAD_STATEMENT -> BAD_STATEMENT
        }
    }
}

/**
 * A recovery-key rotation as its statement says it (design 2026-11-15 §4.5, purpose 0x08):
 * `{"v":2,"purpose":"recovery-rotation","instanceId":<uuid>,"fromFp":<hex64>,"toFp":<hex64>,"issuedAt":<ms>}`.
 * Both fingerprints are `hexLower(SHA-256(recovery public key))`.
 */
data class RotationFields(val instanceId: String, val fromFp: String, val toFp: String, val issuedAt: Long)

/** A rotation that passed [RecoveryRotation.verify]. */
class VerifiedRotation internal constructor(val fields: RotationFields, val hash: String)

/** A change of `recoveryFp` between card [seq] − 1 and card [seq] (null: `none`), as the first-consent walk sees it (§4.5). */
data class FpChange(val seq: Long, val fromFp: String?, val toFp: String?)

/**
 * Rotation of the instance recovery key (design 2026-11-15 §4.5, T-B4). A card that changes
 * `recoveryFp` causes no re-seal by itself: only a statement signed OFFLINE by the OUTGOING recovery
 * seed moves a person's consent from one key to the next. A server compromise cannot forge one,
 * because the seed is offline.
 *
 * The signing key is `crypto_sign_seed_keypair(recovery seed)` (§2.3): the Ed25519 key over the same
 * seed that yields the recovery X25519 key, so `ed25519_pk_to_curve25519(signerPub)` is the recovery
 * public key and its SHA-256 is the fingerprint the statement names.
 */
object RecoveryRotation {
    /**
     * Encode and sign a rotation with [outgoingSigner], the Ed25519 pair of the OUTGOING recovery seed
     * (`recovery-cli rotate`, offline). Refuses (`IllegalArgumentException`) values outside the grammar
     * and a signer whose X25519 image does not hash to `fromFp`.
     */
    fun sign(crypto: CryptoProvider, outgoingSigner: KeyPairBytes, rotation: RotationFields): ByteArray {
        val statement = StatementCodec.encode(
            TrustPurpose.RECOVERY_ROTATION,
            mapOf(
                "instanceId" to rotation.instanceId, "fromFp" to rotation.fromFp, "toFp" to rotation.toFp,
                "issuedAt" to rotation.issuedAt.toString(),
            ),
        )
        require(signerIsRecoveryKey(crypto, outgoingSigner.publicKey, rotation.fromFp)) { "a rotation is signed by the recovery key its fromFp names" }
        return SignedFrame.sign(crypto, outgoingSigner, TrustPurpose.RECOVERY_ROTATION, statement)
    }

    /**
     * The signer binding of 0x08 and 0x09 (§2.1, §2.3): the Ed25519 key [signerPub] maps to the recovery
     * public key that [recoveryFp] names, that is, `SHA-256(ed25519_pk_to_curve25519(signerPub))` is
     * [recoveryFp] at full length. A fingerprint names its key, so no stored copy of the key is needed.
     * False for a key with no curve image, and for a fingerprint that is not a `hex64` (`none` names no
     * key). `A` and `-A` share an image, so this is never authentication alone: the signature check
     * always follows it.
     */
    internal fun signerIsRecoveryKey(crypto: CryptoProvider, signerPub: ByteArray, recoveryFp: String): Boolean {
        val image = try {
            crypto.ed25519PkToCurve25519(signerPub)
        } catch (e: CryptoException) {
            return false
        }
        return InstanceCard.recoveryKeyMatches(crypto, recoveryFp, image)
    }

    /**
     * One rotation statement against the verifier's CURRENT fingerprint [currentFp] (its consent, the
     * card's `recoveryFp`, or the fingerprint of the account's current escrow); the first failure is
     * the verdict (§2.4 "Rotation", VR-9):
     * 1. the §2 parse, purpose 0x08 (`bad_frame`, `unknown_format`, `non_canonical`, `bad_statement`);
     * 2. the statement's `fromFp` is [currentFp] (`fp_mismatch`). This comes before the signer because
     *    it decides WHICH key must have signed;
     * 3. the signer's X25519 image hashes to [currentFp]: the signer is the recovery key that
     *    fingerprint names (`signer_not_pinned_key`);
     * 4. the signature verifies (`bad_signature`);
     * 5. `instanceId` is [instanceId] (`instance_mismatch`): a rotation signed for another instance
     *    that shares the recovery seed moves no consent here.
     *
     * On success the verifier's fingerprint becomes the rotation's `toFp`. A [currentFp] that is not a
     * `hex64` (a card's `none`) equals no statement's `fromFp`, so it is `fp_mismatch`: no rotation
     * turns operator recovery on or off.
     */
    fun verify(crypto: CryptoProvider, frame: ByteArray, instanceId: String, currentFp: String): Checked<VerifiedRotation, RecoveryVerdict> {
        val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.RECOVERY_ROTATION)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return Checked.Refused(RecoveryVerdict.of(p.verdict))
        }
        val raw = parsed.raw
        // The fingerprint is inside the statement, and it decides which key the helper is handed (§2.4).
        if (raw.str("fromFp") != currentFp) return Checked.Refused(RecoveryVerdict.FP_MISMATCH)
        // The recovery key of the current fingerprint: the signer maps to it, then the signature.
        if (!signerIsRecoveryKey(crypto, parsed.parts.signerPubRaw(), currentFp)) return Checked.Refused(RecoveryVerdict.SIGNER_NOT_PINNED_KEY)
        if (!SignedFrame.signatureValid(crypto, parsed.parts)) return Checked.Refused(RecoveryVerdict.BAD_SIGNATURE)
        // Last: what the outgoing seed really signed, for another instance.
        if (raw.str("instanceId") != instanceId) return Checked.Refused(RecoveryVerdict.INSTANCE_MISMATCH)
        val fields = RotationFields(raw.str("instanceId"), raw.str("fromFp"), raw.str("toFp"), raw.long("issuedAt"))
        return Checked.Ok(VerifiedRotation(fields, SignedFrame.hash(crypto, frame)))
    }

    /**
     * A chain of rotations, oldest first, as `PUT /escrow/self` carries it (§4.5, FI-R1): every link
     * verifies in order ([verify], the first against [fromFp], each next against the previous `toFp`)
     * and the last `toFp` is [toFp] (`fp_mismatch` otherwise; also for an empty list unless [fromFp]
     * is already [toFp]). Null when the chain holds; otherwise the verdict of the first link that
     * fails, and nothing after it is looked at.
     */
    fun verifyChain(crypto: CryptoProvider, frames: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): RecoveryVerdict? {
        var reached = fromFp
        for (frame in frames) {
            when (val link = verify(crypto, frame, instanceId, reached)) {
                is Checked.Ok -> reached = link.value.fields.toFp
                is Checked.Refused -> return link.verdict
            }
        }
        return if (reached == toFp) null else RecoveryVerdict.FP_MISMATCH
    }

    /**
     * §4.5 condition 2: [toFp] "equals the consented `fp`, or follows from it by a chain of valid
     * rotation statements". True when [fromFp] is [toFp], or when the served [rotations] (in any
     * order; statements that do not verify are ignored) link [fromFp] to [toFp].
     */
    fun follows(crypto: CryptoProvider, rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): Boolean =
        chain(crypto, rotations, instanceId, fromFp, toFp) != null

    /**
     * The chain a re-seal carries (`PUT /escrow/self {rotations}`, §4.5, FI-R1): out of the served
     * [rotations], in whatever order they came, the frames that lead from [fromFp] (the fingerprint of
     * the account's current escrow) to [toFp] (the pinned card's `recoveryFp`), oldest first. Null when
     * the served rotations do not link the two; an empty list when [fromFp] is already [toFp].
     *
     * Every link is verified against the fingerprint the chain has reached ([verify]), and statements
     * that do not verify are ignored. So it returns a chain exactly when [follows] is true, and what it
     * returns [verifyChain] accepts. It is a shortest chain, the same one for the same input; its
     * rotations need not stand together, or in order, in the served list. The frames are the caller's
     * own arrays, not copies.
     *
     * The work is bounded by what was served: each frame is parsed once, and a statement is verified
     * at most once, only when the fingerprint it starts from has been reached. Statements that start
     * from a fingerprint never reached cost that one parse and nothing more; of those that start from
     * a reached one, only a statement carrying that key's own signer reaches the signature check.
     */
    fun chain(crypto: CryptoProvider, rotations: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): List<ByteArray>? =
        if (fromFp == toFp) emptyList() else ServedRotations(crypto, rotations, instanceId).path(fromFp, toFp)

    /**
     * The first-consent walk (§4.5, FS-R2, FC-2): along [cards], every change of `recoveryFp` that the
     * served [rotations] do NOT cover. A change is covered only when rotations link the old value to
     * the new one ([follows]: one statement, or a chain of them when the key was rotated more than once
     * between two cards); a change from or to `none` cannot be covered, because a rotation names two
     * keys. A non-empty result means the choice shows the unsigned-change warning and preselects
     * "Only me".
     *
     * [cards] is the WHOLE verified served chain, card 0 first (the fields of
     * [InstanceCard.verifyChain]'s cards), whatever root this device pinned through and however new
     * its pin is: the walk covers exactly the list it is given, so a caller that passes only the cards
     * after its pin hides every earlier change. Card 0's value is the anchor and needs no rotation.
     */
    fun unsignedChanges(crypto: CryptoProvider, cards: List<CardFields>, rotations: List<ByteArray>): List<FpChange> {
        // One index for the walk (per instanceId, which a verified chain keeps constant): a statement is verified once however many changes ask for it.
        val served = HashMap<String, ServedRotations>()
        val uncovered = ArrayList<FpChange>()
        for (i in 1 until cards.size) {
            val from = cards[i - 1].recoveryFp
            val to = cards[i].recoveryFp
            if (from == to) continue
            val covered = from != null && to != null &&
                served.getOrPut(cards[i].instanceId) { ServedRotations(crypto, rotations, cards[i].instanceId) }.path(from, to) != null
            if (!covered) uncovered += FpChange(cards[i].seq, from, to)
        }
        return uncovered
    }
}

/**
 * The rotations a server served for one instance, searched from a fingerprint the caller already holds.
 *
 * Each frame is parsed once and filed under the `fromFp` it CLAIMS. That is only an index: nothing in
 * it is trusted. A statement counts as a step out of a fingerprint only once that fingerprint has been
 * reached, and then only when [RecoveryRotation.verify] accepts it for a verifier standing there:
 * signed by the recovery key that fingerprint names, for this instance. So the first step of every
 * path is signed by the key the caller trusts, and each later one by a key the path vouched for.
 */
private class ServedRotations(private val crypto: CryptoProvider, rotations: List<ByteArray>, private val instanceId: String) {
    private class Step(val fromFp: String, val toFp: String, val frame: ByteArray)

    private val claiming = HashMap<String, MutableList<ByteArray>>()
    private val verified = HashMap<String, List<Step>>()

    init {
        for (frame in rotations) {
            val claimed = StatementCodec.parseFrame(frame, TrustPurpose.RECOVERY_ROTATION).valueOrNull()?.raw?.str("fromFp") ?: continue
            claiming.getOrPut(claimed) { ArrayList() } += frame
        }
    }

    /** The steps out of [fp], in served order. Verified on first use and kept, so a statement is verified at most once. */
    private fun stepsFrom(fp: String): List<Step> = verified.getOrPut(fp) {
        claiming[fp].orEmpty().mapNotNull { frame ->
            RecoveryRotation.verify(crypto, frame, instanceId, fp).valueOrNull()?.let { Step(fp, it.fields.toFp, frame) }
        }
    }

    /**
     * The frames of a shortest path of steps from [fromFp] to [toFp], oldest first: empty when the two
     * are equal, null when no path exists. Breadth first, each fingerprint's steps in served order, so
     * the same input gives the same path. A rotation back to an earlier key is a step like any other;
     * the search keeps what it has reached, so it ends.
     */
    fun path(fromFp: String, toFp: String): List<ByteArray>? {
        if (fromFp == toFp) return emptyList()
        val reachedBy = HashMap<String, Step>()
        val queue = ArrayDeque<String>()
        queue.addLast(fromFp)
        while (queue.isNotEmpty()) {
            for (step in stepsFrom(queue.removeFirst())) {
                if (step.toFp == fromFp || step.toFp in reachedBy) continue
                reachedBy[step.toFp] = step
                if (step.toFp == toFp) {
                    val frames = ArrayList<ByteArray>()
                    var at = toFp
                    while (at != fromFp) {
                        val last = reachedBy.getValue(at)
                        frames += last.frame
                        at = last.fromFp
                    }
                    return frames.reversed()
                }
                queue.addLast(step.toFp)
            }
        }
        return null
    }
}

/**
 * The operator's answer to an assisted-recovery request (§9.3 step 3, purpose 0x09, FI-B13):
 * `{"v":2,"purpose":"assisted-recovery","instanceId":<uuid>,"userId":<uuid>,"requestId":<b64_16>,"requestKey":<b64_32>,"uvk":<b64_32>,"issuedAt":<ms>}`.
 * [requestKey] is `rPub` as `b64_32` text; [uvk] the account's 32-byte UVK, copied in and out.
 */
class AssistedRecoveryFields(
    val instanceId: String,
    val userId: String,
    val requestId: String,
    val requestKey: String,
    uvk: ByteArray,
    val issuedAt: Long,
    /**
     * The version-3 answer (spec 04 §7 step 3): [email] is the `emailNorm` the opened
     * recovery copy names, and [commit] the fresh 32-byte commit value. Both given, [AssistedRecovery.sign] writes the
     * version-3 statement; both null, the old version 2, which only the vectors still need.
     */
    val email: String? = null,
    commit: ByteArray? = null,
) {
    private val uvkBytes = uvk.copyOf()
    private val commitBytes = commit?.copyOf()
    val uvk: ByteArray get() = uvkBytes.copyOf()
    val commit: ByteArray? get() = commitBytes?.copyOf()

    /** Zero the held UVK (and the commit value) once the payload is signed. */
    fun wipe() {
        uvkBytes.fill(0)
        commitBytes?.fill(0)
    }
}

/**
 * An assisted-recovery payload that passed every check of [AssistedRecovery.open] or [AssistedRecovery.openV3]. [email]
 * and [commit] are set by [AssistedRecovery.openV3] only: the address the answer names (the one the person typed) and
 * the commit value the device presents at the commit (spec 03 §18.5).
 */
class OpenedAssistedRecovery internal constructor(
    val userId: String,
    uvk: ByteArray,
    val issuedAt: Long,
    val email: String? = null,
    commit: ByteArray? = null,
) {
    private val uvkBytes = uvk.copyOf()
    private val commitBytes = commit?.copyOf()
    val uvk: ByteArray get() = uvkBytes.copyOf()

    /** The commit value, as the `b64_32` the commit carries; null for an old-form payload. */
    val commitB64: String? get() = commitBytes?.let { Bytes.toB64(it) }

    /** Zero the held UVK (and the commit value) once the caller has re-wrapped it under the new password. */
    fun wipe() {
        uvkBytes.fill(0)
        commitBytes?.fill(0)
    }
}

/**
 * Operator-assisted recovery (design 2026-11-15 §9.3, T-B5): the request code, and the payload signed
 * by the offline recovery key and sealed to the requesting device's one-time key. No temporary
 * password exists at any point.
 */
object AssistedRecovery {
    private const val CODE_DOMAIN = "andvari/v2|recovery-request|code|"

    /** A request code is 24 hex characters: 96 bits. */
    private const val CODE_LENGTH = 24

    /**
     * The request code (§2.3): `hexLower(SHA-256("andvari/v2|recovery-request|code|" + b64url(rPub)))[0..24]`,
     * 96 bits. The person reads it to the operator; the operator types it into `recovery-cli assist`.
     * The panel and the CLI never display it (T2-R-c).
     */
    fun requestCode(crypto: CryptoProvider, rPub: ByteArray): String {
        require(rPub.size == 32) { "the request key must be 32 bytes" }
        return Bytes.toHexLower(crypto.sha256((CODE_DOMAIN + Bytes.toB64(rPub)).encodeToByteArray())).substring(0, CODE_LENGTH)
    }

    /** The display form of a request [code] (its 24 lowercase hex characters): six groups of four, separated by single spaces. */
    fun groupedRequestCode(code: String): String {
        require(code.length == CODE_LENGTH && code.all { it in '0'..'9' || it in 'a'..'f' }) { "a request code is 24 lowercase hex characters" }
        return code.chunked(4).joinToString(" ")
    }

    /**
     * `recovery-cli assist`'s reading of the code a HUMAN typed (spec 04 §7 step 3.2: one person reads it out, another
     * types it): spaces, tabs and dashes in [typed] are removed and its letters compare without regard to case;
     * what is left must be exactly the 24 hex characters. Any other character (a line break, a no-break space) is no
     * match, and so is an [rPub] that is not 32 bytes. This is what stops a server that swapped `rPub`. Total.
     */
    fun requestCodeMatches(crypto: CryptoProvider, typed: String, rPub: ByteArray): Boolean {
        if (rPub.size != 32) return false
        val entry = StringBuilder(CODE_LENGTH)
        for (c in typed) {
            when {
                c == ' ' || c == '\t' || c == '-' -> Unit
                c in '0'..'9' || c in 'a'..'f' -> entry.append(c)
                c in 'A'..'F' -> entry.append((c.code + 0x20).toChar())
                else -> return false
            }
            if (entry.length > CODE_LENGTH) return false
        }
        return entry.length == CODE_LENGTH && Bytes.ctEquals(entry.toString().encodeToByteArray(), requestCode(crypto, rPub).encodeToByteArray())
    }

    /**
     * Encode and sign the payload with [recoverySigner], the Ed25519 pair of the recovery seed
     * (`recovery-cli assist`, offline). Refuses (`IllegalArgumentException`) values outside the grammar.
     * The frame carries the UVK in the clear: it leaves the offline machine only inside [seal].
     */
    fun sign(crypto: CryptoProvider, recoverySigner: KeyPairBytes, payload: AssistedRecoveryFields): ByteArray {
        val uvk = payload.uvk
        val commit = payload.commit
        try {
            require((payload.email == null) == (commit == null)) { "a version-3 answer names both the address and the commit value" }
            // The key goes into the statement from its bytes: it never becomes a String.
            val statement = if (payload.email == null || commit == null) {
                StatementCodec.encode(
                    TrustPurpose.ASSISTED_RECOVERY,
                    mapOf(
                        "instanceId" to payload.instanceId, "userId" to payload.userId, "requestId" to payload.requestId,
                        "requestKey" to payload.requestKey, "issuedAt" to payload.issuedAt.toString(),
                    ),
                    secrets = mapOf("uvk" to uvk),
                )
            } else {
                require(commit.size == 32) { "the commit value is 32 bytes" }
                val email = TrustGrammar.encodeEmail(payload.email)?.takeIf { it != TrustGrammar.NONE }
                    ?: throw IllegalArgumentException("the answer's address is not an emailNorm")
                StatementCodec.encode(
                    TrustPurpose.ASSISTED_RECOVERY,
                    mapOf(
                        "instanceId" to payload.instanceId, "userId" to payload.userId, "email" to email, "requestId" to payload.requestId,
                        "requestKey" to payload.requestKey, "commit" to Bytes.toB64(commit), "issuedAt" to payload.issuedAt.toString(),
                    ),
                    secrets = mapOf("uvk" to uvk),
                    version = 3,
                )
            }
            try {
                return SignedFrame.sign(crypto, recoverySigner, TrustPurpose.ASSISTED_RECOVERY, statement)
            } finally {
                statement.fill(0)
            }
        } finally {
            uvk.fill(0)
            commit?.fill(0)
        }
    }

    private const val COMMIT_DOMAIN = "andvari/v2|recovery-request|commit|"

    /**
     * The commit hash (spec 04 §7 step 3, spec 01 §5.5): `hexLower(SHA-256("andvari/v2|recovery-request|commit|" +
     * b64url(commit)))`. The tool prints it in the answer token, the upload carries it, and the server compares a
     * presented commit value's hash with it (spec 03 §18.5).
     */
    fun commitHash(crypto: CryptoProvider, commit: ByteArray): String {
        require(commit.size == 32) { "the commit value is 32 bytes" }
        return Bytes.toHexLower(crypto.sha256((COMMIT_DOMAIN + Bytes.toB64(commit)).encodeToByteArray()))
    }

    /** [commitHash] of a commit value given as its `b64_32` text (the commit's body), or null when it is not one. */
    fun commitHashOf(crypto: CryptoProvider, commitB64: String): String? {
        if (!TrustGrammar.isB64_32(commitB64)) return null
        return Bytes.toHexLower(crypto.sha256((COMMIT_DOMAIN + commitB64).encodeToByteArray()))
    }

    /**
     * True when [rPub] is a request key that an answer may be sealed to: 32 bytes, and not one of
     * Curve25519's low-order points ([X25519.isUsablePublicKey]). A sealed box to a low-order key has a
     * shared secret that does not depend on the requester's private key, so anyone could open it.
     * `recovery-cli assist` checks this when it reads `--request-key`, before the escrow is opened, and
     * refuses with a message of its own; [seal] refuses the same keys. Total.
     */
    fun requestKeyUsable(rPub: ByteArray): Boolean = X25519.isUsablePublicKey(rPub)

    /**
     * `crypto_box_seal` of the signed [frame] to the request key [rPub], the `requestKey` the payload
     * names. Refuses (`IllegalArgumentException`, the caller's contract) an [rPub] that
     * [requestKeyUsable] refuses: a wrong length or a low-order point, so the provider's own
     * `CryptoException` is never what a caller meets.
     */
    fun seal(crypto: CryptoProvider, rPub: ByteArray, frame: ByteArray): ByteArray {
        require(rPub.size == 32) { "the request key must be 32 bytes" }
        require(requestKeyUsable(rPub)) { "the request key is a low-order point: nothing may be sealed to it" }
        return crypto.sealTo(rPub, frame)
    }

    /**
     * The requesting device's checks once the poll answers `ready` (§9.3 step 4), in §2.4's order
     * ("Assisted recovery"); the first failure is the verdict:
     * 1. [sealed] opens with ([rPub], [rSec]) (`unopenable`);
     * 2. the 0x09 frame parses (`bad_frame`, `unknown_format`, `non_canonical`, `bad_statement`);
     * 3. the signer maps to the recovery public key that [recoveryFp] names, where [recoveryFp] is
     *    the PINNED card's `recoveryFp` (`signer_not_pinned_key`; a card with `none` names no key, so
     *    nothing passes), and the signature verifies (`bad_signature`). A hostile server that holds
     *    no recovery key cannot pass this;
     * 4. `instanceId` is [instanceId] (the pinned card's), `requestId` is [requestId], `requestKey` is
     *    [rPub], and when [userId] is given `userId` is it (`request_mismatch`);
     * 5. the identity seed of [identity] opens under the delivered UVK with the statement's `userId`
     *    in its AD, and its X25519 key equals the served `identityPub` (`identity_mismatch` for either,
     *    R27, and for a served value that is not canonical base64url).
     *
     * [userId] has no default, so that the comparison is never skipped by leaving an argument out. A
     * fresh install holds no `userId` of its own and passes an explicit null: that comparison is then
     * skipped (§2.4 "Small cases"), and the account is the one the recovery key signed for, bound to
     * the served identity seed by step 5's AD. A device that holds one passes it.
     *
     * Passing this does not tie the delivered account to the address the person typed. The app shows
     * the delivered account ID for the person to check before any new password is set (§9.3 step 4).
     *
     * The opened frame, the statement the parser worked on, the decoded UVK and the identity seed are
     * zeroed before this returns, on every path; the result holds its own copy of the UVK, which
     * [OpenedAssistedRecovery.wipe] zeroes. One copy is out of reach: the provider's, on its way
     * through the native calls that open the seal and the seed's envelope.
     */
    fun open(
        crypto: CryptoProvider,
        rPub: ByteArray,
        rSec: ByteArray,
        sealed: ByteArray,
        recoveryFp: String,
        instanceId: String,
        requestId: String,
        identity: IdentityCheck,
        userId: String?,
    ): Checked<OpenedAssistedRecovery, RecoveryVerdict> {
        // 1. The seal.
        val frame = try {
            crypto.sealOpen(rPub, rSec, sealed)
        } catch (e: Exception) {
            return refuse(RecoveryVerdict.UNOPENABLE)
        }
        // The frame holds the account's UVK in the clear. Whatever the outcome, the frame and its split
        // parts are zeroed before this returns; the key is read from the statement bytes into one array,
        // which is zeroed too once the result holds its own copy.
        var parts: FrameParts? = null
        try {
            // 2. The frame and the strict parse. Nothing below is trusted until the signature verified.
            val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.ASSISTED_RECOVERY)) {
                is Checked.Ok -> p.value
                is Checked.Refused -> return refuse(RecoveryVerdict.of(p.verdict))
            }
            parts = parsed.parts
            val raw = parsed.raw
            // 3. Signed by the recovery key the pinned card names.
            if (!RecoveryRotation.signerIsRecoveryKey(crypto, parsed.parts.signerPubRaw(), recoveryFp)) return refuse(RecoveryVerdict.SIGNER_NOT_PINNED_KEY)
            if (!SignedFrame.signatureValid(crypto, parsed.parts)) return refuse(RecoveryVerdict.BAD_SIGNATURE)
            // 4. For this instance, this request and this device's one-time key; and for this account, where the device holds one.
            if (raw.str("instanceId") != instanceId || raw.str("requestId") != requestId || raw.str("requestKey") != Bytes.toB64(rPub)) {
                return refuse(RecoveryVerdict.REQUEST_MISMATCH)
            }
            if (userId != null && raw.str("userId") != userId) return refuse(RecoveryVerdict.REQUEST_MISMATCH)
            // 5. The delivered key opens this account's identity seed, and the seed's key is the served one.
            //    The key is read straight from the statement bytes: no String is ever made of it.
            val uvk = raw.secret("uvk")
            try {
                // An all-zero key is no account's key: the identity check's verdict, with nothing opened under it.
                if (KeyFloor.allZero(uvk) || !identityHolds(crypto, uvk, raw.str("userId"), identity)) return refuse(RecoveryVerdict.IDENTITY_MISMATCH)
                return Checked.Ok(OpenedAssistedRecovery(raw.str("userId"), uvk, raw.long("issuedAt")))
            } finally {
                uvk.fill(0)
            }
        } finally {
            frame.fill(0) // the frame carries the UVK in base64
            parts?.wipe() // and so does the statement the parser worked on
        }
    }

    /**
     * The requesting device's checks on a VERSION-3 answer (spec 04 §7 step 4), the
     * only form a device accepts, in [open]'s order; the first failure is the verdict:
     * 1. [sealed] opens with ([rPub], [rSec]) (`unopenable`);
     * 2. the 0x09 frame parses under the version-3 template (`bad_frame`, `unknown_format`, `non_canonical`,
     *    `bad_statement`; a statement canonical under the old version-2 template is `bad_statement`);
     * 3. the signer maps to the recovery key the pinned card's [recoveryFp] names (`signer_not_pinned_key`), and the
     *    signature verifies (`bad_signature`);
     * 4. `instanceId` is [instanceId], `requestId` is [requestId], `requestKey` is [rPub], `userId` is [userId] when
     *    given, and `email` decodes to exactly `emailNorm(`[typedEmail]`)`, the address the person typed when asking, on
     *    a fresh install too (`request_mismatch` for any of them; an [typedEmail] with no `emailNorm` matches nothing);
     * 5. the identity seed opens under the delivered UVK to the served `identityPub` (`identity_mismatch`).
     *
     * The result carries the commit value, which the device presents at the commit (spec 03 §18.5). The frame, the
     * statement and the decoded key are zeroed before this returns, on every path, as in [open].
     */
    fun openV3(
        crypto: CryptoProvider,
        rPub: ByteArray,
        rSec: ByteArray,
        sealed: ByteArray,
        recoveryFp: String,
        instanceId: String,
        requestId: String,
        typedEmail: String,
        identity: IdentityCheck,
        userId: String?,
    ): Checked<OpenedAssistedRecovery, RecoveryVerdict> {
        val frame = try {
            crypto.sealOpen(rPub, rSec, sealed)
        } catch (e: Exception) {
            return refuse(RecoveryVerdict.UNOPENABLE)
        }
        var parts: FrameParts? = null
        try {
            val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.ASSISTED_RECOVERY, version = 3)) {
                is Checked.Ok -> p.value
                is Checked.Refused -> return refuse(RecoveryVerdict.of(p.verdict))
            }
            parts = parsed.parts
            val raw = parsed.raw
            if (!RecoveryRotation.signerIsRecoveryKey(crypto, parsed.parts.signerPubRaw(), recoveryFp)) return refuse(RecoveryVerdict.SIGNER_NOT_PINNED_KEY)
            if (!SignedFrame.signatureValid(crypto, parsed.parts)) return refuse(RecoveryVerdict.BAD_SIGNATURE)
            if (raw.str("instanceId") != instanceId || raw.str("requestId") != requestId || raw.str("requestKey") != Bytes.toB64(rPub)) {
                return refuse(RecoveryVerdict.REQUEST_MISMATCH)
            }
            if (userId != null && raw.str("userId") != userId) return refuse(RecoveryVerdict.REQUEST_MISMATCH)
            // The address the answer restores is the one the person asked with, with or without a held account.
            val named = (TrustGrammar.decodeEmail(raw.str("email")) as? TrustGrammar.Email.Of)?.emailNorm
            val asked = TrustGrammar.emailNorm(typedEmail)
            if (named == null || asked == null || named != asked) return refuse(RecoveryVerdict.REQUEST_MISMATCH)
            val commit = Bytes.fromB64Exact(raw.str("commit"), 32) ?: return refuse(RecoveryVerdict.NON_CANONICAL)
            val uvk = raw.secret("uvk")
            try {
                // An all-zero key is no account's key: the identity check's verdict, with nothing opened under it.
                if (KeyFloor.allZero(uvk) || !identityHolds(crypto, uvk, raw.str("userId"), identity)) return refuse(RecoveryVerdict.IDENTITY_MISMATCH)
                return Checked.Ok(OpenedAssistedRecovery(raw.str("userId"), uvk, raw.long("issuedAt"), named, commit))
            } finally {
                uvk.fill(0)
                commit.fill(0)
            }
        } finally {
            frame.fill(0)
            parts?.wipe()
        }
    }

    /**
     * §9.3 step 4, the last check (R27): the served identity seed opens under [uvk] with [userId] in
     * its AD (`andvari/v1|idkey|{userId}`), and the X25519 key of that seed is the served `identityPub`.
     * Both served values are decoded strictly: a value that is not canonical base64url is no match.
     * Whoever made the delivered key also chose what the envelope holds, so a plaintext that is not a
     * 32-byte seed is no match either, and nothing the envelope holds reaches the caller as an exception.
     */
    private fun identityHolds(crypto: CryptoProvider, uvk: ByteArray, userId: String, identity: IdentityCheck): Boolean {
        val servedKey = Bytes.fromB64Exact(identity.identityPubB64, 32) ?: return false
        val envelope = Bytes.fromB64Canonical(identity.encryptedIdentitySeedB64) ?: return false
        val seed = try {
            Envelope.open(crypto, uvk, envelope, Ad.idkey(userId))
        } catch (e: Exception) {
            return false
        }
        try {
            if (seed.size != 32) return false
            val derived = try {
                crypto.boxKeypairFromSeed(seed)
            } catch (e: Exception) {
                return false
            }
            derived.privateKey.fill(0)
            return Bytes.ctEquals(derived.publicKey, servedKey)
        } finally {
            seed.fill(0)
        }
    }

    private fun refuse(verdict: RecoveryVerdict): Checked.Refused<RecoveryVerdict> = Checked.Refused(verdict)
}

/**
 * A veto of an assisted-recovery request (§9.3 step 2, purpose 0x0A, N3):
 * `{"v":2,"purpose":"recovery-veto","requestId":<b64_16>,"userId":<uuid>,"issuedAt":<ms>}`.
 */
data class VetoFields(val requestId: String, val userId: String, val issuedAt: Long)

/** The veto any signed-in device of the account can post during the 7-day hold (§9.3 step 2). */
object RecoveryVeto {
    /** Encode and sign a veto with [signer], the account's joint Ed25519 key. Refuses (`IllegalArgumentException`) values outside the grammar. */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, veto: VetoFields): ByteArray {
        val statement = StatementCodec.encode(
            TrustPurpose.RECOVERY_VETO,
            mapOf("requestId" to veto.requestId, "userId" to veto.userId, "issuedAt" to veto.issuedAt.toString()),
        )
        return SignedFrame.sign(crypto, signer, TrustPurpose.RECOVERY_VETO, statement)
    }

    /**
     * The server's checks on a posted veto, in §2.4's order ("Veto"); the first failure is the verdict:
     * 1. the §2 parse, purpose 0x0A (`bad_frame`, `unknown_format`, `non_canonical`, `bad_statement`);
     * 2. the signer maps to [identityPub], the identity key the server stores for the session's account
     *    (`signer_not_pinned_key`, §2.4), and the signature verifies (`bad_signature`);
     * 3. `userId` is [userId], the session's account (`user_mismatch`), and `requestId` is
     *    [requestId], the path's (`request_mismatch`).
     */
    fun verify(
        crypto: CryptoProvider,
        frame: ByteArray,
        identityPub: ByteArray,
        userId: String,
        requestId: String,
    ): Checked<VetoFields, RecoveryVerdict> {
        val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.RECOVERY_VETO)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return Checked.Refused(RecoveryVerdict.of(p.verdict))
        }
        val raw = parsed.raw
        // The helper is handed the account's stored identity key (§2.4): the signer maps to it, then the signature.
        if (!SignedFrame.signerMapsTo(crypto, parsed.parts, identityPub)) return Checked.Refused(RecoveryVerdict.SIGNER_NOT_PINNED_KEY)
        if (!SignedFrame.signatureValid(crypto, parsed.parts)) return Checked.Refused(RecoveryVerdict.BAD_SIGNATURE)
        // The field checks, one verdict each, in §2.4's order.
        if (raw.str("userId") != userId) return Checked.Refused(RecoveryVerdict.USER_MISMATCH)
        if (raw.str("requestId") != requestId) return Checked.Refused(RecoveryVerdict.REQUEST_MISMATCH)
        return Checked.Ok(VetoFields(raw.str("requestId"), raw.str("userId"), raw.long("issuedAt")))
    }
}
