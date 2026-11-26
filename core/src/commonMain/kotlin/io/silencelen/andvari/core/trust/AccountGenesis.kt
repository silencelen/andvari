package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes

/**
 * The account genesis record as its statement says it (design 2026-11-15 §5.1):
 *
 * ```
 * {"v":2,"purpose":"account-genesis","userId":<uuid>,"identityKey":<b64_32>,"instanceId":<uuid>,
 *  "personalVaultId":<uuid>,"createdAt":<ms>}
 * ```
 *
 * [identityKey] is the account's X25519 identity key as `b64_32` text. [personalVaultId] names the
 * account's one personal vault forever (§5.3).
 */
data class GenesisFields(
    val userId: String,
    val identityKey: String,
    val instanceId: String,
    val personalVaultId: String,
    val createdAt: Long,
)

/**
 * Why a genesis was refused (§5.2; names and order from §2.4 "Account genesis", VR-13): one verdict
 * per check. A client shows the same identity security fault for every one of them, and the server
 * answers `400 bad_genesis`. The order of the entries is the check order.
 */
enum class GenesisVerdict(val code: String) {
    /** The §2 parse: see [FrameVerdict]. */
    BAD_FRAME("bad_frame"),
    UNKNOWN_FORMAT("unknown_format"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),

    /**
     * The signer is not the key the verifier was handed (§2.4, VR-9): on a client, not byte for byte the
     * seed-derived Ed25519 signing key; on the server, not mapping to `identityPub`.
     */
    SIGNER_NOT_PINNED_KEY("signer_not_pinned_key"),

    /** The Ed25519 signature does not verify. */
    BAD_SIGNATURE("bad_signature"),

    /** `identityKey` is not the expected identity key. */
    IDENTITY_MISMATCH("identity_mismatch"),

    /** `userId` is not the expected account. */
    USER_MISMATCH("user_mismatch"),

    /** `instanceId` is not the expected instance (the pinned card's; on the server, its own). */
    INSTANCE_MISMATCH("instance_mismatch"),

    /** `personalVaultId` is not the expected vault (the served personal wrap's; on the server, the body's). */
    PERSONAL_VAULT_MISMATCH("personal_vault_mismatch"),
    ;

    companion object {
        internal fun of(v: FrameVerdict): GenesisVerdict = when (v) {
            FrameVerdict.BAD_FRAME -> BAD_FRAME
            FrameVerdict.UNKNOWN_FORMAT -> UNKNOWN_FORMAT
            FrameVerdict.NON_CANONICAL -> NON_CANONICAL
            FrameVerdict.BAD_STATEMENT -> BAD_STATEMENT
        }
    }
}

/** A genesis that passed every check of [AccountGenesis.verify]. [hash] is `H(frame)`. */
class VerifiedGenesis internal constructor(val fields: GenesisFields, val hash: String)

/**
 * The account genesis record (design 2026-11-15 §5): signed once, at registration, by the account's own
 * identity key. It binds the account to its instance and to its one personal vault, so neither can be
 * swapped later by a server.
 */
object AccountGenesis {
    /**
     * Encode and sign the genesis with [signer], the account's joint Ed25519 key. The registering
     * client calls this exactly once (§5.2: "no client API can mint a second one"; that single call
     * site is the engine's to keep). Refuses (`IllegalArgumentException`) values outside the grammar
     * and a [signer] that does not map to `identityKey`.
     */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, genesis: GenesisFields): ByteArray {
        val image = try {
            crypto.ed25519PkToCurve25519(signer.publicKey)
        } catch (e: CryptoException) {
            throw IllegalArgumentException("the signer is not a usable Ed25519 key", e)
        }
        require(Bytes.toB64(image) == genesis.identityKey) { "a genesis is signed by the identity key it names" }
        val statement = StatementCodec.encode(
            TrustPurpose.ACCOUNT_GENESIS,
            mapOf(
                "userId" to genesis.userId, "identityKey" to genesis.identityKey, "instanceId" to genesis.instanceId,
                "personalVaultId" to genesis.personalVaultId, "createdAt" to genesis.createdAt.toString(),
            ),
        )
        return SignedFrame.sign(crypto, signer, TrustPurpose.ACCOUNT_GENESIS, statement)
    }

    /**
     * §5.2 on a CLIENT, at every unlock (online, and offline against the genesis cached with the
     * AccountKeys, R14), in this order; the first failure is the verdict:
     *
     * 1. the genesis parses (`bad_frame`, `unknown_format`, `non_canonical`, `bad_statement`);
     * 2. `signerPub` is [signPub], byte for byte (`signer_not_pinned_key`; §2.4, the Signer binding
     *    row 0x05), and the signature verifies (`bad_signature`);
     * 3. `identityKey` equals [identityPub] (`identity_mismatch`);
     * 4. `userId` equals [userId] (`user_mismatch`);
     * 5. `instanceId` equals [instanceId] (`instance_mismatch`);
     * 6. when [personalVaultId] is given, `personalVaultId` equals it (`personal_vault_mismatch`).
     *
     * [signPub] is the Ed25519 signing key and [identityPub] the X25519 identity key, BOTH derived from
     * the identity SEED at this unlock (`crypto_sign_seed_keypair` and `crypto_box_seed_keypair`), never
     * the served `identityPub`; [userId] the session's; [instanceId] the pinned card's; [personalVaultId]
     * the served `personalWrap.vaultId`, or null when no wrap is served. Any refusal is the identity
     * security fault.
     *
     * Comparing the Ed25519 key itself, not its X25519 image, refuses a genesis validly signed under the
     * negated key, which shares the image (spec 01 §5.1). The server holds no seed and uses
     * [verifyAtRegistration] instead.
     */
    fun verify(
        crypto: CryptoProvider,
        frame: ByteArray,
        signPub: ByteArray,
        identityPub: ByteArray,
        userId: String,
        instanceId: String,
        personalVaultId: String?,
    ): Checked<VerifiedGenesis, GenesisVerdict> =
        verifyBound(crypto, frame, identityPub, userId, instanceId, personalVaultId) { parts -> SignedFrame.signerIs(parts, signPub) }

    /**
     * §5.2 on the SERVER, at registration, which holds no seed: the same checks and order as [verify],
     * except that the signer is bound to [identityPub] through its X25519 image (§2.4, the Signer binding
     * row 0x05). [identityPub] and [userId] come from the register body, [instanceId] is the server's own,
     * [personalVaultId] the body's (`400 bad_genesis`).
     *
     * This is the WEAKER binding: `A` and `-A` share an image, so a genesis signed under the negated key
     * passes here (it registers, and every device of the account then refuses it). No client calls it;
     * a client has the seed and calls [verify].
     */
    fun verifyAtRegistration(
        crypto: CryptoProvider,
        frame: ByteArray,
        identityPub: ByteArray,
        userId: String,
        instanceId: String,
        personalVaultId: String?,
    ): Checked<VerifiedGenesis, GenesisVerdict> =
        verifyBound(crypto, frame, identityPub, userId, instanceId, personalVaultId) { parts -> SignedFrame.signerMapsTo(crypto, parts, identityPub) }

    private inline fun verifyBound(
        crypto: CryptoProvider,
        frame: ByteArray,
        identityPub: ByteArray,
        userId: String,
        instanceId: String,
        personalVaultId: String?,
        signerBound: (FrameParts) -> Boolean,
    ): Checked<VerifiedGenesis, GenesisVerdict> {
        val parsed = when (val p = StatementCodec.parseFrame(frame, TrustPurpose.ACCOUNT_GENESIS)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return Checked.Refused(GenesisVerdict.of(p.verdict))
        }
        val raw = parsed.raw
        // The helper is handed the key the context says signed (§2.4): the signer binds to it, then the signature.
        if (!signerBound(parsed.parts)) return Checked.Refused(GenesisVerdict.SIGNER_NOT_PINNED_KEY)
        if (!SignedFrame.signatureValid(crypto, parsed.parts)) return Checked.Refused(GenesisVerdict.BAD_SIGNATURE)
        // The field checks, one verdict each, in §2.4's order.
        val named = Bytes.fromB64Exact(raw.str("identityKey"), 32)
        if (named == null || !Bytes.ctEquals(named, identityPub)) return Checked.Refused(GenesisVerdict.IDENTITY_MISMATCH)
        if (raw.str("userId") != userId) return Checked.Refused(GenesisVerdict.USER_MISMATCH)
        if (raw.str("instanceId") != instanceId) return Checked.Refused(GenesisVerdict.INSTANCE_MISMATCH)
        if (personalVaultId != null && raw.str("personalVaultId") != personalVaultId) return Checked.Refused(GenesisVerdict.PERSONAL_VAULT_MISMATCH)
        val fields = GenesisFields(raw.str("userId"), raw.str("identityKey"), raw.str("instanceId"), raw.str("personalVaultId"), raw.long("createdAt"))
        return Checked.Ok(VerifiedGenesis(fields, SignedFrame.hash(crypto, frame)))
    }

    /**
     * The Ed25519 key that signed a genesis the caller ALREADY VERIFIED and stored: the frame's
     * `signerPub` (32 bytes), or null when [frame] does not parse as a genesis.
     *
     * This is the account's signing key as the server knows it (§4.1, spec 03 §17.2): the server
     * verified the genesis at registration ([verifyAtRegistration]) and kept the frame, and it hands this key to
     * [InstanceCard.verify] through [OperatorKeys], so that a card's `operatorSignKey` is compared with
     * the Ed25519 key itself and never through the X25519 `identityPub`, which a key shares with its
     * negation.
     *
     * It reads the key and verifies NOTHING: no signature, no signer binding, no field. So it is for a
     * stored frame only, never for one that just arrived, and its result is never the key to verify
     * that same frame against.
     */
    fun signerOf(frame: ByteArray): ByteArray? =
        StatementCodec.parseFrame(frame, TrustPurpose.ACCOUNT_GENESIS).valueOrNull()?.parts?.signerPub
}
