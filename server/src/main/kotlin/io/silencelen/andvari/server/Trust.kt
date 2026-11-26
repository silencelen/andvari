package io.silencelen.andvari.server

/**
 * The server's view of the shared pure verifiers (`core/trust`): the server runs the same code
 * every client runs (spec 03 §10.3 step 7, design T-R2) and never keeps a second implementation of the
 * statement rules. This interface is the seam; [CoreTrust] binds it to `core/trust`.
 *
 * Every method is total: a refusal is a value, never an exception.
 */
interface TrustVerifiers {
    /** Strict parse of a 0x04 instance-card frame (spec 01 §5.1 steps 1–6), or null (`400 bad_card`). */
    fun parseCard(frame: ByteArray): ParsedCard?

    /**
     * The chain step for [card] (spec 01 §5.2): card 0 when [previous] is null (signer = its own
     * `operatorSignKey`, `prev` = 64 zeros), otherwise `prev = H(previous)`, the signer = the previous card's
     * `operatorSignKey`, and `instanceId` the instance's; then the Ed25519 signature; and the operator key is
     * byte-equal to the Ed25519 signing key of the account `operator` names ([signKeyOf]: the signer of its
     * stored genesis, spec 03 §17.2; never compared through the X25519 image).
     */
    fun verifyCardStep(previous: ParsedCard?, card: ParsedCard, instanceId: String, card0Hash: String?, signKeyOf: (String) -> ByteArray?): Boolean

    /** The `signerPub` of a stored genesis frame (the account's Ed25519 signing key), or null when it does not parse. */
    fun genesisSigner(frame: ByteArray): ByteArray?

    /**
     * Strict parse and signature of a 0x08 rotation (spec 04 §5, spec 03 §3.2): the signer is the recovery
     * key [currentFp] names (`fromFp == currentFp`, `SHA-256(ed25519_pk_to_curve25519(signerPub)) == fromFp`),
     * the signature, then `instanceId` (design §2.4's order: parse, fp_mismatch, signer, signature, instance).
     */
    fun verifyRotation(frame: ByteArray, instanceId: String, currentFp: String): ParsedRotation?

    /**
     * The account genesis (spec 01 §5.4, purpose 0x05): strict parse, `ed25519_pk_to_curve25519(signerPub)`
     * equal to [identityPub] and so is `identityKey`, `userId` and `instanceId` as given, and the signature.
     * The personal vault id is returned for the caller's own step-9 compare.
     */
    fun verifyGenesis(frame: ByteArray, identityPub: ByteArray, userId: String, instanceId: String): ParsedGenesis?

    /**
     * `PUT /escrow/self`'s `rotations` (spec 03 §3.2): oldest first, the first from [fromFp], each from the
     * previous `toFp`, the last to [toFp], each signed by the key its `fromFp` names. Empty is false.
     */
    fun verifyRotationChain(frames: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): Boolean

    /**
     * A 0x0A veto (spec 03 §18.3): null when it verifies for [userId] and [requestId] under [identityPub],
     * else the wire code (`bad_frame`, `non_canonical`, `bad_statement`, `bad_signer`, `bad_signature`).
     */
    fun checkVeto(frame: ByteArray, identityPub: ByteArray, userId: String, requestId: String): String?

    /** `ed25519_pk_to_curve25519(signerPub)`, or null when the key has no curve image. */
    fun edToCurve(ed25519Pub: ByteArray): ByteArray?
}

/** The routing and field values of a parsed card. [hash] is `H(frame)`, lowercase hex. */
class ParsedCard(
    val frame: ByteArray,
    val hash: String,
    val signerPub: ByteArray,
    val instanceId: String,
    val seq: Long,
    val prev: String,
    val origin: String,
    val name: String,
    val kind: String,
    val operator: String,
    val operatorSignKey: ByteArray,
    val recoveryFp: String,
    val issuedAt: Long,
)

/** A verified 0x08 recovery-rotation statement (spec 04 §5). */
class ParsedRotation(val frame: ByteArray, val hash: String, val instanceId: String, val fromFp: String, val toFp: String)

/** A verified account genesis (spec 01 §5.4). [identityKey] is the X25519 key the statement names. */
class ParsedGenesis(val hash: String, val userId: String, val identityKey: ByteArray, val instanceId: String, val personalVaultId: String, val createdAt: Long)
