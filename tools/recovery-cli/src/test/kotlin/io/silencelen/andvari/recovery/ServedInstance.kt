package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields

/**
 * A server's `GET /api/v1/instance` answer as a test builds it (spec 03 §17.1): its cards, each signed by the operator's
 * key, and its rotations, each signed by the recovery seed it leaves. Every seed here is a made-up test seed.
 */
internal class ServedInstance(private val crypto: CryptoProvider, val instanceId: String) {
    private val operator = crypto.signKeypairFromSeed(crypto.randomBytes(32))
    private val operatorId = "0e0e0e0e-0e0e-4e0e-8e0e-0e0e0e0e0e0e"
    val cards = ArrayList<ByteArray>()
    val rotations = ArrayList<ByteArray>()
    private var prev = "0".repeat(64)

    fun fp(seed: ByteArray): String = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(seed).publicKey)

    /** The next card, naming the key of [recoverySeed] (null: `none`). */
    fun card(recoverySeed: ByteArray?, issuedAt: Long, forInstance: String = instanceId): ServedInstance = apply {
        val f = CardFields(
            forInstance, cards.size.toLong(), prev, "https://vault.family.example", "Family", InstanceKind.PRIVATE, operatorId,
            Bytes.toB64(operator.publicKey), recoverySeed?.let { fp(it) }, issuedAt,
        )
        val frame = InstanceCard.sign(crypto, operator, f)
        prev = InstanceCard.parse(crypto, frame).valueOrNull()!!.hash
        cards += frame
    }

    /** A rotation from [fromSeed]'s key to [toSeed]'s, signed by [signer] (by default the outgoing seed itself). */
    fun rotate(fromSeed: ByteArray, toSeed: ByteArray, issuedAt: Long, signer: ByteArray = fromSeed, forInstance: String = instanceId): ServedInstance = apply {
        val fields = RotationFields(forInstance, fp(fromSeed), fp(toSeed), issuedAt)
        rotations += if (signer === fromSeed) {
            RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(signer), fields)
        } else {
            // A statement whose signer is not the key its fromFp names: signed as the outgoing key would, then the signer swapped.
            val good = RecoveryRotation.sign(crypto, crypto.signKeypairFromSeed(fromSeed), fields)
            val other = crypto.signKeypairFromSeed(signer).publicKey
            good.copyOf().also { other.copyInto(it, 5) }
        }
    }

    /** The hash of card 0: what the operator holds of this server (the line card0Hash of `andvari-cli card show`). */
    fun card0Hash(): String = io.silencelen.andvari.core.trust.SignedFrame.hash(crypto, cards[0])

    fun json(extra: String = ""): ByteArray =
        ("{\"cards\":[" + cards.joinToString(",") { "\"" + Bytes.toB64(it) + "\"" } + "],\"rotations\":[" +
            rotations.joinToString(",") { "\"" + Bytes.toB64(it) + "\"" } + "]" + extra + "}").encodeToByteArray()
}
