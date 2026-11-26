package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.AccountGenesis
import io.silencelen.andvari.core.trust.CardHead
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.OperatorKeys
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RecoveryVerdict

/**
 * [TrustVerifiers] bound to `core/trust` (the shared verifiers): the same pure, clock-free verifiers every client runs.
 * While a body there is still a TODO, a route that reaches it answers `500 internal`; the server never
 * substitutes a second implementation.
 */
class CoreTrust : TrustVerifiers {
    private val crypto = createCryptoProvider()

    override fun parseCard(frame: ByteArray): ParsedCard? {
        val u = InstanceCard.parse(crypto, frame).valueOrNull() ?: return null
        val f = u.fields
        val key = runCatching { Bytes.fromB64(f.operatorSignKey) }.getOrNull() ?: return null
        return ParsedCard(frame, u.hash, u.signerPub, f.instanceId, f.seq, f.prev, f.origin, f.name, f.kind.literal, f.operator, key, f.recoveryFp ?: "none", f.issuedAt)
    }

    override fun verifyCardStep(previous: ParsedCard?, card: ParsedCard, instanceId: String, card0Hash: String?, signKeyOf: (String) -> ByteArray?): Boolean {
        val prior = previous?.let { CardHead(it.instanceId, card0Hash ?: it.hash, it.seq, it.hash, Bytes.toB64(it.operatorSignKey)) }
        // core compares the card's operatorSignKey byte for byte with the account's Ed25519 signing key (design §4.1).
        return InstanceCard.verify(crypto, prior, card.frame, instanceId, OperatorKeys { signKeyOf(it) }).isOk
    }

    override fun genesisSigner(frame: ByteArray): ByteArray? = AccountGenesis.signerOf(frame)

    override fun verifyRotation(frame: ByteArray, instanceId: String, currentFp: String): ParsedRotation? {
        val v = RecoveryRotation.verify(crypto, frame, instanceId, currentFp).valueOrNull() ?: return null
        return ParsedRotation(frame, v.hash, v.fields.instanceId, v.fields.fromFp, v.fields.toFp)
    }

    override fun verifyGenesis(frame: ByteArray, identityPub: ByteArray, userId: String, instanceId: String): ParsedGenesis? {
        // The server holds no seed: the X25519-image binding of §2.4 (a client binds the Ed25519 key itself).
        val v = AccountGenesis.verifyAtRegistration(crypto, frame, identityPub, userId, instanceId, null).valueOrNull() ?: return null
        val f = v.fields
        return ParsedGenesis(v.hash, f.userId, Bytes.fromB64(f.identityKey), f.instanceId, f.personalVaultId, f.createdAt)
    }

    override fun verifyRotationChain(frames: List<ByteArray>, instanceId: String, fromFp: String, toFp: String): Boolean =
        frames.isNotEmpty() && RecoveryRotation.verifyChain(crypto, frames, instanceId, fromFp, toFp) == null

    override fun checkVeto(frame: ByteArray, identityPub: ByteArray, userId: String, requestId: String): String? =
        when (val v = io.silencelen.andvari.core.trust.RecoveryVeto.verify(crypto, frame, identityPub, userId, requestId).verdictOrNull()) {
            null -> null
            RecoveryVerdict.BAD_FRAME, RecoveryVerdict.UNKNOWN_FORMAT, RecoveryVerdict.UNOPENABLE -> "bad_frame"
            RecoveryVerdict.NON_CANONICAL -> "non_canonical"
            RecoveryVerdict.BAD_STATEMENT -> "bad_statement"
            RecoveryVerdict.BAD_SIGNATURE -> "bad_signature"
            else -> "bad_signer"
        }

    override fun edToCurve(ed25519Pub: ByteArray): ByteArray? =
        if (ed25519Pub.size != 32) null else runCatching { crypto.ed25519PkToCurve25519(ed25519Pub) }.getOrNull()
}
