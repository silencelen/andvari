package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.model.AdminEscrowDownload

/**
 * An account as the overhaul's clients seal its recovery copy (spec 04 §3): the version-3 copy that names its address
 * ([v3] false: the old version-2 copy, which names none), and the operator's escrow download for it.
 */
internal class Member(crypto: CryptoProvider, org: ByteArray, val email: String, v3: Boolean = true) {
    private val seed = crypto.randomBytes(32)
    val userId: String = Bytes.uuidV4FromBytes(crypto.randomBytes(16))
    val uvk: ByteArray = crypto.randomBytes(32)
    val identityPub: ByteArray = crypto.boxKeypairFromSeed(seed).publicKey
    val identityFp: String = Escrow.fingerprint(crypto, identityPub)
    val sealed: String = Bytes.toB64(
        if (v3) {
            Escrow.sealUvkV3(crypto, org, Escrow.fingerprint(crypto, org), userId, email, identityPub, crypto.signKeypairFromSeed(seed), uvk, 1_791_590_400_000L)
        } else {
            Escrow.sealUvkV2(crypto, org, Escrow.fingerprint(crypto, org), userId, identityPub, crypto.signKeypairFromSeed(seed), uvk, 1_791_590_400_000L)
        },
    )
    val download = AdminEscrowDownload(userId, sealed, Envelope.sealB64(crypto, uvk, seed, Ad.idkey(userId)), Bytes.toB64(identityPub))
    val check get() = IdentityCheck(download.encryptedIdentitySeed, download.identityPub)
}
