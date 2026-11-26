package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

/**
 * The first form of grant seal (spec 01 §6.3, v1): an anonymous sealed box that anyone holding the member's public key
 * can make, the server included. One that carries a vault key of 32 zero bytes is refused as a grant that carries no
 * key (spec 01, "Keys in memory and the lock", rule 4), never handed back as a key. Before, it was handed back, and every
 * later open under it was refused by the key floor as though the account were locked. Every other key still opens.
 */
class SharedGrantZeroKeyTest {
    private val crypto = createCryptoProvider()
    private val vaultId = "33333333-3333-4333-8333-333333333333"
    private val me = crypto.boxKeypairFromSeed(ByteArray(32) { (it + 7).toByte() })

    /**
     * The test plays the hostile server: a v1 seal to the member of a payload whose `vk` is 32 zero bytes. Building it
     * puts a frame holding an all-zero `vk` through the provider's sealed box, which the zero-key tripwire counts; this
     * function is the one place the tripwire lists as expected for this class. The member's open happens outside it.
     */
    private fun sealOfZeros(): ByteArray = SharedGrant.seal(crypto, me.publicKey, vaultId, ByteArray(32))

    /** Fails on the code before the check: the zeros came back as the key. The member's own open records nothing. */
    @Test fun aV1SealCarryingAZeroVaultKeyIsRefusedAsAGrantWithNoKey() {
        val sealed = sealOfZeros()
        assertFailsWith<CryptoException> { SharedGrant.open(crypto, me.publicKey, me.privateKey, vaultId, sealed) }
    }

    @Test fun everyNonZeroVaultKeyStillOpens() {
        val keys = listOf(
            ByteArray(32).also { it[0] = 1 },
            ByteArray(32).also { it[31] = 1 },
            ByteArray(32) { 0xFF.toByte() },
            crypto.randomBytes(32).also { it[0] = (it[0].toInt() or 1).toByte() },
        )
        for (vk in keys) {
            val sealed = SharedGrant.seal(crypto, me.publicKey, vaultId, vk)
            assertContentEquals(vk, SharedGrant.open(crypto, me.publicKey, me.privateKey, vaultId, sealed), Bytes.toB64(vk))
        }
    }
}
