package io.silencelen.andvari.updatesigner

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Round-trip: a workstation-minted Ed25519 keypair signs manifest bytes, and the CLIENT verify
 * primitive (core CryptoProvider.signVerifyDetached — the exact fn desktop/extension use via
 * UpdateVerify) accepts it; any tamper or wrong key is rejected. Proves signer ⇄ verifier agree.
 */
class UpdateSignerTest {
    private val ls = LazySodiumJava(SodiumJava())
    private val crypto = createCryptoProvider()

    @Test
    fun signThenClientVerifyRoundTrips_andTamperRejected() {
        val pk = ByteArray(32)
        val sk = ByteArray(64)
        assertTrue(ls.cryptoSignKeypair(pk, sk))
        // the pubkey the owner pins == the last 32 bytes of the Ed25519 secret key (seed||pubkey)
        assertTrue(pk.contentEquals(sk.copyOfRange(32, 64)))

        val manifest = """{"seq":1,"linux":{"version":"0.16.0","url":"/downloads/andvari-0.16.0.deb"}}""".encodeToByteArray()
        val sig = ByteArray(64)
        assertTrue(ls.cryptoSignDetached(sig, manifest, manifest.size.toLong(), sk))

        assertTrue(crypto.signVerifyDetached(pk, sig, manifest), "the client verify primitive must accept the signer's output")
        assertFalse(crypto.signVerifyDetached(pk, sig, manifest + 0x20), "appended manifest byte rejected")
        assertFalse(crypto.signVerifyDetached(pk, sig.copyOf().also { it[10] = (it[10] + 1).toByte() }, manifest), "flipped sig rejected")

        val pk2 = ByteArray(32)
        val sk2 = ByteArray(64)
        assertTrue(ls.cryptoSignKeypair(pk2, sk2))
        assertFalse(crypto.signVerifyDetached(pk2, sig, manifest), "a different key must reject")
    }
}
