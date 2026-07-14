package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * H2 signed-update verify (design 2026-07-13-signed-updates §D/§M). Pins the Ed25519 primitive to an
 * RFC 8032 test vector (TEST 2 — a known-good pubkey/message/signature triple, no local signing
 * needed) and exercises the fail-closed + §M-D3 test-key-disable logic of [UpdateVerify].
 */
class UpdateVerifyTest {
    private val crypto = createCryptoProvider()

    private fun hex(s: String) = ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

    // RFC 8032 §7.1 TEST 2
    private val pub = hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    private val msg = hex("72")
    private val sig = hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")

    @Test
    fun primitive_verifiesRfc8032AndRejectsTampering() {
        assertTrue(crypto.signVerifyDetached(pub, sig, msg), "RFC 8032 TEST 2 must verify")
        assertFalse(crypto.signVerifyDetached(pub, sig.copyOf().also { it[0] = (it[0] + 1).toByte() }, msg), "flipped sig must reject")
        assertFalse(crypto.signVerifyDetached(pub, sig, msg.copyOf().also { it[0] = (it[0] + 1).toByte() }), "flipped message must reject")
        assertFalse(crypto.signVerifyDetached(pub, sig, msg + 0x00), "appended message byte must reject")
        assertFalse(crypto.signVerifyDetached(ByteArray(32), sig, msg), "wrong pubkey must reject")
        // Bad sizes fail closed, never throw.
        assertFalse(crypto.signVerifyDetached(pub, ByteArray(63), msg), "short sig fails closed")
        assertFalse(crypto.signVerifyDetached(ByteArray(31), sig, msg), "short pubkey fails closed")
    }

    @Test
    fun updateVerify_realPinnedKeyVerifies_sentinelOnlyIsDisabled() {
        val pinnedReal = listOf(Bytes.toB64(pub)) // the RFC-8032 key used as an explicit pin
        assertTrue(UpdateVerify.updatesEnabled(pinnedReal))
        assertTrue(UpdateVerify.verify(crypto, msg, sig, pinnedReal), "a real pinned key verifies a genuine sig")
        assertFalse(UpdateVerify.verify(crypto, msg + 0x00, sig, pinnedReal), "tamper rejected through the UpdateVerify path")

        // §M-D3: a build pinning ONLY the placeholder sentinel offers NO updates — even a genuine sig.
        assertFalse(UpdateVerify.updatesEnabled(listOf(UpdateVerify.TEST_PUBKEY)), "sentinel-only must be disabled")
        assertFalse(UpdateVerify.verify(crypto, msg, sig, listOf(UpdateVerify.TEST_PUBKEY)), "sentinel-only fails closed")

        // The SHIPPED default now pins the real workstation key (ceremony 2026-07-14) → updates enabled.
        assertTrue(UpdateVerify.updatesEnabled(), "shipped default pins a real key")

        // A key SET (§M-D7): a real key alongside the sentinel still verifies (rotation overlap).
        assertTrue(UpdateVerify.verify(crypto, msg, sig, listOf(UpdateVerify.TEST_PUBKEY, Bytes.toB64(pub))))
    }
}
