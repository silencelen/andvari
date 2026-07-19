package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
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

        // The SHIPPED default is ARMED (2026-07-18): the 2026-07-14 ceremony pubkey is pinned
        // (docs/runbooks/release-signing-keys.md) and the CALLERS scope the channel to the shipped
        // reference origin (multi-tenant §9: a self-host/custom baseUrl returns Disabled without a
        // fetch — desktop Platform.checkForUpdate + extension background.checkForUpdate).
        assertTrue(UpdateVerify.updatesEnabled(), "shipped default is ARMED with the ceremony key (reference-instance-scoped)")
        assertFalse(UpdateVerify.PINNED.contains(UpdateVerify.TEST_PUBKEY), "the armed set must not carry the sentinel")

        // A key SET (§M-D7): a real key alongside the sentinel still verifies (rotation overlap).
        assertTrue(UpdateVerify.verify(crypto, msg, sig, listOf(UpdateVerify.TEST_PUBKEY, Bytes.toB64(pub))))
    }

    @Test
    fun minSeq_isTheCompileTimeAntiRollbackFloor_lockstepWithExtension() {
        // §M-D4(a): the desktop anti-rollback floor (consumed by Platform.checkForUpdate as
        // maxOf(storedSeq, MIN_SEQ)). 1 since the first signed manifest (seq 1, 2026-07-18):
        // desktop refuses `seq < floor`, so 1 admits exactly the published floor. SEMANTIC (not
        // numeric) lockstep with the extension's `MIN_SEQ = 0` — its comparator refuses
        // `seq <= lastAccepted`, so the same "earliest acceptable seq is 1" floor is 0 there.
        assertEquals(1L, UpdateVerify.MIN_SEQ, "desktop floor = first published seq (its < comparator admits equality)")
        assertTrue(UpdateVerify.MIN_SEQ >= 0L, "the floor is never negative")

        // The floor semantics Platform.checkForUpdate applies: a fresh install (0) or a wiped/garbage
        // negative stored seq must never evaluate BELOW MIN_SEQ, so a validly-signed-but-older
        // manifest can't steer a downgrade beneath the floor; a real advance stays above it.
        assertEquals(UpdateVerify.MIN_SEQ, maxOf(0L, UpdateVerify.MIN_SEQ), "fresh install floors at MIN_SEQ")
        assertEquals(UpdateVerify.MIN_SEQ, maxOf(-5L, UpdateVerify.MIN_SEQ), "a wiped/negative stored seq floors at MIN_SEQ")
        assertEquals(42L, maxOf(42L, UpdateVerify.MIN_SEQ), "a real advanced seq stays above the floor")
    }
}
