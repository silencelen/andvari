package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KeysAndEscrowTest {
    private val crypto = createCryptoProvider()

    // Small-but-legal Argon2 params keep the suite fast; real params are vector-pinned.
    private val fastParams = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024)

    @Test
    fun kdfChainIsDeterministicAndSplit() {
        val salt = ByteArray(16) { it.toByte() }
        val mk1 = Keys.masterKey(crypto, "hunter2!hunter2!", salt, fastParams)
        val mk2 = Keys.masterKey(crypto, "hunter2!hunter2!", salt, fastParams)
        assertContentEquals(mk1, mk2)
        val auth = Keys.authKey(crypto, mk1)
        val wrap = Keys.wrapKey(crypto, mk1)
        assertEquals(32, auth.size)
        assertEquals(32, wrap.size)
        assertFalse(auth.contentEquals(wrap), "auth/wrap purpose split must differ")
        val mkOther = Keys.masterKey(crypto, "hunter2!hunter2!", ByteArray(16) { (it + 1).toByte() }, fastParams)
        assertFalse(mk1.contentEquals(mkOther), "salt must change MK")
    }

    @Test
    fun uvkWrapRoundTrip() {
        val mk = Keys.masterKey(crypto, "pw pw pw pw", ByteArray(16), fastParams)
        val wrapKey = Keys.wrapKey(crypto, mk)
        val uvk = crypto.randomBytes(32)
        val userId = "44444444-4444-4444-8444-444444444444"
        val wrapped = Envelope.seal(crypto, wrapKey, uvk, Ad.uvk(userId))
        assertContentEquals(uvk, Envelope.open(crypto, wrapKey, wrapped, Ad.uvk(userId)))
        assertFailsWith<CryptoException> { Envelope.open(crypto, wrapKey, wrapped, Ad.uvk("other-user")) }
    }

    @Test
    fun escrowSealOpenAndSelfCheck() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val uvk = crypto.randomBytes(32)
        val userId = "55555555-5555-4555-8555-555555555555"

        val sealed = Escrow.sealUvk(crypto, recovery.publicKey, userId, uvk)
        val payload = Escrow.open(crypto, recovery.publicKey, recovery.privateKey, sealed)
        assertEquals(userId, payload.userId)
        assertEquals(Escrow.KEY_TYPE_UVK, payload.keyType)
        assertContentEquals(uvk, Bytes.fromB64(payload.key))

        val wrongKey = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        assertFailsWith<CryptoException> { Escrow.open(crypto, wrongKey.publicKey, wrongKey.privateKey, sealed) }
    }

    @Test
    fun escrowSelfCheckCatchesBadSha() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val bogus = """{"v":1,"userId":"x","keyType":"uvk","key":"${Bytes.toB64(crypto.randomBytes(32))}","sha256":"${Bytes.toB64(crypto.randomBytes(32))}"}"""
        val sealed = crypto.sealTo(recovery.publicKey, bogus.encodeToByteArray())
        assertFailsWith<CryptoException> { Escrow.open(crypto, recovery.publicKey, recovery.privateKey, sealed) }
    }

    @Test
    fun canaryRoundTrip() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val sealed = Escrow.sealCanary(crypto, recovery.publicKey)
        val payload = Escrow.open(crypto, recovery.publicKey, recovery.privateKey, sealed)
        assertEquals(Escrow.KEY_TYPE_CANARY, payload.keyType)
        assertEquals(Escrow.CANARY_USER_ID, payload.userId)
        assertContentEquals(Escrow.CANARY_KEY, Bytes.fromB64(payload.key))
    }

    @Test
    fun fingerprintShape() {
        val kp = crypto.boxKeypairFromSeed(ByteArray(32) { 7 })
        val fp = Escrow.fingerprint(crypto, kp.publicKey)
        assertEquals(64, fp.length)
        assertTrue(fp.all { it in "0123456789abcdef" })
        assertEquals(fp.take(16), Escrow.shortFingerprint(crypto, kp.publicKey))
    }

    @Test
    fun shortFormMatchesTolueratesSeparatorsAndRejectsWrong() {
        val full = "a4960ab45c42dea4" + "f".repeat(48) // 64 hex; short form = first 16
        // Exact, spaced, grouped, and uppercase transcriptions of the FIRST 16 all match.
        assertTrue(Escrow.shortFormMatches("a4960ab45c42dea4", full))
        assertTrue(Escrow.shortFormMatches("a496 0ab4 5c42 dea4", full))
        assertTrue(Escrow.shortFormMatches("A4:96:0A:B4:5C:42:DE:A4", full))
        // Wrong, too short, too long, and empty all reject (16 hex chars, exact prefix).
        assertFalse(Escrow.shortFormMatches("a4960ab45c42dea5", full)) // last char off
        assertFalse(Escrow.shortFormMatches("a4960ab45c42dea", full)) // 15 chars
        assertFalse(Escrow.shortFormMatches("a4960ab45c42dea4f", full)) // 17 chars
        assertFalse(Escrow.shortFormMatches("", full))
    }

    @Test
    fun seededKeypairIsDeterministic() {
        val a = crypto.boxKeypairFromSeed(ByteArray(32) { 9 })
        val b = crypto.boxKeypairFromSeed(ByteArray(32) { 9 })
        assertContentEquals(a.publicKey, b.publicKey)
        assertContentEquals(a.privateKey, b.privateKey)
    }
}
