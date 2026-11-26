package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.tripwire.ZeroKeyTripwire
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The suites' tripwire records what reaches the provider under an all-zero
 * key, and every refusal of the floor, and nothing else. Each kind once found uncounted has its line here.
 * Every line this class makes in the suite's own record is marked expected (it is one of [ZeroKeyTripwire.EXPECTED]).
 */
class ZeroKeyTripwireTest {
    private val inner: CryptoProvider = LazySodiumCryptoProvider(com.goterl.lazysodium.LazySodiumJava(com.goterl.lazysodium.SodiumJava()))
    private val record = File.createTempFile("tripwire", ".txt").also { it.deleteOnExit() }
    private val t = ZeroKeyTripwire.Recording(inner, record)
    private val key = ByteArray(32) { 3 }
    private val zero = ByteArray(32)

    private fun counted(what: String, block: () -> Unit) {
        val before = record.readLines().size
        runCatching(block)
        val lines = record.readLines()
        assertEquals(before + 1, lines.size, "$what is counted once: ${lines.drop(before)}")
        assertTrue("ZeroKeyTripwireTest" in lines.last(), "the line names where it came from: ${lines.last()}")
    }

    @Test fun nothingUnderARealKeyIsRecorded() {
        val pair = t.boxKeypairFromSeed(key)
        val sign = t.signKeypairFromSeed(key)
        val sealed = t.aeadEncrypt(key, ByteArray(24), "x".encodeToByteArray(), ByteArray(0))
        t.aeadDecrypt(key, ByteArray(24), sealed, ByteArray(0))
        t.sealOpen(pair.publicKey, pair.privateKey, t.sealTo(pair.publicKey, """{"vk":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}""".encodeToByteArray()))
        // A public key or a hash of zeros in a document is a test's fixture, not a wiped secret.
        t.aeadEncrypt(key, ByteArray(24), """{"identityPub":"${Bytes.toB64(zero)}","genesisHash":"${"0".repeat(64)}"}""".encodeToByteArray(), ByteArray(0))
        t.hmacSha256(key, "message".encodeToByteArray())
        Hkdf.sha256(t, key, ByteArray(0), "info".encodeToByteArray(), 32) // HKDF's own all-zero default salt
        t.signDetached(sign.privateKey, byteArrayOf(1))
        val stream = t.secretstreamEncrypt(key, listOf(byteArrayOf(1)))
        t.secretstreamDecrypt(key, stream.header, stream.chunks)
        assertEquals(0L, record.length(), record.readText())
    }

    @Test fun whatTheFirstTripwireCounted() {
        counted("a seal under zeros") { t.aeadEncrypt(zero, ByteArray(24), "x".encodeToByteArray(), ByteArray(0)) }
        counted("a wrap of a wiped key") { t.aeadEncrypt(key, ByteArray(24), ByteArray(32), ByteArray(0)) }
        counted("a file under zeros") { t.secretstreamEncrypt(zero, listOf(byteArrayOf(1))) }
        counted("a sealed box of a wiped key") { t.sealTo(t.boxKeypairFromSeed(key).publicKey, ByteArray(64)) }
        counted("a signature with a zero seed") { t.signDetached(ByteArray(64), byteArrayOf(1)) }
        counted("HKDF from zeros") { t.hmacSha256(zero, ByteArray(32)) }
    }

    /** The seven kinds once found uncounted. */
    @Test fun theKindsOnceFoundUncounted() {
        counted("a MAC under zeros") { t.hmacSha256(zero, "andvari/v2|device-link|claim".encodeToByteArray()) }
        counted("a MAC under zeros (512)") { t.hmacSha512(zero, "x".encodeToByteArray()) }
        counted("HKDF extract with a salt from zero input") { t.hmacSha256("salt".encodeToByteArray(), ByteArray(32)) }
        counted("an X25519 pair from a zero seed") { t.boxKeypairFromSeed(zero) }
        counted("an Ed25519 pair from a zero seed") { t.signKeypairFromSeed(zero) }
        val pair = t.boxKeypairFromSeed(key)
        val box = t.sealTo(pair.publicKey, "x".encodeToByteArray())
        counted("a sealed-box open with a zero private key") { t.sealOpen(pair.publicKey, zero, box) }
        counted("an AEAD open under zeros") { t.aeadDecrypt(zero, ByteArray(24), ByteArray(40), ByteArray(0)) }
        val frame = """{"purpose":"vault-grant","vk":"${Bytes.toB64(zero)}"}""".encodeToByteArray()
        counted("a sealed box of a frame holding a zero key") { t.sealTo(pair.publicKey, frame) }
        counted("an AEAD seal of a frame holding a zero key") { t.aeadEncrypt(key, ByteArray(24), frame, ByteArray(0)) }
        val stream = t.secretstreamEncrypt(key, listOf(byteArrayOf(1)))
        counted("a stream open under zeros") { t.secretstreamDecrypt(zero, stream.header, stream.chunks) }
    }

    /** The floor tells the tripwire of each refusal before it throws, so a refusal a handler swallows still leaves a line. */
    @Test fun theFloorRecordsEachRefusal() {
        val watch = ZeroKeyTripwire()
        val before = KeyFloor.onRefusal
        val heard = ArrayList<String>()
        KeyFloor.onRefusal = { heard += it; watch.refused(it) }
        try {
            runCatching { Envelope.seal(t, zero, "x".encodeToByteArray(), ByteArray(0)) } // swallowed, as a careless handler would
            assertFailsWith<KeysGoneException> { KeyFloor.requireSigningKey(ByteArray(64)) }
            assertFailsWith<KeysGoneException> { KeyFloor.requireNotWipedKey(ByteArray(32)) }
            assertEquals(listOf("an all-zero key", "a signing key with an all-zero seed", "a wrap of an all-zero key"), heard)
        } finally {
            KeyFloor.onRefusal = before
        }
    }

    /** In the suite (the task sets the property), the factory's provider is the tripwire's and the floor reports to it. */
    @Test fun theSuitesProviderIsWatched() {
        if (System.getProperty(ZeroKeyTripwire.PROPERTY).isNullOrBlank()) return
        assertIs<ZeroKeyTripwire.Recording>(createCryptoProvider())
        assertTrue(KeyFloor.onRefusal != null, "the floor reports its refusals")
    }

    @Test fun aLineFromAnExpectedTestIsMarkedExpected() {
        counted("a seal under zeros") { t.aeadEncrypt(zero, ByteArray(24), "x".encodeToByteArray(), ByteArray(0)) }
        assertTrue(record.readLines().last().startsWith("expected "), "this class is one of EXPECTED")
    }
}
