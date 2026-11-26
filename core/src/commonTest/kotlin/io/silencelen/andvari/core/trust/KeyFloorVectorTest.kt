package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * `keyfloor.json`: the inputs every client must refuse under spec 01 "Keys in memory and the lock", rule 4 (an all-zero
 * key is never a key). Each row names an operation and an all-zero input; the shared code refuses it with
 * [KeysGoneException] before the platform's provider is called, and derives nothing. The near-zero rows that took the
 * places of these inputs in `links.json`, `devicelink.json` and `vaultlog.json` are graded there as ordinary rows.
 *
 * The TypeScript clients do not grade this file yet (spec/test-vectors/README.md says which functions must refuse).
 */
class KeyFloorVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("keyfloor.json")

    @Test
    fun theFileHasTheSectionsThisSuiteGrades() {
        assertSections(v, "_about", "refuse")
    }

    @Test
    fun refuse_everyAllZeroInputIsRefusedAtItsOperation() {
        val seen = mutableSetOf<String>()
        gradeEvery("keyfloor.refuse", v.rows("refuse")) { r ->
            val name = r.s("name")
            assertInputsKnown(r, setOf("name", "why", "operation", "refusedAt", "input", "formerly", "expect"), name)
            assertExpectGraded(r.o("expect"), setOf("refused"), name)
            assertTrue(r.o("expect").bool("refused"), "$name: expect.refused")
            val input = r.o("input")
            val operation = r.s("operation")
            seen += operation
            when (operation) {
                "links.derive" -> {
                    assertInputsKnown(input, setOf("secretB64"), name)
                    assertAllZero(input.b64("secretB64"), name)
                    assertFailsWith<KeysGoneException>(name) { Links.deriveKeys(crypto, input.b64("secretB64")) }
                }
                "devicelink.derive" -> {
                    assertInputsKnown(input, setOf("secretB64"), name)
                    assertAllZero(input.b64("secretB64"), name)
                    assertFailsWith<KeysGoneException>(name) { DeviceLink.deriveKeys(crypto, input.b64("secretB64")) }
                }
                "vaultlog.vkCommit" -> {
                    assertInputsKnown(input, setOf("vkB64", "vaultId"), name)
                    assertAllZero(input.b64("vkB64"), name)
                    assertFailsWith<KeysGoneException>(name) { VaultLog.vkCommit(crypto, input.b64("vkB64"), input.s("vaultId")) }
                    // A zero key matches no commitment: the check answers false, it does not throw.
                    assertEquals(false, VaultLog.keyMatches(crypto, input.s("vaultId"), vectorCommit(), input.b64("vkB64")), name)
                }
                else -> fail("$name: an operation this suite does not grade: $operation")
            }
        }
        assertEquals(setOf("links.derive", "devicelink.derive", "vaultlog.vkCommit"), seen, "every operation of the file has a row")
    }

    private fun assertAllZero(bytes: ByteArray, name: String) {
        assertEquals(32, bytes.size, "$name: a 32-byte input")
        assertTrue(bytes.all { it == 0.toByte() }, "$name: the input is all zeros")
    }

    /** vaultlog.json's own commitment, so that the check is made against a real one. */
    private fun vectorCommit(): String = vector("vaultlog.json").s("vkCommitHex")
}
