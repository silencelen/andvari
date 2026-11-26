package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.tripwire.ZeroKeyTripwire
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The nine ways a key was once carried out of its guard, each written as it was first written,
 * and which half of the fence stops it now: the guard at run time ([KeyEscape], in every module's tests, never in
 * a shipped build) or the source
 * check ([AccountKeyFence], over shipped source in the test suite). Eight are stopped by both. One, a capture into a
 * variable outside the block (escape 4), is stopped only by the source check: its answer is `Unit`, so the guard has
 * nothing to look at. Stopped by neither: a capture or a copy written in a shape the source check does not list (a key
 * handed to a helper that keeps it, or wrapped in an object of the block's own making, as the tests' own `KeyCopy`
 * does).
 *
 * Escape 5's run-time half on the real lend (`StoredVaultLogs.withKey`) is
 * `StoredVaultLogsTest.aVaultKeyLendThatAnswersTheKeyIsRefused`.
 */
class KeyEscapesTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val uvk = GuardedKey.loose(key.copyOf())
    private val pair = KeyPairBytes(ByteArray(32) { 9 }, ByteArray(64) { (it + 7).toByte() })
    private val signing = GuardedKeyPair.loose(KeyPairBytes(pair.publicKey.copyOf(), pair.privateKey.copyOf()))
    private val identity = GuardedKeyPair.loose(KeyPairBytes(pair.publicKey.copyOf(), key.copyOf()))

    private fun caught(source: String) = AccountKeyFence.scan("fun f() {\n$source\n}\n")

    private fun bySource(source: String) = assertEquals(1, caught(source).size, "the source check flags: $source")

    /** [block] answers the use's answer: under `() -> Unit` Kotlin would infer the use's own answer as Unit. */
    private fun refused(what: String, block: () -> Any?) {
        val e = assertFailsWith<KeyEscapeException>(what) { block() }
        assertTrue("guarded use answered" in e.message!!, e.message)
    }

    @Test fun one_aUseThatAnswersThePairStoppedByBoth() {
        refused("identity.use { it }") { identity.use { it }.privateKey }
        bySource("val k = account.identity.use { it }.privateKey")
    }

    @Test fun two_aCopyOfRangeStoppedByBoth() {
        refused("copyOfRange") { uvk.use { it.copyOfRange(0, it.size) } }
        bySource("val k = uvk.use { it.copyOfRange(0, it.size) }")
    }

    @Test fun three_aCopyOfALengthStoppedByBoth() {
        refused("copyOf(32)") { uvk.use { it.copyOf(32) } }
        bySource("val k = uvk.use { it.copyOf(32) }")
    }

    @Test fun four_aCaptureIntoAnOuterVariableStoppedOnlyByTheSourceCheck() {
        var stash: ByteArray? = null
        uvk.use { k -> stash = k }
        assertContentEquals(key, stash, "the guard cannot see a capture: its answer is Unit")
        bySource("uvk.use { k -> stash = k }")
        bySource("uvk.use { stash = it.copyOf() }")
    }

    @Test fun five_theVaultKeyLendStoppedByBoth() {
        refused("withKey { it.copyOf() }") { KeyEscape.refuse(key.copyOf(), key) }
        bySource("val k = logs.withKey(vaultId) { it.copyOf() }")
        bySource("val k = withKey(vaultId) {\n    it.copyOf()\n}")
    }

    @Test fun six_aCopyOfThePrivateKeyStoppedByBoth() {
        refused("privateKey.copyOf(64)") { signing.use { p -> p.privateKey.copyOf(64) } }
        refused("the seed") { signing.use { p -> p.privateKey.copyOfRange(0, 32) } }
        bySource("val k = signing.use { p -> p.privateKey.copyOf(64) }")
    }

    @Test fun seven_aBodyOnTheNextLineStoppedByBoth() {
        refused("next line") {
            uvk.use {
                it.copyOf()
            }
        }
        bySource("val k = uvk.use {\n    it.copyOf()\n}")
        bySource("val k = uvk.use { k ->\n    val n = k.size\n    k.copyOf()\n}")
    }

    @Test fun eight_anAlsoStoppedByBoth() {
        val personalVk: GuardedKey? = uvk
        refused("also") { personalVk?.use { k -> k.also { } } }
        bySource("val k = personalVk?.use { k -> k.also { } }")
    }

    @Test fun nine_theKeysTextStoppedByBoth() {
        refused("toB64") { uvk.use { Bytes.toB64(it) } }
        refused("hex") { uvk.use { Bytes.toHexLower(it) } }
        refused("signing seed as text") { signing.use { Bytes.toB64(it.privateKey.copyOfRange(0, 32)) } }
        bySource("val t = uvk.use { Bytes.toB64(it) }")
    }

    @Test fun aRefusedCopyIsZeroedAndTheKeyIsNot() {
        var copy: ByteArray? = null
        refused("copy") { uvk.use { k -> k.copyOf().also { copy = it } } }
        assertTrue(copy!!.all { it == 0.toByte() }, "the refused copy is zeroed")
        assertContentEquals(key, uvk.copyOut(), "the key itself is untouched")
    }

    /**
     * The check decodes an answer instead of building the key's text, and still catches every
     * form it caught: hex in either case, base64url and base64 with or without padding, as a string or as ASCII bytes,
     * of the key and of a signing secret's seed half. Text of another key, or of the right length and not text, passes.
     */
    @Test fun everyTextFormIsStillCaughtWithoutBuildingOne() {
        val forms = listOf(
            Bytes.toHexLower(key), Bytes.toHexUpper(key),
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(key), java.util.Base64.getUrlEncoder().encodeToString(key),
            java.util.Base64.getEncoder().encodeToString(key), java.util.Base64.getEncoder().withoutPadding().encodeToString(key),
        )
        for (f in forms) {
            refused("the key as $f") { KeyEscape.refuse(f, key) }
            refused("the key as the bytes of $f") { KeyEscape.refuse(f.encodeToByteArray(), key) }
        }
        val seed = pair.privateKey.copyOfRange(0, 32)
        refused("the seed's hex") { KeyEscape.refuse(Bytes.toHexUpper(seed), pair.privateKey, pair) }
        refused("the whole secret's base64") { KeyEscape.refuse(java.util.Base64.getEncoder().encodeToString(pair.privateKey), pair.privateKey, pair) }
        val other = ByteArray(32) { (it + 2).toByte() }
        for (f in listOf(Bytes.toHexLower(other), java.util.Base64.getEncoder().encodeToString(other), "z".repeat(64), "=".repeat(44))) {
            assertEquals(f, KeyEscape.refuse(f, key), "passes: $f")
        }
    }

    /** Every test runs "checked" unless it asks otherwise, and the switch is put back. */
    @Test fun testsRunCheckedByDefaultAndTheSwitchIsPutBack() {
        assertTrue(KeyEscape.checking, "the tripwire is on this suite's class path, and checked is its default")
        ZeroKeyTripwire.asShipped { assertFalse(KeyEscape.checking) }
        assertTrue(KeyEscape.checking)
        assertFailsWith<IllegalStateException> { ZeroKeyTripwire.asShipped { error("thrown inside") } }
        assertTrue(KeyEscape.checking, "put back after a throw too")
    }

    /**
     * As shipped, a lend's answer is never compared with the key, zeroed or refused. Each of
     * the run-time escapes above comes back as the block answered it, and neither the copy nor the key is touched.
     */
    @Test fun asShippedEveryAnswerComesBackAsTheBlockAnsweredIt() = ZeroKeyTripwire.asShipped {
        var copy: ByteArray? = null
        assertContentEquals(key, uvk.use { k -> k.copyOf().also { copy = it } })
        assertContentEquals(key, copy, "the copy is not zeroed")
        assertContentEquals(key, uvk.use { it })
        assertContentEquals(key, uvk.use { it.copyOfRange(0, it.size) })
        assertEquals(Bytes.toB64(key), uvk.use { Bytes.toB64(it) })
        assertEquals(Bytes.toHexLower(key), uvk.use { Bytes.toHexLower(it) })
        assertContentEquals(Bytes.toHexLower(key).encodeToByteArray(), uvk.use { Bytes.toHexLower(it).encodeToByteArray() })
        assertEquals(key.toList(), uvk.use { it.toList() })
        assertEquals(Pair(1, Bytes.toB64(key)), uvk.use { Pair(1, Bytes.toB64(it)) })
        assertContentEquals(key, identity.use { it }.privateKey)
        assertContentEquals(pair.privateKey.copyOfRange(0, 32), signing.use { p -> p.privateKey.copyOfRange(0, 32) })
        assertContentEquals(key, KeyEscape.refuse(key.copyOf(), key), "the vault-key lend's check too")
        assertContentEquals(key, uvk.use { k -> k.copyOf() }, "the key itself is untouched")
    }

    @Test fun whatWasBuiltFromTheKeyLeavesFreely() {
        assertEquals(32, uvk.use { k -> ByteArray(32) { (k[it] + 1).toByte() } }.size)
        assertEquals(pair.publicKey.toList(), signing.use { it.publicKey }.toList(), "the public key may leave")
        assertEquals(Pair(1, "x"), uvk.use { Pair(1, "x") })
        assertTrue(caught("val s = uvk.use { k -> crypto.aeadEncrypt(k, n, p, ad) }\nval c = conn.use { it.read() }").isEmpty())
        refused("inside a pair") { uvk.use { Pair(1, it) } }
        refused("as a list of bytes") { uvk.use { it.toList() } }
    }
}
