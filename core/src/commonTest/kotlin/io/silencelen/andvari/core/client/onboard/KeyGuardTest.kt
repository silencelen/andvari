package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The guard itself: a wipe that cannot be cut short, and none that lands inside a use. */
class KeyGuardTest {
    private val whole = ByteArray(32) { (it + 1).toByte() }

    /** A hook that throws no longer ends the wipe; every hook runs, and the first failure is reported after. */
    @Test fun aHookThatThrowsDoesNotStopTheOthers() {
        val guard = KeyGuard()
        val first = GuardedKey(whole.copyOf(), guard)
        guard.whenWiped { error("a store that cannot be written") }
        var ran = false
        guard.whenWiped { ran = true }
        val later = GuardedKey(whole.copyOf(), guard)
        var a: ByteArray? = null
        var b: ByteArray? = null
        first.use { a = it }
        later.use { b = it }
        val e = assertFailsWith<IllegalStateException> { guard.wipe() }
        assertEquals("a store that cannot be written", e.message)
        assertTrue(guard.isWiped)
        assertTrue(ran, "the hook after the one that threw ran")
        assertTrue(a!!.all { it == 0.toByte() } && b!!.all { it == 0.toByte() }, "keys registered before and after the throwing hook are zeroed")
        guard.wipe() // idempotent, and nothing is left to run
    }

    /**
     * On the same thread the lock is re-entrant, so a wipe reached from inside a use could zero the key under it.
     * Now the wipe asked there marks the keys wiped at once (nothing new starts, a check refuses) and zeroes them when
     * that use ends: the use finishes on whole keys.
     */
    @Test fun aWipeReachedFromInsideAUseWaitsForThatUseToEnd() {
        val guard = KeyGuard()
        val uvk = GuardedKey(whole.copyOf(), guard)
        var held: ByteArray? = null
        val answer = uvk.use { k ->
            held = k
            guard.wipe()
            assertTrue(guard.isWiped, "the keys read as wiped at once")
            assertFailsWith<AccountWipedException> { guard.check() }
            assertFailsWith<AccountWipedException> { uvk.use { } }
            assertContentEquals(whole, k, "the running use still holds the whole key")
            k.size
        }
        assertEquals(32, answer)
        assertTrue(held!!.all { it == 0.toByte() }, "zeroed when the use ended")
        assertFailsWith<AccountWipedException> { uvk.use { } }
    }

    @Test fun aWipeFromANestedUseWaitsForTheOutermost() {
        val guard = KeyGuard()
        val uvk = GuardedKey(whole.copyOf(), guard)
        val signing = GuardedKey(whole.copyOf(), guard)
        var held: ByteArray? = null
        uvk.use { k ->
            held = k
            signing.use { guard.wipe() }
            assertFalse(k.all { it == 0.toByte() }, "the inner use's end is not the outer's")
        }
        assertTrue(held!!.all { it == 0.toByte() })
    }
}
