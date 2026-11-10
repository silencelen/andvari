package io.silencelen.andvari.core.client.session

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Review 3: what the KDF built reaches its caller, or is discarded when the caller stopped waiting for it. */
class HandOffTest {
    @Test
    fun aResultIsHandedToTheCallerThatWaited() = runBlocking<Unit> {
        val discarded = mutableListOf<String>()
        assertEquals("account", handOff({ "account" }, { discarded += it }))
        assertTrue(discarded.isEmpty())
    }

    @Test
    fun aResultTheCallerStoppedWaitingForIsDiscarded() = runBlocking<Unit> {
        val building = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val discarded = CompletableDeferred<String>()
        val unlock = async {
            handOff({
                building.complete(Unit)
                runBlocking { finish.await() } // the KDF is still running
                "account"
            }, { discarded.complete(it) })
        }
        building.await()
        unlock.cancel() // the caller went away while the account was being built
        finish.complete(Unit)
        assertFailsWith<CancellationException> { unlock.await() }
        assertEquals("account", discarded.await(), "the account nobody received was discarded (wiped)")
    }

    @Test
    fun aFailureDiscardsNothing() = runBlocking<Unit> {
        val discarded = mutableListOf<String>()
        assertFailsWith<IllegalStateException> { handOff<String>({ error("wrong password") }, { discarded += it }) }
        assertTrue(discarded.isEmpty())
    }
}
