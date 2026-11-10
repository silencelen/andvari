package io.silencelen.andvari.core.client.session

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Review 3: the unlock mutex is never left held. The bound's timeout, or the caller's cancellation, can land after
 * `lock()` took the mutex and before the bounded wait returned; the acquisition is recorded right after `lock()`, and
 * a failure after it releases the mutex.
 */
class UnlockMutexTest {
    private val session = VaultSession(FakeClocks())

    @Test
    fun aTimeoutThatLandsAfterTheMutexWasTakenReleasesIt() = runBlocking<Unit> {
        // The bound fires while the acquisition is still inside it, after lock() took the mutex.
        val failure = runCatching { session.acquireUnlockMutex(50) { delay(10_000) } }.exceptionOrNull()
        assertIs<IOException>(failure, "a timed-out wait reads as unreachable")
        assertFalse(session.unlockMutex.isLocked, "and leaves the mutex free")
        session.withUnlockMutex(1_000) {} // the next unlock takes it at once
        assertFalse(session.unlockMutex.isLocked)
    }

    @Test
    fun aCancellationThatLandsAfterTheMutexWasTakenReleasesIt() = runBlocking<Unit> {
        val taken = CompletableDeferred<Unit>()
        val unlock = launch {
            session.acquireUnlockMutex(60_000) {
                taken.complete(Unit)
                awaitCancellation()
            }
        }
        taken.await()
        assertTrue(session.unlockMutex.isLocked)
        unlock.cancelAndJoin() // the caller went away right after the mutex was taken
        assertFalse(session.unlockMutex.isLocked, "its cancellation released the mutex")
    }

    @Test
    fun aWaitThatTimesOutWhileAnotherUnlockHoldsTheMutexTakesNothing() = runBlocking<Unit> {
        session.unlockMutex.lock() // another unlock holds it
        assertIs<IOException>(runCatching { session.withUnlockMutex(50) {} }.exceptionOrNull())
        assertTrue(session.unlockMutex.isLocked, "the holder still has it")
        session.unlockMutex.unlock()
        assertFalse(session.unlockMutex.isLocked)
    }

    @Test
    fun aFailingBlockReleasesTheMutex() = runBlocking<Unit> {
        runCatching { session.withUnlockMutex(1_000) { error("the unlock failed") } }
        assertFalse(session.unlockMutex.isLocked)
    }
}
