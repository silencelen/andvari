package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class VaultSessionTest {
    private class FakeClocks(var mono: Long = 1_000L, var wall: Long = 0L, var boot: String? = null) : Clocks {
        override fun wallMs() = wall
        override fun monotonicMs() = mono
        override fun bootId() = boot
    }

    private class TrackingCache(
        private val inner: InMemoryVaultCache = InMemoryVaultCache(),
        override val durable: Boolean = false,
    ) : VaultCache by inner {
        var closed = false
            private set

        override fun close() {
            closed = true
            inner.close()
        }
    }

    /** Records the end-of-session calls in order, and hands `closeTransport` to the test. */
    private class RecordingHook : SessionEndHook {
        val events = mutableListOf<String>()
        var flushed: VaultSession.Unlocked? = null
        var closeTransport: (() -> Unit)? = null

        override fun flush(session: VaultSession.Unlocked, closeTransport: () -> Unit) {
            events += "flush"
            flushed = session
            this.closeTransport = closeTransport
        }

        override fun clear() {
            events += "clear"
        }
    }

    private companion object {
        val crypto = createCryptoProvider()
        // One enrolled account is enough for every holder test: its contents are never read here.
        val account: Account by lazy {
            val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            val fp = Escrow.fingerprint(crypto, recovery.publicKey)
            Account.enroll("invite", "u@example.com", "u", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fp, "device", crypto).account
        }
    }

    private fun api() = AndvariApi("http://fake", HttpClient(MockEngine { respond("{}", HttpStatusCode.OK) }), Tokens("a", "r"))
    private fun engine(cache: TrackingCache = TrackingCache()): Pair<SyncEngine, TrackingCache> = SyncEngine(api(), account, cache) to cache

    private val minute = 60_000L

    @Test
    fun theIdleWindowIsMeasuredOnTheMonotonicClock() {
        val clocks = FakeClocks()
        val s = VaultSession(clocks)
        s.bind(api(), account, engine().first)
        s.setAutoLockSeconds(60)
        clocks.mono += minute - 1
        // A wall-clock jump must not matter to the window in either direction.
        clocks.wall += 90 * minute
        assertFalse(s.idleExpired())
        clocks.mono += 1
        assertTrue(s.idleExpired())
        assertEquals(60, s.idleSeconds())
    }

    @Test
    fun touchAndBindRestartTheWindow() {
        val clocks = FakeClocks()
        val s = VaultSession(clocks)
        s.bind(api(), account, engine().first)
        s.setAutoLockSeconds(60)
        clocks.mono += minute - 1
        s.touch()
        clocks.mono += minute - 1
        assertFalse(s.idleExpired(), "touch restarts the window")
        clocks.mono += 2
        assertTrue(s.idleExpired())
        s.bind(api(), account, engine().first)
        assertFalse(s.idleExpired(), "spec 01 §8: the auto-lock timer resets on unlock")
    }

    @Test
    fun aServerCannotDisableOrStretchTheLock() {
        val clocks = FakeClocks()
        val s = VaultSession(clocks)
        s.bind(api(), account, engine().first)
        val ceilingMs = ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS * 1000L
        s.setAutoLockSeconds(0)
        assertEquals(ceilingMs, s.autoLockMillis(), "0 clamps to the ceiling, it never means 'no lock'")
        clocks.mono += ceilingMs
        assertTrue(s.idleExpired())
        s.setAutoLockSeconds(Int.MAX_VALUE)
        assertEquals(ceilingMs, s.autoLockMillis())
    }

    @Test
    fun aLockedSessionIsNeverIdleExpired() {
        val clocks = FakeClocks()
        val s = VaultSession(clocks)
        s.setAutoLockSeconds(60)
        clocks.mono += 10 * minute
        assertFalse(s.idleExpired())
        assertNull(s.getIfFresh())
    }

    @Test
    fun anExpiredSessionIsLockedAtTheServeGate() {
        val clocks = FakeClocks()
        val hook = RecordingHook()
        val s = VaultSession(clocks, hook)
        val (engine, cache) = engine()
        s.bind(api(), account, engine)
        s.setAutoLockSeconds(60)
        assertNotNull(s.getIfFresh(), "within the window it serves the live session")
        clocks.mono += minute
        assertNull(s.getIfFresh(), "past the window the gate locks and serves nothing")
        assertNull(s.get())
        assertTrue(cache.closed, "the engine's cache handle is released")
        assertEquals(listOf("flush", "clear"), hook.events)
    }

    @Test
    fun anInFlightOpDefersTheServeGateButNotForever() {
        val clocks = FakeClocks()
        val s = VaultSession(clocks)
        val (engine, cache) = engine()
        s.bind(api(), account, engine)
        s.setAutoLockSeconds(60)
        clocks.mono += minute
        s.setOperationInProgress(true)
        assertNotNull(s.getIfFresh(), "an op in flight must not have the engine closed under it")
        assertFalse(cache.closed)
        s.setOperationInProgress(false)
        assertNull(s.getIfFresh(), "the deferred lock lands as soon as the op ends")
        assertTrue(cache.closed)
    }

    @Test
    fun rebindingClosesThePreviousEngine() {
        val s = VaultSession(FakeClocks())
        val (first, firstCache) = engine()
        val (second, secondCache) = engine()
        val holder = api()
        s.bind(holder, account, first)
        s.bind(holder, account, second)
        assertTrue(firstCache.closed)
        assertFalse(secondCache.closed)
        // Rebinding the same engine must not close it (a reused holder).
        s.bind(holder, account, second)
        assertFalse(secondCache.closed)
        assertSame(second, assertNotNull(s.get()).engine)
    }

    @Test
    fun lockHandsTheTransportToTheFlushAndDoesNotWaitForIt() {
        val hook = RecordingHook()
        val s = VaultSession(FakeClocks(), hook)
        val (engine, cache) = engine()
        val live = api()
        s.bind(live, account, engine)
        s.lock()
        // The keys and the engine are gone before the flush has finished.
        assertNull(s.get())
        assertTrue(cache.closed)
        assertSame(live, hook.flushed?.api, "the flush is given the session that was live")
        assertNotNull(hook.closeTransport, "the hook now owns closing the transport")
        hook.closeTransport!!.invoke() // runs without the session still bound; must not throw
        assertEquals(listOf("flush", "clear"), hook.events)
    }

    @Test
    fun lockWithNoSessionStillClearsTheBehaviouralBuffer() {
        val hook = RecordingHook()
        val s = VaultSession(FakeClocks(), hook)
        s.lock()
        assertEquals(listOf("clear"), hook.events)
    }

    private val originKey = OriginCanon.originKey("http://fake")

    @Test
    fun workForAHeldFileWaitsForTheEngineToClose() {
        val s = VaultSession(FakeClocks())
        val (engine, cache) = engine(TrackingCache(durable = true))
        s.bind(api(), account, engine)
        assertTrue(s.holds(originKey, account.userId))
        var ran = 0
        s.runWhenEngineCloses(originKey, account.userId) {
            assertTrue(cache.closed, "the DB is only ever deleted after its engine released it")
            ran++
        }
        assertEquals(0, ran, "held open by the live engine")
        s.lock()
        assertEquals(1, ran, "runs on the close, whichever path ended the session")
        assertFalse(s.holds(originKey, account.userId))
        s.lock()
        assertEquals(1, ran, "exactly once")
    }

    @Test
    fun anInMemoryEngineHoldsNoFileBack() {
        val s = VaultSession(FakeClocks())
        s.bind(api(), account, engine().first) // in-memory cache: the namespace is live, its file is not open
        var ran = 0
        s.runWhenEngineCloses(originKey, account.userId) { ran++ }
        assertEquals(1, ran)
    }

    @Test
    fun workForAnotherNamespaceRunsImmediately() {
        val s = VaultSession(FakeClocks())
        s.bind(api(), account, engine(TrackingCache(durable = true)).first)
        var ran = 0
        s.runWhenEngineCloses(OriginCanon.originKey("https://elsewhere.example"), account.userId) { ran++ }
        assertEquals(1, ran)
        s.runWhenEngineCloses(originKey, "another-user") { ran++ }
        assertEquals(2, ran, "and for another account at this origin")
        val locked = VaultSession(FakeClocks())
        locked.runWhenEngineCloses(originKey, account.userId) { ran++ }
        assertEquals(3, ran, "and when nothing is bound")
    }

    @Test
    fun aRepeatedRequestReplacesTheQueuedOne() {
        val s = VaultSession(FakeClocks())
        s.bind(api(), account, engine(TrackingCache(durable = true)).first)
        val runs = mutableListOf<String>()
        repeat(3) { i -> s.runWhenEngineCloses(originKey, account.userId) { runs += "poll $i" } }
        s.lock()
        assertEquals(listOf("poll 2"), runs, "one entry per namespace, however many polls repeated the verdict")
    }

    @Test
    fun aReplacementThatDoesNotHoldTheFileRunsTheQueuedWork() {
        val s = VaultSession(FakeClocks())
        val holder = api()
        val (first, firstCache) = engine(TrackingCache(durable = true))
        s.bind(holder, account, first)
        var ran = 0
        s.runWhenEngineCloses(originKey, account.userId) {
            assertTrue(firstCache.closed, "the replaced engine released the file first")
            ran++
        }
        s.bind(holder, account, engine().first) // in memory: nothing holds the file any more
        assertEquals(1, ran, "a rebind must not drop the deletion")
    }

    @Test
    fun aReplacementForAnotherNamespaceRunsTheQueuedWork() {
        val s = VaultSession(FakeClocks())
        s.bind(api(), account, engine(TrackingCache(durable = true)).first)
        var ran = 0
        s.runWhenEngineCloses(originKey, account.userId) { ran++ }
        val elsewhere = AndvariApi("https://elsewhere.example", HttpClient(MockEngine { respond("{}", HttpStatusCode.OK) }), Tokens("a", "r"))
        s.bind(elsewhere, account, SyncEngine(elsewhere, account, TrackingCache(durable = true)))
        assertEquals(1, ran)
    }

    @Test
    fun aReplacementHoldingTheSameFileKeepsTheWorkWaiting() {
        val s = VaultSession(FakeClocks())
        val holder = api()
        s.bind(holder, account, engine(TrackingCache(durable = true)).first)
        var ran = 0
        s.runWhenEngineCloses(originKey, account.userId) { ran++ }
        val (second, secondCache) = engine(TrackingCache(durable = true))
        s.bind(holder, account, second)
        assertEquals(0, ran, "the new engine has the same file open")
        s.lock()
        assertEquals(1, ran)
        assertTrue(secondCache.closed)
    }

    @Test
    fun aQuickUnlockKeepsItsProvenanceOnTheBoundSession() {
        val s = VaultSession(FakeClocks())
        s.bind(api(), account, engine().first, VaultSession.UnlockProvenance.QUICK)
        assertEquals(VaultSession.UnlockProvenance.QUICK, assertNotNull(s.get()).provenance)
    }
}
