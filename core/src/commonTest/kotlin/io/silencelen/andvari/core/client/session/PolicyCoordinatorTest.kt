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
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.ClientPolicy
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The policy coordinator against in-memory platform seams, so these rules run on every target. */
class PolicyCoordinatorTest {
    private val home = "https://home.example"
    private val other = "https://other.example"
    private val homeKey = OriginCanon.originKey(home)
    private val otherKey = OriginCanon.originKey(other)

    private val clocks = FakeClocks(wall = 5_000L)
    private val store = FakeSessionPersistence(home)
    private val fence = OriginProbeFence()
    private var cacheClosedAtDelete: Boolean? = null
    private var liveCache: TrackingCache? = null
    private val artifacts = RecordingArtifacts { cacheClosedAtDelete = liveCache?.closed }
    private val session = VaultSession(clocks)
    private var rejected = 0
    private val coordinator = PolicyCoordinator(store, artifacts, session, clocks, fence, onSessionRejected = { rejected++ })

    private class TrackingCache(
        private val inner: InMemoryVaultCache = InMemoryVaultCache(),
        override val durable: Boolean = true,
    ) : VaultCache by inner {
        var closed = false
            private set

        override fun close() {
            closed = true
            inner.close()
        }
    }

    private companion object {
        val crypto = createCryptoProvider()
        val account: Account by lazy {
            val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            val fp = Escrow.fingerprint(crypto, recovery.publicKey)
            Account.enroll("invite", "u@example.com", "u", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fp, "device", crypto).account
        }
    }

    private fun api(origin: String) = AndvariApi(origin, HttpClient(MockEngine { respond("{}", HttpStatusCode.OK) }), Tokens("a", "r"))

    /** Binds a live session at [origin], on a durable cache unless [durable] is false, and hands back its api. */
    private fun bindLive(origin: String = home, durable: Boolean = true): AndvariApi {
        val api = api(origin)
        val cache = TrackingCache(durable = durable).also { liveCache = it }
        session.bind(api, account, SyncEngine(api, account, cache))
        store.save(StoredSession(origin, account.userId, "u@example.com", "a", "r"))
        return api
    }

    /** What every caller does before purging: the forbidding verdict is in the origin's mirror. */
    private fun forbid(originKey: String = homeKey) = coordinator.recordPolicy(originKey, ClientPolicy(offlineCacheAllowed = false))

    private fun storedHomeSession() = store.save(StoredSession(home, "u1", "u@example.com", "a", "r"))

    // ---- applyPolicy: the per-origin mirrors, the clamp, the fence ----

    @Test
    fun aCurrentPolicyIsMirroredUnderItsOriginAndArmsTheClampedWindow() {
        val tag = fence.tag(homeKey)
        val p = ClientPolicy(autoLockSeconds = 0, offlineCacheAllowed = false, serverTime = 123L)
        assertTrue(coordinator.applyPolicy(p, tag))
        val mirror = store.origin(homeKey)
        assertFalse(mirror.cacheAllowed)
        assertEquals(ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS, mirror.autoLockSeconds, "a 0 from the server clamps to the ceiling")
        assertEquals(5_000L, mirror.policyFetchedAt)
        assertEquals(123L, mirror.serverTimeFloorMs)
        assertEquals(ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS * 1000L, session.autoLockMillis(), "the live window is armed too")
    }

    @Test
    fun aStaleReplyWritesNothing() {
        val tag = fence.tag(homeKey)
        fence.advance()
        assertFalse(coordinator.applyPolicy(ClientPolicy(autoLockSeconds = 60), tag), "a reply from an earlier visit is dropped")
        assertEquals(0L, store.origin(homeKey).policyFetchedAt)
        assertEquals(0L, session.autoLockMillis())
    }

    @Test
    fun aReplyFromAnotherOriginIsRejectedAtTheFence() {
        val tag = fence.tag(otherKey) // the client dials home; this probe was of another origin
        assertFalse(coordinator.applyPolicy(ClientPolicy(autoLockSeconds = 60), tag))
        assertEquals(0L, store.origin(otherKey).policyFetchedAt)
    }

    @Test
    fun nothingIsCurrentBeforeAnOriginIsChosen() {
        val fresh = PolicyCoordinator(FakeSessionPersistence(null), artifacts, session, clocks, fence)
        assertFalse(fresh.probeIsCurrent(fence.tag(homeKey)))
    }

    @Test
    fun theServerTimeFloorOnlyMovesForward() {
        coordinator.recordPolicy(homeKey, ClientPolicy(serverTime = 500L))
        coordinator.recordPolicy(homeKey, ClientPolicy(serverTime = 100L))
        assertEquals(500L, store.origin(homeKey).serverTimeFloorMs, "a rollback in the server's clock must not lower the anchor")
    }

    @Test
    fun aPolicyProbeIsBounded() = runBlocking<Unit> {
        val slow = AndvariApi(home, HttpClient(MockEngine { delay(60_000L); respond("{}", HttpStatusCode.OK) }), null)
        assertFailsWith<IOException> { coordinator.boundedPolicy(slow, timeoutMs = 30L) }
        slow.close()
    }

    // ---- purgeForbidden: spec 02 §8 / spec 01 §8.1, the session stays valid ----

    @Test
    fun aForbiddingVerdictWithNoLiveEngineClearsEverythingButTheSession() {
        storedHomeSession()
        forbid()
        coordinator.purgeForbidden(homeKey, "u1")
        assertEquals(listOf("blob:$homeKey/u1", "cache:$homeKey/u1"), artifacts.events)
        assertEquals(listOf("u1"), store.origin(homeKey).clearedAccountKeys)
        assertEquals(listOf("u1"), store.origin(homeKey).clearedStamps)
        assertNotNull(store.stored, "a policy flip is not a revocation: the session stays")
        assertEquals(0, store.clearCalls)
        assertTrue(store.origin(otherKey).clearedAccountKeys.isEmpty(), "§4.2: never another origin")
    }

    @Test
    fun aForbiddingPollWithALiveEngineWipesSecretsNowAndTheFileAtClose() {
        val live = bindLive()
        val before = assertNotNull(session.get())
        forbid()
        coordinator.purgeForbidden(homeKey, account.userId)
        assertEquals(listOf("blob:$homeKey/${account.userId}"), artifacts.events, "the blob goes now; the DB is held open by the engine")
        assertEquals(listOf(account.userId), store.origin(homeKey).clearedStamps)
        assertEquals(before, session.get(), "the poll does not end the session")
        assertTrue(live === session.get()?.api)
        session.lock()
        assertEquals(listOf("blob:$homeKey/${account.userId}", "cache:$homeKey/${account.userId}"), artifacts.events, "the file goes as soon as the engine closes")
        assertEquals(true, cacheClosedAtDelete, "and only after it closes")
        session.lock()
        assertEquals(2, artifacts.events.size, "exactly once")
    }

    @Test
    fun aForbiddingVerdictForAnotherOriginIsNotDeferredByThisOnesEngine() {
        bindLive(home)
        forbid(otherKey)
        coordinator.purgeForbidden(otherKey, "stranger")
        assertTrue("cache:$otherKey/stranger" in artifacts.events, "no live engine holds that namespace")
        assertNotNull(session.get(), "and the live session here is untouched")
    }

    @Test
    fun aLaterAllowingVerdictKeepsTheFile() {
        bindLive()
        forbid()
        coordinator.purgeForbidden(homeKey, account.userId)
        coordinator.recordPolicy(homeKey, ClientPolicy(offlineCacheAllowed = true)) // the admin changed their mind
        session.lock()
        assertTrue(artifacts.events.none { it.startsWith("cache:") }, "the deletion reads the verdict when it runs: ${artifacts.events}")
    }

    @Test
    fun repeatedForbiddingPollsDeleteTheFileOnce() {
        bindLive()
        repeat(3) {
            forbid()
            coordinator.purgeForbidden(homeKey, account.userId)
        }
        session.lock()
        assertEquals(1, artifacts.events.count { it.startsWith("cache:") })
    }

    @Test
    fun aRebindUnderAForbiddingVerdictStillDeletesTheFile() {
        // The view model's bind: the verdict was queued against the old engine, and the new one runs in
        // memory. The replaced engine releases the file and the queued deletion runs, rather than vanishing.
        bindLive()
        forbid()
        coordinator.purgeForbidden(homeKey, account.userId)
        val oldCache = liveCache
        val api = api(home)
        session.bind(api, account, SyncEngine(api, account, TrackingCache(durable = false)))
        assertEquals(true, oldCache?.closed)
        assertTrue("cache:$homeKey/${account.userId}" in artifacts.events)
    }

    @Test
    fun theBindTimePurgeRunsAtOnceForAnInMemoryEngine() {
        // Purging AFTER the bind (as the view model and the autofill unlock now do) must not wait on an
        // engine that holds no file.
        forbid()
        bindLive(durable = false)
        coordinator.purgeForbidden(homeKey, account.userId)
        assertTrue("cache:$homeKey/${account.userId}" in artifacts.events)
    }

    @Test
    fun aRebindOntoTheSameFileKeepsTheDeletionWaiting() {
        bindLive()
        forbid()
        coordinator.purgeForbidden(homeKey, account.userId)
        bindLive() // another durable engine on the same file
        assertTrue(artifacts.events.none { it.startsWith("cache:") })
        session.lock()
        assertEquals(1, artifacts.events.count { it.startsWith("cache:") })
    }

    // ---- purgeRevoked and the in-session rejection: spec 02 §8, spec 01 §8.1 ----

    @Test
    fun aRevocationPurgesEverythingAndEndsTheStoredSession() {
        storedHomeSession()
        coordinator.purgeRevoked(homeKey, "u1")
        assertEquals(listOf("cache:$homeKey/u1", "blob:$homeKey/u1"), artifacts.events)
        assertEquals(listOf("u1"), store.origin(homeKey).clearedAccountKeys)
        assertEquals(listOf("u1"), store.origin(homeKey).clearedStamps)
        assertNull(store.stored, "the session is over")
    }

    @Test
    fun aRefusedRefreshOnTheLiveHolderEndsTheSessionAndPurges() {
        val live = bindLive()
        coordinator.onRefreshRefused(live)
        assertNull(session.get(), "the session is locked")
        assertEquals(true, cacheClosedAtDelete, "and the engine closes before its database is deleted")
        assertEquals(listOf("cache:$homeKey/${account.userId}", "blob:$homeKey/${account.userId}"), artifacts.events)
        assertEquals(listOf(account.userId), store.origin(homeKey).clearedAccountKeys)
        assertNull(store.stored)
        assertEquals(1, rejected, "the UI layer hears about it after the purge")
    }

    @Test
    fun aRefusedRefreshOnAnyOtherClientChangesNothingHere() {
        // Nothing live: an unlock in progress handles its own 401 at the catch site.
        val orphan = api(home)
        coordinator.onRefreshRefused(orphan)
        assertTrue(artifacts.events.isEmpty())
        assertEquals(0, rejected)

        // A live session of its own is not ended by a superseded holder's refusal.
        val liveApi = bindLive()
        coordinator.onRefreshRefused(orphan)
        assertTrue(artifacts.events.isEmpty())
        assertEquals(liveApi, session.get()?.api)
        assertEquals(0, rejected)
    }
}
