package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.UsageLedger.Entry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The usage-recorder SHELL's wiring (audit G39 hoist + G04 prune), the behaviour the two thin
 * platform adapters share. The RULES are pinned in [UsageLedgerTest]; these pin the state machine
 * around them — most sharply, WHERE it is safe to prune.
 *
 * G04's whole hazard is a prune against a NON-authoritative item set: dropping usage for items
 * merely not synced to THIS device yet silently destroys other devices' entries. So the two
 * load-bearing pins here are (a) the post-sync flush DOES prune a deleted item's entry against a
 * complete live set, and (b) the teardown flush does NOT prune — an entry for an item this device
 * has never seen locally survives, because a lock/pagehide view can be pre-sync.
 *
 * The recorder launches its flushes fire-and-forget on the injected scope, so the tests drive a
 * real single-thread dispatcher and poll the fake transport for the outcome (the DesktopAsyncFlows
 * harness's shape) — no coroutines-test dependency, and a timeout FAILS rather than passing vacuously.
 */
class UsageRecorderCoreTest {

    private val T = 1_755_000_000_000L

    private val executor = Executors.newSingleThreadExecutor { r -> Thread(r, "usage-core-test").apply { isDaemon = true } }
    private val scope = CoroutineScope(executor.asCoroutineDispatcher())

    @AfterTest
    fun cleanup() {
        scope.cancel()
        executor.shutdownNow()
    }

    /** A marker session — the shell only ever passes it back to [transportFor]. */
    private object Session

    /** An in-memory stand-in for the sealed `/usage` blob. "Sealing" is identity (UTF-8) so the
     *  test can read the stored ledger back; put()s are counted so a no-op flush is observable. */
    private class FakeTransport(seed: Map<String, Entry>?) : UsageRecorderCore.Transport {
        @Volatile var blob: String? = seed?.let { UsageLedger.serialize(it) }
        val gets = AtomicInteger(0)
        val puts = AtomicInteger(0)
        override suspend fun fetchSealed(): String? { gets.incrementAndGet(); return blob }
        override fun open(sealed: String): ByteArray = sealed.encodeToByteArray()
        override fun seal(plain: ByteArray): String = plain.decodeToString()
        override suspend fun put(sealed: String) { blob = sealed; puts.incrementAndGet() }
        fun stored(): Map<String, Entry> = blob?.let { UsageLedger.parse(it) } ?: emptyMap()
    }

    private fun recorder(transport: FakeTransport, session: () -> Session? = { Session }) =
        UsageRecorderCore(
            scope = scope,
            debounceMs = 60_000L, // long: the debounce must never fire during a test
            boundedFlushTimeoutMs = 5_000L,
            session = session,
            transportFor = { transport },
        )

    private fun awaitUntil(what: String, timeoutMs: Long = 10_000, cond: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (cond()) return
            Thread.sleep(5)
        }
        fail("timed out after ${timeoutMs}ms waiting for: $what")
    }

    /** (a) G04: a flush AFTER a successful sync prunes the entry of an item that is gone, against
     *  the complete live set the sync produced. */
    @Test
    fun postSyncFlushPrunesADeletedItemsEntry() {
        val transport = FakeTransport(mapOf("alive" to Entry(T, 3), "deleted" to Entry(T, 9)))
        val rec = recorder(transport)

        rec.flushWithPrune(Session, liveItemIds = setOf("alive"))

        awaitUntil("the prune flush to land") { transport.puts.get() >= 1 }
        assertEquals(setOf("alive"), transport.stored().keys, "the gone item's entry is dropped")
        assertEquals(Entry(T, 3), transport.stored()["alive"], "the live item's entry is untouched")
    }

    /** (b) G04: the teardown flush merges but must NEVER prune — an entry for an item this device
     *  has no local knowledge of (another device's, not yet synced here) MUST survive. If the
     *  teardown path pruned against any local view, this entry would be destroyed. */
    @Test
    fun teardownFlushMergesWithoutPruningAForeignEntry() {
        val transport = FakeTransport(mapOf("other-device-item" to Entry(T, 2)))
        val rec = recorder(transport)

        rec.record("local-item", T + 1000) // one buffered use, so the flush actually writes
        rec.flushForSession(Session) // the lock/pagehide path — no liveItemIds, so it cannot prune

        awaitUntil("the teardown flush to land") { transport.stored().containsKey("local-item") }
        assertTrue("other-device-item" in transport.stored().keys, "a pre-sync teardown must not prune a foreign entry")
        assertEquals(Entry(T + 1000, 1), transport.stored()["local-item"], "the buffered use is merged in")
    }

    /** G04 edge: a use buffered in the sub-instant AFTER the caller snapshotted the live set (an
     *  item created/used right as the sync landed) is inherently live and must survive the prune,
     *  even though the snapshot predates it — under-prune, never drop a live entry. */
    @Test
    fun aBufferedUseNotInTheSnapshotIsNotPruned() {
        val transport = FakeTransport(mapOf("alive" to Entry(T, 1)))
        val rec = recorder(transport)

        rec.record("fresh", T + 1000) // used just after the snapshot below was taken
        rec.flushWithPrune(Session, liveItemIds = setOf("alive")) // snapshot excludes "fresh"

        awaitUntil("the prune flush to land") { transport.stored().containsKey("fresh") }
        assertEquals(setOf("alive", "fresh"), transport.stored().keys, "a just-used item survives a stale snapshot")
    }

    /** A quiet post-sync flush that finds nothing deleted and has no buffered uses must NOT write
     *  — batched, never a spurious `updatedAt` bump on every 5-min poll (spec 03 §3). */
    @Test
    fun postSyncFlushWithNothingToDoDoesNotWrite() {
        val transport = FakeTransport(mapOf("alive" to Entry(T, 1)))
        val rec = recorder(transport)

        rec.flushWithPrune(Session, liveItemIds = setOf("alive"))

        // The flush ran (it read the server copy) but, finding nothing to change, chose not to PUT.
        awaitUntil("the prune flush to read the server copy") { transport.gets.get() >= 1 }
        assertEquals(0, transport.puts.get(), "no deletion and no buffered use → no write")
    }
}
