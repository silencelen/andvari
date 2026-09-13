package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.UsageLedger.Entry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
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
 * The G03 mechanism itself — the teardown flush COMPLETING before the transport is closed — is the
 * third load-bearing pin (audit H88): [UsageRecorderCore.flushForSession] hands `then` (the
 * desktop's `a.close()`, the phone's `api.close()`) to the flush coroutine, and the test asserts
 * `then` observed the landed PUT. A regression that reorders `then()` ahead of the store — the
 * original G03 bug, close cancels the GET+PUT — fails here and nowhere else.
 *
 * H05 (spec 02 §8.2's MUST): a server copy this client could not FETCH or OPEN is left untouched —
 * no PUT, buffer retained — and only a genuinely absent blob is written without a merge.
 *
 * The recorder launches its flushes fire-and-forget on the injected scope, so the tests drive a
 * real single-thread dispatcher — no coroutines-test dependency. The launched flushes return their
 * Job, so a pin that needs "the flush has ENDED" joins it rather than sampling the transport at an
 * instant the code happens to win by default (H88's vacuous no-write assertion); the debounced
 * `flush()` is a plain suspend call and runs to completion under runBlocking.
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
        /** H05 knobs: the GET fails (offline / 5xx / 401), or the blob is present but will not
         *  open (wrong key, AD mismatch, a future encoding). */
        @Volatile var failFetch = false
        @Volatile var failOpen = false
        /** H88 knob: a PUT that outlives the teardown bound. */
        @Volatile var putDelayMs = 0L
        override suspend fun fetchSealed(): String? {
            gets.incrementAndGet()
            if (failFetch) throw IllegalStateException("GET /usage failed")
            return blob
        }
        override fun open(sealed: String): ByteArray {
            if (failOpen) throw IllegalStateException("AEAD open failed")
            return sealed.encodeToByteArray()
        }
        override fun seal(plain: ByteArray): String = plain.decodeToString()
        override suspend fun put(sealed: String) {
            if (putDelayMs > 0) delay(putDelayMs)
            blob = sealed
            puts.incrementAndGet()
        }
        fun stored(): Map<String, Entry> = blob?.let { UsageLedger.parse(it) } ?: emptyMap()
    }

    private fun recorder(transport: FakeTransport, session: () -> Session? = { Session }, boundMs: Long = 5_000L) =
        UsageRecorderCore(
            scope = scope,
            debounceMs = 60_000L, // long: the debounce must never fire during a test
            boundedFlushTimeoutMs = boundMs,
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
        // G03 (audit H88): `then` is the caller's transport close — the desktop's `a.close()`, the
        // phone's `api.close()`. It must run AFTER the bounded store, or the close cancels the very
        // GET+PUT this path exists to land. Recording how many PUTs had landed when it ran is the
        // ordering assertion; a reorder that fires `then()` first records 0 here.
        val putsWhenClosed = AtomicInteger(-1)
        val job = rec.flushForSession(Session) { putsWhenClosed.set(transport.puts.get()) } // the lock path — no liveItemIds, so it cannot prune
        runBlocking { job.join() }

        assertEquals(1, putsWhenClosed.get(), "the transport close (`then`) must observe the landed PUT — it ran before the store")
        assertTrue("other-device-item" in transport.stored().keys, "a pre-sync teardown must not prune a foreign entry")
        assertEquals(Entry(T + 1000, 1), transport.stored()["local-item"], "the buffered use is merged in")
    }

    /** G03's other half (audit H88): the bound. A store that outlives [boundedFlushTimeoutMs] is
     *  abandoned and `then` STILL runs — a ranking hint can never hold the transport open or delay
     *  the lock past the bound. The buffer is not resurrected: the session accessor reads null
     *  (the caller has torn down), so the session-gated re-arm stays quiet. */
    @Test
    fun teardownThenRunsEvenWhenTheStoreOutlivesTheBound() {
        val transport = FakeTransport(mapOf("other-device-item" to Entry(T, 2))).apply { putDelayMs = 60_000L }
        var live: Session? = Session
        val rec = recorder(transport, session = { live }, boundMs = 200L)

        rec.record("local-item", T + 1000)
        live = null // the lock has dropped the session; only the explicit one below is in hand
        val thenRan = AtomicInteger(0)
        val job = rec.flushForSession(Session) { thenRan.incrementAndGet() }
        runBlocking { job.join() }

        assertEquals(1, thenRan.get(), "`then` must run whether or not the flush landed")
        assertEquals(0, transport.puts.get(), "the PUT was abandoned at the bound")
        assertTrue(rec.peek().isEmpty(), "no session stands, so nothing is re-armed into a locked process")
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

        val job = rec.flushWithPrune(Session, liveItemIds = setOf("alive"))
        // Join the flush rather than sample at "the GET was observed" (audit H88): at that instant
        // the coroutine is still deciding whether to PUT, so a regression that writes
        // unconditionally would usually still read 0 here and pass.
        runBlocking { job.join() }

        assertEquals(1, transport.gets.get(), "the flush ran — it read the server copy")
        assertEquals(0, transport.puts.get(), "no deletion and no buffered use → no write")
    }

    // ---- H05: spec 02 §8.2 — "a client that cannot open the ledger MUST leave it untouched" ----

    /** A GET that fails (offline, 5xx, a token racing a lock) is NOT an empty ledger. Writing the
     *  buffer over it would replace the household's whole ledger with this session's few uses —
     *  the endpoint is last-writer-wins with no server-side merge. No PUT; the uses stay buffered
     *  for the next round. */
    @Test
    fun aFetchFailureLeavesTheServerLedgerUntouchedAndKeepsTheBuffer() {
        val transport = FakeTransport(mapOf("other-device-item" to Entry(T, 2))).apply { failFetch = true }
        val before = transport.blob
        val rec = recorder(transport)

        rec.record("local-item", T + 1000)
        runBlocking { rec.flush() }

        assertEquals(0, transport.puts.get(), "a copy we could not read must not be overwritten")
        assertEquals(before, transport.blob)
        assertEquals(setOf("local-item"), rec.peek().keys, "the session's uses are re-armed, not dropped")
    }

    /** The case the spec sentence was written for: a blob is THERE but will not open under our
     *  key (another key, a future encoding). Same rule, same outcome. */
    @Test
    fun anUnopenableServerLedgerIsLeftUntouchedAndTheBufferKept() {
        val transport = FakeTransport(mapOf("other-device-item" to Entry(T, 2))).apply { failOpen = true }
        val before = transport.blob
        val rec = recorder(transport)

        rec.record("local-item", T + 1000)
        runBlocking { rec.flush() }

        assertEquals(0, transport.puts.get())
        assertEquals(before, transport.blob)
        assertEquals(setOf("local-item"), rec.peek().keys)
    }

    /** …and the prune path degrades the same way: a prune request against a server copy we could
     *  not read writes nothing (it cannot know what it would be dropping). */
    @Test
    fun aPruneAgainstAnUnreadableServerLedgerWritesNothing() {
        val transport = FakeTransport(mapOf("alive" to Entry(T, 3), "deleted" to Entry(T, 9))).apply { failFetch = true }
        val rec = recorder(transport)

        // R41: WITH a buffered use — an empty buffer made this pin vacuous (no shape of the
        // Unreadable branch PUTs nothing over nothing). Pre-fix, or with Unreadable flipped to
        // Present(empty), this round PUTs {local} over the household's {alive, deleted}.
        rec.record("local", T + 1000)
        val job = rec.flushWithPrune(Session, liveItemIds = setOf("alive"))
        runBlocking { job.join() }

        assertEquals(1, transport.gets.get(), "the round did reach the server")
        assertEquals(0, transport.puts.get())
        assertEquals(setOf("alive", "deleted"), transport.stored().keys, "untouched — the prune is retried next sync")
        assertEquals(setOf("local"), rec.peek().keys, "the buffered use is re-armed for the next round, not dropped")
    }

    /** The one merge-less write that is a FIRST write: the GET succeeded and said there is no
     *  ledger yet (`sealedUsage: null`). */
    @Test
    fun aMissingLedgerIsCreatedFromTheBuffer() {
        val transport = FakeTransport(seed = null)
        val rec = recorder(transport)

        rec.record("local-item", T + 1000)
        runBlocking { rec.flush() }

        assertEquals(1, transport.puts.get())
        assertEquals(mapOf("local-item" to Entry(T + 1000, 1)), transport.stored())
        assertTrue(rec.peek().isEmpty(), "landed — nothing left buffered")
    }

    /** The teardown flush obeys the same rule: on the lock path a GET that fails must not turn
     *  into an overwrite either, and `then` still runs. */
    @Test
    fun aTeardownFlushOverAnUnreadableLedgerDoesNotWrite() {
        val transport = FakeTransport(mapOf("other-device-item" to Entry(T, 2))).apply { failFetch = true }
        val before = transport.blob
        // R40: live-then-dropped (the teardownThenRuns… shape). With `session = { null }` from
        // the start, record() is a no-op, the buffer stays empty, store() is never entered and
        // the pin was vacuous — flipping Unreadable to Present(empty) stayed green.
        var live: Session? = Session
        val rec = recorder(transport, session = { live })

        rec.record("local-item", T + 1000) // recorded while live…
        live = null // …then the lock dropped the session; only the explicit one below is in hand
        val thenRan = AtomicInteger(0)
        val job = rec.flushForSession(Session) { thenRan.incrementAndGet() }
        runBlocking { job.join() }

        assertEquals(1, transport.gets.get(), "the teardown flush did reach the server")
        assertEquals(0, transport.puts.get())
        assertEquals(before, transport.blob)
        assertEquals(1, thenRan.get())
        assertNull(rec.peek()["local-item"], "no session stands after teardown, so the miss is not re-armed")
    }
}
