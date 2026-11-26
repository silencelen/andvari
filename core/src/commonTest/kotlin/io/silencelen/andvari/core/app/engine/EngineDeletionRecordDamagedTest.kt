package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.client.CoreLog
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The record of deletions begun with an entry that does not read, or that does not read at all, is written again at the
 * start from the entries that read, those are finished, and a diagnostic line says how many were dropped. Nothing is
 * removed for a dropped entry: an unfinished deletion only keeps more. Before, one such entry held back every deletion's
 * finish and every sweep of the device for good, and every later end left its account's records behind.
 */
class EngineDeletionRecordDamagedTest {
    private val k = SweepSteps(createCryptoProvider())
    private val uuid = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val h = "https://h.example"

    private fun keyLists(w: SweepWorld): List<List<String>> =
        listOf(w.state.inner.keys(), w.secure.inner.keys()).map { keys -> keys.map { it.replace(uuid, "<id>") }.sorted() }

    private class Stop(val w: SweepWorld, val n: Int, val startsAt: (String, String?) -> Boolean, val startsAfter: (String, String?) -> Boolean = { _, _ -> false }) {
        var started = false
        var count = 0
        var at: String? = null

        init {
            val hook: (String, String?) -> Unit = hook@{ key, value ->
                if (at != null) throw IllegalStateException("stopped")
                if (!started) {
                    if (startsAfter(key, value)) {
                        started = true
                        return@hook
                    }
                    if (!startsAt(key, value)) return@hook
                    started = true
                }
                if (count++ == n) {
                    at = key
                    throw IllegalStateException("stopped at $key")
                }
            }
            w.state.beforeSet = hook
            w.secure.beforeSet = hook
        }

        fun end() {
            w.state.beforeSet = null
            w.secure.beforeSet = null
        }
    }

    private fun mark(w: SweepWorld) = w.state.inner.get(EngineAccountSettings.DELETION_KEY)

    /** The engine over [w]'s stores, its diagnostic lines into [lines], started. */
    private fun device(w: SweepWorld, lines: MutableList<Pair<String, String>>): EngineAppApi =
        k.device(w, start = false).also { a ->
            a.diagnostics = CoreLog { event, detail -> lines += event to detail }
            a.start()
        }

    /** alice's deletion at h.example stopped after the keeper's end ([n] writes after its mark), the process closed. */
    private suspend fun stoppedDeletion(n: Int = 4): SweepWorld {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        val stop = Stop(w, n, startsAt = { key, value -> key == SessionKeeper.OWN_ENDS_KEY && value != null },
            startsAfter = { key, value -> key == EngineAccountSettings.DELETION_KEY && value != null })
        runCatching { k.deleteAt(w, w.home) }
        stop.end()
        assertNotNull(stop.at, "the deletion stopped")
        w.app.close()
        return w
    }

    /** The uncut deletion followed by a start: both stores' key lists. */
    private suspend fun uncut(): List<List<String>> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        k.deleteAt(w, w.home)
        k.restart(w)
        assertEquals(emptyMap(), k.byId(w))
        return keyLists(w)
    }

    private fun garbageBeside(text: String) = text.dropLast(1) + ",[\"garbage\"]]"

    @Test fun aReadableDeletionBesideAnEntryThatDoesNotReadIsFinished() = runBlocking<Unit> {
        val expected = uncut()
        val w = stoppedDeletion()
        w.state.inner.set(EngineAccountSettings.DELETION_KEY, garbageBeside(assertNotNull(mark(w))))
        val lines = ArrayList<Pair<String, String>>()
        w.app = device(w, lines)
        assertNull(mark(w), "the readable deletion finished, the entry that does not read dropped")
        assertEquals(emptyMap(), k.byId(w), "nothing kept by the deleted account's id is left")
        assertIs<PinState.None>(w.app.trust.pinState(h), "the deleted account's server is forgotten")
        assertEquals(expected, keyLists(w), "as the uncut deletion")
        val said = lines.filter { it.first == "deletion_record_rewritten" }
        assertEquals(1, said.size, "one diagnostic line: $lines")
        assertTrue("1" in said.single().second, "it says how many were dropped: ${said.single().second}")
    }

    @Test fun aRecordThatDoesNotReadAtAllIsWrittenAgainAsEmptyAndHoldsNothingBack() = runBlocking<Unit> {
        val w = k.world()
        w.app.close()
        w.state.inner.set(EngineAccountSettings.DELETION_KEY, "not a mark")
        val lines = ArrayList<Pair<String, String>>()
        w.app = device(w, lines)
        assertNull(mark(w), "written again as empty")
        assertEquals(1, lines.count { it.first == "deletion_record_rewritten" }, "one diagnostic line: $lines")
        // A later end on that device leaves nothing of its account: "Forget this server" of another account's server.
        w.u = k.register(w.app, "other.example", k.bob)
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        k.restart(w)
        assertEquals(emptyMap(), k.byId(w), "nothing kept by the id of the forgotten server's account")
        assertEquals(emptyList(), k.naming(w))
    }

    /** An entry that names a real account but does not read (a flag in no known form) finishes nothing and removes nothing. */
    @Test fun nothingIsRemovedForADroppedEntry() = runBlocking<Unit> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        k.signOut(w.app)
        w.app.close()
        w.state.inner.set(EngineAccountSettings.DELETION_KEY, """[["$h","${w.u}","${k.alice}","tie:maybe","others:no",""]]""")
        val before = w.state.snapshot() - EngineAccountSettings.DELETION_KEY
        val lines = ArrayList<Pair<String, String>>()
        w.app = device(w, lines)
        assertNull(mark(w), "the entry was dropped")
        assertEquals(1, lines.count { it.first == "deletion_record_rewritten" }, "one diagnostic line: $lines")
        val after = w.state.snapshot()
        assertEquals(before.filterKeys { key -> SWEEP_BY_ID.any { key.startsWith(it) } }, after.filterKeys { key -> SWEEP_BY_ID.any { key.startsWith(it) } }, "nothing kept by an id went")
        assertEquals(w.u, w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + h + "|" + k.alice)?.substringBefore('|'), "the address record stays")
        assertIs<PinState.Pinned>(w.app.trust.pinState(h), "the server stays pinned")
    }

    /**
     * The start over a damaged record beside a deletion stopped part-way, stopped at each of its writes (its rewrite of the
     * record among them), then the next start stopped at each of its writes, then a start: as the uncut deletion.
     */
    @Test fun theStartsRewriteStoppedAtEachOfItsWritesAndTwoStopsInARowEndAsTheUncut() = runBlocking<Unit> {
        val expected = uncut()
        val base = stoppedDeletion()
        base.state.inner.set(EngineAccountSettings.DELETION_KEY, garbageBeside(assertNotNull(mark(base))))
        val state0 = base.state.snapshot()
        val secure0 = base.secure.snapshot()
        fun copy(): SweepWorld = SweepWorld(base.home, base.other, base.wires).also { c ->
            for ((key, value) in state0) c.state.inner.set(key, value)
            for ((key, value) in secure0) c.secure.inner.set(key, value)
            c.u = base.u
        }
        val firstCuts = ArrayList<String>()
        val bad = ArrayList<String>()
        var combos = 0
        var n = 0
        while (n < 120) {
            val probe = copy()
            val stop1 = Stop(probe, n, startsAt = { _, _ -> true })
            runCatching { k.device(probe, start = false).also { runCatching { it.start() } }.close() }
            stop1.end()
            val at1 = stop1.at ?: break
            firstCuts += at1.replace(uuid, "<id>")
            var m = 0
            while (m < 120) {
                val w = copy()
                val s1 = Stop(w, n, startsAt = { _, _ -> true })
                runCatching { k.device(w, start = false).also { runCatching { it.start() } }.close() }
                s1.end()
                val s2 = Stop(w, m, startsAt = { _, _ -> true })
                runCatching { k.device(w, start = false).also { runCatching { it.start() } }.close() }
                s2.end()
                val at2 = s2.at
                w.app = k.device(w)
                combos++
                if (keyLists(w) != expected || k.byId(w).isNotEmpty()) bad += "#$n@${at1.replace(uuid, "<id>")} then #$m@${at2?.replace(uuid, "<id>")}: ${keyLists(w)}"
                if (at2 == null) break
                m++
            }
            n++
        }
        println("DELETION RECORD the start cut at $n writes: $firstCuts; $combos pairs")
        assertTrue(n > 3, "the start's writes were cut ($n)")
        assertEquals(emptyList(), bad.take(10), "${bad.size} of $combos")
    }
}
