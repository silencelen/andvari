package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.restore.RestoreEvent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the restore's hold of its refusals is for: a take of refusals by the vault's content on another thread (after a
 * save the person makes meanwhile) that falls between the server's refusal of an item in the restore's batch and the
 * restore's own take. Without the hold the content would take the item's refusal and let it go, and the restore would
 * count the item as stored; with it, the item is listed by name as refused.
 */
internal class RestoreHoldTest : RestoreTestKit() {
    @Test
    fun aSaveOnAnotherThreadBetweenTheRefusalAndTheRestoresTakeLeavesTheRefusalToTheRestore() {
        // Three times over: the order is fixed by the test, not by chance.
        repeat(3) { once("hold-$it") }
    }

    private fun once(name: String) {
        val w = world(name)
        val c = assertNotNull(w.m.content.value)
        val f = flow(w, backup(201))
        open(f)
        w.server.rejectFirst = true
        var saved: ActionResult? = null
        var progressAtTheSave: RestoreEvent.Progress? = RestoreEvent.Progress(-1, -1)
        var thread: Thread? = null
        // The sync that ends the restore's import of its first batch (the server refused "A" in it): the person saves a
        // login on another thread. The save waits for the sync's lock and is resumed when the import lets go of it, on
        // the import's own thread, before the import returns to the restore.
        w.server.syncAfterRefusal = {
            val t = kotlin.concurrent.thread(isDaemon = true) {
                runBlocking(Dispatchers.Unconfined) {
                    saved = c.saveLogin(null, LoginInput("Mine", "me", "pw", listOf("https://mine.test"), "", "", false), null)
                    progressAtTheSave = f.views.value.progress
                }
            }
            thread = t
            // The import goes on only once the save waits for the lock (its thread parked), so that the order is fixed.
            val until = System.nanoTime() + 10_000_000_000L
            while (t.isAlive && t.state != Thread.State.WAITING && System.nanoTime() < until) Thread.onSpinWait()
        }
        runBlocking { f.confirm() }
        thread?.join(60_000)
        val end = page(w, f)
        println("HOLD|saved=$saved progressAtTheSave=$progressAtTheSave stage=${f.views.value.stage} refused=${f.views.value.done?.refused?.map { it.name }} end=$end")
        assertEquals(ActionResult.Ok, saved, "the save went through")
        assertEquals(null, progressAtTheSave, "the content's take ran before the restore took its batch's refusals")
        assertEquals(listOf("A"), f.views.value.done?.refused?.map { it.name }, "the refused item is the restore's, by name")
        has(end, ph(Placeholder.RESTORE_REFUSED, "“A”"))
        assertTrue(end.any { it.startsWith("200 items restored") }, "$end")
    }
}
