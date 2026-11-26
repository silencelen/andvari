package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Whatever ends a run, the page afterwards does not say it is running (decided on 23 November 2026): its own result, a
 * cancellation (its page leaving the window cancels the page's scope, in which the run lives), or anything thrown out
 * of the restore.
 */
internal class RestoreWaysOutTest : RestoreTestKit() {
    @Test
    fun aRunCancelledAsItsPageLeavesTheWindowIsStoppedAndTryAgainGoesOnFromTheRecord() {
        val w = world("ways-cancel")
        keepOn(w)
        val bytes = backup(401)
        val f = flow(w, bytes)
        open(f)
        var job: Job? = null
        // The page's work scope is cancelled when the page leaves the window: the network call the run waits on ends with
        // a cancellation.
        w.server.beforePush = { n ->
            if (n == 2) {
                job?.cancel()
                throw CancellationException("the page left the window")
            }
        }
        runBlocking {
            val j = launch(Dispatchers.Unconfined, start = CoroutineStart.LAZY) { f.confirm() }
            job = j
            j.join()
        }
        w.server.beforePush = null
        val v = f.views.value
        val lines = page(w, f)
        println("WAYS|cancel|stage=${v.stage} busy=${v.busy} items=${personalItems(w)} drawn=$lines")
        assertEquals(RestoreFlow.Stage.STOPPED, v.stage, "not running: $lines")
        has(lines, ph(Placeholder.RESTORE_INTERRUPTED), "Try again")
        runBlocking { f.tryAgain() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage, "${f.views.value.stop}")
        assertEquals(401, personalItems(w), "every item once")
        assertEquals(1, w.server.uploads.toSet().size, "the attached file once")
    }

    @Test
    fun aRunOutOfWhichALockThrowsIsStoppedAndTryAgainWhileLockedSaysTheVaultCannotTakeARestoreNow() {
        val w = atRest("ways-lock")
        val bytes = backup(401)
        val f = flow(w, bytes)
        open(f)
        val threads = ArrayList<Thread>()
        w.server.beforePush = { n ->
            if (n == 1) threads += kotlin.concurrent.thread(isDaemon = true) { runCatching { w.api.lock() } }.also { it.join(10_000) }
        }
        val thrown = caught { f.confirm() }
        w.server.beforePush = null
        threads.forEach { it.join(60_000) }
        w.m.onSnapshot(w.api.snapshot)
        val lines = page(w, f)
        println("WAYS|lock|thrown=$thrown stage=${f.views.value.stage} busy=${f.views.value.busy} phase=${w.api.snapshot.phase} drawn=$lines")
        assertNotEquals(RestoreFlow.Stage.RUNNING, f.views.value.stage, "not running: $lines")
        assertTrue("Try again" in lines || ph(Placeholder.RESTORE_NO_VAULT) in lines, "$lines")
        runBlocking { f.tryAgain() }
        has(page(w, f), ph(Placeholder.RESTORE_NO_VAULT))
    }
}
