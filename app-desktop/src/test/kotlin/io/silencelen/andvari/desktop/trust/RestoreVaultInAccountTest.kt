package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.restore.RestoreStop
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A vault every item of which is in the account and that nothing ended: an item the server refused, sent again, taken
 * by the server with its answer lost. The record still holds it as refused, so no look ends the vault, and its line
 * says that every item of it is in the account and it is not offered again.
 */
internal class RestoreVaultInAccountTest : RestoreTestKit() {
    @Test
    fun aRefusedItemTakenWithItsAnswerLostLeavesAVaultInTheAccountThatNothingEnded() {
        val w = world("in-account")
        val bytes = backup(201, familyItems = 0)
        val f = flow(w, bytes)
        open(f)
        // The first run: "A" (in the first batch) is refused, and the second batch is refused whole, so the run stops
        // before the vault's end.
        w.server.rejectFirst = true
        w.server.beforePush = { n -> if (n == 2) w.server.failNext = 503 }
        runBlocking { f.confirm() }
        w.server.rejectFirst = false
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        // Try again: the run's own sync sends the second batch the stopped run left queued, the run sends it again so that
        // the record holds it, then "A" is sent again and taken, and its answer is lost.
        w.server.beforePush = { n -> if (n == 3) w.server.loseNextAnswer = true }
        runBlocking { f.tryAgain() }
        w.server.beforePush = null
        println("INACCOUNT|stop=${f.views.value.stop} sent=${w.server.sent.map { it.size }} taken=${w.server.taken.size} account=${personalItems(w)}")
        assertIs<RestoreStop.BatchRefused>(f.views.value.stop)
        assertEquals(201, personalItems(w), "every item is in the account")
        // The next page: nothing is left, and nothing ended the vault.
        val g = flow(w, bytes)
        open(g)
        val v = assertNotNull(g.views.value.preview).vaults.first { it.personal }
        assertEquals(0, v.left)
        assertNull(v.restoredAt)
        has(page(w, g), ph(Placeholder.RESTORE_VAULT_IN_ACCOUNT, "Personal vault: 201 items."))
    }
}
