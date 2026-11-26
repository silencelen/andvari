package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.restore.RestoreStop
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Three of the restore's lines in the words decided on 25 November 2026, each drawn where it is said: the line that
 * names the items the server refused in an earlier restore, the two phrases of a stop's line for items and for an
 * attached file that are not confirmed as stored, and the line over a vault that cannot take a restore. These hold the
 * approved sentences themselves.
 */
internal class RestoreWordsOfTwentyFifthTest : RestoreTestKit() {
    @Test
    fun theItemsRefusedInAnEarlierRestoreAreNamedWithWhatIsTrueOnEveryRoad() {
        val w = world("words-refused-before")
        val bytes = backup(201)
        w.server.rejectFirst = true
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        val again = flow(w, bytes)
        open(again)
        has(page(w, again), "Refused by the server in an earlier restore: “A”. Where their vault can be ticked, the restore tries them again.")
    }

    @Test
    fun aStopOverItemsOrAnAttachedFileSaysTheyAreNotConfirmedAsStoredAndWhatWasSeenFollowsTheColon() {
        val w = world("words-stop")
        val f = flow(w, backup(1))
        fun drawn(stop: RestoreStop) = f.page(RestoreFlow.View(RestoreFlow.Stage.STOPPED, stop = stop)).texts
        has(
            drawn(RestoreStop.BatchRefused(2, "Personal", ItemFailure.Halted)),
            "The restore stopped (these items are not confirmed as stored in the account: Halted). Nothing it stored is undone. Try again continues where it stopped.",
        )
        has(
            drawn(RestoreStop.BatchRefused(2, "Personal", ItemFailure.Refused("server_error", 500))),
            "The restore stopped (these items are not confirmed as stored in the account: server_error). Nothing it stored is undone. Try again continues where it stopped.",
        )
        has(
            drawn(RestoreStop.AttachmentRefused("photo.jpg", ItemFailure.Refused("too_large", 413))),
            "The restore stopped (the attached file “photo.jpg” is not confirmed as stored in the account: too_large). Nothing it stored is undone. Try again continues where it stopped.",
        )
    }

    @Test
    fun aVaultThatCannotTakeARestoreSaysSoInOneLine() {
        val w = world("words-no-vault")
        val f = flow(w, backup(3))
        open(f)
        lock(w)
        runBlocking { f.confirm() }
        has(page(w, f), "This vault cannot take a restore now. When it can, choose the file again.")
        assertEquals(0, w.server.pushes)
    }
}
