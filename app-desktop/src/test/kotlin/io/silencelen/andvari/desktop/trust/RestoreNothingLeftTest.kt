package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * When nothing of the backup can be restored (the owner's words of 23 November 2026): one true line in place of the
 * button, and no line about the items already in the account, in both cases that draw it: every vault of the file is
 * already restored into this account, and the file holds no item at all. Where something can be restored, the button
 * and that line are drawn as before.
 */
internal class RestoreNothingLeftTest : RestoreTestKit() {
    private val nothingLeft = "Nothing in this backup is left to restore into this account."
    private val holds = "This account already holds "

    /** The account of [w] holds one item of its own. */
    private fun ownItem(w: World) {
        val c = assertNotNull(w.m.content.value)
        runBlocking { assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Mine 1", "me", "pw-1", listOf("https://one.test"), "", "", false), null)) }
    }

    private fun personalOnly(names: List<String>) = build(
        BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal, family),
            items = names.map { BackupItem(id(), personal.vaultId, 1, 0, doc(it)) },
        ),
    )

    private fun saysNothingLeft(lines: List<String>) {
        has(lines, nothingLeft)
        assertFalse(lines.any { it.startsWith(holds) }, "no line about the items already in the account: $lines")
        assertFalse(lines.any { it.startsWith("Restore ") && it != "Restore a backup" }, "no restore button: $lines")
    }

    @Test
    fun everyVaultOfTheFileAlreadyRestoredDrawsTheOneLineAndNotTheLineAboutTheAccountsItems() {
        val w = world("nothing-left-restored")
        ownItem(w)
        val bytes = personalOnly(listOf("Only"))
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        val again = flow(w, bytes)
        open(again)
        assertTrue(assertNotNull(again.views.value.preview).accountItemsBeside > 0, "the account holds an item of its own")
        saysNothingLeft(page(w, again))
    }

    @Test
    fun aFileThatHoldsNoItemAtAllDrawsTheOneLineAndNotTheLineAboutTheAccountsItems() {
        val w = world("nothing-left-empty")
        ownItem(w)
        val f = flow(w, personalOnly(emptyList()))
        open(f)
        assertEquals(RestoreFlow.Stage.PREVIEW, f.views.value.stage)
        assertTrue(assertNotNull(f.views.value.preview).accountItemsBeside > 0, "the account holds an item of its own")
        saysNothingLeft(page(w, f))
    }

    @Test
    fun whereSomethingCanBeRestoredTheButtonAndTheLineAboutTheAccountsItemsAreDrawnAsBefore() {
        val w = world("nothing-left-ordinary")
        ownItem(w)
        val f = flow(w, personalOnly(listOf("One", "Two")))
        open(f)
        val lines = page(w, f)
        has(lines, ph(Placeholder.RESTORE_ACCOUNT_HOLDS_ONE, "1"), "Restore 2 items")
        assertFalse(nothingLeft in lines, "$lines")
        assertFalse(ph(Placeholder.RESTORE_NOTHING_LEFT) in lines, "$lines")
    }
}
