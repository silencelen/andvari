package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.restore.RestoreLeftOut
import io.silencelen.andvari.core.client.restore.RestorePreview
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.client.restore.RestoreVaultLine
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A vault's line inside a longer line, and the ends of a restore that stored nothing or stored into several vaults
 * (decided on 23 November 2026): a vault's line ends with a full stop before the sentence that follows it; a vault found
 * complete says its whole line and that this computer saw it finished; a shared vault whose restore started here and
 * stored nothing says so and stays unticked; a run left with nothing to store says that, not "0 items".
 */
internal class RestoreJoinedLinesTest : RestoreTestKit() {
    private val at = 1_794_500_000_000L
    private val familyLine = "Family: 2 items. You owned it."
    private val workLine = "Work: 2 items. You were a member."

    private fun line(personal: Boolean, items: Int, restoredAt: Long? = null, left: Int = items, started: Boolean = false, member: Boolean = false) =
        if (personal) RestoreVaultLine(this.personal.vaultId, "Personal", "personal", true, "owner", true, items, restoredAt, left, started = started)
        else if (member) RestoreVaultLine("33333333-3333-4333-8333-333333333332", "Work", "shared", false, "writer", false, items, restoredAt, left, started = started)
        else RestoreVaultLine(family.vaultId, "Family", "shared", false, "owner", true, items, restoredAt, left, started = started)

    /** The page drawn from a preview holding [vaults]: the state of each vault given as the shared restore gives it. */
    private fun drawnWith(f: RestoreFlow, vararg vaults: RestoreVaultLine): List<String> = f.page(
        RestoreFlow.View(
            RestoreFlow.Stage.PREVIEW,
            preview = RestorePreview(1_794_484_800_000L, "https://vault.example.org", vaults.toList(), 0, 0L, emptyList(), emptyList(), 0, 0, emptyList(), RestoreLeftOut(), accountItemsBeside = 0),
        ),
    ).texts

    @Test
    fun aVaultsLineInsideALongerLineEndsWithOneFullStop() {
        val w = world("joined-stop")
        val f = flow(w, backup(1))
        // Personal: its line has no full stop, so one is added. Shared: its line ends with one, so none is added.
        has(drawnWith(f, line(true, 201, left = 1), line(false, 2, left = 1)), ph(Placeholder.RESTORE_VAULT_LEFT, "Personal vault: 201 items.", "1"), ph(Placeholder.RESTORE_VAULT_LEFT, familyLine, "1"))
        val day = RestoreFlow.dayText(at)
        has(drawnWith(f, line(true, 201, at, left = 0), line(false, 2, at, left = 0)), ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.", day), ph(Placeholder.RESTORE_RESTORED_AT, familyLine, day))
        has(drawnWith(f, line(true, 201, left = 0), line(false, 2, left = 0)), ph(Placeholder.RESTORE_VAULT_IN_ACCOUNT, "Personal vault: 201 items."), ph(Placeholder.RESTORE_VAULT_IN_ACCOUNT, familyLine))
        // A shared vault started here that stored nothing (the personal vault never draws this line).
        has(drawnWith(f, line(true, 201), line(false, 2, started = true), line(false, 2, started = true, member = true)), "Personal vault: 201 items", ph(Placeholder.RESTORE_VAULT_STARTED, familyLine), ph(Placeholder.RESTORE_VAULT_STARTED, workLine))
        // Alone, each line reads as approved.
        has(drawnWith(f, line(true, 201), line(false, 2)), "Personal vault: 201 items", familyLine)
    }

    @Test
    fun aVaultRestoredByARunSaysItsWholeLineAndTheDayThisComputerSawItFinished() {
        val w = world("joined-after-run")
        val bytes = backup(3, familyItems = 0)
        val first = flow(w, bytes)
        open(first)
        runBlocking { first.confirm() }
        val f = flow(w, bytes)
        open(f)
        val restoredAt = assertNotNull(assertNotNull(f.views.value.preview).vaults.first { it.personal }.restoredAt)
        has(page(w, f), ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 3 items.", RestoreFlow.dayText(restoredAt)))
    }

    @Test
    fun aVaultFoundCompleteByALookSaysItsWholeLineAndTheDayThisComputerSawItFinished() {
        val w = world("joined-after-look")
        val bytes = backup(201, familyItems = 0)
        val first = flow(w, bytes)
        open(first)
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { first.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, first.views.value.stage)
        // The next preview's look finds every item in the account and ends the vault.
        val f = flow(w, bytes)
        open(f)
        val restoredAt = assertNotNull(assertNotNull(f.views.value.preview).vaults.first { it.personal }.restoredAt)
        has(page(w, f), ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.", RestoreFlow.dayText(restoredAt)))
    }

    @Test
    fun aSharedVaultTickedWithThePersonalVaultThatStoppedBeforeStoringSaysItsRestoreStartedAndStaysUnticked() {
        val w = world("joined-started-both")
        val bytes = backup(3, familyItems = 2)
        val f = flow(w, bytes)
        open(f)
        f.choose(family.vaultId, true)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage, "the kit's server leaves a new shared vault unconfirmed")
        val g = flow(w, bytes)
        open(g)
        val started = ph(Placeholder.RESTORE_VAULT_STARTED, familyLine)
        onScreen(w, g) { d ->
            has(d.lines(), started)
            assertEquals(false, d.ticked(started), "not ticked")
        }
        assertEquals(emptySet(), g.views.value.chosen)
    }

    @Test
    fun aSharedVaultTickedAloneThatStoppedBeforeStoringSaysItsRestoreStartedAndStaysUnticked() {
        val w = world("joined-started-alone")
        val bytes = backup(3, familyItems = 2)
        val f = flow(w, bytes)
        open(f)
        f.choose(personal.vaultId, false)
        f.choose(family.vaultId, true)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        assertEquals(0, personalItems(w))
        val g = flow(w, bytes)
        open(g)
        val started = ph(Placeholder.RESTORE_VAULT_STARTED, familyLine)
        onScreen(w, g) { d ->
            has(d.lines(), started, "Personal vault: 3 items")
            assertEquals(false, d.ticked(started), "not ticked")
            assertEquals(true, d.ticked("Personal vault: 3 items"))
        }
    }

    @Test
    fun tryAgainWithNothingLeftAfterASyncSaysNothingWasLeftAndSendsNothing() {
        val w = world("joined-nothing-left")
        val bytes = backup(201, familyItems = 0)
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        runBlocking { w.m.content.value?.syncQuietly() }
        val pushes = w.server.pushes
        runBlocking { f.tryAgain() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        assertEquals(0, assertNotNull(f.views.value.done).vaults)
        assertEquals(pushes, w.server.pushes, "nothing was sent")
        val end = page(w, f)
        has(end, ph(Placeholder.RESTORE_DONE_NOTHING_LEFT))
        assertTrue(end.none { it.contains("restored into") }, "$end")
        assertEquals(201, personalItems(w))
    }

    @Test
    fun anEndOverTwoVaultsSaysTheItemsAndTheVaults() {
        // The kit's server confirms no new shared vault, so a run over two vaults is given as its end.
        val w = world("joined-two-vaults")
        val f = flow(w, backup(1))
        val end = f.page(RestoreFlow.View(RestoreFlow.Stage.ENDED, done = RestoreResult.Done(5, 2, emptyList(), 0, 0, RestoreLeftOut()))).texts
        has(end, ph(Placeholder.RESTORE_DONE_VAULTS, "5", "2"))
    }
}
