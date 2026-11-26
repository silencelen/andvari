package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The restore's page goes by one rule, the shared restore's (decided on 23 November 2026): a vault has a tick box exactly
 * when something of it is left to store, the button runs what the page showed or nothing, and the screen is handed
 * nothing to decide with. Each sequence is driven on the drawn page: its boxes and its button found and pressed there.
 */
internal class RestorePageRulesTest : RestoreTestKit() {
    @Test
    fun afterARunThatEndedWithARefusedItemTheVaultHasABoxAndUntickedNothingOfItIsSent() {
        val w = world("rules-refused")
        val bytes = backup(201)
        w.server.rejectFirst = true
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        w.server.rejectFirst = false
        val again = flow(w, bytes)
        open(again)
        val p = assertNotNull(again.views.value.preview)
        val personalLine = RestoreFlow.vaultLine(p.vaults.first { it.personal }).shown()
        val familyLine = RestoreFlow.vaultLine(p.vaults.first { !it.personal }).shown()
        val sent = w.server.sent.size
        onScreen(w, again) { d ->
            println("RULES|refused page=${d.lines()} personal=${d.ticked(personalLine)} family=${d.ticked(familyLine)}")
            // The refused item is left: the personal vault can be chosen, and is ticked as the personal vault is.
            assertEquals(true, d.ticked(personalLine), "the personal vault's line is in a ticked box")
            assertTrue(d.press(personalLine))
            assertEquals(false, d.ticked(personalLine))
            assertTrue(d.press(familyLine))
            assertEquals(true, d.ticked(familyLine))
            assertTrue(d.press(RestoreFlow.confirmLine(2).shown()), "the button names the two items of Family: ${d.lines()}")
            until { again.views.value.stage != RestoreFlow.Stage.RUNNING && !again.views.value.busy }
        }
        assertEquals(sent, w.server.sent.size, "nothing of the personal vault is sent while it is unticked")
    }

    @Test
    fun afterTheAnswerToTheLastBatchWasLostTheVaultHasNoBoxAndPressingItsLineChangesNothing() {
        val w = world("rules-unheard")
        val bytes = backup(201, familyItems = 0)
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        val again = flow(w, bytes)
        open(again)
        val p = assertNotNull(again.views.value.preview)
        val line = RestoreFlow.vaultLine(p.vaults.first { it.personal }).shown()
        onScreen(w, again) { d ->
            val before = d.lines()
            println("RULES|unheard page=$before box=${d.ticked(line)}")
            assertEquals(null, d.ticked(line), "nothing of the vault is left: no box")
            d.press(line)
            assertEquals(before, d.lines())
        }
    }

    @Test
    fun aSyncBetweenThePreviewAndThePressSendsNothingAndTheButtonNeverNamesWhatTheRunDidNotStore() {
        val w = world("rules-sync-between")
        keepOn(w)
        val bytes = backup(450, familyItems = 0)
        stopAfter(w, bytes, taken = 2)
        // The preview's own sync cannot send the batch the stopped run left queued: the page names its 50 items.
        w.server.failNext = 503
        val f = flow(w, bytes)
        open(f)
        w.server.failNext = null
        val button = RestoreFlow.confirmLine(50).shown()
        has(page(w, f), button)
        // A sync while the page is shown ("Sync now", the bell) sends them.
        runBlocking { w.m.content.value?.syncQuietly() }
        assertEquals(450, personalItems(w))
        val pushes = w.server.pushes
        onScreen(w, f) { d ->
            assertTrue(d.press(button))
            until { !f.views.value.busy }
            println("RULES|sync between: stage=${f.views.value.stage} page=${d.lines()} pushes=${w.server.pushes - pushes}")
        }
        assertEquals(pushes, w.server.pushes, "nothing was sent")
        assertEquals(RestoreFlow.Stage.PREVIEW, f.views.value.stage, "the page is made again from what is left now")
        // Added once the rule was built: the draft line says so, and the page shows that nothing is left.
        val again = page(w, f)
        has(again, ph(Placeholder.RESTORE_CHANGED), ph(Placeholder.RESTORE_NOTHING_LEFT))
        assertTrue(again.none { it.startsWith("Restoring") || it.endsWith("restored into 1 vault.") }, "$again")
    }

    @Test
    fun aVaultOfTheFileWithNoItemHasNoBoxAndNothingIsMadeForIt() {
        val w = world("rules-empty-vault")
        val f = flow(w, backup(1, familyItems = 0))
        open(f)
        val p = assertNotNull(f.views.value.preview)
        val emptyLine = RestoreFlow.vaultLine(p.vaults.first { !it.personal }).shown()
        // What a tick of it does on the page as it stands (the evidence asked for before the rule changes).
        f.choose(family.vaultId, true)
        val ticked = family.vaultId in f.views.value.chosen
        val lines = page(w, f)
        runBlocking { f.confirm() }
        println("RULES|empty vault: line='$emptyLine' chosenAfterTick=$ticked page=$lines then stage=${f.views.value.stage} stop=${f.views.value.stop} end=${f.views.value.done?.let { "${it.stored}/${it.vaults}" }}")
        val again = flow(w, backup(1, familyItems = 0))
        open(again)
        val line = RestoreFlow.vaultLine(assertNotNull(again.views.value.preview).vaults.first { !it.personal }).shown()
        onScreen(w, again) { d ->
            val before = d.lines()
            assertEquals(null, d.ticked(line), "a vault with no item has no box: $before")
            d.press(line)
            assertEquals(before, d.lines())
        }
        assertFalse(ticked, "a tick of a vault with no item chooses nothing")
    }

    @Test
    fun theScreenIsHandedNothingToDecideWith() {
        val source = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/RestoreScreens.kt").readText()
        val code = source.lines().filterNot { it.trimStart().startsWith("*") || it.trimStart().startsWith("/*") || it.trimStart().startsWith("//") }.joinToString("\n")
        for (word in listOf("core.client.restore", "RestoreFlow.", "offered", "restoredAt", ".left", ".stage", ".stop", ".done", "chosen", "unfinishedRestore", "ExportCopy", "safeName")) {
            assertFalse(word in code, "RestoreScreens.kt holds \"$word\"")
        }
    }
}
