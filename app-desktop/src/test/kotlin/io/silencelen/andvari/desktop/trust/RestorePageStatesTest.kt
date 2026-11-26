package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.BackupRestoreApi
import io.silencelen.andvari.core.client.restore.BackupRestore
import io.silencelen.andvari.core.client.restore.RefusedItem
import io.silencelen.andvari.core.client.restore.RestoreChoice
import io.silencelen.andvari.core.client.restore.RestoreEvent
import io.silencelen.andvari.core.client.restore.RestoreFile
import io.silencelen.andvari.core.client.restore.RestoreLeftOut
import io.silencelen.andvari.core.client.restore.RestoreOpening
import io.silencelen.andvari.core.client.restore.RestorePreview
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.client.restore.RestoreVaultLine
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Each state of the restore's page at two levels (decided on 23 November 2026): (a) over the real flow, the real shared
 * restore and the kit's server, the page [RestoreFlow.page] makes asserted whole; (b) the same page drawn by the real
 * composable, each box and the button found on the drawn screen and pressed there, a vault's line without a box pressed
 * too, and the next page asserted.
 */
internal class RestorePageStatesTest : RestoreTestKit() {
    /** The page's rows as text: a box as "[x] " or "[ ] ", a button as "<…>" (with " (off)" when it cannot be pressed). */
    private fun rows(f: RestoreFlow): List<String> = f.page().rows.map { r ->
        when (r) {
            is RestoreRow.Line -> when (r.tone) {
                RestoreRow.Tone.PLAIN -> r.text.shown()
                RestoreRow.Tone.SMALL -> "small|" + r.text.shown()
                RestoreRow.Tone.ERROR -> "error|" + r.text.shown()
            }
            is RestoreRow.Box -> (if (r.ticked) "[x] " else "[ ] ") + r.text.shown() + if (r.enabled) "" else " (off)"
            is RestoreRow.Button -> "<" + r.text.shown() + ">" + if (r.enabled) "" else " (off)"
            is RestoreRow.Passphrase -> "passphrase|" + r.label.shown()
        }
    }

    private fun button(n: Int, on: Boolean = true) = "<" + RestoreFlow.confirmLine(n).shown() + ">" + if (on) "" else " (off)"

    private val made = "Made on 12 November 2026 from vault.example.org."
    private val files = "Attached files: 1 (69 KB)."
    private val notInBackup get() = ph(Placeholder.RESTORE_NOT_IN_BACKUP)
    private val oneComputer get() = ph(Placeholder.RESTORE_ONE_COMPUTER)
    private val memory get() = ph(Placeholder.RESTORE_MEMORY_ONLY)
    private val emptyFamily = "Family: 0 items. You owned it."

    private fun day(f: RestoreFlow, personal: Boolean = true) = RestoreFlow.dayText(assertNotNull(assertNotNull(f.views.value.preview).vaults.first { it.personal == personal }.restoredAt))

    private fun ran(f: RestoreFlow) = until { !f.views.value.busy && f.views.value.stage != RestoreFlow.Stage.RUNNING }

    @Test
    fun noRecordYetThePersonalVaultTickedAndASharedVaultNot() {
        val w = world("states-none")
        val f = flow(w, backup(401))
        open(f)
        assertEquals(
            listOf("small|family.andvari", made, "[x] Personal vault: 401 items", "[ ] Family: 2 items. You owned it.", files, notInBackup, oneComputer, memory, button(401)),
            rows(f),
        )
        onScreen(w, f) { d ->
            assertTrue(d.press("Personal vault: 401 items"))
            assertEquals(button(0, on = false), rows(f).last())
            assertEquals(true, d.disabled(RestoreFlow.confirmLine(0).shown()))
            assertTrue(d.press("Family: 2 items. You owned it."))
            assertEquals(button(2), rows(f).last())
            assertTrue(d.press("Personal vault: 401 items"))
            assertEquals(listOf("[x] Personal vault: 401 items", "[x] Family: 2 items. You owned it.", button(403)), rows(f).filter { it.startsWith("[") || it.startsWith("<") })
            assertTrue(d.press("Family: 2 items. You owned it."))
            assertTrue(d.press(RestoreFlow.confirmLine(401).shown()))
            ran(f)
            assertEquals(listOf("small|family.andvari", "401 items restored into 1 vault.", "1 attached file restored."), rows(f))
            has(d.lines(), "401 items restored into 1 vault.", "1 attached file restored.")
        }
        assertEquals(401, personalItems(w))
    }

    @Test
    fun aRunThatStoppedInTheMiddleOfAVault() {
        val w = world("states-middle")
        keepOn(w)
        val bytes = backup(401, familyItems = 0)
        stopAfter(w, bytes, taken = 1)
        val f = flow(w, bytes)
        open(f)
        val left = ph(Placeholder.RESTORE_VAULT_LEFT, "Personal vault: 401 items.", "1")
        assertEquals(listOf("small|family.andvari", made, "[x] $left", emptyFamily, files, notInBackup, oneComputer, button(1)), rows(f))
        onScreen(w, f) { d ->
            val before = rows(f)
            d.press(emptyFamily)
            assertEquals(before, rows(f), "a line without a box: nothing changes")
            assertTrue(d.press(left))
            assertEquals(button(0, on = false), rows(f).last())
            assertTrue(d.press(left))
            assertTrue(d.press(RestoreFlow.confirmLine(1).shown()))
            ran(f)
            assertEquals(listOf("small|family.andvari", ph(Placeholder.RESTORE_DONE_ONE, "1", "1")), rows(f))
        }
        assertEquals(401, personalItems(w))
    }

    @Test
    fun aRunThatEndedWithAnItemTheServerRefusedInThePersonalVault() {
        val w = world("states-refused")
        val bytes = backup(201)
        w.server.rejectFirst = true
        val first = flow(w, bytes)
        open(first)
        runBlocking { first.confirm() }
        w.server.rejectFirst = false
        val f = flow(w, bytes)
        open(f)
        val left = ph(Placeholder.RESTORE_VAULT_LEFT, "Personal vault: 201 items.", "1")
        assertEquals(
            listOf("small|family.andvari", made, "[x] $left", "[ ] Family: 2 items. You owned it.", files, notInBackup, ph(Placeholder.RESTORE_REFUSED_BEFORE, "“A”"), oneComputer, memory, button(1)),
            rows(f),
        )
        onScreen(w, f) { d ->
            assertTrue(d.press(left))
            assertTrue(d.press(left))
            assertTrue(d.press(RestoreFlow.confirmLine(1).shown()))
            ran(f)
            assertEquals(listOf("small|family.andvari", ph(Placeholder.RESTORE_DONE_ONE, "1", "1"), "1 attached file restored."), rows(f))
        }
        assertEquals(201, personalItems(w))
    }

    @Test
    fun aRunThatEndedWithAnItemTheServerRefusedInASharedVault() {
        // The kit's server does not make shared vaults, so this state's description is given as the shared restore
        // would give it (Family restored, one of its items refused); the page and its presses are the real ones.
        val w = world("states-shared-refused")
        val bytes = backup(3)
        val file = assertIs<RestoreOpening.Opened>(BackupRestore.open(crypto, pass, bytes)).file
        val description = RestorePreview(
            1_794_484_800_000L, "https://vault.example.org",
            listOf(
                RestoreVaultLine(personal.vaultId, "Personal", "personal", true, "owner", true, 3, 1_794_500_000_000L, left = 0),
                RestoreVaultLine(family.vaultId, "Family", "shared", false, "owner", true, 2, 1_794_500_000_000L, left = 1),
            ),
            0, 0L, emptyList(), emptyList(), 0, 5, listOf(RefusedItem("x", "Family 1", family.vaultId, "item_too_large")), RestoreLeftOut(), accountItemsBeside = 0,
        )
        val asked = ArrayList<Map<String, Int>>()
        val api = object : BackupRestoreApi {
            override suspend fun open(passphrase: CharArray, bytes: ByteArray): RestoreOpening = RestoreOpening.Opened(file).also { passphrase.fill('0') }
            override suspend fun preview(file: RestoreFile): RestorePreview = description
            override suspend fun restore(file: RestoreFile, choice: RestoreChoice, events: (RestoreEvent) -> Unit): RestoreResult {
                asked += choice.left
                return RestoreResult.Done(1, 1, emptyList(), 0, 0, RestoreLeftOut())
            }
            override suspend fun restoreAgain(file: RestoreFile, vaults: Set<String>, events: (RestoreEvent) -> Unit): RestoreResult? = null
            override fun recordInMemoryOnly(): Boolean = false
            override fun unfinishedRestore(): Boolean = true
        }
        val f = RestoreFlow(api, assertNotNull(w.m.content.value), "family.andvari", bytes)
        runBlocking { f.open(pass.toCharArray()) }
        val restored = ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 3 items.", RestoreFlow.dayText(1_794_500_000_000L))
        val left = ph(Placeholder.RESTORE_VAULT_LEFT, "Family: 2 items. You owned it.", "1")
        assertEquals(
            listOf("small|family.andvari", made, restored, "[ ] $left", notInBackup, ph(Placeholder.RESTORE_REFUSED_BEFORE, "“Family 1”"), oneComputer, button(0, on = false)),
            rows(f),
        )
        onScreen(w, f) { d ->
            val before = rows(f)
            d.press(restored)
            assertEquals(before, rows(f))
            assertTrue(d.press(left), "the shared vault's refused item can be tried again: its line is in a box")
            assertEquals(button(1), rows(f).last())
            assertTrue(d.press(RestoreFlow.confirmLine(1).shown()))
            ran(f)
        }
        assertEquals(listOf(mapOf(family.vaultId to 1)), asked, "the run was asked for what the page showed")
    }

    @Test
    fun aRunThatEndedWholeWhileASharedVaultWasLeftUnticked() {
        val w = world("states-shared-left")
        val bytes = backup(3, familyItems = 2)
        val first = flow(w, bytes)
        open(first)
        runBlocking { first.confirm() }
        val f = flow(w, bytes)
        open(f)
        val restored = ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 3 items.", day(f))
        assertEquals(listOf("small|family.andvari", made, restored, "[ ] Family: 2 items. You owned it.", files, notInBackup, oneComputer, memory, button(0, on = false)), rows(f))
        onScreen(w, f) { d ->
            val before = rows(f)
            d.press(restored)
            assertEquals(before, rows(f), "a vault with nothing left: no box, and its line does nothing")
            assertTrue(d.press("Family: 2 items. You owned it."))
            assertEquals(button(2), rows(f).last())
            assertEquals(false, d.disabled(RestoreFlow.confirmLine(2).shown()))
        }
    }

    @Test
    fun aVaultWhoseLastAnswerWasLostAndAVaultOfTheFileWithNoItem() {
        val w = world("states-unheard")
        val bytes = backup(201, familyItems = 0)
        val first = flow(w, bytes)
        open(first)
        w.server.beforePush = { n -> if (n == 2) w.server.loseNextAnswer = true }
        runBlocking { first.confirm() }
        w.server.beforePush = null
        assertEquals(RestoreFlow.Stage.STOPPED, first.views.value.stage)
        val f = flow(w, bytes)
        open(f)
        val restored = ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 201 items.", day(f))
        assertEquals(listOf("small|family.andvari", made, restored, emptyFamily, files, notInBackup, oneComputer, memory, ph(Placeholder.RESTORE_NOTHING_LEFT)), rows(f))
        onScreen(w, f) { d ->
            val before = rows(f)
            d.press(restored)
            d.press(emptyFamily)
            assertEquals(before, rows(f))
            assertEquals(null, d.ticked(emptyFamily))
        }
    }

    @Test
    fun everythingRestored() {
        val w = world("states-all")
        val bytes = backup(3, familyItems = 0)
        val first = flow(w, bytes)
        open(first)
        runBlocking { first.confirm() }
        val f = flow(w, bytes)
        open(f)
        val restored = ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 3 items.", day(f))
        assertEquals(listOf("small|family.andvari", made, restored, emptyFamily, files, notInBackup, oneComputer, memory, ph(Placeholder.RESTORE_NOTHING_LEFT)), rows(f))
        onScreen(w, f) { d ->
            val before = d.lines()
            d.press(restored)
            assertEquals(before, d.lines())
            assertTrue(d.lines().none { it.startsWith("Restore ") && it != "Restore a backup" }, "no button")
        }
    }
}
