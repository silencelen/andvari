package io.silencelen.andvari.desktop.trust

import androidx.compose.runtime.CompositionLocalProvider
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayOutputStream
import java.io.RandomAccessFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The restore's numbers in each state of the record and for ticks on and off, the lines of its drafts, and the lines
 * for files that do not open: each drawn through the real flow over the real shared restore.
 */
internal class RestoreLinesTest : RestoreTestKit() {
    private fun progressOf(lines: List<String>): String? = lines.firstOrNull { it.startsWith("Restoring: ") }

    /** The pushes the server answered, as the item ids each carried. */
    private fun sentSince(w: World, n: Int): List<String> = w.server.sent.drop(n).flatten()

    // ---- decision 1, the four states of the record ----

    @Test
    fun noRecordYetTheButtonNamesTheTickedVaultsAndTheRunStoresJustThose() {
        val w = world("lines-none")
        val f = flow(w, backup(401))
        open(f)
        val preview = page(w, f)
        has(preview, "Personal vault: 401 items", "Family: 2 items. You owned it.", "Restore 401 items")
        f.choose(family.vaultId, true)
        assertEquals(403, buttonCount(page(w, f)), "a shared vault ticked adds its items")
        f.choose(family.vaultId, false)
        f.choose(personal.vaultId, false)
        val none = page(w, f)
        assertEquals(0, buttonCount(none), "everything unticked offers nothing")
        assertEquals(true, Drawn { RestorePage(w.m, f) }.let { d -> try { d.disabled("Restore 0 items") } finally { d.close() } })
        runBlocking { f.confirm() }
        assertEquals(0, w.server.pushes, "nothing sent")
        f.choose(personal.vaultId, true)
        var during: List<String>? = null
        w.server.beforePush = { n -> if (n == 2) during = page(w, f) }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        assertEquals("Restoring: 200 of 401 items.", progressOf(assertNotNull(during)))
        has(page(w, f), "401 items restored into 1 vault.")
        assertEquals(401, personalItems(w))
        assertEquals(401, sentSince(w, 0).toSet().size, "only the personal vault's items were sent")
    }

    @Test
    fun aRunThatStoppedInTheMiddleOfAVaultOffersWhatIsLeftOfIt() {
        val w = world("lines-stopped")
        keepOn(w)
        val bytes = backup(401)
        // Stopped by a refusal of the whole first push: nothing stored by that run, and the batch is left queued.
        stopAfter(w, bytes, taken = 1)
        assertEquals(200, personalItems(w))
        val f = flow(w, bytes)
        open(f)
        val held = personalItems(w)
        val lines = page(w, f)
        val left = 401 - held
        has(lines, ph(Placeholder.RESTORE_VAULT_LEFT, "Personal vault: 401 items.", left.toString()))
        val named = buttonCount(lines) ?: if (RestoreFlow.confirmLine(1).shown() in lines) 1 else null
        assertEquals(left, named, "the button names what is left: $lines")
        f.choose(personal.vaultId, false)
        val pushes = w.server.pushes
        runBlocking { f.confirm() }
        assertEquals(pushes, w.server.pushes, "unticked: nothing sent")
        f.choose(personal.vaultId, true)
        runBlocking { f.confirm() }
        has(page(w, f), RestoreFlow.doneLine(left, 1).shown())
        assertEquals(held + left, personalItems(w))
        assertEquals(401, personalItems(w))
    }

    @Test
    fun aRunThatEndedWithARefusedItemOffersOnlyThatItemAndOnlyWhenItsVaultIsTicked() {
        val w = world("lines-refused")
        val bytes = backup(201)
        w.server.rejectFirst = true
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, f.views.value.stage)
        assertEquals(200, personalItems(w))
        val again = flow(w, bytes)
        open(again)
        val p = assertNotNull(again.views.value.preview)
        val lines = page(w, again)
        assertNotNull(p.vaults.first { it.personal }.restoredAt)
        has(
            lines,
            ph(Placeholder.RESTORE_VAULT_LEFT, "Personal vault: 201 items.", "1"),
            ph(Placeholder.RESTORE_REFUSED_BEFORE, "“A”"),
            RestoreFlow.confirmLine(1).shown(),
        )
        assertFalse(lines.any { it.startsWith("This account already holds ") }, "the 200 came from this file: $lines")
        // Unticked: the refused item is not sent.
        again.choose(personal.vaultId, false)
        val sent = w.server.sent.size
        runBlocking { again.confirm() }
        assertEquals(sent, w.server.sent.size, "nothing sent for a vault that is not ticked")
        // Ticked, and refused again: the account gets the one item named less the one refused in this run.
        again.choose(personal.vaultId, true)
        runBlocking { again.confirm() }
        val end = page(w, again)
        has(end, ph(Placeholder.RESTORE_DONE, "0", "1"), ph(Placeholder.RESTORE_REFUSED, "“A”"), "Try again")
        assertEquals(200, personalItems(w))
        // Try again right after the run that refused it, the server taking it now.
        w.server.rejectFirst = false
        runBlocking { again.tryAgain() }
        has(page(w, again), RestoreFlow.doneLine(1, 1).shown(), "1 attached file restored.")
        assertEquals(201, personalItems(w))
    }

    @Test
    fun aRunThatEndedWholeWithASharedVaultLeftUntickedOffersOnlyThatVault() {
        val w = world("lines-shared-left")
        val bytes = backup(3, familyItems = 2)
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        assertEquals(3, personalItems(w))
        val again = flow(w, bytes)
        open(again)
        val p = assertNotNull(again.views.value.preview)
        val lines = page(w, again)
        has(lines, ph(Placeholder.RESTORE_RESTORED_AT, "Personal vault: 3 items.",RestoreFlow.dayText(assertNotNull(p.vaults.first { it.personal }.restoredAt))), "Family: 2 items. You owned it.", "Restore 0 items")
        assertEquals(emptySet(), again.views.value.chosen)
        again.choose(family.vaultId, true)
        assertEquals(2, buttonCount(page(w, again)), "the shared vault left unticked, whole")
        // A vault already restored is not offered and cannot be ticked.
        again.choose(personal.vaultId, true)
        assertEquals(setOf(family.vaultId), again.views.value.chosen)
    }

    // ---- decision 5: lines for files that do not open ----

    @Test
    fun aBackupCutShortAndOneOverTheLimitEachHaveALineOfTheirOwn() {
        val w = world("lines-not-opened")
        val bytes = backup(3)
        val cut = flow(w, bytes.copyOf(bytes.size - 1))
        open(cut)
        val cutLines = page(w, cut)
        has(cutLines, ph(Placeholder.RESTORE_CUT_SHORT))
        assertFalse("This is not an andvari backup file, or it is damaged." in cutLines)
        // A real backup made larger than any backup may be (the file grown past the limit; it is not read).
        val file = java.io.File(newDir("over-limit"), "big.andvari")
        file.writeBytes(bytes)
        RandomAccessFile(file, "rw").use { it.setLength(Backup.MAX_FILE_BYTES + 1) }
        val said = runBlocking { readBackup(w.m, assertNotNull(w.m.content.value), file) }
        assertEquals(ph(Placeholder.RESTORE_TOO_LARGE), said)
        assertTrue(w.m.restoring.value === cut, "nothing opened")
        // A file that is not a backup keeps its approved sentence.
        val junk = flow(w, ByteArray(4000) { 7 }, "notes.txt")
        open(junk)
        has(page(w, junk), "This is not an andvari backup file, or it is damaged.")
    }

    // ---- the drafts no test drew ----

    @Test
    fun whatAFileLeavesOutIsSaidKindByKind() {
        val w = world("lines-left-out")
        val fileKey = crypto.randomBytes(32)
        val plain = ByteArray(10) { 1 }
        val stray = BackupVault("44444444-4444-4444-8444-444444444444", "shared", "Gone", "owner")
        val kept = BackupItem(id(), personal.vaultId, 1, 0, doc("Kept"))
        val orphan = BackupItem(id(), stray.vaultId, 1, 0, doc("Orphan"))
        val payload = BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org",
            // The personal vault twice; "Orphan" under a vault the file does not list.
            vaults = listOf(personal, personal.copy(name = "Again")),
            items = listOf(kept, orphan),
            // A file under an item the file does not list. (A part no entry names is a file the shared writer refuses
            // to make: `Backup.build` asks one part per entry, so RESTORE_LEFT_OUT_SECTIONS is not drawn here.)
            attachments = listOf(BackupAttachmentEntry(1, id(), id(), "lost.pdf", plain.size.toLong(), Bytes.toB64(fileKey))),
        )
        val out = ByteArrayOutputStream()
        Backup.build(
            crypto, pass, id(), crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload,
            listOf(Backup.AttachmentSection(fileKey) { plain.copyOf() }),
        ) { out.write(it) }
        val f = flow(w, out.toByteArray())
        open(f)
        val lines = page(w, f)
        println("LEFTOUT|${f.views.value.said?.shown()} $lines")
        has(
            lines,
            ph(Placeholder.RESTORE_LEFT_OUT_VAULTS_TWICE, "1"),
            ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_NO_VAULT, "1"),
            ph(Placeholder.RESTORE_LEFT_OUT_FILES_NO_ITEM, "1"),
        )
    }

    @Test
    fun aVaultWhoseCreationTheServerPacesSaysHowLongTheWaitIs() {
        val w = world("lines-waiting-vaults")
        val f = flow(w, backup(1, familyItems = 2))
        open(f)
        f.choose(personal.vaultId, false)
        f.choose(family.vaultId, true)
        w.server.vaultCreationWait = 1
        runBlocking {
            val run = launch(Dispatchers.Unconfined) { f.confirm() }
            val waiting = page(w, f)
            println("WAITING|$waiting")
            has(waiting, ph(Placeholder.RESTORE_WAITING_VAULTS, waitText(1).shown()))
            w.server.vaultCreationWait = null
            run.join()
        }
        println("WAITING|end ${f.views.value.stage} ${f.views.value.stop}")
    }

    @Test
    fun aVaultLockedBeforeThePressSaysItCannotTakeARestoreNow() {
        val w = world("lines-no-vault")
        val f = flow(w, backup(3))
        open(f)
        lock(w)
        runBlocking { f.confirm() }
        has(page(w, f), ph(Placeholder.RESTORE_NO_VAULT))
        assertEquals(0, w.server.pushes)
    }

    // ---- what the check took out, each noticed ----

    @Test
    fun aVaultsNameIsDrawnThroughTheCleaner() {
        val w = world("lines-cleaner")
        val hostile = BackupVault("55555555-5555-4555-8555-555555555555", "shared", "Fam" + Char(0x202E) + "ily", "owner")
        val payload = BackupPayload(
            exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal, hostile),
            items = listOf(BackupItem(id(), personal.vaultId, 1, 0, doc("P")), BackupItem(id(), hostile.vaultId, 1, 0, doc("H"))),
        )
        val out = ByteArrayOutputStream()
        Backup.build(crypto, pass, id(), crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload) { out.write(it) }
        val f = flow(w, out.toByteArray())
        open(f)
        val lines = page(w, f)
        assertTrue(lines.none { Char(0x202E) in it }, "no direction mark drawn raw: $lines")
        val line = RestoreFlow.vaultLine(assertNotNull(f.views.value.preview).vaults.first { !it.personal }).shown()
        has(lines, line)
        assertTrue(io.silencelen.andvari.core.app.ExportCopy.safeName(hostile.name) in line)
    }

    @Test
    fun thePassphraseIsZeroedByTheFlowAndByTheAppInterface() {
        val w = world("lines-wipe")
        val bytes = backup(1)
        val typed = pass.toCharArray()
        val f = flow(w, bytes)
        runBlocking { f.open(typed) }
        assertEquals(RestoreFlow.Stage.PREVIEW, f.views.value.stage)
        assertTrue(typed.all { it == 0.toChar() }, "the flow zeroed what it was handed")
        val wrong = "not it".toCharArray()
        val g = flow(w, bytes)
        runBlocking { g.open(wrong) }
        assertTrue(wrong.all { it == 0.toChar() }, "also a wrong one")
        val direct = pass.toCharArray()
        runBlocking { w.api.restores.open(direct, bytes) }
        assertTrue(direct.all { it == 0.toChar() }, "the app interface zeroes it too")
    }

    @Test
    fun theEntryIsDisabledWhileNothingCanBeSaved() {
        val w = world("lines-entry")
        val free = Drawn { BackupSection(w.m) }
        val held = Drawn { CompositionLocalProvider(LocalSavesHeld provides true) { BackupSection(w.m) } }
        try {
            assertEquals(false, free.disabled("Restore a backup"))
            assertEquals(true, held.disabled("Restore a backup"), "saves held: no restore")
        } finally {
            free.close()
            held.close()
        }
    }
}
