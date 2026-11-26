package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.nio.file.Files
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The rest of the vault on the desktop's new path: files, earlier versions, move and copy,
 * "Recently removed", CSV import, backup and CSV export with the write discipline, and vault health, over the fake.
 */
class VaultRestTest {
    private fun unlocked(): Triple<FakeDesktopAppApi, TrustModel, VaultContent> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return Triple(api, m, assertNotNull(m.content.value))
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    private fun tempDir(): File = Files.createTempDirectory("andvari-l7-test").toFile().also { it.deleteOnExit() }

    // ---- reading a picked file ----

    @Test
    fun aPickedFileIsReadOnlyUpToItsLimitAndASizeOverItIsRefusedUnread() {
        val dir = tempDir()
        val small = File(dir, "a.txt").apply { writeBytes(ByteArray(10) { 7 }) }
        val read = assertIs<PickedFiles.Picked.Read>(PickedFiles.read(small, 10))
        assertEquals("a.txt", read.name)
        assertEquals(10, read.bytes.size)
        val big = File(dir, "b.bin").apply { writeBytes(ByteArray(11)) }
        assertEquals(11L, assertIs<PickedFiles.Picked.TooLarge>(PickedFiles.read(big, 10)).size, "its size is asked first")
        assertIs<PickedFiles.Picked.NotRead>(PickedFiles.read(File(dir, "missing"), 10))
        assertIs<PickedFiles.Picked.NotRead>(PickedFiles.read(dir, 10), "a folder is not a file")
        // A stream that says nothing about its size is still stopped one byte past the limit.
        var served = 0
        val endless = object : java.io.InputStream() {
            override fun read(): Int = 1.also { served++ }
            override fun read(b: ByteArray, off: Int, len: Int): Int { b.fill(1, off, off + len); served += len; return len }
        }
        assertNull(PickedFiles.readAtMost(endless, 100_000))
        assertTrue(served <= 100_001, "read stops at the limit plus one")
        assertEquals(3, assertNotNull(PickedFiles.readAtMost(ByteArrayInputStream(byteArrayOf(1, 2, 3)), 3)).size)
    }

    // ---- the write discipline ----

    @Test
    fun aWriteIsCheckedBesideTheTargetAndOnlyThenMovedOverIt() {
        val dir = tempDir()
        val dest = File(dir, "export.csv")
        val bytes = "name,url\nBank,https://bank.example\n".toByteArray()
        assertEquals(ExportWrite.SAVED, writeVerified(dest, bytes).result)
        assertTrue(dest.readBytes().contentEquals(bytes))
        assertEquals(listOf("export.csv"), dir.list()!!.toList(), "no temporary file is left")
        // A file already there is replaced only by a checked copy.
        val newer = "newer".toByteArray()
        assertEquals(ExportWrite.SAVED, writeVerified(dest, newer).result)
        assertEquals("newer", dest.readText())
        // A folder that cannot be written to writes nothing.
        assertEquals(ExportWrite.NOT_OPENED, writeVerified(File(File(dir, "no-such-folder"), "x.csv"), bytes).result)
    }

    @Test
    fun aCopyThatReadsBackDifferentIsRemovedAndAFailedWriteToo() {
        var deleted = false
        var data = ByteArray(0)
        val bytes = "secret".toByteArray()
        val corrupting = {
            object : java.io.ByteArrayOutputStream() {
                override fun close() { data = toByteArray().also { it[0] = (it[0] + 1).toByte() } }
            }
        }
        assertEquals(ExportWrite.DIFFERS, writeAndCheck(corrupting, { ByteArrayInputStream(data) }, { deleted = true }, bytes))
        assertTrue(deleted)
        deleted = false
        val failing = { object : OutputStream() { override fun write(b: Int) = throw IOException("disk full") } }
        assertEquals(ExportWrite.NOT_WRITTEN, writeAndCheck(failing, { null }, { deleted = true }, bytes))
        assertTrue(deleted)
        deleted = false
        assertEquals(ExportWrite.NOT_OPENED, writeAndCheck({ null }, { null }, { deleted = true }, bytes))
        assertFalse(deleted, "nothing written, nothing to remove")
    }

    @Test
    fun theExportIsMadeAfterThePlaceIsPickedAndWrittenOffTheUiThread() {
        val panel = src("VaultTransferScreens.kt").substringAfter("internal fun ExportPanel(")
        val picked = panel.indexOf("FilePicker.save(")
        val made = panel.indexOf("c.csvFile(ack)")
        val write = panel.indexOf("withContext(NonCancellable + Dispatchers.IO)")
        assertTrue(made in 0 until write, "made, then written")
        assertTrue(panel.indexOf("writeVerified(dest, file.bytes)") > write)
        assertTrue(panel.indexOf("file.bytes.fill(0)") > write, "the bytes are zeroed whatever happens")
        // The file is made inside writeTo, which runs only from the Save dialog's answer (through the overwrite gate).
        assertTrue(picked > 0 && panel.indexOf("overwrite.request(pick.file) { writeTo(pick.file) }") > picked)
        assertTrue(panel.contains("c.backupFileChars(pass, again)"), "the passphrase goes as characters")
        assertFalse(panel.contains("c.backupFile(passphrase"))
        assertTrue(panel.contains("pass.fill("))
        assertTrue(panel.contains("if (v.busy || writing) Say(Placeholder.WORKING)"))
        assertEquals("andvari-export-2026-11-15.csv", exportFileName(ExportKind.CSV, LocalDate.of(2026, 11, 15)))
        assertEquals("andvari-backup-2026-11-15.andvari", exportFileName(ExportKind.BACKUP, LocalDate.of(2026, 11, 15)))
    }

    // ---- files ----

    @Test
    fun filesAreListedSavedAndAddedThroughTheEditorsDraftWithinItsRoom() {
        val (api, m, c) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val fileId = fake.seedAttachment(id, "statement.pdf", byteArrayOf(1, 2, 3))
        val d = assertNotNull(c.itemDetail(id))
        assertEquals(listOf("statement.pdf"), d.attachments.map { it.name })
        assertEquals(listOf<Byte>(1, 2, 3), assertNotNull(runBlocking { c.readAttachment(id, fileId) }.bytes).toList())

        fake.setAttachmentLimits(perFileBytes = 8, perItemBytes = 10)
        c.openAttachmentDraft(id)
        val draft = assertNotNull(c.state.attachmentDraft)
        assertEquals(7, attachmentRoom(draft), "the item's room left is less than the per-file limit")
        val dir = tempDir()
        val tooBig = File(dir, "big.bin").apply { writeBytes(ByteArray(8)) }
        assertNotNull(runBlocking { addPicked(c, tooBig) }, "a file over the room is refused in the content's words")
        val fits = File(dir, "key.txt").apply { writeBytes(byteArrayOf(9, 9)) }
        assertNull(runBlocking { addPicked(c, fits) })
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(id, LoginInput("Bank", "me", "pw", emptyList(), "", "", false), d.vaultId) })
        c.closeAttachmentDraft()
        assertEquals(setOf("statement.pdf", "key.txt"), assertNotNull(c.itemDetail(id)).attachments.map { it.name }.toSet())
        assertTrue(m.content.value === c)

        val screens = src("VaultItemsScreens.kt")
        assertTrue(screens.contains("bytes.fill(0)"), "the decrypted bytes are zeroed after the write")
        assertTrue(screens.contains("onDispose { Overtaken.read(fault, null, Unit) { c.closeAttachmentDraft() } }"))
        assertTrue(screens.contains("FilePicker.save(UiText.ph(Placeholder.ATTACHMENT_SAVE).shown(), a.name)"), "the name is made safe by the picker")
        assertTrue(src("DesktopFiles.kt").contains("d.file = SaveTarget.defaultName(suggestedName)"))
        assertTrue(src("DesktopFiles.kt").contains("SaveTarget.resolve(dir, name)"))
        assertEquals("3 B", sizeText(3))
        assertEquals("2 KB", sizeText(1025))
    }

    @Test
    fun aPickIsUsedOnlyIfTheVaultItWasPickedForIsStillOpen() {
        val (api, m, c) = unlocked()
        assertTrue(stillOpen(m, c))
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertFalse(stillOpen(m, c), "the vault locked while the dialog was open: the pick goes")
        val screens = src("VaultItemsScreens.kt") + src("VaultTransferScreens.kt")
        // The import (the toolbar's icon and the menu share one dialog), the export, a file saved, a file added.
        assertEquals(4, Regex("stillOpen\\(model, c\\)").findAll(screens).count(), "every file dialog checks")
    }

    // ---- history, move and copy, recently removed ----

    @Test
    fun anEditedLoginsHistoryHoldsTheEarlierPassword() {
        val (_, _, c) = unlocked()
        val personal = assertNotNull(c.vaultsForNewItems().firstOrNull { it.personal }).vaultId
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(null, LoginInput("Bank", "me", "old-pw", emptyList(), "", "", false), personal) })
        val id = c.state.items.single().itemId
        assertEquals(ActionResult.Ok, runBlocking { c.saveLogin(id, LoginInput("Bank", "me", "new-pw", emptyList(), "", "", false), personal) })
        assertEquals(ActionResult.Ok, runBlocking { c.openItemHistory(id) })
        val h: ItemHistoryView = assertNotNull(c.state.history)
        assertEquals("old-pw", c.historyPassword(id, h.versions.first().rev))
        c.closeItemHistory()
        assertNull(c.state.history)
        assertTrue(src("VaultItemsScreens.kt").contains("copyWithAutoClear(it, clipboardSeconds(model))) null else CLIPBOARD_COPY_FAILED"))
    }

    @Test
    fun anItemMovesToASharedVaultAndARemovedVaultCanBeCopiedOutOrDropped() {
        val (api, _, c) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        fake.addSharedVault("shared-1", "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "")
        val target = c.moveTargets(id).single { it.vaultId == "shared-1" }
        assertTrue(c.canMoveOut(id))
        assertEquals(ActionResult.Ok, runBlocking { c.moveOrCopyItem(id, target.vaultId, move = true) })
        assertEquals("shared-1", assertNotNull(c.itemDetail(c.state.items.single { it.name == "Bank" }.itemId)).vaultId)

        fake.holdVault("shared-1", ItemNotice.DELETED, readable = true)
        val held = c.state.held.single()
        assertTrue(held.readable)
        assertEquals(ActionResult.Ok, runBlocking { c.saveVaultItemsToPersonal(held.vaultId) })
        assertTrue(c.state.items.any { it.name == "Bank" }, "the copy is in the personal vault")
        assertEquals(ActionResult.Ok, c.removeFromDevice(held.vaultId))
        assertTrue(c.state.held.isEmpty())
        val screens = src("VaultItemsScreens.kt")
        assertTrue(screens.contains("if (ask.second) Say(CopyKey.CHECK_WHAT_YOU_COPY)"), "copying out always warns first")
        val removed = screens.substringAfter("private fun RecentlyRemovedSection(").substringBefore("\n@Composable")
        assertTrue(removed.indexOf("Placeholder.BACK") < removed.indexOf("c.saveVaultItemsToPersonal("), "the way out comes first")
    }

    // ---- import and export ----

    @Test
    fun aPickedCsvImportsAndTheVaultExportsAsCsv() {
        val (_, _, c) = unlocked()
        val csv = File(tempDir(), "passwords.csv").apply { writeText("name,url,username,password\nBank,https://bank.example,me,pw\n") }
        assertNull(runBlocking { importPicked(c, csv) })
        assertEquals(1, assertNotNull(c.state.csvImport).toImport)
        assertEquals(ActionResult.Ok, runBlocking { c.confirmImport() })
        c.closeImport()
        assertEquals(listOf("Bank"), c.state.items.map { it.name })
        assertTrue(csvTooLarge().contains("10.0 MB"), "the cap is named: " + csvTooLarge())
        assertEquals(10L * 1024 * 1024, CsvImport.MAX_BYTES.toLong())

        assertEquals(ActionResult.Ok, runBlocking { c.openExport(ExportKind.CSV) })
        val file = assertNotNull(c.csvFile(acknowledged = true))
        val dest = File(tempDir(), "out.csv")
        assertEquals(ExportWrite.SAVED, writeVerified(dest, file.bytes).result)
        c.exportSaved(dest.name, dest.parent)
        assertTrue(dest.readText().contains("bank.example"))
        c.closeExport()
    }

    // ---- health ----

    @Test
    fun healthTakesThePersonsVerdictsAndAGoneLoginIsOfferedForTheTrash() {
        val (api, _, c) = unlocked()
        val fake = assertNotNull(api.fakeContent)
        val bank = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "Bank-pass-1!", "https://bank.example")
        fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "me", "Mail-pass-2!", "https://mail.example")
        c.openHealth()
        assertEquals(2, assertNotNull(c.state.health).staleness.size)
        c.checkLogin(bank)
        val run = assertNotNull(c.state.health?.run)
        assertEquals("https://bank.example", run.site?.let { webAddress(it) })
        assertFalse(runBlocking { c.recordCheck(bank, "gone") } is ActionResult.Failed)
        assertEquals("Bank", assertNotNull(c.state.health?.offerDelete).name)
        assertFalse(runBlocking { c.trashGoneLogin() } is ActionResult.Failed)
        assertTrue(c.state.health!!.staleness.none { it.itemId == bank }, "in the trash now")
        c.closeHealth()
        assertNull(c.state.health)
    }

    @Test
    fun theHealthPanelOffersEveryActionAndASiteOpensOnlyAsAWebAddress() {
        val panel = src("VaultHealthScreens.kt")
        for (call in listOf(
            "c.restoreDuplicates(", "c.unsnoozeLogin(", "c.trashGoneLogin()", "c.keepGoneLogin()", "c.answerBadOffer(false)",
            "c.startCheckRun(false)", "c.startCheckRun(true)", "c.checkLogin(", "c.skipCheck()", "c.stopCheckRun()",
            "c.recordCheck(", "c.setHealthShowSnoozed(", "c.mergeDuplicates(", "c.keepDuplicate(", "c.markNotDuplicates(",
            "c.checkBreaches()", "openInBrowser(url)", "copyWithAutoClear(it, clipboardSeconds(model))",
        )) {
            assertTrue(panel.contains(call), call)
        }
        assertEquals(listOf("ok", "bad", "gone", "blocked"), CHECK_VERDICTS)
        assertEquals("https://bank.example", webAddress("bank.example"))
        for (bad in listOf("javascript:alert(1)", "file:///etc/passwd", "", "bank example.com", "smb://host/share")) assertNull(webAddress(bad), bad)
        assertTrue(src("VaultItemsScreens.kt").contains("if (generate) editing = Editing(\"login\", itemId, generate = true) else open = itemId"))
    }
}
