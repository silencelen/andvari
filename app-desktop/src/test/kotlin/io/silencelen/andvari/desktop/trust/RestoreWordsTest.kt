package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.BackupRestoreApi
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.ExportCopy
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.restore.RestoreEvent
import io.silencelen.andvari.core.client.restore.RestoreLeftOut
import io.silencelen.andvari.core.client.restore.RestorePreview
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.client.restore.RestoreVaultLine
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The restore's lines that got their words on 23 November 2026, each drawn where it is said: through the real flow over
 * the kit's server where that server reaches the state, otherwise on the page made from a state of the page that holds
 * it. Lines are named by their keys, so these hold whatever their words are.
 */
internal class RestoreWordsTest : RestoreTestKit() {
    private fun texts(f: RestoreFlow, v: RestoreFlow.View): List<String> = f.page(v).texts

    /** A preview of the kit's file as the shared restore describes one: the personal vault and "Family", nothing restored. */
    private fun preview(leftOut: RestoreLeftOut = RestoreLeftOut()) = RestorePreview(
        1_794_484_800_000L, "https://vault.example.org",
        listOf(
            RestoreVaultLine(personal.vaultId, "Personal", "personal", true, "owner", true, 3, null),
            RestoreVaultLine(family.vaultId, "Family", "shared", false, "owner", true, 2, null),
        ),
        0, 0L, emptyList(), emptyList(), 0, 0, emptyList(), leftOut, accountItemsBeside = 0,
    )

    @Test
    fun aWaitIsSaidAsALengthOfTimeInBothLinesOfAWait() {
        val w = world("words-waits")
        val f = flow(w, backup(1))
        for (seconds in listOf(0L, 42L, 600L, 7201L)) {
            val wait = waitText(seconds.toInt()).shown()
            has(texts(f, RestoreFlow.View(RestoreFlow.Stage.RUNNING, busy = true, waiting = RestoreEvent.Waiting(seconds, vaultCreation = false))), ph(Placeholder.RESTORE_WAITING, wait))
            has(texts(f, RestoreFlow.View(RestoreFlow.Stage.RUNNING, busy = true, waiting = RestoreEvent.Waiting(seconds, vaultCreation = true))), ph(Placeholder.RESTORE_WAITING_VAULTS, wait))
        }
        // Each length the server can name has its own line: a while, seconds, minutes, hours.
        assertEquals(
            listOf(Placeholder.WAIT_A_WHILE, Placeholder.WAIT_SECONDS, Placeholder.WAIT_MINUTES, Placeholder.WAIT_HOURS),
            listOf(0, 42, 600, 7201).map { assertIs<UiText.Ph>(waitText(it)).placeholder },
        )
    }

    @Test
    fun everyKindOfWhatAFileLeavesOutIsSaidOnThePreviewAndAtTheEnd() {
        // A part of the file that no entry names cannot be made by the shared writer (one part per entry), so the
        // description holds it as the shared restore gives it; the page is the real one.
        val w = world("words-left-out")
        val f = flow(w, backup(1))
        val all = RestoreLeftOut(vaultsTwice = 1, itemsTwice = 2, itemsUnderNoVault = 3, filesUnderNoItem = 4, sectionsUnnamed = 5)
        val lines = listOf(
            ph(Placeholder.RESTORE_LEFT_OUT_VAULTS_TWICE, "1"),
            ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_TWICE, "2"),
            ph(Placeholder.RESTORE_LEFT_OUT_ITEMS_NO_VAULT, "3"),
            ph(Placeholder.RESTORE_LEFT_OUT_FILES_NO_ITEM, "4"),
            ph(Placeholder.RESTORE_LEFT_OUT_SECTIONS, "5"),
        )
        has(texts(f, RestoreFlow.View(RestoreFlow.Stage.PREVIEW, preview = preview(all), chosen = setOf(personal.vaultId))), *lines.toTypedArray())
        has(texts(f, RestoreFlow.View(RestoreFlow.Stage.ENDED, done = RestoreResult.Done(3, 1, emptyList(), 0, 0, all))), *lines.toTypedArray())
    }

    @Test
    fun aFileThatDoesNotOpenSaysWhichWayAndACodeIsDrawnClean() {
        val w = world("words-not-opened")
        // An entry under an item whose document does not name that file: refused whole, `bad_payload`.
        val key = crypto.randomBytes(32)
        val plain = ByteArray(10) { 1 }
        val kept = BackupItem(id(), personal.vaultId, 1, 0, doc("Kept"))
        val misnamed = build(
            BackupPayload(
                exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal), items = listOf(kept),
                attachments = listOf(BackupAttachmentEntry(1, id(), kept.itemId, "stray.pdf", plain.size.toLong(), Bytes.toB64(key))),
            ),
            listOf(key to plain),
        )
        val bad = flow(w, misnamed)
        open(bad)
        has(page(w, bad), ph(Placeholder.RESTORE_NOT_OPENED, Backup.ERR_BAD_PAYLOAD))
        // A first part over 64 KiB: the file's header says so before anything is read, `too_large`.
        val big = backup(1)
        val headerLen = 70_000
        for (i in 0 until 4) big[8 + i] = (headerLen ushr (8 * i)).toByte()
        val large = flow(w, big)
        open(large)
        has(page(w, large), ph(Placeholder.RESTORE_TOO_LARGE))
        // A later version of the format, and a code with characters a person must not get raw.
        val f = flow(w, backup(1))
        has(texts(f, RestoreFlow.View(RestoreFlow.Stage.PASSPHRASE, said = RestoreFlow.notOpenedLine(Backup.ERR_UNKNOWN_VERSION))), ph(Placeholder.RESTORE_NOT_OPENED, Backup.ERR_UNKNOWN_VERSION))
        val hostile = "odd" + Char(0x202E) + "code" + "\n"
        val drawn = texts(f, RestoreFlow.View(RestoreFlow.Stage.PASSPHRASE, said = RestoreFlow.notOpenedLine(hostile)))
        has(drawn, ph(Placeholder.RESTORE_NOT_OPENED, ExportCopy.safeName(hostile)))
        assertTrue(drawn.none { Char(0x202E) in it || "\n" in it }, "$drawn")
    }

    @Test
    fun aPressAfterTheSameFileWasRestoredFromASecondPageSendsNothingAndSaysTheAccountChanged() {
        val w = world("words-second-page")
        val bytes = backup(3, familyItems = 0)
        val first = flow(w, bytes)
        open(first)
        val second = flow(w, bytes)
        open(second)
        runBlocking { second.confirm() }
        assertEquals(RestoreFlow.Stage.ENDED, second.views.value.stage)
        val pushes = w.server.pushes
        runBlocking { first.confirm() }
        assertEquals(pushes, w.server.pushes, "nothing was sent")
        assertEquals(RestoreFlow.Stage.PREVIEW, first.views.value.stage)
        has(page(w, first), ph(Placeholder.RESTORE_CHANGED), ph(Placeholder.RESTORE_NOTHING_LEFT))
        assertEquals(3, personalItems(w))
    }

    @Test
    fun theLineBeforeASignOutIsDrawnAtTheSwitchToAnotherServer() {
        // The kit's server opens no invitation for another server; the shared code's own stand-in does, and its record
        // of a restore is said as not finished here. The window is the real one.
        val fake = FakeScenes.desktopAt(FakeScene.OPENED_OTHER_INSTANCE)
        val unfinished = object : BackupRestoreApi by fake.restores {
            override fun unfinishedRestore(): Boolean = true
        }
        val api = object : DesktopAppApi by fake {
            override val restores: BackupRestoreApi get() = unfinished
        }
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        val opened = assertIs<OpenedInvite.OtherInstance>(api.snapshot.account?.opened)
        val lines = drawn { OtherInstanceWindow(m, api.snapshot, opened) }
        has(lines, ph(Placeholder.RESTORE_UNFINISHED_AT_SIGN_OUT))
        // And not where the record shows nothing unfinished.
        val plain = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), { 0L })
        plain.onSnapshot(fake.snapshot)
        val none = drawn { OtherInstanceWindow(plain, fake.snapshot, assertNotNull(fake.snapshot.account?.opened as? OpenedInvite.OtherInstance)) }
        assertTrue(none.isNotEmpty())
        assertTrue(ph(Placeholder.RESTORE_UNFINISHED_AT_SIGN_OUT) !in none, "$none")
    }
}
