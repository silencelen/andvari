package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.ExportCopy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The content's last lines that were put together by hand are said by keys, their words unchanged: the saved exports
 * with their folder and their number, what a lock left unsaved with its list of names, the copies into the personal
 * vault, out of a held vault and into a vault, and files not handed over. Where a name cannot be read, the plain words
 * that stand there ("the other vault", "its vault", "This item", "a vault") are never quoted as if they were a name.
 */
class HandBuiltLinesTest {
    @Test
    fun theSavedExportLines_areTheirKeys_andWordForWordTheCurrentAppsWithAndWithoutAFolder() {
        // Word for word the current app's where a folder is named; with none, the new line leaves the folder out.
        for (folder in listOf("Downloads")) {
            for (n in listOf(1, 3)) {
                assertEquals(ExportCopy.csvSaved("x.csv", folder, n), ContentCopy.csvSaved("x.csv", folder, n), "folder=$folder n=$n")
                for (vaults in listOf(1, 2)) for (files in listOf(0, 1, 4)) {
                    assertEquals(ExportCopy.backupSaved("b.andvari", folder, n, vaults, files), ContentCopy.backupSaved("b.andvari", folder, n, vaults, files), "folder=$folder n=$n v=$vaults f=$files")
                }
            }
        }
        assertEquals(
            CopyKey.EXPORT_SAVED_TO.fill(listOf("x.csv", "Downloads", CopyKey.EXPORT_CSV_HOLDS_MANY.fill(listOf("3")))),
            ContentCopy.csvSaved("x.csv", "Downloads", 3),
        )
        assertEquals(CopyKey.EXPORT_SAVED.fill(listOf("x.csv", CopyKey.EXPORT_CSV_HOLDS_ONE.fill(emptyList()))), ContentCopy.csvSaved("x.csv", "", 1))
        assertEquals(
            CopyKey.EXPORT_SAVED.fill(listOf("b.andvari", CopyKey.EXPORT_BACKUP_HOLDS.fill(listOf(CopyKey.COUNT_ITEMS_ONE.fill(emptyList()), CopyKey.COUNT_VAULTS_MANY.fill(listOf("2")))))),
            ContentCopy.backupSaved("b.andvari", " ", 1, 2, 0),
        )
        val holds = CopyKey.EXPORT_BACKUP_HOLDS_FILES.fill(listOf(CopyKey.COUNT_ITEMS_MANY.fill(listOf("5")), CopyKey.COUNT_VAULTS_ONE.fill(emptyList()), CopyKey.COUNT_FILES_MANY.fill(listOf("2"))))
        assertEquals(CopyKey.EXPORT_SAVED_TO.fill(listOf("b.andvari", "iCloud Drive", holds)), ContentCopy.backupSaved("b.andvari", "iCloud Drive", 5, 1, 2))
    }

    @Test
    fun whatALockLeftUnsaved_namesUpToThreeItemsByItsKeys_andCountsTheRest() {
        assertEquals(CopyKey.UNSAVED_AT_LOCK_ONE.fill(listOf("Bank")), ContentCopy.unsavedAtLock(listOf("Bank"), 0, 0))
        // One entry per item: two items of the same name are two changes.
        assertEquals(CopyKey.UNSAVED_AT_LOCK_TWO.fill(listOf("Bank", "Bank")), ContentCopy.unsavedAtLock(listOf("Bank", "Bank"), 0, 0))
        assertEquals(CopyKey.UNSAVED_AT_LOCK_TWO.fill(listOf("Bank", "Mail")), ContentCopy.unsavedAtLock(listOf("Bank", "Mail"), 0, 0))
        assertEquals(CopyKey.UNSAVED_AT_LOCK_THREE.fill(listOf("A", "B", "C")), ContentCopy.unsavedAtLock(listOf("A", "B", "C"), 0, 0))
        assertEquals(CopyKey.UNSAVED_AT_LOCK_MORE.fill(listOf("A", "B", "C", "2")), ContentCopy.unsavedAtLock(listOf("A", "B", "C", "D", "E"), 0, 0))
        val unnamed = ContentCopy.unsavedAtLock(listOf(""), 0, 0)
        assertTrue("an item with no name" in unnamed, unnamed)
        assertFalse("“an item with no name”" in unnamed, "plain words, not a name: $unnamed")

        assertEquals(CopyKey.LOCK_CUT_IMPORT_KEPT_MANY_LOST_ONE.fill(listOf("0")), ContentCopy.unsavedAtLock(emptyList(), 0, 1))
        assertEquals(CopyKey.LOCK_CUT_IMPORT_KEPT_MANY_LOST_MANY.fill(listOf("200", "51")), ContentCopy.unsavedAtLock(emptyList(), 200, 51))
        assertEquals(
            CopyKey.UNSAVED_AT_LOCK_ONE.fill(listOf("Bank")) + " " + CopyKey.LOCK_CUT_IMPORT_KEPT_MANY_LOST_MANY.fill(listOf("2", "3")),
            ContentCopy.unsavedAtLock(listOf("Bank"), 2, 3),
        )
    }

    @Test
    fun theCopyLines_areTheirKeys_andAVaultWithNoReadableNameIsSaidInPlainWords() {
        assertEquals(CopyKey.COPIED_TO_PERSONAL_ONE.fill(emptyList()), ContentCopy.copiedToPersonal(1))
        assertEquals(CopyKey.COPIED_TO_PERSONAL_MANY.fill(listOf("2")), ContentCopy.copiedToPersonal(2))
        // The current app's words, which these keys keep.
        assertEquals("Copied 2 items to your personal vault. Deleting the shared vault won't remove those copies.", ContentCopy.copiedToPersonal(2))

        assertEquals(CopyKey.COPIED_OUT_OF_HELD_MANY.fill(listOf("3")), ContentCopy.copiedOutOfHeld(3, 0))
        assertEquals(CopyKey.COPIED_OUT_OF_HELD_ONE.fill(emptyList()) + " " + CopyKey.FILES_NOT_HANDED_OVER_MANY.fill(listOf("2")), ContentCopy.copiedOutOfHeld(1, 2))
        assertEquals(CopyKey.BROUGHT_INTO_MANY.fill(listOf("2", "Family")) + " " + CopyKey.FILES_NOT_HANDED_OVER_ONE.fill(emptyList()), ContentCopy.broughtInto("Family", 2, 1))
        assertEquals(CopyKey.BROUGHT_INTO_ONE.fill(listOf("Family")), ContentCopy.broughtInto("Family", 1, 0))
        val unknown = ContentCopy.broughtInto(null, 1, 1)
        assertTrue("a vault" in unknown && "“a vault”" !in unknown && "“”" !in unknown, unknown)
    }

    @Test
    fun theFallbackWordsOfAMove_readAsPlainWords_neverInsideQuotationMarks() {
        val other = CopyKey.NAME_THE_OTHER_VAULT.english
        val its = CopyKey.NAME_ITS_VAULT.english
        val item = CopyKey.NAME_THIS_ITEM.english
        for (line in listOf(ContentCopy.moved(null), ContentCopy.copied(""), ContentCopy.alreadyCopied("Bank", null, false))) {
            assertTrue(other in line && "“$other”" !in line, line)
        }
        val both = ContentCopy.inBothVaults("", null, null)
        for (w in listOf(other, its, item)) assertTrue(w in both && "“$w”" !in both, both)
        val again = ContentCopy.alreadyCopied(null, "Family", true)
        assertTrue(item in again && "“$item”" !in again && "“Family”" in again, again)
        // A name that can be read is still said as a name, quoted once.
        assertEquals(CopyKey.ITEM_MOVED_TO.fill(listOf("Family")), ContentCopy.moved("Family"))
    }
}
