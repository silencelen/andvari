package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.ItemHistoryView
import io.silencelen.andvari.core.app.ItemVersionView
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.QuotaRoom
import io.silencelen.andvari.core.client.items.Shortfall
import io.silencelen.andvari.core.model.wire.QuotaName
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Where the content's own sentences carry a count, a count of one is its own key and reads in the singular; and an item
 * with no earlier versions has a line of its own under its history, never the empty vault's line. Each line is named by
 * its key, so the words the owner gives them later change nothing here.
 */
class CountOfOneLinesTest {
    private fun named(s: String) = ContentCopy.Slot(s, true)
    private fun plain(s: String) = ContentCopy.Slot(s, false)

    @Test
    fun aCopyALockCutShortAfterOneItem_isSaidByItsOwnKey() {
        assertEquals(
            ContentCopy.fillNames(CopyKey.LOCK_CUT_COPY_ONE, named("Family"), named("Personal"), plain("5")),
            ContentCopy.lockCut(LockCut(LockCutKind.VAULT_COPY, "Family", "Personal", 1, 5)),
        )
        assertEquals(
            ContentCopy.fillNames(CopyKey.LOCK_CUT_COPY, named("Family"), named("Personal"), named("2"), named("5")),
            ContentCopy.lockCut(LockCut(LockCutKind.VAULT_COPY, "Family", "Personal", 2, 5)),
        )
        // A copy into the personal vault has lines of its own: copying it again copies everything again.
        assertEquals(
            ContentCopy.fillNames(CopyKey.LOCK_CUT_COPY_TO_PERSONAL_ONE, named("Family"), named("Personal"), plain("5")),
            ContentCopy.lockCut(LockCut(LockCutKind.PERSONAL_COPY, "Family", "Personal", 1, 5)),
        )
        assertEquals(
            ContentCopy.fillNames(CopyKey.LOCK_CUT_COPY_TO_PERSONAL, named("Family"), named("Personal"), named("2"), named("5")),
            ContentCopy.lockCut(LockCut(LockCutKind.PERSONAL_COPY, "Family", "Personal", 2, 5)),
        )
    }

    @Test
    fun oneEditThatWaitedWhenItsVaultWasDeleted_isSaidByItsOwnKey() {
        fun deleted(count: Int) = ContentCopy.notice(ItemNotice("n1", "00000000-0000-4000-8000-0000000000aa", "Family", ItemNotice.DELETED, count)).first
        val head = ContentCopy.fillNames(CopyKey.NOTICE_VAULT_DELETED, named("Family"))
        assertEquals(head + " " + ContentCopy.fillNames(CopyKey.NOTICE_EDITS_KEPT_ONE), deleted(1))
        assertEquals(head + " " + ContentCopy.fillNames(CopyKey.NOTICE_EDITS_KEPT_MANY, named("3")), deleted(3))
        assertEquals(head, deleted(0))
    }

    @Test
    fun aLimitOfItemsPassedByOne_andALimitOfOneSharedVault_areSaidByTheirOwnKeys() {
        fun line(quota: String, used: Long, limit: Long, adds: Long) =
            SpaceCheck.of(QuotaRoom.Short(listOf(Shortfall(quota, used, limit, adds))), SpaceFor.CSV_IMPORT, null).line!!
        val oneOver = line(QuotaName.ITEMS, 99, 100, 2)
        assertEquals(CopyKey.SPACE_SHORT_ITEMS_ONE_OVER, oneOver.key)
        assertEquals(listOf("100"), oneOver.values)
        assertEquals(CopyKey.SPACE_SHORT_ITEMS, line(QuotaName.ITEMS, 99, 100, 3).key)
        val oneVault = line(QuotaName.OWNED_SHARED_VAULTS, 1, 1, 1)
        assertEquals(CopyKey.SPACE_SHORT_VAULTS_ONE, oneVault.key)
        assertEquals(emptyList(), oneVault.values)
        assertEquals(CopyKey.SPACE_SHORT_VAULTS, line(QuotaName.OWNED_SHARED_VAULTS, 2, 2, 1).key)
    }

    @Test
    fun theImportsCountsOfOne_areSaidByTheirOwnKeys() {
        assertEquals(CopyKey.IMPORT_STOPPED_SAVED_ONE_NOT_ONE.fill(emptyList()) + " " + CopyKey.IMPORT_RETRY_THE_REST.fill(emptyList()), ContentCopy.importStopped(1, 1, null))
        assertEquals(CopyKey.IMPORT_STOPPED_SAVED_ONE_NOT_MANY.fill(listOf("4")) + " " + CopyKey.IMPORT_RETRY_THE_REST.fill(emptyList()), ContentCopy.importStopped(1, 4, null))
        assertEquals("Why. " + CopyKey.IMPORT_STOPPED_SAVED_MANY_NOT_ONE.fill(listOf("4")), ContentCopy.importStopped(4, 1, "Why."))
        assertNull(ContentCopy.importStopped(0, 4, null), "nothing saved: the plain line says it")
        val written = io.silencelen.andvari.core.client.items.Written.QUEUED
        assertEquals(CopyKey.IMPORT_KEPT_ONE.fill(emptyList()), ContentCopy.importKept(1, written))
        assertEquals(CopyKey.IMPORT_KEPT_UNTIL_SIGN_IN_ONE.fill(emptyList()), ContentCopy.importKept(1, io.silencelen.andvari.core.client.items.Written.KEPT_SESSION_ENDED))
    }

    @Test
    fun anItemWithNoEarlierVersions_hasALineOfItsOwn() {
        assertEquals(CopyKey.ITEM_HISTORY_EMPTY, ItemHistoryView("i", emptyList(), canRestore = true).emptyLine)
        assertNull(ItemHistoryView("i", listOf(ItemVersionView(3, 0, "Bank", null, true)), canRestore = true).emptyLine)
    }
}
