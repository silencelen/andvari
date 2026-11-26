package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared code says while a "Move everything" deletion of the old vault is signed and waiting, and after the
 * server stored it outside the move: the vault's read-only line on its row and above the items, the notice with its
 * copy and its dismiss, and the two new refusals in the shared code's own sentences.
 */
class MoveDeleteWaitingScreensTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun aVaultWhoseDeletionWaitsSaysItIsReadOnlyOnItsRowAndAboveTheItems() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val me = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        val family = me.vaults.first { it.name == "Family" }
        family.moveUnfinishedInto = "Work"
        family.moveDeleteWaiting = true
        api.script.changed()
        val account = assertNotNull(api.snapshot.account)
        val row = account.vaults.first { it.name == "Family" }
        val line = assertNotNull(row.readOnlyLine)
        assertEquals(CopyKey.MOVE_WAITING_READ_ONLY, line.key)
        assertFalse(row.writable)
        assertEquals(listOf(UiText.of(line).shown()), readOnlyVaultLines(account).map { it.shown() })
        // Drawn as information on the row and the vault's page, and above the items on the vault's page.
        assertTrue(src("VaultScreens.kt").substringAfter("private fun VaultStateLines(").substringBefore("\n}\n").contains("v.readOnlyLine?.let { Say(UiText.of(it)) }"))
        assertTrue(src("AccountScreens.kt").contains("for (line in readOnlyVaultLines(account)) Quiet(line)"))
    }

    @Test
    fun aDeletionStoredOutsideTheMoveIsANoticeWithItsCopyAndItsDismiss() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        val me = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        val family = me.vaults.first { it.name == "Family" }
        family.moveUnfinishedInto = "Work"
        family.moveDeleteWaiting = true
        api.script.changed()
        assertTrue(api.script.serverStoresMoveDeleteLater(added = 2, changed = 1))
        val notice = assertNotNull(api.snapshot.account).movesStoredOutside.single()
        assertEquals(CopyKey.MOVE_STORED_OUTSIDE, notice.line.key)
        assertTrue(notice.canCopy)
        assertNull(notice.copiedLine)
        m.run({ vaults.bringLateIntoMove(notice) })
        val after = assertNotNull(api.snapshot.account).movesStoredOutside.single()
        assertEquals(CopyKey.MOVE_STORED_COPIED, assertNotNull(after.copiedLine).key)
        assertFalse(after.canCopy, "a second copy is not offered")
        m.act { vaults.dismissMoveStored(after) }
        assertTrue(assertNotNull(api.snapshot.account).movesStoredOutside.isEmpty())
        val view = src("AccountScreens.kt").substringAfter("internal fun MoveStoredOutsideNotice(").substringBefore("\n}\n")
        assertTrue("for (line in moveStoredLines(n)) Say(line)" in view, "information, not a warning about the server")
        assertEquals(listOf(UiText.of(notice.line).shown()), moveStoredLines(notice).map { it.shown() })
        assertTrue("vaults.bringLateIntoMove(n)" in view && "vaults.dismissMoveStored(n)" in view)
        assertTrue(src("AccountScreens.kt").contains("for (n in account.movesStoredOutside) MoveStoredOutsideNotice(model, s, n)"))
    }

    @Test
    fun theNewRefusalsSayTheSharedCodesSentences() {
        assertEquals(UiText.of(CopyKey.MOVE_WAITING_REFUSED).shown(), UiText.forResult(VaultActionResult.MOVE_DELETE_WAITING, 0)?.shown())
        assertEquals(UiText.of(CopyKey.ESCROW_WRONG_FORM).shown(), UiText.forResult(RecoveryChangeResult.ESCROW_WRONG_FORM, 0)?.shown())
    }
}
