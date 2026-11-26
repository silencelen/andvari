package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.client.items.HeldPick
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.model.wire.QuotaName
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [VaultContent.bringHeldItemsInto]: the items of a vault deleted behind a move's back, with their files, into the move's
 * new vault, checked for space first. Through the fake, whose controller is the real one.
 */
class BringHeldContentTest {
    private val old = "00000000-0000-4000-8000-0000000000aa"
    private val into = "00000000-0000-4000-8000-0000000000cc"
    private val ample = 1L shl 40

    private fun ActionResult.message(): String = (this as? ActionResult.Failed)?.message ?: error("expected Failed, got $this")

    /** The old vault with one login carrying two files, held here; the new vault, the account's own. */
    private fun rig(): Pair<FakeVaultContent, String> {
        val c = FakeVaultContent()
        c.addSharedVault(old, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        c.addSharedVault(into, "Family (new)", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val id = c.seedLogin(old, "Router", "admin", "pw", "")
        c.seedAttachment(id, "a.txt", "first".encodeToByteArray())
        c.seedAttachment(id, "b.txt", "second".encodeToByteArray())
        c.holdVault(old, ItemNotice.DELETED, readable = true)
        return c to id
    }

    @Test
    fun shortOfSpace_nothingIsSentAndTheScreenSaysWhichLimit() = runBlocking<Unit> {
        val (c, id) = rig()
        c.setRoomLeft(ample, 0, 0)
        val b = c.bringHeldItemsInto(old, into, listOf(HeldPick(id, null)))
        assertTrue(ContentCopy.isOutOfSpace(b.result.message()), b.result.message())
        assertEquals(emptyList(), b.made)
        assertEquals(SpaceFor.MOVE_OR_COPY to into, c.state.space?.forWhat to c.state.space?.vaultId)
        assertEquals(QuotaName.ITEMS, c.state.space?.limits?.single()?.quota)
        assertEquals(0, c.state.items.count { c.itemDetail(it.itemId)?.vaultId == into }, "nothing was copied")
        assertNull(c.state.copying)
    }

    @Test
    fun withRoom_theItemLandsWithBothFiles_aSecondRunCopiesNothing_andARunWithNothingLeftChecksNoSpace() = runBlocking<Unit> {
        val (c, id) = rig()
        c.setRoomLeft(ample, 1, 0)
        val b = c.bringHeldItemsInto(old, into, listOf(HeldPick(id, null)))
        assertEquals(ActionResult.Ok, b.result)
        val made = b.made.single()
        val copy = c.itemDetail(made.madeItemId)!!
        assertEquals(into to "Router", copy.vaultId to copy.name)
        assertEquals(listOf("a.txt", "b.txt"), copy.attachments.map { it.name })
        assertEquals("second", c.readAttachment(made.madeItemId, copy.attachments[1].id).bytes?.decodeToString())

        // The meter is full now: a second run has nothing left to copy, so nothing is checked and nothing refused.
        c.setRoomLeft(ample, 0, 0)
        val again = c.bringHeldItemsInto(old, into, listOf(HeldPick(id, made.madeItemId)))
        assertEquals(ActionResult.Ok, again.result)
        assertEquals(listOf(made.madeItemId), again.made.map { it.madeItemId })
        assertNull(c.state.space)
        assertEquals(1, c.state.items.count { c.itemDetail(it.itemId)?.vaultId == into })
    }

    @Test
    fun aVaultClosedForWritingTakesNothing_andSaysWhy() = runBlocking<Unit> {
        val (c, id) = rig()
        c.markVaultClosedForWriting(into, VaultClosedReason.DELETION_WAITING)
        val b = c.bringHeldItemsInto(old, into, listOf(HeldPick(id, null)))
        assertEquals(ContentCopy.closedForWriting(VaultClosedReason.DELETION_WAITING), b.result.message())
        assertEquals(emptyList(), b.made)
    }

    @Test
    fun anItemThePersonDeletedWhileItsVaultClosed_isNotCopied_itsEarlierCopyGoes_andTheNoticeCountsOnlyCopies() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(old, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        c.addSharedVault(into, "Family (new)", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val gone = c.seedLogin(old, "Old bank", "admin", "pw", "")
        val kept = c.seedLogin(old, "Router", "admin", "pw", "")
        c.seedAttachment(kept, "a.txt", "first".encodeToByteArray())
        c.setRoomLeft(ample, 10, 0)
        // The move copied both while the vault was open.
        val first = c.bringHeldItemsInto(old, into, listOf(HeldPick(gone, null), HeldPick(kept, null))).made.associateBy { it.itemId }
        // Offline, the person deletes one and edits the other; then the vault is closed for writing.
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.deleteItem(gone))
        assertEquals(ActionResult.Ok, c.saveLogin(kept, io.silencelen.andvari.core.app.LoginInput("Router (edited)", "admin", "pw", emptyList(), "", "", false), old))
        c.markVaultClosedForWriting(old, VaultClosedReason.DELETION_WAITING)
        c.setOffline(false)

        val b = c.bringHeldItemsInto(old, into, listOf(HeldPick(gone, first.getValue(gone).madeItemId, first.getValue(gone).madeRev), HeldPick(kept, first.getValue(kept).madeItemId, first.getValue(kept).madeRev)))
        assertEquals(ActionResult.Ok, b.result)
        assertEquals(listOf(kept), b.made.map { it.itemId }, "only the edited item is copied")
        assertEquals(listOf(gone to first.getValue(gone).madeItemId), b.deleted.map { it.itemId to it.earlier })
        val inNew = c.state.items.filter { c.itemDetail(it.itemId)?.vaultId == into }.map { it.name }
        assertEquals(listOf("Router (edited)"), inNew, "the item the person deleted is not in the new vault")
    }
}
