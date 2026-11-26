package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A move or a copy names the item it made; the fake holds back what waits for a vault closed for writing, as the engine
 * does, and its vault list says why such a vault is closed.
 */
class MoveMadeContentTest {
    private val family = "00000000-0000-4000-8000-0000000000aa"
    private val other = "00000000-0000-4000-8000-0000000000cc"

    @Test
    fun aMoveAndACopyNameTheItemTheyMade_andARefusedOneNamesNone() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        c.addSharedVault(other, "Readers", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        val a = c.seedLogin(family, "A", "a", "pa", "")
        val b = c.seedLogin(family, "B", "b", "pb", "")

        val moved = c.moveOrCopyItemWithId(a, FakeVaultContent.PERSONAL_VAULT_ID, move = true)
        assertEquals(ActionResult.Ok, moved.result)
        val made = assertNotNull(moved.madeItemId)
        assertEquals(FakeVaultContent.PERSONAL_VAULT_ID to "A", c.itemDetail(made)?.vaultId to c.itemDetail(made)?.name)

        val copied = c.moveOrCopyItemWithId(b, FakeVaultContent.PERSONAL_VAULT_ID, move = false)
        assertEquals(ActionResult.Ok, copied.result)
        assertEquals("B", c.itemDetail(assertNotNull(copied.madeItemId))?.name)
        assertEquals(family, c.itemDetail(b)?.vaultId, "a copy leaves the original")

        val refused = c.moveOrCopyItemWithId(b, other, move = false)
        assertEquals(ActionResult.Failed::class, refused.result::class)
        assertNull(refused.madeItemId)
        assertEquals(refused.result, c.moveOrCopyItem(b, other, move = false), "the old call answers the same")
    }

    @Test
    fun theFakeRefusesASaveEditOrDeleteIntoAVaultClosedForWriting_asTheEngineDoes() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val a = c.seedLogin(family, "A", "a", "pa", "")
        c.markVaultClosedForWriting(family, VaultClosedReason.DELETION_WAITING)
        val line = ContentCopy.closedForWriting(VaultClosedReason.DELETION_WAITING)
        // A new item is refused with why the vault is closed, not with the general "can't add items to that vault".
        assertEquals(ActionResult.Failed(line), c.saveLogin(null, LoginInput("New", "n", "pn", emptyList(), "", "", false), family))
        assertEquals(ActionResult.Failed(line), c.saveLogin(a, LoginInput("A (edited)", "a", "pa", emptyList(), "", "", false), family))
        assertEquals(ActionResult.Failed(line), c.deleteItem(a))
        assertEquals("A", c.serverDoc(a)?.name)
        assertEquals(1, c.state.items.count { c.itemDetail(it.itemId)?.vaultId == family }, "nothing was added")
    }

    @Test
    fun theFakesVaultListSaysWhyAVaultIsClosed_andAMoveOrCopyIntoItIsRefusedWithThatLine() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        c.addSharedVault(other, "Readers", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        val mine = c.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mine", "m", "pm", "")
        c.markVaultClosedForWriting(family, VaultClosedReason.DELETION_WAITING)
        val line = ContentCopy.closedForWriting(VaultClosedReason.DELETION_WAITING)

        val shut = c.state.vaults.single { it.vaultId == family }
        assertEquals(ContentVaultState.CLOSED_FOR_WRITING, shut.access)
        assertEquals(VaultClosedReason.DELETION_WAITING, shut.closedFor)
        assertEquals(line, shut.closedLine)
        val reader = c.state.vaults.single { it.vaultId == other }
        assertEquals(ContentVaultState.READER, reader.access, "a reader's vault is still a reader's")
        assertNull(reader.closedFor)
        assertNull(reader.closedLine)

        assertEquals(ActionResult.Failed(line), c.moveOrCopyItem(mine, family, move = false))
        assertEquals(ActionResult.Failed(line), c.moveOrCopyItem(mine, family, move = true))
        assertEquals(ActionResult.Failed(ContentCopy.VAULT_NOT_WRITABLE), c.moveOrCopyItem(mine, other, move = false), "a reader's vault keeps the general line")
        assertEquals(ActionResult.Failed(ContentCopy.VAULT_NOT_WRITABLE), c.saveLogin(null, LoginInput("New", "n", "pn", emptyList(), "", "", false), other))
        assertEquals(FakeVaultContent.PERSONAL_VAULT_ID, c.itemDetail(mine)?.vaultId, "nothing moved")
        assertEquals(1, c.state.items.size, "nothing was copied")

        c.markVaultClosedForWriting(family, null)
        assertEquals(ContentVaultState.WRITABLE to null, c.state.vaults.single { it.vaultId == family }.let { it.access to it.closedLine })
    }

    @Test
    fun theFakeHoldsBackWhatWaitsForAVaultClosedForWriting_untilTheMarkGoes() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        val a = c.seedLogin(family, "A", "a", "pa", "")
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(a, LoginInput("A (edited)", "a", "pa", emptyList(), "", "", false), family))
        c.markVaultClosedForWriting(family, VaultClosedReason.DELETION_WAITING)
        c.setOffline(false)
        c.refresh()
        assertEquals("A", c.serverDoc(a)?.name, "nothing is sent into a vault whose deletion waits")
        c.markVaultClosedForWriting(family, null)
        c.refresh()
        assertEquals("A (edited)", c.serverDoc(a)?.name)
    }
}
