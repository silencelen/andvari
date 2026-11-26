package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultClosedReason
import io.silencelen.andvari.core.client.items.ok
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The app interface's one call that closes a vault for writing, as the content says it, over the engine. */
class WriteClosedContentTest {
    private class Host(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    @Test
    fun aClosedVaultIsNotWritable_aChangeIsRefusedWithItsReason_andClearingOpensItAgain() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6)))
        r.server.itemRows[id] = r.itemRow(id, r.shared, r.sharedKey, rev = 6)
        val c = EngineVaultContent(r.engine, r.crypto, Host(r))
        assertTrue(c.state.items.single { it.itemId == id }.editable)

        c.markVaultClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        assertEquals(false, c.state.items.single { it.itemId == id }.editable, "no Edit while it is closed")
        val pushes = r.server.pushes.size
        assertEquals(ActionResult.Failed(CopyKey.VAULT_CLOSED_DELETION_WAITING.fill(emptyList())), c.deleteItem(id))
        assertEquals(pushes, r.server.pushes.size)

        c.markVaultClosedForWriting(r.shared, null)
        assertTrue(c.state.items.single { it.itemId == id }.editable)
        r.engine.sync().ok()
    }

    @Test
    fun theVaultListSaysWhyAVaultIsClosed_withItsLine_andANewItemForItIsRefusedWithThatLine() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6)))
        r.server.itemRows[id] = r.itemRow(id, r.shared, r.sharedKey, rev = 6)
        val c = EngineVaultContent(r.engine, r.crypto, Host(r))
        val open = c.state.vaults.single { it.vaultId == r.shared }
        assertEquals(ContentVaultState.WRITABLE to null, open.access to open.closedFor)
        assertNull(open.closedLine)

        c.markVaultClosedForWriting(r.shared, VaultClosedReason.DELETION_WAITING)
        val line = CopyKey.VAULT_CLOSED_DELETION_WAITING.fill(emptyList())
        val shut = c.state.vaults.single { it.vaultId == r.shared }
        assertEquals(ContentVaultState.CLOSED_FOR_WRITING, shut.access, "not taken for a reader's vault")
        assertEquals(VaultClosedReason.DELETION_WAITING, shut.closedFor)
        assertEquals(line, shut.closedLine, "the line beside the vault is the line its changes are refused with")
        assertEquals(false, shut.writable)
        assertEquals(c.state.vaults.single { it.personal }.let { it.access to it.closedLine }, ContentVaultState.WRITABLE to null, "only that vault")

        val pushes = r.server.pushes.size
        assertEquals(ActionResult.Failed(line), c.saveLogin(null, LoginInput("New", "n", "pn", emptyList(), "", "", false), r.shared))
        assertEquals(ActionResult.Failed(line), c.saveNote(null, NoteInput("Note", "text", false), r.shared))
        assertEquals(pushes, r.server.pushes.size, "nothing was sent")

        c.markVaultClosedForWriting(r.shared, null)
        val again = c.state.vaults.single { it.vaultId == r.shared }
        assertEquals(ContentVaultState.WRITABLE, again.access)
        assertNull(again.closedFor)
        assertNull(again.closedLine)
    }

    /**
     * A change of the vault waits here that this device cannot read, and it may be the vault's signed deletion: the vault
     * is closed as if it were, and the line beside it and every refusal say that it may be, never that it is signed.
     */
    @Test
    fun aWaitingChangeThisDeviceCannotRead_closesTheVaultWithALineOfItsOwn() = runBlocking<Unit> {
        val r = ItemRig()
        val id = r.id()
        r.openShared(items = listOf(r.itemRow(id, r.shared, r.sharedKey, rev = 6)))
        r.server.itemRows[id] = r.itemRow(id, r.shared, r.sharedKey, rev = 6)
        val c = EngineVaultContent(r.engine, r.crypto, Host(r))

        c.markVaultClosedForWriting(r.shared, VaultClosedReason.DELETION_MAY_BE_WAITING)
        val line = CopyKey.VAULT_CLOSED_DELETION_MAY_BE_WAITING.fill(emptyList())
        assertTrue(line != CopyKey.VAULT_CLOSED_DELETION_WAITING.fill(emptyList()), "a line of its own")
        val shut = c.state.vaults.single { it.vaultId == r.shared }
        assertEquals(ContentVaultState.CLOSED_FOR_WRITING to VaultClosedReason.DELETION_MAY_BE_WAITING, shut.access to shut.closedFor)
        assertEquals(line, shut.closedLine)
        val pushes = r.server.pushes.size
        assertEquals(ActionResult.Failed(line), c.deleteItem(id))
        assertEquals(ActionResult.Failed(line), c.saveLogin(null, LoginInput("New", "n", "pn", emptyList(), "", "", false), r.shared))
        assertEquals(pushes, r.server.pushes.size, "nothing was sent")

        // Kept in the account's cache by its name: it outlives a restart.
        assertEquals(VaultClosedReason.DELETION_MAY_BE_WAITING, r.restarted().closedForWriting(r.shared))
    }
}
