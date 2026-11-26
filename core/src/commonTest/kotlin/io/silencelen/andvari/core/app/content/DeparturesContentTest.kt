package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultDeparture
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.items.ok
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A vault's departure: an own leave or delete the server refused does not make a later, genuine departure of that vault
 * silent; and a held vault's line names the account's own delete as its own, never "by its owner".
 */
class DeparturesContentTest {
    private class Host(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    @Test
    fun aWithdrawnExpectation_letsALaterDepartureBeSaid() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared(items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey)))
        // The person's own leave, refused by the server: the host withdraws what it told the engine to expect.
        r.engine.expectDeparture(r.shared)
        r.engine.withdrawDeparture(r.shared)
        // Later, the owner removes this account: that is said.
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.REMOVED) }
        r.server.queue.add(r.response(r.server.rev + 100, removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertEquals(listOf(ItemNotice.REMOVED), r.engine.notices().map { it.kind })
    }

    @Test
    fun anExpectationNotWithdrawn_staysQuiet_asBefore() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared(items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey)))
        r.engine.expectDeparture(r.shared)
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.LEFT) }
        r.server.queue.add(r.response(r.server.rev + 100, removed = listOf(r.shared)))
        r.engine.sync().ok()
        assertTrue(r.engine.notices().isEmpty())
    }

    @Test
    fun theOwnersOwnDelete_isNotSaidToBeByItsOwner_overTheEngine() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared(role = VaultAccess.ROLE_OWNER, items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey)))
        r.server.echo = true
        val c = EngineVaultContent(r.engine, r.crypto, Host(r))
        r.keys.onServed = { report -> if (r.shared in report.lostAccess) r.keys.depart(r.shared, VaultDeparture.DELETED) }
        r.server.queue.add(r.response(r.server.rev + 100, removed = listOf(r.shared)))
        c.refresh()
        val line = c.state.held.single().line
        assertTrue(line.startsWith(deletedByYou), line)
        assertTrue("by its owner" !in line, line)
    }

    @Test
    fun aMembersHeldVault_stillSaysItsOwnerDeletedIt_andTheFakeAgrees() {
        val c = FakeVaultContent()
        val mine = "00000000-0000-4000-8000-0000000000cc"
        val theirs = "00000000-0000-4000-8000-0000000000aa"
        c.addSharedVault(mine, "Mine", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        c.addSharedVault(theirs, "Theirs", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.holdVault(mine, ItemNotice.DELETED, readable = true)
        c.holdVault(theirs, ItemNotice.DELETED, readable = true)
        val rows = c.state.held.associateBy { it.vaultId }
        assertTrue(rows.getValue(theirs).line.startsWith(CopyKey.HELD_DELETED_BY_OWNER.english.substringBefore("{0}") + keptUntil), rows.getValue(theirs).line)
        assertTrue(rows.getValue(mine).line.startsWith(deletedByYou), rows.getValue(mine).line)
    }

    /** Until when the copy is kept, by its key, whatever its words. */
    private val keptUntil: String = CopyKey.HELD_KEPT_UNTIL.english.substringBefore("{0}")

    /** The owner's own delete is said by its key, whatever its words, with the day it is kept until in its slot. */
    private val deletedByYou: String = CopyKey.HELD_DELETED_BY_YOU.english.substringBefore("{0}") + keptUntil
}
