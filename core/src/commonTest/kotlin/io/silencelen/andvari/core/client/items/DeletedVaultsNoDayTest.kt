package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.content.EngineVaultContent
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.model.wire.DeletedVaultSummary
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The owner's "Recently deleted" shared vaults where the server served no day for a vault's grace (its `purgeAt` is
 * empty, which reads as 0): the vault is still listed by its own mark (this device's verified log shows its owner's
 * `delete`), with no day, and the content hands the line without a day in place of a date. Over the real item engine.
 */
class DeletedVaultsNoDayTest {
    private val day = 86_400_000L

    /** [shared] deleted in this device's log and served with no day; a second vault deleted and served with its day. */
    private fun rig(): Pair<ItemRig, String> {
        val r = ItemRig()
        r.keys.put(r.shared, r.sharedKey)
        r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true)
        val meta = r.codec.sealVaultMeta(r.sharedKey, r.shared, "Team")
        r.server.deletedVaultRows += DeletedVaultSummary(r.shared, meta, "wrap-never-opened", r.now - 2 * day, 0L, "AAAAAAAAAAAAAAAAAAAAAA==")
        val other = r.id()
        val otherKey = r.crypto.randomBytes(32)
        r.keys.put(other, otherKey)
        r.keys.depart(other, VaultDeparture.DELETED, keepKey = true)
        r.server.deletedVaultRows += DeletedVaultSummary(other, r.codec.sealVaultMeta(otherKey, other, "Family"), "w", r.now - 3 * day, r.now + 4 * day, "BBBBBBBBBBBBBBBBBBBBBB==")
        return r to other
    }

    @Test
    fun aVaultWhoseGraceEndTheServerDidNotServeIsListedWithNoDay() = runBlocking<Unit> {
        val (r, _) = rig()
        // A row with no day for a vault whose deletion this device's log does not show stays dropped (a purge before the deletion).
        val unmarked = r.id()
        r.server.deletedVaultRows += DeletedVaultSummary(unmarked, "m", "w", r.now - day, 0L, "CCCCCCCCCCCCCCCCCCCCCC==")
        val list = (r.engine.deletedVaults() as ItemResult.Ok).value
        assertTrue(list.none { it.vaultId == unmarked }, "no mark of its own: dropped")
        val team = list.singleOrNull { it.vaultId == r.shared }
        assertEquals(listOf<Any?>("Team", true, 0L), listOf(team?.name, team?.verified, team?.purgeAt), "listed by its own mark, with no day")
    }

    @Test
    fun theContentHandsTheMarkTheDayOnlyWhereServedAndElseTheLineWithoutADay() = runBlocking<Unit> {
        val (r, other) = rig()
        val content = EngineVaultContent(r.engine, r.crypto, Host(r))
        assertEquals(ActionResult.Ok, content.openDeletedVaults())
        val listed = content.state.deletedVaults ?: error("the list is open")
        assertEquals(listOf(r.shared, other), listed.map { it.vaultId }, "newest deletion first, both listed")
        val team = listed[0]
        assertTrue(team.deleted, "the vault's own mark")
        assertEquals(0L, team.purgeAtMs, "no day where the server served none")
        assertEquals(CopyKey.VAULT_DELETED_NO_DAY, team.deletedNoDayLine?.key)
        val family = listed[1]
        assertTrue(family.deleted)
        assertEquals(r.now + 4 * day, family.purgeAtMs, "the served day")
        assertNull(family.deletedNoDayLine, "a served day is named, so no line without one")
    }

    /** The stand-in content plays the same: a vault seeded with no day served hands the line without a day. */
    @Test
    fun theStandInHandsTheSame() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val none = c.seedDeletedVault("Team", daysAgo = 1, dayServed = false)
        val served = c.seedDeletedVault("Family", daysAgo = 2)
        assertEquals(ActionResult.Ok, c.openDeletedVaults())
        val listed = c.state.deletedVaults ?: error("the list is open")
        assertEquals(listOf(none, served), listed.map { it.vaultId })
        assertEquals(listOf(0L), listOf(listed[0].purgeAtMs))
        assertEquals(CopyKey.VAULT_DELETED_NO_DAY, listed[0].deletedNoDayLine?.key)
        assertTrue(listed[1].purgeAtMs > 0L)
        assertNull(listed[1].deletedNoDayLine)
    }

    private class Host(val r: ItemRig) : io.silencelen.andvari.core.app.content.ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = io.silencelen.andvari.core.app.AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): io.silencelen.andvari.core.crypto.KdfParams? = null
    }
}
