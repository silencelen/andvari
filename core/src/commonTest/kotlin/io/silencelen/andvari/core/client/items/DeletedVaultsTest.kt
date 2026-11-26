package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.model.wire.DeletedVaultSummary
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The owner's "Recently deleted" shared vaults (spec 03 §11.2): served rows, checked and named on this device. */
class DeletedVaultsTest {
    private val day = 86_400_000L

    @Test
    fun theListIsNamedWithThisDevicesOwnKey_andMarkedByWhatItsLogShows() = runBlocking<Unit> {
        val r = ItemRig()
        val other = r.id()
        r.keys.put(r.shared, r.sharedKey)
        r.keys.depart(r.shared, VaultDeparture.DELETED, keepKey = true)
        val meta = r.codec.sealVaultMeta(r.sharedKey, r.shared, "Team")
        r.server.deletedVaultRows += DeletedVaultSummary(r.shared, meta, "wrap-never-opened", r.now - 2 * day, r.now + 5 * day, "AAAAAAAAAAAAAAAAAAAAAA==")
        // A vault this device holds no key for and whose deletion its log does not show: listed unnamed, unverified.
        r.server.deletedVaultRows += DeletedVaultSummary(other, meta, "w", r.now - 1 * day, r.now + 6 * day, "BBBBBBBBBBBBBBBBBBBBBB==")
        // Rows the engine drops: an id that is not a UUID, the personal vault, dates that are not a grace, a repeat.
        r.server.deletedVaultRows += DeletedVaultSummary("../x", meta, "w", r.now, r.now + day, "C")
        r.server.deletedVaultRows += DeletedVaultSummary(r.personal, meta, "w", r.now, r.now + day, "D")
        r.server.deletedVaultRows += DeletedVaultSummary(r.id(), meta, "w", r.now, r.now - day, "E")
        r.server.deletedVaultRows += DeletedVaultSummary(r.shared, meta, "w", r.now, r.now + day, "F")

        val list = (r.engine.deletedVaults() as ItemResult.Ok).value
        assertEquals(listOf(other, r.shared), list.map { it.vaultId }, "newest deletion first, one row per vault")
        val team = list.single { it.vaultId == r.shared }
        assertEquals(listOf<Any?>("Team", true, r.now + 5 * day), listOf(team.name, team.verified, team.purgeAt))
        val unknown = list.single { it.vaultId == other }
        assertNull(unknown.name)
        assertEquals(false, unknown.verified)
    }

    @Test
    fun offlineOrStopped_isAFailure_andNothingIsSentUnderAStoppedOrigin() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.offline = true
        assertTrue((r.engine.deletedVaults() as ItemResult.Failed).why is ItemFailure.Unreachable)
        r.server.offline = false
        r.engine.halt()
        val calls = r.server.calls
        assertEquals(ItemFailure.Halted, (r.engine.deletedVaults() as ItemResult.Failed).why)
        assertEquals(calls, r.server.calls)
    }
}
