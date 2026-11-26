package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.DeletedVaultView
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The owner's "Recently deleted" shared vaults on the content: what this device's log shows, while the list is open. */
class DeletedVaultsContentTest {
    // Not assertNull: its contract would smart-cast the (stable) property to Nothing? for the rest of the test.
    private fun closed(c: FakeVaultContent): Boolean = c.state.deletedVaults == null

    @Test
    fun theContentListsOnlyWhatThisDevicesLogShowsDeleted_andForgetsItOnClose() = runBlocking<Unit> {
        val c = FakeVaultContent()
        assertTrue(closed(c))
        val team = c.seedDeletedVault("Team", daysAgo = 1)
        c.seedDeletedVault("Claimed by the server only", daysAgo = 0, verified = false)
        val older = c.seedDeletedVault("Family", daysAgo = 3)
        assertEquals(ActionResult.Ok, c.openDeletedVaults())
        val listed: List<DeletedVaultView> = c.state.deletedVaults ?: error("the list is open")
        assertEquals(listOf(team, older), listed.map { v -> v.vaultId })
        assertEquals("Team", listed[0].name)
        c.closeDeletedVaults()
        assertTrue(closed(c))

        c.setOffline(true)
        assertTrue(c.openDeletedVaults() is ActionResult.Failed)
        assertTrue(closed(c))
    }
}
