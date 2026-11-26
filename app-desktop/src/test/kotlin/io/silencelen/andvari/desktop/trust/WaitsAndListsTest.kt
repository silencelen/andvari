package io.silencelen.andvari.desktop.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** A server's wait said as a length of time, and which list of vaults the desktop has. By key. */
class WaitsAndListsTest {
    private val dir = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/")

    private fun ph(t: UiText) = assertIs<UiText.Ph>(t).let { it.placeholder to it.args }

    @Test
    fun aWaitIsSaidAsALengthOfTimeRoundedUpAndAsAWhileWhereNoneIsNamed() {
        assertEquals(Placeholder.WAIT_A_WHILE to emptyList(), ph(waitText(0)))
        assertEquals(Placeholder.WAIT_A_WHILE to emptyList(), ph(waitText(-5)))
        assertEquals(Placeholder.WAIT_SECONDS to listOf("42"), ph(waitText(42)))
        assertEquals(Placeholder.WAIT_SECONDS to listOf("119"), ph(waitText(119)))
        assertEquals(Placeholder.WAIT_MINUTES to listOf("2"), ph(waitText(120)))
        assertEquals(Placeholder.WAIT_MINUTES to listOf("3"), ph(waitText(121)), "never shorter than the server's")
        assertEquals(Placeholder.WAIT_HOURS to listOf("2"), ph(waitText(7200)))
        assertEquals(Placeholder.WAIT_HOURS to listOf("3"), ph(waitText(7201)))
        // No line of the desktop puts a bare number of seconds into a wait any more.
        val all = dir.walkTopDown().filter { it.isFile }.joinToString("\n") { it.readText() }
        assertFalse(all.contains("retryAfterSeconds.toString()"))
        assertFalse(all.contains("\"wait \${retryAfterSeconds}s\""))
    }

    /**
     * Two lines of the shared code point to "your deleted vaults". The desktop has no list of that name: it never reads
     * the content's list of deleted vaults ([io.silencelen.andvari.core.app.content.ContentState.deletedVaults]); a shared
     * vault this account deleted, still restorable, is a row of the shared vaults' list, marked as deleted with the day
     * until which it can be restored, and offering Restore. "Recently removed" is another list: vaults no longer shared
     * with this account.
     */
    @Test
    fun theDesktopHasNoListCalledDeletedVaultsOnlyDeletedRowsInTheSharedVaultsList() {
        val all = dir.walkTopDown().filter { it.isFile }.joinToString("\n") { it.readText() }
        // (An account deletion's plan has a list of its own by that name, of what the deletion takes: not this one.)
        assertFalse(all.contains("openDeletedVaults(") || all.contains("state.deletedVaults"), "the content's list of deleted vaults is not drawn")
        assertFalse(Placeholder.entries.any { it.name.contains("DELETED_VAULTS") })
        val vaults = File(dir, "VaultScreens.kt").readText()
        assertTrue(vaults.contains("Placeholder.VAULT_DELETED_IN_GRACE") && vaults.contains("vaults.restoreVault(v)"))
        val removed = File(dir, "VaultItemsScreens.kt").readText().substringAfter("private fun RecentlyRemovedSection(").substringBefore("\n}\n")
        assertTrue(removed.contains("Placeholder.RECENTLY_REMOVED") && removed.contains("state.held"), "Recently removed lists the held vaults")
    }
}
