package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Three new states from the shared code on the desktop, and the approved
 * words of the SERVER_* and LINK_REQUIRED_* keys now taken from the shared code.
 */
class SharedCodeStatesTest {
    private fun source(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    @Test
    fun theApprovedWordsComeFromTheSharedCodeAndDidNotChange() {
        // Each key against the approved entry the desktop used to show for it: the same words, character for character.
        val entries = mapOf(
            CopyKey.SERVER_CREATE_ACCOUNT to "SERVER_CREATE_ACCOUNT.button0",
            CopyKey.SERVER_SIGN_IN to "SERVER_CREATE_ACCOUNT.button1",
            CopyKey.SERVER_INVITATION_ONLY to "SERVER_INVITATION_ONLY.body",
            CopyKey.SERVER_NOT_TAKING_ACCOUNTS to "SERVER_NOT_TAKING_ACCOUNTS.body",
            CopyKey.LINK_REQUIRED_TITLE to "LINK_REQUIRED.title",
            CopyKey.LINK_REQUIRED_BODY to "LINK_REQUIRED.body",
        )
        for ((key, id) in entries) {
            assertFalse(key.reserved, "$key is worded in the shared code")
            assertFalse(key.awaitingOwner, "$key")
            assertEquals(ApprovedCopy.text.getValue(id), key.english, "$key: the approved words, unchanged")
            val shown = UiText.of(key)
            assertIs<UiText.Plain>(shown)
            assertEquals(key.english, shown.shown())
        }
        // The desktop's own copies are gone: nothing maps a key of core's to words of the desktop's.
        assertFalse(source("ApprovedCopy.kt").contains("CopyKey."))
        assertFalse(source("UiText.kt").contains("ApprovedCopy.reserved"))
        // A key core still reserves is a visible placeholder, never words of the desktop's.
        CopyKey.entries.firstOrNull { it.reserved }?.let { assertIs<UiText.Ph>(UiText.of(it)) }
    }

    @Test
    fun aCompletedDeletionIsCoresNoticeOnTheFirstScreen() {
        // Core's line, by its key: it reads as unfinished exactly while it awaits the owner's words, like the desktop's own.
        assertEquals(CopyKey.ACCOUNT_DELETED_DONE.awaitingOwner, UiText.of(CopyKey.ACCOUNT_DELETED_DONE).isPlaceholder)
        val first = source("EntryScreens.kt").substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        assertTrue(first.contains("screen.accountDeleted?.let"))
        assertTrue(first.contains("entry.dismissNotice(screen)"))
        assertFalse(source("TrustModel.kt").contains("deletedFlow"), "the desktop's own flag is gone")
    }

    @Test
    fun liveUpdatesThatDoNotConnectAreOneQuietLineOnTheOpenVault() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(assertNotNull(api.snapshot.account).liveUpdates.line, "connected: nothing")
        val server = assertNotNull(api.script.server(assertNotNull(api.snapshot.instance).label.origin))
        server.liveUpdatesConnect = false
        api.lock()
        kotlinx.coroutines.runBlocking { api.unlock(assertNotNull(api.snapshot.locked), FakeScenes.PASSWORD) }
        val line = assertNotNull(assertNotNull(api.snapshot.account).liveUpdates.line)
        assertEquals(CopyKey.LIVE_UPDATES_NOT_CONNECTED, line.key)
        assertEquals(line.key.awaitingOwner, UiText.of(line).isPlaceholder, "unfinished exactly while it awaits the owner's words")
        val shell = source("AccountScreens.kt").substringAfter("private fun SignedInPages(").substringBefore("\n}\n")
        assertTrue(shell.contains("account.liveUpdates.line?.let { Quiet(UiText.of(it)) }"), "one quiet line")
    }

    @Test
    fun aSharedVaultOutOfSpaceSaysWhoseSpaceItIs() {
        val api = FakeScenes.desktopAt(FakeScene.VAULT_STATES)
        val row = assertNotNull(api.snapshot.account).vaults.first { it.ownerOutOfSpace }
        val line = assertNotNull(row.outOfSpaceLine)
        val expected = if (row.role == RoleInVault.OWNER) CopyKey.OWNER_OUT_OF_SPACE_YOURS else CopyKey.OWNER_OUT_OF_SPACE_THEIRS
        assertEquals(expected, line.key)
        val shown = UiText.of(line)
        assertFalse(shown.isPlaceholder, "approved entries 27 and 28")
        assertEquals(expected.english, shown.shown())
        val vaults = source("VaultScreens.kt")
        assertTrue(vaults.contains("Quiet(UiText.of(CopyKey.OWNER_OUT_OF_SPACE))") && vaults.contains("v.outOfSpaceLine?.let { Quiet(UiText.of(it)) }"))
        assertTrue(vaults.indexOf("UiText.of(CopyKey.OWNER_OUT_OF_SPACE))") < vaults.indexOf("v.outOfSpaceLine?.let"), "under OWNER_OUT_OF_SPACE")
    }
}
