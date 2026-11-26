package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The lines the shared code gained: the open vault's quiet
 * line while live updates are not connected, and whose space it is when a shared vault's owner is out of space. The
 * first screen's deletion notice is in [AccountDeletionTest]; the approved words that moved into the shared code are
 * pinned in [ApprovedCopyTest].
 */
class SharedCodeLinesTest {
    private val scope = CoroutineScope(Dispatchers.Unconfined)

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, scope, BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun liveUpdatesThatDoNotConnectAreOneQuietLineOnTheOpenVaultThatGoesWhenTheyConnect() {
        val (api, _) = at(FakeScene.VAULTS)
        assertTrue(assertNotNull(api.snapshot.account).liveUpdates.connected)
        assertNull(liveUpdatesLine(assertNotNull(api.snapshot.account)), "connected: nothing is said")

        val server = assertNotNull(api.script.server(assertNotNull(api.snapshot.instance).label.origin))
        server.liveUpdatesConnect = false
        api.script.changed()
        val line = assertNotNull(liveUpdatesLine(assertNotNull(api.snapshot.account)))
        // The shared code's line, named by its key and shown the way the app shows that key (whatever its words are).
        assertEquals(UiText.of(CopyKey.LIVE_UPDATES_NOT_CONNECTED).shown(), line.shown())

        server.liveUpdatesConnect = true
        api.script.changed()
        assertNull(liveUpdatesLine(assertNotNull(api.snapshot.account)), "it goes the moment they connect")

        // On the vault page (the home screen), as a quiet line above the items: never a dialog, an error or a badge.
        val shell = src("AccountScreens.kt").substringAfter("fun AccountShell(").substringBefore("\n}\n")
        assertTrue(shell.contains("SignedInPage.VAULT -> VaultItemsSection(model, header = {\n            header()\n            liveUpdatesLine(account)?.let { Quiet(it) }"))
    }

    @Test
    fun aSharedVaultOutOfSpaceSaysWhoseSpaceItIsInTheApprovedWords() {
        val (api, _) = at(FakeScene.VAULT_STATES)
        val vaults = assertNotNull(api.snapshot.account).vaults
        val full = vaults.first { it.ownerOutOfSpace }
        val words = assertNotNull(outOfSpaceLine(full))
        assertFalse(words.isPlaceholder)
        assertEquals(
            if (full.role == RoleInVault.OWNER) "This wasn't saved. You own this vault: remove items or attachments you no longer need, or ask the operator for more space."
            else "This wasn't saved. Ask the vault's owner to free up space.",
            words.shown(),
        )
        assertEquals(full.outOfSpaceLine?.key, if (full.role == RoleInVault.OWNER) CopyKey.OWNER_OUT_OF_SPACE_YOURS else CopyKey.OWNER_OUT_OF_SPACE_THEIRS)
        for (row in vaults.filter { !it.ownerOutOfSpace }) assertNull(outOfSpaceLine(row), "${row.vaultId}: no line when there is space")
    }

    @Test
    fun theSharedCodesNewKeysThatAwaitTheOwnerShowAsPlaceholders() {
        for (key in CopyKey.entries.filter { it.awaitingOwner }) {
            val ph = assertIs<UiText.Ph>(UiText.of(key), "$key")
            assertEquals(Placeholder.AWAITING_OWNER, ph.placeholder)
            assertTrue(ph.shown().startsWith("⟦") && ph.shown().endsWith("⟧"), ph.shown())
            assertFalse(ph.shown().contains("⟦⟦"), "the shared code's own brackets are not doubled: ${ph.shown()}")
        }
    }
}
