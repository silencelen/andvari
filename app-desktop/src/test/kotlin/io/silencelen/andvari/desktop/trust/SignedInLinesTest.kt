package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultClosedReason
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** What the shared code says above the open vault and beside a vault, drawn where it belongs. */
class SignedInLinesTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")

    /** A vault closed for writing here says why above its items when the list is filtered to it, and in an item's view. */
    @Test
    fun aVaultClosedForWritingSaysWhyBesideTheVault() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        val c = assertNotNull(m.content.value)
        val vault = c.state.vaults.first()
        assertTrue(closedVaultLines(c.state, null).isEmpty())
        c.markVaultClosedForWriting(vault.vaultId, VaultClosedReason.DELETION_WAITING)
        val state = c.state
        val line = assertNotNull(state.vaults.first { it.vaultId == vault.vaultId }.closedLine)
        assertEquals(listOf(line), closedVaultLines(state, null))
        assertEquals(listOf(line), closedVaultLines(state, vault.vaultId))
        assertEquals(line, closedLineOf(state, vault.vaultId))
        state.vaults.firstOrNull { it.vaultId != vault.vaultId }?.let { other -> assertTrue(closedVaultLines(state, other.vaultId).isEmpty()) }
        assertTrue(body("VaultItemsScreens.kt", "private fun VaultItemsList(").contains("closedVaultLines(state, vaultFilter)"))
        assertTrue(body("VaultItemsScreens.kt", "private fun ItemDetailView(").contains("closedLineOf(state, d.vaultId)"))
    }

    /** The line after a sign-in over a copy sealed under another master password: once, above the vault, until dismissed. */
    @Test
    fun theLineAfterASignInOverACopyUnderAnotherPasswordIsShownOnceAndDismissed() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        api.script.sessionEndedByServer()
        m.signInAgain()
        api.script.signInOverOtherPasswordCopy = true
        m.act { entry.openSignIn(assertIs(api.snapshot.entry)) }
        m.act { entry.openPasswordSignIn(assertIs(api.snapshot.entry)) }
        m.run({ entry.choosePublicInstance(assertIs(api.snapshot.entry)) })
        m.run({ entry.submitSignIn(assertIs<EntryScreen.SignIn>(api.snapshot.entry), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertEquals(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER, assertNotNull(api.snapshot.account?.signInNotice).key)
        api.dismissSignInNotice()
        assertNull(api.snapshot.account?.signInNotice)
        assertTrue(body("AccountScreens.kt", "private fun AttentionArea(").contains("account.signInNotice?.let { NoticeBar(UiText.of(it)) { model.quietly { model.api.dismissSignInNotice() } } }"))
    }
}
