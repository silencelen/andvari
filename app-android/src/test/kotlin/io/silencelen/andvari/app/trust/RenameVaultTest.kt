package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Renaming a shared vault the account owns, through the vault content. */
class RenameVaultTest {
    private fun open(): Pair<FakeVaultContent, VaultContent> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        return assertNotNull(api.fakeContent) to assertNotNull(m.content.value)
    }

    @Test
    fun anOwnerRenamesTheVaultAndOthersAreRefusedInTheContentsWords() {
        val (fake, c) = open()
        fake.addSharedVault("shared-1", "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        fake.addSharedVault("shared-2", "Work", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)

        val done = runBlocking { c.renameSharedVault("shared-1", "  Household  ") }
        assertNull(renameSentence(done))
        assertTrue(c.state.vaults.any { it.vaultId == "shared-1" && it.name == "Household" }, "the name is trimmed and saved")

        val empty = runBlocking { c.renameSharedVault("shared-1", "   ") }
        assertIs<ActionResult.Failed>(empty)
        assertEquals(empty.message, renameSentence(empty), "an empty name is refused in the content's own sentence")

        val reader = runBlocking { c.renameSharedVault("shared-2", "Mine now") }
        assertIs<ActionResult.Failed>(reader)
        assertEquals(reader.message, renameSentence(reader))
    }

    @Test
    fun theControlIsOfferedToTheOwnerOfAWritableVaultAndCallsTheContent() {
        val code = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultScreens.kt").readText()
        // Beside the name on the vault's own page, as the current app's Rename (owner, writable, not deleted, open).
        val head = code.substringAfter("private fun VaultSettingsHead(")
        assertTrue(head.contains("val canRename = c != null && v.role == RoleInVault.OWNER && v.writable && !v.deleted"))
        assertTrue(code.substringAfter("internal fun SharedVaultSettings(").substringBefore("\n}\n").contains("VaultSettingsHead(model, s, v)"))
        assertTrue(code.contains("c.renameSharedVault(v.vaultId, name)"))
    }
}
