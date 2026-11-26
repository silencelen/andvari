package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PW
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.await
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.HeldPick
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The pretend content plays what the engine does with changes not sent yet: parked with the held copy when their vault
 * leaves (never sent, never dropped by the leaving, carried by "bring them into another vault"), and kept, read-only,
 * when the server ends the session, to be sent at the next sign-in ([ServerEndedCopyTest] is the engine's side).
 */
class FakeWaitingChangesTest {
    private val shared = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"

    private fun login(name: String, password: String = "pw-$name") = LoginInput(name, "me", password, listOf("https://${name.lowercase()}.test"), "", "", false)

    @Test
    fun changesWaitingWhenTheirVaultLeft_areParkedWithTheHeldCopy_neverSent_andCarriedIntoAnotherVault() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.addSharedVault(shared, "Family", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val wifi = c.seedLogin(shared, "Wifi", "me", "old", "https://wifi.test")
        val old = c.seedLogin(shared, "Old", "me", "pw", "https://old.test")
        c.syncQuietly()
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(wifi, login("Wifi", "edited offline"), shared))
        assertEquals(ActionResult.Ok, c.deleteItem(old))
        assertEquals(setOf(wifi, old), c.waitingChanges(shared))
        assertEquals(2, c.state.queued)

        c.holdVault(shared, "removed", readable = true)
        // Parked, as the engine parks them: out of the queue and the list, named for the held vault.
        assertEquals(0, c.state.queued)
        assertEquals(setOf(wifi, old), c.waitingChanges(shared))
        assertTrue(c.state.items.none { it.itemId == wifi || it.itemId == old }, "nothing of the vault that left is in the list")
        assertEquals(shared, c.state.held.single().vaultId)

        // The server answers again: nothing parked is sent anywhere.
        c.setOffline(false)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertTrue(c.state.items.none { it.vaultId == shared })
        assertEquals(setOf(wifi, old), c.waitingChanges(shared))

        // Brought into the personal vault: the edit is the copy's content, the deletion is carried (no copy of it).
        val b = c.bringHeldItemsInto(shared, FakeVaultContent.PERSONAL_VAULT_ID, listOf(HeldPick(wifi, null), HeldPick(old, null)))
        val made = b.made.single()
        assertEquals(wifi, made.itemId)
        assertEquals(listOf(old), b.deleted.map { it.itemId })
        assertEquals("edited offline", c.revealSecret(made.madeItemId, io.silencelen.andvari.core.app.SecretField.PASSWORD))
        assertTrue(c.state.items.none { it.name == "Old" })
    }

    @Test
    fun aSessionTheServerEnded_keepsTheQueueReadOnly_andTheSignInAgainSendsIt() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.setOffline(true)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Train"), null))
        assertEquals(1, c.state.queued)

        c.endedByServer()
        assertTrue(c.state.serverStopped)
        assertEquals(ContentCopy.SERVER_STOPPED, (c.saveLogin(null, login("New"), null) as ActionResult.Failed).message)
        c.close()
        // The next unlock opens the same copy, still read-only, with what waits.
        val reopened = c.reopened()
        assertTrue(reopened.state.serverStopped)
        assertEquals(1, reopened.state.queued)
        reopened.close()

        // Signed in again: the same copy, writable; its next sync sends what waited.
        val again = reopened.signedInAgain()
        again.setOffline(false)
        assertEquals(ActionResult.Ok, again.syncQuietly())
        assertEquals(0, again.state.queued)
        assertTrue(again.state.items.any { it.name == "Train" && !it.pendingSync })
    }

    /**
     * What the fake app interface counts after the server's end, today: its own end drops the open content and opens a
     * new, empty one at the next unlock, so a change saved offline before is counted as 0 there, where the engine keeps
     * it (its copy is the device's cache file) and counts 1. The fake's app interface keeps the content once it reopens
     * [FakeVaultContent.endedByServer]'s copy; this records the difference until then.
     */
    @Test
    fun theFakeAppInterfaceAfterTheServersEnd_countsWhatItsNewContentHolds_today() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        val c = assertNotNull(app.fakeContent)
        c.setOffline(true)
        assertEquals(ActionResult.Ok, await { c.saveLogin(null, login("Bank"), null) })
        assertEquals(1, assertNotNull(app.signOutCheck()).unsentChanges)

        app.script.sessionEndedByServer()
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(locked, PW) })
        val after = assertNotNull(app.signOutCheck()).unsentChanges
        // As the engine (EngineUnsentAtSignOutTest, ServerEndedCopyTest): the server's end keeps what waited.
        assertEquals(1, after, "the fake's own end keeps the open content's queue")
    }
}
