package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.session.SessionEndReason
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §4.4, "A session the server ends does not delete the device's copy". The app interface composes the content
 * of an account the server signed out over an engine it halted ([ItemEngine.halt]); that content opens read-only from
 * the copy, the way a forked server's does: read, revealed, filled from, nothing sent and nothing written, and every
 * kept record left as it is. Signing in again sends what was not sent.
 */
class ServerEndedCopyTest {
    private class Stores {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
        val fill = InMemoryFillSnapshots()
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun content(r: ItemRig, engine: ItemEngine, s: Stores): EngineVaultContent {
        r.server.echo = true
        r.server.journal = true
        return EngineVaultContent(engine, r.crypto, TestHost(r), ContentKeeping(unlock(r), s.moves, s.keptSaves, s.files, s.applied, s.queue, s.fill))
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test".lowercase()), "", "", false)


    @Test
    fun aCopyTheServerSignedOut_opensReadOnly_sendsAndWritesNothing_andSignInAgainSendsWhatWaited() = runBlocking<Unit> {
        // A durable cache, as on a device: a save made offline is queued in it.
        val r = ItemRig(io.silencelen.andvari.core.client.items.DurableCache())
        r.openShared()
        val s = Stores()
        val a = content(r, r.engine, s)
        a.syncQuietly()
        a.saveLogin(null, login("Wifi"), null)
        val wifi = a.state.items.single().itemId
        // A move a lock cut short, a save with a file a lock cut short, and an edit made offline: all not yet sent.
        r.server.offlineAfterNextPush = true
        a.moveOrCopyItem(wifi, r.shared, true)
        r.server.offline = true
        assertEquals(ActionResult.Ok, a.saveLogin(null, login("Offline"), null), "queued for the next sync")
        a.openAttachmentDraft(null)
        a.addAttachment("scan.pdf", "page one".encodeToByteArray())
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, (a.saveLogin(null, login("Passport"), null) as ActionResult.Failed).message)
        a.close()
        SaveQueue.enqueue(s.queue, r.crypto, "https://shop.test/login", "ana", "s3cret", r.now, "safari")
        val moves = assertNotNull(s.moves.bytes)
        val keptSaves = assertNotNull(s.keptSaves.bytes)
        val files = s.files.ids().toSet()
        val queued = s.queue.map.keys.toSet()
        r.server.offline = false

        // The server refused the refresh: the app interface keeps the copy and composes it over a halted engine.
        val stopped = r.restarted().also { it.halt() }
        val calls = r.server.calls
        val judged = r.gate.judged
        s.fill.bytes = null
        val b = content(r, stopped, s)
        b.reload()
        assertTrue(b.state.serverStopped)
        val names = b.state.items.map { it.name }.toSet()
        assertTrue("Offline" in names && "Wifi" in names, "$names")
        val offline = b.state.items.single { it.name == "Offline" }.itemId
        assertEquals("pw-Offline", b.revealSecret(offline, SecretField.PASSWORD), "read and copied from")
        assertEquals("pw-Offline", b.fillCredential(offline)?.password, "filled from")
        assertEquals(ContentCopy.SERVER_STOPPED, (b.saveLogin(null, login("New"), null) as ActionResult.Failed).message)
        assertEquals(ContentCopy.SERVER_STOPPED, (b.moveOrCopyItem(wifi, r.shared, true) as ActionResult.Failed).message)
        assertEquals(ContentCopy.SERVER_STOPPED, (b.readSaveQueue() as ActionResult.Failed).message)
        assertEquals(ContentCopy.SERVER_STOPPED, (b.dismissAppliedSaves() as ActionResult.Failed).message)
        assertEquals(ContentCopy.SERVER_STOPPED, (b.refresh() as ActionResult.Failed).message)
        val fed = assertNotNull(s.fill.bytes, "the extension is fed from the copy")
        assertTrue(FillSnapshotVault.readBytes(r.crypto, fed, "https://vault.example.com", r.userId) { p, x -> unlock(r).openUnderVaultKey(r.crypto, p, x) } is FillSnapshotRead.Opened)
        b.close()
        assertEquals(calls, r.server.calls, "nothing was sent")
        assertEquals(judged, r.gate.judged, "not even the card chain was fetched")
        assertContentEquals(moves, s.moves.bytes, "the kept move stays")
        assertContentEquals(keptSaves, s.keptSaves.bytes, "the kept saves stay")
        assertEquals(files, s.files.ids().toSet(), "the files set aside stay")
        assertEquals(queued, s.queue.map.keys.toSet(), "the extensions' captures stay")

        // Signing in again to the same account at the same origin: what waited is sent.
        val c = content(r, r.restarted(), s)
        val before = r.server.pushes.size
        assertEquals(ActionResult.Ok, c.syncQuietly())
        val sent = r.server.pushes.drop(before).flatten()
        assertTrue(sent.any { it.itemId == offline }, "the offline edit is sent")
        assertEquals(ActionResult.Ok, c.moveOrCopyItem(wifi, r.shared, true))
        assertNull(s.moves.bytes, "the move finished")
        assertNull(s.keptSaves.bytes, "the saves with files finished")
        assertTrue(s.queue.map.isEmpty(), "the capture was saved")
        val after = c.state.items.map { it.name }.toSet()
        assertTrue(after.containsAll(setOf("Wifi", "Passport", "Offline", "shop.test")), "$after")
        assertTrue(r.server.pushes.flatten().none { it.op == MutationOp.DELETE && it.itemId != wifi }, "nothing of the copy was deleted")
    }

    @Test
    fun onlyThePersonsOwnActsDeleteTheCopy() {
        assertEquals(CopyDeletion.SIGNED_OUT, CopyDeletion.forSessionEnd(SessionEndReason.SIGNED_OUT))
        assertEquals(CopyDeletion.FORGOT_SERVER, CopyDeletion.forSessionEnd(SessionEndReason.FORGOTTEN))
        assertNull(CopyDeletion.forSessionEnd(SessionEndReason.REFRESH_REFUSED), "a refused refresh keeps the copy")
    }
}
