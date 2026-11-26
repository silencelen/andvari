package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The AutoFill working set and the extensions' save queue on the new session. */
class SaveQueueContentTest {
    private val queue = InMemorySaveQueue()
    private val applied = InMemoryFillSnapshots()

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig, var allowed: Boolean, val at: String = "https://vault.example.com") : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = at
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = allowed
    }

    private fun content(r: ItemRig, account: OpenedAccount = unlock(r), allowed: Boolean = true): EngineVaultContent {
        r.server.echo = true
        return EngineVaultContent(r.engine, r.crypto, TestHost(r, allowed), ContentKeeping(account, InMemoryFillSnapshots(), InMemoryFillSnapshots(), InMemoryBlobs(), applied, queue))
    }

    private fun capture(r: ItemRig, site: String, user: String, password: String): SaveQueued =
        SaveQueue.enqueue(queue, r.crypto, site, user, password, r.now, "safari")

    private fun login(name: String, uri: String) = LoginInput(name, "me", "pw", listOf(uri), "", "", false)

    @Test
    fun theWorkingSet_leavesFrozenFailedAndWithheldVaultsOut_andTakesAVerifiedOneBack() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val c = content(r)
        c.saveLogin(null, login("Mine", "https://mine.test"), null)
        c.saveLogin(null, login("Ours", "https://ours.test"), r.shared)
        val ours = c.state.items.single { it.name == "Ours" }.itemId
        assertEquals(listOf("Ours", "Mine"), c.fillLogins(listOf("ours.test")).map { it.name })
        // A withheld vault is read, never filled from (spec 02 §10.4): like a frozen or failed one.
        for (standing in listOf(VaultStanding.FROZEN, VaultStanding.FAILED, VaultStanding.WITHHELD)) {
            r.keys.put(r.shared, r.sharedKey, VaultAccess.ROLE_WRITER, standing)
            assertEquals(listOf("Mine"), c.fillLogins(emptyList()).map { it.name }, "$standing")
            assertNull(c.fillCredential(ours))
            assertFalse(c.fillMatches(ours, listOf("ours.test")))
            assertTrue(c.credentialIdentities().none { it.itemId == ours })
        }
        r.keys.put(r.shared, r.sharedKey, VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        assertEquals("pw", c.fillCredential(ours)!!.password, "a vault verified again is filled from again")
        assertEquals(setOf("mine.test", "ours.test"), c.credentialIdentities().map { it.host }.toSet())
    }

    @Test
    fun theWorkingSet_carriesAppAddressesApart_fromTheVaultsThatMayFillOnly() = runBlocking<Unit> {
        val r = ItemRig()
        r.openShared()
        val c = content(r)
        val both = listOf("https://shop.test/login", " androidapp://com.shop.app ")
        c.saveLogin(null, LoginInput("Mine", "me", "pw", both, "", "", false), null)
        c.saveLogin(null, LoginInput("Ours", "me", "pw", listOf("androidapp://com.ours.app"), "", "", false), r.shared)
        val mine = c.fillLogins(emptyList()).single { it.name == "Mine" }
        assertEquals(listOf("https://shop.test/login"), mine.uris, "a web matcher never sees an app address")
        assertEquals(listOf("androidapp://com.shop.app"), mine.appUris)
        assertEquals(listOf("androidapp://com.ours.app"), c.fillLogins(emptyList()).single { it.name == "Ours" }.appUris)
        r.keys.put(r.shared, r.sharedKey, VaultAccess.ROLE_WRITER, VaultStanding.FROZEN)
        assertEquals(listOf("Mine"), c.fillLogins(emptyList()).map { it.name }, "a frozen vault's app logins are not offered either")
    }

    /**
     * Captures queued just before a followed move go with it: filed again at the new address with their seals untouched,
     * then read and saved there (before, the new address removed them as another origin's). Another account's entry is
     * left as it is; a queue that cannot be read, or an entry that cannot be written again, keeps what it holds and says so.
     */
    @Test
    fun aFollowedMove_carriesTheCapturesQueuedJustBeforeIt() = runBlocking<Unit> {
        val r = ItemRig()
        val account = unlock(r)
        val old = "https://vault.example.com"
        val moved = "https://new.example.com"
        content(r, account).syncQuietly()
        assertEquals(SaveQueued.QUEUED, capture(r, "https://shop.test/login", "ana", "s3cret"))
        val captured = queue.map.keys.single()
        val foreign = QueueEntries.encode(QueueEntry(origin = old, userId = "77777777-7777-4777-8777-777777777777", sealed = "AAAA"))
        queue.add("other", foreign)

        // A queue that cannot be read: nothing is carried, nothing is lost.
        val unreadable = object : io.silencelen.andvari.core.app.SaveQueueStore by queue {
            override fun entries(): Map<String, ByteArray> = throw IllegalStateException("disk")
        }
        assertFalse(ContentStores(r.crypto, null, unreadable).carry(old, moved, r.userId))
        // An entry that cannot be written again stays where it was.
        val full = object : io.silencelen.andvari.core.app.SaveQueueStore by queue {
            override fun add(id: String, bytes: ByteArray): Boolean = false
        }
        assertFalse(ContentStores(r.crypto, null, full).carry(old, moved, r.userId))
        assertEquals(setOf(captured, "other"), queue.map.keys)

        assertTrue(ContentStores(r.crypto, null, queue).carry(old, moved, r.userId))
        assertFalse(captured in queue.map, "the old entry goes once its copy is written")
        assertTrue(queue.map["other"]!!.contentEquals(foreign), "another account's entry is left as it is")
        val carried = QueueEntries.decode(queue.map.values.first { !it.contentEquals(foreign) })!!
        assertEquals(moved, carried.origin)
        assertEquals(old, carried.carriedFrom)

        val c = EngineVaultContent(
            r.engine, r.crypto, TestHost(r, true, moved),
            ContentKeeping(account, InMemoryFillSnapshots(), InMemoryFillSnapshots(), InMemoryBlobs(), applied, queue),
        )
        assertEquals(ActionResult.Ok, c.readSaveQueue())
        assertEquals("shop.test", c.state.appliedSaves.single().host, "read and saved at the new address")
        assertEquals("s3cret", c.revealSecret(c.state.items.single().itemId, io.silencelen.andvari.core.app.SecretField.PASSWORD))
        assertTrue(queue.map.isEmpty(), "the other account's entry is not this one's: removed at the read, as before")
    }

    /**
     * Android's save prompt: a login typed in an app goes into the same queue and is saved under its rules as the app's
     * address (`androidapp://`). Before, the queue read the package as a web host and saved `https://com.bank.app`: a
     * login for the app offered on the web site `bank.app`. A site that is neither an app nor a host is refused.
     */
    @Test
    fun anAppCaptureFromAndroid_isSavedAsTheAppsAddress_neverAsAWebSite() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.syncQuietly()
        assertEquals(SaveQueued.QUEUED, SaveQueue.enqueue(queue, r.crypto, "androidapp://com.bank.app", "ana", "s3cret", r.now, ContentCapture.SOURCE))
        assertEquals(ActionResult.Ok, c.readSaveQueue())
        val row = c.state.appliedSaves.single()
        assertEquals("com.bank.app", row.host)
        val item = c.state.items.single()
        assertEquals(listOf("androidapp://com.bank.app"), c.itemDetail(item.itemId)!!.uris)
        val fill = c.fillLogins(emptyList()).single()
        assertEquals(listOf("androidapp://com.bank.app"), fill.appUris)
        assertTrue(fill.uris.isEmpty(), "an app's login carries no web address")
        assertFalse(c.fillMatches(item.itemId, listOf("bank.app")) || c.fillMatches(item.itemId, listOf("com.bank.app")), "never offered on a web site")

        // The same login captured again in the app is the same login: nothing new is written.
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(queue, r.crypto, ContentCapture.appSite("com.bank.app")!!, "ana", "s3cret", r.now + 1))
        assertEquals(ActionResult.Ok, c.readSaveQueue())
        assertEquals(1, c.state.items.size)
        assertTrue(queue.map.isEmpty())

        // The service's call: what it may pass.
        assertNull(ContentCapture.appSite("not a package"))
        assertEquals("https://shop.test", ContentCapture.webSite("shop.test", "https"))
        assertEquals("shop.test", ContentCapture.webSite("shop.test", null))
        assertNull(ContentCapture.webSite("shop.test", "ftp"))
        assertEquals(SaveQueued.REFUSED, ContentCapture.queue(queue, r.crypto, "androidapp://not a package", "ana", "pw", r.now))
        assertEquals(SaveQueued.REFUSED, ContentCapture.queue(queue, r.crypto, "https://shop.test", "ana", "", r.now))
        assertTrue(queue.map.isEmpty())

        // The fake's twin: the same call into the queue the fake reads, saved under the same rules.
        val q = io.silencelen.andvari.core.app.InMemorySaveQueue()
        val fake = FakeVaultContent(r.crypto, q)
        assertEquals(SaveQueued.NO_ACCOUNT, ContentCapture.queue(q, r.crypto, ContentCapture.appSite("com.bank.app")!!, "ana", "pw", r.now))
        fake.syncQuietly()
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(q, r.crypto, ContentCapture.webSite("shop.test", "https")!!, "ana", "pw", fake.nowMs))
        assertEquals(ActionResult.Ok, fake.readSaveQueue())
        assertEquals("shop.test", fake.state.appliedSaves.single().host)
        assertEquals(listOf("https://shop.test"), fake.itemDetail(fake.state.items.single { it.name == "shop.test" }.itemId)!!.uris)
    }

    @Test
    fun aNewCapture_isSavedToThePersonalVault_listed_andUndone() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.syncQuietly()
        assertNotNull(queue.key, "the key the extensions seal to is published")
        assertEquals(SaveQueued.QUEUED, capture(r, "https://shop.test/login", "ana", "s3cret"))
        assertEquals(ActionResult.Ok, c.readSaveQueue())
        val row = c.state.appliedSaves.single()
        assertEquals("shop.test", row.host)
        assertTrue(queue.map.isEmpty())
        val item = c.state.items.single()
        assertEquals(r.personal, c.itemDetail(item.itemId)!!.vaultId)
        assertEquals("s3cret", c.revealSecret(item.itemId, io.silencelen.andvari.core.app.SecretField.PASSWORD))
        assertEquals(ActionResult.Ok, c.undoAppliedSave(row.id))
        assertTrue(c.state.items.isEmpty())
        assertTrue(c.state.appliedSaves.isEmpty())
    }

    @Test
    fun aCaptureIsNeverSavedIntoAPersonalVaultThatIsNotWritableHere() = runBlocking<Unit> {
        val r = ItemRig()
        val c = content(r)
        c.syncQuietly()
        r.keys.put(r.personal, r.personalKey, VaultAccess.ROLE_OWNER, VaultStanding.FROZEN)
        capture(r, "https://shop.test", "ana", "s3cret")
        c.readSaveQueue()
        assertEquals(ContentSaves.PERSONAL_NOT_WRITABLE, c.state.pendingSaves.single().reason)
        val id = c.state.pendingSaves.single().id
        assertEquals(ContentSaves.PERSONAL_NOT_WRITABLE, (c.confirmPendingSave(id) as ActionResult.Failed).message)
        assertTrue(c.state.items.isEmpty())
        assertEquals("s3cret", c.pendingSavePassword(id))
        assertEquals(ActionResult.Ok, c.discardPendingSave(id))
        assertTrue(queue.map.isEmpty())
    }

    @Test
    fun aLockedAccount_leavesTheQueueAndTheListAsTheyAre() = runBlocking<Unit> {
        val r = ItemRig()
        val first = unlock(r)
        content(r, first).syncQuietly()
        capture(r, "https://shop.test", "ana", "s3cret")
        first.wipe()
        val stale = content(r, first)
        stale.readSaveQueue()
        assertEquals(1, queue.map.size, "an entry is never dropped because the app locked")
        assertTrue(stale.state.items.isEmpty())
        assertNull(stale.state.notice)
        val b = content(r, unlock(r))
        b.readSaveQueue()
        assertEquals(1, b.state.appliedSaves.size)
        assertTrue(queue.map.isEmpty())
    }

    @Test
    fun aPolicyThatForbidsKeepingData_keepsTheQueueAndItsKey_andListsNoIdentity() = runBlocking<Unit> {
        // Decided on 2026-11-18: caught logins stay on the phone until the person answers them, also under such a policy.
        val r = ItemRig()
        content(r).syncQuietly()
        capture(r, "https://shop.test", "ana", "s3cret")
        val c = content(r, allowed = false)
        c.saveLogin(null, login("Mine", "https://mine.test"), null)
        c.readSaveQueue()
        assertNotNull(queue.key, "the key stays published, so catches go on")
        assertTrue(queue.map.isNotEmpty() || c.state.appliedSaves.any { it.host == "shop.test" }, "the capture is read, never emptied")
        assertTrue(c.credentialIdentities().isEmpty())
    }

    /**
     * A capture that fails to open for a reason that says nothing about it (the crypto provider failed, not the seal)
     * is unknown, never "not ours": the queue is kept as it is and said to be unreadable; the next read that works
     * offers it. Before, every failure counted as a box for someone else, and the capture was removed.
     */
    @Test
    fun aCaptureThatFailsToOpenForAReasonThatIsNotItsSeal_isKept() = runBlocking<Unit> {
        val r = ItemRig()
        val account = unlock(r)
        content(r, account).syncQuietly()
        assertEquals(SaveQueued.QUEUED, capture(r, "https://shop.test/login", "ana", "s3cret"))
        val held = queue.map.keys.toSet()
        val failing = object : io.silencelen.andvari.core.crypto.CryptoProvider by r.crypto {
            override fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray = throw IllegalStateException("the provider failed")
        }
        r.server.echo = true
        val c = EngineVaultContent(r.engine, failing, TestHost(r, true), ContentKeeping(account, InMemoryFillSnapshots(), InMemoryFillSnapshots(), InMemoryBlobs(), applied, queue))
        assertEquals(ContentCopy.SAVES_LIST_UNREADABLE, (c.readSaveQueue() as ActionResult.Failed).message)
        assertEquals(held, queue.map.keys.toSet(), "the capture stays")
        assertTrue(c.state.pendingSaves.isEmpty())
        val again = content(r, account)
        again.readSaveQueue()
        assertEquals(1, again.state.pendingSaves.size + again.state.appliedSaves.size, "taken up once a read works")
    }
}
