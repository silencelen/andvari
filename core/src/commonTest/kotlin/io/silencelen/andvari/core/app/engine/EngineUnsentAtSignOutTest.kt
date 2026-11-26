package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.SendFirstResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** What a sign-out does with changes made on this device and not sent yet (design §4.4: a sign-out deletes the copy). */
class EngineUnsentAtSignOutTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /**
     * Cache files in memory, recorded: what was opened and what was deleted. Each answers as durable, as the SQLite file
     * does, so a change made offline is queued in it rather than refused.
     */
    private class Files : VaultCacheFiles {
        val opened = ArrayList<String>()
        val deleted = ArrayList<String>()
        val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache {
            opened += fileName
            return caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            caches.remove(fileName)
            return true
        }
    }

    /** [instance] with the item plane of an honest server (the personal vault's row and the items pushed); [down]: no answer to either. */
    private class ItemServer(private val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var down = false
        var rev = 1L
        val items = ArrayList<SyncItem>()

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            when (route) {
                WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        rev++
                        items.removeAll { it.itemId == m.itemId }
                        val up = m.item
                        items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                            up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
    }

    private class Env(val instance: FakeInstance, val server: ItemServer, val files: Files, val app: EngineAppApi)

    private fun env(): Env {
        val instance = FakeInstance(crypto)
        val server = ItemServer(instance)
        val files = Files()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files),
        ).also { it.start() }
        return Env(instance, server, files, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /** Two logins saved while the server answers nothing: both wait in this device's cache. */
    private suspend fun Env.offlineChanges() {
        open(app)
        // The second opening has read the policy, which allows an offline copy: the cache is the account's own file.
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlock(app.snapshot.locked!!, strong))
        // (The first opening deleted any file left at rest; only what a sign-out deletes counts below.)
        files.deleted.clear()
        val c = assertNotNull(app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        server.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Shop"), null))
    }

    /** The account's cache file, as this device named it. */
    private fun Env.cacheName(): String = files.opened.last()

    /**
     * Two changes made offline, then "Sign out" without the second confirmation: nothing is deleted, nothing is signed
     * out, and the check says how many changes would be lost and offers to send them first. Before, the sign-out
     * answered DONE and deleted the cache with both changes in it.
     */
    @Test fun aSignOutOverUnsentChangesWithoutTheConfirmationDeletesNothingAndTheLineSaysHowMany() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val a = e.app
        val check = assertNotNull(a.signOutCheck())
        assertEquals(2, check.unsentChanges)
        assertTrue(check.needsConfirmation)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_LOST, check.line?.key)
        assertEquals(listOf("2"), check.line?.values)
        assertTrue(check.canSendFirst)
        assertEquals(CopyKey.SIGN_OUT_SEND_FIRST, check.sendFirstLabel?.key)
        assertSame(check, a.signOutCheck(), "the same check while what it says holds")

        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, a.signOut())
        assertEquals(CopyKey.UNSENT_NOT_CONFIRMED, PlainResult.UNSENT_NOT_CONFIRMED.sentence)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertNotNull(a.keeper.session, "still signed in")
        assertEquals(emptyList(), e.files.deleted, "nothing deleted")
        assertEquals(2, a.vault!!.queued().pending.size, "both changes still wait")
    }

    /**
     * A vault in the holding area adds to the count each change parked with it, and one with none adds nothing (a count too
     * low deletes changes unsaid). Before, each held vault counted as one change: here 2 + 2 instead of 2 + 3.
     */
    @Test fun eachChangeParkedWithAHeldVaultCountsAndAHeldVaultWithNoneAddsNothing() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val cache = assertNotNull(e.files.caches[e.cacheName()])
        val parked = (1..3).map { io.silencelen.andvari.core.model.Mutation("held-change-$it", "put", "held-item-$it", "held-vault", 1L) }
        cache.putHeld(io.silencelen.andvari.core.client.HeldVaultRecord(io.silencelen.andvari.core.model.WireVault("held-vault", "shared", 1, "", 0L), null,
            emptyList(), "removed", true, null, null, parked, Long.MAX_VALUE))
        cache.putHeld(io.silencelen.andvari.core.client.HeldVaultRecord(io.silencelen.andvari.core.model.WireVault("held-empty", "shared", 1, "", 0L), null,
            emptyList(), "removed", true, null, null, emptyList(), Long.MAX_VALUE))
        val check = assertNotNull(e.app.signOutCheck())
        assertEquals(5, check.unsentChanges)
        assertEquals(listOf("5"), check.line?.values)
        assertTrue(check.needsConfirmation)
    }

    /** With the person's second confirmation of the check on show, the sign-out goes ahead: the copy goes with both changes. */
    @Test fun withTheSecondConfirmationTheSignOutDeletesTheCopyAndItsUnsentChanges() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val a = e.app
        val name = e.cacheName()
        val check = assertNotNull(a.signOutCheck())
        assertEquals(PlainResult.DONE, a.signOutConfirmed(check))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertNull(a.keeper.session)
        assertTrue(name in e.files.deleted, "the copy is deleted")
        assertEquals(0, e.server.items.size, "the two changes never reached the server")
        assertNull(a.signOutCheck(), "nothing to sign out")
    }

    /** A confirmation of a check that no longer holds (one more change since) signs nothing out: the new check is shown. */
    @Test fun aConfirmationOfACheckThatNoLongerHoldsSignsNothingOut() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val a = e.app
        val shown = assertNotNull(a.signOutCheck())
        assertEquals(ActionResult.Ok, a.content!!.saveLogin(null, login("Mail"), null))
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, a.signOutConfirmed(shown))
        assertEquals(emptyList(), e.files.deleted)
        val now = assertNotNull(a.signOutCheck())
        assertEquals(3, now.unsentChanges)
        assertEquals(PlainResult.DONE, a.signOutConfirmed(now))
    }

    /** "Try sending them first", with the server back: both are sent, nothing is lost, and the sign-out needs no second confirmation. */
    @Test fun sendingFirstThatSucceedsLeavesNothingToLose() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val a = e.app
        val check = assertNotNull(a.signOutCheck())
        e.server.down = false
        assertEquals(SendFirstResult.DONE, a.sendBeforeSignOut(check))
        assertEquals(2, e.server.items.size, "both changes reached the server")
        val after = assertNotNull(a.signOutCheck())
        assertEquals(0, after.unsentChanges)
        assertFalse(after.needsConfirmation)
        assertNull(after.line)
        assertNull(after.sendFirstLabel)
        assertEquals(PlainResult.DONE, a.signOut())
        assertTrue(e.files.deleted.isNotEmpty())
    }

    /** "Try sending them first" while the server still answers nothing: nothing is deleted, the count stays, the confirmation is still needed. */
    @Test fun sendingFirstThatFailsKeepsEverythingAndStillAsks() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val a = e.app
        val check = assertNotNull(a.signOutCheck())
        assertEquals(SendFirstResult.NOT_ALL_SENT, a.sendBeforeSignOut(check))
        assertEquals(CopyKey.SIGN_OUT_SEND_FIRST_FAILED, SendFirstResult.NOT_ALL_SENT.sentence)
        assertEquals(emptyList(), e.files.deleted)
        val after = assertNotNull(a.signOutCheck())
        assertEquals(2, after.unsentChanges)
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, a.signOut())
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /**
     * Locked, the changes cannot be counted: the line says this device cannot tell, nothing can be sent first, and the
     * sign-out needs the second confirmation all the same.
     */
    @Test fun lockedTheLineSaysThisDeviceCannotTellAndTheConfirmationIsStillNeeded() = runBlocking<Unit> {
        val e = env()
        e.offlineChanges()
        val a = e.app
        a.lock()
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        val check = assertNotNull(a.signOutCheck())
        assertNull(check.unsentChanges)
        assertTrue(check.needsConfirmation)
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, check.line?.key)
        assertFalse(check.canSendFirst)
        assertNull(check.sendFirstLabel)
        assertEquals(SendFirstResult.STALE, a.sendBeforeSignOut(check), "nothing is sent while locked")
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, a.signOut())
        assertEquals(emptyList(), e.files.deleted)
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertEquals(PlainResult.DONE, a.signOutConfirmed(check))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertTrue(e.files.deleted.isNotEmpty())
    }

    /** Nothing waits: the check says so, and the sign-out needs no second confirmation, as before. */
    @Test fun withNothingWaitingTheSignOutNeedsNoSecondConfirmation() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        assertEquals(ActionResult.Ok, e.app.content!!.syncQuietly())
        assertEquals(ActionResult.Ok, e.app.content!!.saveLogin(null, login("Bank"), null))
        val check = assertNotNull(e.app.signOutCheck())
        assertEquals(0, check.unsentChanges)
        assertFalse(check.needsConfirmation)
        assertNull(check.line)
        assertEquals(PlainResult.DONE, e.app.signOut())
    }

    /**
     * A save with a file whose upload got no answer is kept to finish while its editor is open, outside the item queue;
     * a sign-out deletes it. It is counted, and the sign-out asks. Before, the count said 0 and the sign-out went at once.
     */
    @Test fun aSaveWithAFileKeptToFinishIsCountedAndTheSignOutAsks() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        val c = assertNotNull(e.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        e.server.down = true
        c.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, c.addAttachment("a.bin", ByteArray(1) { 7 }))
        assertTrue(c.saveLogin(null, login("Doc"), null) is ActionResult.Failed, "said as not saved")
        assertEquals(1, c.keptSavesWaiting(), "kept to finish")
        val check = assertNotNull(e.app.signOutCheck())
        assertEquals(1, check.unsentChanges)
        assertTrue(check.needsConfirmation)
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, e.app.signOut())
        assertNotNull(e.app.keeper.session, "nothing was signed out")
    }
}
