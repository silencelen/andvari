package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.ContentCapture
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
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
import kotlin.test.assertTrue

/**
 * A login the Android app caught before a server's policy forbade keeping data on the device, and that needs no answer,
 * is saved by itself at the very opening that records the policy and removes the copy. The content over the copy is
 * composed again for the removal: what that opening saved is still said as saved afterwards (the person is told), and
 * the one that waits for the person's answer still waits. Over the real engine, against a server whose item plane keeps
 * what it is sent and serves it back at every sync, as a real one does, and whose policy is read only after the
 * opening's own sync (as a server answers it on a phone).
 */
class EnginePolicySavedAtRemovalTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val day = 86_400_000L

    private class Files : VaultCacheFiles {
        val deleted = ArrayList<String>()
        val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            caches.remove(fileName)
            return true
        }
    }

    private class Records : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobs = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobs.getOrPut(name) { InMemoryBlobs() }
    }

    /** [instance] with an item plane that keeps what is pushed; its policy forbids the copy while [forbid]; [down]: no answer at all. */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var forbid = false
        var down = false
        var rev = 1L
        val taken = LinkedHashSet<String>()
        val items = ArrayList<SyncItem>()
        val routes = ArrayList<String>()

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        /** The items the server holds live now. */
        fun live(): Int = items.count { !it.deleted }

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT, neverLeft = true)
            routes += route.name
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        if (taken.add(m.mutationId)) {
                            rev++
                            items.removeAll { it.itemId == m.itemId }
                            val up = m.item
                            items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false, up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private class Env(val instance: FakeInstance, val server: Server, val files: Files, val records: Records, val queue: InMemorySaveQueue, val app: EngineAppApi)

    private fun env(): Env {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val files = Files()
        val records = Records()
        val queue = InMemorySaveQueue()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }, contentStores = ContentStores(crypto, records, queue)),
        ).also { it.start() }
        return Env(instance, server, files, records, queue, app)
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

    private suspend fun EngineAppApi.unlockWith() = unlock(snapshot.locked!!, strong)

    /**
     * Signed up, opened again (the copy at rest), locked; two logins caught while locked: one for a new site (saved by
     * itself) and one dated in the future (it waits for the person's answer). Then the server's policy forbids keeping
     * data, and the next opening, which reads it only after its own sync, records it and removes the copy.
     */
    private suspend fun Env.removedAtAnOpeningThatSaved() {
        open(app)
        app.lock()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        app.lock()
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(queue, crypto, "https://auto.test", "me", "pw-auto-1", instance.now))
        assertEquals(SaveQueued.QUEUED, ContentCapture.queue(queue, crypto, "https://later.test", "me", "pw-later-2", instance.now + 2 * day))
        assertEquals(0, server.live())
        server.forbid = true
        server.routes.clear()
        assertEquals(VaultUnlockResult.DONE, app.unlockWith())
        app.policyWipe.running?.join()
        assertNotNull(app.snapshot.policyWipe, "the copy was removed")
        assertTrue(files.deleted.isNotEmpty())
    }

    @Test fun aLoginSavedByItselfAtTheRemovalsOwnOpeningIsStillSaidAsSaved() = runBlocking<Unit> {
        val e = env()
        e.removedAtAnOpeningThatSaved()
        val c = assertNotNull(e.app.content)
        val st = c.state
        println("routes at the opening: ${e.server.routes}")
        println("after the removal: applied ${st.appliedSaves.map { it.host }}, pending ${st.pendingSaves.map { it.host to it.reason }}, live at the server ${e.server.live()}, queue ${e.queue.entries().size}")
        assertEquals(1, e.server.live(), "the server took the one saved by itself")
        assertEquals(1, e.queue.entries().size, "the list of caught logins dropped it; the other waits")
        assertEquals(listOf("later.test"), st.pendingSaves.map { it.host }, "the one that needs an answer waits for it")
        assertEquals(listOf("auto.test"), st.appliedSaves.map { it.host }, "what that opening saved is said as saved")
        // A read of the list afterwards says the same, and saves nothing twice.
        c.readSaveQueue()
        assertEquals(listOf("auto.test"), c.state.appliedSaves.map { it.host })
        assertEquals(listOf("later.test"), c.state.pendingSaves.map { it.host })
        assertEquals(1, e.server.live())
        // Taken across in memory only: nothing of the list is on the device's storage after the removal.
        assertTrue(e.records.records.values.all { it.read() == null }, "no record at rest after the removal")
        // Undone from the list carried across: the person's undo still works on what that opening saved.
        val undo = c.state.appliedSaves.single()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, c.undoAppliedSave(undo.id))
        assertEquals(0, e.server.live(), "the undo removed it at the server")
        assertEquals(emptyList(), c.state.appliedSaves.map { it.host })
    }

    /**
     * The owner's condition, again, after such an opening: with the server silent, the phone opens no caught login and
     * says none as saved; the list of caught logins is left as it is. With the server answering, it is read again.
     */
    @Test fun withTheServerSilentNoCaughtLoginOpensAndNoneIsSaidAsSaved() = runBlocking<Unit> {
        val e = env()
        e.removedAtAnOpeningThatSaved()
        e.app.lock()
        val waiting = e.queue.entries().toMap()
        assertEquals(1, waiting.size)
        e.server.down = true
        // The keys are kept at the server only: its silence has an answer of its own, with its own line and no trouble.
        val silent = e.app.unlockWith()
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, silent)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE, silent.sentence)
        assertNull(silent.trouble)
        assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
        assertTrue(e.app.content?.state?.appliedSaves.isNullOrEmpty(), "nothing is said as saved while locked")
        assertTrue(e.app.content?.state?.pendingSaves.isNullOrEmpty(), "no caught login is opened while locked")
        assertEquals(waiting.keys, e.queue.entries().keys, "nothing removed without the server")
        assertEquals(1, e.server.live(), "nothing sent")
        e.server.down = false
        assertEquals(VaultUnlockResult.DONE, e.app.unlockWith())
        val c = assertNotNull(e.app.content)
        c.readSaveQueue()
        assertEquals(listOf("later.test"), c.state.pendingSaves.map { it.host })
        assertFalse(c.state.appliedSaves.any { it.host == "later.test" })
        assertEquals(1, e.server.live(), "the one saved before is not saved again")
    }
}
