package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PolicyWipeNotice
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
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
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.Mutation
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
import io.silencelen.andvari.core.app.content.ContentCopy
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Saves with files that a lock cut short ("kept saves"), on a device whose server's policy then forbids keeping data:
 * they are part of the one attempt before the copy is removed (decided on 2026-11-17 and 2026-11-18). The attempt
 * finishes each one as one more change of its pass, its files first and then its item, with no drain of the item engine
 * and no conflict copy; one that is not finished is counted as not sent. And a save that the removal stopped before its
 * change was queued is said as not made. Over the real engine and a server that keeps the files and items it is sent.
 */
class EnginePolicyKeptSavesTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

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

    /**
     * [instance] with an item plane that keeps what it is sent (each change once, by its id) and serves it back, and that
     * keeps the files uploaded to it. [filesDown]: an upload gets no answer. Its policy forbids the copy while [forbid].
     */
    private class Server(val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var forbid = false
        var filesDown = false

        /** How long push n (counted from 0) waits before it is answered, and whether it is then dropped unanswered and unstored. */
        var pushDelay: (Int) -> Long = { 0L }
        var pushDropped: (Int) -> Boolean = { false }
        var pushes = 0
        var rev = 1L
        val items = LinkedHashMap<String, SyncItem>()
        val files = LinkedHashMap<String, ByteArray>()
        private val taken = HashMap<String, Long>()
        val received = ArrayList<Mutation>()

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route != WireRoute.ATTACHMENT_UPLOAD || filesDown) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            val q = query.orEmpty().split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
            val id = pathParams.getValue("attachmentId")
            files[id] = body.copyOf()
            val meta = AttachmentMeta(id, q["itemId"].orEmpty(), q["vaultId"].orEmpty(), body.size.toLong(), Bytes.toHexLower(createCryptoProvider().sha256(body)), instance.now)
            return WireResult.Ok(decode(WireJson.json.encodeToString(AttachmentMeta.serializer(), meta)), 200)
        }

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            return when (route) {
                WireRoute.CLIENT_POLICY -> WireResult.Ok(decode(policy(forbid)), 200)
                WireRoute.SYNC -> {
                    val since = query?.substringAfter("since=")?.substringBefore('&')?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val rows = items.values.filter { since == 0L || it.rev > since }
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), rows, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val n = pushes++
                    val wait = pushDelay(n)
                    if (wait > 0) kotlinx.coroutines.delay(wait)
                    if (pushDropped(n)) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    val results = b.mutations.map { m ->
                        received += m
                        val at = taken.getOrPut(m.mutationId) {
                            rev++
                            items[m.itemId] = SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                                m.item?.formatVersion ?: 1, m.item?.attachmentIds.orEmpty(), m.item?.blob)
                            rev
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, at)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private class Env(val instance: FakeInstance, val server: Server, val files: Files, val app: EngineAppApi)

    private fun env(): Env {
        val instance = FakeInstance(crypto)
        val server = Server(instance)
        val files = Files()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = { true }, contentStores = ContentStores(crypto, Records())),
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

    private suspend fun EngineAppApi.unlockWith() = assertEquals(VaultUnlockResult.DONE, unlock(snapshot.locked!!, strong))

    /**
     * Signed up and opened again (the copy at rest); a new login with one file saved while the file could not go up, so
     * the save is kept to be finished; locked. Then the policy forbids keeping data, and the next opening runs the attempt
     * and removes the copy. [filesDuringAttempt]: whether files go up during the attempt. Answers the notice.
     */
    private suspend fun Env.keptThenWiped(filesDuringAttempt: Boolean): PolicyWipeNotice {
        open(app)
        app.lock()
        app.unlockWith()
        server.filesDown = true
        val c = assertNotNull(app.content)
        c.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, c.addAttachment("a.bin", ByteArray(1) { 7 }))
        assertTrue(c.saveLogin(null, LoginInput("Doc", "me", "pw-doc", listOf("https://doc.test"), "", "", false), null) is ActionResult.Failed, "kept to finish")
        assertEquals(1, c.keptSavesWaiting())
        assertTrue(server.items.isEmpty() && server.files.isEmpty(), "nothing of it reached the server")
        app.lock()
        server.filesDown = !filesDuringAttempt
        app.policies.record(instance.origin, WireJson.json.decodeFromString(ClientPolicy.serializer(), server.policy(true)), instance.now)
        server.forbid = true
        app.unlockWith()
        app.policyWipe.running?.join()
        assertTrue(files.deleted.isNotEmpty(), "the copy was removed")
        return assertNotNull(app.snapshot.policyWipe)
    }

    /**
     * A kept save is finished inside the attempt: its file goes up under its id, then its item, once; the notice counts
     * nothing as not sent. Before, it was counted as not sent and never tried, and its file and record went with the copy.
     */
    @Test fun aKeptSaveIsFinishedInsideTheOneAttemptFilesFirst() = runBlocking<Unit> {
        val e = env()
        val notice = e.keptThenWiped(filesDuringAttempt = true)
        assertEquals(0, notice.notSent, "nothing is lost")
        assertEquals(0, notice.unsure)
        assertFalse(notice.cannotTell)
        val file = e.server.files.keys.single()
        val item = e.server.items.values.single()
        assertEquals(listOf(file), item.attachmentIds, "the item names its file, which went up first")
        assertEquals(1, e.server.received.size, "one change, sent once: ${e.server.received}")
        assertEquals(MutationOp.PUT, e.server.received.single().op)
    }

    /**
     * A kept save whose file cannot go up during the attempt is not finished: it is counted as not sent, and its item is
     * never sent without its file. (This guards the direction of the change: the code before it counted the same.)
     */
    @Test fun aKeptSaveNotFinishedInTheAttemptIsCountedAsNotSent() = runBlocking<Unit> {
        val e = env()
        val notice = e.keptThenWiped(filesDuringAttempt = false)
        assertEquals(1, notice.notSent)
        assertEquals(0, notice.unsure)
        assertTrue(e.server.received.isEmpty(), "the item never went without its file")
    }

    /**
     * An edit of an item that already had a change waiting, stopped before its own change was queued (it waited behind a
     * running sync whose push got no answer, and the removal for the policy began then): it is said as not made, never as
     * "may or may not arrive". Nothing of the edit is sent. The earlier change was in the sync's request that was out when
     * the removal began; that request got no answer, so the change still waits and the attempt's one try sends it.
     */
    @Test fun anEditStoppedBeforeItWasQueuedIsNotMadeAlsoWhenTheItemHadAChangeWaiting() = runBlocking<Unit> {
        val e = env()
        open(e.app)
        e.app.lock()
        e.app.unlockWith()
        val c = assertNotNull(e.app.content)
        // The first change waits: its push gets no answer.
        e.server.pushDropped = { it == 0 }
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Offline", "me", "pw-1", listOf("https://offline.test"), "", "", false), null))
        val row = c.state.items.single { it.name == "Offline" }
        assertTrue(row.pendingSync, "the first change waits")
        // The sync's push of it is held and dropped; the attempt's push is held longer, so the content is still open when
        // the edit answers.
        e.server.pushDelay = { if (it == 1) 300 else 1_500 }
        e.server.pushDropped = { it <= 1 }
        val sync = async(start = CoroutineStart.UNDISPATCHED) { c.syncQuietly() }
        val edit = async(start = CoroutineStart.UNDISPATCHED) {
            c.saveLogin(row.itemId, LoginInput("Offline", "me", "pw-2", listOf("https://offline.test"), "", "", false), row.vaultId)
        }
        assertTrue(edit.isActive, "the edit waits behind the sync")
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        sync.await()
        assertEquals(ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED), edit.await())
        e.app.policyWipe.running?.join()
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(0, notice.notSent)
        assertEquals(0, notice.unsure, "the attempt's own request for the earlier change was taken")
        assertEquals(1, e.server.received.map { it.mutationId }.distinct().size, "only the earlier change, nothing of the edit: ${e.server.received}")
        assertEquals(1, e.server.items.size)
    }
}
