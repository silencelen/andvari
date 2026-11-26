package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.PolicyWipeNotice
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.content.ContentCopy
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.app.content.VaultSyncState
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.HeldVaultRecord
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.KeptPolicies
import io.silencelen.andvari.core.client.session.PolicyWipeMarks
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.ItemUpload
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.WireVault
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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A server's policy that forbids the offline copy, on a device (decided on 2026-11-17: "Try once to send what waits,
 * then wipe as specified; say afterwards how many could not be sent"): nothing is removed before it is counted, one
 * attempt with its limits, the three outcomes, the wipe and its notice. Each test is one of the investigation's
 * sequences, over the real engine and an item server that answers as told.
 */
class EnginePolicyWipeTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** Cache files in memory that answer as durable, recorded; [holdDelete]: the platform cannot delete now; [broken]: opening fails. */
    private class Files : VaultCacheFiles {
        val opened = ArrayList<String>()
        val deleted = ArrayList<String>()
        val caches = HashMap<String, VaultCache>()
        var holdDelete = false
        var broken = false
        override fun open(fileName: String, userId: String): VaultCache {
            opened += fileName
            if (broken) throw IllegalStateException("the file is damaged")
            return caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            if (holdDelete) return false
            caches.remove(fileName)
            return true
        }
        /** A followed move's carry: the file goes to its new name, never over one already there. */
        override fun rename(from: String, to: String): Boolean {
            if (to in caches) return false
            caches.remove(from)?.let { caches[to] = it }
            return true
        }
    }

    /**
     * [instance] with an honest item plane (the personal vault's row, the items pushed, each change taken once by its
     * id) and a policy that allows the copy until [forbid]. [down]: no answer to a sync or a push; [upAfterPolicy]: the
     * network comes back with the first policy read. [policyScript]: one step per policy read, in order (null answers
     * nothing, true forbids, false allows); then [forbid]. [pushDelay]: how long the answer to push n takes, after the
     * server took it. [onPolicy]: run as a policy read is answered.
     */
    private class ItemServer(private val instance: FakeInstance) : WireClient {
        override val origin: String get() = instance.origin
        var down = false

        /** With [down]: no connection is made at all (nothing of a request leaves the device), as a refused connection. */
        var unreachable = false
        private fun noAnswer() = if (unreachable) WireResult.NoAnswer(NoAnswerKind.TRANSPORT, neverLeft = true) else WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        var upAfterPolicy = false
        var forbid = false
        val policyScript = ArrayList<suspend () -> Boolean?>()
        var onPolicy: (() -> Unit)? = null
        var pushDelay: (Int) -> Long = { 0L }
        var rev = 1L
        val items = ArrayList<SyncItem>()
        val taken = LinkedHashSet<String>()
        val pushes = ArrayList<List<String>>()
        var policyReads = 0

        fun policy(forbids: Boolean): String = WireJson.json.encodeToString(
            ClientPolicy.serializer(),
            ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, !forbids, 3600, 30, 1, 1, instance.now, SignupPolicy(SignupMode.OPEN, false, true, 0), false),
        )

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            when (route) {
                WireRoute.CLIENT_POLICY -> {
                    policyReads++
                    val step = if (policyScript.isNotEmpty()) policyScript.removeAt(0) else null
                    val forbids = if (step != null) step() else forbid
                    if (upAfterPolicy) down = false
                    onPolicy?.invoke()
                    if (forbids == null) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else WireResult.Ok(decode(policy(forbids)), 200)
                }
                WireRoute.SYNC -> if (down) noAnswer() else {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                    val vaults = pv?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> if (down) noAnswer() else {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val n = pushes.size
                    pushes += b.mutations.map { it.mutationId }
                    val results = b.mutations.map { m ->
                        // A change it already holds is taken once (spec 03 §5's dedup window).
                        if (taken.add(m.mutationId)) {
                            rev++
                            items.removeAll { it.itemId == m.itemId }
                            val up = m.item
                            items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                                up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        }
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    val wait = pushDelay(n)
                    if (wait > 0) delay(wait)
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
    }

    private class Env(val instance: FakeInstance, val server: ItemServer, val files: Files, val state: MemoryDeviceState, val secure: MemoryDeviceState, val app: EngineAppApi)

    /** A process over [from]'s server, files and stores (a restart), or a first one. */
    private fun env(from: Env? = null, keep: () -> Boolean = { true }, kept: KeptStorage? = null): Env {
        val instance = from?.instance ?: FakeInstance(crypto)
        val server = from?.server ?: ItemServer(instance)
        val files = from?.files ?: Files()
        val state = from?.state ?: MemoryDeviceState()
        val secure = from?.secure ?: MemoryDeviceState()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server)), state, secure, crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = keep, contentStores = kept?.let { ContentStores(crypto, it) }),
        ).also { it.start() }
        return Env(instance, server, files, state, secure, app)
    }

    /** The platform's kept records, as files in memory by name (both apps pass stores of their own). */
    private class Records : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = InMemoryBlobs()
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

    private suspend fun EngineAppApi.unlockNow() = assertEquals(VaultUnlockResult.DONE, unlock(snapshot.locked!!, strong))

    /** Signed up, opened again under the allowing policy (the copy is the account's file), [n] logins saved offline, locked. */
    private suspend fun Env.waiting(n: Int) {
        open(app)
        app.lock()
        app.unlockNow()
        assertTrue(assertNotNull(app.vault).keptAtRest, "the copy is at rest")
        files.deleted.clear()
        val c = assertNotNull(app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        server.down = true
        for (i in 1..n) assertEquals(ActionResult.Ok, c.saveLogin(null, login("Site$i"), null))
        assertEquals(n, app.vault!!.queued().pending.size)
        app.lock()
    }

    private fun Env.cacheName(): String = files.opened.last()
    private fun Env.cache(): VaultCache = assertNotNull(files.caches[cacheName()])
    private fun Env.personal(): String = assertNotNull(instance.accounts.values.last().personalWrap).vaultId

    /** [n] sealed changes put straight into the copy's queue (as a first import leaves them). */
    private fun Env.queueMany(n: Int): List<String> {
        val pv = personal()
        return (1..n).map { i ->
            "bulk-$i".also { cache().enqueue(Mutation(it, "put", "bulk-item-$i", pv, 0, ItemUpload(1, emptyList(), "sealed-$i"))) }
        }
    }

    /** The server forbids the copy from its next policy read, and the network is back from that read on. */
    private fun Env.flip() {
        server.forbid = true
        server.upAfterPolicy = true
    }

    private suspend fun Env.runEnds() {
        app.policyWipe.running?.join()
    }

    private fun Env.wipeMark() = PolicyWipeMarks(state).mark(instance.origin, app.keeper.session!!.userId)

    /**
     * A "Move everything" this device started and had not finished stands half-done at the server, and its record here
     * goes with the copy: the notice counts such moves on a line of their own (one kept move over, one not). The change
     * that waited is counted with the rest, as before.
     */
    @Test fun movesOfEverythingNotFinishedAreCountedAndSaidOnALineOfTheirOwn() = runBlocking<Unit> {
        val e = env()
        e.waiting(1)
        val userId = assertNotNull(e.app.keeper.session).userId
        val prefix = "${EngineSharedVaults.MOVE_PREFIX}${e.instance.origin}|$userId|"
        val json = kotlinx.serialization.json.Json
        e.state.set(prefix + "old-vault-1", json.encodeToString(MoveRecord.serializer(), MoveRecord("planned-1", newVaultId = "new-vault-1")))
        e.state.set(prefix + "old-vault-2", json.encodeToString(MoveRecord.serializer(), MoveRecord("planned-2", newVaultId = "new-vault-2", deleteSent = true, storedOutside = true)))
        // The forbidding policy is recorded while locked; the next opening runs the one try.
        e.server.down = false
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        assertNotNull(e.wipeMark())
        e.app.unlockNow()
        e.runEnds()
        assertEquals(1, e.server.taken.size, "the change that waited was sent")
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(0, notice.notSent)
        assertEquals(1, notice.unfinishedMoves, "the move that is over is not counted")
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST, CopyKey.POLICY_COPY_REMOVED_MOVE_UNFINISHED_ONE), notice.lines.map { it.key })
        assertEquals(emptyList(), e.state.keys().filter { it.startsWith(prefix) }, "the move records went with the copy")
        // Kept with the notice, so a restart says the same.
        val again = env(e)
        assertEquals(1, assertNotNull(again.app.snapshot.policyWipe).unfinishedMoves)
        again.app.close()
    }

    /**
     * An owed wipe follows a followed move: the copy goes to the server's new address, and so does the mark that its wipe
     * is owed, naming the same account's copy there. Before, the mark stayed at the old address, which nothing opens any
     * more, and the copy at the new one was used as if no policy forbade it.
     */
    @Test fun anOwedWipeFollowsAFollowedMove() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        val from = e.instance.origin
        val userId = assertNotNull(e.app.keeper.session).userId
        e.server.down = false
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(from), e.instance.now)
        assertTrue(e.app.policyWipeOwed(from, userId))
        val to = "https://moved.example"
        e.app.keeper.moved(from, to)
        e.app.vaultMoved(from)
        assertEquals(to, assertNotNull(e.app.keeper.session).origin)
        assertNull(PolicyWipeMarks(e.state).mark(from, userId), "nothing is owed at the old address, where nothing is left")
        assertNull(assertNotNull(PolicyWipeMarks(e.state).mark(to, userId), "owed at the new address").count)
        assertTrue(e.app.policyWipeOwed(to, userId))
        assertTrue(e.app.policyWipe.owed(to, userId), "the next opening there opens the copy halted, for the run")
    }

    /** The marks themselves: a part left under the old address keeps its mark there too; a notice and an own wipe follow. */
    @Test fun theMarksFollowAMoveAndStayWherePartOfTheCopyIsLeft() {
        val s = MemoryDeviceState()
        val m = PolicyWipeMarks(s)
        m.owe("https://a.example", "u-1")
        m.moved("https://a.example", "https://b.example", "u-1", partly = true)
        assertNotNull(m.mark("https://a.example", "u-1"))
        assertNotNull(m.mark("https://b.example", "u-1"))
        m.gone("https://a.example", "u-2", PolicyWipeMarks.Count(1, 0, false))
        m.ownWipeWaits("https://a.example", "u-2", CopyDeletion.SIGNED_OUT.name)
        m.moved("https://a.example", "https://b.example", "u-2")
        assertEquals(listOf("https://b.example" to 1), m.notices().filter { it.userId == "u-2" }.map { it.origin to it.count.notSent })
        assertEquals(listOf(Triple("https://b.example", "u-2", CopyDeletion.SIGNED_OUT.name)), m.ownWipes())
    }

    /** Two or more such moves are said with their number; a notice kept before moves were counted reads as none. */
    @Test fun manyUnfinishedMovesAreSaidWithTheirNumberAndAnOlderNoticeReadsAsNone() {
        val many = io.silencelen.andvari.core.app.PolicyWipeNotice.of("https://h.example", "Home", 0, 0, false, unfinishedMoves = 3)
        val last = many.lines.last()
        assertEquals(CopyKey.POLICY_COPY_REMOVED_MOVES_UNFINISHED, last.key)
        assertEquals("3", last.values[3])
        val s = MemoryDeviceState()
        s.set(PolicyWipeMarks.NOTICES_KEY, "https://h.example|u-1|2|0|0|0|0")
        assertEquals(0, PolicyWipeMarks(s).notices().single().count.moves)
        assertEquals(2, PolicyWipeMarks(s).notices().single().count.notSent)
    }

    // ---- item 1: nothing is removed before it is counted ----

    /**
     * Sequence 12. The forbidding answer arrives after a lock: before, the next opening composed under the kept
     * forbidding policy and deleted the cache file unread, with both changes in it. Now the wipe is owed from the record;
     * the next opening sends both once, counts, and only then removes the copy.
     */
    @Test fun aForbiddingAnswerThatArrivesAfterALockMakesTheNextOpeningSendBeforeItRemoves() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        val gate = CompletableDeferred<Unit>()
        e.server.policyScript += { gate.await(); true }
        e.server.policyScript += { null }
        e.app.unlockNow()
        e.app.lock()
        gate.complete(Unit)
        assertNotNull(e.wipeMark(), "owed from the moment it was recorded")
        assertEquals(emptyList(), e.files.deleted, "nothing removed while locked")
        assertEquals(2, e.cache().pending().size)

        e.server.down = false
        e.server.forbid = true
        e.app.unlockNow()
        e.runEnds()
        assertEquals(2, e.server.taken.size, "both were sent before anything was removed")
        assertTrue(e.cacheName() in e.files.deleted, "then the copy went")
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(0, notice.notSent)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST, notice.lines.single().key)
        assertNull(e.wipeMark())
        assertFalse(assertNotNull(e.app.vault).keptAtRest, "the account goes on from the server, in memory")
    }

    /**
     * The snapshot says whether the removal is owed for the kept account's own copy, with no id for an app to supply: false
     * under the allowing policy; true once the forbidding policy is recorded while the copy is still there, also after a
     * restart; false once the copy is gone and counted, also after a lock and a restart. The fake reads the same at every
     * step. Before, no snapshot said it, and the desktop read its disk instead.
     */
    @Test fun theSnapshotSaysWhetherTheKeptAccountsRemovalIsOwedAsTheFakeDoes() = runBlocking<Unit> {
        val engine = Readings()
        val e = env()
        e.waiting(1)
        engine += e.app.snapshot.policyWipeOwed
        val gate = CompletableDeferred<Unit>()
        e.server.policyScript += { gate.await(); true }
        e.server.policyScript += { null }
        e.app.unlockNow()
        e.app.lock()
        gate.complete(Unit)
        assertNotNull(e.wipeMark(), "recorded")
        assertEquals(1, e.cache().pending().size, "the copy is still there")
        engine += e.app.snapshot.policyWipeOwed
        e.app.close()
        val again = env(e)
        engine += again.app.snapshot.policyWipeOwed
        again.server.down = false
        again.server.forbid = true
        again.app.unlockNow()
        again.runEnds()
        assertTrue(again.cacheName() in again.files.deleted, "the removal is done")
        assertNull(again.wipeMark())
        engine += again.app.snapshot.policyWipeOwed
        again.app.lock()
        engine += again.app.snapshot.policyWipeOwed
        again.app.close()
        val third = env(again)
        engine += third.app.snapshot.policyWipeOwed
        assertEquals(listOf<Any?>(false, true, true, false, false, false), engine.toList())

        val fake = Readings()
        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        fake += f.snapshot.policyWipeOwed
        f.lock()
        f.script.policyForbidsCopy()
        fake += f.snapshot.policyWipeOwed
        f.script.restart()
        fake += f.snapshot.policyWipeOwed
        assertEquals(VaultUnlockResult.DONE, f.unlock(assertNotNull(f.snapshot.locked), io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD))
        f.script.policyCopyRemoved(notSent = 0)
        fake += f.snapshot.policyWipeOwed
        f.lock()
        fake += f.snapshot.policyWipeOwed
        f.script.restart()
        fake += f.snapshot.policyWipeOwed
        assertEquals(engine.toList(), fake.toList())
    }

    /** Sequence 13. The opening's own read gets no answer and the re-key's cost read records the forbidding policy: the same road. */
    @Test fun theReKeysReadOfAForbiddingPolicyTakesTheSameRoad() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        e.server.policyScript += { null }
        e.flip()
        e.app.unlockNow()
        e.runEnds()
        assertEquals(false, e.app.policies.get(e.instance.origin)?.offlineCacheAllowed, "the re-key's read recorded it")
        assertEquals(2, e.server.taken.size)
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /**
     * Sequence 14. A kept policy record that cannot be read is not a forbidding policy: nothing is deleted, the copy stays
     * closed and the screens are told why, until the policy is read from the server; then it goes on as that policy says.
     */
    @Test fun aKeptPolicyThatCannotBeReadKeepsTheCopyClosedAndDeletesNothing() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        e.state.set(KeptPolicies.KEY_PREFIX + e.instance.origin, "{damaged")
        e.server.policyScript += { null }
        e.server.policyScript += { null }
        e.app.unlockNow()
        assertEquals(AppPhase.UNLOCKED, e.app.snapshot.phase)
        assertNull(e.app.content, "the copy is not opened")
        assertEquals(CopyKey.POLICY_UNREADABLE_COPY_CLOSED, e.app.snapshot.closedForPolicy?.key)
        assertEquals(emptyList(), e.files.deleted, "nor deleted")
        assertEquals(2, e.cache().pending().size)

        // Read from the server: it forbids the copy. What waited is sent first, then the copy goes.
        e.app.lock()
        e.flip()
        e.app.unlockNow()
        e.runEnds()
        assertNull(e.app.snapshot.closedForPolicy)
        assertEquals(2, e.server.taken.size)
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /**
     * Sequence 16. A forbidding policy read while the vault is open, three changes waiting and the server unreachable
     * (no connection can be made), then a lock: before, the three were carried into memory and lost at the lock,
     * uncounted. Now the one attempt's request never leaves the device, so the three are counted as not sent (they are
     * lost), never as "sent with no answer"; the copy is removed and the notice says so. (Check of 2026-11-18, defect C:
     * this test said "none known lost, 3 sent with no answer" before.)
     */
    @Test fun aLiveForbiddingReadCountsTheChangesItCouldNotSend() = runBlocking<Unit> {
        val e = env()
        e.waiting(3)
        e.server.unreachable = true
        e.app.unlockNow()
        // The opening read the allowing policy; the next read (a later opening's) forbids, and the network stays down.
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        e.runEnds()
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(3, notice.notSent, "the one request never left the device")
        assertEquals(0, notice.unsure)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_LOST), notice.lines.map { it.key })
        assertEquals(listOf("3", notice.serverName, "0"), notice.lines[0].values)
        assertTrue(e.cacheName() in e.files.deleted, "the copy went after the count")
        e.app.lock()
        assertSame(notice, e.app.snapshot.policyWipe, "said on the lock screen too")
    }

    /** Defect C's other half: a request that left and got no answer is "may or may not have arrived", not lost. */
    @Test fun aRequestThatLeftAndGotNoAnswerIsMayOrMayNot() = runBlocking<Unit> {
        val e = env()
        e.waiting(3)
        e.app.unlockNow()
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        e.runEnds()
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(3, notice.unsure)
        assertEquals(0, notice.notSent)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_NONE_KNOWN_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE), notice.lines.map { it.key })
    }

    // ---- the check of 2026-11-18 ----

    /**
     * Defect A. While the copy is being removed the content's state says so, with its line, and is not a stopped
     * server: the writes stay offered (each is refused with the line), and a shared vault's change is refused with the
     * same line, not a general failure.
     */
    @Test fun aCopyBeingRemovedIsNotAStoppedServerAndSharedVaultChangesSayTheSameLine() = runBlocking<Unit> {
        val e = env()
        e.waiting(1)
        e.server.pushDelay = { 500 }
        e.flip()
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        val s = c.state
        // The state's own line, by its key: not the save's "this change wasn't made", since nothing was asked for.
        assertEquals(CopyKey.POLICY_COPY_BEING_REMOVED.english, s.removingLine)
        assertTrue(s.removingLine != ContentCopy.COPY_BEING_REMOVED)
        assertFalse(s.serverStopped, "not a stopped server")
        assertTrue(s.sync != VaultSyncState.STOPPED)
        assertTrue(s.items.isNotEmpty() && s.items.all { it.editable }, "Save stays offered, so the refusal can be said")
        assertEquals(ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED), c.saveLogin(null, login("Late"), null))
        val r = e.app.vaults.createVault("Family")
        assertEquals(VaultActionResult.REMOVING_COPY, r)
        assertEquals(CopyKey.SAVE_COPY_BEING_REMOVED, r.sentence)
        e.runEnds()
        assertNull(assertNotNull(e.app.content).state.removingLine, "the new copy in memory is not being removed")
    }

    /**
     * Defect B (the check's p5). The session was ended by its server, with the platform's own content stores (as both
     * apps pass): the queue was read, nothing was sent, and no kept-save record exists. Before, "cannot tell" hid the
     * known 3 and said the copy could not be opened. Now the notice says 3 were lost.
     */
    @Test fun aKnownNumberIsNotHiddenWhereNoKeptRecordExists() = runBlocking<Unit> {
        val e = env(kept = Records())
        e.waiting(3)
        endedThenForbidsWhileLocked(e)
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertFalse(notice.cannotTell)
        assertEquals(3, notice.notSent)
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_LOST), notice.lines.map { it.key })
    }

    /**
     * Defect B, with a kept-save record present that the run cannot open (the session's end closed the content): both
     * are said, at least the 3 known, and that more cannot be told; never "the copy could not be opened" (it was read).
     */
    @Test fun aKeptRecordThatCannotBeReadSaysAtLeastTheKnownNumber() = runBlocking<Unit> {
        val records = Records()
        val e = env(kept = records)
        e.waiting(3)
        // A kept-save record is there (sealed; the run finds it without opening it).
        val userId = assertNotNull(e.app.keeper.session).userId
        records.record(ItemCacheNames.keptPrefix(crypto, e.instance.origin, userId) + ContentStores.KEPT_SAVES).write(byteArrayOf(1, 2, 3))
        endedThenForbidsWhileLocked(e)
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertTrue(notice.cannotTell)
        assertFalse(notice.unopened, "the copy itself was read")
        assertEquals(3, notice.notSent)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_AT_LEAST_LOST, notice.lines[0].key)
        assertEquals("3", notice.lines[0].values[0])
    }

    /** Locked: the server ends the session, then a read records the forbidding policy: the run starts at once, with no open content. */
    private suspend fun endedThenForbidsWhileLocked(e: Env) {
        assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
        e.app.keeper.endedByServer(e.instance.origin)
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        e.runEnds()
        assertNull(e.app.content, "the run read the copy with no content open")
        assertTrue(e.cacheName() in e.files.deleted)
    }

    /** Defect B: each "cannot tell" says only what happened. */
    @Test fun theNoticeSaysWhichPartCouldNotBeRead() {
        fun keys(n: PolicyWipeNotice) = n.lines.map { it.key }
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_CANNOT_TELL), keys(PolicyWipeNotice.of("o", "S", 0, 0, cannotTell = true, unopened = true)))
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_KEPT_UNREAD), keys(PolicyWipeNotice.of("o", "S", 0, 0, cannotTell = true, unopened = false)))
        assertEquals(listOf(CopyKey.POLICY_COPY_REMOVED_AT_LEAST_LOST, CopyKey.POLICY_COPY_REMOVED_UNSURE_ONE),
            keys(PolicyWipeNotice.of("o", "S", 2, 1, cannotTell = true, unopened = false)))
        // A record kept before the kept-records field existed: its "cannot tell" was the copy's.
        val old = PolicyWipeMarks(MemoryDeviceState().also { it.set(PolicyWipeMarks.NOTICES_KEY, "o|u|0|0|1|0") }).notices().single()
        assertTrue(old.count.unopened)
    }

    /**
     * Defect D. "Forget this server" while the run holds the lock: the wipe waits behind it. The app stops before the run
     * ends (the process dies: nothing more of it runs). Before, the held list had already let go of the account, so the
     * next start never removed the copy. Now the waiting wipe is kept durably and the next start makes it.
     */
    @Test fun anOwnWipeThatWaitsBehindTheRunIsMadeAfterAStop() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        e.server.pushDelay = { 5_000 }
        e.flip()
        e.app.unlockNow()
        assertTrue(e.app.policyWipe.lock.held)
        val name = e.cacheName()
        e.app.dropHeldAt(e.instance.origin)
        assertFalse(name in e.files.deleted, "it waits behind the run")
        // The process dies here: a second process starts over the same device state and files.
        val again = env(e)
        assertTrue(name in e.files.deleted, "the next start made the wipe")
        assertEquals(emptyList(), PolicyWipeMarks(e.state).ownWipes())
        e.app.close()
        again.app.close()
    }

    /**
     * The notice belongs to its account: another account's session neither reads it nor puts it away; it is shown where
     * no account is signed in; it goes when its server is forgotten (nothing of the server stays).
     */
    @Test fun theNoticeBelongsToItsAccount() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        val marks = PolicyWipeMarks(e.state)
        marks.gone(e.instance.origin, "someone-else", PolicyWipeMarks.Count(4, 0, false))
        e.app.unlockNow()
        assertNull(e.app.snapshot.policyWipe, "another account's notice is not read inside this one")
        assertEquals(PlainResult.DONE, e.app.signOutConfirmed(assertNotNull(e.app.signOutCheck())))
        val shown = assertNotNull(e.app.snapshot.policyWipe, "no account is signed in: it is shown")
        assertEquals(4, shown.notSent)
        e.app.dropHeldAt(e.instance.origin)
        assertEquals(emptyList(), marks.notices(), "forgetting the server takes it")
    }

    /** An account's deletion on the device takes its notice too (nothing stays). */
    @Test fun anAccountsDeletionTakesItsNotice() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        e.app.unlockNow()
        val s = assertNotNull(e.app.keeper.session)
        PolicyWipeMarks(e.state).gone(s.origin, s.userId, PolicyWipeMarks.Count(1, 0, false))
        e.app.endVault(s, CopyDeletion.ACCOUNT_DELETED)
        assertEquals(emptyList(), PolicyWipeMarks(e.state).notices())
    }

    /**
     * The number the app asks for before it ends counts what waits in memory and, while locked with kept records in
     * memory that cannot be opened, is "cannot be told", never 0.
     */
    @Test fun whatWaitsInMemoryIsCannotBeToldWhileLockedWithKeptRecords() = runBlocking<Unit> {
        var keep = true
        val e = env(keep = { keep })
        e.waiting(0)
        e.app.unlockNow()
        keep = false
        e.app.atRestConsentChanged()
        assertEquals(0, e.app.waitingInMemory())
        val open = assertNotNull(e.app.keeper.established)
        e.app.lock()
        assertEquals(0, e.app.waitingInMemory())
        // A save kept to be finished is held in memory for the account (sealed: it cannot be counted while locked).
        e.app.stores.keeping(open.account, open.origin, false).keptSaves.write(byteArrayOf(9))
        assertNull(e.app.waitingInMemory())
    }

    // ---- item 2: the run ----

    /** Sequence 1. Five changes, the policy flips while locked: one pass sends all five, the copy goes, "nothing lost" once. */
    @Test fun fiveWaitingChangesAreSentOnceThenTheCopyGoesAndNothingIsLost() = runBlocking<Unit> {
        val e = env()
        e.waiting(5)
        // Nothing is sent before the policy is read: the opening's sync meets no network.
        e.flip()
        e.app.unlockNow()
        e.runEnds()
        assertEquals(5, e.server.taken.size)
        assertEquals(1, e.server.pushes.size, "one pass, no second try")
        assertTrue(e.cacheName() in e.files.deleted)
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_NOTHING_LOST, notice.lines.single().key)
        e.app.dismissPolicyWipe(notice)
        assertNull(e.app.snapshot.policyWipe)
        // A restart does not bring it back, and no second wipe is owed.
        e.app.close()
        val again = env(e)
        assertNull(again.app.snapshot.policyWipe)
        again.app.unlockNow()
        again.runEnds()
        assertNull(again.app.snapshot.policyWipe)
        assertEquals(1, e.server.pushes.size)
    }

    /** Sequence 2. 250 waiting; the first request answered, the second held past its limit: may or may not, the rest not sent. */
    @Test fun aRequestHeldPastItsLimitEndsTheAttemptAndTheRestIsNotSent() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        e.queueMany(250)
        e.app.policyWipe.requestMs = 300
        e.app.policyWipe.wholeMs = 3_000
        e.server.pushDelay = { n -> if (n == 1) 1_000 else 0 }
        e.flip()
        e.app.unlockNow()
        e.runEnds()
        assertEquals(2, e.server.pushes.size, "one pass: the third request was never made")
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(100, notice.unsure)
        assertEquals(50, notice.notSent)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_LOST, notice.lines[0].key)
        assertEquals("50", notice.lines[0].values[0])
        assertTrue(e.cacheName() in e.files.deleted)
    }

    /** Sequence 3. 1,000 waiting, each request answered just inside its own limit: the whole limit ends it, the request out is "may or may not". */
    @Test fun theWholeLimitEndsTheAttemptWithTheRequestInFlightUnsure() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        e.queueMany(1_000)
        e.app.policyWipe.requestMs = 400
        e.app.policyWipe.wholeMs = 1_000
        e.server.pushDelay = { 290 }
        e.flip()
        e.app.unlockNow()
        val started = kotlin.time.TimeSource.Monotonic.markNow()
        e.runEnds()
        assertTrue(started.elapsedNow().inWholeMilliseconds < 1_500, "the wipe follows the whole limit")
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(300, e.server.taken.size - 100, "three answered, and the fourth taken without an answer in time")
        assertEquals(100, notice.unsure)
        assertEquals(600, notice.notSent)
    }

    /** Sequence 4. A sign-out during the attempt waits for the run; the count is the run's; the account is signed out after. */
    @Test fun aSignOutDuringTheAttemptWaitsForTheRun() = runBlocking<Unit> {
        val e = env()
        e.waiting(3)
        e.server.pushDelay = { 300 }
        e.flip()
        e.app.unlockNow()
        assertTrue(e.app.policyWipe.lock.held, "the run is under way")
        assertEquals(PlainResult.DONE, e.app.signOutConfirmed(assertNotNull(e.app.signOutCheck())))
        assertFalse(e.app.policyWipe.lock.held)
        assertEquals(3, e.server.taken.size, "the run sent all three before the sign-out went on")
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(0, notice.notSent)
        assertEquals(AppPhase.ENTRY, e.app.snapshot.phase)
    }

    /**
     * Sequence 5. A lock during the attempt: what remains is sealed already, so the attempt goes on to its limit with the
     * session alone, touching no key; the wipe follows without keys, and the notice is on the lock screen.
     */
    @Test fun aLockDuringTheAttemptDoesNotEndItWhereWhatRemainsIsSealed() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        e.queueMany(150)
        e.server.pushDelay = { n -> if (n == 0) 300 else 0 }
        e.flip()
        e.app.unlockNow()
        e.app.lock()
        assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
        e.runEnds()
        assertEquals(150, e.server.taken.size, "both requests made, the second after the lock")
        assertTrue(e.cacheName() in e.files.deleted)
        assertEquals(AppPhase.LOCKED, e.app.snapshot.phase)
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /** Sequence 6. The server ended the session before the run: nothing is sent, the wipe follows at once, every change counted. */
    @Test fun anEndedSessionSendsNothingAndTheWipeFollowsAtOnce() = runBlocking<Unit> {
        val e = env()
        e.waiting(3)
        e.flip()
        e.server.onPolicy = { e.server.onPolicy = null; e.app.keeper.endedByServer(e.instance.origin) }
        e.app.unlockNow()
        e.runEnds()
        assertEquals(0, e.server.taken.size)
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertEquals(3, notice.notSent)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_LOST, notice.lines[0].key)
        assertTrue(e.cacheName() in e.files.deleted)
    }

    /** Sequence 8. Changes parked with a held vault are not sent and count as not sent; the wipe removes them. */
    @Test fun changesParkedWithAHeldVaultAreCountedAsNotSent() = runBlocking<Unit> {
        val e = env()
        e.waiting(1)
        val parked = (1..3).map { Mutation("held-change-$it", "put", "held-item-$it", "held-vault", 1L) }
        e.cache().putHeld(HeldVaultRecord(WireVault("held-vault", "shared", 1, "", 0L), null, emptyList(), "removed", true, null, null, parked, Long.MAX_VALUE))
        e.flip()
        e.app.unlockNow()
        e.runEnds()
        assertEquals(1, e.server.taken.size)
        assertFalse(e.server.taken.any { it.startsWith("held-change") }, "parked changes are not sent")
        assertEquals(3, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /** Sequence 9. A copy that cannot be opened is "cannot tell", never "nothing lost"; the file is still removed. */
    @Test fun aCopyThatCannotBeOpenedIsCannotTellNeverNothingLost() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        // The forbidding policy is recorded while locked; then the file is damaged before the next opening.
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        assertNotNull(e.wipeMark())
        e.files.broken = true
        e.server.down = false
        e.app.unlockNow()
        e.runEnds()
        val notice = assertNotNull(e.app.snapshot.policyWipe)
        assertTrue(notice.cannotTell)
        assertEquals(CopyKey.POLICY_COPY_REMOVED_CANNOT_TELL, notice.lines[0].key)
        assertTrue(e.cacheName() in e.files.deleted)
    }

    /**
     * Sequence 10. The wipe could not be made (the file is held): the mark stays, nothing is said; the policy allows the
     * copy again at the next opening: the mark ends, nothing is said or deleted, the copy is used again.
     */
    @Test fun aLiftedPolicyEndsTheWipeThatCouldNotBeMade() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        e.files.holdDelete = true
        e.flip()
        e.app.unlockNow()
        e.runEnds()
        assertNull(e.app.snapshot.policyWipe, "a wipe not made is not said as made")
        assertNotNull(assertNotNull(e.wipeMark()).count, "counted, owed still")
        e.app.lock()
        e.app.close()
        // A restart while it still forbids tries again: still held.
        val second = env(e)
        assertNull(second.app.snapshot.policyWipe)
        second.files.holdDelete = false
        second.files.deleted.clear()
        second.server.forbid = false
        second.app.unlockNow()
        assertNull(second.wipeMark(), "the lifted policy ended the mark")
        assertNull(second.app.snapshot.policyWipe)
        second.app.lock()
        second.app.unlockNow()
        assertTrue(assertNotNull(second.app.vault).keptAtRest, "the copy is used again")
        assertEquals(emptyList(), second.files.deleted)
    }

    /** Sequence 11. The app stops in the middle: the next opening runs again from the start; the server takes each once; one notice. */
    @Test fun aStopInTheMiddleRunsAgainFromTheStart() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        e.server.pushDelay = { n -> if (n == 0) 5_000 else 0 }
        e.flip()
        e.app.unlockNow()
        assertTrue(e.app.policyWipe.lock.held)
        e.app.close()
        assertNull(assertNotNull(e.wipeMark()).count, "still owed: nothing counted")
        assertEquals(emptyList(), e.files.deleted)
        val again = env(e)
        again.app.unlockNow()
        again.runEnds()
        assertEquals(2, e.server.pushes.size, "the attempt again, from the start")
        assertEquals(2, e.server.taken.size, "each taken once")
        assertEquals(0, assertNotNull(again.app.snapshot.policyWipe).notSent)
    }

    /**
     * Item 3 (beside the policy): on a device that keeps nothing at rest, changes that wait stay in memory, sealed,
     * through a lock, and are sent after the next unlock. Here "Keep me signed in" is turned off while two changes made
     * offline wait: the copy goes to memory with them; a lock; an unlock with the server back: both arrive. Before, the
     * lock dropped them without a word. Until the unlock, the app interface says how many would be lost if the app ended.
     */
    @Test fun aLockOnADeviceThatKeepsNothingAtRestKeepsTheWaitingChangesAndSendsThemAfterTheUnlock() = runBlocking<Unit> {
        var keep = true
        val e = env(keep = { keep })
        e.waiting(2)
        e.app.unlockNow()
        keep = false
        e.app.atRestConsentChanged()
        assertFalse(assertNotNull(e.app.vault).keptAtRest, "the copy is in memory now")
        assertEquals(2, e.app.waitingInMemory())
        e.app.lock()
        assertEquals(2, e.app.waitingInMemory(), "kept through the lock, in memory only")
        e.server.down = false
        e.app.unlockNow()
        assertEquals(2, e.server.taken.size, "sent after the unlock")
        assertEquals(0, e.app.waitingInMemory())
    }

    /**
     * The switch that keeps data on the device, turned off (the desktop's "Keep me signed in"), with the platform's own
     * records (which then hold what the content kept in memory: the desktop carries them there). A save with a file that
     * a lock cut short is read by the opening that follows and counted by what waits in memory, locked ("cannot be told")
     * and open. Before, that opening was handed records of its own, empty: the save was neither read nor counted.
     */
    @Test fun withTheSwitchOffTheOpeningThatFollowsReadsWhatWasCarriedToMemory() = runBlocking<Unit> {
        var keep = true
        val e = env(keep = { keep }, kept = Records())
        e.waiting(0)
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        c.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, c.addAttachment("a.bin", ByteArray(1) { 7 }))
        assertTrue(c.saveLogin(null, login("Doc"), null) is ActionResult.Failed, "the file could not go up: kept to finish")
        assertEquals(1, c.keptSavesWaiting())
        // A lock cuts it short; then the switch goes off.
        e.app.lock()
        keep = false
        e.app.atRestConsentChanged()
        assertNull(e.app.waitingInMemory(), "locked, what is kept in memory cannot be counted")
        e.app.unlockNow()
        assertFalse(assertNotNull(e.app.vault).keptAtRest, "the opening is in memory")
        assertEquals(1, assertNotNull(e.app.content).keptSavesWaiting(), "the opening read what was carried")
        assertEquals(1, e.app.waitingInMemory(), "and what waits in memory counts it")
    }

    /** As above, with the switch turned off while the account is open: the composition that follows reads it at once. */
    @Test fun withTheSwitchOffWhileOpenTheCompositionThatFollowsReadsWhatWasKept() = runBlocking<Unit> {
        var keep = true
        val e = env(keep = { keep }, kept = Records())
        e.waiting(0)
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        c.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, c.addAttachment("a.bin", ByteArray(1) { 7 }))
        assertTrue(c.saveLogin(null, login("Doc"), null) is ActionResult.Failed)
        assertEquals(1, c.keptSavesWaiting())
        keep = false
        e.app.atRestConsentChanged()
        assertFalse(assertNotNull(e.app.vault).keptAtRest, "the copy is in memory now")
        assertEquals(1, assertNotNull(e.app.content).keptSavesWaiting(), "the composition read what was kept")
        assertEquals(1, e.app.waitingInMemory())
    }

    /** Point 6. While the wipe is owed, a change the person makes is refused with its own line, and nothing is queued. */
    @Test fun aChangeMadeWhileTheCopyIsBeingRemovedIsRefusedWithItsOwnLine() = runBlocking<Unit> {
        val e = env()
        e.waiting(1)
        e.server.pushDelay = { 500 }
        e.flip()
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        val r = c.saveLogin(null, login("Late"), null)
        assertEquals(ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED), r)
        assertEquals(1, e.cache().pending().size, "nothing new taken in")
        e.runEnds()
    }

    // ---- the check of 2026-11-19 ----

    /** What a read refused while the copy is being removed leaves: the state as it was, never a stopped server. */
    private fun assertStillRemoving(c: io.silencelen.andvari.core.app.content.VaultContent, before: VaultSyncState, road: String) {
        val s = c.state
        assertEquals(ContentCopy.REMOVING_LINE, s.removingLine, road)
        assertFalse(s.serverStopped, road)
        assertTrue(s.sync != VaultSyncState.STOPPED, "$road: not a stopped server")
        assertEquals(before, s.sync, "$road: the state as it was")
        assertTrue(s.items.all { it.editable }, "$road: Save stays offered")
    }

    /**
     * The check's probe a1: the bin, an item's history and the deleted vaults, each opened while the copy is being
     * removed, are refused, and the state stays as it was. Before, each refusal turned the state to stopped, so both
     * apps hid Save and said "andvari has stopped using this server" for the rest of the removal.
     */
    @Test fun aReadRefusedWhileTheCopyIsBeingRemovedLeavesTheStateAsItWas() = runBlocking<Unit> {
        val e = env()
        e.waiting(1)
        e.server.pushDelay = { 500 }
        e.flip()
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        val before = c.state.sync
        assertStillRemoving(c, before, "at the start")
        val item = c.state.items.first().itemId
        assertIs<ActionResult.Failed>(c.openTrash())
        assertStillRemoving(c, before, "the bin")
        assertIs<ActionResult.Failed>(c.openItemHistory(item))
        assertStillRemoving(c, before, "the history")
        assertIs<ActionResult.Failed>(c.openDeletedVaults())
        assertStillRemoving(c, before, "the deleted vaults")
        e.runEnds()
    }

    /** A sync that was running when the removal began ends refused, and the state stays as it was. */
    @Test fun aSyncRunningWhenTheRemovalBeginsLeavesTheStateAsItWas() = runBlocking<Unit> {
        val e = env()
        e.waiting(0)
        e.server.down = false
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        e.server.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Offline"), null))
        val before = c.state.sync
        e.server.down = false
        // The sync's push is held; the run's own pushes longer, so the content stays open until the sync has answered
        // (with both held alike, a loaded machine let the run close the content first, and the sync answered NotDone).
        val base = e.server.pushes.size
        e.server.pushDelay = { if (it == base) 300 else 1_500 }
        val sync = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.syncQuietly() }
        assertTrue(sync.isActive, "the sync waits on the server's answer")
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        assertIs<ActionResult.Failed>(sync.await())
        assertStillRemoving(c, before, "the sync")
        e.runEnds()
    }

    /** Signed up and opened again with the server in reach under the allowing policy: the open content. */
    private suspend fun Env.openNow(): io.silencelen.andvari.core.app.content.VaultContent {
        waiting(0)
        server.down = false
        app.unlockNow()
        return assertNotNull(app.content)
    }

    /**
     * The check's probe a2: the server holds a save's answer back for a moment, and the forbidding policy is recorded
     * meanwhile. The server stored the save; before, the drain met the halt after the answered batch and the person
     * was told "this change wasn't made" (while the notice afterwards said nothing was lost). Now it is settled as made.
     */
    @Test fun aSaveTheServerStoredWhileThePolicyWasRecordedIsMade() = runBlocking<Unit> {
        val e = env()
        val c = e.openNow()
        val base = e.server.pushes.size
        e.server.pushDelay = { if (it == base) 400 else 1_500 }
        val save = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.saveLogin(null, login("New"), null) }
        assertTrue(save.isActive, "the server holds the save's answer back")
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        assertEquals(ActionResult.Ok, save.await(), "the server stored it")
        e.runEnds()
        assertEquals(1, e.server.taken.size)
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /**
     * Where the code can tell a save's change is still queued (it waits behind an answered batch when the halt lands),
     * it goes in the policy's one try: "may or may not arrive", never settled as made.
     */
    @Test fun aSaveStillQueuedBehindAnAnsweredBatchMayOrMayNotArrive() = runBlocking<Unit> {
        val e = env()
        val c = e.openNow()
        // More than one batch (the server's limit is 200): the save's change is in the second.
        e.queueMany(250)
        val base = e.server.pushes.size
        // The run's own requests take longer, so the content is still open when the save answers.
        e.server.pushDelay = { if (it == base) 400 else 1_500 }
        val save = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.saveLogin(null, login("New"), null) }
        assertTrue(save.isActive)
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        assertEquals(ActionResult.Failed(ContentCopy.IN_POLICY_ATTEMPT), save.await())
        e.runEnds()
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /**
     * A save stopped before its change was ever queued (it waited behind a running sync, and the halt landed then) is
     * said as not made, never as "may or may not arrive": nothing of it is queued or sent.
     */
    @Test fun aSaveStoppedBeforeItWasQueuedIsNotMade() = runBlocking<Unit> {
        val e = env()
        val c = e.openNow()
        e.server.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Offline"), null))
        e.server.down = false
        // The run's own requests take longer, so the content is still open when the save answers.
        val base = e.server.pushes.size
        e.server.pushDelay = { if (it == base) 300 else 1_500 }
        val sync = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.syncQuietly() }
        val save = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { c.saveLogin(null, login("Blocked"), null) }
        assertTrue(save.isActive, "it waits behind the sync")
        e.server.forbid = true
        e.app.policies.fetch(e.app.clientFor(e.instance.origin), e.instance.now)
        sync.await()
        assertEquals(ActionResult.Failed(ContentCopy.COPY_BEING_REMOVED), save.await())
        e.runEnds()
        assertEquals(1, e.server.taken.size, "only the change that waited was sent: nothing of the save was queued")
        assertEquals(0, assertNotNull(e.app.snapshot.policyWipe).notSent)
    }

    /**
     * The check's probe h1: the process's part ends between the record of a forbidding policy (on the recording thread)
     * and the hop to the main thread. Before, the mark was written only after the hop, so it was never written: the two
     * changes stayed at rest under a forbidding policy, never sent, counted or said. Now the mark is at rest from the
     * record on, and the next start runs the attempt.
     */
    @Test fun theMarkIsAtRestFromTheRecordEvenWhenTheProcessEndsBeforeTheHop() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        val userId = assertNotNull(e.app.keeper.session).userId
        val client = e.app.clientFor(e.instance.origin)
        // The process's part ends: nothing launched on its scope runs any more.
        e.app.close()
        e.server.forbid = true
        e.app.policies.fetch(client, e.instance.now)
        assertNotNull(PolicyWipeMarks(e.state).mark(e.instance.origin, userId), "the mark is at rest")
        val again = env(e)
        e.server.down = false
        again.app.unlockNow()
        again.runEnds()
        assertEquals(2, e.server.taken.size, "both were sent at the next start")
        assertEquals(0, assertNotNull(again.app.snapshot.policyWipe).notSent)
        assertTrue(e.cacheName() in e.files.deleted, "then the copy went")
        again.app.close()
    }

    /**
     * The check's probe n1: "Forget this server" while the run holds its lock. The run's wipe wrote the notice and
     * redrew; the forgetting, made after it, took the record. Before, nothing redrew then, so the screens showed the
     * notice of a server just forgotten until something else redrew. Now the snapshot carries no notice.
     */
    @Test fun aServerForgottenWhileTheRunHoldsItsLockLeavesNoNoticeOnShow() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        e.server.pushDelay = { 300 }
        e.flip()
        e.app.unlockNow()
        assertTrue(e.app.policyWipe.lock.held)
        e.app.dropHeldAt(e.instance.origin)
        e.runEnds()
        assertEquals(emptyList(), PolicyWipeMarks(e.state).notices(), "the record went")
        assertNull(e.app.snapshot.policyWipe, "and nothing of it is on show")
    }

    /** The check's probe n2: the account's deletion while the run holds its lock leaves no notice on show either. */
    @Test fun anAccountDeletedWhileTheRunHoldsItsLockLeavesNoNoticeOnShow() = runBlocking<Unit> {
        val e = env()
        e.waiting(2)
        e.server.pushDelay = { 300 }
        e.flip()
        e.app.unlockNow()
        assertTrue(e.app.policyWipe.lock.held)
        e.app.endVault(assertNotNull(e.app.keeper.session), CopyDeletion.ACCOUNT_DELETED)
        e.runEnds()
        assertEquals(emptyList(), PolicyWipeMarks(e.state).notices(), "the record went")
        assertNull(e.app.snapshot.policyWipe, "and nothing of it is on show")
    }

    /** For a server that is stopped (it ended the session), a refused read still says so, as before. */
    @Test fun aReadRefusedByAStoppedServerStillSaysStopped() = runBlocking<Unit> {
        val e = env()
        e.waiting(1)
        e.app.keeper.endedByServer(e.instance.origin)
        e.app.unlockNow()
        val c = assertNotNull(e.app.content)
        assertNull(c.state.removingLine)
        assertTrue(c.state.serverStopped)
        assertIs<ActionResult.Failed>(c.openTrash())
        assertEquals(VaultSyncState.STOPPED, c.state.sync)
        assertTrue(c.state.serverStopped)
    }
}
