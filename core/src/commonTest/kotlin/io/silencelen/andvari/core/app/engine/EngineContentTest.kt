package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.client.items.BellLink
import io.silencelen.andvari.core.client.items.BellSocket
import io.silencelen.andvari.core.client.items.BellState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.EventFrame
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.SignupPolicy
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The vault's content on the engine-backed API: composed at every unlock, closed at a lock, its cache deleted at the end of the session. */
class EngineContentTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** Cache files that are only recorded: each open hands out a cache in memory. */
    private class Files : VaultCacheFiles {
        val opened = ArrayList<String>()
        val deleted = ArrayList<String>()
        val caches = ArrayList<VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache {
            opened += fileName
            return InMemoryVaultCache().also { caches += it }
        }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            return true
        }
    }

    private class Env(
        val server: FakeInstance, val transport: BearerTransport, val files: Files, val app: EngineAppApi,
        val state: MemoryDeviceState, val secure: MemoryDeviceState,
    )

    /** The platform's app-private files for the kept records, by name. */
    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobSets = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobSets.getOrPut(name) { InMemoryBlobs() }
        fun holds(): List<String> = records.filterValues { it.bytes != null }.keys.sorted() + blobSets.filterValues { it.ids().isNotEmpty() }.keys.sorted()
    }

    /** A new process over the same server and stores ([from]'s), or a first one. */
    private fun env(
        contentStores: ContentStores? = null, from: Env? = null, secure: MemoryDeviceState? = null, bell: BellSocket? = null,
        keep: () -> Boolean = { true }, front: (io.silencelen.andvari.core.client.net.WireClient) -> io.silencelen.andvari.core.client.net.WireClient = { it },
    ): Env {
        val server = from?.server ?: FakeInstance(crypto)
        val files = from?.files ?: Files()
        val transport = from?.transport ?: BearerTransport(mapOf(server.origin to front(server)))
        bell?.let { transport.bell = it }
        val state = from?.state ?: MemoryDeviceState()
        val sec = secure ?: from?.secure ?: MemoryDeviceState()
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, state, sec, crypto,
                { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, contentStores = contentStores, keepsAtRest = keep),
        ).also { it.start() }
        return Env(server, transport, files, app, state, sec)
    }

    private fun movesOf(disk: Disk, a: EngineAppApi): FillSnapshotStore {
        val s = assertNotNull(a.keeper.session)
        return disk.record(ItemCacheNames.keptPrefix(crypto, s.origin, s.userId) + ContentStores.MOVES)
    }

    /**
     * The content keeps its records in the platform's files only under a policy, as last read, that allows keeping data
     * at rest. The first opening read none, so that process keeps them in memory for good; the next process (the policy
     * now known) keeps them in files. There the queue's key is published, a login an extension captured is read when the
     * app returns to the foreground, a lock keeps everything, and a sign-out empties it all.
     */
    @Test fun theContentKeepsItsRecordsInThePlatformsFilesOnlyWhileThePolicyAllowsIt() = runBlocking<Unit> {
        val disk = Disk()
        val queue = InMemorySaveQueue()
        val first = env(ContentStores(crypto, disk, queue))
        open(first.app)
        val s = first.app.keeper.session!!
        assertTrue(first.app.stores.inMemory(s.origin, s.userId), "no policy was read at the first opening: memory")
        first.app.lock()
        assertEquals(VaultUnlockResult.DONE, first.app.unlock(first.app.snapshot.locked!!, strong))
        assertTrue(first.app.stores.inMemory(s.origin, s.userId), "what was kept in memory stays there for the process")
        first.app.lock()
        first.app.close()

        val e = env(ContentStores(crypto, disk, queue), from = first)
        val a = e.app
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertFalse(a.stores.inMemory(s.origin, s.userId), "the policy allows it: the platform's files")
        movesOf(disk, a).write(byteArrayOf(1))
        // (This test server serves no sync, after which the content reads the queue by itself: the return to the
        // foreground reads it here.)
        a.returnedToForeground()
        assertNotNull(queue.publication(), "the key the extensions seal to is published")
        assertEquals(SaveQueued.QUEUED, SaveQueue.enqueue(queue, crypto, "bank.example", "alice", "pw-1", e.server.now, "safari"))
        // A network that came back tells live updates alone: the queue is not read.
        val sent = e.server.calls.size
        a.networkReturned()
        assertEquals(0, a.content!!.state.let { it.appliedSaves.size + it.pendingSaves.size }, "a network's return reads no save queue")
        assertEquals(sent, e.server.calls.size, "and sends nothing")
        a.returnedToForeground()
        val st = a.content!!.state
        // Read: saved by itself, or listed with its reason (this test server serves no personal vault to save into).
        assertEquals(1, st.appliedSaves.size + st.pendingSaves.size, "the capture was read")
        movesOf(disk, a).write(byteArrayOf(2))
        a.lock()
        assertNotNull(movesOf(disk, a).read(), "a lock keeps what the content kept")
        assertNotNull(queue.publication())
        // Locked, this device cannot count what was not sent: the sign-out takes the person's second confirmation.
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, a.signOut())
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        assertEquals(emptyList(), disk.holds())
        assertNull(queue.publication(), "the account is gone: no key is left for the extensions")
    }

    /**
     * Before the policy is read nothing is kept at rest: what the files held for the account goes at the opening. And a
     * stop between the person's own end of a session and the deletion of its data is finished at the next start: the
     * cache file and the kept records of an account no longer kept on this device go. (Only an
     * end the keeper recorded as the person's own act; `EngineKeptAccountLateTest` holds the other side.)
     */
    @Test fun nothingIsKeptAtRestBeforeThePolicyIsReadNorLeftFromAnAccountThatIsGone() = runBlocking<Unit> {
        val disk = Disk()
        val first = env(ContentStores(crypto, disk))
        open(first.app)
        assertEquals(emptyList(), disk.holds(), "no policy was read at the opening: nothing at rest")
        val s = first.app.keeper.session!!
        first.app.lock()
        first.app.close()
        // What a later process would have kept for the account, and then the person's sign-out ended the session (the
        // keeper's durable record of it) and a stop came before its data went.
        val prefix = ItemCacheNames.keptPrefix(crypto, s.origin, s.userId)
        disk.record(prefix + ContentStores.MOVES).write(byteArrayOf(2))
        first.state.set(io.silencelen.andvari.core.client.session.SessionKeeper.OWN_ENDS_KEY, "${s.origin}|${s.userId}")
        first.files.deleted.clear()
        val e = env(ContentStores(crypto, disk), from = first, secure = MemoryDeviceState())
        assertEquals(AppPhase.ENTRY, e.app.snapshot.phase)
        assertEquals(emptyList(), disk.holds(), "the account is gone: what was left goes at the start")
        assertEquals(listOf(ItemCacheNames.fileName(crypto, s.origin, s.userId)), e.files.deleted, "its cache file too")
        assertNull(e.state.get(EngineAppApi.HELD_KEY))
        assertNull(e.state.get(io.silencelen.andvari.core.client.session.SessionKeeper.OWN_ENDS_KEY), "the record is settled")
    }

    /** Without the platform's files the process keeps the account's records in memory: across a lock, never past its end. */
    @Test fun withoutThePlatformsFilesTheProcessKeepsTheRecordsAcrossALockAndNotPastTheEnd() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val origin = a.keeper.session!!.origin
        val userId = a.keeper.session!!.userId
        assertTrue(a.stores.inMemory(origin, userId))
        val before = a.stores.keeping(a.keeper.established!!.account, origin, false)
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val after = a.stores.keeping(a.keeper.established!!.account, origin, true)
        assertTrue(before.moves === after.moves && before.files === after.files, "the same records across a lock")
        after.moves.write(byteArrayOf(1))
        assertEquals(PlainResult.DONE, a.signOut())
        assertNull(after.moves.read())
        assertFalse(a.stores.inMemory(origin, userId), "the account's records go with it")
    }

    /**
     * The policy turns to forbidding an offline copy while the vault is open with one at rest: the vault is composed
     * again at once, so the cache file and the kept records leave the disk without waiting for the next unlock.
     */
    @Test fun aPolicyThatNowForbidsAnOfflineCopyTakesItOffTheDiskWhileUnlocked() = runBlocking<Unit> {
        val disk = Disk()
        val first = env(ContentStores(crypto, disk))
        open(first.app)
        first.app.lock()
        first.app.close()
        val e = env(ContentStores(crypto, disk), from = first)
        val a = e.app
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val before = assertNotNull(a.vault)
        assertTrue(before.keptAtRest)
        movesOf(disk, a).write(byteArrayOf(1))
        e.files.deleted.clear()
        // The next reading of the policy says no.
        e.server.override[io.silencelen.andvari.core.model.wire.WireRoute.CLIENT_POLICY] = WireResult.Ok(
            WireJson.json.encodeToString(ClientPolicy.serializer(), ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, false, 3600, 30, 1, 1, e.server.now,
                SignupPolicy(SignupMode.OPEN, false, true, 0), false)), 200,
        )
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        // That unlock composed with the policy as kept (allowing), then read it again: forbidden now.
        val now = assertNotNull(a.vault)
        assertFalse(now === before)
        assertFalse(now.keptAtRest, "composed again under the new policy")
        assertEquals(emptyList(), disk.holds(), "the kept records left the disk")
        assertTrue(ItemCacheNames.fileName(crypto, a.keeper.session!!.origin, a.keeper.session!!.userId) in e.files.deleted, "and the cache file")
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        // Decided on 2026-11-17: the policy's run took them off (after trying once to send what waited, here nothing),
        // and says so once the copy is gone.
        val notice = assertNotNull(a.snapshot.policyWipe)
        assertEquals(0, notice.notSent)
        assertFalse(notice.cannotTell)
    }

    /**
     * The session layer's point (spec 03 §2, "What a client does at a lock that keeps no token"): what a lock
     * does with the session's tokens where nothing may be kept at rest (the platform's consent off, the server's policy
     * forbidding an offline copy). The app KEEPS its pair at every lock, there too: the kept session (its wrap and its
     * tokens, in the platform's secure store) is what the password unlocks from, so the lock sends nothing, neither
     * `end-session` nor a logout, and the next unlock needs no sign-in. Only a host that drops its pair at a lock (the
     * web tab) ends that one session with `client.endSession(newestRefreshToken)`; this one never does.
     */
    @Test fun aLockWhereNothingMayBeKeptAtRestKeepsThePairAndSendsNothing() = runBlocking<Unit> {
        val e = env(keep = { false })
        val a = e.app
        e.server.override[io.silencelen.andvari.core.model.wire.WireRoute.CLIENT_POLICY] = WireResult.Ok(
            WireJson.json.encodeToString(ClientPolicy.serializer(), ClientPolicy(emptyMap(), KdfParams.DEFAULT, 300, 30, false, 3600, 30, 1, 1, e.server.now,
                SignupPolicy(SignupMode.OPEN, false, true, 0), false)), 200,
        )
        open(a)
        assertFalse(assertNotNull(a.vault).keptAtRest)
        val sent = e.transport.sent.size
        val kept = assertNotNull(a.keeper.session)
        a.lock()
        assertEquals(sent, e.transport.sent.size, "a lock sends nothing: ${e.transport.sent.drop(sent).map { it.route }}")
        assertEquals(kept.userId, assertNotNull(a.keeper.session, "the pair is kept").userId)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val after = e.transport.sent.drop(sent).map { it.route }
        assertTrue(after.none { it == io.silencelen.andvari.core.model.wire.WireRoute.END_SESSION || it == io.silencelen.andvari.core.model.wire.WireRoute.LOGOUT ||
            it == io.silencelen.andvari.core.model.wire.WireRoute.PRELOGIN || it == io.silencelen.andvari.core.model.wire.WireRoute.LOGIN }, "no session was ended or opened anew: $after")
    }

    /**
     * The desktop's ask: the platform's own consent to a copy at rest ("keep me signed in") turns off while the vault is
     * open with its copy at rest. [EngineAppApi.atRestConsentChanged] composes it again at once on a cache in memory that
     * carries what was queued to send, and the cache file is deleted before it returns. Before, the queue went with the
     * file.
     */
    @Test fun aConsentThatStopsAllowingACopyAtRestCarriesWhatIsQueuedIntoMemory() = runBlocking<Unit> {
        var keep = true
        val first = env(keep = { keep })
        open(first.app)
        first.app.lock()
        first.app.close()
        val e = env(from = first, keep = { keep })
        val a = e.app
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val before = assertNotNull(a.vault)
        assertTrue(before.keptAtRest, "the policy (kept) and the consent allow it: a file")
        val file = e.files.caches.last()
        val vaultId = before.personalVaultId
        val queued = io.silencelen.andvari.core.model.Mutation("m-queued", "delete", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", vaultId, 3)
        val denied = io.silencelen.andvari.core.model.Mutation("m-denied", "delete", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", vaultId, 4)
        file.enqueue(queued)
        file.enqueue(denied)
        file.markStagedDenied(denied.mutationId)

        // The consent still allows it: nothing changes.
        a.atRestConsentChanged()
        assertTrue(a.vault === before)

        keep = false
        e.files.deleted.clear()
        val opened = e.files.opened.size
        a.atRestConsentChanged()
        val now = assertNotNull(a.vault)
        assertFalse(now === before)
        assertFalse(now.keptAtRest, "composed again with its cache in memory")
        assertEquals(opened, e.files.opened.size, "no file was opened for it")
        assertTrue(ItemCacheNames.fileName(crypto, a.keeper.session!!.origin, a.keeper.session!!.userId) in e.files.deleted, "the file is deleted")
        val carried = now.queued()
        assertEquals(listOf("m-queued"), carried.pending.map { it.mutationId }, "what was queued to send is still queued")
        assertEquals(listOf("m-denied"), carried.staged.map { it.mutationId }, "a denied change still waits for its fate")
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)

        // The next opening under the same consent stays in memory.
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertFalse(assertNotNull(a.vault).keptAtRest)
    }

    /** A bell socket that plays [frames] after the client's ping, then holds the socket open until it is closed. */
    private class Bell(private val frames: List<String>) : BellSocket {
        val opened = ArrayList<String>()
        var closed = 0
        override suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T? {
            opened += origin
            val left = ArrayDeque(frames)
            try {
                return block(object : BellLink {
                    override suspend fun send(text: String): Boolean = true
                    override suspend fun receive(): String? = left.removeFirstOrNull() ?: kotlinx.coroutines.awaitCancellation()
                })
            } finally {
                closed++
            }
        }
    }

    private fun ticket(server: FakeInstance) {
        server.override[io.silencelen.andvari.core.model.wire.WireRoute.EVENTS_TICKET] =
            WireResult.Ok("""{"ticket":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","expiresInSeconds":30}""", 200)
    }

    /** The bell rings while the vault is open, at the session's origin: every registered open and every newer rev syncs; a lock stops it. */
    @Test fun theBellRunsWhileTheVaultIsOpenAndARingSyncs() = runBlocking<Unit> {
        val socket = Bell(listOf(EventFrame.PONG, """{"type":"rev","rev":5}""", """{"type":"rev","rev":5}"""))
        val e = env(bell = socket)
        ticket(e.server)
        val a = e.app
        open(a)
        val bell = assertNotNull(a.vault?.bell)
        assertEquals(listOf(e.server.origin), socket.opened)
        assertEquals(BellState.OPEN, bell.state)
        val syncs = e.server.calls.count { it == io.silencelen.andvari.core.model.wire.WireRoute.SYNC }
        // The opening's own sync, then one more for the rings (the registered open and both rev 5) that came while it ran:
        // they are coalesced (hostile harness H12). This server answers no pull, so no rev is known to be answered, and a
        // ring's own rev is never taken as one.
        assertEquals(2, syncs)
        a.lock()
        assertEquals(BellState.IDLE, bell.state)
        assertEquals(1, socket.closed, "the lock closed the socket")
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertFalse(a.vault?.bell === bell, "a new opening, a new bell")
    }

    /** A bell socket that plays what the test sends on [frames], one by one, until it is closed. */
    private class FloodBell(private val frames: kotlinx.coroutines.channels.Channel<String>) : BellSocket {
        override suspend fun <T> open(origin: String, ticket: String, block: suspend (BellLink) -> T): T? =
            block(object : BellLink {
                override suspend fun send(text: String): Boolean = true
                override suspend fun receive(): String? = frames.receive()
            })
    }

    /**
     * Hostile harness H12 (the engine's `BellLiesTest`): a flood of rings that arrive while a sync runs costs one
     * more sync after it, not one per ring; a ring with an absurdly high rev costs one sync and does not silence the
     * honest rings after it; a ring at or below the rev the server's own sync answered at costs nothing.
     */
    @Test fun aFloodOfRingsCostsOneMoreSyncAndAnAbsurdRevSilencesNoLaterRing() = runBlocking<Unit> {
        val frames = kotlinx.coroutines.channels.Channel<String>(kotlinx.coroutines.channels.Channel.UNLIMITED)
        var probe: LockProbe? = null
        val e = env(bell = FloodBell(frames), front = { LockProbe(it).also { p -> probe = p } })
        ticket(e.server)
        val a = e.app
        open(a)
        val p = assertNotNull(probe)
        val route = io.silencelen.andvari.core.model.wire.WireRoute.SYNC
        val personal = assertNotNull(a.keeper.established!!.account.personalVaultId)
        e.server.override[route] = WireResult.Ok(io.silencelen.andvari.core.model.wire.WireJson.json.encodeToString(
            io.silencelen.andvari.core.model.wire.SyncResponse.serializer(),
            io.silencelen.andvari.core.model.wire.SyncResponse(5, false, listOf(io.silencelen.andvari.core.model.wire.SyncVault(personal, "personal", 1, "", e.server.now)),
                emptyList(), emptyList(), emptyList(), emptyList(), 0, 0)), 200)
        fun syncs() = p.log.count { it.first == route }
        suspend fun settlesAt(n: Int, why: String) {
            kotlinx.coroutines.withTimeout(10_000) { while (syncs() < n) kotlinx.coroutines.delay(5) }
            kotlinx.coroutines.delay(100)
            assertEquals(n, syncs(), why)
        }
        fun rev(r: Long) = """{"type":"rev","rev":$r}"""

        // The registration's ring pulls, and the server holds that pull while 400 rings arrive.
        val held = p.hold(route)
        val start = syncs()
        frames.send(EventFrame.PONG)
        kotlinx.coroutines.withTimeout(10_000) { held.reached.await() }
        for (r in 6L..405L) frames.send(rev(r))
        kotlinx.coroutines.withTimeout(10_000) { while (!frames.isEmpty) kotlinx.coroutines.delay(5) }
        held.release.complete(Unit)
        settlesAt(start + 2, "400 rings during a sync cost one more sync")

        // The pull answered at rev 5: a ring at or below it costs nothing.
        frames.send(rev(5))
        settlesAt(start + 2, "a ring the server's own answer already covered")
        // An absurd rev costs one sync and silences nothing after it.
        frames.send(rev(Long.MAX_VALUE / 2))
        settlesAt(start + 3, "the absurd ring pulls once")
        frames.send(rev(406))
        settlesAt(start + 4, "an honest ring after it still pulls")
        a.lock()
    }

    /** A `revoked` frame ends the session as the server's own end. */
    @Test fun aRevokedBellEndsTheSessionAsTheServersEnd() = runBlocking<Unit> {
        val socket = Bell(listOf(EventFrame.PONG, """{"type":"revoked"}"""))
        val e = env(bell = socket)
        ticket(e.server)
        val a = e.app
        open(a, unlocked = false)
        assertNull(a.content)
        assertEquals(io.silencelen.andvari.core.client.session.SessionEndReason.REFRESH_REFUSED, a.keeper.lastEnd)
    }

    @Test fun aBackupUsesThePolicysKdfCostOnlyWithinTheClientsFence() {
        val policies = io.silencelen.andvari.core.client.session.KeptPolicies(MemoryDeviceState())
        fun policy(k: KdfParams) = io.silencelen.andvari.core.model.wire.ClientPolicy(emptyMap(), k, 300, 30, true, 3600, 30, 1, 2, 3,
            io.silencelen.andvari.core.model.wire.SignupPolicy(io.silencelen.andvari.core.model.wire.SignupMode.OPEN, false, true, 20), false, "x", "https://h.example", null)
        val strongCost = KdfParams(ops = 4, memBytes = 128L * 1024 * 1024)
        assertEquals(strongCost, policies.record("https://h.example", policy(strongCost), 0).kdfParams)
        assertNull(policies.record("https://h.example", policy(KdfParams(ops = 1, memBytes = 8L * 1024 * 1024)), 0).kdfParams, "below the floor")
        assertNull(policies.record("https://h.example", policy(KdfParams(ops = 50, memBytes = 64L * 1024 * 1024)), 0).kdfParams, "above the ceiling")
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Typed address, Trust Gate, sign-up, kit: the vault is open. */
    private suspend fun open(a: EngineAppApi, unlocked: Boolean = true) {
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
        if (unlocked) assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private fun cacheName(a: EngineAppApi): String {
        val kept = assertNotNull(a.keeper.session)
        return ItemCacheNames.fileName(crypto, kept.origin, kept.userId)
    }

    @Test fun theContentIsThereOnlyWhileUnlockedAndIsNewAtEveryUnlock() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val first = assertNotNull(a.content)
        assertEquals(first.state.revision, a.snapshot.account!!.contentRevision)
        val before = a.snapshot.account!!.contentRevision
        first.setQuery("bank")
        assertTrue(a.snapshot.account!!.contentRevision > before, "a change of the content publishes a snapshot")
        assertEquals(first.state.revision, a.snapshot.account!!.contentRevision)

        a.lock()
        assertNull(a.content)
        assertNull(a.vault)
        assertIs<ActionResult.NotDone>(first.syncQuietly(), "the instance of the last unlock is closed")

        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val second = assertNotNull(a.content)
        assertFalse(second === first, "a new instance per unlock")
    }

    @Test fun theCacheIsAFileOnlyOnceThePolicyAllowsItAndALockKeepsIt() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val name = cacheName(a)
        // At the first opening no policy was read yet: the cache is in memory. A policy never read removes nothing (decided
        // on 2026-11-17: only the policy's run removes a copy, after counting it); no file was written either.
        assertTrue(e.files.opened.isEmpty())
        assertEquals(emptyList(), e.files.deleted)
        assertTrue(name.isNotEmpty())
        assertTrue(a.snapshot.account!!.policy.offlineCacheAllowed)

        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(listOf(name), e.files.opened, "the policy allows an offline cache: the account's own file")
        a.lock()
        assertEquals(emptyList(), e.files.deleted, "a lock keeps the file")
    }

    @Test fun signingOutDeletesTheCacheFile() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val name = cacheName(a)
        val c = assertNotNull(a.content)
        e.files.deleted.clear()
        assertEquals(PlainResult.DONE, a.signOut())
        assertNull(a.content)
        assertEquals(listOf(name), e.files.deleted)
        assertIs<ActionResult.NotDone>(c.syncQuietly())
    }

    @Test fun signingOutWhileLockedDeletesTheCacheFileToo() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val name = cacheName(a)
        a.lock()
        e.files.deleted.clear()
        // Locked: the person's second confirmation, as this device cannot count what was not sent.
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        assertEquals(listOf(name), e.files.deleted)
    }

    /**
     * Design §4.4: a refused refresh ends the session, not the copy. The account stays
     * as signed out by the server; nothing of its copy is deleted; the password opens it read-only and nothing is sent;
     * signing in again to the same account takes it back. Only the person's sign-out deletes it.
     */
    @Test fun aRefusedRefreshEndsTheSessionAndKeepsTheCopy() = runBlocking<Unit> {
        val disk = Disk()
        val first = env(ContentStores(crypto, disk))
        open(first.app)
        first.app.lock()
        first.app.close()
        val e = env(ContentStores(crypto, disk), from = first)
        val a = e.app
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val name = cacheName(a)
        movesOf(disk, a).write(byteArrayOf(1))
        val c = assertNotNull(a.content)
        e.files.deleted.clear()
        e.transport.refreshAnswer = { io.silencelen.andvari.core.client.net.WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("refresh_reuse", "x")) }
        e.transport.expired += "at-${a.keeper.session!!.deviceId}"
        a.keeper.clientFor(e.server.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        val locked = assertNotNull(a.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertNull(a.content)
        assertIs<ActionResult.NotDone>(c.syncQuietly())
        assertEquals(emptyList(), e.files.deleted, "the cache file stays")
        assertNotNull(movesOf(disk, a).read(), "the kept records stay")

        // The password opens the copy read-only, and nothing is sent.
        e.server.calls.clear()
        assertEquals(VaultUnlockResult.DONE, a.unlock(locked, strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertTrue(a.snapshot.account!!.serverStopped)
        assertTrue(a.snapshot.account!!.signedOutByServer, "the account's snapshot says so too")
        assertTrue(assertNotNull(a.vault).signedOutByServer)
        assertFalse(a.content!!.syncQuietly() == ActionResult.Ok, "a halted copy does not sync")
        assertTrue(e.server.calls.none { it == io.silencelen.andvari.core.model.wire.WireRoute.SYNC }, "sent: ${e.server.calls}")
        a.lock()

        // Sign in again: the same account at the same server takes the copy back, its first sync sends what waited.
        // (This test server hands this device the same token names again: they are good once more.)
        e.transport.expired.clear()
        e.transport.refreshAnswer = null
        a.signInAgain(a.snapshot.locked!!)
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), e.server.origin))
        val form = a.snapshot.entry
        val signIn = if (form is EntryScreen.TrustGate) {
            assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(form))
            a.at<EntryScreen.SignIn>()
        } else assertIs<EntryScreen.SignIn>(form)
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, a.entry.submitSignIn(signIn, "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertFalse(a.keeper.session!!.endedByServer)
        assertFalse(a.snapshot.account!!.serverStopped)
        assertTrue(e.server.calls.any { it == io.silencelen.andvari.core.model.wire.WireRoute.SYNC }, "it syncs again")
        assertEquals(emptyList(), e.files.deleted)
    }

    /**
     * Decided on 2026-11-16: while an account its server signed out is kept, a sign-in to another account
     * is refused with its own answer, before anything is sent, and the journey names the kept account. The sign-out
     * works from the journey and deletes that copy.
     */
    @Test fun anotherAccountIsRefusedWhileAServerEndedOneIsKeptUntilItIsSignedOut() = runBlocking<Unit> {
        val first = env()
        open(first.app)
        first.app.lock()
        first.app.close()
        val e = env(from = first)
        val a = e.app
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val name = cacheName(a)
        e.files.deleted.clear()
        e.transport.refreshAnswer = { WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("refresh_reuse", "x")) }
        e.transport.expired += "at-${a.keeper.session!!.deviceId}"
        a.keeper.clientFor(e.server.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertTrue(a.snapshot.locked!!.signedOutByServer)
        assertNull(a.snapshot.keptSignedOut, "only the journey names it")
        e.transport.refreshAnswer = null
        e.transport.expired.clear()

        a.signInAgain(a.snapshot.locked!!)
        assertEquals("alice@example.com", assertNotNull(a.snapshot.keptSignedOut).email)
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), e.server.origin))
        val signIn = a.at<EntryScreen.SignIn>()
        e.server.calls.clear()
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.ANOTHER_ACCOUNT_KEPT, a.entry.submitSignIn(signIn, "Bob@Example.com", strong))
        assertTrue(e.server.calls.none { it == io.silencelen.andvari.core.model.wire.WireRoute.PRELOGIN || it == io.silencelen.andvari.core.model.wire.WireRoute.LOGIN }, "sent: ${e.server.calls}")
        assertTrue(a.keeper.session!!.endedByServer, "the kept account stays as it was")
        assertEquals(emptyList(), e.files.deleted)

        // "Sign out of that account first": the sign-out works here, and deletes its copy, on the person's second
        // confirmation (what its copy holds unsent cannot be counted here).
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        assertNull(a.keeper.session)
        assertNull(a.snapshot.keptSignedOut)
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertEquals(listOf(name), e.files.deleted)
    }

    /**
     * Account deletion on the engine (§3.11 and the account-deletion design): the plan from the preview, a refusal said
     * as such, an answer that never came kept as an unknown outcome until a check says the account is there, and a
     * deletion that went through deleting this device's copy (`ACCOUNT_DELETED`) and the account's identity record.
     */
    @Test fun anAccountDeletionKeepsAnUnknownOutcomeUntilCheckedAndDeletesTheCopyWhenDone() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val est = a.keeper.established!!
        val personal = assertNotNull(est.account.personalVaultId)
        val name = cacheName(a)
        e.files.deleted.clear()
        e.server.override[io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":["$personal"],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        val screen = assertNotNull(a.snapshot.account!!.deletion)
        val plan = assertNotNull(screen.plan)
        assertTrue(plan.canProceed)
        assertEquals(listOf("Personal"), plan.deletedVaults)
        assertEquals("alice@example.com", screen.email)

        val del = io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_DELETE
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.EMAIL_MISMATCH, a.settings.deleteAccount(screen, "bob@example.com", strong, null))
        assertTrue(e.server.calls.none { it == del }, "a typo sends nothing")
        e.server.override[del] = WireResult.Refused(403, io.silencelen.andvari.core.model.wire.WireError("reauth_failed", "x"))
        // The server's refusal of the right password's proof is never a wrong password (a wrong one is found on the device).
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.PROOF_REFUSED, a.settings.deleteAccount(a.snapshot.account!!.deletion!!, "alice@example.com", strong, null))

        // No answer: neither done nor failed, until a check says the account is still there.
        e.server.override[del] = WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.OUTCOME_UNKNOWN, a.settings.deleteAccount(a.snapshot.account!!.deletion!!, "alice@example.com", strong, null))
        val unknown = assertNotNull(a.snapshot.account!!.deletion)
        assertTrue(unknown.outcomeUnknown)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertEquals(emptyList(), e.files.deleted, "nothing is deleted on an unknown outcome")
        assertEquals(PlainResult.DONE, a.settings.checkDeletion(unknown))
        assertFalse(assertNotNull(a.snapshot.account!!.deletion).outcomeUnknown, "the preview answered: the account is there")
        assertEquals(PlainResult.STALE, a.settings.checkDeletion(a.snapshot.account!!.deletion!!), "nothing to check now")

        // Deleted: this device's copy goes with the session and the account's identity record.
        e.server.override[del] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.DONE, a.settings.deleteAccount(a.snapshot.account!!.deletion!!, " Alice@Example.com ", strong, null))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        // The first screen says the deletion once, in a field of its own (no new FirstRunNotice value).
        val first = assertIs<io.silencelen.andvari.core.app.EntryScreen.FirstRun>(a.snapshot.entry)
        assertNull(first.notice)
        val said = assertNotNull(first.accountDeleted)
        assertEquals("https://h.example", said.instance.origin)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN, said.line.key)
        a.entry.dismissNotice(first)
        assertNull(assertIs<io.silencelen.andvari.core.app.EntryScreen.FirstRun>(a.snapshot.entry).accountDeleted)
        assertNull(a.keeper.session)
        assertEquals(listOf(name), e.files.deleted)
        assertNull(a.keeper.knownIdentity(est.userId), "the identity record goes with the account")
        assertNull(e.state.get(EngineAppApi.HELD_KEY))
    }

    /**
     * After a deletion whose answer never came,
     * only the server's answer settles "we cannot tell yet". A typo in the address, a wrong password proven on this device
     * and a session the server then ends (the likely sign that the deletion landed) all keep it, and it is said on the
     * lock screen, in this process and the next; the account's own sign-out clears it.
     */
    @Test fun anUnknownDeletionOutcomeIsSettledOnlyByTheServerAndOutlivesASessionTheServerEnds() = runBlocking<Unit> {
        val first = env()
        open(first.app)
        first.app.lock()
        first.app.close()
        val e = env(from = first)
        val a = e.app
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        e.server.override[io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        assertEquals(PlainResult.DONE, a.settings.openDeletion())
        val del = io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_DELETE
        e.server.override[del] = WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.OUTCOME_UNKNOWN, a.settings.deleteAccount(a.snapshot.account!!.deletion!!, "alice@example.com", strong, null))
        assertTrue(a.snapshot.account!!.deletion!!.outcomeUnknown)

        // A typo sends nothing and settles nothing; nor does a wrong password, proven on this device.
        e.server.calls.clear()
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.EMAIL_MISMATCH, a.settings.deleteAccount(a.snapshot.account!!.deletion!!, "bob@example.com", strong, null))
        assertTrue(a.snapshot.account!!.deletion!!.outcomeUnknown, "a typo is not the server's answer")
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.WRONG_PASSWORD, a.settings.deleteAccount(a.snapshot.account!!.deletion!!, "alice@example.com", "not the password at all 3", null))
        assertTrue(a.snapshot.account!!.deletion!!.outcomeUnknown, "a wrong password proven here is not the server's answer")
        assertTrue(e.server.calls.none { it == del }, "sent: ${e.server.calls}")

        // The server ends the session: the copy is kept, and the lock screen says the outcome is still unknown.
        e.transport.refreshAnswer = { WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("refresh_reuse", "x")) }
        e.transport.expired += "at-${a.keeper.session!!.deviceId}"
        a.keeper.clientFor(e.server.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        val locked = assertNotNull(a.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertFalse(locked.sessionNotConfirmed, "the server's own end")
        assertNull(locked.endLine)
        assertTrue(locked.deletionOutcomeUnknown, "said with the lock screen")
        a.close()

        // The next process says it too.
        val next = env(from = e)
        assertTrue(assertNotNull(next.app.snapshot.locked).deletionOutcomeUnknown, "kept across a restart")

        // "Sign in again": the first screen says it too, beside its notice, until dismissed.
        next.app.signInAgain(assertNotNull(next.app.snapshot.locked))
        val firstRun = assertIs<EntryScreen.FirstRun>(next.app.snapshot.entry)
        assertEquals(io.silencelen.andvari.core.app.FirstRunNotice.SIGNED_OUT_BY_SERVER, firstRun.notice)
        val said = assertNotNull(firstRun.deletionOutcomeUnknown, "the first screen says the outcome is unknown")
        assertEquals("alice@example.com", said.email)
        assertEquals(e.server.origin, said.instance.origin)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ACCOUNT_DELETION_UNKNOWN, said.line.key)
        assertNull(firstRun.accountDeleted, "nothing says it was deleted")
        next.app.entry.dismissNotice(firstRun)
        assertNull(assertIs<EntryScreen.FirstRun>(next.app.snapshot.entry).deletionOutcomeUnknown, "dismissed")

        // The account's own sign-out settles it.
        assertEquals(PlainResult.DONE, next.app.signOutConfirmed(assertNotNull(next.app.signOutCheck())))
        val userId = first.server.accounts.values.single().userId
        assertNull(next.state.get("${EngineAccountSettings.OUTCOME_UNKNOWN_KEY}${e.server.origin}|$userId"))
    }

    /**
     * A refresh whose answer was lost twice leaves no try: this device ends the session itself, and the lock screen, a
     * restart's lock screen and the first screen after "Sign in again" say that end as itself (this device could not
     * confirm its session in time), never "signed out by its server" (before: the server's end, in all three).
     */
    @Test fun aSessionThisDeviceCouldNotConfirmInTimeIsSaidAsItselfNeverAsTheServersEnd() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        // The server makes each refresh (the second within its grace, with the same pair) and the device never hears back.
        e.transport.graceMs = 60_000
        e.transport.clock = { e.server.now }
        e.transport.loseAnswers = 2
        e.transport.expired += "at-${a.keeper.session!!.deviceId}"
        repeat(4) {
            if (a.keeper.session?.endedByServer != true) {
                a.keeper.clientFor(e.server.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
            }
        }
        assertTrue(assertNotNull(a.keeper.session).endedUnconfirmed, "no try left")
        val locked = assertNotNull(a.snapshot.locked)
        assertTrue(locked.signedOutByServer, "handled as a kept session with no token")
        assertTrue(locked.sessionNotConfirmed)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED, locked.endLine)
        a.close()

        val next = env(from = e)
        val again = assertNotNull(next.app.snapshot.locked)
        assertTrue(again.sessionNotConfirmed, "kept across a restart")
        // The kept session's mark is the same copy's across the restart (a way out under an older notice stays offered).
        assertTrue(locked.prompt.keptMark.isNotEmpty())
        assertEquals(locked.prompt.keptMark, again.prompt.keptMark, "the mark across a restart")
        // A copy opened after such an end says it as itself, never as the server's end.
        assertEquals(VaultUnlockResult.DONE, next.app.unlock(again, strong))
        val opened = assertNotNull(next.app.snapshot.account)
        assertTrue(opened.signedOutByServer)
        assertTrue(opened.sessionNotConfirmed)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_COPY_OPEN, opened.endLine)
        next.app.lock()
        next.app.signInAgain(assertNotNull(next.app.snapshot.locked))
        val first = assertIs<EntryScreen.FirstRun>(next.app.snapshot.entry)
        assertNull(first.notice, "never SIGNED_OUT_BY_SERVER")
        assertTrue(first.sessionNotConfirmed)
        // What the first screen says of the kept account says the same end.
        assertNotNull(next.app.snapshot.keptSignedOut)
        assertTrue(next.app.snapshot.keptSignedOutNotConfirmed)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED, next.app.snapshot.keptSignedOutLine)
        // Beside the kept account where it must be signed out first: a line of its own that does not say "sign in again".
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST, next.app.snapshot.keptSignedOutSignOutFirstLine)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST, first.sessionNotConfirmedBesideSignOut)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST, locked.endLineBesideSignOut)
        // The fake, through the script's public member for this end, reads the same on the lock screen, on the first screen
        // after "Sign in again", and of the kept account there.
        fun lockRead(l: io.silencelen.andvari.core.app.LockedScreen) = listOf(l.signedOutByServer, l.sessionNotConfirmed, l.endLine, l.endLineBesideSignOut)
        fun firstRead(r: EntryScreen.FirstRun) = listOf(r.notice, r.sessionNotConfirmed, r.sessionNotConfirmedBesideSignOut)
        fun kept(s: io.silencelen.andvari.core.app.AppSnapshot) = listOf(s.keptSignedOut != null, s.keptSignedOutNotConfirmed, s.keptSignedOutLine, s.keptSignedOutSignOutFirstLine)
        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        f.script.sessionNotConfirmed()
        val fLocked = assertNotNull(f.snapshot.locked)
        assertEquals(lockRead(locked), lockRead(fLocked), "the lock screen")
        f.signInAgain(fLocked)
        assertEquals(firstRead(first), firstRead(assertIs<EntryScreen.FirstRun>(f.snapshot.entry)), "the first screen")
        assertEquals(kept(next.app.snapshot), kept(f.snapshot), "the kept account")
        next.app.entry.dismissNotice(first)
        assertFalse(assertIs<EntryScreen.FirstRun>(next.app.snapshot.entry).sessionNotConfirmed, "dismissed")
    }

    /**
     * While an account its server signed out is kept here, sign-up for a new account is
     * refused at its first step, before an address or a code is sent anywhere.
     */
    @Test fun aNewAccountIsRefusedAtSignUpsFirstStepWhileAServerEndedOneIsKept() = runBlocking<Unit> {
        val first = env()
        open(first.app)
        first.app.lock()
        first.app.close()
        val e = env(from = first)
        val a = e.app
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        e.transport.refreshAnswer = { WireResult.Refused(401, io.silencelen.andvari.core.model.wire.WireError("refresh_reuse", "x")) }
        e.transport.expired += "at-${a.keeper.session!!.deviceId}"
        a.keeper.clientFor(e.server.origin).call(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        assertTrue(a.snapshot.locked!!.signedOutByServer)
        e.transport.refreshAnswer = null
        e.transport.expired.clear()

        a.signInAgain(a.snapshot.locked!!)
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        e.server.calls.clear()
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.ANOTHER_ACCOUNT_KEPT, a.entry.startSignUp(a.at(), "bob@example.com", true))
        assertTrue(e.server.calls.none { it == io.silencelen.andvari.core.model.wire.WireRoute.SIGNUP_START || it == io.silencelen.andvari.core.model.wire.WireRoute.SIGNUP_VERIFY },
            "no address and no code were sent: ${e.server.calls}")
        assertTrue(a.keeper.session!!.endedByServer, "the kept account stays as it was")
    }

    @Test fun forgettingTheSessionsServerDeletesTheCacheFile() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        val name = cacheName(a)
        e.files.deleted.clear()
        assertEquals(PlainResult.DONE, a.instance.forgetServer(a.snapshot.instance!!))
        assertNull(a.content)
        assertEquals(setOf(name), e.files.deleted.toSet())
        // The engine's per-origin wipe took the pin and the records kept under the origin and its account.
        assertEquals(io.silencelen.andvari.core.client.pin.PinState.None, a.trust.pinState(e.server.origin))
        assertNull(e.state.get(EngineAppApi.HELD_KEY))
    }
}
