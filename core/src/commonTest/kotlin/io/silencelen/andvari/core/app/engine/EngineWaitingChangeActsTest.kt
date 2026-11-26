package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.WaitingChanges
import io.silencelen.andvari.core.app.WaitingKind
import io.silencelen.andvari.core.app.WaitingKnown
import io.silencelen.andvari.core.app.WaitingResult
import io.silencelen.andvari.core.app.WaitingUndo
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.SelfWrapPut
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A change to a shared vault that waits, over the real engine and a server whose answer to each log append is chosen by
 * the test: an act lands only on the very change the person saw, in the opening of the account it was drawn in; a deletion
 * is asked about only after a look of its own; an addition is never sent again to a contact that is gone, has another key
 * or is no longer compared; and each line says only what this device knows. The stand-in plays the same where it holds
 * the same state.
 */
class EngineWaitingChangeActsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val carol = "33333333-3333-4333-8333-333333333333"
    private val dave = "55555555-5555-4555-8555-555555555555"
    private val erin = "66666666-6666-4666-8666-666666666666"
    private val dayAndAHour = 25L * 60 * 60 * 1000

    /** The server's vault side: each vault's stored log, its grants, and what was stored and asked for. */
    private inner class VaultServer(val instance: FakeInstance) {
        val logs = LinkedHashMap<String, MutableList<String>>()
        val meta = HashMap<String, String>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        var rev = 1L
        val stored = ArrayList<Pair<String, LogEntry?>>()
        val calls = ArrayList<Pair<WireRoute, String?>>()

        /** Run once (then cleared) at the next call, before it is answered. */
        var onCall: (suspend (WireRoute) -> Unit)? = null

        private fun head(log: List<String>) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last())))

        fun fetchesOf(vaultId: String) = calls.count { it.first == WireRoute.LOG_FETCH && it.second == vaultId }

        fun client(caller: () -> String?): WireClient = object : WireClient {
            override val origin: String = instance.origin
            override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                calls += route to pathParams["vaultId"]
                return instance.callBytes(route, pathParams, query, body, authenticated, decode)
            }

            override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> {
                calls += route to pathParams["vaultId"]
                return instance.fetchBytes(route, pathParams, query, authenticated)
            }

            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                onCall?.let { hook ->
                    onCall = null
                    hook(route)
                }
                val user = caller()
                calls += route to pathParams["vaultId"]
                fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
                return when (route) {
                    WireRoute.SYNC -> {
                        val mine = grants.values.filter { it.userId == user }
                        val vaults = mine.mapNotNull { g ->
                            val log = logs[g.vaultId] ?: return@mapNotNull null
                            SyncVault(g.vaultId, "shared", rev, meta[g.vaultId].orEmpty(), 0, SyncLogHead(log.size - 1L, head(log)))
                        }
                        val full = query?.removePrefix("since=")?.toLongOrNull() == 0L
                        ok(WireJson.json.encodeToString(SyncResponse.serializer(), SyncResponse(rev++, full, vaults, mine, emptyList(), emptyList(), emptyList(), 0, 0, null)))
                    }
                    WireRoute.PUSH -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    WireRoute.LOG_FETCH -> {
                        val log = logs[pathParams.getValue("vaultId")] ?: return WireResult.Refused(403, WireError("no_grant", "m"))
                        val from = ((query?.removePrefix("after=")?.toLong() ?: -1) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        ok(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, LogHead(log.size - 1L, head(log), 0), deleted = null)))
                    }
                    WireRoute.VAULT_MEMBERS -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val rows = grants.keys.filter { it.first == vaultId }.map { (_, u) ->
                            VaultMemberSummary(u, "$u@example.com", "", grants.getValue(vaultId to u).role, Bytes.toB64(ByteArray(32)), 0)
                        }
                        ok(WireJson.json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), rows))
                    }
                    WireRoute.LOG_APPEND -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val log = logs.getOrPut(vaultId) { ArrayList() }
                        val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                        if (req.entry !in log) {
                            val frame = Bytes.fromB64(req.entry)
                            val prior = if (log.isEmpty()) null else VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                            if (VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD) !is Checked.Ok) {
                                return WireResult.Refused(400, WireError("bad_entry", "m"))
                            }
                            log += req.entry
                            val entry = VaultLog.parse(crypto, frame).valueOrNull()?.entry
                            stored += vaultId to entry
                            if (entry is LogEntry.Genesis) grants[vaultId to user!!] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, rev)
                            if (entry is LogEntry.Add) grants[vaultId to entry.member] = SyncGrant(vaultId, entry.member, entry.role.literal, "", rev, req.grant)
                            if (entry is LogEntry.Remove) grants.remove(vaultId to entry.member)
                            req.metaBlob?.let { meta[vaultId] = it }
                        }
                        ok(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(rev++, LogHead(log.size - 1L, head(log), 0), null)))
                    }
                    WireRoute.VAULT_SELF_WRAP -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                        grants[vaultId to user!!] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk)
                        ok("{\"rev\":${rev++}}")
                    }
                    WireRoute.VAULT_META -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }

        /** The server stores [frame] itself, later: a signed entry that reached it, appended while its place is free. */
        fun storeLater(vaultId: String, frame: String) {
            logs.getValue(vaultId) += frame
            stored += vaultId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        }
    }

    private enum class Ans { PASS, LOST, LIE, REFUSE }

    /** Answers each log append as [answer] says for its entry, and keeps every entry and frame posted. */
    private class Front {
        var answer: (LogEntry?) -> Ans = { Ans.PASS }
        val posted = ArrayList<Pair<LogEntry?, String>>()
        val crypto = createCryptoProvider()

        fun wrap(inner: WireClient): WireClient = object : WireClient by inner {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                if (route == WireRoute.LOG_APPEND) {
                    val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                    val bytes = Bytes.fromB64(req.entry)
                    val e = VaultLog.parse(crypto, bytes).valueOrNull()?.entry
                    posted += e to req.entry
                    when (answer(e)) {
                        Ans.PASS -> {}
                        Ans.LOST -> return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                        Ans.LIE -> {
                            val head = LogHead(e!!.seq, Bytes.toHexLower(crypto.sha256(bytes)), 0)
                            return WireResult.Ok(decode(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(1_000, head))), 200)
                        }
                        Ans.REFUSE -> return WireResult.Refused(403, WireError("forbidden", "x"))
                    }
                }
                return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }

        fun count(kind: (LogEntry?) -> Boolean) = posted.count { kind(it.first) }

        fun last(kind: (LogEntry?) -> Boolean) = posted.last { kind(it.first) }.second
    }

    private fun app(front: Front): Pair<VaultServer, EngineAppApi> {
        val server = VaultServer(FakeInstance(crypto))
        var self: EngineAppApi? = null
        val client = front.wrap(server.client { self?.keeper?.session?.userId })
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to client)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, cacheFiles = null),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return server to app
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** A new account at the server, signed in on this device. */
    private suspend fun open(a: EngineAppApi, email: String = "alice@example.com") {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** A compared contact with identity key [key], confirmed on this device (also over an earlier record of [userId]). */
    private suspend fun contact(a: EngineAppApi, server: VaultServer, userId: String, label: String, key: String = Bytes.toB64(crypto.randomBytes(32))): ContactRow {
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (userId to ContactRecord(userId, key, TrustGrammar.encodeName(label)!!, verifiedAt = server.instance.now, compared = true,
                madeOn = "44444444-4444-4444-8444-444444444444")))
        }
        a.contacts.openContacts()
        val row = a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }
        a.contacts.confirmOnThisDevice(row)
        val now = a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }
        a.contacts.closeContacts()
        return now
    }

    private fun EngineAppApi.row() = snapshot.account!!.vaults.single { !it.deleted && it.name == "Family" }
    private fun EngineAppApi.rowOf(id: String) = snapshot.account!!.vaults.single { it.vaultId == id }
    private fun AppApi.waits() = vaults as WaitingChanges
    private fun AppApi.notices() = snapshot.account!!.waitingNotices

    /** "Family", owned here, shared with Carol (writer) and Dave (reader). */
    private suspend fun family(a: EngineAppApi, server: VaultServer): String {
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val c = contact(a, server, carol, "Carol")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.addMember(a.snapshot.account!!.members!!, c, MemberRole.WRITER))
        a.vaults.closeMembers()
        val d = contact(a, server, dave, "Dave")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.addMember(a.snapshot.account!!.members!!, d, MemberRole.READER))
        a.vaults.closeMembers()
        return server.logs.keys.single()
    }

    /** A completed sync of the open vault: the general re-send and the looks follow it. */
    private fun sync(a: EngineAppApi) = a.vault!!.afterLogAction()

    private suspend fun removeDave(a: EngineAppApi): VaultActionResult {
        a.vaults.openMembers(a.row())
        val r = a.vaults.removeMember(a.snapshot.account!!.members!!.members.single { it.userId == dave })
        a.vaults.closeMembers()
        return r
    }

    private suspend fun addErin(a: EngineAppApi, e: ContactRow): VaultActionResult {
        a.vaults.openMembers(a.row())
        val r = a.vaults.addMember(a.snapshot.account!!.members!!, e, MemberRole.WRITER)
        a.vaults.closeMembers()
        return r
    }

    /** An entry another device of this account signs and the server stores, at the head of [vaultId]'s log. */
    private fun otherDevice(a: EngineAppApi, server: VaultServer, vaultId: String, make: (Long, String, String, Long) -> LogEntry) {
        val log = server.logs.getValue(vaultId)
        val state = assertNotNull(VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state)
        val pos = VaultLog.position(state, server.instance.now + 1_000)
        val me = a.keeper.established!!
        val entry = make(pos.seq, pos.prev, me.userId, pos.at)
        log += Bytes.toB64(me.account.signing.use { kp -> VaultLog.sign(crypto, kp, entry) })
        server.stored += vaultId to entry
    }

    private fun addsOf(front: Front, member: String) = front.count { (it as? LogEntry.Add)?.member == member }

    // ---- an act lands only on the change the person saw, in the opening it was drawn in ----

    /**
     * "Withdraw" tapped on an addition that settled meanwhile, while a later removal of another member waits: the row is
     * stale, nothing is withdrawn or sent, and the removal is sent again and made. Before, the tap withdrew the removal,
     * and the member the person removed kept the vault's key.
     */
    @Test fun withdrawTappedOnAnAdditionThatNoLongerWaitsIsStaleAndTheRemovalThatWaitsIsKept() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        val e = contact(a, server, erin, "Erin")
        front.answer = { if (it is LogEntry.Add) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, addErin(a, e))
        val addition = assertNotNull(a.row().waiting)
        assertEquals(WaitingKind.ADD, addition.kind)
        front.answer = { Ans.PASS }
        sync(a)
        assertNull(a.row().waiting, "the addition was sent again and made")
        front.answer = { if (it is LogEntry.Remove) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, removeDave(a))
        assertEquals(WaitingKind.REMOVE, a.row().waiting?.kind)
        val posted = front.posted.size
        assertEquals(WaitingResult.STALE, a.waits().withdrawWaiting(addition), "the addition the person saw no longer waits")
        assertEquals(posted, front.posted.size, "nothing is sent")
        assertEquals(WaitingKind.REMOVE, a.row().waiting?.kind, "the removal that waits now is not withdrawn")
        front.answer = { Ans.PASS }
        sync(a)
        sync(a)
        assertTrue(server.stored.any { it.first == vaultId && it.second is LogEntry.Remove }, "the removal is made")
        assertFalse(server.grants.containsKey(vaultId to dave), "Dave no longer holds the vault's key")
    }

    /**
     * Across a lock and an unlock: an addition drawn before the lock, tapped after it while the person's deletion of the
     * vault waits, is stale and keeps nothing; the deletion drawn before the lock is stale too; only an object drawn in this
     * opening acts. Before, the old tap withdrew the person's deletion of the vault.
     */
    @Test fun withdrawTappedOnAnObjectDrawnBeforeALockIsStaleAndTheDeletionThatWaitsIsKept() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        val e = contact(a, server, erin, "Erin")
        front.answer = { if (it is LogEntry.Add) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, addErin(a, e))
        val addition = assertNotNull(a.row().waiting)
        front.answer = { Ans.PASS }
        sync(a)
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val deletionBefore = assertNotNull(a.rowOf(vaultId).waiting)
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(WaitingKind.DELETION, a.rowOf(vaultId).waiting?.kind)
        val posted = front.posted.size
        assertEquals(WaitingResult.STALE, a.waits().withdrawWaiting(addition))
        assertEquals(WaitingResult.STALE, a.waits().withdrawWaiting(deletionBefore), "drawn in the opening before the lock")
        assertEquals(WaitingResult.STALE, a.waits().deleteWaitingNow(deletionBefore))
        assertEquals(posted, front.posted.size, "nothing is sent")
        val now = assertNotNull(a.rowOf(vaultId).waiting)
        assertEquals(WaitingKind.DELETION, now.kind, "the deletion is not withdrawn")
        assertEquals(WaitingResult.KEPT_MAY_BE_DELETED, a.waits().withdrawWaiting(now), "the object drawn in this opening acts")
        assertEquals(posted, front.posted.size)
    }

    /**
     * The person's deletion is found made and the vault restored; a later deletion of it is another entry: it is asked
     * about only after a look of its own, and the question about the earlier deletion sends nothing. Before, the later
     * deletion was asked about with no look, and the old question sent it.
     */
    @Test fun aLaterDeletionIsLookedAtBeforeItIsAskedAboutAndTheEarlierQuestionSendsNothing() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val first = assertNotNull(a.row().waiting)
        assertTrue(first.asksForWord)
        server.storeLater(vaultId, front.last { it is LogEntry.Delete })
        front.answer = { Ans.PASS }
        sync(a)
        assertTrue(a.rowOf(vaultId).deleted)
        val made = a.notices().single { it.kind == WaitingKind.DELETION }
        assertEquals(CopyKey.WAITING_FOUND_DELETED to WaitingUndo.RESTORE_VAULT, made.line.key to made.undo, "the vault reads deleted: the restore is offered")
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(a.rowOf(vaultId)))
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        val fetches = server.fetchesOf(vaultId)
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.rowOf(vaultId)))
        assertTrue(server.fetchesOf(vaultId) > fetches, "the later deletion gets a look of its own")
        val later = assertNotNull(a.rowOf(vaultId).waiting)
        assertTrue(later.asksForWord)
        val deletions = front.count { it is LogEntry.Delete }
        front.answer = { Ans.PASS }
        assertEquals(WaitingResult.STALE, a.waits().deleteWaitingNow(first), "the question about the earlier deletion")
        assertEquals(deletions, front.count { it is LogEntry.Delete }, "it sends nothing")
        assertFalse(a.rowOf(vaultId).deleted)
        assertEquals(WaitingResult.DELETED, a.waits().deleteWaitingNow(later), "the question about this deletion sends it")
    }

    /**
     * A waiting change drawn for one account, tapped after that account signed out and another signed in on this device:
     * stale, and the first account's change stays held for its next sign-in. Before, the act took the account open now.
     */
    @Test fun aWaitingChangeDrawnForOneAccountIsStaleForAnotherAccountOfTheDevice() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val alice = assertNotNull(a.keeper.session).userId
        val vaultId = family(a, server)
        val e = contact(a, server, erin, "Erin")
        front.answer = { if (it is LogEntry.Add) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, addErin(a, e))
        val w = assertNotNull(a.row().waiting)
        assertEquals(PlainResult.DONE, a.signOutConfirmed(assertNotNull(a.signOutCheck())))
        open(a, "bob@example.com")
        val posted = front.posted.size
        assertEquals(WaitingResult.STALE, a.waits().withdrawWaiting(w))
        assertEquals(WaitingResult.STALE, a.waits().deleteWaitingNow(w))
        assertEquals(posted, front.posted.size)
        assertNotNull(a.engine.state.get(StoredVaultLogs.recordKey(alice, vaultId, "pending")), "the first account's change stays held")
    }

    /** The stand-in acts only on the change it drew, in the opening it drew it in, as the engine. */
    @Test fun theStandInActsOnlyOnTheChangeItDrewInTheOpeningItDrewIt() = runBlocking<Unit> {
        val f = FakeScenes.at(FakeScene.VAULTS)
        fun row() = f.snapshot.account!!.vaults.first { it.name == "Family" }
        assertEquals(VaultActionResult.DONE, f.vaults.openMembers(row()))
        val member = f.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        f.vaults.closeMembers()
        assertTrue(f.script.changeWaits("Family", WaitingKind.ADD, memberId = member.userId, role = RoleInVault.WRITER))
        val addition = assertNotNull(row().waiting)
        assertTrue(f.script.waitingFound("Family", CopyKey.WAITING_FOUND_NOT_MADE_YET))
        assertTrue(f.script.changeWaits("Family", WaitingKind.REMOVE, memberId = member.userId))
        assertEquals(WaitingResult.STALE, f.waits().withdrawWaiting(addition))
        assertEquals(WaitingKind.REMOVE, row().waiting?.kind)
        val removal = assertNotNull(row().waiting)
        f.lock()
        assertEquals(VaultUnlockResult.DONE, f.unlock(f.snapshot.locked!!, FakeScenes.PASSWORD))
        assertEquals(WaitingResult.STALE, f.waits().withdrawWaiting(removal))
        assertEquals(WaitingKind.REMOVE, row().waiting?.kind)
        assertEquals(WaitingResult.WITHDRAWN_MAY_BE_MADE, f.waits().withdrawWaiting(assertNotNull(row().waiting)))
    }

    // ---- an addition is sent again only to the contact it was signed for ----

    private suspend fun addErinWhoseAnswerIsLost(front: Front, a: EngineAppApi, server: VaultServer, key: String): String {
        val vaultId = family(a, server)
        val e = contact(a, server, erin, "Erin", key)
        front.answer = { if (it is LogEntry.Add) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, addErin(a, e))
        assertEquals("Erin", assertIs<PersonName.Contact>(assertNotNull(a.row().waiting).names).label)
        return vaultId
    }

    private fun assertNotSentAgainAndSaidSo(front: Front, a: EngineAppApi, server: VaultServer, vaultId: String, adds: Int) {
        front.answer = { Ans.PASS }
        sync(a)
        sync(a)
        assertEquals(adds, addsOf(front, erin), "the addition is not sent again")
        assertTrue(server.stored.none { it.first == vaultId && (it.second as? LogEntry.Add)?.member == erin })
        assertFalse(server.grants.containsKey(vaultId to erin), "no grant for Erin")
        assertNull(a.row().waiting, "let go of")
        val n = a.notices().single { it.kind == WaitingKind.ADD }
        assertEquals(CopyKey.WAITING_FOUND_CONTACT_CHANGED, n.line.key, "an earlier send of it got no answer: it may still be made")
        assertEquals(listOf("Family"), n.line.values)
        assertEquals(erin, n.memberId)
    }

    /**
     * Erin's contact is replaced by another key after her addition's answer was lost: the row names the waiting addition
     * by the key in it (no contact here has it now: unverified), the re-send after a sync does not send it, and a notice
     * says so. Before, the row still said "Erin" and the re-send granted the vault's key to the key the person replaced.
     */
    @Test fun anAdditionWhoseContactHasAnotherKeyIsNotSentAgainAndIsNamedByItsOwnKey() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = addErinWhoseAnswerIsLost(front, a, server, Bytes.toB64(crypto.randomBytes(32)))
        val adds = addsOf(front, erin)
        contact(a, server, erin, "Erin", Bytes.toB64(crypto.randomBytes(32)))
        val w = a.row().waiting
        assertTrue(w == null || w.names is PersonName.Unverified, "never named as the contact whose key is another now: ${w?.names}")
        assertNotSentAgainAndSaidSo(front, a, server, vaultId, adds)
    }

    /** As above, for a contact removed from this device. */
    @Test fun anAdditionWhoseContactWasRemovedIsNotSentAgain() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = addErinWhoseAnswerIsLost(front, a, server, Bytes.toB64(crypto.randomBytes(32)))
        val adds = addsOf(front, erin)
        a.vault!!.store.update { doc -> doc.copy(contacts = doc.contacts - erin) }
        // The record was written straight to the store: the snapshot is drawn again before it is read.
        a.publish()
        val w = a.row().waiting
        assertTrue(w == null || w.names is PersonName.Unverified, "${w?.names}")
        assertNotSentAgainAndSaidSo(front, a, server, vaultId, adds)
    }

    /** As above, for a contact whose comparison of codes was withdrawn. */
    @Test fun anAdditionWhoseContactIsNoLongerComparedIsNotSentAgain() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = addErinWhoseAnswerIsLost(front, a, server, Bytes.toB64(crypto.randomBytes(32)))
        val adds = addsOf(front, erin)
        a.vault!!.store.update { doc -> doc.copy(contacts = doc.contacts + (erin to doc.contacts.getValue(erin).copy(compared = false))) }
        assertNotSentAgainAndSaidSo(front, a, server, vaultId, adds)
    }

    /** An addition whose contact is unchanged is still sent again after a sync, as signed, and made. */
    @Test fun anAdditionWhoseContactIsUnchangedIsStillSentAgainAfterASync() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val key = Bytes.toB64(crypto.randomBytes(32))
        val vaultId = addErinWhoseAnswerIsLost(front, a, server, key)
        front.answer = { Ans.PASS }
        sync(a)
        val add = assertIs<LogEntry.Add>(server.stored.last { it.first == vaultId && (it.second as? LogEntry.Add)?.member == erin }.second)
        assertEquals(key, add.memberKey)
        assertTrue(server.grants.containsKey(vaultId to erin))
        assertTrue(a.notices().none { it.line.key == CopyKey.WAITING_FOUND_CONTACT_CHANGED })
    }

    // ---- each line says what this device knows ----

    /**
     * The person's deletion that waited is found made, and another device of the account restored the vault meanwhile:
     * the notice says it was restored since and offers no restore. Before, it offered a restore that was refused.
     */
    @Test fun aDeletionFoundMadeOfAVaultRestoredSinceOffersNoRestore() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val frame = front.last { it is LogEntry.Delete }
        server.storeLater(vaultId, frame)
        val deleteId = assertIs<LogEntry.Delete>(VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry).deleteId
        otherDevice(a, server, vaultId) { seq, prev, me, at -> LogEntry.Restore(vaultId, seq, prev, me, at, deleteId) }
        front.answer = { Ans.PASS }
        sync(a)
        assertFalse(a.rowOf(vaultId).deleted)
        val n = a.notices().single { it.kind == WaitingKind.DELETION }
        assertEquals(CopyKey.WAITING_FOUND_DELETED_RESTORED_SINCE, n.line.key)
        assertNull(n.undo)
    }

    /**
     * An addition whose answer was lost and whose re-send the server refused: the notice says refused and cannot tell, not
     * "waited more than a day". "Delete it now" refused the same way answers with a line of its own. Before, both read as
     * a change given up after a day, and the deletion's answer was "nothing waits".
     */
    @Test fun aReSendTheServerRefusedIsSaidAsRefusedAndCannotTell() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        val e = contact(a, server, erin, "Erin")
        front.answer = { if (it is LogEntry.Add) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, addErin(a, e))
        front.answer = { if (it is LogEntry.Add) Ans.REFUSE else Ans.PASS }
        sync(a)
        assertNull(a.rowOf(vaultId).waiting)
        assertEquals(CopyKey.WAITING_FOUND_REFUSED_CANNOT_TELL, a.notices().single { it.kind == WaitingKind.ADD }.line.key)

        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val d = assertNotNull(a.rowOf(vaultId).waiting)
        assertTrue(d.asksForWord)
        front.answer = { if (it is LogEntry.Delete) Ans.REFUSE else Ans.PASS }
        assertEquals(WaitingResult.DELETE_REFUSED_CANNOT_TELL, a.waits().deleteWaitingNow(d))
        assertEquals(CopyKey.WAITING_FOUND_REFUSED_CANNOT_TELL, a.notices().single { it.kind == WaitingKind.DELETION }.line.key)
    }

    /**
     * The person's deletion waited a day and was given up, and the server made it after all: the notice says it was given
     * up, never "the deletion that you withdrew". Before, every deletion made after all read as withdrawn.
     */
    @Test fun aGivenUpDeletionMadeAfterAllIsNotSaidAsWithdrawn() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val frame = front.last { it is LogEntry.Delete }
        front.answer = { Ans.PASS }
        server.instance.now += dayAndAHour
        sync(a)
        assertNull(a.rowOf(vaultId).waiting, "given up after its day")
        server.storeLater(vaultId, frame)
        sync(a)
        assertTrue(a.rowOf(vaultId).deleted)
        val made = a.notices().single { it.undo == WaitingUndo.RESTORE_VAULT }
        assertEquals(CopyKey.WAITING_FOUND_GIVEN_UP_DELETED_AFTER_ALL, made.line.key)
    }

    /**
     * A deletion the server's answer called stored, which the log does not show: its line says that and promises no act,
     * and it is not asked about (neither "Delete it now" nor "Keep the vault" is offered). The stand-in draws the same.
     * Before, the line said "nothing is sent until you choose", and the question offered "Keep the vault".
     */
    @Test fun aDeletionTheServerSaysItStoredPromisesNothingThatIsNotOffered() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        front.answer = { if (it is LogEntry.Delete) Ans.LIE else Ans.PASS }
        a.vaults.deleteVault(a.row())
        val w = assertNotNull(a.rowOf(vaultId).waiting)
        assertEquals(WaitingKnown.SERVER_SAYS_STORED, w.known)
        val drawn = listOf(w.line.key, w.asksForWord, w.askLine, w.withdrawLabel)
        assertEquals(listOf<Any?>(CopyKey.WAITING_DELETE_SERVER_SAYS_STORED, false, null, null), drawn)
        assertEquals(WaitingResult.NOT_OFFERED, a.waits().deleteWaitingNow(w))

        val f = FakeScenes.at(FakeScene.VAULTS)
        assertTrue(f.script.changeWaits("Family", WaitingKind.DELETION, WaitingKnown.SERVER_SAYS_STORED))
        f.script.waitingDeletionLooked("Family")
        val fw = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        assertEquals(drawn, listOf(fw.line.key, fw.asksForWord, fw.askLine, fw.withdrawLabel))
    }

    /**
     * A change made while another change of the vault waits is neither signed nor sent, and says so in a result of its own,
     * never "sent, not yet acknowledged". The stand-in answers the same. Before, both said it was sent.
     */
    @Test fun aChangeMadeWhileAnotherWaitsIsNeitherSignedNorSentAndSaysSo() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        family(a, server)
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val removals = front.count { it is LogEntry.Remove }
        assertEquals(VaultActionResult.OTHER_CHANGE_WAITS, removeDave(a))
        assertEquals(removals, front.count { it is LogEntry.Remove }, "nothing was signed or sent")
        assertEquals(CopyKey.WAITING_OTHER_CHANGE_FIRST, VaultActionResult.OTHER_CHANGE_WAITS.sentence)

        val f = FakeScenes.at(FakeScene.VAULTS)
        fun row() = f.snapshot.account!!.vaults.first { it.name == "Family" }
        assertTrue(f.script.changeWaits("Family", WaitingKind.DELETION))
        assertEquals(VaultActionResult.DONE, f.vaults.openMembers(row()))
        val member = f.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        assertEquals(VaultActionResult.OTHER_CHANGE_WAITS, f.vaults.removeMember(member))
    }

    /**
     * A waiting change of a member's role carries the member's account id and the role it would go back to, and so does
     * the notice that it was made after all, whose undo acts on that member. The stand-in carries the same.
     */
    @Test fun aWaitingChangeAndItsNoticeCarryTheMembersIdAndTheRoleItGoesBackTo() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        val vaultId = family(a, server)
        front.answer = { if (it is LogEntry.Role) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.changeRole(a.snapshot.account!!.members!!.members.single { it.userId == carol }, MemberRole.READER))
        a.vaults.closeMembers()
        val w = assertNotNull(a.row().waiting)
        assertEquals(listOf<Any?>(WaitingKind.ROLE, RoleInVault.READER, carol, RoleInVault.WRITER), listOf(w.kind, w.role, w.memberId, w.roleBack))
        assertEquals(WaitingResult.WITHDRAWN_MAY_BE_MADE, a.waits().withdrawWaiting(w))
        server.storeLater(vaultId, front.last { it is LogEntry.Role })
        front.answer = { Ans.PASS }
        sync(a)
        val made = a.notices().single { it.undo == WaitingUndo.CHANGE_ROLE_BACK }
        assertEquals(listOf<Any?>(carol, RoleInVault.WRITER), listOf(made.memberId, made.roleBack))

        val f = FakeScenes.at(FakeScene.VAULTS)
        assertEquals(VaultActionResult.DONE, f.vaults.openMembers(f.snapshot.account!!.vaults.first { it.name == "Family" }))
        val member = f.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        f.vaults.closeMembers()
        val other = if (member.role == RoleInVault.READER) RoleInVault.WRITER else RoleInVault.READER
        assertTrue(f.script.changeWaits("Family", WaitingKind.ROLE, memberId = member.userId, role = other))
        val fw = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        assertEquals(listOf<Any?>(member.userId, member.role), listOf(fw.memberId, fw.roleBack))
        assertTrue(f.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CHANGE_ROLE_BACK))
        val fn = f.snapshot.account!!.waitingNotices.single()
        assertEquals(listOf<Any?>(member.userId, member.role), listOf(fn.memberId, fn.roleBack))
    }

    /**
     * "Delete it now" tapped while a move of the same vault runs sends nothing and says so; the stand-in refuses it the
     * same while the move's own deletion of the vault waits. Before, it sent the deletion in the middle of the move.
     */
    @Test fun deleteItNowWhileAMoveOfTheVaultRunsSendsNothing() = runBlocking<Unit> {
        val front = Front()
        val (server, a) = app(front)
        open(a)
        family(a, server)
        front.answer = { if (it is LogEntry.Delete) Ans.LOST else Ans.PASS }
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val d = assertNotNull(a.row().waiting)
        assertTrue(d.asksForWord)
        front.answer = { Ans.PASS }
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        var tapped: WaitingResult? = null
        var sentDuring = -1
        server.onCall = { _ ->
            val before = front.count { it is LogEntry.Delete }
            tapped = a.waits().deleteWaitingNow(d)
            sentDuring = front.count { it is LogEntry.Delete } - before
        }
        a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertEquals(WaitingResult.MOVE_IN_PROGRESS, tapped)
        assertEquals(0, sentDuring, "nothing was sent")

        val f = FakeScenes.at(FakeScene.VAULTS)
        assertTrue(f.script.changeWaits("Family", WaitingKind.DELETION))
        assertTrue(f.script.waitingDeletionLooked("Family"))
        f.session!!.account.vaults.first { it.name == "Family" }.moveDeleteWaiting = true
        val fw = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        assertEquals(WaitingResult.MOVE_IN_PROGRESS, f.waits().deleteWaitingNow(fw))
    }
}
