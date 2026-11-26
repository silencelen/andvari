package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.state.AcceptedRecord
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogDeleted
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.LogPurged
import io.silencelen.andvari.core.model.wire.SelfWrapPut
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import kotlinx.serialization.builtins.ListSerializer
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.Checkpoint
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The vault-log engine against an in-memory server that stores and serves frames, verified with the trust layer's
 * VaultLog on append exactly as the real server does (spec 03 §10.3 step 7).
 */
class StoredVaultLogsTest {
    private val crypto = createCryptoProvider()

    private class Person(crypto: io.silencelen.andvari.core.crypto.CryptoProvider, val userId: String, seed: Byte) {
        val sign = crypto.signKeypairFromSeed(ByteArray(32) { seed })
        val box = crypto.boxKeypairFromSeed(ByteArray(32) { seed })
        val uvk = ByteArray(32) { (seed + 1).toByte() }
        val pub: String = Bytes.toB64(box.publicKey)
    }

    private val alice = Person(crypto, "11111111-1111-4111-8111-111111111111", 3)
    private val bob = Person(crypto, "22222222-2222-4222-8222-222222222222", 5)

    /** One server for every vault: the stored chain, the grant rows, and switches for hostile behaviour. */
    private inner class Server {
        val logs = HashMap<String, MutableList<String>>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        var down = false
        var serveOnly: Int? = null
        var replaceAt: Pair<Int, String>? = null
        var purgedAt: Long? = null
        /** Raw JSON for `deleted` on log fetches ([deletedOnFetch]) and appends ([deletedOnAppend]); null sends none. */
        var deletedRaw: String? = null
        var deletedOnFetch = true
        var deletedOnAppend = true
        /** A head to name in append answers instead of the real one. */
        var appendHead: LogHead? = null
        /** Users the member list leaves out; a raw answer to send instead; a hook run when the list is read. */
        var unlisted = setOf<String>()
        var membersAnswer: WireResult<String>? = null
        var onMembers: (() -> Unit)? = null
        var memberReads = 0
        /** A head to name on log fetches above what is served. */
        var claimHead: LogHead? = null
        var fetches = 0
        /** Run when a self-wrap is posted (a lock that cancels the job throws from here). */
        var onSelfWrap: (() -> Unit)? = null
        /** The next appends answered `429 rate_limited` before the frame is looked at (nothing stored). */
        var rateLimitAppends = 0
        /** The next appends' answers lost after the server stored (or already held) the frame. */
        var loseAppendAnswers = 0
        /** The next appends lost on the way: nothing stored, no answer. */
        var dropAppends = 0
        /** The next appends answered `200` naming the frame stored at its own position as the head ([appendHead] where set), while nothing is stored (a lying server). */
        var lieAppends = 0
        /** The next append refused with this status and code before the frame is looked at, nothing stored (then cleared). */
        var refuseAppend: Pair<Int, String>? = null
        /** The next append answered `409 log_head_moved` naming this head, nothing stored (then cleared). */
        var headMovedAppend: LogHead? = null
        /** The sync revision the vaults' items stand at, for a deletion's read point. */
        var itemsRev = 0L
        /** Appends received (every kind of answer), and the last body. */
        var appends = 0
        var lastAppend: String? = null
        /** Run once (then cleared) when the next append arrives, before anything is decided; and when the next log fetch arrives. */
        var onAppend: (suspend () -> Unit)? = null
        var onFetch: (suspend () -> Unit)? = null
        /** A page asked for after a position starts AT that position (it serves the head the device named again). */
        var pageFromHead = false

        /** The frame of the last append received, as sent. */
        fun lastFrame(): String = WireJson.json.decodeFromString(LogAppendRequest.serializer(), lastAppend!!).entry

        /** [frame] stored late (a request that reached the server after all), at the end of [vaultId]'s log. */
        fun lateAppend(vaultId: String, frame: String) { logs.getValue(vaultId) += frame }

        private fun <T> lost(answer: WireResult<T>): WireResult<T> =
            if (loseAppendAnswers > 0) { loseAppendAnswers--; WireResult.NoAnswer(NoAnswerKind.TIMEOUT) } else answer

        private fun withDeleted(json: String, on: Boolean): String =
            deletedRaw?.takeIf { on }?.let { json.dropLast(1) + ",\"deleted\":$it}" } ?: json

        fun client(user: String): WireClient = object : WireClient {
            override val origin = "https://h.example"
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                val vaultId = pathParams.getValue("vaultId")
                val log = logs.getOrPut(vaultId) { ArrayList() }
                return when (route) {
                    WireRoute.LOG_FETCH -> {
                        onFetch?.let { onFetch = null; it() }
                        fetches++
                        var served = log.toMutableList()
                        replaceAt?.let { (i, f) -> if (i < served.size) served[i] = f }
                        serveOnly?.let { served = served.take(it).toMutableList() }
                        val after = query?.removePrefix("after=")?.toLong()
                        val from = if (after != null && pageFromHead) after.toInt() else ((after ?: -1) + 1).toInt()
                        val page = if (from < served.size) served.subList(from, served.size) else emptyList()
                        val headSeq = served.size - 1L
                        val head = claimHead ?: LogHead(headSeq, if (served.isEmpty()) "0".repeat(64) else Bytes.toHexLower(crypto.sha256(Bytes.fromB64(served.last()))), 0)
                        WireResult.Ok(decode(withDeleted(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, head, purgedAt?.let { LogPurged(it) })), deletedOnFetch)), 200)
                    }
                    WireRoute.LOG_APPEND -> {
                        appends++
                        lastAppend = bodyJson
                        onAppend?.let { onAppend = null; it() }
                        if (dropAppends > 0) {
                            dropAppends--
                            return WireResult.NoAnswer(NoAnswerKind.TIMEOUT)
                        }
                        if (rateLimitAppends > 0) {
                            rateLimitAppends--
                            return WireResult.Refused(429, WireError("rate_limited", "m"))
                        }
                        val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                        val frame = Bytes.fromB64(req.entry)
                        refuseAppend?.let { (status, code) ->
                            refuseAppend = null
                            return WireResult.Refused(status, WireError(code, "m"))
                        }
                        headMovedAppend?.let { h ->
                            headMovedAppend = null
                            return WireResult.Refused(409, WireError("log_head_moved", "m", seq = h.seq, hash = h.hash, at = 0))
                        }
                        if (lieAppends > 0) {
                            lieAppends--
                            val seq = VaultLog.parse(crypto, frame).valueOrNull()!!.entry.seq
                            return WireResult.Ok(decode(WireJson.json.encodeToString(LogAppendResponse.serializer(),
                                LogAppendResponse(1, appendHead ?: LogHead(seq, Bytes.toHexLower(crypto.sha256(frame)), 0)))), 200)
                        }
                        if (req.entry in log) return lost(WireResult.Ok(decode(appended(log)), 200))
                        // A deletion's read point below the revision the vault's items stand at: refused, nothing stored.
                        if (req.itemsAtMost != null && itemsRev > req.itemsAtMost) return WireResult.Refused(409, WireError("vault_items_moved", "m"))
                        val prior = VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                        val entry = VaultLog.parse(crypto, frame).valueOrNull()?.entry
                        if (entry != null && entry.seq != log.size.toLong()) {
                            val h = prior!!.head
                            return WireResult.Refused(409, WireError("log_head_moved", "m", seq = h.seq, hash = h.hash, at = prior.at))
                        }
                        when (val v = VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD)) {
                            is Checked.Refused -> return WireResult.Refused(400, WireError(v.verdict.code, "m"))
                            is Checked.Ok -> {}
                        }
                        log += req.entry
                        if (entry is LogEntry.Genesis) grants[vaultId to user] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, 1)
                        if (entry is LogEntry.Add) grants[vaultId to entry.member] = SyncGrant(vaultId, entry.member, entry.role.literal, "", 1, req.grant)
                        lost(WireResult.Ok(decode(appended(log)), 200))
                    }
                    WireRoute.VAULT_MEMBERS -> {
                        memberReads++
                        onMembers?.invoke()
                        val raw = membersAnswer ?: WireResult.Ok(WireJson.json.encodeToString(ListSerializer(VaultMemberSummary.serializer()),
                            grants.values.filter { it.vaultId == vaultId && it.userId !in unlisted }
                                .map { VaultMemberSummary(it.userId, "e@x.example", "N", it.role, "", 1) }), 200)
                        @Suppress("UNCHECKED_CAST")
                        when (raw) {
                            is WireResult.Ok -> runCatching { WireResult.Ok(decode(raw.value), 200) }.getOrElse { WireResult.NoAnswer(NoAnswerKind.UNDECODABLE) }
                            else -> raw as WireResult<T>
                        }
                    }
                    WireRoute.VAULT_SELF_WRAP -> {
                        onSelfWrap?.invoke()
                        val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                        grants[vaultId to user] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk)
                        WireResult.Ok(decode("{\"rev\":1}"), 200)
                    }
                    else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                }
            }
        }

        private fun appended(log: List<String>) = withDeleted(WireJson.json.encodeToString(LogAppendResponse.serializer(),
            LogAppendResponse(1, appendHead ?: LogHead(log.size - 1L, Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last()))), 0))), deletedOnAppend)
    }

    /** Account state shared by one account's devices, merged trivially (one writer at a time in these tests). */
    private class SharedState : AccountStateStore {
        var doc = AccountDocument.EMPTY
        /** The next write refused by the server ([AccountStateWrite.Refused]): nothing recorded. */
        var refuseNext = false
        /** The next write's answer lost ([AccountStateWrite.Unknown]); nothing recorded here. */
        var loseNext = false
        /** Run once (then cleared) while the next write is out, before it is decided. */
        var onUpdate: (suspend () -> Unit)? = null
        override fun local() = doc
        override suspend fun read(): AccountStateRead = AccountStateRead.Ok(doc, emptyList())
        override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite {
            onUpdate?.let { onUpdate = null; it() }
            if (refuseNext) {
                refuseNext = false
                return AccountStateWrite.Refused("quota_exceeded")
            }
            if (loseNext) {
                loseNext = false
                return AccountStateWrite.Unknown
            }
            val n = change(doc)
            if (n == doc) return AccountStateWrite.Unchanged(doc)
            doc = n.copy(seq = doc.seq + 1)
            return AccountStateWrite.Written(doc)
        }
    }

    private inner class Host(val server: Server, val user: Person, val contacts: Map<String, String>) : VaultLogHost {
        override fun grantRow(vaultId: String) = server.grants[vaultId to user.userId]
        override fun isCurrentContact(userId: String, identityPub: String) = contacts[userId] == identityPub
        override fun currentContact(userId: String) = contacts[userId]?.let { it to true }
        override fun labelFor(userId: String, identityPub: String) = if (contacts[userId] == identityPub) "Alice" else null
        override fun vaultName(vaultId: String, vk: ByteArray) = "Family"
        override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
        override fun serverOwnerName(vaultId: String) = "someone"
    }

    private var now = 1_763_164_800_000L
    private val DAY = 86_400_000L

    private fun engine(
        server: Server, p: Person, account: AccountStateStore, contacts: Map<String, String>, device: MemoryDeviceState = MemoryDeviceState(),
        checkpoints: Map<String, Checkpoint> = emptyMap(),
    ) = StoredVaultLogs(p.userId, p.sign, p.box, p.uvk, server.client(p.userId), crypto, device, account, Host(server, p, contacts), { now }, { checkpoints[it] })

    @Test fun aBundleCheckpointIsAHeldHashAndALowerBound() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        now += 1000
        a.append(vaultId, LogAction.Role(bob.userId, "reader"))
        val h2 = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.logs.getValue(vaultId)[2])))
        val cp = mapOf(vaultId to Checkpoint(2, h2))

        // A linked device whose bundle carried seq 2: a log served only to seq 1 is withheld, from the first fetch on.
        server.serveOnly = 2
        val linked = engine(server, alice, SharedState(), emptyMap(), checkpoints = cp)
        val w = assertIs<VaultLogStatus.Withheld>(linked.refresh(vaultId, null, null, force = true))
        assertEquals(1, w.state.headSeq, "the device keeps what it verified")
        // The served head equals the verified one, but the checkpoint is above it: no shortcut past the lower bound.
        val head1 = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.logs.getValue(vaultId)[1])))
        assertIs<VaultLogStatus.Withheld>(linked.refresh(vaultId, 1, head1, force = false))
        server.serveOnly = null
        assertEquals(2, assertIs<VaultLogStatus.Verified>(linked.refresh(vaultId, 2, h2, force = false)).state.headSeq)

        // Another validly signed entry at the checkpoint's position: a fork, though this device never verified seq 2 itself.
        val s1 = VaultLog.replay(crypto, vaultId, server.logs.getValue(vaultId).take(2).map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state!!
        val pos = VaultLog.position(s1, now + 5)
        val other = (VaultLog.signChecked(crypto, alice.sign, s1, LogEntry.Remove(vaultId, pos.seq, pos.prev, alice.userId, pos.at, bob.userId)) as Checked.Ok).value
        server.replaceAt = 2 to Bytes.toB64(other.frame)
        val fresh = engine(server, alice, SharedState(), emptyMap(), checkpoints = cp)
        assertIs<VaultLogStatus.Frozen>(fresh.refresh(vaultId, null, null, force = true))
        server.replaceAt = null

        // A checkpoint that names another hash than this device verified at that position: a fork too.
        val device = MemoryDeviceState()
        assertIs<VaultLogStatus.Verified>(engine(server, alice, SharedState(), emptyMap(), device).refresh(vaultId, null, null, force = true))
        val other2 = mapOf(vaultId to Checkpoint(1, "a".repeat(64)))
        assertIs<VaultLogStatus.Frozen>(engine(server, alice, SharedState(), emptyMap(), device, other2).refresh(vaultId, null, null, force = true))
    }

    @Test fun createAddAcceptSelfWrapAndAnotherDevice() = runBlocking<Unit> {
        val server = Server()
        val aliceState = SharedState()
        val a = engine(server, alice, aliceState, mapOf(bob.userId to bob.pub))
        val created = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family")))
        val vaultId = created.state.vaultId
        assertEquals(AcceptedRecord(vaultId, alice.userId, 0, now, AcceptedRecord.ACCEPT), aliceState.doc.accepted[vaultId], "the creator's accepted record answers the genesis")
        assertEquals(0, aliceState.doc.vaults.getValue(vaultId).seq, "a new vault's record is written at once")
        assertTrue(a.writeAllowed(vaultId))
        val a2 = engine(server, alice, aliceState, emptyMap())
        a2.refresh(vaultId, null, null, force = true)
        assertEquals(Adoption.Adopted(vaultId, KeySource.OWNER_WRAP), a2.adoption(vaultId), "another device of alice adopts through the owner wrap")

        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Add(bob.userId, "writer")))

        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub))
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        val ask = assertIs<Adoption.AskAccept>(b.adoption(vaultId), "a grant from a current contact is never adopted unasked")
        assertNull(bobState.doc.vaults[vaultId], "§3.6 (e): no vault record merely because the server listed a log")
        assertEquals(1, ask.addSeq)
        assertEquals("Alice", ask.ownerLabel)
        assertNull(b.keyFor(vaultId))
        assertEquals(Adoption.Adopted(vaultId, KeySource.GRANT), b.answerIncoming(ask, accept = true))
        assertEquals(1, bobState.doc.vaults.getValue(vaultId).seq, "recording the answer and adopting write the record")
        assertContentEquals(a.keyFor(vaultId), b.keyFor(vaultId))
        assertTrue(server.grants.getValue(vaultId to bob.userId).wrappedVk.isNotEmpty(), "the self-wrap was posted")

        // bob's second device: no contacts at all, adopts through the self-wrap and the accepted record.
        val b2 = engine(server, bob, bobState, emptyMap())
        b2.refresh(vaultId, null, null, force = true)
        assertEquals(Adoption.Adopted(vaultId, KeySource.SELF_WRAP), b2.adoption(vaultId))

        // A stranger's view: no current contact → connect first.
        val strangerState = SharedState()
        val b3 = engine(server, bob, strangerState, emptyMap())
        b3.refresh(vaultId, null, null, force = true)
        assertIs<Adoption.ConnectFirst>(b3.adoption(vaultId))
        assertTrue(strangerState.doc.vaults.isEmpty(), "a listed, verified but unadopted log writes no record")
    }

    @Test fun declineSignsALeaveAndRecordsIt() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "reader"))
        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub))
        b.refresh(vaultId, null, null, force = true)
        val ask = assertIs<Adoption.AskAccept>(b.adoption(vaultId))
        assertEquals(Adoption.Declined(vaultId), b.answerIncoming(ask, accept = false))
        assertEquals(AcceptedRecord.DECLINE, bobState.doc.accepted.getValue(vaultId).decision)
        assertEquals(server.logs.getValue(vaultId).size - 2L, bobState.doc.vaults.getValue(vaultId).seq, "a declined vault is recorded at the head the answer was given")
        assertIs<VaultLogStatus.Removed>(b.status(vaultId))
        assertEquals(3, server.logs.getValue(vaultId).size, "genesis, add, leave")
    }

    /**
     * A decline whose leave the server did not store is signed again at a later unlock, once per unlock, until the server
     * takes it; the unlock that answered signs no second one; once it went through nothing more is sent.
     */
    @Test fun aDeclinesLeaveTheServerDidNotStoreIsSignedAgainOncePerUnlockUntilItGoesThrough() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Add(bob.userId, "reader")))
        val bobState = SharedState()
        val device = MemoryDeviceState()
        fun unlock() = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), device)
        val b = unlock()
        b.refresh(v, null, null, force = true)
        server.refuseAppend = 403 to "forbidden"
        assertEquals(Adoption.Declined(v), b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(v)), accept = false))
        assertEquals(AcceptedRecord.DECLINE, bobState.doc.accepted.getValue(v).decision)
        assertEquals(2, server.logs.getValue(v).size, "the leave was not stored")
        assertNull(b.heldChange(v))
        val sent = server.appends
        assertTrue(b.leaveAgainForDeclines().isEmpty(), "the unlock that answered signs no second leave")
        assertEquals(sent, server.appends)

        val b2 = unlock()
        server.refuseAppend = 403 to "forbidden"
        val again = b2.leaveAgainForDeclines().single()
        assertEquals(v, again.vaultId)
        assertIs<AppendOutcome.Refused>(again.outcome)
        assertEquals(sent + 1, server.appends, "one leave at this unlock")
        assertTrue(b2.leaveAgainForDeclines().isEmpty())
        assertEquals(sent + 1, server.appends, "and no more at this unlock")

        now += 1000
        val b3 = unlock()
        assertIs<AppendOutcome.Appended>(b3.leaveAgainForDeclines().single().outcome)
        assertEquals(3, server.logs.getValue(v).size, "genesis, add, leave")
        assertIs<VaultLogStatus.Removed>(b3.status(v))

        val b4 = unlock()
        val after = server.appends
        assertTrue(b4.leaveAgainForDeclines().isEmpty())
        assertEquals(after, server.appends, "gone through: nothing is sent at a later unlock")
    }

    /**
     * Nothing is signed again where the log, read afresh, no longer lists the account (the owner removed it meanwhile), or
     * lists it through a later addition (a new invitation, asked anew); nor where a leave is held, which the general
     * re-send sends as it is, exactly once.
     */
    @Test fun aDeclinesLeaveIsNotSignedAgainWhereTheLogMovedOnOrALeaveIsHeld() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        suspend fun shared(): String {
            val id = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
            now += 1000
            assertIs<AppendOutcome.Appended>(a.append(id, LogAction.Add(bob.userId, "reader")))
            now += 1000
            return id
        }
        val bobState = SharedState()
        val device = MemoryDeviceState()
        fun unlock() = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), device)
        suspend fun declineUnstored(v: String) {
            val b = unlock()
            b.refresh(v, null, null, force = true)
            server.refuseAppend = 403 to "forbidden"
            assertEquals(Adoption.Declined(v), b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(v)), accept = false))
        }

        // The owner removed the account meanwhile: the stored state still lists it, the fresh read does not.
        val removed = shared()
        declineUnstored(removed)
        assertIs<AppendOutcome.Appended>(a.append(removed, LogAction.Remove(bob.userId)))
        now += 1000
        var n = server.appends
        assertTrue(unlock().leaveAgainForDeclines().isEmpty())
        assertEquals(n, server.appends)

        // Removed and added again: a later addition, which is asked anew.
        assertIs<AppendOutcome.Appended>(a.append(removed, LogAction.Add(bob.userId, "reader")))
        now += 1000
        n = server.appends
        val b = unlock()
        b.refresh(removed, null, null, force = true)
        assertTrue(b.leaveAgainForDeclines().isEmpty())
        assertEquals(n, server.appends)
        assertIs<Adoption.AskAccept>(b.adoption(removed))

        // A leave held (lost on the way): no second one is signed; the re-send sends it as it is, once.
        val held = shared()
        val c = unlock()
        c.refresh(held, null, null, force = true)
        server.dropAppends = 1
        assertEquals(Adoption.Declined(held), c.answerIncoming(assertIs<Adoption.AskAccept>(c.adoption(held)), accept = false))
        assertEquals(HeldKind.LEAVE, assertNotNull(c.heldChange(held)).kind)
        val d = unlock()
        n = server.appends
        assertTrue(d.leaveAgainForDeclines().isEmpty())
        assertEquals(n, server.appends)
        assertIs<HeldResend.Stored>(d.resendHeld().single())
        assertEquals(n + 1, server.appends, "exactly one leave")
        assertEquals(3, server.logs.getValue(held).size)
    }

    /**
     * An answer to a share whose write the server refused is not recorded: the question stands, and no leave is signed for
     * a decline that did not happen. Before, the decline was answered as recorded and a leave went to the server.
     */
    @Test fun anAnswerToAShareThatWasNotRecordedLeavesTheQuestionAsItWas() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "reader"))
        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub))
        b.refresh(vaultId, null, null, force = true)
        for (accept in listOf(false, true)) {
            val ask = assertIs<Adoption.AskAccept>(b.adoption(vaultId))
            bobState.refuseNext = true
            assertIs<Adoption.AskAccept>(b.answerIncoming(ask, accept), "accept=$accept: the question stands")
            assertTrue(vaultId !in bobState.doc.accepted, "accept=$accept: nothing recorded")
            assertEquals(2, server.logs.getValue(vaultId).size, "accept=$accept: no leave was signed")
        }
        // Recorded the next time: the decline as before.
        assertEquals(Adoption.Declined(vaultId), b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(vaultId)), accept = false))
        assertEquals(3, server.logs.getValue(vaultId).size, "genesis, add, leave")
    }

    /**
     * An answer to a share whose write had no answer that settles it has a result of its own: never "recorded" and never
     * the question asked again as if nothing happened. A decline whose leave the log holds is declined all the same.
     * Before, an acceptance came back as the question again and a decline as declined while its leave was still waiting.
     */
    @Test fun anAnswerToAShareWhoseRecordCannotBeToldIsAResultOfItsOwn() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        suspend fun shared(): String {
            val id = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
            now += 1000
            a.append(id, LogAction.Add(bob.userId, "reader"))
            return id
        }
        val v = shared()
        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub))
        b.refresh(v, null, null, force = true)
        bobState.loseNext = true
        assertEquals(Adoption.AnswerNotKnown(v, accepted = true, adopted = false), b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(v)), accept = true))
        bobState.loseNext = true
        server.dropAppends = 1
        assertEquals(Adoption.AnswerNotKnown(v, accepted = false, adopted = false), b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(v)), accept = false))
        assertEquals(HeldKind.LEAVE, assertNotNull(b.heldChange(v), "the leave was signed as asked and waits").kind)

        val w = shared()
        b.refresh(w, null, null, force = true)
        bobState.loseNext = true
        assertEquals(Adoption.Declined(w), b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(w)), accept = false), "its leave is in the log")
    }

    /**
     * A change the server asked this device to slow down for at its first send is known not stored (the server answers
     * that before it looks at the frame): it is said as a refusal that keeps the change ([AppendOutcome.Refused.held]),
     * sent again byte for byte, and until then it can be withdrawn. Before, it was a bare refusal although the change was
     * kept and later sent, so a change the person was told had not happened could happen after all.
     */
    @Test fun aChangeTheServerAskedToSlowDownForIsKeptKnownNotStoredAndCanBeWithdrawn() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.rateLimitAppends = 1
        val r = assertIs<AppendOutcome.Refused>(a.append(vaultId, LogAction.Add(bob.userId, "writer")))
        assertEquals("rate_limited", r.code)
        assertTrue(r.held, "kept, and known not stored")
        assertEquals(1, server.logs.getValue(vaultId).size, "nothing stored")
        a.retryPending()
        assertEquals(2, server.logs.getValue(vaultId).size, "sent again and stored")
        assertFalse(a.withdrawHeld(vaultId), "nothing is held now")

        now += 1000
        server.rateLimitAppends = 2
        assertTrue(assertIs<AppendOutcome.Refused>(a.append(vaultId, LogAction.Role(bob.userId, "reader"))).held)
        assertIs<HeldRepost.Waiting>(a.repostAsHeld(vaultId))
        assertTrue(a.withdrawHeld(vaultId), "two slow-downs: still known not stored, so it is withdrawn")
        a.retryPending()
        assertEquals(2, server.logs.getValue(vaultId).size, "a withdrawn change is never sent")
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Role(bob.userId, "reader")), "nothing waits on the vault")
    }

    /**
     * A change sent once without an answer (the server may have stored it) and then answered "slow down" is not known
     * either way: the outcome is [AppendOutcome.Pending], never a refusal, and it cannot be withdrawn. Before, a resumed
     * restore's create said "refused" although its genesis was stored.
     */
    @Test fun aSlowDownAfterASendWithoutAnAnswerIsStillCannotTell() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val id = "11111111-2222-4333-8444-555555555555"
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(null, LogAction.Create("Family", id)))
        assertEquals(1, server.logs.getValue(id).size, "the server stored the genesis")
        server.rateLimitAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(null, LogAction.Create("Family", id)), "cannot tell, never refused")
        assertFalse(a.withdrawHeld(id), "a change that may be stored is not withdrawn")
        assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family", id)))
        assertEquals(1, server.logs.getValue(id).size, "made once")
    }

    /** A vault of alice's with bob a writer, and alice's engine (over [device]). */
    private suspend fun vaultWithBob(server: Server, device: MemoryDeviceState = MemoryDeviceState()): Pair<StoredVaultLogs, String> {
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub), device)
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Add(bob.userId, "writer")))
        now += 1000
        return a to v
    }

    /**
     * A removal the server stored but whose answer was lost is shown as held with what is known, withdrawn, never sent
     * again, and the read the withdrawal makes finds it made after all: kept at rest across a restart until shown. One
     * the server said it did not store (a slow-down) is withdrawn with nothing more to say.
     */
    @Test fun aChangeWhoseAnswerWasLostIsWithdrawnRememberedAndFoundMadeAfterAll() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        assertEquals(3, server.logs.getValue(v).size, "the server stored the removal")
        val held = assertNotNull(a.heldChange(v))
        assertEquals(HeldKind.REMOVE, held.kind)
        assertEquals(bob.userId, held.names)
        assertEquals(HeldKnown.CANNOT_TELL, held.known)
        assertEquals(now, held.heldSince)
        assertTrue(held.withdrawable)
        assertFalse(held.waitsForWord)
        assertFalse(held.requestOut)
        val w = assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        assertEquals(HeldKnown.CANNOT_TELL, w.known, "the words follow the state the record had")
        assertNull(a.heldChange(v))
        val sent = server.appends
        a.retryPending()
        a.resendHeld()
        assertEquals(sent, server.appends, "a withdrawn change is never sent again")
        val again = engine(server, alice, SharedState(), emptyMap(), device)
        val f = again.heldFindings().single()
        assertEquals(FoundKind.MADE_AFTER_ALL, f.what)
        assertEquals(LetGo.WITHDRAWN, f.letGo)
        assertEquals(HeldKind.REMOVE, f.change)
        assertEquals(bob.userId, f.names)
        assertEquals(v, f.vaultId)
        again.findingShown(f.id)
        assertTrue(a.heldFindings().isEmpty(), "forgotten once shown")

        server.rateLimitAppends = 1
        assertTrue(assertIs<AppendOutcome.Refused>(a.append(v, LogAction.Add(bob.userId, "reader"))).held)
        assertEquals(HeldKnown.NOT_STORED, assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v)).known)
        assertTrue(a.heldFindings().isEmpty(), "known not stored: nothing more to say")
        assertNull(device.get(StoredVaultLogs.recordKey(alice.userId, v, "watch")), "and nothing remembered")
    }

    /**
     * Where no answer named a head, "not made" is said from the log as read, once, and the change stays remembered while
     * its position is free: when the request reaches the server after all, the person is told it was made.
     */
    @Test fun aWithdrawnChangeTheServerNeverGotIsToldNotMadeOnceAndMadeAfterAllIfItLandsLater() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        val frame = server.lastFrame()
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        val first = a.heldFindings().single()
        assertEquals(FoundKind.NOT_MADE, first.what)
        assertFalse(first.final, "still remembered while its position is free")
        a.findingShown(first.id)
        a.refresh(v, null, null, force = true)
        assertTrue(a.heldFindings().isEmpty(), "said once")
        server.lateAppend(v, frame)
        a.refresh(v, null, null, force = true)
        val made = a.heldFindings().single()
        assertEquals(FoundKind.MADE_AFTER_ALL, made.what)
        assertEquals(HeldKind.REMOVE, made.change)
    }

    /**
     * A withdrawal whose read cannot reach the server says nothing yet, and makes the next look read the log although the
     * served head did not move; the person's next change takes the position and ends the memory.
     */
    @Test fun anUntoldWithdrawalIsReadAtTheNextLookAndTheNextChangeEndsItsMemory() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.down = true
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        assertTrue(a.heldFindings().isEmpty(), "no read reached the server: nothing is said yet")
        server.down = false
        val head = assertIs<VaultLogStatus.Verified>(a.status(v)).state
        val fetches = server.fetches
        a.refresh(v, head.headSeq, head.headHash, force = false)
        assertTrue(server.fetches > fetches, "read although the served head did not move")
        assertEquals(FoundKind.NOT_MADE, a.heldFindings().single().what)
        val after = server.fetches
        a.refresh(v, head.headSeq, head.headHash, force = false)
        assertEquals(after, server.fetches, "once told, no more reads of its own")
        val watch = StoredVaultLogs.recordKey(alice.userId, v, "watch")
        assertNotNull(device.get(watch))
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Remove(bob.userId)))
        assertNull(device.get(watch), "its position taken: the memory ends")
        assertEquals(1, a.heldFindings().size, "already told: nothing more")
    }

    /**
     * An addition the server stored, answered with a head beyond it, read back one short: the server has it, so it is not
     * offered for withdrawal and a withdrawal is refused with a result of its own (it stays held, and nothing is said of it
     * as let go); once a read reaches it, it is stored. (Before, it was withdrawable; a change withdrawn while a try is out
     * and answered so afterwards is [aWithdrawnChangeAnAnswerNamedThenAnotherEntryThereFreezesTheVaultAndSaysNothing].)
     */
    @Test fun aChangeTheServersAnswerCalledStoredIsNotOfferedForWithdrawal() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.appendHead = LogHead(2, "ab".repeat(32), 0)
        server.serveOnly = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Add(bob.userId, "writer")))
        server.appendHead = null
        assertEquals(2, server.logs.getValue(v).size, "the server stored the addition")
        val held = assertNotNull(a.heldChange(v))
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, held.known)
        assertFalse(held.withdrawable, "the server has it: not offered for withdrawal")
        assertEquals(HeldWithdrawal.STORED_BY_SERVERS_WORD, assertIs<HeldWithdrawal.Kept>(a.withdrawAsHeld(v)).reason)
        assertNotNull(a.heldChange(v), "still held")
        a.refresh(v, null, null, force = true)
        assertTrue(a.heldFindings().isEmpty(), "a read that ends before the head the answer named says nothing")
        assertNotNull(a.heldChange(v))
        server.serveOnly = null
        a.refresh(v, null, null, force = true)
        assertNull(a.heldChange(v), "the log shows it: stored")
        assertTrue(a.heldFindings().isEmpty(), "never let go: nothing to tell")
        assertNotNull(assertIs<VaultLogStatus.Verified>(a.status(v)).state.members[bob.userId])
    }

    /**
     * During the give-up's read the person withdraws the held removal and signs a
     * change of role whose request is lost. The give-up drops nothing it did not read, and never overwrites the
     * withdrawal's memory: the removal, stored late, is told as withdrawn and made after all.
     */
    @Test fun givingUpNeverDropsARecordItDidNotReadNorOverwritesAWithdrawalsMemory() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        val removal = server.lastFrame()
        now += StoredVaultLogs.GIVE_UP_MS + 1
        var inner: AppendOutcome? = null
        server.onFetch = {
            assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
            server.dropAppends = 1
            inner = a.append(v, LogAction.Role(bob.userId, "reader"))
        }
        assertEquals(listOf<HeldResend>(HeldResend.NotHeld(v)), a.resendHeld())
        assertEquals(AppendOutcome.Pending, inner)
        assertEquals(HeldKind.ROLE, assertNotNull(a.heldChange(v), "the change signed during the read is still held").kind)
        assertTrue(a.heldFindings().none { it.what == FoundKind.GIVEN_UP }, "nothing was given up")
        server.lateAppend(v, removal)
        a.refresh(v, null, null, force = true)
        val made = a.heldFindings().single { it.what == FoundKind.MADE_AFTER_ALL }
        assertEquals(LetGo.WITHDRAWN, made.letGo)
        assertEquals(HeldKind.REMOVE, made.change)
    }

    /** A change whose first request is out is not withdrawn until that request ends. */
    @Test fun aChangeWhoseFirstRequestIsOutIsWithdrawnOnlyOnceThatRequestHasEnded() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        var during: HeldWithdrawal? = null
        var shown: HeldChange? = null
        server.onAppend = {
            shown = a.heldChange(v)
            during = a.withdrawAsHeld(v)
        }
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        assertEquals(HeldWithdrawal.FIRST_REQUEST_OUT, assertIs<HeldWithdrawal.Kept>(during).reason)
        val drawn = assertNotNull(shown)
        assertTrue(drawn.requestOut)
        assertFalse(drawn.withdrawable)
        assertEquals(HeldKind.REMOVE, assertNotNull(a.heldChange(v), "still held").kind)
        assertTrue(assertNotNull(a.heldChange(v)).withdrawable, "once the request ended")
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        assertEquals(FoundKind.MADE_AFTER_ALL, a.heldFindings().single().what)
    }

    /**
     * A re-post is out when the person withdraws the change and signs another; the old answer then arrives (stored). The
     * withdrawn record is not brought back, the newer one is not dropped, and "not made" was never said while that
     * request was out. The newer change, whose place the old one took, is said as never to be made, as soon as it is
     * reported (settled against what the old answer's read verified, with nothing sent).
     */
    @Test fun anAnswerForAChangeWithdrawnMeanwhileNeitherBringsItBackNorDropsANewerOne() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        var inner: AppendOutcome? = null
        server.onAppend = {
            assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
            server.dropAppends = 1
            inner = a.append(v, LogAction.Role(bob.userId, "reader"))
        }
        assertIs<HeldResend.Stored>(a.resendHeld().single())
        assertEquals(AppendOutcome.Pending, inner)
        assertNotNull(device.get(StoredVaultLogs.recordKey(alice.userId, v, "pending")), "the newer change is not dropped by the old answer")
        assertEquals(listOf(FoundKind.MADE_AFTER_ALL), a.heldFindings().map { it.what }, "never 'not made' while its own request was out")
        val sent = server.appends
        assertNull(a.heldChange(v), "its place taken: no longer reported as waiting")
        assertEquals(emptyList<HeldResend>(), a.resendHeld())
        assertEquals(sent, server.appends)
        assertEquals(HeldKind.ROLE, a.heldFindings().single { it.what == FoundKind.PLACE_TAKEN }.change)
    }

    /**
     * A role change, an offer and a removal held a day are not sent again: the log is read, and each is given up and
     * remembered (the removal, stored late, is told made after all); one known not stored is given up for good; one the
     * read shows stored is stored; a record from before the day's field counts its day from the first time it is seen.
     */
    @Test fun aChangeHeldADayIsNotSentAgainButGivenUpAfterARead() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        for (action in listOf(LogAction.Role(bob.userId, "reader"), LogAction.Offer(bob.userId, DAY), LogAction.Remove(bob.userId))) {
            server.dropAppends = 1
            assertEquals(AppendOutcome.Pending, a.append(v, action), "$action")
            now += StoredVaultLogs.GIVE_UP_MS
            val sent = server.appends
            assertEquals(listOf<HeldResend>(HeldResend.GivenUp(v)), a.resendHeld(), "$action")
            assertEquals(sent, server.appends, "$action: not sent again")
            assertNull(a.heldChange(v))
        }
        val given = a.heldFindings().filter { it.what == FoundKind.GIVEN_UP }
        assertEquals(listOf(HeldKind.ROLE, HeldKind.OFFER, HeldKind.REMOVE), given.map { it.change })
        assertTrue(given.all { !it.final && it.absentAtRead })
        server.lateAppend(v, server.lastFrame())
        a.refresh(v, null, null, force = true)
        assertEquals(LetGo.GIVEN_UP, a.heldFindings().single { it.what == FoundKind.MADE_AFTER_ALL }.letGo)

        server.rateLimitAppends = 1
        assertTrue(assertIs<AppendOutcome.Refused>(a.append(v, LogAction.Add(bob.userId, "reader"))).held)
        now += StoredVaultLogs.GIVE_UP_MS
        assertEquals(listOf<HeldResend>(HeldResend.GivenUp(v)), a.resendHeld())
        assertTrue(a.heldFindings().last().let { it.what == FoundKind.GIVEN_UP && it.final }, "known not stored: given up for good")

        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Add(bob.userId, "reader")))
        now += StoredVaultLogs.GIVE_UP_MS
        assertIs<HeldResend.Stored>(a.resendHeld().single(), "the read shows it stored")

        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "writer")))
        val key = StoredVaultLogs.recordKey(alice.userId, v, "pending")
        device.set(key, assertNotNull(device.get(key)).replace(Regex(",\"heldAt\":[0-9]+"), ""))
        now += 2 * StoredVaultLogs.GIVE_UP_MS
        assertEquals(now, assertNotNull(a.heldChange(v)).heldSince, "counted from the first time it is seen")
        server.dropAppends = 1
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld(), "sent again inside its day")
        now += StoredVaultLogs.GIVE_UP_MS
        assertEquals(listOf<HeldResend>(HeldResend.GivenUp(v)), a.resendHeld())
    }

    /**
     * A vault's deletion that waits is never sent by the general re-send, nor before another change of the vault; the
     * person's word sends it. A deletion a move signed is the move's: never withdrawn, sent or given up here. The person's
     * deletion held a day is given up, after a read.
     */
    @Test fun aVaultsDeletionThatWaitsIsSentAgainOnlyAtThePersonsWord() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Delete))
        val held = assertNotNull(a.heldChange(v))
        assertEquals(HeldKind.DELETE, held.kind)
        assertTrue(held.waitsForWord)
        assertTrue(held.withdrawable)
        assertFalse(held.movesOwn)
        val sent = server.appends
        assertEquals(listOf<HeldResend>(HeldResend.WaitsForWord(v)), a.resendHeld())
        a.retryPending()
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.APPEND_PENDING), a.append(v, LogAction.Role(bob.userId, "reader")))
        assertEquals(sent, server.appends, "nothing sent without the person's word")
        assertIs<HeldRepost.Stored>(a.repostAsHeld(v), "the person's word sends it")
        assertNotNull(assertIs<VaultLogStatus.Verified>(a.status(v)).state.deletedId)

        val w = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Old"))).state.vaultId
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(w, LogAction.DeleteVault(movesOwn = true)))
        val moves = assertNotNull(a.heldChange(w))
        assertTrue(moves.movesOwn)
        assertFalse(moves.withdrawable)
        assertFalse(moves.waitsForWord)
        assertEquals(HeldWithdrawal.NOT_WITHDRAWABLE, assertIs<HeldWithdrawal.Kept>(a.withdrawAsHeld(w)).reason)
        now += 2 * StoredVaultLogs.GIVE_UP_MS
        val before = server.appends
        assertEquals(listOf<HeldResend>(HeldResend.MovesOwn(w)), a.resendHeld())
        assertEquals(before, server.appends)
        assertIs<HeldRepost.Stored>(a.repostAsHeld(w), "the move's own road sends it")

        val x = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Third"))).state.vaultId
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(x, LogAction.Delete))
        now += StoredVaultLogs.GIVE_UP_MS
        val fetches = server.fetches
        assertEquals(listOf<HeldResend>(HeldResend.GivenUp(x)), a.resendHeld())
        assertTrue(server.fetches > fetches, "read first")
        assertNull(a.heldChange(x))
    }

    /** A held deletion a read already shows stored is settled with nothing sent, and the vault takes its next change (a restore). */
    @Test fun aHeldDeletionTheLogAlreadyHoldsIsSettledAndTheNextChangeGoesOn() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.DeleteVault(movesOwn = true)))
        a.refresh(v, null, null, force = true)
        val sent = server.appends
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Restore))
        assertEquals(sent + 1, server.appends, "only the restore was sent")
        assertNull(a.heldChange(v))
    }

    /**
     * A vault's deletion names the point up to which its items were read, beside the signed entry and at every re-post; a
     * refusal because the items moved on is its own outcome (nothing stored, nothing held, never "cannot tell"), and a
     * deletion signed afresh with a new point is stored. No other change carries a point.
     */
    @Test fun aVaultsDeletionNamesItsReadPointAndItemsThatMovedOnAreAnOutcomeOfTheirOwn() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        assertNull(WireJson.json.decodeFromString(LogAppendRequest.serializer(), server.lastAppend!!).itemsAtMost)
        assertFalse("itemsAtMost" in server.lastAppend!!, "no point on an addition")
        server.itemsRev = 7
        val r = assertIs<AppendOutcome.Refused>(a.append(v, LogAction.DeleteVault(movesOwn = true, itemsAtMost = 5)))
        assertEquals(io.silencelen.andvari.core.model.wire.WireErrors.VAULT_ITEMS_MOVED, r.code)
        assertFalse(r.held)
        assertEquals(5L, WireJson.json.decodeFromString(LogAppendRequest.serializer(), server.lastAppend!!).itemsAtMost)
        assertEquals(2, server.logs.getValue(v).size, "nothing stored")
        assertNull(a.heldChange(v), "nothing held")
        assertTrue(a.heldFindings().isEmpty(), "nothing remembered: the server proved it not stored")
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.DeleteVault(movesOwn = true, itemsAtMost = 7)))
        assertIs<HeldRepost.Stored>(a.repostAsHeld(v))
        assertEquals(7L, WireJson.json.decodeFromString(LogAppendRequest.serializer(), server.lastAppend!!).itemsAtMost, "the point goes again with the re-post")
        assertNotNull(assertIs<VaultLogStatus.Verified>(a.status(v)).state.deletedId)
    }

    /** The memories of one vault are bounded (the oldest go first), and a taken position ends every memory of it at once. */
    @Test fun theMemoriesOfOneVaultAreBoundedAndATakenPositionEndsThemAtOnce() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        val frames = ArrayList<String>()
        repeat(StoredVaultLogs.MAX_WATCHES + 4) {
            server.dropAppends = 1
            assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
            frames += server.lastFrame()
            now += 1000
            assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        }
        val key = StoredVaultLogs.recordKey(alice.userId, v, "watch")
        assertEquals(StoredVaultLogs.MAX_WATCHES, Regex("\"hash\"").findAll(assertNotNull(device.get(key))).count(), "bounded")
        server.lateAppend(v, frames.first())
        a.refresh(v, null, null, force = true)
        assertTrue(a.heldFindings().none { it.what == FoundKind.MADE_AFTER_ALL }, "the oldest memory went first")
        assertNull(device.get(key), "a taken position ends every memory of it at once")
    }

    /**
     * An addition the server asked to slow down for is sent again by one session; during that try a new
     * engine over the same records (a lock and an unlock) reads the record at rest. It is "cannot tell" from the moment the
     * try left, so the withdrawal keeps its memory, and the try that the server then stores is told made after all.
     */
    @Test fun aSendMakesTheRecordAtRestCannotTellBeforeItLeaves() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub), device)
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.rateLimitAppends = 1
        assertTrue(assertIs<AppendOutcome.Refused>(a.append(v, LogAction.Add(bob.userId, "writer"))).held)
        assertEquals(HeldKnown.NOT_STORED, assertNotNull(a.heldChange(v)).known)
        var shown: HeldChange? = null
        var during: HeldWithdrawal? = null
        server.onAppend = {
            val b = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub), device)
            shown = b.heldChange(v)
            during = b.withdrawAsHeld(v)
        }
        a.resendHeld()
        assertEquals(HeldKnown.CANNOT_TELL, assertNotNull(shown).known, "a try is out: never known not stored")
        assertEquals(HeldKnown.CANNOT_TELL, assertIs<HeldWithdrawal.Withdrawn>(during).known)
        assertEquals(2, server.logs.getValue(v).size, "the earlier session's try was stored")
        val made = a.heldFindings().single { it.what == FoundKind.MADE_AFTER_ALL }
        assertEquals(HeldKind.ADD, made.change)
        assertEquals(bob.userId, made.names)
        assertEquals(LetGo.WITHDRAWN, made.letGo)
    }

    /**
     * The server answered that it stored a change of role at its position, then serves another device's
     * removal there. The answer and the log cannot both be true: the vault is frozen and nothing is said of the change.
     */
    @Test fun anAnswerThatNamedTheChangeThenAReadWithAnotherEntryThereFreezesTheVault() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.lieAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertEquals(2, server.logs.getValue(v).size, "the answer said stored; nothing was")
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        val r = a.resendHeld()
        assertIs<VaultLogStatus.Frozen>(a.status(v))
        assertEquals(listOf<HeldResend>(HeldResend.Frozen(v)), r)
        assertTrue(a.heldFindings().isEmpty(), "nothing is said of the change")
        assertNull(a.heldChange(v))
    }

    /**
     * A change of role is withdrawn while a try of it is out, and the server answers that try
     * with a head naming it at its position. A read short of that head says nothing ("not made" never), and a read with
     * another entry there freezes the vault and says nothing of the change.
     */
    @Test fun aWithdrawnChangeAnAnswerNamedThenAnotherEntryThereFreezesTheVaultAndSaysNothing() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.onAppend = { assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v)) }
        server.lieAppends = 1
        a.resendHeld()
        assertNull(a.heldChange(v))
        assertTrue(a.heldFindings().none { it.what == FoundKind.NOT_MADE }, "an answer named it: never 'not made' from a read short of it")
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.refresh(v, null, null, force = true)
        assertIs<VaultLogStatus.Frozen>(a.status(v))
        assertTrue(a.heldFindings().isEmpty(), "nothing is said of the change")
    }

    /**
     * A change of role the server answered stored at its position while nothing was stored, then another
     * device's entry there. ONE read of the log (a sync's, not forced), and nothing called after it: the vault reads frozen
     * and is not writable at that read, the held change is gone, and nothing is said of it.
     */
    @Test fun aContradictionOfAHeldChangeOfMembersFreezesTheVaultAtTheReadThatShowsIt() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.lieAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        val sent = server.appends
        a.refresh(v, null, null, force = false)
        assertIs<VaultLogStatus.Frozen>(a.status(v), "frozen at the read itself")
        assertFalse(a.writeAllowed(v))
        assertEquals(sent, server.appends, "nothing sent")
        assertTrue(a.heldFindings().isEmpty(), "nothing is said of the change")
        assertTrue(a.heldChanges().isEmpty())
        assertEquals(AppendOutcome.VaultReadOnly, a.append(v, LogAction.Role(alice.userId, "owner")))
    }

    /**
     * A move's own deletion: sent with no answer, its re-post answered as stored at its position while
     * nothing was stored, then another device's entry there. One forced read: frozen and not writable, the held deletion is
     * dropped (nothing is held for the move to send), and nothing is said of it.
     */
    @Test fun aContradictionOfAMovesOwnDeletionFreezesTheVaultAtTheReadThatShowsIt() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.DeleteVault(movesOwn = true)))
        server.lieAppends = 1
        assertEquals(HeldRepost.Waiting, a.repostAsHeld(v))
        val held = assertNotNull(a.heldChange(v))
        assertTrue(held.movesOwn)
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, held.known)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        val sent = server.appends
        a.refresh(v, null, null, force = true)
        assertIs<VaultLogStatus.Frozen>(a.status(v), "frozen at the read itself")
        assertFalse(a.writeAllowed(v))
        assertTrue(a.heldFindings().isEmpty(), "nothing is said of the change")
        assertEquals(HeldRepost.NothingHeld, a.repostAsHeld(v), "nothing is held for the move to send")
        assertEquals(sent, server.appends, "nothing sent")
        assertEquals(HeldWithdrawal.NOTHING_HELD, assertIs<HeldWithdrawal.Kept>(a.dropHalfMade(v)).reason)
    }

    /** An answer naming a head far beyond the change is an answer about it, and one read freezes. */
    @Test fun aContradictionOfAnAnswerFarBeyondTheChangeFreezesTheVaultAtTheReadThatShowsIt() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.lieAppends = 1
        server.appendHead = LogHead(2 + 7, "ab".repeat(32), 0)
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.appendHead = null
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.refresh(v, null, null, force = true)
        assertIs<VaultLogStatus.Frozen>(a.status(v), "frozen at the read itself")
        assertFalse(a.writeAllowed(v))
        assertTrue(a.heldFindings().isEmpty(), "nothing is said of the change")
        assertTrue(a.heldChanges().isEmpty())
    }

    /**
     * An answer naming a head below the change is no answer about it. Another entry at
     * its place and one read leave the vault verified and writable; the held change is then settled as "its place was taken".
     */
    @Test fun anAnswerBelowTheChangeStaysNoAnswerAtTheReadThatShowsAnotherEntryThere() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.lieAppends = 1
        server.appendHead = LogHead(2 - 1, "ab".repeat(32), 0)
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.appendHead = null
        assertEquals(HeldKnown.CANNOT_TELL, assertNotNull(a.heldChange(v)).known)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.refresh(v, null, null, force = true)
        assertIs<VaultLogStatus.Verified>(a.status(v))
        assertTrue(a.writeAllowed(v))
        assertTrue(a.heldChanges().isEmpty(), "its place was taken")
        assertEquals(listOf(FoundKind.PLACE_TAKEN), a.heldFindings().map { it.what })
        assertIs<VaultLogStatus.Verified>(a.status(v))
    }

    /**
     * An honest server: a change stored and answered `200` at its position, whose read right after did not reach it yet, so
     * it is held as stored by the server's word; another device's entry after it; one read. Verified, writable, the change
     * settled as stored, nothing said: the read's check freezes no honest sequence.
     */
    @Test fun anHonestAnswerHeldUntilAReadNeverFreezesTheVaultAtThatRead() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.serveOnly = 2
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        server.serveOnly = null
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.refresh(v, null, null, force = false)
        assertIs<VaultLogStatus.Verified>(a.status(v))
        assertTrue(a.writeAllowed(v))
        assertTrue(a.heldChanges().isEmpty(), "stored")
        assertTrue(a.heldFindings().isEmpty())
        assertEquals(4, server.logs.getValue(v).size)
    }

    /**
     * An answer that names a head below the change (a replayed answer, another vault's) is no answer about this change's
     * position: where the read holds the change it is stored and the vault is not frozen; where another entry took its
     * place, its place was taken, and the vault is not frozen either.
     */
    @Test fun anAnswerNamingAHeadBelowTheChangeNeverFreezesTheVault() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.appendHead = LogHead(0, "cd".repeat(32), 0)
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Role(bob.userId, "reader")))
        assertIs<VaultLogStatus.Verified>(a.status(v))
        now += 1000
        server.serveOnly = 3
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "writer")))
        server.appendHead = null
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        server.logs.getValue(v).removeAt(3)
        server.serveOnly = null
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.refresh(v, null, null, force = true)
        assertIs<VaultLogStatus.Verified>(a.status(v))
        assertNull(a.heldChange(v), "its place was taken")
        assertEquals(listOf(FoundKind.PLACE_TAKEN), a.heldFindings().map { it.what })
    }

    /**
     * A deletion the server stored, whose answer was lost, then a sync's read of the vault. What is reported
     * as waiting is settled against what this device verified, with nothing sent: the deletion no longer waits for a word.
     */
    @Test fun aHeldDeletionTheServerStoredIsNoLongerReportedWaitingAfterASyncsRead() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Delete))
        assertTrue(assertNotNull(a.heldChange(v)).waitsForWord)
        a.refresh(v, null, null, force = true)
        assertNotNull(assertIs<VaultLogStatus.Verified>(a.status(v)).state.deletedId, "the sync's read verified the deletion")
        val sent = server.appends
        assertEquals(HeldWithdrawal.NOTHING_HELD, assertIs<HeldWithdrawal.Kept>(a.withdrawAsHeld(v)).reason, "'keep the vault' keeps nothing: it is deleted")
        assertTrue(a.heldChanges().isEmpty(), "settled against what this device verified")
        assertNull(a.heldChange(v))
        assertEquals(sent, server.appends, "nothing sent")
        val f = a.heldFindings().single()
        assertEquals(FoundKind.MADE, f.what, "the person is told the vault was deleted")
        assertEquals(HeldKind.DELETE, f.change)
        assertEquals(v, f.vaultId)
    }

    /**
     * The same, as one call: the look before the question reads one vault's log and settles what is held for it,
     * sending nothing and leaving every other vault's change alone. A deletion the log holds is made; one still held is
     * asked about; one whose place another device took did not happen.
     */
    @Test fun theLookBeforeTheQuestionReadsAndSettlesAndSendsNothing() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        val w = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Other"))).state.vaultId
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(w, LogAction.Delete))
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Delete))
        val sent = server.appends
        assertNotNull(assertIs<HeldLook.Made>(a.lookHeld(v)).state.deletedId)
        assertEquals(FoundKind.MADE, a.heldFindings().single().what)
        val still = assertIs<HeldLook.StillHeld>(a.lookHeld(w))
        assertTrue(still.change.waitsForWord)
        assertTrue(still.readReached)
        assertEquals(sent, server.appends, "nothing sent, and the other vault's deletion was left alone")
        assertIs<HeldLook.NothingHeld>(a.lookHeld(v))

        val other = engine(server, alice, SharedState(), emptyMap())
        other.refresh(w, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(w, LogAction.Delete))
        val before = server.appends
        assertIs<HeldLook.PlaceTaken>(a.lookHeld(w))
        assertEquals(before, server.appends)
        assertNull(a.heldChange(w))
        assertEquals(HeldKind.DELETE, a.heldFindings().single { it.what == FoundKind.PLACE_TAKEN }.change)
        server.down = true
        assertIs<HeldLook.NothingHeld>(a.lookHeld(w))
    }

    /**
     * A held removal a day old; during the give-up's read a second try of it is stored and answered, and
     * that read ends one short. A change the server's own answer called stored is not given up as "cannot tell": it is
     * kept and sent as it is until the log shows it.
     */
    @Test fun aChangeTheServersAnswerCalledStoredIsNotGivenUp() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        now += StoredVaultLogs.GIVE_UP_MS + 1
        server.serveOnly = 2
        server.onFetch = { assertIs<HeldRepost.Waiting>(a.repostAsHeld(v)) }
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld())
        assertTrue(a.heldFindings().none { it.what == FoundKind.GIVEN_UP }, "${a.heldFindings()}")
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        server.serveOnly = null
        assertIs<HeldResend.Stored>(a.resendHeld().single())
        assertTrue(a.heldFindings().isEmpty())
    }

    /** A withdrawal that took effect answers as that, also where a lock cuts off the read that follows it. */
    @Test fun aWithdrawalThatTookEffectAnswersAsThatWhenALockCutsOffItsRead() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        server.onFetch = { throw io.silencelen.andvari.core.crypto.KeysGoneException() }
        assertEquals(HeldKnown.CANNOT_TELL, assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v)).known)
        assertNull(a.heldChange(v))
        a.refresh(v, null, null, force = true)
        assertEquals(FoundKind.MADE_AFTER_ALL, a.heldFindings().single().what)
    }

    /**
     * The limit on what is remembered lets go of withdrawals already told first (an untold one stays, and is told when the
     * server makes it after all), and never of a "made after all" not yet shown while anything else can go.
     */
    @Test fun theLimitLetsGoOfToldWithdrawalsFirstAndNeverOfAnUnshownMadeAfterAll() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        val made = a.heldFindings().single()
        assertEquals(FoundKind.MADE_AFTER_ALL, made.what)
        now += 1000
        server.headMovedAppend = LogHead(9, "ab".repeat(32), 0)
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "writer")))
        val untold = server.lastFrame()
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        assertEquals(1, a.heldFindings().size, "a read short of the head the answer named says nothing")
        repeat(StoredVaultLogs.MAX_FINDINGS) {
            now += 1000
            server.dropAppends = 1
            assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "writer")))
            assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        }
        assertTrue(a.heldFindings().any { it.id == made.id }, "an unshown 'made after all' is kept while anything else can go")
        server.lateAppend(v, untold)
        a.refresh(v, null, null, force = true)
        assertTrue(a.heldFindings().any { it.what == FoundKind.MADE_AFTER_ALL && it.id != made.id }, "the untold withdrawal outlived those already told")
    }

    /**
     * A deletion of a vault half-made by a stopped move, held from an earlier try (the move's own, or unmarked), is dropped
     * unsent at the move's word, sending and reading nothing, and remembered as a kind of its own: when the log holds it
     * after all, the finding says so with that kind and when it was signed. A later change of such a vault sends only itself.
     */
    @Test fun aHeldDeletionOfAHalfMadeVaultIsDroppedAndRememberedAsItsOwnKind() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        val signed = now
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.DeleteVault(movesOwn = true)))
        val frame = server.lastFrame()
        assertEquals(HeldWithdrawal.NOT_WITHDRAWABLE, assertIs<HeldWithdrawal.Kept>(a.withdrawAsHeld(v)).reason)
        val sent = server.appends
        val fetches = server.fetches
        val d = assertIs<HeldWithdrawal.Withdrawn>(a.dropHalfMade(v))
        assertEquals(HeldKind.DELETE, d.change.kind)
        assertEquals(HeldKnown.CANNOT_TELL, d.known)
        assertEquals(sent, server.appends)
        assertEquals(fetches, server.fetches, "nothing read")
        assertNull(a.heldChange(v))
        assertTrue(a.heldFindings().isEmpty(), "no 'not made' line")
        server.lateAppend(v, frame)
        a.refresh(v, null, null, force = true)
        val f = a.heldFindings().single()
        assertEquals(FoundKind.MADE_AFTER_ALL, f.what)
        assertEquals(LetGo.HALF_MADE, f.letGo)
        assertEquals(HeldKind.DELETE, f.change)
        assertEquals(signed, f.signedAt)

        val w = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Half"))).state.vaultId
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(w, LogAction.Delete))
        assertIs<HeldWithdrawal.Withdrawn>(a.dropHalfMade(w))
        val before = server.appends
        assertIs<AppendOutcome.Appended>(a.append(w, LogAction.Add(bob.userId, "writer")))
        assertEquals(before + 1, server.appends, "only the new change was sent")
        assertNull(assertIs<VaultLogStatus.Verified>(a.status(w)).state.deletedId)
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(w, LogAction.Role(bob.userId, "reader")))
        assertEquals(HeldWithdrawal.NOT_A_DELETION, assertIs<HeldWithdrawal.Kept>(a.dropHalfMade(w)).reason)
        assertNotNull(a.heldChange(w))
    }

    /**
     * Forgetting an account removes every record this engine keeps for it (verified logs, held changes, memories,
     * findings), and nothing of another account's or of anything else. A store that cannot list its keys loses the
     * indexed held changes and findings, and the answer says that not everything went.
     */
    @Test fun forgettingAnAccountRemovesEveryRecordThisEngineKeepsForIt() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        assertEquals(1, a.heldFindings().size)
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "writer")))
        device.set("ovh.log|${bob.userId}|$v|state", "another account's")
        device.set("ovh.acct|${alice.userId}", "not this engine's")
        val mine = "ovh.log|${alice.userId}|"
        val unlisted = object : io.silencelen.andvari.core.client.DeviceState {
            override fun get(key: String) = device.get(key)
            override fun set(key: String, value: String?) = device.set(key, value)
        }
        assertFalse(StoredVaultLogs.forgetAccount(unlisted, alice.userId), "a store that cannot list: not everything")
        assertNull(device.get(StoredVaultLogs.recordKey(alice.userId, v, "pending")))
        assertNull(device.get(StoredVaultLogs.recordKey(alice.userId, v, "found")))
        assertTrue(device.keys().any { it.startsWith(mine) }, "the verified log stays where nothing lists it")
        assertTrue(StoredVaultLogs.forgetAccount(device, alice.userId))
        assertTrue(device.keys().none { it.startsWith(mine) })
        assertEquals("another account's", device.get("ovh.log|${bob.userId}|$v|state"))
        assertEquals("not this engine's", device.get("ovh.acct|${alice.userId}"))
        val again = engine(server, alice, SharedState(), emptyMap(), device)
        assertTrue(again.heldChanges().isEmpty())
        assertTrue(again.heldFindings().isEmpty())
        assertIs<VaultLogStatus.Unknown>(again.status(v))
    }

    /**
     * A send that is out when the layer above forgets the account (after a deletion of unknown outcome) writes nothing of
     * that account when its answer comes: not a held change, not its index, not a verified state. Three sequences: a new
     * vault's creation whose account-state write is out (the sequence the layer's own test found), a change the server stored and
     * answered, and a stored answer that arrives after a later sign-in of the same account opened a new engine here (the
     * old request neither writes nor removes anything of the new engine's).
     */
    @Test fun aSendOutAtAnAccountsForgettingWritesNothingOfThatAccountWhenItsAnswerComes() = runBlocking<Unit> {
        val mine = "ovh.log|${alice.userId}|"
        fun MemoryDeviceState.left() = keys().filter { it.startsWith(mine) }.sorted()

        // 1. A new vault's creation whose account-state write is out when the forgetting is confirmed (the sequence the
        //    layer's own test found): the held creation and its index are not written, and its frame is not sent.
        val server = Server()
        val device = MemoryDeviceState()
        val shared = SharedState()
        val a = engine(server, alice, shared, mapOf(bob.userId to bob.pub), device)
        assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family")))
        now += 1000
        shared.onUpdate = { assertTrue(StoredVaultLogs.forgetAccount(device, alice.userId)); assertEquals(emptyList(), device.left()) }
        val appendsBefore = server.appends
        val created = runCatching { a.append(null, LogAction.Create("Two")) }
        assertEquals(emptyList(), device.left(), "the held creation and its index are not written back")
        assertEquals(appendsBefore, server.appends, "nothing of the forgotten account is sent")
        assertIs<io.silencelen.andvari.core.crypto.KeysGoneException>(created.exceptionOrNull(), "$created")

        // 2. A change of role the server stores and answers, out when the forgetting is confirmed.
        val server2 = Server()
        val device2 = MemoryDeviceState()
        val (a2, v2) = vaultWithBob(server2, device2)
        server2.onAppend = { assertTrue(StoredVaultLogs.forgetAccount(device2, alice.userId)) }
        val stored = runCatching { a2.append(v2, LogAction.Role(bob.userId, "reader")) }
        assertEquals(3, server2.logs.getValue(v2).size, "the server stored it")
        assertEquals(emptyList(), device2.left(), "no verified state, hash or record is written back")
        assertIs<io.silencelen.andvari.core.crypto.KeysGoneException>(stored.exceptionOrNull(), "$stored")

        // 3. The same account signs in again while the old request is out; then the old request is answered.
        val server3 = Server()
        val device3 = MemoryDeviceState()
        val (a3, v3) = vaultWithBob(server3, device3)
        var b3: StoredVaultLogs? = null
        val stateKey = StoredVaultLogs.recordKey(alice.userId, v3, StoredVaultLogs.STATE_PART)
        var newEngines: String? = null
        server3.onAppend = {
            assertTrue(StoredVaultLogs.forgetAccount(device3, alice.userId))
            val b = engine(server3, alice, SharedState(), mapOf(bob.userId to bob.pub), device3)
            b.refresh(v3, null, null, force = true)
            newEngines = device3.get(stateKey)
            b3 = b
        }
        val late = runCatching { a3.append(v3, LogAction.Role(bob.userId, "reader")) }
        assertEquals(3, server3.logs.getValue(v3).size, "the server stored the old request's change")
        assertNotNull(newEngines)
        assertEquals(newEngines, device3.get(stateKey), "the old request writes nothing over the new engine's verified state")
        assertNull(device3.get(StoredVaultLogs.recordKey(alice.userId, v3, "pending")), "nor a held change")
        assertNull(device3.get("${mine}pending-index"))
        assertIs<io.silencelen.andvari.core.crypto.KeysGoneException>(late.exceptionOrNull(), "$late")
        val b = b3!!
        assertTrue(b.heldChanges().isEmpty())
        assertIs<VaultLogStatus.Verified>(b.status(v3))
        now += 1000
        assertIs<VaultLogStatus.Verified>(b.refresh(v3, null, null, force = true))
        assertIs<AppendOutcome.Appended>(b.append(v3, LogAction.Remove(bob.userId)), "the new engine reads and writes as before")
    }

    /**
     * What the forgetting of an account removes, by a scan of every key and every value: after it nothing on the device
     * names the account but the records other keepers hold for it (here the account state's copy, which is the layer's).
     */
    @Test fun theForgettingOfAnAccountLeavesNoKeyOrValueOfThisEngineThatNamesIt() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "writer")))
        device.set("ovh.acct|${alice.userId}", "the layer's")
        val id = alice.userId
        assertTrue(device.keys().count { it.startsWith("ovh.log|$id|") } >= 7, "${device.keys()}")
        assertTrue(StoredVaultLogs.forgetAccount(device, id))
        val naming = device.keys().filter { it.contains(id) || device.get(it)!!.contains(id) || it.contains(v) || device.get(it)!!.contains(v) }
        assertEquals(listOf("ovh.acct|$id"), naming, "only another keeper's record names the account")
    }

    /**
     * A lying answer names a change of role at its own position, a second answer names an older head,
     * and another entry is then served at that position. The head named at the change is never taken away by the later
     * answer, so the vault freezes and nothing is said of the change.
     */
    @Test fun aLaterAnswerNamingAnOlderHeadNeverTakesAwayTheHeadNamedAtTheChange() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.lieAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.appendHead = LogHead(0, "cd".repeat(32), 0)
        server.lieAppends = 1
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld())
        server.appendHead = null
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.resendHeld()
        assertIs<VaultLogStatus.Frozen>(a.status(v))
        assertTrue(a.heldFindings().isEmpty(), "${a.heldFindings()}")
    }

    /**
     * An answer naming a head below the change, repeated, with nothing stored, is no answer about the
     * change: it does not read as stored by the server's word, it can be withdrawn, and a day later it is given up like any
     * other, so the vault's member changes are not blocked for as long as the answer is repeated.
     */
    @Test fun aReplayedOlderAnswerIsNoAnswerAboutTheChange() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.appendHead = LogHead(0, "cd".repeat(32), 0)
        server.lieAppends = 100
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        val held = assertNotNull(a.heldChange(v))
        assertEquals(HeldKnown.CANNOT_TELL, held.known, "not the server's word about this change")
        assertTrue(held.withdrawable)
        now += StoredVaultLogs.GIVE_UP_MS + 1
        assertEquals(listOf<HeldResend>(HeldResend.GivenUp(v)), a.resendHeld())
        server.lieAppends = 0
        server.appendHead = null
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Remove(bob.userId)), "the vault's member changes are not blocked")
    }

    /**
     * With an honest server: an addition stored and answered, read back one short, then its re-send refused because
     * the session ended. A refusal about the session says nothing of the change: it stays as it was, no "refused" is
     * kept, and the next whole read shows it made.
     */
    @Test fun aRefusalAboutTheSessionSaysNothingOfAHeldChange() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.serveOnly = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Add(bob.userId, "writer")))
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        server.refuseAppend = 401 to "unauthorized"
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld())
        assertTrue(a.heldFindings().isEmpty(), "${a.heldFindings()}")
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v), "the record stays as it was").known)
        server.serveOnly = null
        a.refresh(v, null, null, force = true)
        assertNull(a.heldChange(v))
        assertTrue(a.heldFindings().isEmpty())
        assertNotNull(assertIs<VaultLogStatus.Verified>(a.status(v)).state.members[bob.userId])
    }

    /**
     * A re-send that the origin's own guard stopped (nothing left this device) puts the record back as it was: a change
     * known not stored stays known not stored, although the record was marked "cannot tell" before the send.
     */
    @Test fun aResendTheOriginsGuardStoppedLeavesTheRecordAsItWas() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.rateLimitAppends = 1
        assertTrue(assertIs<AppendOutcome.Refused>(a.append(v, LogAction.Role(bob.userId, "reader"))).held)
        assertEquals(HeldKnown.NOT_STORED, assertNotNull(a.heldChange(v)).known)
        server.refuseAppend = 0 to io.silencelen.andvari.core.client.net.ORIGIN_STOPPED
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld())
        assertEquals(2, server.logs.getValue(v).size)
        assertEquals(HeldKnown.NOT_STORED, assertNotNull(a.heldChange(v), "still held").known, "the record stands as it was")
        assertEquals(HeldKnown.NOT_STORED, assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v)).known)
        assertTrue(a.heldFindings().isEmpty(), "known not stored: nothing to say")
    }

    /**
     * The limit of memories per vault lets go of a given-up change after a withdrawal already told and before a withdrawal
     * not told yet: with sixteen untold withdrawals the given-up change goes (its late landing then says nothing "made
     * after all"); with a told one among them, the told one goes and the given-up change is still told when it lands.
     */
    @Test fun theLimitLetsGoOfAGivenUpChangeAfterAToldWithdrawalAndBeforeAnUntoldOne() = runBlocking<Unit> {
        suspend fun run(told: Int): List<HeldFinding> {
            val server = Server()
            val (a, v) = vaultWithBob(server)
            server.dropAppends = 1
            assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
            val givenUp = server.lastFrame()
            now += StoredVaultLogs.GIVE_UP_MS + 1
            assertEquals(listOf<HeldResend>(HeldResend.GivenUp(v)), a.resendHeld())
            repeat(told) {
                now += 1000
                server.dropAppends = 1
                assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
                assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
            }
            repeat(StoredVaultLogs.MAX_WATCHES - told) {
                now += 1000
                server.headMovedAppend = LogHead(9, "ab".repeat(32), 0)
                assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
                assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v))
            }
            server.lateAppend(v, givenUp)
            a.refresh(v, null, null, force = true)
            return a.heldFindings()
        }
        val untoldOnly = run(told = 0)
        assertTrue(untoldOnly.none { it.what == FoundKind.MADE_AFTER_ALL }, "the given-up change went first: $untoldOnly")
        val withTold = run(told = 1)
        assertEquals(LetGo.GIVEN_UP, withTold.single { it.what == FoundKind.MADE_AFTER_ALL }.letGo, "the told withdrawal went first")
    }

    /**
     * The look before a question answers "frozen" where the read it makes finds another entry at the position the
     * server's own answer named the change at, and "unreadable" where this device's records of the vault cannot be read;
     * it sends nothing either way.
     */
    @Test fun theLookAnswersFrozenAndUnreadable() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val (a, v) = vaultWithBob(server, device)
        server.lieAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        val sent = server.appends
        assertEquals(HeldLook.Frozen(v), a.lookHeld(v))
        assertEquals(sent, server.appends, "nothing sent")
        assertTrue(a.heldFindings().isEmpty(), "nothing is said of the change")

        val (b, w) = vaultWithBob(server, device)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, b.append(w, LogAction.Role(bob.userId, "reader")))
        device.set(StoredVaultLogs.recordKey(alice.userId, w, "hashes"), "not json")
        val fetches = server.fetches
        assertEquals(HeldLook.Unreadable(w), b.lookHeld(w))
        assertEquals(fetches, server.fetches, "nothing read")
    }

    /**
     * A first send answered as "the session has ended" (`401`) reads "cannot tell" (the request reached the server, which
     * said nothing of the entry): nothing is said of it, and the next verified read settles it either way. Sent again and
     * stored: stored, with no finding. Withdrawn instead: the read the withdrawal makes says "not made" (not final, since
     * its position is free) and keeps the memory, which a later read that finds it stored turns into "made after all".
     */
    @Test fun aFirstSendAnsweredSessionEndedReadsCannotTellAndTheNextVerifiedReadSettlesIt() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.refuseAppend = 401 to "unauthorized"
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        val held = assertNotNull(a.heldChange(v))
        assertEquals(HeldKnown.CANNOT_TELL, held.known)
        assertTrue(held.withdrawable)
        assertTrue(a.heldFindings().isEmpty(), "${a.heldFindings()}")
        assertIs<HeldResend.Stored>(a.resendHeld().single())
        assertNull(a.heldChange(v))
        assertTrue(a.heldFindings().isEmpty(), "stored: nothing to say")
        assertEquals("reader", assertIs<VaultLogStatus.Verified>(a.status(v)).state.members[bob.userId]?.role)

        now += 1000
        server.refuseAppend = 401 to "unauthorized"
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        val frame = server.lastFrame()
        assertEquals(HeldKnown.CANNOT_TELL, assertIs<HeldWithdrawal.Withdrawn>(a.withdrawAsHeld(v)).known)
        val notMade = a.heldFindings().single()
        assertEquals(FoundKind.NOT_MADE, notMade.what)
        assertFalse(notMade.final, "remembered while its position is free")
        a.findingShown(notMade.id)
        server.lateAppend(v, frame)
        a.refresh(v, null, null, force = true)
        assertEquals(FoundKind.MADE_AFTER_ALL, a.heldFindings().single().what)
    }

    /**
     * With a hostile server: a lying answer names a change of role at its position, its re-send is refused for the
     * entry, and another entry is then served there. A change the server's own answer called stored is never dropped as
     * refused: it stays and is sent as it is, so the contradiction still freezes the vault, with nothing said.
     */
    @Test fun aRefusalNeverDropsAsRefusedAChangeTheServerCalledStored() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.lieAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.refuseAppend = 400 to "bad_frame"
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld())
        assertTrue(a.heldFindings().isEmpty(), "${a.heldFindings()}")
        assertEquals(HeldKnown.STORED_BY_SERVERS_WORD, assertNotNull(a.heldChange(v)).known)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
        a.resendHeld()
        assertIs<VaultLogStatus.Frozen>(a.status(v))
        assertTrue(a.heldFindings().isEmpty())
    }

    /**
     * A change whose outcome cannot be told (a removal stored, its answer lost): a refusal about the session keeps it as it
     * was; a refusal of its re-send for the entry gives it up with that reason, remembered, and never "refused": the next
     * read that verifies the log tells it made after all.
     */
    @Test fun aCannotTellChangeRefusedForTheEntryIsGivenUpWithItsReasonAndSettledByTheNextRead() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        server.refuseAppend = 401 to "unauthorized"
        assertEquals(listOf<HeldResend>(HeldResend.Waiting(v)), a.resendHeld())
        assertEquals(HeldKnown.CANNOT_TELL, assertNotNull(a.heldChange(v)).known)
        assertTrue(a.heldFindings().isEmpty())
        server.refuseAppend = 400 to "bad_frame"
        assertEquals(listOf<HeldResend>(HeldResend.GivenUp(v)), a.resendHeld())
        assertNull(a.heldChange(v))
        val g = a.heldFindings().single()
        assertEquals(FoundKind.GIVEN_UP, g.what)
        assertEquals("bad_frame", g.code)
        assertFalse(g.final)
        a.refresh(v, null, null, force = true)
        assertEquals(LetGo.GIVEN_UP, a.heldFindings().single { it.what == FoundKind.MADE_AFTER_ALL }.letGo)
    }

    /**
     * While a change's first request is out, a sync verifies another entry at its position (kept as
     * "its place was taken"); the server then answers that request naming the change at that position. The vault freezes,
     * and the freeze takes back the finding: nothing is said of the change.
     */
    @Test fun theFreezeTakesBackAPlaceTakenFindingKeptForTheChange() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        other.refresh(v, null, null, force = true)
        server.onAppend = {
            assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Remove(bob.userId)))
            a.refresh(v, null, null, force = true)
            assertNull(a.heldChange(v), "its place was taken")
            server.lieAppends = 1
        }
        assertEquals(AppendOutcome.VaultReadOnly, a.append(v, LogAction.Role(bob.userId, "reader")))
        assertIs<VaultLogStatus.Frozen>(a.status(v))
        assertTrue(a.heldFindings().isEmpty(), "${a.heldFindings()}")
    }

    /** A refusal's code is kept at rest only as a code this client knows, or as "other": it is the server's text. */
    @Test fun aRefusalsCodeIsKeptOnlyAsACodeTheClientKnows() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Role(bob.userId, "reader")))
        server.refuseAppend = 400 to "Visit evil.example to restore your vault"
        a.resendHeld()
        assertEquals(StoredVaultLogs.OTHER_REFUSAL, a.heldFindings().single().code)
    }


    @Test fun aGrantForAnEarlierAddIsNeverAdoptedNorAsked() = runBlocking<Unit> {
        // §3.5 step 6: a grant must be bound to the account's LATEST add. The shared verifiers' VaultGrant.open refuses an
        // earlier add's grant (no_add_entry); the engine's own add-seq comparison is the second line.
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "reader"))
        val oldRow = server.grants.getValue(vaultId to bob.userId)
        now += 1000
        a.append(vaultId, LogAction.Remove(bob.userId))
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "reader"))
        server.grants[vaultId to bob.userId] = oldRow
        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub))
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        assertIs<Adoption.Refused>(b.adoption(vaultId), "the replayed grant of the add at seq 1 neither adopts nor asks")
        assertNull(b.keyFor(vaultId))
        // A record of the person's answer to the earlier add does not let it through either.
        bobState.doc = bobState.doc.copy(accepted = mapOf(vaultId to AcceptedRecord(vaultId, alice.userId, 1, now, AcceptedRecord.ACCEPT)))
        assertIs<Adoption.Refused>(b.adoption(vaultId))
        assertNull(b.keyFor(vaultId))
    }

    @Test fun withheldForkFailedAndPurged() = runBlocking<Unit> {
        val server = Server()
        val aState = SharedState()
        val a = engine(server, alice, aState, mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        now += 1000
        a.append(vaultId, LogAction.Role(bob.userId, "reader"))

        val observer = engine(server, alice, SharedState(), emptyMap())
        assertIs<VaultLogStatus.Verified>(observer.refresh(vaultId, null, null, force = true))
        server.serveOnly = 2
        val w = assertIs<VaultLogStatus.Withheld>(observer.refresh(vaultId, 1, "x", force = true))
        assertEquals(2, w.state.headSeq, "the device keeps its own state")
        assertTrue(!observer.writeAllowed(vaultId))
        server.serveOnly = null

        // Another validly signed entry at seq 2, where the observer verified the role change: a fork.
        val s1 = VaultLog.replay(crypto, vaultId, server.logs.getValue(vaultId).take(2).map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state!!
        val pos = VaultLog.position(s1, now + 5)
        val other = (VaultLog.signChecked(crypto, alice.sign, s1, LogEntry.Remove(vaultId, pos.seq, pos.prev, alice.userId, pos.at, bob.userId)) as Checked.Ok).value
        server.replaceAt = 2 to Bytes.toB64(other.frame)
        assertIs<VaultLogStatus.Frozen>(observer.refresh(vaultId, 2, other.step.hash))
        server.replaceAt = null
        assertIs<VaultLogStatus.Frozen>(observer.refresh(vaultId, null, null, force = true), "frozen is sticky")

        // A broken frame: failed at the last good entry.
        val broken = engine(server, alice, SharedState(), emptyMap())
        val bad = server.logs.getValue(vaultId)[1].let { val f = Bytes.fromB64(it); f[50] = (f[50].toInt() xor 1).toByte(); Bytes.toB64(f) }
        server.replaceAt = 1 to bad
        val failed = assertIs<VaultLogStatus.Failed>(broken.refresh(vaultId, null, null, force = true))
        assertEquals(0, failed.lastGood!!.headSeq)
        server.replaceAt = null

        // The owner deletes; the server purges and serves the tombstone: purged only after a verified delete.
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Delete))
        server.purgedAt = now
        val witness = engine(server, alice, SharedState(), emptyMap())
        assertIs<VaultLogStatus.Purged>(witness.refresh(vaultId, null, null, force = true))
    }

    private fun graceJson(deletedAt: Long, purgeAt: Long) = """{"deletedAt":$deletedAt,"purgeAt":$purgeAt}"""

    @Test fun theServersGraceEndIsKeptBesideTheVerifiedDeleteAndOnlyForIt() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        // Served before any verified delete (a server that lies about the grace): nothing kept.
        server.deletedRaw = graceJson(now, now + 7 * DAY)
        assertIs<VaultLogStatus.Verified>(a.refresh(vaultId, null, null, force = true))
        assertEquals(null, a.serverGraceEnd(vaultId), "no verified delete: the server's word is not kept")

        now += 1000
        val deletedAt = now + 3
        server.deletedRaw = graceJson(deletedAt, deletedAt + 7 * DAY)
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Delete))
        assertEquals(LogDeleted(deletedAt, deletedAt + 7 * DAY), a.serverGraceEnd(vaultId))

        // Another device learns it from the log fetch alone.
        val b = engine(server, alice, SharedState(), emptyMap())
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        assertEquals(LogDeleted(deletedAt, deletedAt + 7 * DAY), b.serverGraceEnd(vaultId))

        // Only for display: a grace end already in the past deletes, closes and blocks nothing on the device.
        server.deletedRaw = graceJson(deletedAt, deletedAt + 1)
        now += 30 * DAY
        val st = assertIs<VaultLogStatus.Verified>(a.refresh(vaultId, null, null, force = true))
        assertEquals(LogDeleted(deletedAt, deletedAt + 1), a.serverGraceEnd(vaultId), "the newest word for the same delete")
        assertTrue(st.state.deletedId != null)
        assertTrue(a.copyOutAllowed(vaultId) && a.keyFor(vaultId) != null, "the key stays")
        server.deletedRaw = null
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Restore), "a restore is still signed and sent")
        assertEquals(null, a.serverGraceEnd(vaultId), "a verified restore drops it")

        // A second delete: the first delete's value is never answered for it.
        now += 1000
        server.deletedOnFetch = false
        server.deletedRaw = graceJson(now, now + 2 * DAY)
        server.appendHead = LogHead(99, "b".repeat(64), 0)
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Delete))
        assertEquals(null, a.serverGraceEnd(vaultId), "an append answer naming another head is not kept")
        assertEquals(LogDeleted(deletedAt, deletedAt + 7 * DAY), b.serverGraceEnd(vaultId), "b has not verified the restore yet")
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        assertEquals(null, b.serverGraceEnd(vaultId), "b verified the restore and the new delete; the old value is gone")
    }

    @Test fun theAppendAnswerAloneCarriesTheGraceEnd() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), emptyMap())
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        server.deletedOnFetch = false
        server.deletedRaw = graceJson(now, now + 7 * DAY)
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Delete))
        assertEquals(LogDeleted(now - 1000, now - 1000 + 7 * DAY), a.serverGraceEnd(vaultId))
    }

    @Test fun anOlderServerOrAMalformedGraceEndKeepsNothingAndTheLogStillVerifies() = runBlocking<Unit> {
        for (raw in listOf(null, graceJson(2000, 1999), """{"deletedAt":"1","purgeAt":"2"}""", """{"deletedAt":1.5,"purgeAt":2}""", "[]", "null")) {
            val server = Server()
            val a = engine(server, alice, SharedState(), emptyMap())
            val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
            server.deletedRaw = raw
            now += 1000
            assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Delete), "$raw")
            assertEquals(null, a.serverGraceEnd(vaultId), "$raw")
            val b = engine(server, alice, SharedState(), emptyMap())
            val st = assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true), "$raw")
            assertTrue(st.state.deletedId != null, "$raw")
            assertEquals(null, b.serverGraceEnd(vaultId), "$raw")
        }
    }

    /** Alice's vault with bob added (and, with [accept], adopted by bob): alice's engine, bob's, the vault id. */
    private suspend fun sharedWithBob(server: Server, accept: Boolean): Triple<StoredVaultLogs, StoredVaultLogs, String> {
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Add(bob.userId, "writer")))
        val b = engine(server, bob, SharedState(), mapOf(alice.userId to alice.pub))
        b.refresh(vaultId, null, null, force = true)
        if (accept) assertIs<Adoption.Adopted>(b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(vaultId)), accept = true))
        return Triple(a, b, vaultId)
    }

    @Test fun aMemberTheServerNoLongerListsIsNoGrantAsTheServerSaysAndNothingElse() = runBlocking<Unit> {
        val server = Server()
        val (a, _, vaultId) = sharedWithBob(server, accept = false)
        val honest = assertIs<ServerGrants.Read>(a.serverGrants(vaultId))
        assertEquals(ServerGrant.LISTED, honest.of(bob.userId))
        assertEquals(ServerGrant.LISTED, honest.of(alice.userId))
        assertEquals(ServerGrant.UNKNOWN, honest.of("33333333-3333-4333-8333-333333333333"), "not a verified member")

        // The operator deletes bob's account: the server stops listing him; the verified log still names him.
        server.unlisted = setOf(bob.userId)
        val g = assertIs<ServerGrants.Read>(a.serverGrants(vaultId))
        assertEquals(ServerGrant.NO_GRANT_AS_SERVER_SAYS, g.of(bob.userId))
        assertEquals(setOf(bob.userId), g.noGrant)
        assertEquals(ServerGrant.LISTED, g.of(alice.userId))
        assertEquals(server.logs.getValue(vaultId).size - 1L, g.headSeq)
        // Nothing else changes: bob is a member for every signature and key decision until the log says otherwise.
        val st = assertIs<VaultLogStatus.Verified>(a.status(vaultId))
        assertTrue(bob.userId in st.state.members)
        assertTrue(a.writeAllowed(vaultId))
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Role(bob.userId, "reader")), "a role change for him is still signed")
        // A verified remove ends it: he is no longer a member at all.
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Remove(bob.userId)))
        val after = assertIs<ServerGrants.Read>(a.serverGrants(vaultId))
        assertEquals(ServerGrant.UNKNOWN, after.of(bob.userId))
        assertEquals(emptySet(), after.noGrant)
    }

    @Test fun aServerThatDropsALiveMemberFromItsListChangesNothingButTheLabel() = runBlocking<Unit> {
        val server = Server()
        val (a, b, vaultId) = sharedWithBob(server, accept = true)
        assertTrue(b.writeAllowed(vaultId), "bob is live: adopted and writing")
        // A hostile server leaves bob out of the list it shows alice. The app can be made to say so; that is all.
        server.unlisted = setOf(bob.userId)
        assertEquals(ServerGrant.NO_GRANT_AS_SERVER_SAYS, a.serverGrants(vaultId).of(bob.userId))
        // And leaves alice, the owner, out of the list it shows bob.
        assertEquals(ServerGrant.LISTED, b.serverGrants(vaultId).of(alice.userId))
        server.unlisted = setOf(alice.userId)
        assertEquals(ServerGrant.NO_GRANT_AS_SERVER_SAYS, b.serverGrants(vaultId).of(alice.userId))
        assertTrue(b.writeAllowed(vaultId) && b.keyFor(vaultId) != null, "bob keeps his key and his writes")
        assertTrue(a.writeAllowed(vaultId) && a.keyFor(vaultId) != null)
        val stB = assertIs<VaultLogStatus.Verified>(b.status(vaultId))
        assertEquals(setOf(alice.userId, bob.userId), stB.state.members.keys)
        assertEquals(alice.userId, stB.state.owner, "the owner stays the owner")
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Offer(bob.userId, DAY)), "an offer to the unlisted member is still signed")
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        assertIs<Adoption.Adopted>(b.adoption(vaultId), "his key decision is the log's, not the list's")
        assertEquals(bob.userId, assertIs<VaultLogStatus.Verified>(b.status(vaultId)).state.pending?.to, "and the offer to him stands")
    }

    @Test fun aListThatCannotBeReadOrHeldAgainstTheVerifiedHeadIsUnknownNeverNoGrant() = runBlocking<Unit> {
        val server = Server()
        val (a, _, vaultId) = sharedWithBob(server, accept = false)
        server.unlisted = setOf(bob.userId)
        fun unknown(g: ServerGrants, reason: String) {
            assertEquals(reason, assertIs<ServerGrants.Unknown>(g).reason)
            assertEquals(ServerGrant.UNKNOWN, g.of(bob.userId))
        }
        // The list does not come: no answer, a refusal, a body that is not a member list.
        for (answer in listOf<WireResult<String>>(WireResult.NoAnswer(NoAnswerKind.TRANSPORT), WireResult.Refused(403, WireError("no_grant", "m")),
            WireResult.Ok("""{"members":[]}""", 200), WireResult.Ok("""[{"userId":1}]""", 200))) {
            server.membersAnswer = answer
            unknown(a.serverGrants(vaultId), ServerGrants.LIST_UNREADABLE)
        }
        server.membersAnswer = null

        // The log is withheld, or the server names a head it does not serve: the list is not even read.
        val reads = server.memberReads
        server.serveOnly = 1
        unknown(a.serverGrants(vaultId), ServerGrants.LOG_NOT_VERIFIED)
        server.serveOnly = null
        server.claimHead = LogHead(9, "c".repeat(64), 0)
        unknown(a.serverGrants(vaultId), ServerGrants.LOG_NOT_VERIFIED)
        server.claimHead = null
        server.down = true
        unknown(a.serverGrants(vaultId), ServerGrants.LOG_NOT_VERIFIED)
        server.down = false
        assertEquals(reads, server.memberReads)

        // The head moves while the list is read: the list may predate the new entry.
        val s = VaultLog.replay(crypto, vaultId, server.logs.getValue(vaultId).map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state!!
        val pos = VaultLog.position(s, now + 5)
        val role = (VaultLog.signChecked(crypto, alice.sign, s, LogEntry.Role(vaultId, pos.seq, pos.prev, alice.userId, pos.at, bob.userId, io.silencelen.andvari.core.trust.MemberRole.READER)) as Checked.Ok).value
        server.onMembers = { server.logs.getValue(vaultId) += Bytes.toB64(role.frame); server.onMembers = null }
        unknown(a.serverGrants(vaultId), ServerGrants.LOG_MOVED)
        assertIs<ServerGrants.Read>(a.serverGrants(vaultId), "the next read holds")

        // A deleted vault's list says nothing about accounts.
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Delete))
        unknown(a.serverGrants(vaultId), ServerGrants.VAULT_DELETED)
    }

    @Test fun itemHeadsAreHintsNeverVerdicts() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        val observer = engine(server, alice, SharedState(), emptyMap())
        observer.refresh(vaultId, null, null, force = true)
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        val h1 = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.logs.getValue(vaultId)[1])))
        // An item names a head this device has not seen: it fetches, and the hint resolves.
        val v = assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 1, h1))
        assertEquals(1, v.state.headSeq)
        assertTrue(!v.itemHintUnresolved)
        // An item names history the server does not show: noted, the member list "may be incomplete", nothing frozen.
        val u = assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 7, "c".repeat(64)))
        assertTrue(u.itemHintUnresolved)
        // An item names another hash at a verified position: still only a hint (FS-R4), never a fork on its own.
        val w = assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 1, "d".repeat(64)))
        assertTrue(w.itemHintUnresolved)
        assertTrue(observer.copyOutAllowed(vaultId) || observer.keyFor(vaultId) == null)
    }

    @Test fun anUnresolvedItemHeadIsChasedOnceThenBacksOff() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        val observer = engine(server, alice, SharedState(), emptyMap())
        assertIs<VaultLogStatus.Verified>(observer.refresh(vaultId, null, null, force = true))
        server.fetches = 0
        // A writer puts a head the server never shows on an item: chased once, unresolved.
        assertTrue(assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 50, "c".repeat(64))).itemHintUnresolved)
        val once = server.fetches
        assertTrue(once >= 1)
        // Every later item read, at that seq or any other, is not chased again while the verified head stays put.
        for (i in 0 until 20) {
            assertTrue(assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 50L + i, "c".repeat(64))).itemHintUnresolved, "still may be incomplete")
        }
        assertTrue(assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 0, "d".repeat(64))).itemHintUnresolved)
        assertEquals(once, server.fetches, "no refetch while backed off")
        // After the back-off a hint is chased again.
        now += StoredVaultLogs.HINT_BACKOFF_MS
        assertTrue(assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 90, "c".repeat(64))).itemHintUnresolved)
        assertTrue(server.fetches > once)
        // A head this device then verifies moves past the chase: a real hint resolves at once.
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        val h1 = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.logs.getValue(vaultId)[1])))
        val chased = server.fetches
        val r = assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 1, h1))
        assertEquals(chased, server.fetches, "still within the back-off at the same verified head")
        assertTrue(r.itemHintUnresolved)
        assertIs<VaultLogStatus.Verified>(observer.refresh(vaultId, 1, h1, force = false))
        assertTrue(assertIs<VaultLogStatus.Verified>(observer.noteItemHead(vaultId, 2, "e".repeat(64))).itemHintUnresolved)
        assertTrue(server.fetches > chased + 1, "a moved verified head lifts the back-off")
    }

    @Test fun aGrantRowThatIsNotBase64IsARefusedGrantNotAnException() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Add(bob.userId, "writer")))
        server.grants[vaultId to bob.userId] = server.grants.getValue(vaultId to bob.userId).copy(signedGrant = "not base64 *!")
        val b = engine(server, bob, SharedState(), mapOf(alice.userId to alice.pub))
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        assertEquals(Adoption.Refused(vaultId, AdoptionRefusal.GRANT_REFUSED), b.adoption(vaultId))
        assertNull(b.keyFor(vaultId))
    }

    @Test fun replayingAnOldRemoveNeverRollsBackTheAnswerToALaterAdd() = runBlocking<Unit> {
        // §5.4: the higher addSeq wins. Bob is added (1), removed (2), re-added (3) and accepts at 3.
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        now += 1000
        a.append(vaultId, LogAction.Remove(bob.userId))
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub))
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        val ask = assertIs<Adoption.AskAccept>(b.adoption(vaultId))
        assertEquals(3, ask.addSeq)
        assertEquals(Adoption.Adopted(vaultId, KeySource.GRANT), b.answerIncoming(ask, accept = true))
        val accepted = bobState.doc.accepted.getValue(vaultId)
        assertEquals(AcceptedRecord.ACCEPT, accepted.decision)
        assertEquals(3, accepted.addSeq)
        // A newly linked device replays from the genesis and passes the remove at seq 2: the answer to add 3 stays.
        now += 1000
        val b2 = engine(server, bob, bobState, emptyMap())
        assertIs<VaultLogStatus.Verified>(b2.refresh(vaultId, null, null, force = true))
        assertEquals(accepted, bobState.doc.accepted.getValue(vaultId), "a replayed remove of add 1 never rolls back the answer to add 3")
        assertEquals(Adoption.Adopted(vaultId, KeySource.SELF_WRAP), b2.adoption(vaultId))
        // A verified leave of the CURRENT add still declines it (same addSeq: decline wins).
        now += 1000
        assertIs<AppendOutcome.Appended>(b.append(vaultId, LogAction.Leave))
        val left = bobState.doc.accepted.getValue(vaultId)
        assertEquals(AcceptedRecord.DECLINE, left.decision)
        assertEquals(3, left.addSeq)
    }

    @Test fun oneFetchThatRemovesAndReAddsThisAccountDeclinesOnlyTheEarlierAdd() = runBlocking<Unit> {
        // The log is verified in one replay; the remove's decline still takes the state right after the remove (add 1),
        // never the state at the end of the fetch (add 3), which would decline the add the person has not answered.
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        now += 1000
        a.append(vaultId, LogAction.Remove(bob.userId))
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        now += 1000
        a.append(vaultId, LogAction.Role(bob.userId, "reader"))
        val bobState = SharedState()
        val device = MemoryDeviceState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), device)
        assertEquals(4, assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true)).state.headSeq)
        val declined = bobState.doc.accepted.getValue(vaultId)
        assertEquals(AcceptedRecord.DECLINE, declined.decision)
        assertEquals(1, declined.addSeq)
        assertEquals(3, assertIs<Adoption.AskAccept>(b.adoption(vaultId)).addSeq, "the later add is still asked")
        // Every position the replay verified is held: a checkpoint naming another entry at any of them is a fork.
        val log = server.logs.getValue(vaultId)
        for (seq in 0..4) {
            val real = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log[seq])))
            assertIs<VaultLogStatus.Verified>(engine(server, bob, SharedState(), emptyMap(), device, mapOf(vaultId to Checkpoint(seq.toLong(), real)))
                .refresh(vaultId, null, null, force = true), "seq $seq")
            assertIs<VaultLogStatus.Frozen>(engine(server, bob, SharedState(), emptyMap(), device, mapOf(vaultId to Checkpoint(seq.toLong(), "a".repeat(64))))
                .refresh(vaultId, null, null, force = true), "seq $seq")
            device.set("ovh.log|${bob.userId}|$vaultId|flag", null)
        }
    }

    @Test fun theStoredHeadIsReadFromTheRecordTheEngineWrites() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub), device)
        val created = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state
        now += 1000
        val added = assertIs<AppendOutcome.Appended>(a.append(created.vaultId, LogAction.Add(bob.userId, "writer"))).state
        assertEquals(Checkpoint(added.headSeq, added.headHash), StoredVaultLogs.storedHead(device, alice.userId, created.vaultId, created.genesisHash))
        assertNull(StoredVaultLogs.storedHead(device, bob.userId, created.vaultId, created.genesisHash), "another account's records are not this one's")
        assertNull(StoredVaultLogs.storedHead(device, alice.userId, created.vaultId, "b".repeat(64)), "another log")
    }

    @Test fun pendingIsRepostedByteForByte() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.down = true
        assertEquals(AppendOutcome.Pending, a.append(vaultId, LogAction.Add(bob.userId, "writer")))
        server.down = false
        now += 60_000
        a.retryPending()
        assertEquals(2, server.logs.getValue(vaultId).size)
        val add = VaultLog.parse(crypto, Bytes.fromB64(server.logs.getValue(vaultId)[1])).valueOrNull()!!.entry
        assertEquals(now - 60_000, add.at, "the stored frame is the one signed before the outage, never re-signed")
        assertNotNull(a.keyFor(vaultId))
    }

    /**
     * The signed grant frame (the vault key in the clear) is zeroed once sealed, and the copy of
     * a granted vault key held across the self-wrap post is zeroed when a lock cancels that post.
     */
    @Test fun theGrantFrameAndAKeyCopyACancelledPostHeldAreZeroed() = runBlocking<Unit> {
        val server = Server()
        val frames = ArrayList<ByteArray>()
        val wraps = ArrayList<ByteArray>()
        val spy = object : io.silencelen.andvari.core.crypto.CryptoProvider by crypto {
            override fun sealTo(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray =
                crypto.sealTo(recipientPublicKey, plaintext).also { frames += plaintext }
            override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray =
                crypto.aeadEncrypt(key, nonce, plaintext, ad).also { if (plaintext.size == 32) wraps += plaintext }
        }
        fun spied(p: Person, contacts: Map<String, String>, state: SharedState) =
            StoredVaultLogs(p.userId, p.sign, p.box, p.uvk, server.client(p.userId), spy, MemoryDeviceState(), state, Host(server, p, contacts), { now }, { null })
        val a = spied(alice, mapOf(bob.userId to bob.pub), SharedState())
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Add(bob.userId, "writer")))
        assertTrue(frames.isNotEmpty() && frames.all { f -> f.all { it == 0.toByte() } }, "the signed grant frame is zeroed once sealed")

        val b = spied(bob, mapOf(alice.userId to alice.pub), SharedState())
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        val ask = assertIs<Adoption.AskAccept>(b.adoption(vaultId))
        server.onSelfWrap = { throw kotlinx.coroutines.CancellationException("the lock cancelled the job") }
        wraps.clear()
        runCatching { b.answerIncoming(ask, accept = true) }
        assertTrue(wraps.isNotEmpty(), "the self-wrap was sealed before its post")
        assertTrue(wraps.all { w -> w.all { it == 0.toByte() } }, "the key copy held across the cancelled post is zeroed")
    }

    /**
     * A lock during create's account-state write (a wait between the genesis' signature and its post) sends no genesis:
     * the check in `post`. With that check dropped, no other test of the suite failed; this one does.
     */
    @Test fun aLockDuringCreatesAccountStateWriteSendsNoGenesis() = runBlocking<Unit> {
        val server = Server()
        val guard = io.silencelen.andvari.core.client.onboard.KeyGuard()
        val state = object : AccountStateStore {
            var doc = AccountDocument.EMPTY
            override fun local() = doc
            override suspend fun read(): AccountStateRead = AccountStateRead.Ok(doc, emptyList())
            override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite {
                guard.wipe() // the vault locks while the account's state is written
                doc = change(doc).copy(seq = doc.seq + 1)
                return AccountStateWrite.Written(doc)
            }
        }
        val a = StoredVaultLogs(
            alice.userId,
            io.silencelen.andvari.core.client.onboard.GuardedKeyPair(io.silencelen.andvari.core.crypto.KeyPairBytes(alice.sign.publicKey, alice.sign.privateKey.copyOf()), guard),
            io.silencelen.andvari.core.client.onboard.GuardedKeyPair(io.silencelen.andvari.core.crypto.KeyPairBytes(alice.box.publicKey, alice.box.privateKey.copyOf()), guard),
            io.silencelen.andvari.core.client.onboard.GuardedKey(alice.uvk.copyOf(), guard),
            server.client(alice.userId), crypto, MemoryDeviceState(), state, Host(server, alice, emptyMap()), { now }, { null },
        )
        val outcome = runCatching { a.append(null, LogAction.Create("Family")) }
        assertTrue(guard.isWiped)
        assertTrue(server.logs.values.all { it.isEmpty() }, "no genesis reached the server after the lock: $outcome")
    }

    /**
     * Escape 5: where the test machinery is on, the vault-key lend refuses a block that
     * answers the key or its text. Where it is not (core's Android unit tests and the iPhone's, which carry no tripwire,
     * as a shipped build carries none), the lend hands back what the block answered.
     */
    @Test fun aVaultKeyLendThatAnswersTheKeyIsRefused() = runBlocking<Unit> {
        val a = engine(Server(), alice, SharedState(), emptyMap())
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        if (io.silencelen.andvari.core.client.onboard.KeyEscape.checking) {
            kotlin.test.assertFailsWith<io.silencelen.andvari.core.client.onboard.KeyEscapeException> { a.withKey(vaultId) { it.copyOf() } }
            kotlin.test.assertFailsWith<io.silencelen.andvari.core.client.onboard.KeyEscapeException> { a.withKey(vaultId) { it } }
            kotlin.test.assertFailsWith<io.silencelen.andvari.core.client.onboard.KeyEscapeException> { a.withKey(vaultId) { Bytes.toB64(it) } }
        } else {
            val copy = assertNotNull(a.withKey(vaultId) { it.copyOf() })
            assertEquals(Bytes.toB64(copy), a.withKey(vaultId) { Bytes.toB64(it) }, "unchecked, the lend answers what the block answered")
            copy.fill(0)
        }
        assertEquals(32, a.withKey(vaultId) { it.size }, "what is built from the key leaves")
    }

    /** A write that fails between the hold's seal and its map entry leaves no key unzeroed. */
    @Test fun aHoldWhoseWriteFailsZeroesTheVaultKey() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        val disk = MemoryDeviceState()
        var full = false
        val device = object : io.silencelen.andvari.core.client.DeviceState by disk {
            override fun set(key: String, value: String?) {
                if (full && key.endsWith("|held")) throw IllegalStateException("the disk is full")
                disk.set(key, value)
            }
        }
        val b = StoredVaultLogs(bob.userId, bob.sign, bob.box, bob.uvk, server.client(bob.userId), crypto, device, SharedState(),
            Host(server, bob, mapOf(alice.userId to alice.pub)), { now }, { null })
        b.refresh(vaultId, null, null, force = true)
        b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(vaultId)), accept = true)
        // The engine's own array (not a copy), in a holder of the test's making.
        val theKey = assertNotNull(b.withKey(vaultId) { io.silencelen.andvari.core.client.items.KeyCopy(it) }).bytes
        assertTrue(theKey.any { it != 0.toByte() })
        now += 1000
        a.append(vaultId, LogAction.Remove(bob.userId))
        full = true
        runCatching { b.refresh(vaultId, null, null, force = true) }
        assertTrue(theKey.all { it == 0.toByte() }, "the key the hold could not keep is zeroed")
        assertNull(b.withKey(vaultId) { it.size }, "and nothing offers it")
    }

    @Test fun aRemovedVaultsKeyIsOfferedForCopyOutUntilTheHoldingPeriodEnds() = runBlocking<Unit> {
        // Spec 02 §10.6: after a verified remove the vault's data is in the holding area for 30 days, copyable out.
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        val bobDevice = MemoryDeviceState()
        val bobState = SharedState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), bobDevice)
        b.refresh(vaultId, null, null, force = true)
        b.answerIncoming(assertIs<Adoption.AskAccept>(b.adoption(vaultId)), accept = true)
        val vk = b.keyFor(vaultId)!!
        now += 1000
        a.append(vaultId, LogAction.Remove(bob.userId))
        assertIs<VaultLogStatus.Removed>(b.refresh(vaultId, null, null, force = true))
        assertContentEquals(vk, b.keyFor(vaultId), "the committed key is still offered for copy-out")
        assertTrue(b.copyOutAllowed(vaultId))
        assertTrue(!b.writeAllowed(vaultId), "never for a write")

        // A new session on the same device (nothing in memory) still offers it, from the record sealed under the UVK.
        val restarted = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), bobDevice)
        assertContentEquals(vk, restarted.keyFor(vaultId))
        // A record that does not open under this account's UVK offers nothing.
        val stranger = StoredVaultLogs(bob.userId, bob.sign, bob.box, ByteArray(32) { 9 }, server.client(bob.userId), crypto, bobDevice, bobState,
            Host(server, bob, emptyMap()), { now }, { null })
        assertNull(stranger.keyFor(vaultId))

        // When the holding period ends the key is gone, in memory and on disk.
        now += StoredVaultLogs.HOLDING_MS
        assertNull(b.keyFor(vaultId))
        assertTrue(!b.copyOutAllowed(vaultId))
        assertNull(restarted.keyFor(vaultId))
        assertTrue(bobDevice.keys().none { it.endsWith("|held") }, "the held record is wiped")
    }

    @Test fun aColdStartOfflineReopensWhatThisDeviceAdoptedAndSendsNothing() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val aState = SharedState()
        val a = engine(server, alice, aState, mapOf(bob.userId to bob.pub), device)
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        val vk = a.keyFor(vaultId)!!
        val before = aState.doc
        val silent = object : WireClient {
            override val origin = "https://h.example"
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                error("nothing may be sent: $route")
        }
        val cold = StoredVaultLogs(alice.userId, alice.sign, alice.box, alice.uvk, silent, crypto, device, aState,
            Host(server, alice, mapOf(bob.userId to bob.pub)), { now }, { null })
        assertNull(cold.keyFor(vaultId))
        assertIs<Adoption.Adopted>(cold.reopenAdopted(vaultId))
        assertContentEquals(vk, cold.keyFor(vaultId))
        assertEquals(before, aState.doc, "nothing written to the account state")
        // A vault this device never verified, or one with no cached wrap, reopens nothing.
        assertEquals(Adoption.Refused("33333333-3333-4333-8333-333333333333", AdoptionRefusal.LOG_NOT_VERIFIED), cold.reopenAdopted("33333333-3333-4333-8333-333333333333"))
        server.grants.remove(vaultId to alice.userId)
        val noRow = StoredVaultLogs(alice.userId, alice.sign, alice.box, alice.uvk, silent, crypto, device, aState,
            Host(server, alice, emptyMap()), { now }, { null })
        assertEquals(Adoption.Refused(vaultId, AdoptionRefusal.NO_KEY), noRow.reopenAdopted(vaultId))
    }

    /** The owner's vault "Family" with Bob added (seq 1) and made a reader (seq 2): its id, and the hash of each entry. */
    private suspend fun threeEntries(server: Server): Pair<String, List<String>> {
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Add(bob.userId, "writer")))
        now += 1000
        assertIs<AppendOutcome.Appended>(a.append(vaultId, LogAction.Role(bob.userId, "reader")))
        return vaultId to server.logs.getValue(vaultId).map { Bytes.toHexLower(crypto.sha256(Bytes.fromB64(it))) }
    }

    private fun recordOf(state: SharedState, vaultId: String, genesis: String, seq: Long, hash: String) {
        state.doc = state.doc.copy(vaults = state.doc.vaults + (vaultId to io.silencelen.andvari.core.client.state.VaultRecord(vaultId, genesis, seq, hash)))
    }

    private val silentClient = object : WireClient {
        override val origin = "https://h.example"
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            error("nothing may be sent: $route")
    }

    /**
     * Design §3.6 (e) as decided on 23 November 2026, at rest: a vault whose key this device took read-only (the account's
     * record ahead of a withheld log, or beside a log frozen after its first entry) reopens at a cold start offline with
     * its key held, still withheld or frozen, and still not writable.
     */
    @Test fun aColdStartOfflineReopensAVaultTakenReadOnlyAndItStaysReadOnly() = runBlocking<Unit> {
        val server = Server()
        val (vaultId, h) = threeEntries(server)
        val aState = SharedState()
        recordOf(aState, vaultId, h[0], 2, h[2])

        // Withheld: the server serves the log only to seq 1, below the account's record.
        server.serveOnly = 2
        val device = MemoryDeviceState()
        val d = engine(server, alice, aState, emptyMap(), device)
        assertIs<VaultLogStatus.Withheld>(d.refresh(vaultId, null, null, force = true))
        assertEquals(Adoption.Adopted(vaultId, KeySource.OWNER_WRAP), d.adoption(vaultId), "the key is taken read-only")
        assertFalse(d.writeAllowed(vaultId))
        val cold = StoredVaultLogs(alice.userId, alice.sign, alice.box, alice.uvk, silentClient, crypto, device, aState,
            Host(server, alice, emptyMap()), { now }, { null })
        assertNull(cold.keyFor(vaultId))
        assertEquals(Adoption.Adopted(vaultId, KeySource.OWNER_WRAP), cold.reopenAdopted(vaultId), "a cold start reopens the withheld vault read-only")
        assertContentEquals(d.keyFor(vaultId), cold.keyFor(vaultId), "its key is held")
        assertIs<VaultLogStatus.Withheld>(cold.status(vaultId))
        assertFalse(cold.writeAllowed(vaultId), "the withheld vault is not writable after the cold start")
        server.serveOnly = null

        // Frozen after the first entry: the server serves another validly signed entry at seq 2, where the record names
        // the lost one.
        val s1 = VaultLog.replay(crypto, vaultId, server.logs.getValue(vaultId).take(2).map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state!!
        val pos = VaultLog.position(s1, now + 5)
        val other = (VaultLog.signChecked(crypto, alice.sign, s1, LogEntry.Remove(vaultId, pos.seq, pos.prev, alice.userId, pos.at, bob.userId)) as Checked.Ok).value
        server.replaceAt = 2 to Bytes.toB64(other.frame)
        val device2 = MemoryDeviceState()
        val f = engine(server, alice, aState, emptyMap(), device2)
        assertEquals(2L, assertIs<VaultLogStatus.Frozen>(f.refresh(vaultId, null, null, force = true)).seq)
        assertEquals(Adoption.Adopted(vaultId, KeySource.OWNER_WRAP), f.adoption(vaultId), "the key is taken read-only")
        assertFalse(f.writeAllowed(vaultId))
        val coldFrozen = StoredVaultLogs(alice.userId, alice.sign, alice.box, alice.uvk, silentClient, crypto, device2, aState,
            Host(server, alice, emptyMap()), { now }, { null })
        assertNull(coldFrozen.keyFor(vaultId))
        assertEquals(Adoption.Adopted(vaultId, KeySource.OWNER_WRAP), coldFrozen.reopenAdopted(vaultId), "a cold start reopens the frozen vault read-only")
        assertContentEquals(f.keyFor(vaultId), coldFrozen.keyFor(vaultId), "its key is held")
        assertIs<VaultLogStatus.Frozen>(coldFrozen.status(vaultId))
        assertFalse(coldFrozen.writeAllowed(vaultId), "the frozen vault is not writable after the cold start")
    }

    /**
     * The engine's refusal names how the account's record failed (design §3.6 (e)), once for each way: a record ahead of
     * the served chain ([AdoptionRefusal.RECORD_AHEAD]), one beside the verified chain ([AdoptionRefusal.RECORD_FORK]),
     * also while the log is withheld, where no key is taken; and one of another beginning
     * ([AdoptionRefusal.RECORD_GENESIS_MISMATCH]). In each, every other condition holds.
     */
    @Test fun theEnginesRefusalSaysHowTheAccountsRecordFailed() = runBlocking<Unit> {
        val server = Server()
        val (vaultId, h) = threeEntries(server)

        // Ahead: this device verified the log to seq 1; the account's record moved to seq 2 before its next fetch.
        server.serveOnly = 2
        val aheadState = SharedState()
        val ahead = engine(server, alice, aheadState, emptyMap())
        assertIs<VaultLogStatus.Verified>(ahead.refresh(vaultId, null, null, force = true))
        recordOf(aheadState, vaultId, h[0], 2, h[2])
        assertEquals(Adoption.Refused(vaultId, AdoptionRefusal.RECORD_AHEAD), ahead.adoption(vaultId))
        assertNull(ahead.keyFor(vaultId))
        server.serveOnly = null

        // Beside: this device verified the whole log; the account's record names another hash at seq 1.
        val besideState = SharedState()
        val beside = engine(server, alice, besideState, emptyMap())
        assertIs<VaultLogStatus.Verified>(beside.refresh(vaultId, null, null, force = true))
        recordOf(besideState, vaultId, h[0], 1, "ab".repeat(32))
        assertEquals(Adoption.Refused(vaultId, AdoptionRefusal.RECORD_FORK), beside.adoption(vaultId))
        assertNull(beside.keyFor(vaultId))
        // The same record while the log is withheld (served only to seq 1): still refused, and no key, for the record
        // stands beside the chain, not ahead of it.
        server.serveOnly = 2
        assertIs<VaultLogStatus.Withheld>(beside.refresh(vaultId, null, null, force = true))
        assertEquals(Adoption.Refused(vaultId, AdoptionRefusal.RECORD_FORK), beside.adoption(vaultId))
        assertNull(beside.keyFor(vaultId))
        assertFalse(beside.writeAllowed(vaultId))
        server.serveOnly = null

        // Another beginning: the account's record names another genesis.
        val otherState = SharedState()
        val another = engine(server, alice, otherState, emptyMap())
        assertIs<VaultLogStatus.Verified>(another.refresh(vaultId, null, null, force = true))
        recordOf(otherState, vaultId, "cd".repeat(32), 2, h[2])
        assertEquals(Adoption.Refused(vaultId, AdoptionRefusal.RECORD_GENESIS_MISMATCH), another.adoption(vaultId))
        assertNull(another.keyFor(vaultId))
    }

    private val carol = Person(crypto, "55555555-5555-4555-8555-555555555555", 7)

    /** `H(frame)` of the frame at [seq] of [vaultId]'s stored log. */
    private fun hashAt(server: Server, vaultId: String, seq: Int): String =
        Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.logs.getValue(vaultId)[seq])))

    /** A device of the owner's that verified a vault past an honest restore of the server, and the server after it. */
    private class PastTheHead(val vaultId: String, val device: MemoryDeviceState, val account: SharedState, val d: StoredVaultLogs, val lost: List<String>, val departing: List<String>)

    /**
     * The owner's vault "Family" (Bob added at seq 1, made a reader at seq 2), verified to seq 2 by a device of hers that
     * holds the key and the account's record at seq 2. The server's log is then put back to seq 1, and another device of
     * hers adds Carol there (seq 2) and makes Bob a reader again (seq 3): the restored chain departs at seq 2 and ends
     * above the head the device verified. [PastTheHead.lost] are the frames the device verified, [PastTheHead.departing]
     * the frames the server serves now. [beforeRestore] runs on the device's engine just before the server is put back.
     */
    private suspend fun pastTheHead(server: Server, beforeRestore: suspend (StoredVaultLogs, String) -> Unit = { _, _ -> }): PastTheHead {
        val owner = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(owner.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(vaultId, LogAction.Add(bob.userId, "writer")))
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(vaultId, LogAction.Role(bob.userId, "reader")))
        val device = MemoryDeviceState()
        val aState = SharedState()
        val d = engine(server, alice, aState, emptyMap(), device)
        assertEquals(2, assertIs<VaultLogStatus.Verified>(d.refresh(vaultId, null, null, force = true)).state.headSeq)
        assertEquals(Adoption.Adopted(vaultId, KeySource.OWNER_WRAP), d.adoption(vaultId))
        assertEquals(2L, aState.doc.vaults.getValue(vaultId).seq, "the device's account records the head it verified")
        beforeRestore(d, vaultId)
        val lost = server.logs.getValue(vaultId).toList()

        server.logs[vaultId] = lost.take(2).toMutableList()
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub, carol.userId to carol.pub))
        assertEquals(1, assertIs<VaultLogStatus.Verified>(other.refresh(vaultId, null, null, force = true)).state.headSeq)
        assertIs<Adoption.Adopted>(other.adoption(vaultId))
        now += 1000
        assertIs<AppendOutcome.Appended>(other.append(vaultId, LogAction.Add(carol.userId, "writer")))
        now += 1000
        assertIs<AppendOutcome.Appended>(other.append(vaultId, LogAction.Role(bob.userId, "writer")))
        return PastTheHead(vaultId, device, aState, d, lost, server.logs.getValue(vaultId).toList())
    }

    /** [frame] with a byte of its signature (bytes 37 to 100) changed: it still parses, and its signature no longer verifies. */
    private fun forged(frame: String): String = Bytes.fromB64(frame).let { f -> f[40] = (f[40].toInt() xor 1).toByte(); Bytes.toB64(f) }

    /**
     * Design §3.9 as decided on 23 November 2026: a served chain that departs from what this device verified at or before
     * its head, and ends above it, is a fork. The first entry served after the head does not chain onto it, so the log is
     * read again from its beginning against every hash this device holds: the restored entry at the place where the chains
     * part is validly signed, so the vault freezes there, its state stands at the entry before that place (the roster this
     * device verified itself; Carol, added on the departing chain, is not in it), and the key is taken read-only, also at a
     * cold start offline. Before, the log read as failed (`bad_prev`) and no key was taken.
     */
    @Test fun aChainThatDepartsAtOrBeforeTheVerifiedHeadAndGrowsPastItFreezesWhereItDeparts() = runBlocking<Unit> {
        val server = Server()
        val p = pastTheHead(server)
        val v = p.vaultId
        val f = assertIs<VaultLogStatus.Frozen>(p.d.refresh(v, 3, hashAt(server, v, 3)), "the vault's standing: ${p.d.status(v)}")
        assertEquals(2L, f.seq, "frozen where the served chain departs")
        assertEquals(1L, f.state.headSeq, "the state stands at the entry before that place")
        assertEquals(Bytes.toHexLower(crypto.sha256(Bytes.fromB64(p.lost[1]))), f.state.headHash)
        assertEquals(setOf(alice.userId, bob.userId), f.state.members.keys, "the roster this device verified; the departing add is not applied")
        assertEquals("writer", f.state.members.getValue(bob.userId).role, "Bob's role at seq 1")
        assertFalse(p.d.writeAllowed(v), "not writable")
        assertEquals(AppendOutcome.VaultReadOnly, p.d.append(v, LogAction.Role(bob.userId, "reader")), "a change of the log is refused")
        assertIs<VaultLogStatus.Frozen>(p.d.refresh(v, null, null, force = true), "frozen is sticky")

        // The key, read-only: the account's record (seq 2) is not on the served chain.
        val again = engine(server, alice, p.account, emptyMap(), p.device)
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), again.adoption(v), "the key is taken read-only")
        assertFalse(again.writeAllowed(v))
        val cold = StoredVaultLogs(alice.userId, alice.sign, alice.box, alice.uvk, silentClient, crypto, p.device, p.account,
            Host(server, alice, emptyMap()), { now }, { null })
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), cold.reopenAdopted(v), "a cold start reopens it read-only")
        assertIs<VaultLogStatus.Frozen>(cold.status(v))
        assertFalse(cold.writeAllowed(v), "not writable after the cold start")
    }

    /**
     * A freeze comes only from a validly signed entry at a place this device verified, never from a frame that does not
     * chain: the device's own chain served to its head, then a frame at the next place that names another entry and whose
     * signature does not verify, stays failed (`bad_prev`) with its state at the head; a departing entry at a verified
     * place whose signature does not verify stays failed too. In neither is a key taken.
     */
    @Test fun aForgedFrameAfterTheVerifiedHeadLeavesTheLogFailedAndGivesNoKey() = runBlocking<Unit> {
        val server = Server()
        val p = pastTheHead(server)
        val v = p.vaultId
        // A device of the owner's that verified the log to seq 2 and holds no key yet.
        server.logs[v] = p.lost.toMutableList()
        val d = engine(server, alice, SharedState(), emptyMap())
        assertEquals(2, assertIs<VaultLogStatus.Verified>(d.refresh(v, null, null, force = true)).state.headSeq)
        server.logs[v] = (p.lost + forged(p.departing[3])).toMutableList()
        val failed = assertIs<VaultLogStatus.Failed>(d.refresh(v, 3, "ab".repeat(32)), "a frame after the head that does not chain: ${d.status(v)}")
        assertEquals("bad_prev", failed.verdict)
        assertEquals(2L, failed.lastGood!!.headSeq, "the state stays at the head")
        assertEquals(Adoption.Refused(v, AdoptionRefusal.LOG_NOT_VERIFIED), d.adoption(v), "no key is taken")
        assertNull(d.keyFor(v))
        assertFalse(d.writeAllowed(v))

        // A departing entry at a verified place whose signature does not verify, then the rest of the departing chain.
        val e = engine(server, alice, SharedState(), emptyMap())
        server.logs[v] = p.lost.toMutableList()
        assertIs<VaultLogStatus.Verified>(e.refresh(v, null, null, force = true))
        server.logs[v] = (p.departing.take(2) + forged(p.departing[2]) + p.departing[3]).toMutableList()
        val st = e.refresh(v, 3, "cd".repeat(32))
        assertIs<VaultLogStatus.Failed>(st, "a forged departing entry is no fork: $st")
        assertEquals(Adoption.Refused(v, AdoptionRefusal.LOG_NOT_VERIFIED), e.adoption(v), "no key is taken")
        assertNull(e.keyFor(v))
        assertFalse(e.writeAllowed(v))
    }

    /**
     * The read from the beginning that a departing chain calls for gets no answer: the log is not taken as verified at the
     * head this device holds. It reads as failed and nothing can be written, though the key is still in memory.
     */
    @Test fun aReadFromTheBeginningThatGetsNoAnswerAfterADepartingFrameIsNotVerified() = runBlocking<Unit> {
        val server = Server()
        val p = pastTheHead(server)
        val v = p.vaultId
        assertTrue(p.d.writeAllowed(v), "writable before")
        // The first fetch (after the head) is answered; the server is down for the next one.
        server.onFetch = { server.down = true }
        val st = p.d.refresh(v, 3, hashAt(server, v, 3))
        server.down = false
        assertFalse(st is VaultLogStatus.Verified, "not verified: $st")
        assertIs<VaultLogStatus.Failed>(p.d.status(v))
        assertFalse(p.d.writeAllowed(v), "not writable")
    }

    /**
     * The same gap where the served head is at or below this device's head and names another entry there: the read from
     * the beginning gets no answer. Before, the log read as verified at the device's head and stayed writable.
     */
    @Test fun aReadFromTheBeginningThatGetsNoAnswerAfterAnotherHeadAtAVerifiedPlaceIsNotVerified() = runBlocking<Unit> {
        val server = Server()
        val p = pastTheHead(server)
        val v = p.vaultId
        // The server serves the departing chain cut at seq 2, the place where the device verified another entry.
        server.serveOnly = 3
        assertTrue(p.d.writeAllowed(v), "writable before")
        server.onFetch = { server.down = true }
        val st = p.d.refresh(v, 2, hashAt(server, v, 2))
        server.down = false
        server.serveOnly = null
        assertFalse(st is VaultLogStatus.Verified, "not verified: $st")
        assertIs<VaultLogStatus.Failed>(p.d.status(v))
        assertFalse(p.d.writeAllowed(v), "not writable")
    }

    /**
     * The account's record is written only from a verified log (design §3.6 (e)): not by the flush at an unlock and not by
     * an adoption while the log is withheld or frozen, though the record's batching would be due. Two devices of the
     * owner's record seq 1 and verify seq 3; one is then served the log only to seq 2 (withheld), and after the server is
     * put back to seq 2 and grown past seq 3 on another chain the other is frozen at seq 3, its state at seq 2. Before,
     * the flush raised the first device's record to its own head and the second device's to the entry before the fork.
     */
    @Test fun noRecordOfTheAccountIsWrittenWhileTheLogIsNotVerified() = runBlocking<Unit> {
        val server = Server()
        val owner = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(owner.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Add(bob.userId, "writer")))
        val dState = SharedState()
        val dDevice = MemoryDeviceState()
        val d = engine(server, alice, dState, emptyMap(), dDevice)
        val wState = SharedState()
        val w = engine(server, alice, wState, emptyMap())
        for (e in listOf(d, w)) {
            assertIs<VaultLogStatus.Verified>(e.refresh(v, null, null, force = true))
            assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), e.adoption(v))
        }
        val atOne = io.silencelen.andvari.core.client.state.VaultRecord(v, hashAt(server, v, 0), 1, hashAt(server, v, 1))
        assertEquals(atOne, dState.doc.vaults[v])
        assertEquals(atOne, wState.doc.vaults[v])
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "reader")))
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "writer")))
        for (e in listOf(d, w)) assertEquals(3, assertIs<VaultLogStatus.Verified>(e.refresh(v, null, null, force = true)).state.headSeq)
        assertEquals(atOne, dState.doc.vaults[v], "the batching keeps the record at seq 1")
        val lost = server.logs.getValue(v).toList()

        // Withheld: the log served only to seq 2, below the head this device verified; ten minutes on.
        server.serveOnly = 3
        assertIs<VaultLogStatus.Withheld>(w.refresh(v, null, null, force = true))
        server.serveOnly = null
        now += 11 * 60_000L
        w.flushVaultRecords()
        val withheldFlush = wState.doc.vaults[v]

        // The server put back to seq 2 and grown on another chain to seq 4: frozen at seq 3.
        server.logs[v] = lost.take(3).toMutableList()
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        assertIs<VaultLogStatus.Verified>(other.refresh(v, null, null, force = true))
        assertIs<Adoption.Adopted>(other.adoption(v))
        now += 1000
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Role(bob.userId, "reader")))
        now += 1000
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Role(bob.userId, "writer")))
        val f = assertIs<VaultLogStatus.Frozen>(d.refresh(v, 4, hashAt(server, v, 4)))
        assertEquals(3L to 2L, f.seq to f.state.headSeq)
        d.flushVaultRecords()
        val frozenFlush = dState.doc.vaults[v]
        val again = engine(server, alice, dState, emptyMap(), dDevice)
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), again.adoption(v), "the key is taken: the record agrees with the chain to seq 2")
        assertFalse(again.writeAllowed(v))
        val frozenAdoption = dState.doc.vaults[v]

        assertEquals(
            listOf("withheld, flush" to atOne, "frozen, flush" to atOne, "frozen, adoption" to atOne).toString(),
            listOf("withheld, flush" to withheldFlush, "frozen, flush" to frozenFlush, "frozen, adoption" to frozenAdoption).toString(),
        )
    }

    /**
     * A change this device signed at the place after its head before the server was put back, whose request got no
     * answer, is never sent after the vault froze over the departing chain: it names an entry the served chain does not
     * hold, so it can never be stored, and the vault takes no change.
     */
    @Test fun aChangeHeldBeforeTheRestoreIsNotSentAfterTheVaultFroze() = runBlocking<Unit> {
        val server = Server()
        val p = pastTheHead(server) { d, id ->
            server.dropAppends = 1
            assertEquals(AppendOutcome.Pending, d.append(id, LogAction.Role(bob.userId, "writer")), "signed at seq 3, no answer")
            assertNotNull(d.heldChange(id))
        }
        val v = p.vaultId
        assertEquals(3, server.logs.getValue(v).size - 1, "the departing chain ends at seq 3")
        assertIs<VaultLogStatus.Frozen>(p.d.refresh(v, 3, hashAt(server, v, 3)))
        val sent = server.appends
        val resent = p.d.resendHeld()
        p.d.retryPending()
        assertEquals(sent, server.appends, "the held change is not sent: $resent")
        assertFalse(resent.any { it is HeldResend.Stored }, "nothing is stored: $resent")
        assertEquals(p.departing, server.logs.getValue(v), "the served chain is as it was")
    }

    /**
     * The engine's post of a self-wrap after an adoption through the grant, where the vault froze over a departing chain,
     * written down as it is. Bob's device accepted Alice's add (seq 1) and verified seq 2; the server is put back to seq 1
     * with Bob's grant row carrying no wrap, and Alice's other device grows it to seq 3 on another chain. Bob's device is
     * frozen at seq 2; a new engine over its state takes the key through the grant, read-only, and posts the self-wrap.
     */
    @Test fun anAdoptionThroughTheGrantAfterTheFreezeStillPostsTheSelfWrap() = runBlocking<Unit> {
        val server = Server()
        val owner = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(owner.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Add(bob.userId, "writer")))
        val bobState = SharedState()
        val device = MemoryDeviceState()
        val b = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), device)
        assertIs<VaultLogStatus.Verified>(b.refresh(v, null, null, force = true))
        val ask = assertIs<Adoption.AskAccept>(b.adoption(v))
        assertEquals(Adoption.Adopted(v, KeySource.GRANT), b.answerIncoming(ask, accept = true))
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "reader")))
        assertEquals(2, assertIs<VaultLogStatus.Verified>(b.refresh(v, null, null, force = true)).state.headSeq)

        // The server put back to seq 1, Bob's row as it was before his wrap; another device of Alice's makes seq 2 and 3.
        val lost = server.logs.getValue(v).toList()
        server.logs[v] = lost.take(2).toMutableList()
        server.grants[v to bob.userId] = server.grants.getValue(v to bob.userId).copy(wrappedVk = "")
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        assertIs<VaultLogStatus.Verified>(other.refresh(v, null, null, force = true))
        assertIs<Adoption.Adopted>(other.adoption(v))
        now += 1000
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Role(bob.userId, "writer")))
        now += 1000
        assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Role(bob.userId, "reader")))
        assertEquals(2L, assertIs<VaultLogStatus.Frozen>(b.refresh(v, 3, hashAt(server, v, 3))).seq)

        var posts = 0
        server.onSelfWrap = { posts++ }
        val again = engine(server, bob, bobState, mapOf(alice.userId to alice.pub), device)
        assertEquals(Adoption.Adopted(v, KeySource.GRANT), again.adoption(v), "the key is taken through the grant")
        assertFalse(again.writeAllowed(v), "read-only")
        assertEquals(1, posts, "the self-wrap is posted once")
        assertTrue(server.grants.getValue(v to bob.userId).wrappedVk.isNotEmpty(), "the row now carries Bob's wrap")
    }

    /** The owner's vault: create (0), Bob added (1), Bob made a reader (2). Returns the owner's engine and the vault. */
    private suspend fun family(server: Server): Pair<StoredVaultLogs, String> {
        val owner = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(owner.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Add(bob.userId, "writer")))
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "reader")))
        return owner to v
    }

    /** Another device of the owner's, on the restored log: verified, adopted, then [roles] appended (each a second later). */
    private suspend fun grow(server: Server, v: String, vararg roles: String) {
        val other = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        assertIs<VaultLogStatus.Verified>(other.refresh(v, null, null, force = true))
        assertIs<Adoption.Adopted>(other.adoption(v))
        for (r in roles) {
            now += 1000
            assertIs<AppendOutcome.Appended>(other.append(v, LogAction.Role(bob.userId, r)))
        }
    }

    /**
     * No record of the account is written from a failed log either. A device with the key in memory verified seq 3 while
     * the account's record stays at seq 1 (batching). The server is put back to seq 1 and grown on another chain to seq 4;
     * the device's read from the beginning gets no answer, so the log is failed. Eleven minutes on, an unlock's flush: the
     * record stays at seq 1. The control: a device of another account state whose log is still verified at seq 3 raises
     * its record at the same flush, so the batching is due and the flush does write.
     */
    @Test fun aFailedLogWritesNoRecordAtTheFlush() = runBlocking<Unit> {
        val server = Server()
        val owner = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(owner.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Add(bob.userId, "writer")))
        val dState = SharedState()
        val d = engine(server, alice, dState, emptyMap())
        val wState = SharedState()
        val w = engine(server, alice, wState, emptyMap())
        for (e in listOf(d, w)) {
            assertIs<VaultLogStatus.Verified>(e.refresh(v, null, null, force = true))
            assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), e.adoption(v))
        }
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "reader")))
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "writer")))
        for (e in listOf(d, w)) assertEquals(3, assertIs<VaultLogStatus.Verified>(e.refresh(v, null, null, force = true)).state.headSeq)
        assertEquals(1L, dState.doc.vaults.getValue(v).seq, "the batching keeps the record at seq 1")
        assertEquals(1L, wState.doc.vaults.getValue(v).seq)
        val lost = server.logs.getValue(v).toList()

        server.logs[v] = lost.take(2).toMutableList()
        grow(server, v, "reader", "writer", "reader")
        server.onFetch = { server.down = true }
        val st = d.refresh(v, 4, hashAt(server, v, 4))
        server.down = false
        assertIs<VaultLogStatus.Failed>(st, "the read from the beginning got no answer: $st")
        assertTrue(d.keyFor(v) != null, "the key is still in memory, so the flush looks at the vault")

        now += 11 * 60_000L
        w.flushVaultRecords()
        d.flushVaultRecords()
        assertEquals(
            listOf("control (verified)" to 3L, "failed" to 1L).toString(),
            listOf("control (verified)" to wState.doc.vaults.getValue(v).seq, "failed" to dState.doc.vaults.getValue(v).seq).toString(),
        )
    }

    /**
     * The log is read again from its beginning only when the first frame served sits at the place right after the
     * verified head. A server whose page "after the head" starts at the head itself (it serves the verified head again,
     * then the new entry), while its read from the beginning is honest: the first frame served does not name the head as
     * its prev, but it does not sit after the head, so there is no read from the beginning, and the replay from the head
     * refuses it as `bad_seq`. Were the log read again from its beginning here, the device would come out verified.
     */
    @Test fun aPageThatStartsAtTheVerifiedHeadIsBadSeqNotARereadFromTheBeginning() = runBlocking<Unit> {
        val server = Server()
        val (owner, v) = family(server)
        val d = engine(server, alice, SharedState(), emptyMap())
        assertEquals(2, assertIs<VaultLogStatus.Verified>(d.refresh(v, null, null, force = true)).state.headSeq)
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "writer")))
        server.pageFromHead = true
        val f0 = server.fetches
        val st = d.refresh(v, 3, hashAt(server, v, 3))
        server.pageFromHead = false
        val failed = assertIs<VaultLogStatus.Failed>(st, "a page that starts at the head: $st")
        assertEquals("bad_seq" to 1, failed.verdict to (server.fetches - f0))
    }

    /**
     * The log is read again from its beginning only when the first frame served after the verified head does not name
     * that head as its prev. An honest chain grown by one entry past the verified head is read with ONE fetch: no read
     * from the beginning.
     */
    @Test fun anHonestEntryAfterTheHeadIsReadWithOneFetch() = runBlocking<Unit> {
        val server = Server()
        val (owner, v) = family(server)
        val d = engine(server, alice, SharedState(), emptyMap())
        assertEquals(2, assertIs<VaultLogStatus.Verified>(d.refresh(v, null, null, force = true)).state.headSeq)
        now += 1000
        assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, "writer")))
        val f0 = server.fetches
        assertEquals(3, assertIs<VaultLogStatus.Verified>(d.refresh(v, 3, hashAt(server, v, 3))).state.headSeq)
        assertEquals(1, server.fetches - f0, "one fetch")
    }

    /**
     * At a freeze over a departing chain, only a held change at or above the place where the chains part is dropped. A
     * device holds a change at seq 3 (no answer). The account's record names seq 5 of chain A (another device of the
     * account verified it). The server, put back to seq 4, serves A's 3 and 4 and then another entry at 5: the vault
     * freezes at 5, above the held change. The held change is not dropped there: its place (3) is held by another verified
     * entry, so the general re-send tells the person it will never be made (place taken).
     */
    @Test fun aHeldChangeBelowTheForkPlaceIsToldPlaceTaken() = runBlocking<Unit> {
        val server = Server()
        val (owner, v) = family(server)
        val acct = SharedState()
        val x = engine(server, alice, acct, emptyMap())
        assertEquals(2, assertIs<VaultLogStatus.Verified>(x.refresh(v, null, null, force = true)).state.headSeq)
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), x.adoption(v))
        server.dropAppends = 1
        now += 1000
        assertEquals(AppendOutcome.Pending, x.append(v, LogAction.Role(bob.userId, "writer")), "held at seq 3")
        for (r in listOf("writer", "reader", "writer")) {
            now += 1000
            assertIs<AppendOutcome.Appended>(owner.append(v, LogAction.Role(bob.userId, r)))
        }
        now += 11 * 60_000L
        val y = engine(server, alice, acct, emptyMap())
        assertEquals(5, assertIs<VaultLogStatus.Verified>(y.refresh(v, null, null, force = true)).state.headSeq)
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), y.adoption(v))
        assertEquals(5L to hashAt(server, v, 5), acct.doc.vaults.getValue(v).let { it.seq to it.hash }, "the account records seq 5 of chain A")

        server.logs[v] = server.logs.getValue(v).take(5).toMutableList()
        grow(server, v, "reader")
        val f = assertIs<VaultLogStatus.Frozen>(x.refresh(v, null, null, force = true), "x: ${x.status(v)}")
        assertEquals(5L, f.seq, "frozen at 5, above the held change")
        // (heldChange() settles a change against the verified log itself, so it is not called before the re-send.)
        assertEquals(listOf<HeldResend>(HeldResend.PlaceTaken(v)), x.resendHeld(), "the re-send tells its place was taken")
    }

    /**
     * A change held at seq 3 before the restore; the server is put back to seq 1 and grown to seq 3 on another chain.
     * The person's own re-send of it: the server answers `log_head_moved`, the read that follows freezes the vault at 2
     * and drops the change, and the re-send says the vault is frozen, so the person is told why the change went.
     */
    @Test fun aRepostWhoseOwnReadFrozeTheVaultSaysFrozen() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = family(server)
        val x = engine(server, alice, SharedState(), emptyMap())
        assertEquals(2, assertIs<VaultLogStatus.Verified>(x.refresh(v, null, null, force = true)).state.headSeq)
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), x.adoption(v))
        server.dropAppends = 1
        now += 1000
        assertEquals(AppendOutcome.Pending, x.append(v, LogAction.Role(bob.userId, "writer")), "held at seq 3")
        val held = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.lastFrame())))

        server.logs[v] = server.logs.getValue(v).take(2).toMutableList()
        grow(server, v, "writer", "reader")
        val r = x.repostHeld(v, held)
        assertEquals(listOf("repost" to HeldRepost.Refused(StoredVaultLogs.VAULT_FROZEN).toString(), "status" to "frozen:2", "held" to "null").toString(),
            listOf("repost" to r.toString(), "status" to (x.status(v) as? VaultLogStatus.Frozen)?.let { "frozen:${it.seq}" }, "held" to x.heldChange(v)?.toString().toString()).toString())
    }

    @Test fun lockWipesEveryKeyHeldInMemory() = runBlocking<Unit> {
        val server = Server()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub))
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        assertTrue(a.writeAllowed(vaultId))
        val copy = a.keyFor(vaultId)!!
        a.wipeKeys()
        assertNull(a.keyFor(vaultId), "no key is offered after the lock")
        assertTrue(!a.writeAllowed(vaultId) && !a.copyOutAllowed(vaultId))
        assertTrue(copy.any { it != 0.toByte() }, "a copy handed out before is the caller's to wipe")
        assertIs<Adoption.Adopted>(a.adoption(vaultId))
        assertContentEquals(copy, a.keyFor(vaultId), "the next session adopts the same key again")
    }

    @Test fun aRestoreResumesItsCreateUnderTheVaultIdItChose() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val aliceState = SharedState()
        val id = "3333aaaa-3333-4333-8333-333333333333"
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.BAD_VAULT_ID), engine(server, alice, aliceState, emptyMap(), device).append(null, LogAction.Create("Family", "not-a-uuid")))
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.BAD_VAULT_ID), engine(server, alice, aliceState, emptyMap(), device).append(null, LogAction.Create("Family", id.uppercase())))

        // The restore's create goes out while the server does not answer: the genesis stays pending on this device.
        server.down = true
        assertEquals(AppendOutcome.Pending, engine(server, alice, aliceState, emptyMap(), device).append(null, LogAction.Create("Family", id)))
        val signedAt = now
        server.down = false
        now += 60_000

        // The restore resumes after a restart: the held genesis is re-posted byte for byte, never signed again.
        val resumed = engine(server, alice, aliceState, emptyMap(), device)
        assertEquals(id, assertIs<AppendOutcome.Appended>(resumed.append(null, LogAction.Create("Family", id))).state.vaultId)
        assertEquals(1, server.logs.getValue(id).size)
        assertEquals(signedAt, VaultLog.parse(crypto, Bytes.fromB64(server.logs.getValue(id)[0])).valueOrNull()!!.entry.at)
        // Asked once more: already verified, answered as appended, nothing new sent.
        val again = assertIs<AppendOutcome.Appended>(resumed.append(null, LogAction.Create("Family", id)))
        assertEquals(0, again.state.headSeq)
        assertEquals(1, server.logs.getValue(id).size)
        assertIs<Adoption.Adopted>(engine(server, alice, aliceState, emptyMap(), device).adoption(id), "the owner wrap went with the genesis")

        // Another account that verified this vault cannot claim its id.
        val b = engine(server, bob, SharedState(), mapOf(alice.userId to alice.pub))
        b.refresh(id, null, null, force = true)
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.VAULT_ID_TAKEN), b.append(null, LogAction.Create("Mine", id)))
        assertEquals(1, server.logs.getValue(id).size)

        // A fresh id goes out at once, under that id.
        val other = "44444444-4444-4444-8444-444444444444"
        assertEquals(other, assertIs<AppendOutcome.Appended>(resumed.append(null, LogAction.Create("Work", other))).state.vaultId)
    }

    @Test fun deletionPlacesItsLeavesFromTheEnginesOwnVerifiedState() = runBlocking<Unit> {
        val server = Server()
        val device = MemoryDeviceState()
        val a = engine(server, alice, SharedState(), mapOf(bob.userId to bob.pub), device)
        val vaultId = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        a.append(vaultId, LogAction.Add(bob.userId, "writer"))
        val h1 = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(server.logs.getValue(vaultId)[1])))
        val s = assertNotNull(a.verifiedState(vaultId))
        assertEquals(1, s.head.seq)
        assertEquals(h1, s.head.hash)
        assertNull(a.verifiedState("00000000-0000-4000-8000-000000000000"), "nothing verified, nothing answered")

        val reauth = io.silencelen.andvari.core.client.account.Reauth(object : io.silencelen.andvari.core.client.account.ReauthSession {
            override val origin = "https://a.example"
            override val emailNorm = "alice@x.example"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String = "K".repeat(43)
        }, { emptyList() })
        fun deletion() = io.silencelen.andvari.core.client.deletion.WireAccountDeletion(
            alice.userId, "alice@x.example", alice.sign, server.client(alice.userId), crypto, reauth, a, { now }, {},
        )
        val farAt = now + 3 * io.silencelen.andvari.core.client.deletion.WireAccountDeletion.FUTURE_LIMIT_MS
        val verifiedHead = listOf(io.silencelen.andvari.core.model.wire.DeleteMembership(vaultId, LogHead(1, h1, farAt)))
        val leave = VaultLog.parse(crypto, Bytes.fromB64(assertNotNull(deletion().leaves(verifiedHead, now), "the engine verified that head").single()))
            .valueOrNull()!!.entry
        assertEquals(maxOf(now, s.at), leave.at, "placed from the verified state, never the served at")
        val otherHead = listOf(io.silencelen.andvari.core.model.wire.DeleteMembership(vaultId, LogHead(1, "b".repeat(64), farAt)))
        assertNull(deletion().leaves(otherHead, now), "a head the engine did not verify is held to the one-day bound")

        // A trust record that cannot be read is not a verified state: the head is treated as unverified.
        device.set("ovh.log|${alice.userId}|$vaultId|hashes", "not json")
        assertNull(a.verifiedState(vaultId))
        assertNull(deletion().leaves(verifiedHead, now))
    }

    // ---- a held addition is sent again only to the contact it was signed for ----

    /** A vault alice owns with nobody else in it yet, and bob's addition held: its request got no answer and stored nothing. */
    private suspend fun heldAdditionOfBob(server: Server, contacts: Map<String, String>): Pair<StoredVaultLogs, String> {
        val a = engine(server, alice, SharedState(), contacts)
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Add(bob.userId, "writer")))
        assertEquals(bob.pub, assertNotNull(a.heldChange(v)).memberKey, "the addition names bob by the key it was signed for")
        return a to v
    }

    private fun addsOf(server: Server, vaultId: String): Int = server.logs[vaultId].orEmpty().count {
        VaultLog.parse(crypto, Bytes.fromB64(it)).valueOrNull()?.entry is LogEntry.Add
    }

    /**
     * The general re-send never sends a held addition whose contact has another key now: it is let go of, and a finding of
     * its own says so and that it may still be made (an earlier send may have reached the server). Before, it was sent as
     * it was signed, to the key the person had since replaced.
     */
    @Test fun aHeldAdditionWhoseContactHasAnotherKeyIsNotSentAgainByTheGeneralResend() = runBlocking<Unit> {
        val server = Server()
        val contacts = HashMap(mapOf(bob.userId to bob.pub))
        val (a, v) = heldAdditionOfBob(server, contacts)
        contacts[bob.userId] = Bytes.toB64(ByteArray(32) { 9 })
        val sent = server.appends
        assertEquals(listOf<HeldResend>(HeldResend.ContactChanged(v)), a.resendHeld())
        assertEquals(sent, server.appends, "not sent again")
        assertNull(a.heldChange(v), "let go of")
        assertEquals(0, addsOf(server, v))
        val f = a.heldFindings().single()
        assertEquals(FoundKind.CONTACT_CHANGED, f.what)
        assertFalse(f.final, "an earlier send may have reached the server")
        assertEquals(bob.userId, f.names)
        assertEquals(bob.pub, f.memberKey)
        a.resendHeld()
        a.retryPending()
        assertEquals(sent, server.appends, "never sent again by any road")
    }

    /**
     * The road before the person's next change of the vault and the person's own word ([StoredVaultLogs.repostHeld]) check
     * the contact too: an addition whose contact is gone, or has another key, is let go of unsent, and the next change goes
     * on from the vault's head. Before, both sent it as it was signed.
     */
    @Test fun aHeldAdditionWhoseContactChangedIsNotSentBeforeTheNextChangeNorAtThePersonsWord() = runBlocking<Unit> {
        val server = Server()
        val contacts = HashMap(mapOf(bob.userId to bob.pub))
        val (a, v) = heldAdditionOfBob(server, contacts)
        contacts.remove(bob.userId)
        assertIs<AppendOutcome.Appended>(a.append(v, LogAction.Delete), "the next change is signed and stored")
        assertEquals(0, addsOf(server, v), "the addition was not sent before it")
        assertEquals(FoundKind.CONTACT_CHANGED, a.heldFindings().single { it.vaultId == v }.what)

        contacts[bob.userId] = bob.pub
        val (b, w) = heldAdditionOfBob(server, contacts)
        contacts[bob.userId] = Bytes.toB64(ByteArray(32) { 9 })
        val sent = server.appends
        assertEquals(HeldRepost.Waiting, b.repostHeld(w, assertNotNull(b.heldChange(w)).hash))
        assertEquals(sent, server.appends, "not sent at the person's word either")
        assertNull(b.heldChange(w))
        assertEquals(FoundKind.CONTACT_CHANGED, b.heldFindings().single { it.vaultId == w }.what)
    }

    /**
     * An addition let go of for its contact, which an earlier send had stored after all: the next read that finds it keeps
     * "made after all" (with the way to undo it), naming the key it was signed for.
     */
    @Test fun aHeldAdditionLetGoForItsContactIsToldMadeAfterAllWhenALaterReadFindsIt() = runBlocking<Unit> {
        val server = Server()
        val contacts = HashMap(mapOf(bob.userId to bob.pub))
        val a = engine(server, alice, SharedState(), contacts)
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.loseAppendAnswers = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Add(bob.userId, "writer")))
        assertEquals(1, addsOf(server, v), "the server stored it; its answer was lost")
        contacts[bob.userId] = Bytes.toB64(ByteArray(32) { 9 })
        assertEquals(listOf<HeldResend>(HeldResend.ContactChanged(v)), a.resendHeld())
        a.refresh(v, null, null, force = true)
        val made = a.heldFindings().single { it.what == FoundKind.MADE_AFTER_ALL }
        assertEquals(LetGo.CONTACT_CHANGED, made.letGo)
        assertEquals(bob.pub, made.memberKey)
    }

    /** One known not stored (every send answered "slow down") is let go of as not made, and nothing is remembered of it. */
    @Test fun aHeldAdditionKnownNotStoredLetGoForItsContactIsSaidNotMade() = runBlocking<Unit> {
        val server = Server()
        val contacts = HashMap(mapOf(bob.userId to bob.pub))
        val a = engine(server, alice, SharedState(), contacts)
        val v = assertIs<AppendOutcome.Appended>(a.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        server.rateLimitAppends = 1
        assertIs<AppendOutcome.Refused>(a.append(v, LogAction.Add(bob.userId, "writer")))
        contacts[bob.userId] = Bytes.toB64(ByteArray(32) { 9 })
        val sent = server.appends
        assertEquals(listOf<HeldResend>(HeldResend.ContactChanged(v)), a.resendHeld())
        assertEquals(sent, server.appends)
        assertTrue(a.heldFindings().single().final, "it was known not stored: not made")
    }

    /** An addition whose contact is unchanged is still sent again by the general re-send. */
    @Test fun aHeldAdditionWhoseContactIsUnchangedIsStillSentAgain() = runBlocking<Unit> {
        val server = Server()
        val contacts = HashMap(mapOf(bob.userId to bob.pub))
        val (a, v) = heldAdditionOfBob(server, contacts)
        assertIs<HeldResend.Stored>(a.resendHeld().single())
        assertEquals(1, addsOf(server, v))
        assertTrue(a.heldFindings().isEmpty())
    }

    /**
     * Withdrawing and re-posting act only on the change the caller named by its signed entry's hash: where another change
     * is held for the vault now, nothing is withdrawn or sent. Before, both acted on whatever was held at that moment.
     */
    @Test fun withdrawAndRepostActOnlyOnTheChangeTheCallerNamed() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = vaultWithBob(server)
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Remove(bob.userId)))
        val first = assertNotNull(a.heldChange(v)).hash
        // The removal reached the server after all; a read settles it, and a later change of the vault is held instead.
        server.lateAppend(v, server.lastFrame())
        a.refresh(v, null, null, force = true)
        assertNull(a.heldChange(v))
        now += 1000
        server.dropAppends = 1
        assertEquals(AppendOutcome.Pending, a.append(v, LogAction.Add(bob.userId, "reader")))
        val second = assertNotNull(a.heldChange(v)).hash
        val sent = server.appends
        assertEquals(HeldWithdrawal.NOT_THIS_CHANGE, assertIs<HeldWithdrawal.Kept>(a.withdraw(v, first)).reason)
        assertEquals(HeldRepost.NotThisChange, a.repostHeld(v, first))
        assertEquals(sent, server.appends, "nothing was sent")
        assertEquals(second, assertNotNull(a.heldChange(v)).hash, "the change held now stays held")
        assertIs<HeldWithdrawal.Withdrawn>(a.withdraw(v, second))
    }
}
