package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.client.onboard.GuardedKeyPair
import io.silencelen.andvari.core.client.onboard.KeyGuard
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.SyncGrant
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
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A change is signed only over the head its caller checked ([VaultLogEngine.append] with an expected head), and a held
 * change can be re-posted without signing anything new ([VaultLogEngine.repostHeld]). The interleavings are driven by the
 * test (another device's change stored and read between the caller's check and its append, or stored while this device's
 * held change waits); nothing sleeps.
 */
class CheckedHeadAppendTest {
    private val crypto = createCryptoProvider()

    /** Counts every Ed25519 signature made through it: a statement signed is a statement built. */
    private class Signing(val inner: CryptoProvider) : CryptoProvider by inner {
        var signatures = 0
        override fun signDetached(secretKey: ByteArray, message: ByteArray): ByteArray {
            signatures++
            return inner.signDetached(secretKey, message)
        }
    }

    private class Person(crypto: CryptoProvider, val userId: String, seed: Byte) {
        val sign = crypto.signKeypairFromSeed(ByteArray(32) { seed })
        val box = crypto.boxKeypairFromSeed(ByteArray(32) { seed })
        val uvk = ByteArray(32) { (seed + 1).toByte() }
        val pub: String = Bytes.toB64(box.publicKey)
    }

    private val alice = Person(crypto, "11111111-1111-4111-8111-111111111111", 3)
    private val bob = Person(crypto, "22222222-2222-4222-8222-222222222222", 5)
    private val carol = Person(crypto, "33333333-3333-4333-8333-333333333333", 7)

    /** One server: stores frames verified as the real one does, and switches for the interleavings. */
    private inner class Server {
        val logs = HashMap<String, MutableList<String>>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        var down = false
        /** Store the next append, then answer nothing (an answer lost on the way back). */
        var storeThenNoAnswer = false
        /** Run at each append, before it is looked at. */
        var onAppend: ((LogAppendRequest) -> Unit)? = null
        var appends = 0
        val posted = ArrayList<String>()

        fun client(user: String): WireClient = object : WireClient {
            override val origin = "https://h.example"
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                // Every entry a device posts, answered or not, in order.
                if (route == WireRoute.LOG_APPEND) posted += WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry
                if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                val vaultId = pathParams.getValue("vaultId")
                val log = logs.getOrPut(vaultId) { ArrayList() }
                return when (route) {
                    WireRoute.LOG_FETCH -> {
                        val after = query?.removePrefix("after=")?.toLong()
                        val from = ((after ?: -1) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        WireResult.Ok(decode(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, head(log), null))), 200)
                    }
                    WireRoute.LOG_APPEND -> {
                        appends++
                        val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                        onAppend?.invoke(req)
                        if (req.entry in log) return answer(log, decode)
                        val prior = VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                        val entry = VaultLog.parse(crypto, Bytes.fromB64(req.entry)).valueOrNull()?.entry
                        if (entry != null && entry.seq != log.size.toLong()) {
                            val h = prior!!.head
                            return WireResult.Refused(409, WireError("log_head_moved", "m", seq = h.seq, hash = h.hash, at = prior.at))
                        }
                        when (val v = VaultLog.verify(crypto, vaultId, prior, Bytes.fromB64(req.entry), KnownHashes.NONE_HELD)) {
                            is Checked.Refused -> return WireResult.Refused(400, WireError(v.verdict.code, "m"))
                            is Checked.Ok -> {}
                        }
                        log += req.entry
                        if (entry is LogEntry.Genesis) grants[vaultId to user] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, 1)
                        if (entry is LogEntry.Add) grants[vaultId to entry.member] = SyncGrant(vaultId, entry.member, entry.role.literal, "", 1, req.grant)
                        answer(log, decode)
                    }
                    else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                }
            }

            private fun <T> answer(log: List<String>, decode: (String) -> T): WireResult<T> {
                if (storeThenNoAnswer) {
                    storeThenNoAnswer = false
                    return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                }
                return WireResult.Ok(decode(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(1, head(log)))), 200)
            }
        }

        fun head(log: List<String>) = LogHead(log.size - 1L, if (log.isEmpty()) "0".repeat(64) else hashOf(log.last()), 0)

        fun hashOf(frame: String) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(frame)))

        /** The entries stored for [vaultId], parsed. */
        fun entries(vaultId: String): List<LogEntry> = logs.getValue(vaultId).map { VaultLog.parse(crypto, Bytes.fromB64(it)).valueOrNull()!!.entry }
    }

    private class SharedState : AccountStateStore {
        var doc = AccountDocument.EMPTY
        override fun local() = doc
        override suspend fun read(): AccountStateRead = AccountStateRead.Ok(doc, emptyList())
        override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite {
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
        override fun labelFor(userId: String, identityPub: String) = null
        override fun vaultName(vaultId: String, vk: ByteArray) = "Family"
        override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
        override fun serverOwnerName(vaultId: String) = "someone"
    }

    private var now = 1_763_164_800_000L

    private val contacts by lazy { mapOf(bob.userId to bob.pub, carol.userId to carol.pub) }

    /**
     * One of alice's devices: its own device state, the account's shared state, and its keys (copies) under [guard], so a
     * test can lock it; a later engine over the same [device] is the next unlock.
     */
    private fun device(server: Server, account: SharedState, device: MemoryDeviceState = MemoryDeviceState(), guard: KeyGuard = KeyGuard(), spy: Signing = Signing(crypto)) =
        StoredVaultLogs(
            alice.userId,
            GuardedKeyPair(KeyPairBytes(alice.sign.publicKey, alice.sign.privateKey.copyOf()), guard),
            GuardedKeyPair(KeyPairBytes(alice.box.publicKey, alice.box.privateKey.copyOf()), guard),
            GuardedKey(alice.uvk.copyOf(), guard),
            server.client(alice.userId), spy, device, account, Host(server, alice, contacts), { now }, { null },
        )

    private fun headOf(engine: VaultLogEngine, vaultId: String): Checkpoint =
        assertIs<VaultLogStatus.Verified>(engine.status(vaultId)).state.let { Checkpoint(it.headSeq, it.headHash) }

    /** A vault alice owns, with bob a writer, seen by her second device too: (vault, first device, second device). */
    private suspend fun sharedVault(server: Server, account: SharedState, spy: Signing, guard: KeyGuard = KeyGuard()): Triple<String, StoredVaultLogs, StoredVaultLogs> {
        val a1 = device(server, account, guard = guard, spy = spy)
        val vaultId = assertIs<AppendOutcome.Appended>(a1.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Add(bob.userId, "writer")))
        val a2 = device(server, account)
        assertIs<VaultLogStatus.Verified>(a2.refresh(vaultId, null, null, force = true))
        assertIs<Adoption.Adopted>(a2.adoption(vaultId))
        now += 1000
        return Triple(vaultId, a1, a2)
    }

    @Test fun aChangeStoredByAnotherDeviceBetweenTheCallersCheckAndTheAppendIsRefusedAndNothingIsSigned() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, a2) = sharedVault(server, SharedState(), spy)

        // The caller checks the members at this head: bob is a writer.
        val checked = headOf(a1, vaultId)
        assertEquals(1, checked.seq)
        // Meanwhile alice's other device adds carol, and this device's sync reads that in before the append.
        assertIs<AppendOutcome.Appended>(a2.append(vaultId, LogAction.Add(carol.userId, "reader")))
        assertEquals(2, assertIs<VaultLogStatus.Verified>(a1.refresh(vaultId, 2, server.hashOf(server.logs.getValue(vaultId)[2]))).state.headSeq)

        val signedBefore = spy.signatures
        val appendsBefore = server.appends
        val r = a1.append(vaultId, LogAction.Role(bob.userId, "reader"), checked)
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.LOG_MOVED_ON), r, "the log moved on since the check")
        assertEquals(signedBefore, spy.signatures, "nothing was signed")
        assertEquals(appendsBefore, server.appends, "nothing was sent")
        assertEquals(3, server.logs.getValue(vaultId).size)

        // Read again and decided again: the change goes out over the head now checked.
        val again = headOf(a1, vaultId)
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Role(bob.userId, "reader"), again))
        assertEquals("reader", assertIs<VaultLogStatus.Verified>(a1.status(vaultId)).state.members.getValue(bob.userId).role)

        // Without the head, an append behaves as before.
        now += 1000
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Role(bob.userId, "writer"), null))
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Role(bob.userId, "reader")))
    }

    @Test fun aChangeStoredByAnotherDeviceThatThisDeviceHasNotReadIsSignedOnlyOverTheCheckedHeadAndNeverStored() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, a2) = sharedVault(server, SharedState(), spy)
        val checked = headOf(a1, vaultId)
        assertIs<AppendOutcome.Appended>(a2.append(vaultId, LogAction.Remove(bob.userId)))

        // This device has not read the remove: it signs over the head the caller checked, the server refuses that head,
        // and once the refetch shows another entry at that position the frame is dropped.
        assertEquals(AppendOutcome.HeadMoved, a1.append(vaultId, LogAction.Delete, checked))
        assertTrue(server.entries(vaultId).none { it is LogEntry.Delete }, "no delete stored over a head nobody checked")
        assertEquals(2, headOf(a1, vaultId).seq)
        assertEquals(HeldRepost.NothingHeld, a1.repostAsHeld(vaultId))
    }

    @Test fun aVaultDeletionOverAHeadThatMovedWhileAHeldChangeWaitedIsRefusedAndNothingIsSigned() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, a2) = sharedVault(server, SharedState(), spy)

        // This device's role change goes unanswered and is held; the caller then checks at the head it knows.
        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Role(bob.userId, "reader")))
        server.down = false
        val checked = headOf(a1, vaultId)
        // The other device's change takes that place first.
        assertIs<AppendOutcome.Appended>(a2.append(vaultId, LogAction.Add(carol.userId, "reader")))

        // The delete re-posts the held change first: refused, the other entry verified at its place, dropped. The verified
        // head is no longer the one checked, so the delete is never signed.
        val signedBefore = spy.signatures
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.LOG_MOVED_ON), a1.append(vaultId, LogAction.Delete, checked))
        assertEquals(signedBefore, spy.signatures, "no delete was signed")
        assertTrue(server.entries(vaultId).none { it is LogEntry.Delete || it is LogEntry.Role })
        assertEquals(HeldRepost.NothingHeld, a1.repostAsHeld(vaultId), "the held change was dropped by the log's own rule")

        // The same when the held change itself is what was stored: the caller decided before it, so it reads again.
        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Role(bob.userId, "reader")))
        server.down = false
        val beforeOwn = headOf(a1, vaultId)
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.LOG_MOVED_ON), a1.append(vaultId, LogAction.Delete, beforeOwn))
        assertTrue(server.entries(vaultId).any { it is LogEntry.Role } && server.entries(vaultId).none { it is LogEntry.Delete })
        // Read again: now the delete goes out.
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Delete, headOf(a1, vaultId)))
        assertNotNull(assertIs<VaultLogStatus.Verified>(a1.status(vaultId)).state.deletedId)
        // A new vault has no head to have checked.
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.BAD_EXPECT_HEAD), a1.append(null, LogAction.Create("Other"), beforeOwn))
    }

    @Test fun aHeldChangeStoredLateIsReportedStoredAndNeverSentTwice() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, _) = sharedVault(server, SharedState(), spy)

        // Stored, but the answer was lost: held.
        server.storeThenNoAnswer = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Delete))
        val signedBefore = spy.signatures
        val appendsBefore = server.appends
        val stored = assertIs<HeldRepost.Stored>(a1.repostAsHeld(vaultId))
        assertNotNull(stored.state.deletedId)
        assertEquals(appendsBefore + 1, server.appends, "re-posted once, byte for byte")
        assertEquals(HeldRepost.NothingHeld, a1.repostAsHeld(vaultId))
        assertEquals(appendsBefore + 1, server.appends, "and never again")
        assertEquals(signedBefore, spy.signatures, "nothing new was signed")
        assertEquals(1, server.entries(vaultId).count { it is LogEntry.Delete })

        // Stored late and read by a sync before the re-post: settled without sending it again.
        now += 1000
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Restore))
        server.storeThenNoAnswer = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Delete))
        val log = server.logs.getValue(vaultId)
        a1.refresh(vaultId, log.size - 1L, server.hashOf(log.last()))
        val appends = server.appends
        assertIs<HeldRepost.Stored>(a1.repostAsHeld(vaultId))
        assertEquals(appends, server.appends, "not sent a second time")
        assertEquals(HeldRepost.NothingHeld, a1.repostAsHeld(vaultId))
    }

    @Test fun aHeldChangeWhosePlaceWasTakenIsDroppedByTheLogsOwnRule() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, a2) = sharedVault(server, SharedState(), spy)

        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Delete))
        // No answer: still waiting, and kept.
        assertEquals(HeldRepost.Waiting, a1.repostAsHeld(vaultId))
        server.down = false
        assertIs<AppendOutcome.Appended>(a2.append(vaultId, LogAction.Add(carol.userId, "reader")))

        val signedBefore = spy.signatures
        assertEquals(HeldRepost.Dropped, a1.repostAsHeld(vaultId))
        assertEquals(signedBefore, spy.signatures, "nothing was signed in its place")
        assertTrue(server.entries(vaultId).none { it is LogEntry.Delete }, "the dropped delete was never stored")
        assertEquals(HeldRepost.NothingHeld, a1.repostAsHeld(vaultId))
        // The members are what the log says: carol in, and the vault not deleted.
        val st = assertIs<VaultLogStatus.Verified>(a1.status(vaultId)).state
        assertTrue(carol.userId in st.members && st.deletedId == null)

        // Its place taken and already read by a sync: dropped without sending it.
        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Delete))
        server.down = false
        a2.refresh(vaultId, null, null, force = true)
        assertIs<AppendOutcome.Appended>(a2.append(vaultId, LogAction.Role(carol.userId, "writer")))
        a1.refresh(vaultId, null, null, force = true)
        val appends = server.appends
        assertEquals(HeldRepost.Dropped, a1.repostAsHeld(vaultId))
        assertEquals(appends, server.appends)
    }

    @Test fun aLockInTheMiddleLeavesNothingHalfDone() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val account = SharedState()
        val guard = KeyGuard()
        val device = MemoryDeviceState()
        val a1 = device(server, account, device, guard, spy)
        val vaultId = assertIs<AppendOutcome.Appended>(a1.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a1.append(vaultId, LogAction.Add(bob.userId, "writer")))
        now += 1000

        // A held role change, stored with its answer lost. The caller checks at the head that includes it.
        server.storeThenNoAnswer = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Role(bob.userId, "reader")))
        val log = server.logs.getValue(vaultId)
        val checked = Checkpoint(log.size - 1L, server.hashOf(log.last()))

        // The vault locks while the held change is re-posted, before the delete is built.
        server.onAppend = { guard.wipe() }
        val signedBefore = spy.signatures
        val r = runCatching { a1.append(vaultId, LogAction.Delete, checked) }
        assertTrue(guard.isWiped)
        assertIs<KeysGoneException>(r.exceptionOrNull(), "a lock is said as itself: $r")
        assertEquals(signedBefore, spy.signatures, "no delete was signed after the lock")
        assertTrue(server.entries(vaultId).none { it is LogEntry.Delete })
        assertEquals(1, server.entries(vaultId).count { it is LogEntry.Role }, "the held change is stored once")

        // A re-post-only call under the lock sends nothing.
        server.onAppend = null
        val appends = server.appends
        server.storeThenNoAnswer = false
        assertTrue(runCatching { a1.repostAsHeld(vaultId) }.let { it.isSuccess || it.exceptionOrNull() is KeysGoneException })
        assertEquals(appends, server.appends)

        // The next unlock: whatever was held settles, nothing more is signed, and the delete goes out only when asked.
        val again = device(server, account, device, KeyGuard(), spy)
        assertTrue(again.repostAsHeld(vaultId).let { it is HeldRepost.NothingHeld || it is HeldRepost.Stored })
        assertEquals(signedBefore, spy.signatures)
        assertEquals(3, server.logs.getValue(vaultId).size)

        // A lock while a held change waits to be re-posted: the held frame stays, and nothing is sent.
        val lockGuard = KeyGuard()
        val d2 = MemoryDeviceState()
        val b = device(server, account, d2, lockGuard, spy)
        assertIs<VaultLogStatus.Verified>(b.refresh(vaultId, null, null, force = true))
        server.down = true
        assertEquals(AppendOutcome.Pending, b.append(vaultId, LogAction.Role(bob.userId, "writer")))
        server.down = false
        lockGuard.wipe()
        val sent = server.appends
        assertIs<KeysGoneException>(runCatching { b.repostAsHeld(vaultId) }.exceptionOrNull())
        assertEquals(sent, server.appends, "nothing sent under the lock")
        // Re-posted after the next unlock, byte for byte.
        assertIs<HeldRepost.Stored>(device(server, account, d2, KeyGuard(), spy).repostAsHeld(vaultId))
        assertEquals("writer", server.entries(vaultId).filterIsInstance<LogEntry.Role>().last().role.literal)
    }

    /**
     * The re-post-only call signs nothing on any path: a held change stored at the re-post, and a held delete dropped
     * because another entry took its place. On each, the only entry posted is the held frame itself, byte for byte, and
     * no signature is made.
     */
    @Test fun aRepostSignsAndPostsNothingButTheHeldFrameOnEveryPath() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, a2) = sharedVault(server, SharedState(), spy)

        // Stored at the re-post.
        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Role(bob.userId, "reader")))
        server.down = false
        val held = server.posted.last()
        var signed = spy.signatures
        var from = server.posted.size
        assertIs<HeldRepost.Stored>(a1.repostAsHeld(vaultId))
        assertEquals(listOf(held), server.posted.drop(from), "only the held frame was posted")
        assertEquals(signed, spy.signatures, "nothing was signed")
        assertEquals(held, server.logs.getValue(vaultId).last())

        // Dropped because its place was taken.
        now += 1000
        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Delete))
        server.down = false
        val heldDelete = server.posted.last()
        a2.refresh(vaultId, null, null, force = true)
        assertIs<AppendOutcome.Appended>(a2.append(vaultId, LogAction.Add(carol.userId, "reader")))
        signed = spy.signatures
        from = server.posted.size
        val stored = server.logs.getValue(vaultId).size
        assertEquals(HeldRepost.Dropped, a1.repostAsHeld(vaultId))
        assertEquals(listOf(heldDelete), server.posted.drop(from), "only the held frame was posted")
        assertEquals(signed, spy.signatures, "nothing was signed in its place")
        assertEquals(stored, server.logs.getValue(vaultId).size, "no entry was stored")
    }

    /**
     * The review's sequence, at the log's level: a member whose user id is all zeros (a server can register such an
     * account and have it added), a held change of this device, then an ownership offer to that id. The held change is
     * re-posted and stored, and the offer is never built: no action that names the all-zero id is signed. A role change
     * or a removal naming it is refused the same way.
     */
    @Test fun noActionNamingTheAllZeroUserIdIsEverBuilt() = runBlocking<Unit> {
        val server = Server()
        val spy = Signing(crypto)
        val (vaultId, a1, _) = sharedVault(server, SharedState(), spy)

        // Another of alice's devices (the test, signing with her key) adds the account the server registered as all zeros.
        val log = server.logs.getValue(vaultId)
        val s = VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state!!
        val pos = VaultLog.position(s, now)
        val add = LogEntry.Add(vaultId, pos.seq, pos.prev, alice.userId, pos.at, io.silencelen.andvari.core.client.UserIds.NIL, carol.pub,
            io.silencelen.andvari.core.trust.MemberRole.fromLiteral("writer")!!, Bytes.toB64(crypto.randomBytes(16)))
        log += Bytes.toB64((VaultLog.signChecked(crypto, alice.sign, s, add) as Checked.Ok).value.frame)
        assertTrue(io.silencelen.andvari.core.client.UserIds.NIL in assertIs<VaultLogStatus.Verified>(a1.refresh(vaultId, null, null, force = true)).state.members)
        now += 1000

        server.down = true
        assertEquals(AppendOutcome.Pending, a1.append(vaultId, LogAction.Role(bob.userId, "reader")))
        server.down = false
        val held = server.posted.last()
        val signed = spy.signatures
        val from = server.posted.size
        assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.NIL_USER_ID), a1.append(vaultId, LogAction.Offer(io.silencelen.andvari.core.client.UserIds.NIL, 60_000L)))
        assertEquals(listOf(held), server.posted.drop(from), "the held change was re-posted, and nothing else")
        assertEquals(signed, spy.signatures, "the offer was never signed")
        assertTrue(server.entries(vaultId).none { it is LogEntry.Offer })
        for (action in listOf(LogAction.Role(io.silencelen.andvari.core.client.UserIds.NIL, "reader"), LogAction.Remove(io.silencelen.andvari.core.client.UserIds.NIL),
            LogAction.Add(io.silencelen.andvari.core.client.UserIds.NIL, "reader", releaseUncompared = true))) {
            assertEquals(AppendOutcome.NotAllowed(StoredVaultLogs.NIL_USER_ID), a1.append(vaultId, action), "$action")
        }
        assertEquals(signed, spy.signatures)
        assertEquals(listOf(held), server.posted.drop(from))
    }
}
