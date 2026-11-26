package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.ServedVaults
import io.silencelen.andvari.core.client.items.SessionVaultKeys
import io.silencelen.andvari.core.client.items.VaultRows
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.SelfWrapPut
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What a second device of one account learns by itself (design §3.6, §5.3, §5.4, §8.5): two devices of Bob, each with
 * its OWN device state and its OWN copy of the account state (the real [StoredAccountState] over a scripted
 * `/account/state` with compare-and-set), the real vault-log engine and [SessionVaultKeys] driven by delta syncs of a
 * scripted server that stores frames, grant rows and self-wraps the way spec 03 §10.3 and §11.4 say.
 *
 * The fault these pin (found on the bench): a second device of Bob answered "connect first" for a
 * vault Bob had accepted on his first device. The adoption read the person's answer (`accepted`) from this device's own
 * copy of the account state, and no sync ever read the served one, so the answer given on the first device never
 * reached the second, and the self-wrap the first device posted could not be used (design §3.6 (d), second bullet).
 */
class SecondDeviceTest {
    private val crypto = createCryptoProvider()

    private inner class Person(val userId: String, val seed: Byte, val personalVaultId: String) {
        val pub: String = Bytes.toB64(crypto.boxKeypairFromSeed(ByteArray(32) { seed }).publicKey)

        /** A fresh opened account of this person, as each device holds its own (its wipe zeroes only its own copies). */
        fun opened(): OpenedAccount {
            val box = crypto.boxKeypairFromSeed(ByteArray(32) { seed })
            val genesis = VerifiedGenesis(GenesisFields(userId, Bytes.toB64(box.publicKey), "instance", personalVaultId, 0), "00".repeat(32))
            return OpenedAccount(userId, ByteArray(32) { (seed + 1).toByte() }, box, crypto.signKeypairFromSeed(ByteArray(32) { seed }), genesis, personalVaultId, ByteArray(32) { (seed + 2).toByte() })
        }
    }

    private val alice = Person("11111111-1111-4111-8111-111111111111", 3, "aaaaaaaa-0000-4000-8000-000000000001")
    private val bob = Person("22222222-2222-4222-8222-222222222222", 5, "bbbbbbbb-0000-4000-8000-000000000002")

    private var now = 1_763_164_800_000L

    /**
     * What the sync answer says of the account state's counter: nothing told (a host before the counter), the truth, the
     * value this device last saw (the counter made to stand still), one below the truth, far above it, or none served.
     */
    private enum class Counter { NONE, TRUE, STILL, BACK, JUMP, ABSENT }

    /** What a self-wrap post comes to on the server. */
    private enum class WrapPost { STORE, DROP_500, DROP_OK }

    /** One server: the stored chains, grant rows, vault rows (each with the global rev of its last change) and account states. */
    private inner class Server {
        var rev = 0L
        val logs = HashMap<String, MutableList<String>>()
        val vaultRev = HashMap<String, Long>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        val states = HashMap<String, Pair<String?, Long>>()
        val stateReads = HashMap<String, Int>()
        val wrapPosts = HashMap<String, Int>()
        var wrapPost = WrapPost.STORE

        /** Run once, at the next self-wrap post, BEFORE the server acts on it (a sync of another device "meanwhile"). */
        var beforeWrap: (suspend () -> Unit)? = null

        fun head(vaultId: String): SyncLogHead {
            val log = logs.getValue(vaultId)
            return SyncLogHead(log.size - 1L, Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last()))))
        }

        fun vaultRow(vaultId: String) = SyncVault(vaultId, "shared", vaultRev.getValue(vaultId), "meta", 0, head(vaultId))

        fun client(user: String): WireClient = object : WireClient {
            override val origin = "https://h.example"
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                when (route) {
                    WireRoute.ACCOUNT_STATE_GET -> {
                        stateReads[user] = (stateReads[user] ?: 0) + 1
                        val (blob, cas) = states[user] ?: (null to 0L)
                        WireResult.Ok(decode(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(blob, cas))), 200)
                    }
                    WireRoute.ACCOUNT_STATE_PUT -> {
                        val put = WireJson.json.decodeFromString(AccountStatePut.serializer(), bodyJson!!)
                        val cas = states[user]?.second ?: 0L
                        if (put.baseSeq != cas) WireResult.Refused(409, WireError(WireErrors.STALE_STATE, "m"))
                        else {
                            states[user] = put.sealedState to cas + 1
                            WireResult.Ok(decode(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(put.sealedState, cas + 1))), 200)
                        }
                    }
                    WireRoute.LOG_FETCH -> {
                        val log = logs.getValue(pathParams.getValue("vaultId"))
                        val from = ((query?.removePrefix("after=")?.toLong() ?: -1L) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        val h = head(pathParams.getValue("vaultId"))
                        WireResult.Ok(decode(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, LogHead(h.seq, h.hash, 0)))), 200)
                    }
                    WireRoute.LOG_APPEND -> append(user, pathParams.getValue("vaultId"), bodyJson!!, decode)
                    WireRoute.VAULT_SELF_WRAP -> {
                        val vaultId = pathParams.getValue("vaultId")
                        wrapPosts[user] = (wrapPosts[user] ?: 0) + 1
                        beforeWrap?.let { hook -> beforeWrap = null; hook() }
                        when (wrapPost) {
                            WrapPost.DROP_500 -> WireResult.Refused(500, WireError("internal", "m"))
                            WrapPost.DROP_OK -> WireResult.Ok(decode("{\"rev\":1}"), 200)
                            WrapPost.STORE -> {
                                val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                                grants[vaultId to user] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk, rev = ++rev)
                                WireResult.Ok(decode("{\"rev\":$rev}"), 200)
                            }
                        }
                    }
                    else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                }
        }

        private fun <T> append(user: String, vaultId: String, bodyJson: String, decode: (String) -> T): WireResult<T> {
            val log = logs.getOrPut(vaultId) { ArrayList() }
            val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson)
            val frame = Bytes.fromB64(req.entry)
            if (req.entry !in log) {
                val prior = VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                when (val v = VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD)) {
                    is Checked.Refused -> return WireResult.Refused(400, WireError(v.verdict.code, "m"))
                    is Checked.Ok -> {}
                }
                log += req.entry
                when (val e = VaultLog.parse(crypto, frame).valueOrNull()?.entry) {
                    is LogEntry.Genesis -> grants[vaultId to user] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, ++rev)
                    is LogEntry.Add -> grants[vaultId to e.member] = SyncGrant(vaultId, e.member, e.role.literal, "", ++rev, req.grant)
                    is LogEntry.Accept -> {
                        for ((key, g) in grants.toList()) if (key.first == vaultId && g.role == "owner") grants[key] = g.copy(role = "writer", rev = ++rev)
                        grants[vaultId to user] = grants.getValue(vaultId to user).copy(role = "owner", wrappedVk = req.wrappedVk!!, rev = ++rev)
                    }
                    else -> {}
                }
                vaultRev[vaultId] = ++rev
            }
            val h = head(vaultId)
            return WireResult.Ok(decode(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(1, LogHead(h.seq, h.hash, 0)))), 200)
        }
    }

    /**
     * One device: its own device state, its own account-state copy, its own engines. [contacts] are the contacts CURRENT on
     * it (design §6.9): a device linked from another one carries them, a password-only device has none (design §8.5).
     * Its syncs are deltas from its own cursors, the vault rows and the grant rows each with their own, so a test can
     * serve one kind of row in an earlier answer than the other.
     */
    private inner class Device(val server: Server, val p: Person, val contacts: Map<String, String> = emptyMap()) {
        val state = MemoryDeviceState()
        val account = p.opened()
        val client = server.client(p.userId)
        val store = StoredAccountState(p.userId, account.uvk, client, crypto, state)
        val rows = VaultRows(crypto)
        val host = object : VaultLogHost {
            override fun grantRow(vaultId: String) = rows.grantRow(vaultId)
            override fun isCurrentContact(userId: String, identityPub: String) = contacts[userId] == identityPub
            override fun currentContact(userId: String) = contacts[userId]?.let { it to true }
            override fun labelFor(userId: String, identityPub: String) = if (contacts[userId] == identityPub) "Alice" else null
            override fun vaultName(vaultId: String, vk: ByteArray) = "Family"
            override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
            override fun serverOwnerName(vaultId: String) = "someone"
        }
        val engine = StoredVaultLogs.forAccount(account, client, crypto, state, store, host, { now }, { null })

        val logs = Recording(engine)
        val keys = SessionVaultKeys(account, logs, rows, state)
        private var vaultCursor = 0L
        private var grantCursor = 0L

        /** One delta sync: the rows changed since this device's cursors, and the trust engine's pass over them. */
        suspend fun sync(vaults: Boolean = true, grants: Boolean = true, counter: Counter = Counter.NONE) {
            val v = if (!vaults) emptyList() else server.vaultRev.filter { (id, r) -> r > vaultCursor && server.grants.containsKey(id to p.userId) }.keys.sorted().map { server.vaultRow(it) }
            val g = if (!grants) emptyList() else server.grants.values.filter { it.userId == p.userId && it.rev > grantCursor }.sortedBy { it.vaultId }
            if (vaults) vaultCursor = server.rev
            if (grants) grantCursor = server.rev
            // The sync answer's `accountStateSeq` (spec 03 §4), told before the round's refreshes, as the sync does.
            val truth = server.states[p.userId]?.second ?: 0L
            val told: Long? = when (counter) {
                Counter.NONE -> null
                Counter.TRUE -> truth
                Counter.STILL -> store.heldCounter()
                Counter.BACK -> truth - 1
                Counter.JUMP -> truth + 1000
                Counter.ABSENT -> null
            }
            keys.served(ServedVaults(false, v, g, emptySet(), told))
        }

        /**
         * What the vault's row shows after the sync: the outcome that adopted the key, or else the app's own pass right
         * after the sync (`EngineSharedVaults.refresh` asks [VaultLogEngine.adoption] again for a vault not adopted).
         */
        suspend fun shown(vaultId: String): Adoption =
            if (logs.copyOutAllowed(vaultId)) logs.outcomes.getValue(vaultId) else logs.adoption(vaultId)

        fun reads(vaultId: String): Boolean = keys.access(vaultId) != null && key(vaultId) != null

        fun key(vaultId: String): ByteArray? = engine.keyFor(vaultId)
    }

    /** The engine, with every adoption's outcome kept: the sync's own pass drops it, the test reads it. */
    private class Recording(val engine: StoredVaultLogs) : VaultLogEngine by engine {
        val outcomes = HashMap<String, Adoption>()
        override suspend fun adoption(vaultId: String): Adoption = engine.adoption(vaultId).also { outcomes[vaultId] = it }
    }

    /** Alice creates "Family" and adds Bob as a writer. */
    private suspend fun aliceShares(server: Server): Pair<Device, String> {
        val a = Device(server, alice, mapOf(bob.userId to bob.pub))
        val v = assertIs<AppendOutcome.Appended>(a.logs.append(null, LogAction.Create("Family"))).state.vaultId
        now += 1000
        assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Add(bob.userId, "writer")))
        now += 1000
        return a to v
    }

    /** Bob's first device: Alice is current on it (it was the device that connected). It syncs and is asked. */
    private suspend fun firstDeviceAsked(server: Server, v: String): Pair<Device, Adoption.AskAccept> {
        val b1 = Device(server, bob, mapOf(alice.userId to alice.pub))
        b1.sync()
        return b1 to assertIs<Adoption.AskAccept>(b1.shown(v), "a grant from a current contact is asked, never adopted unasked")
    }

    private suspend fun accept(b1: Device, ask: Adoption.AskAccept) {
        assertEquals(Adoption.Adopted(ask.vaultId, KeySource.GRANT), b1.logs.answerIncoming(ask, accept = true))
    }

    @Test fun aSecondDeviceSignedInAfterTheAcceptAdoptsThroughTheSelfWrapByItself() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = aliceShares(server)
        val (b1, ask) = firstDeviceAsked(server, v)
        accept(b1, ask)
        assertTrue(server.grants.getValue(v to bob.userId).wrappedVk.isNotEmpty(), "the first device posted the self-wrap")

        // Signed in with the password only, after the accept: no current contacts, a copy of the account state never read.
        val b2 = Device(server, bob)
        b2.sync()
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), b2.shown(v), "the account's answer and its self-wrap: adopted by itself")
        assertTrue(b2.reads(v))
        assertContentEquals(a.key(v), b2.key(v))
        assertEquals(ask.addSeq, b2.store.local().accepted.getValue(v).addSeq, "the answer given on the first device is now held here too")
        assertEquals(1, server.wrapPosts[bob.userId], "the second device posted no wrap of its own")

        // Asked about nothing afterwards, and the next sync reads the account state no more (nothing waits for an answer).
        val reads = server.stateReads.getValue(bob.userId)
        b2.sync()
        assertEquals(reads, server.stateReads.getValue(bob.userId))
    }

    @Test fun aSecondDeviceSignedInBeforeTheAcceptGetsTheVaultAtTheFirstSyncAfterIt() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = aliceShares(server)
        val b2 = Device(server, bob)
        b2.sync()
        // Before the accept: no answer anywhere, and no contact current here. The design's "Connect with them first" is what
        // a password-only device can say (the app shows it as "confirm the contact" when the sender is a contact, §8.5).
        assertIs<Adoption.ConnectFirst>(b2.shown(v))
        assertTrue(!b2.reads(v))
        val readsBefore = server.stateReads[bob.userId] ?: 0
        assertTrue(readsBefore in 1..2, "one read for the sync's pass (and at most one for the app's own pass): $readsBefore")

        val (b1, ask) = firstDeviceAsked(server, v)
        accept(b1, ask)
        now += 1000
        b2.sync()
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), b2.shown(v))
        assertTrue(b2.reads(v))
    }

    @Test fun aSyncBetweenTheAnswerAndItsSelfWrapIsNeverAskedAndAdoptsOnceTheWrapIsThere() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = aliceShares(server)
        val b2 = Device(server, bob)
        // A device linked from the first one: Alice is current on it too (design §8.3).
        val b3 = Device(server, bob, mapOf(alice.userId to alice.pub))
        b2.sync()
        b3.sync()
        assertIs<Adoption.ConnectFirst>(b2.shown(v))
        assertIs<Adoption.AskAccept>(b3.shown(v), "before the answer, a linked device is asked like the first")

        val (b1, ask) = firstDeviceAsked(server, v)
        var meanwhile2: Adoption? = null
        var meanwhile3: Adoption? = null
        // The answer is in the account state; the self-wrap's post has reached the server, which has not acted on it yet.
        server.beforeWrap = {
            now += 1000
            b2.sync()
            meanwhile2 = b2.shown(v)
            b3.sync()
            meanwhile3 = b3.shown(v)
        }
        accept(b1, ask)
        // The password-only device has no key yet (the grant needs a current contact, the wrap is not stored): it adopts
        // nothing and is asked nothing. The linked one is not asked again: it takes the grant under the account's answer.
        assertIs<Adoption.ConnectFirst>(meanwhile2)
        assertEquals(Adoption.Adopted(v, KeySource.GRANT), meanwhile3, "the account answered: a linked device does not ask again")
        assertTrue(!b2.reads(v))

        now += 1000
        b2.sync()
        assertTrue(server.grants.getValue(v to bob.userId).wrappedVk.isNotEmpty())
        assertIs<Adoption.Adopted>(b2.shown(v))
        assertTrue(b2.reads(v))
        assertContentEquals(b1.key(v), b2.key(v))
    }

    @Test fun aSelfWrapPostThatDidNotLandIsPostedAgainAndTheSecondDeviceThenAdopts() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = aliceShares(server)
        val (b1, ask) = firstDeviceAsked(server, v)
        server.wrapPost = WrapPost.DROP_500
        accept(b1, ask)
        assertEquals(1, server.wrapPosts[bob.userId])
        assertTrue(server.grants.getValue(v to bob.userId).wrappedVk.isEmpty(), "the post did not land")

        val b2 = Device(server, bob)
        b2.sync()
        assertIs<Adoption.ConnectFirst>(b2.shown(v), "no wrap stored: nothing a password-only device can open")

        // The first device's next syncs: not again within the retry interval, then once.
        b1.sync()
        assertEquals(1, server.wrapPosts[bob.userId], "an unanswered post is not repeated at every sync")
        now += StoredVaultLogs.WRAP_RETRY_MS
        b1.sync()
        assertEquals(2, server.wrapPosts[bob.userId])
        // Still refused: once more only after the interval again.
        b1.sync()
        assertEquals(2, server.wrapPosts[bob.userId])
        server.wrapPost = WrapPost.STORE
        now += StoredVaultLogs.WRAP_RETRY_MS
        b1.sync()
        assertEquals(3, server.wrapPosts[bob.userId])
        assertTrue(server.grants.getValue(v to bob.userId).wrappedVk.isNotEmpty(), "the re-post landed")

        b2.sync()
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), b2.shown(v))
        assertContentEquals(b1.key(v), b2.key(v))
        // With the wrap on the row, nothing more is posted.
        now += StoredVaultLogs.WRAP_RETRY_MS
        b1.sync()
        assertEquals(3, server.wrapPosts[bob.userId])
    }

    @Test fun aServerThatAnswersAPostItDidNotStoreGetsOnePostPerChangeOfTheRowNeverOnePerSync() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = aliceShares(server)
        val (b1, ask) = firstDeviceAsked(server, v)
        server.wrapPost = WrapPost.DROP_OK
        accept(b1, ask)
        repeat(3) {
            now += StoredVaultLogs.WRAP_RETRY_MS
            b1.sync()
        }
        assertEquals(1, server.wrapPosts[bob.userId], "the row it answered for is still the one served")
        // The row changes (a role change by Alice) and still carries no wrap: posted once more.
        assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Role(bob.userId, "reader")))
        server.grants[v to bob.userId] = server.grants.getValue(v to bob.userId).copy(role = "reader", rev = ++server.rev)
        b1.sync()
        b1.sync()
        assertEquals(2, server.wrapPosts[bob.userId])
    }

    @Test fun theVaultRowAndTheGrantRowInSeparateAnswersInEitherOrder() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = aliceShares(server)
        val (b1, ask) = firstDeviceAsked(server, v)
        accept(b1, ask)

        // The vault row first, its grant row in a later answer.
        val early = Device(server, bob)
        early.sync(grants = false)
        assertIs<Adoption.Refused>(early.shown(v), "no grant row yet: no key, nothing asked")
        assertTrue(!early.reads(v))
        early.sync(vaults = false)
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), early.shown(v))

        // The grant row first: the vault is not listed yet, so nothing is decided; then the vault row.
        val late = Device(server, bob)
        late.sync(vaults = false)
        assertIs<VaultLogStatus.Unknown>(late.logs.status(v))
        assertTrue(!late.reads(v))
        late.sync(grants = false)
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), late.shown(v))
        assertTrue(late.reads(v))
    }

    @Test fun anAnswerTheServerWithholdsFromTheSecondDeviceAdoptsNothing() = runBlocking<Unit> {
        // The server alone can withhold the account state (or serve an older one): the self-wrap alone never adopts.
        val server = Server()
        val (_, v) = aliceShares(server)
        val (b1, ask) = firstDeviceAsked(server, v)
        val beforeAnswer = server.states[bob.userId]
        accept(b1, ask)
        val withAnswer = server.states.getValue(bob.userId)
        server.states[bob.userId] = beforeAnswer ?: (null to withAnswer.second)
        val b2 = Device(server, bob)
        b2.sync()
        assertIs<Adoption.ConnectFirst>(b2.shown(v), "a wrap without the account's answer to the latest add is never used")
        assertTrue(!b2.reads(v))
        server.states[bob.userId] = withAnswer
        now += 1000
        b2.sync()
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), b2.shown(v))
    }

    @Test fun theAccountStateIsReadOncePerSyncRoundHoweverManyVaultsWaitForAnAnswer() = runBlocking<Unit> {
        val server = Server()
        val a = Device(server, alice, mapOf(bob.userId to bob.pub))
        val vaults = (1..3).map { n ->
            val v = assertIs<AppendOutcome.Appended>(a.logs.append(null, LogAction.Create("Family $n"))).state.vaultId
            now += 1000
            assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Add(bob.userId, "writer")))
            now += 1000
            v
        }
        // A password-only device and a linked one: three invitations, none answered anywhere.
        for (d in listOf(Device(server, bob), Device(server, bob, mapOf(alice.userId to alice.pub)))) {
            val before = server.stateReads[bob.userId] ?: 0
            d.sync()
            assertEquals(before + 1, server.stateReads[bob.userId] ?: 0, "one read in the sync round, not one per vault")
            // The app's own pass right after the sync is part of that round: it reads nothing more.
            for (v in vaults) assertTrue(d.shown(v) is Adoption.ConnectFirst || d.shown(v) is Adoption.AskAccept)
            assertEquals(before + 1, server.stateReads[bob.userId] ?: 0, "the app's pass after the sync reads nothing more")
            // A vault refreshed again within the round (a forced re-read of one log) does not open another read.
            d.logs.refresh(vaults[1], null, null, force = true)
            for (v in vaults) d.shown(v)
            assertEquals(before + 1, server.stateReads[bob.userId] ?: 0, "a refresh of one vault is not a new sync round")
            // The next sync round reads once more, once.
            now += 1000
            d.sync()
            assertEquals(before + 2, server.stateReads[bob.userId] ?: 0)
        }
    }

    private fun Server.reads(user: String) = stateReads[user] ?: 0

    @Test fun anotherDevicesDecisionIsReadOnceWithTheNextSyncAndNothingIsReadWhileTheCounterStandsStill() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = aliceShares(server)
        val b2 = Device(server, bob)
        b2.sync(counter = Counter.TRUE)
        assertIs<Adoption.ConnectFirst>(b2.shown(v))
        assertEquals(1, server.reads(bob.userId), "this device had never seen the counter: one read")
        // The invitation still waits for an answer, and before the counter every one of these rounds read the state.
        repeat(3) {
            now += 1000
            b2.sync(counter = Counter.TRUE)
            assertIs<Adoption.ConnectFirst>(b2.shown(v))
        }
        assertEquals(1, server.reads(bob.userId), "nothing is read while the counter stands still")

        // The first device answers, and its write moves the counter.
        val (b1, ask) = firstDeviceAsked(server, v)
        accept(b1, ask)
        val before = server.reads(bob.userId)
        now += 1000
        b2.sync(counter = Counter.TRUE)
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), b2.shown(v), "the other device's decision arrives with the next sync")
        assertEquals(before + 1, server.reads(bob.userId), "and is read once")
        assertContentEquals(b1.key(v), b2.key(v))
        repeat(2) { b2.sync(counter = Counter.TRUE) }
        assertEquals(before + 1, server.reads(bob.userId))
    }

    @Test fun aCounterThatGoesBackOrJumpsIsReadAndOneHeldStillOverAWriteOnlyWithholdsIt() = runBlocking<Unit> {
        val server = Server()
        val (_, v) = aliceShares(server)
        val b2 = Device(server, bob)
        b2.sync(counter = Counter.TRUE)
        assertIs<Adoption.ConnectFirst>(b2.shown(v))
        for (told in listOf(Counter.BACK, Counter.JUMP, Counter.ABSENT, Counter.NONE)) {
            val before = server.reads(bob.userId)
            now += 1000
            b2.sync(counter = told)
            assertIs<Adoption.ConnectFirst>(b2.shown(v))
            assertEquals(before + 1, server.reads(bob.userId), "$told: read, never skipped")
        }

        // The first device answers; the server says the counter stands where this device last saw it.
        val (b1, ask) = firstDeviceAsked(server, v)
        accept(b1, ask)
        val before = server.reads(bob.userId)
        repeat(2) {
            now += 1000
            b2.sync(counter = Counter.STILL)
            assertIs<Adoption.ConnectFirst>(b2.shown(v), "withheld, as a server serving the older state would withhold it")
        }
        assertEquals(before, server.reads(bob.userId))
        assertTrue(!b2.reads(v), "nothing is adopted without the account's answer")
        // The counter moves (or the server stops sending it): read once, and the answer is taken.
        now += 1000
        b2.sync(counter = Counter.TRUE)
        assertEquals(Adoption.Adopted(v, KeySource.SELF_WRAP), b2.shown(v))
        assertEquals(before + 1, server.reads(bob.userId))
        assertContentEquals(b1.key(v), b2.key(v))
    }

    @Test fun whatElseASecondDeviceLearnsByItself() = runBlocking<Unit> {
        val server = Server()
        val (a, v) = aliceShares(server)

        // A vault the account owns: the owner wrap, with no answer needed (design §3.6 (d), first bullet).
        val a2 = Device(server, alice)
        a2.sync()
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), a2.shown(v))
        assertContentEquals(a.key(v), a2.key(v))

        // The personal vault: from the account itself, on any device (design §5.3).
        val b2 = Device(server, bob)
        assertNotNull(b2.keys.access(bob.personalVaultId))

        val (b1, ask) = firstDeviceAsked(server, v)
        accept(b1, ask)
        b2.sync()
        assertIs<Adoption.Adopted>(b2.shown(v))

        // An ownership offer: from the verified log, on every device of the account.
        now += 1000
        assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Offer(bob.userId, 86_400_000L)))
        b2.sync()
        val pending = assertNotNull(assertIs<VaultLogStatus.Verified>(b2.logs.status(v)).state.pending, "the second device sees the offer")
        assertEquals(bob.userId, pending.to)
        // Accepted on the first device: a third device of Bob, signed in afterwards, adopts the vault as its owner.
        now += 1000
        b1.sync()
        assertIs<AppendOutcome.Appended>(b1.logs.append(v, LogAction.Accept))
        val b3 = Device(server, bob)
        b3.sync()
        assertEquals(Adoption.Adopted(v, KeySource.OWNER_WRAP), b3.shown(v))
        b2.sync()
        assertEquals(bob.userId, assertIs<VaultLogStatus.Verified>(b2.logs.status(v)).state.owner, "and the second sees itself the owner")
        assertTrue(b2.logs.writeAllowed(v))
        assertNull(assertIs<VaultLogStatus.Verified>(b2.logs.status(v)).state.pending)
    }
}
