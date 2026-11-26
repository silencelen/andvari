package io.silencelen.andvari.core.client.items

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.HttpRequestTimeoutException
import io.ktor.http.HttpStatusCode
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.content.ContentHost
import io.silencelen.andvari.core.app.content.EngineVaultContent
import io.silencelen.andvari.core.app.content.HeldVaultRow
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogHost
import io.silencelen.andvari.core.client.net.KtorWireClient
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A decline opens the kept copy of a shared vault for the invitation it answers (decided on 24 November 2026), whatever
 * the server answered, did not answer or stored, and also when this device's own store throws while the decline is
 * written. An accept whose outcome is not known keeps the copy closed, as before.
 *
 * Each course: the person is removed from a shared vault holding `wifi`, the device keeps the copy with its day, three
 * days on the owner adds the person again, and the invitation shows: the copy is closed. The server then answers the two
 * writes that carry the person's answer (the account state's PUT and this account's log appends) as the case says, and
 * everything else honestly. The person answers accept, decline, accept, decline; each answer is followed by the app's
 * sync and, an hour on, by a later sync. The screen's copy-out is tried until it has copied once; after that only the
 * engine's gate is read, so that the count on the copy's day is exact. On its day the copy goes from the device, and the
 * personal vault holds the one item copied out of it.
 *
 * Real: the item engine and the content layer the screens draw ([EngineVaultContent]: `refresh` is the app's sync,
 * `saveVaultItemsToPersonal` the screen's copy-out); the trust engine ([StoredVaultLogs] behind [SessionVaultKeys]); the
 * account state ([StoredAccountState]); and, for each broken write, the wire client ([KtorWireClient]) over a mock
 * engine, so the product's own reading of a status and a body decides what the engine sees. Stand-ins: the log server
 * ([LogServerStandIn]), the item server ([FakeItemServer]) and an honest account-state server in memory.
 */
class KeptCopyDeclineCoursesTest {
    /** How the server answers the writes that carry the person's answer. */
    private sealed class Writes {
        class Http(val status: Int, val body: String) : Writes()

        /** No answer: the client's timeout. */
        object Timeout : Writes()

        /** No answer: a broken connection. */
        object Reset : Writes()

        /** The answer an honest server gives, for a write it then does not keep. */
        object Lie : Writes()
    }

    /** This device's own records, whose writes can be made to throw (a full or failing disk). */
    private class Store : DeviceState {
        private val d = MemoryDeviceState()
        var refusing = false
        override fun get(key: String): String? = d.get(key)
        override fun keys(): Set<String>? = d.keys()
        override fun set(key: String, value: String?) {
            if (refusing) throw IllegalStateException(REFUSED)
            d.set(key, value)
        }
    }

    /**
     * This account's wire: the account state honestly in memory (GET, and PUT with its compare-and-set), the log routes of
     * the stand-in log server, and, while [writes] is set, the account state's PUT and every log append answered as it
     * says, through the real [KtorWireClient] over a mock engine.
     */
    private class Wire(private val logServer: LogServerStandIn, user: String, private val crypto: CryptoProvider) : WireClient {
        override val origin = "https://h.example"
        private val logs = logServer.client(user)
        private var sealed: String? = null
        private var seq = 0L
        var writes: Writes? = null

        private val ktor = KtorWireClient(origin, HttpClient(MockEngine { _ ->
            when (val w = writes) {
                is Writes.Http -> respond(w.body, HttpStatusCode.fromValue(w.status))
                Writes.Timeout -> throw HttpRequestTimeoutException("https://h.example/api/v1", 30_000L)
                Writes.Reset -> throw IllegalStateException("connection reset by peer")
                else -> error("only a broken write reaches the mock engine")
            }
        }), "android")

        override suspend fun <T> call(
            route: WireRoute,
            pathParams: Map<String, String>,
            query: String?,
            bodyJson: String?,
            authenticated: Boolean,
            decode: (String) -> T,
        ): WireResult<T> {
            val w = writes
            if (w != null && (route == WireRoute.ACCOUNT_STATE_PUT || route == WireRoute.LOG_APPEND)) {
                if (w === Writes.Lie) return lie(route, pathParams, bodyJson!!, decode)
                return ktor.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
            return when (route) {
                WireRoute.ACCOUNT_STATE_GET ->
                    WireResult.Ok(decode(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(sealed, seq))), 200)
                WireRoute.ACCOUNT_STATE_PUT -> {
                    val put = WireJson.json.decodeFromString(AccountStatePut.serializer(), bodyJson!!)
                    if (put.baseSeq != seq) {
                        WireResult.Refused(409, WireError(WireErrors.STALE_STATE, "m"))
                    } else {
                        sealed = put.sealedState
                        seq += 1
                        WireResult.Ok(decode(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(sealed, seq))), 200)
                    }
                }
                else -> logs.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }

        private fun <T> lie(route: WireRoute, pathParams: Map<String, String>, body: String, decode: (String) -> T): WireResult<T> =
            if (route == WireRoute.ACCOUNT_STATE_PUT) {
                val put = WireJson.json.decodeFromString(AccountStatePut.serializer(), body)
                WireResult.Ok(decode(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(put.sealedState, seq + 1))), 200)
            } else {
                val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), body)
                val log = logServer.logs[pathParams.getValue("vaultId")].orEmpty()
                val hash = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(req.entry)))
                WireResult.Ok(decode(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(1, LogHead(log.size.toLong(), hash, 0)))), 200)
            }
    }

    /**
     * The item engine and the content layer over the real trust engine and the real account state on [Wire]; the
     * stand-in log server and item server; a second account, [owner], that owns the shared vault.
     */
    private class Bed {
        private class Person(crypto: CryptoProvider, val userId: String, seed: Byte) {
            val sign = crypto.signKeypairFromSeed(ByteArray(32) { seed })
            val box = crypto.boxKeypairFromSeed(ByteArray(32) { seed })
            val uvk = ByteArray(32) { (seed + 1).toByte() }
            val pub: String = Bytes.toB64(box.publicKey)
        }

        private inner class Host(val user: String, val contacts: Map<String, String>) : VaultLogHost {
            override fun grantRow(vaultId: String) = logServer.grants[vaultId to user]
            override fun isCurrentContact(userId: String, identityPub: String) = contacts[userId] == identityPub
            override fun currentContact(userId: String) = contacts[userId]?.let { it to true }
            override fun labelFor(userId: String, identityPub: String) = if (contacts[userId] == identityPub) "Owner" else null
            override fun vaultName(vaultId: String, vk: ByteArray) = "Family"
            override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
            override fun serverOwnerName(vaultId: String) = "someone"
        }

        private class Screen(val r: ItemRig) : ContentHost {
            override fun timeZone(): kotlinx.datetime.TimeZone = kotlinx.datetime.TimeZone.UTC
            override fun wallMs(): Long = r.now
            override fun attachmentLimits() = AttachmentRules.limits(null, null)
            override fun origin(): String = "https://vault.example.com"
            override fun userId(): String = r.userId
            override fun accountId(): String = "0123456789abcdef0123456789abcdef"
            override fun backupKdfParams(): KdfParams? = null
            override fun openInvitationName(vaultId: String): String? = "Family"
        }

        private val crypto0: CryptoProvider = io.silencelen.andvari.core.crypto.createCryptoProvider()
        val logServer = LogServerStandIn(crypto0)
        private val ownerP = Person(crypto0, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", 3)
        private val meSeed: Byte = 5
        val device = Store()
        private val contacts = HashMap(mapOf(ownerP.userId to ownerP.pub))
        lateinit var wire: Wire
        lateinit var logs: StoredVaultLogs
        val rig: ItemRig = ItemRig(InMemoryVaultCache(), trust = { r -> keysFor(r) })
        val owner: StoredVaultLogs = StoredVaultLogs(
            ownerP.userId, ownerP.sign, ownerP.box, ownerP.uvk, logServer.client(ownerP.userId), crypto0, MemoryDeviceState(), AccountStateStandIn(),
            Host(ownerP.userId, mapOf(rig.userId to Bytes.toB64(crypto0.boxKeypairFromSeed(ByteArray(32) { meSeed }).publicKey))), { rig.now }, { null },
        )
        val content = EngineVaultContent(rig.engine, rig.crypto, Screen(rig))

        private fun keysFor(r: ItemRig): VaultKeySource {
            val account = openedFor(r)
            wire = Wire(logServer, r.userId, crypto0)
            logs = StoredVaultLogs.forAccount(account, wire, crypto0, device, StoredAccountState.forAccount(account, wire, crypto0, device), Host(r.userId, contacts), { r.now }, { null })
            return SessionVaultKeys(account, logs, VaultRows(crypto0), device)
        }

        private fun openedFor(r: ItemRig): OpenedAccount {
            val me = Person(crypto0, r.userId, meSeed)
            val genesis = VerifiedGenesis(GenesisFields(r.userId, me.pub, "instance", r.personal, 0), "00".repeat(32))
            return OpenedAccount(r.userId, me.uvk, me.box, me.sign, genesis, r.personal, r.personalKey.copyOf())
        }

        fun vaultRow(s: TrustBed.Shared) = rig.vaultRow(s.vaultId, s.key, "shared", "Family", 1, logServer.head(s.vaultId))
        fun grantRow(s: TrustBed.Shared) = logServer.grants.getValue(s.vaultId to rig.userId)
        fun row(s: TrustBed.Shared, itemId: String, name: String, rev: Long) = rig.itemRow(itemId, s.vaultId, s.key, rig.doc.copy(name = name), rev)

        /** The owner makes a vault holding the items given and adds this account, which accepts: the vault opens here. */
        suspend fun share(items: (TrustBed.Shared) -> List<io.silencelen.andvari.core.model.wire.SyncItem>): TrustBed.Shared {
            val made = owner.append(null, LogAction.Create("Family")) as AppendOutcome.Appended
            val vaultId = made.state.vaultId
            rig.now += 1000
            check(owner.append(vaultId, LogAction.Add(rig.userId, "writer")) is AppendOutcome.Appended)
            logs.refresh(vaultId, null, null, force = true)
            val taken = logs.answerIncoming(logs.adoption(vaultId) as Adoption.AskAccept, accept = true)
            check(taken is Adoption.Adopted) { "the first acceptance is taken: $taken" }
            val s = TrustBed.Shared(vaultId, owner.withKey(vaultId) { KeyCopy(it.copyOf()) }!!.bytes)
            rig.server.queue.add(rig.response(rig.server.rev + 1, vaults = listOf(vaultRow(s)), grants = listOf(grantRow(s)), items = items(s)))
            rig.engine.sync().ok()
            check(rig.engine.vaults().any { it.vaultId == vaultId }) { "the shared vault opens on this device" }
            return s
        }

        /** The owner removes this account from [s]; the server's next answer says the grant ended. */
        suspend fun removeMe(s: TrustBed.Shared) {
            rig.now += 1000
            check(owner.append(s.vaultId, LogAction.Remove(rig.userId)) is AppendOutcome.Appended)
            rig.server.queue.add(rig.response(rig.server.rev + 1, removed = listOf(s.vaultId)))
        }
    }

    /** One course on its own [Bed]: the kept copy, the invitation to its vault, and what the person does. */
    private class Course {
        val b = Bed()
        val r: ItemRig get() = b.rig
        lateinit var s: TrustBed.Shared
        val v: String get() = s.vaultId
        var day = 0L
        var addSeq = -1L

        /** Whether the screen's copy-out has copied once: after that only the engine's gate is read. */
        var copied = false

        fun held(): HeldVaultView? = r.engine.heldVaults().singleOrNull { it.vaultId == v }

        fun row(): HeldVaultRow? {
            b.content.refreshHealth()
            return b.content.state.held.singleOrNull { it.vaultId == v }
        }

        fun personal(): List<String> = r.engine.items().filter { it.vaultId == r.personal }.map { it.doc.name }

        fun assertNotLive(what: String) {
            assertTrue(r.engine.vaults().none { it.vaultId == v }, "$what: not a vault the account may use")
            assertTrue(r.engine.items().none { it.vaultId == v }, "$what: no item of it among the account's items")
        }

        /** An ordinary kept copy: it opens with its day, the screen offers its items, the engine's gate allows a copy-out. */
        fun assertOpen(what: String) {
            val h = assertNotNull(held(), "$what: the kept copy is there")
            assertTrue(h.readable && !h.addedAgain, "$what: open (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertEquals(listOf("wifi"), r.engine.heldItems(v).map { it.doc.name }, "$what: its items read")
            assertEquals(true, row()?.readable, "$what: the screen's row offers its items")
            assertTrue(b.logs.copyOutAllowed(v), "$what: the engine's gate allows a copy-out")
            assertNotLive(what)
        }

        /** Closed for the invitation: nothing of it reads, the screen offers nothing, the engine's gate refuses. */
        fun assertClosed(what: String) {
            val h = assertNotNull(held(), "$what: the kept copy is there")
            assertTrue(!h.readable && h.addedAgain, "$what: closed (readable ${h.readable}, addedAgain ${h.addedAgain})")
            assertEquals(day, h.expungeAt, "$what: its day")
            assertEquals(false, row()?.readable, "$what: the screen's row offers nothing")
            assertTrue(!b.logs.copyOutAllowed(v), "$what: the engine's gate refuses a copy-out")
            assertNotLive(what)
        }

        /** The adoption rules, asked now, ask about the same add (the invitation is there to be answered). */
        suspend fun assertAskedAgain(what: String): Adoption.AskAccept {
            val again = b.logs.adoption(v)
            assertTrue(again is Adoption.AskAccept && again.addSeq == addSeq, "$what: asked again for the same add: $again")
            return again
        }

        /** The server serves the vault's row and this account's grant; the app's sync runs. */
        suspend fun sync() {
            r.server.queue.add(r.response(r.server.rev + 1, vaults = listOf(b.vaultRow(s)), grants = listOf(b.grantRow(s))))
            b.content.refresh()
        }

        /** One hour on, a later sync. */
        suspend fun later() {
            r.now += HOUR
            sync()
        }

        /**
         * The screen's copy-out, until it has copied once: refused with nothing copied while the copy is closed, one `wifi`
         * into the personal vault once it is open. After that, the engine's gate only.
         */
        suspend fun copyOut(what: String, open: Boolean) {
            if (copied) {
                assertEquals(open, b.logs.copyOutAllowed(v), "$what: the engine's gate")
                return
            }
            val before = personal().count { it == "wifi" }
            val res = b.content.saveVaultItemsToPersonal(v)
            if (open) {
                assertEquals(ActionResult.Ok, res, "$what: the screen's copy-out")
                assertEquals(before + 1, personal().count { it == "wifi" }, "$what: one wifi copied into the personal vault")
                copied = true
            } else {
                assertTrue(res !is ActionResult.Ok, "$what: the screen's copy-out is refused: $res")
                assertEquals(before, personal().count { it == "wifi" }, "$what: nothing copied out")
            }
        }

        /**
         * Shared with `wifi`; removed: the copy is kept with its day, open, and the engine's gate allows a copy-out. Three
         * days on the owner adds the person again; the app's sync: asked, closed.
         */
        suspend fun asked() {
            s = b.share { listOf(b.row(it, r.id(), "wifi", 7)) }
            b.removeMe(s)
            r.engine.sync().ok()
            b.content.refresh()
            day = assertNotNull(held(), "removed: the copy is kept").expungeAt
            assertOpen("removed")
            r.now += 3 * DAY
            check(b.owner.append(v, LogAction.Add(r.userId, "writer")) is AppendOutcome.Appended)
            b.logs.refresh(v, null, null, force = true)
            sync()
            assertClosed("added again, the invitation shows")
            val ask = b.logs.adoption(v)
            assertTrue(ask is Adoption.AskAccept, "asked: $ask")
            addSeq = ask.addSeq
        }

        /** The person answers the invitation the adoption rules give now. */
        suspend fun answer(accept: Boolean): Adoption {
            val ask = b.logs.adoption(v)
            assertTrue(ask is Adoption.AskAccept && ask.addSeq == addSeq, "an invitation to answer: $ask")
            return b.logs.answerIncoming(ask, accept)
        }

        /** The copy's day: a sync takes the copy from the device; the personal vault holds the one `wifi` copied out. */
        suspend fun toTheDay() {
            r.now = day + 1
            sync()
            assertEquals(null, held(), "on its day the kept copy goes from this device")
            assertNotLive("on its day")
            assertEquals(listOf("wifi"), personal(), "on its day the personal vault holds exactly the one wifi copied out")
        }
    }

    /**
     * The course for a server whose answer to the writes the engine reads as not known: accept, decline, accept, decline.
     * The first accept keeps the copy closed after the app's sync; the decline opens it from then on.
     */
    private fun notKnown(writes: Writes) = runBlocking<Unit> {
        val c = Course()
        c.asked()
        c.b.wire.writes = writes

        assertEquals(Adoption.AnswerNotKnown(c.v, accepted = true, adopted = false), c.answer(accept = true), "1. the accept")
        c.assertOpen("1. the accept, before the app's sync")
        c.sync()
        c.assertClosed("1. the accept, after the app's sync")
        c.assertAskedAgain("1. the accept, after the app's sync")
        c.copyOut("1. the accept, after the app's sync", open = false)
        c.later()
        c.assertClosed("1. the accept, after a later sync")
        c.copyOut("1. the accept, after a later sync", open = false)

        assertEquals(Adoption.AnswerNotKnown(c.v, accepted = false, adopted = false), c.answer(accept = false), "2. the decline")
        c.assertOpen("2. the decline, before the app's sync")
        c.sync()
        c.assertOpen("2. the decline, after the app's sync")
        c.assertAskedAgain("2. the decline, after the app's sync")
        c.copyOut("2. the decline, after the app's sync", open = true)
        c.later()
        c.assertOpen("2. the decline, after a later sync")
        c.copyOut("2. the decline, after a later sync", open = true)

        for ((n, accept) in listOf(3 to true, 4 to false)) {
            val word = if (accept) "the accept" else "the decline"
            assertEquals(Adoption.AnswerNotKnown(c.v, accepted = accept, adopted = false), c.answer(accept), "$n. $word")
            c.assertOpen("$n. $word, before the app's sync")
            c.sync()
            c.assertOpen("$n. $word, after the app's sync")
            c.assertAskedAgain("$n. $word, after the app's sync")
            c.copyOut("$n. $word, after the app's sync", open = true)
            c.later()
            c.assertOpen("$n. $word, after a later sync")
            c.copyOut("$n. $word, after a later sync", open = true)
        }

        c.toTheDay()
    }

    @Test fun aDeclineOpensTheCopyWhenTheWritesGetA503WithNoBody() = notKnown(Writes.Http(503, ""))

    @Test fun aDeclineOpensTheCopyWhenTheWritesGetA502WhoseBodyIsNotJson() = notKnown(Writes.Http(502, "<html><body>Bad gateway</body></html>"))

    @Test fun aDeclineOpensTheCopyWhenTheWritesGetNoAnswerBeforeTheClientsTimeout() = notKnown(Writes.Timeout)

    @Test fun aDeclineOpensTheCopyWhenTheWritesMeetABrokenConnection() = notKnown(Writes.Reset)

    @Test fun aDeclineOpensTheCopyWhenTheWritesGetA400ThatNamesNoCode() = notKnown(Writes.Http(400, """{"message":"m"}"""))

    @Test fun aDeclineOpensTheCopyWhenTheWritesGetA403WithNoBody() = notKnown(Writes.Http(403, ""))

    /**
     * The course for a server that refuses the writes with an error the engine reads as a refusal: each answer leaves the
     * question standing, and the copy is open after every answer and every sync; it copies out at the first try, and on
     * its day the personal vault holds its item.
     */
    private fun refused(writes: Writes) = runBlocking<Unit> {
        val c = Course()
        c.asked()
        c.b.wire.writes = writes
        for ((n, accept) in listOf(1 to true, 2 to false, 3 to true, 4 to false)) {
            val word = if (accept) "the accept" else "the decline"
            val res = c.answer(accept)
            assertTrue(res is Adoption.AskAccept && res.addSeq == c.addSeq, "$n. $word refused: the question stands: $res")
            c.assertOpen("$n. $word, before the app's sync")
            c.sync()
            c.assertOpen("$n. $word, after the app's sync")
            c.assertAskedAgain("$n. $word, after the app's sync")
            c.copyOut("$n. $word, after the app's sync", open = true)
            c.later()
            c.assertOpen("$n. $word, after a later sync")
            c.copyOut("$n. $word, after a later sync", open = true)
        }
        c.toTheDay()
    }

    @Test fun aRefusalStillOpensTheCopyWhenTheWritesGetA500WithAnErrorCode() = refused(Writes.Http(500, """{"error":"internal","message":"m"}"""))

    @Test fun aRefusalStillOpensTheCopyWhenTheWritesGetA400WhoseCodeIsUnknown() = refused(Writes.Http(400, """{"error":"unknown","message":"m"}"""))

    @Test fun aRefusalStillOpensTheCopyWhenTheWritesGetA400WhoseCodeIsUnreachable() = refused(Writes.Http(400, """{"error":"unreachable","message":"m"}"""))

    @Test fun aRefusalStillOpensTheCopyWhenTheWritesGetA400WhoseCodeIsOriginStopped() = refused(Writes.Http(400, """{"error":"origin_stopped","message":"m"}"""))

    @Test fun aRefusalStillOpensTheCopyWhenTheWritesGetA400WhoseCodeIsRecordUnreadable() = refused(Writes.Http(400, """{"error":"record_unreadable","message":"m"}"""))

    /**
     * A server that answers a decline's writes as stored and keeps neither: the decline is recorded on this device, and
     * the copy is open after the app's sync and a later one; it copies out, and on its day the personal vault holds it.
     */
    @Test
    fun aDeclineTheServerSaysItStoredAndDoesNotKeepOpensTheCopy() = runBlocking<Unit> {
        val c = Course()
        c.asked()
        c.b.wire.writes = Writes.Lie
        assertEquals(Adoption.Declined(c.v), c.answer(accept = false), "the decline")
        c.assertOpen("the decline, before the app's sync")
        c.sync()
        c.assertOpen("the decline, after the app's sync")
        c.copyOut("the decline, after the app's sync", open = true)
        c.later()
        c.assertOpen("the decline, after a later sync")
        c.copyOut("the decline, after a later sync", open = true)
        c.toTheDay()
    }

    /**
     * The server honest throughout; this device's store refuses writes while the person answers. The invitation the
     * screen holds is read with the store working. An accept throws and, once the store writes again, the app's sync asks
     * again and the copy is closed. A decline throws too, and its error is thrown on; once the store writes again, the
     * app's sync asks again for the same add and the copy is open, with no second answer: it copies out, and on its day
     * the personal vault holds its item.
     */
    @Test
    fun aDeclineOpensTheCopyWhenTheDevicesStoreThrowsWhileItIsWritten() = runBlocking<Unit> {
        val c = Course()
        c.asked()
        val held = c.b.logs.adoption(c.v)
        assertTrue(held is Adoption.AskAccept && held.addSeq == c.addSeq, "the invitation the screen holds: $held")

        c.b.device.refusing = true
        val accepted = runCatching { c.b.logs.answerIncoming(held, accept = true) }
        c.b.device.refusing = false
        assertEquals(REFUSED, accepted.exceptionOrNull()?.message, "1. the accept throws the store's error: $accepted")
        c.sync()
        c.assertClosed("1. the accept that threw, after the app's sync")
        val again = c.assertAskedAgain("1. the accept that threw, after the app's sync")

        c.b.device.refusing = true
        val declined = runCatching { c.b.logs.answerIncoming(again, accept = false) }
        c.b.device.refusing = false
        val thrown = declined.exceptionOrNull()
        assertTrue(thrown is IllegalStateException && thrown.message == REFUSED, "2. the decline throws the store's error on: $declined")
        c.sync()
        c.assertOpen("2. the decline that threw, after the app's sync")
        c.assertAskedAgain("2. the decline that threw, after the app's sync")
        c.copyOut("2. the decline that threw, after the app's sync", open = true)
        c.later()
        c.assertOpen("2. the decline that threw, after a later sync")
        c.copyOut("2. the decline that threw, after a later sync", open = true)

        c.toTheDay()
    }

    private companion object {
        const val DAY = 86_400_000L
        const val HOUR = 3_600_000L
        const val REFUSED = "the disk refused the write"
    }
}
