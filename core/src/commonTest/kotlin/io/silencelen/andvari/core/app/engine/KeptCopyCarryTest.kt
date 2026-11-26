package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.state.ContactRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SelfWrapPut
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
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
import kotlin.test.assertTrue

/**
 * A kept copy carried into a new cache (spec 02 §10.6): when the server's rules or the platform's consent turn, the open
 * vault is composed again on a new cache and the held copies are carried into it ([QueuedCarry]). The record of the
 * deletions served for a held copy's items goes with the copy, so a deletion that the server no longer serves does not
 * come back at the acceptance after such a carry.
 *
 * The course: Bob shares "Family" with Alice, who holds x, y and z; Bob removes her and her device keeps the copy; Bob
 * deletes y and adds her again; one sync serves y's deletion and the device shows the invitation. Then the cache is
 * carried into a new one, on one of the roads below, and the new cache syncs from the start: its full list either
 * serves y's deletion again or holds no row of y at all (the server no longer holds one). Then Alice accepts: y stays
 * out, and x and z are as served.
 *
 * Real: both apps' engines (the item engine, the trust engine, the composition and its carry), over a stand-in server.
 */
class KeptCopyCarryTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** The roads on which the product carries the open vault's cache into a new one. */
    private enum class Road {
        /** The platform's consent to a copy at rest turns off while the copy is a file: composed again in memory. */
        CONSENT_OFF,

        /** "Update required" stands and then clears while the copy is in memory: composed again twice, in memory. */
        UPDATE_REQUIRED,

        /**
         * A change made while the copy is a file waits; the consent turns off (carried into memory, as above); a lock keeps
         * what is in memory, and the next opening, in memory, takes it. A change cannot wait in a copy that was always in
         * memory: a save that cannot be sent there is refused.
         */
        LOCK_IN_MEMORY,

        /** The same, and the consent allows a file again before the unlock: the opening's new file takes what was kept. */
        LOCK_INTO_A_FILE,
    }

    /** What the new cache's full list holds of y. */
    private enum class Form { DELETION_SERVED_AGAIN, NO_ROW_OF_Y }

    /** Cache files by name, as a platform keeps them: the same name opens the same cache until it is deleted. */
    private class Files : VaultCacheFiles {
        val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache = caches.getOrPut(fileName) { InMemoryVaultCache() }
        override fun delete(fileName: String): Boolean {
            caches.remove(fileName)
            return true
        }
    }

    /**
     * The vault routes of a server over [FakeInstance] for everything else: `/sync` serves the caller's personal vault, its
     * shared vaults, its grants and every item of them (deletions included), and the vaults whose grant a `remove` ended
     * once; the log
     * routes store and serve each vault's chain; each account's state is kept by caller.
     */
    private inner class Server(val instance: FakeInstance) {
        val logs = LinkedHashMap<String, MutableList<String>>()
        val meta = HashMap<String, String>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        val items = LinkedHashMap<String, SyncItem>()
        val states = HashMap<String, Pair<String?, Long>>()
        var rev = 1L

        /** Vaults whose grant a `remove` ended, by member, served once as removed. */
        val removedFor = HashMap<String, MutableList<String>>()

        /** While true, a sync and a push get no answer: the device keeps its change waiting. */
        var down = false

        /** Answers that replace a route's own. */
        val override = HashMap<WireRoute, WireResult<String>>()

        /** The `since` of every `/sync`, in order. */
        val syncsFrom = ArrayList<Long?>()

        private fun head(log: List<String>) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last())))

        fun client(caller: () -> String?): WireClient = object : WireClient {
            override val origin: String = instance.origin
            override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                instance.callBytes(route, pathParams, query, body, authenticated, decode)

            override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> =
                instance.fetchBytes(route, pathParams, query, authenticated)

            @Suppress("UNCHECKED_CAST")
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                override[route]?.let { o -> return if (o is WireResult.Ok) WireResult.Ok(decode(o.value), o.status) else o as WireResult<T> }
                val user = caller()
                fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
                return when (route) {
                    WireRoute.ACCOUNT_STATE_GET -> {
                        val (sealed, seq) = states[user] ?: (null to 0L)
                        ok(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(sealed, seq)))
                    }
                    WireRoute.ACCOUNT_STATE_PUT -> {
                        val put = WireJson.json.decodeFromString(AccountStatePut.serializer(), bodyJson!!)
                        val seq = states[user]?.second ?: 0L
                        if (put.baseSeq != seq) return WireResult.Refused(409, WireError("stale_state", "m"))
                        states[user!!] = put.sealedState to seq + 1
                        ok(WireJson.json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(put.sealedState, seq + 1)))
                    }
                    WireRoute.SYNC -> {
                        if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                        val since = query?.removePrefix("since=")?.toLongOrNull()
                        syncsFrom += since
                        val mine = grants.values.filter { it.userId == user }
                        val personal = instance.accounts.values.firstOrNull { it.userId == user }?.personalWrap?.vaultId
                        val vaults = personal?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty() + mine.mapNotNull { g ->
                            val log = logs[g.vaultId] ?: return@mapNotNull null
                            SyncVault(g.vaultId, "shared", rev, meta[g.vaultId].orEmpty(), 0, SyncLogHead(log.size - 1L, head(log)))
                        }
                        val served = items.values.filter { i -> i.vaultId == personal || mine.any { it.vaultId == i.vaultId } }
                        val removed = removedFor.remove(user).orEmpty()
                        ok(WireJson.json.encodeToString(SyncResponse.serializer(), SyncResponse(rev++, since == 0L, vaults, mine, served, removed, emptyList(), 0, 0)))
                    }
                    WireRoute.PUSH -> {
                        if (down) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                        val req = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                        val results = req.mutations.map { m ->
                            val r = rev++
                            val body = m.item
                            items[m.itemId] = SyncItem(m.itemId, m.vaultId, r, instance.now, instance.now, m.op == "delete", false,
                                body?.formatVersion ?: 1, body?.attachmentIds ?: emptyList(), body?.blob)
                            MutationResult(m.mutationId, "applied", newItemRev = r)
                        }
                        ok(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results)))
                    }
                    WireRoute.LOG_FETCH -> {
                        val log = logs[pathParams.getValue("vaultId")] ?: return WireResult.Refused(403, WireError("no_grant", "m"))
                        val from = ((query?.removePrefix("after=")?.toLong() ?: -1) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        ok(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, LogHead(log.size - 1L, head(log), 0), deleted = null)))
                    }
                    WireRoute.LOG_APPEND -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val log = logs.getOrPut(vaultId) { ArrayList() }
                        val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                        if (req.entry !in log) {
                            val frame = Bytes.fromB64(req.entry)
                            val prior = if (log.isEmpty()) null else VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                            if (VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD) !is Checked.Ok) return WireResult.Refused(400, WireError("bad_entry", "m"))
                            log += req.entry
                            when (val entry = VaultLog.parse(crypto, frame).valueOrNull()?.entry) {
                                is LogEntry.Genesis -> grants[vaultId to user!!] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, rev)
                                is LogEntry.Add -> grants[vaultId to entry.member] = SyncGrant(vaultId, entry.member, entry.role.literal, "", rev, req.grant)
                                is LogEntry.Remove -> {
                                    grants.remove(vaultId to entry.member)
                                    removedFor.getOrPut(entry.member) { ArrayList() } += vaultId
                                }
                                else -> {}
                            }
                            req.metaBlob?.let { meta[vaultId] = it }
                        }
                        ok(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(rev++, LogHead(log.size - 1L, head(log), 0), null)))
                    }
                    WireRoute.VAULT_MEMBERS -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val rows = grants.keys.filter { it.first == vaultId }.map { (_, u) ->
                            VaultMemberSummary(u, "$u@example.com", "", grants.getValue(vaultId to u).role, Bytes.toB64(ByteArray(32)), 0)
                        }
                        ok(WireJson.json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), rows))
                    }
                    WireRoute.VAULT_SELF_WRAP -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                        grants[vaultId to user!!] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk)
                        ok("{\"rev\":${rev++}}")
                    }
                    WireRoute.VAULTS_DELETED -> ok("[]")
                    WireRoute.VAULT_META -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
    }

    /** An app on [server]; with [files], its copy is a file whenever the policy and [keep] (the platform's consent) allow. */
    private fun appOn(server: Server, files: Files? = null, keep: () -> Boolean = { true }): EngineAppApi {
        var self: EngineAppApi? = null
        val client = server.client { self?.keeper?.session?.userId }
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to client)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = files, keepsAtRest = keep),
        )
        self = app
        app.linksFlow.answersPollMs = Long.MAX_VALUE
        app.start()
        return app
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Typed address, Trust Gate, sign-up, kit: the vault is open. */
    private suspend fun open(a: EngineAppApi, email: String) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Someone", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private fun EngineAppApi.me(): Pair<String, String> = keeper.established!!.let { it.userId to Bytes.toB64(it.account.identity.publicKey) }

    /** [userId] with their real identity key [key], compared and confirmed on [a] (as a link there would have made them). */
    private suspend fun knows(a: EngineAppApi, server: Server, userId: String, key: String, label: String): io.silencelen.andvari.core.app.ContactRow {
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (userId to ContactRecord(userId, key, TrustGrammar.encodeName(label)!!, verifiedAt = server.instance.now, compared = true,
                madeOn = "44444444-4444-4444-8444-444444444444")))
        }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.confirmOnThisDevice(a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }))
        return a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }.also { a.contacts.closeContacts() }
    }

    private fun EngineAppApi.family() = snapshot.account!!.vaults.single { !it.deleted && it.name == "Family" }

    private fun EngineAppApi.names(vaultId: String): List<String> = vault!!.items.items().filter { it.vaultId == vaultId }.map { it.doc.name }.sorted()

    private fun EngineAppApi.held(vaultId: String) = vault!!.items.heldVaults().singleOrNull { it.vaultId == vaultId }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    private suspend fun addAgain(bob: EngineAppApi, server: Server, alice: io.silencelen.andvari.core.app.ContactRow) {
        server.instance.now += 1000
        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.family()))
        assertEquals(VaultActionResult.DONE, bob.vaults.addMember(bob.snapshot.account!!.members!!, alice, MemberRole.READER))
        bob.vaults.closeMembers()
    }

    private suspend fun accept(a: EngineAppApi) {
        a.content!!.refresh()
        val prompt = assertIs<AccountPrompt.IncomingVault>(a.snapshot.account!!.prompts.singleOrNull { it is AccountPrompt.IncomingVault }, "${a.snapshot.account!!.prompts}")
        assertEquals(VaultActionResult.DONE, a.vaults.acceptIncoming(prompt))
        a.content!!.refresh()
    }

    private fun course(road: Road, form: Form) = runBlocking<Unit> {
        val server = Server(FakeInstance(crypto))
        val bob = appOn(server)
        open(bob, "bob@example.com")
        var keep = road != Road.UPDATE_REQUIRED
        val files = Files()
        val alice = appOn(server, files) { keep }
        open(alice, "alice@example.com")
        // The policy is read by now: the next opening's copy is a file only where the consent allows one.
        alice.lock()
        assertEquals(VaultUnlockResult.DONE, alice.unlock(alice.snapshot.locked!!, strong))
        assertEquals(keep, alice.vault!!.keptAtRest, "the copy is a file only with the consent")
        val (aliceId, aliceKey) = alice.me()
        val (bobId, bobKey) = bob.me()
        val aliceRow = knows(bob, server, aliceId, aliceKey, "Alice")
        knows(alice, server, bobId, bobKey, "Bob")

        // Bob shares "Family" with Alice, who accepts and holds x, y and z.
        assertEquals(VaultActionResult.DONE, bob.vaults.createVault("Family"))
        val v = bob.family().vaultId
        addAgain(bob, server, aliceRow)
        accept(alice)
        for (n in listOf("x", "y", "z")) assertEquals(ActionResult.Ok, bob.content!!.saveLogin(null, login(n), v))
        alice.content!!.refresh()
        assertEquals(listOf("x", "y", "z"), alice.names(v), "Alice holds x, y and z")
        val y = alice.vault!!.items.items().single { it.vaultId == v && it.doc.name == "y" }.itemId

        // Bob removes Alice: her device keeps its copy.
        server.instance.now += 1000
        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.family()))
        assertEquals(VaultActionResult.DONE, bob.vaults.removeMember(bob.snapshot.account!!.members!!.members.single { it.userId == aliceId }))
        bob.vaults.closeMembers()
        alice.content!!.refresh()
        assertTrue(alice.held(v)?.readable == true, "the copy is kept: ${alice.vault!!.items.heldVaults()}")
        assertEquals(listOf("x", "y", "z"), alice.vault!!.items.heldItems(v).map { it.doc.name }.sorted(), "the copy holds x, y and z")

        // Bob deletes y and adds Alice again; one sync serves y's deletion and shows the invitation.
        assertEquals(ActionResult.Ok, bob.content!!.deleteItem(y))
        assertTrue(server.items.getValue(y).deleted, "y's deletion is on the server")
        addAgain(bob, server, aliceRow)
        alice.content!!.refresh()
        assertTrue(alice.held(v)?.let { !it.readable && it.addedAgain } == true, "closed while the invitation is open")
        assertTrue(alice.snapshot.account!!.prompts.any { it is AccountPrompt.IncomingVault && it.vaultId == v }, "the invitation is shown")

        if (form == Form.NO_ROW_OF_Y) server.items.remove(y)
        var syncs = server.syncsFrom.size
        val before = alice.vault!!

        // The carry.
        when (road) {
            Road.CONSENT_OFF -> {
                keep = false
                alice.atRestConsentChanged()
                assertFalse(alice.vault!!.keptAtRest, "composed again in memory")
            }
            Road.UPDATE_REQUIRED -> {
                val origin = server.instance.origin
                server.override[WireRoute.SYNC] = WireResult.Refused(426, WireError(WireErrors.UPGRADE_REQUIRED, "m"))
                alice.keeper.clientFor(origin).call(WireRoute.SYNC, authenticated = true) { it }
                assertTrue(alice.vault!!.haltedForUpdate, "composed again, read-only")
                server.override.remove(WireRoute.SYNC)
                server.instance.override[WireRoute.LINK_ACK] = WireResult.Ok("{}", 200)
                alice.keeper.clientFor(origin).call(WireRoute.LINK_ACK, authenticated = true) { it }
                assertFalse(alice.vault!!.haltedForUpdate, "composed again once it cleared")
                assertFalse(alice.vault!!.keptAtRest)
            }
            Road.LOCK_IN_MEMORY, Road.LOCK_INTO_A_FILE -> {
                // A change made while the copy is a file waits; the consent turns off (the first carry, into memory); a
                // lock keeps what waits in memory, and the next opening takes it (the second carry).
                // The change is put into the file's queue as the carry's own tests put it there.
                server.down = true
                val personal = alice.vault!!.personalVaultId
                assertTrue(alice.vault!!.keptAtRest, "the copy is a file")
                files.caches.values.single().enqueue(io.silencelen.andvari.core.model.Mutation("m-waiting", "delete", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", personal, 3))
                keep = false
                alice.atRestConsentChanged()
                assertFalse(alice.vault!!.keptAtRest, "composed again in memory")
                assertEquals(1, alice.waitingInMemory(), "one change waits in memory")
                alice.lock()
                if (road == Road.LOCK_INTO_A_FILE) keep = true
                server.down = false
                syncs = server.syncsFrom.size
                assertEquals(VaultUnlockResult.DONE, alice.unlock(alice.snapshot.locked!!, strong))
                assertEquals(road == Road.LOCK_INTO_A_FILE, alice.vault!!.keptAtRest, "the opening's copy")
                assertTrue(server.items.containsKey("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") || alice.vault!!.queued().pending.any { it.mutationId == "m-waiting" },
                    "what waited was taken by the opening")
            }
        }
        assertTrue(alice.vault !== before, "a new composition")
        if (road == Road.LOCK_INTO_A_FILE) assertEquals(y, files.caches.values.single().clientState(RECORD + v), "the copy's record went with it into the new file")
        assertTrue(alice.held(v) != null, "the copy was carried")

        // The new cache syncs from the start.
        alice.content!!.refresh()
        assertEquals(0L, server.syncsFrom.drop(syncs).firstOrNull(), "the first sync after the carry is from the start: ${server.syncsFrom.drop(syncs)}")
        assertTrue(alice.held(v)?.let { !it.readable && it.addedAgain } == true, "still closed after the sync from the start")

        accept(alice)
        assertTrue(alice.held(v) == null && alice.vault!!.items.vaults().any { it.vaultId == v }, "the vault is back and the copy taken")
        assertEquals(listOf("x", "z"), alice.names(v), "$road, $form: y stays out, x and z as served")
    }

    @Test fun afterTheConsentCarryAResyncThatServesYsDeletionAgainLeavesYOut() = course(Road.CONSENT_OFF, Form.DELETION_SERVED_AGAIN)

    @Test fun afterTheConsentCarryAResyncWithNoRowOfYLeavesYOut() = course(Road.CONSENT_OFF, Form.NO_ROW_OF_Y)

    @Test fun afterTheUpdateRequiredCarryAResyncThatServesYsDeletionAgainLeavesYOut() = course(Road.UPDATE_REQUIRED, Form.DELETION_SERVED_AGAIN)

    @Test fun afterTheUpdateRequiredCarryAResyncWithNoRowOfYLeavesYOut() = course(Road.UPDATE_REQUIRED, Form.NO_ROW_OF_Y)

    @Test fun afterALockInMemoryAResyncThatServesYsDeletionAgainLeavesYOut() = course(Road.LOCK_IN_MEMORY, Form.DELETION_SERVED_AGAIN)

    @Test fun afterALockInMemoryAResyncWithNoRowOfYLeavesYOut() = course(Road.LOCK_IN_MEMORY, Form.NO_ROW_OF_Y)

    @Test fun afterALockCarriedIntoAFileAResyncThatServesYsDeletionAgainLeavesYOut() = course(Road.LOCK_INTO_A_FILE, Form.DELETION_SERVED_AGAIN)

    @Test fun afterALockCarriedIntoAFileAResyncWithNoRowOfYLeavesYOut() = course(Road.LOCK_INTO_A_FILE, Form.NO_ROW_OF_Y)

    // ---- what the carry leaves behind ----

    /**
     * A carry with no kept copy carries no record: a record left in the file with no copy beside it, and another entry of
     * the client state, stay behind. The road that ends in a file the test can read: a change waits while the copy is a
     * file, the consent turns off, a lock, the consent allows a file again, an unlock.
     */
    @Test fun aCarryWithNoKeptCopyCarriesNoRecordAndNothingElseOfTheClientState() = runBlocking<Unit> {
        val server = Server(FakeInstance(crypto))
        var keep = true
        val files = Files()
        val alice = appOn(server, files) { keep }
        open(alice, "alice@example.com")
        alice.lock()
        assertEquals(VaultUnlockResult.DONE, alice.unlock(alice.snapshot.locked!!, strong))
        assertTrue(alice.vault!!.keptAtRest, "the copy is a file")
        val file = files.caches.values.single()
        val leftOver = "99999999-9999-4999-8999-999999999999"
        file.setClientState(RECORD + leftOver, "88888888-8888-4888-8888-888888888888")
        file.setClientState("test.other", "1")
        server.down = true
        file.enqueue(io.silencelen.andvari.core.model.Mutation("m-waiting", "delete", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", alice.vault!!.personalVaultId, 3))
        keep = false
        alice.atRestConsentChanged()
        assertEquals(emptyList(), alice.vault!!.queued().held, "no kept copy")
        assertEquals(1, alice.waitingInMemory())
        alice.lock()
        keep = true
        server.down = false
        assertEquals(VaultUnlockResult.DONE, alice.unlock(alice.snapshot.locked!!, strong))
        assertTrue(alice.vault!!.keptAtRest, "the opening's copy is a new file")
        val now = files.caches.values.single()
        assertTrue(now !== file, "a new file")
        assertEquals(null, now.clientState(RECORD + leftOver), "a record with no copy beside it is not carried")
        assertEquals(null, now.clientState("test.other"), "nothing else of the client state is carried")
    }

    /**
     * Only the kept copies' records are carried: a record left under a vault the cache lists (the personal vault, which
     * no copy is kept of) is not, neither into what the carry takes nor into the new cache, which lists that vault again
     * after its sync from the start. The road: the consent turns off while the copy is a file, and the server answers.
     */
    @Test fun aCarryLeavesBehindARecordUnderAVaultTheCacheListsWithNoKeptCopy() = runBlocking<Unit> {
        val server = Server(FakeInstance(crypto))
        var keep = true
        val files = Files()
        val alice = appOn(server, files) { keep }
        open(alice, "alice@example.com")
        alice.lock()
        assertEquals(VaultUnlockResult.DONE, alice.unlock(alice.snapshot.locked!!, strong))
        assertTrue(alice.vault!!.keptAtRest, "the copy is a file")
        alice.content!!.refresh()
        val file = files.caches.values.single()
        val personal = alice.vault!!.personalVaultId
        assertTrue(file.vaults().any { it.vaultId == personal }, "the file lists the personal vault: ${file.vaults().map { it.vaultId }}")
        assertEquals(emptyList(), file.heldVaults(), "no kept copy")
        file.setClientState(RECORD + personal, "88888888-8888-4888-8888-888888888888")
        val before = alice.vault!!
        assertEquals(emptyMap(), before.queued().heldDeleted, "what a carry takes holds no record of a vault with no kept copy")
        val syncs = server.syncsFrom.size
        keep = false
        alice.atRestConsentChanged()
        assertTrue(alice.vault !== before, "a new composition")
        assertFalse(alice.vault!!.keptAtRest, "composed again in memory")
        alice.content!!.refresh()
        assertEquals(0L, server.syncsFrom.drop(syncs).firstOrNull(), "the new cache syncs from the start: ${server.syncsFrom.drop(syncs)}")
        assertTrue(alice.vault!!.items.vaults().any { it.vaultId == personal }, "the new cache lists the personal vault again")
        val carried = alice.vault!!.queued()
        assertEquals(null, carried.heldDeleted[personal], "the personal vault's record was not carried into the new cache")
        assertEquals(emptyMap(), carried.heldDeleted, "the new cache holds no record of a kept copy, for it holds none")
    }

    /**
     * The carry's own call: a carried copy takes its own record into the new cache, or none, over whatever record that
     * cache held for the vault; a record of a vault the carry holds no copy of is not touched.
     */
    @Test fun aCarriedCopyTakesItsOwnRecordOrNoneOverWhatTheNewCacheHeld() {
        fun held(vaultId: String) = io.silencelen.andvari.core.client.HeldVaultRecord(
            io.silencelen.andvari.core.model.WireVault(vaultId, "shared", 1, "", 0L), null, emptyList(), "removed", true, null, null, emptyList(), Long.MAX_VALUE)
        val a = "11111111-1111-4111-8111-111111111111"
        val b = "22222222-2222-4222-8222-222222222222"
        val c = "33333333-3333-4333-8333-333333333333"
        val y = "44444444-4444-4444-8444-444444444444"
        val into = InMemoryVaultCache()
        into.setClientState(RECORD + a, "stale")
        into.setClientState(RECORD + b, "stale")
        into.setClientState(RECORD + c, "not this carry's")
        QueuedCarry("https://h.example", "u", emptyList(), emptyList(), listOf(held(a), held(b)), mapOf(a to y)).into(into)
        assertEquals(y, into.clientState(RECORD + a), "the copy's own record")
        assertEquals(null, into.clientState(RECORD + b), "a copy with no record leaves none")
        assertEquals("not this carry's", into.clientState(RECORD + c), "another vault's entry is not touched")
        assertEquals(listOf(a, b), into.heldVaults().map { it.vault.vaultId }.sorted(), "the copies are carried")
    }

    private companion object {
        /** The client-state key prefix under which a kept copy's record of served deletions is kept, per vault. */
        const val RECORD = "held.deleted."
    }
}
