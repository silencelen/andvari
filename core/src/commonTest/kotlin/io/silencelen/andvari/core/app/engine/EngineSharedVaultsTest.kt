package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
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
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Shared vaults on the engine (design §3): the rows from the verified log, the members, and the log actions. */
class EngineSharedVaultsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /**
     * The vault routes of a server, over [FakeInstance] for everything else: `/sync` serves the shared vault rows and
     * the caller's grants (no items), and the log routes store and serve each vault's chain.
     */
    private inner class VaultServer(val instance: FakeInstance) {
        /** The files uploaded, or put here by a test, by attachment id, as `GET /attachments/{id}` serves them. */
        val files = HashMap<String, ByteArray>()
        val logs = LinkedHashMap<String, MutableList<String>>()
        val meta = HashMap<String, String>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        var rev = 1L
        /** The vaults "Recently deleted" serves. */
        val deletedNow = ArrayList<String>()

        /** The grace end the server sends with a log that ends in a `delete` (null: an older server, none sent). */
        var graceEnd: io.silencelen.andvari.core.model.wire.LogDeleted? = null

        /** Members the server's member list leaves out; [membersRefused] makes the list unreadable. */
        val unlisted = HashSet<String>()
        var membersRefused = false

        /** The name the server's member list gives each user it names here (none: an empty name). */
        val displayNames = HashMap<String, String>()

        /** Every entry stored, in the order stored, across all vaults: (vault, entry). */
        val stored = ArrayList<Pair<String, LogEntry?>>()

        /** When true, pushes are stored and every sync serves the items of the caller's vaults (else no items at all). */
        var servesItems = false
        val items = LinkedHashMap<String, io.silencelen.andvari.core.model.wire.SyncItem>()

        /** Items whose deletion this server refuses (`denied`), leaving them as they are. */
        val deniesDeleteOf = HashSet<String>()

        /** Runs at the start of each `/sync`, before it is answered (a change another device stores just then). */
        var onSync: (() -> Unit)? = null

        /** While true, a push gets no answer: the device keeps its change waiting. */
        var pushUnanswered = false

        /** While true (read after [onSync]), a `/sync` gets no answer. */
        var syncUnanswered = false

        /** The caller's use and limits each `/sync` serves (null: an older server, none sent). */
        var quota: io.silencelen.andvari.core.model.wire.QuotaUse? = null

        /** When set, the policy allows files up to this size (the onboarding fake allows one byte). */
        var filesUpTo: Long? = null

        /** Every route called, in order (for "nothing was signed or sent"). */
        val calls = ArrayList<WireRoute>()

        /** Every `delete` posted, with the read point it named beside it (`itemsAtMost`; null: none named). */
        val readPoints = ArrayList<Pair<String, Long?>>()

        /**
         * When true, a `delete` that names a read point is refused (`409 vault_items_moved`, nothing stored) where an item of
         * the vault, live or deleted, stands at a later `rev`, as the reference server does.
         */
        var checksReadPoint = false

        private fun head(log: List<String>) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last())))

        private fun deleted(log: List<String>) =
            graceEnd?.takeIf { VaultLog.parse(crypto, Bytes.fromB64(log.last())).valueOrNull()?.entry is LogEntry.Delete }

        /**
         * When true, each account's state is kept here by caller (the instance keeps only its last account's), for tests
         * with more than one account; [stateRefused] makes the reads of the accounts it names answer 503.
         */
        var statesByCaller = false
        val states = HashMap<String, Pair<String?, Long>>()
        var stateRefused: (String) -> Boolean = { false }

        fun client(caller: () -> String?): WireClient = object : WireClient {
            override val origin: String = instance.origin
            override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                calls += route
                if (route != WireRoute.ATTACHMENT_UPLOAD) return instance.callBytes(route, pathParams, query, body, authenticated, decode)
                val q = query.orEmpty().split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
                val meta = io.silencelen.andvari.core.model.wire.AttachmentMeta(pathParams.getValue("attachmentId"), q["itemId"].orEmpty(), q["vaultId"].orEmpty(),
                    body.size.toLong(), Bytes.toHexLower(crypto.sha256(body)), instance.now)
                files[pathParams.getValue("attachmentId")] = body.copyOf()
                return WireResult.Ok(decode(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.AttachmentMeta.serializer(), meta)), 200)
            }

            override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> {
                calls += route
                if (route != WireRoute.ATTACHMENT_GET) return instance.fetchBytes(route, pathParams, query, authenticated)
                return files[pathParams.getValue("attachmentId")]?.let { WireResult.Ok(it.copyOf(), 200) } ?: WireResult.Refused(404, WireError("not_found", "m"))
            }

            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                val user = caller()
                calls += route
                fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
                if (statesByCaller && user != null && route == WireRoute.ACCOUNT_STATE_GET) {
                    if (stateRefused(user)) return WireResult.Refused(503, WireError("unavailable", "m"))
                    val (sealed, seq) = states[user] ?: (null to 0L)
                    return ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.AccountStateResponse.serializer(),
                        io.silencelen.andvari.core.model.wire.AccountStateResponse(sealed, seq)))
                }
                if (statesByCaller && user != null && route == WireRoute.ACCOUNT_STATE_PUT) {
                    val put = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.AccountStatePut.serializer(), bodyJson!!)
                    val seq = states[user]?.second ?: 0L
                    if (put.baseSeq != seq) return WireResult.Refused(409, WireError("stale_state", "m"))
                    states[user] = put.sealedState to seq + 1
                    return ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.AccountStateResponse.serializer(),
                        io.silencelen.andvari.core.model.wire.AccountStateResponse(put.sealedState, seq + 1)))
                }
                return when (route) {
                    WireRoute.CLIENT_POLICY -> {
                        val served = instance.call(route, pathParams, query, bodyJson, authenticated) { it }
                        val max = filesUpTo
                        if (max == null || served !is WireResult.Ok) return instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                        val p = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.ClientPolicy.serializer(), served.value)
                        ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.ClientPolicy.serializer(), p.copy(attachmentMaxBytes = max, itemAttachmentsMaxBytes = 4 * max)))
                    }
                    WireRoute.SYNC -> {
                        onSync?.invoke()
                        if (syncUnanswered) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                        val mine = grants.values.filter { it.userId == user }
                        val vaults = mine.mapNotNull { g ->
                            val log = logs[g.vaultId] ?: return@mapNotNull null
                            SyncVault(g.vaultId, "shared", rev, meta[g.vaultId].orEmpty(), 0, SyncLogHead(log.size - 1L, head(log)))
                        }
                        // Every row in each answer; a full snapshot only when asked from the start (an unasked one is a rollback).
                        val full = query?.removePrefix("since=")?.toLongOrNull() == 0L
                        val served = if (!servesItems) emptyList() else items.values.filter { i -> mine.any { it.vaultId == i.vaultId } }
                        ok(WireJson.json.encodeToString(SyncResponse.serializer(), SyncResponse(rev++, full, vaults, mine, served, emptyList(), emptyList(), 0, 0, quota)))
                    }
                    WireRoute.PUSH -> {
                        if (!servesItems || pushUnanswered) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                        val req =WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.PushRequest.serializer(), bodyJson!!)
                        val results = req.mutations.map { m ->
                            if (m.op == "delete" && m.itemId in deniesDeleteOf) return@map io.silencelen.andvari.core.model.wire.MutationResult(m.mutationId, "denied")
                            val r = rev++
                            val body = m.item
                            items[m.itemId] = io.silencelen.andvari.core.model.wire.SyncItem(m.itemId, m.vaultId, r, instance.now, instance.now,
                                m.op == "delete", false, body?.formatVersion ?: 1, body?.attachmentIds ?: emptyList(), body?.blob)
                            io.silencelen.andvari.core.model.wire.MutationResult(m.mutationId, "applied", newItemRev = r)
                        }
                        ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.PushResponse.serializer(), io.silencelen.andvari.core.model.wire.PushResponse(rev, results)))
                    }
                    WireRoute.LOG_FETCH -> {
                        val log = logs[pathParams.getValue("vaultId")] ?: return WireResult.Refused(403, WireError("no_grant", "m"))
                        val from = ((query?.removePrefix("after=")?.toLong() ?: -1) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        ok(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, LogHead(log.size - 1L, head(log), 0), deleted = deleted(log))))
                    }
                    WireRoute.VAULT_MEMBERS -> {
                        val vaultId = pathParams.getValue("vaultId")
                        if (membersRefused) return WireResult.Refused(503, WireError("unavailable", "m"))
                        val rows = grants.keys.filter { it.first == vaultId && it.second !in unlisted }.map { (_, u) ->
                            io.silencelen.andvari.core.model.wire.VaultMemberSummary(u, "$u@example.com", displayNames[u].orEmpty(), grants.getValue(vaultId to u).role, Bytes.toB64(ByteArray(32)), 0)
                        }
                        ok(WireJson.json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.wire.VaultMemberSummary.serializer()), rows))
                    }
                    WireRoute.LOG_APPEND -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val log = logs.getOrPut(vaultId) { ArrayList() }
                        val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                        if (VaultLog.parse(crypto, Bytes.fromB64(req.entry)).valueOrNull()?.entry is LogEntry.Delete) {
                            readPoints += vaultId to req.itemsAtMost
                            val at = req.itemsAtMost
                            if (checksReadPoint && req.entry !in log && at != null && items.values.any { it.vaultId == vaultId && it.rev > at }) {
                                return WireResult.Refused(409, WireError("vault_items_moved", "m"))
                            }
                        }
                        if (req.entry !in log) {
                            val frame = Bytes.fromB64(req.entry)
                            val prior = if (log.isEmpty()) null else VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                            if (VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD) !is io.silencelen.andvari.core.trust.Checked.Ok) {
                                return WireResult.Refused(400, WireError("bad_entry", "m"))
                            }
                            log += req.entry
                            val entry = VaultLog.parse(crypto, frame).valueOrNull()?.entry
                            stored += vaultId to entry
                            if (entry is LogEntry.Genesis) grants[vaultId to user!!] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, rev)
                            if (entry is LogEntry.Add) grants[vaultId to entry.member] = SyncGrant(vaultId, entry.member, entry.role.literal, "", rev, req.grant)
                            req.metaBlob?.let { meta[vaultId] = it }
                        }
                        ok(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(rev++, LogHead(log.size - 1L, head(log), 0), deleted(log))))
                    }
                    WireRoute.VAULT_SELF_WRAP -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                        grants[vaultId to user!!] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk)
                        ok("{\"rev\":${rev++}}")
                    }
                    WireRoute.VAULTS_DELETED -> {
                        // The vaults whose log ends in this account's `delete`, as the server lists them (no entry id: none is checked).
                        val rows = deletedNow.map { id ->
                            """{"vaultId":"$id","metaBlob":"${meta[id].orEmpty()}","wrappedVk":"","deletedAt":${instance.now - 1000},"purgeAt":${instance.now + 7 * 86_400_000L},"deleteId":"AAAAAAAAAAAAAAAAAAAAAA=="}"""
                        }
                        ok("[" + rows.joinToString(",") + "]")
                    }
                    WireRoute.VAULT_META -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    WireRoute.ITEMS_DELETED -> {
                        // The trash: the deleted items of the caller's vaults, newest first, in one page.
                        val mine = grants.values.filter { it.userId == user }.mapTo(HashSet()) { it.vaultId }
                        val rows = items.values.filter { it.deleted && it.vaultId in mine }
                            .map { io.silencelen.andvari.core.model.wire.DeletedItem(it.itemId, it.vaultId, it.updatedAt) }
                            .sortedWith(compareByDescending<io.silencelen.andvari.core.model.wire.DeletedItem> { it.deletedAt }.thenByDescending { it.itemId })
                        ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.DeletedItemsResponse.serializer(),
                            io.silencelen.andvari.core.model.wire.DeletedItemsResponse(rows)))
                    }
                    else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
    }

    private fun app(): Pair<VaultServer, EngineAppApi> = app { it }

    private fun app(front: (WireClient) -> WireClient): Pair<VaultServer, EngineAppApi> = appOn(VaultServer(FakeInstance(crypto)), front)

    /** Another device on [server] (another account, or another device of one). */
    private fun appOn(
        server: VaultServer,
        front: (WireClient) -> WireClient = { it },
        state: MemoryDeviceState = MemoryDeviceState(),
        secure: MemoryDeviceState = MemoryDeviceState(),
        cacheFiles: VaultCacheFiles? = null,
        /** Files are served for download too ([Fetching]); without it every download gets no answer, as before. */
        fetches: Boolean = false,
    ): Pair<VaultServer, EngineAppApi> {
        val instance = server.instance
        var self: EngineAppApi? = null
        val client = front(server.client { self?.keeper?.session?.userId })
        val bearer = BearerTransport(mapOf(instance.origin to client))
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", if (fetches) Fetching(bearer, mapOf(instance.origin to client)) else bearer,
                state, secure, crypto, { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, cacheFiles = cacheFiles),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return server to app
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Typed address, Trust Gate, sign-up, kit: the vault is open. */
    private suspend fun open(a: EngineAppApi, email: String = "alice@example.com") {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
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

    @Test fun aVaultCreatedHereIsListedFromItsVerifiedLogAndItsOwnerManagesIt() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertTrue(a.snapshot.account!!.vaults.isEmpty())
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        assertEquals(1, server.logs.size, "the genesis is on the server's log")
        val row = a.snapshot.account!!.vaults.single()
        assertEquals("Family", row.name)
        assertEquals(VaultLogState.VERIFIED, row.log)
        assertEquals(RoleInVault.OWNER, row.role)
        assertIs<PersonName.You>(row.owner)
        assertTrue(row.writable)
        assertFalse(row.deleted)

        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(row))
        val members = assertNotNull(a.snapshot.account!!.members)
        assertTrue(members.canManage)
        assertIs<PersonName.You>(members.members.single().who)
        a.vaults.closeMembers()

        // The owner cannot leave; it deletes, and restores during the grace.
        assertEquals(VaultActionResult.NOT_ALLOWED, a.vaults.leaveVault(row))
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(a.snapshot.account!!.vaults.single()))
        val deleted = a.snapshot.account!!.vaults.single()
        assertTrue(deleted.deleted, "in its grace")
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(deleted))
        assertFalse(a.snapshot.account!!.vaults.single().deleted)
        assertEquals(3, server.logs.values.single().size, "genesis, delete, restore")
    }

    /** "Recently deleted": an entry on show restores the vault through its log, and the open list is read again. */
    @Test fun aVaultIsRestoredFromRecentlyDeleted() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(a.snapshot.account!!.vaults.single()))
        val vaultId = server.logs.keys.single()
        server.deletedNow += vaultId
        val content = assertNotNull(a.content)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, content.openDeletedVaults())
        val entry = content.state.deletedVaults!!.single()
        assertEquals(vaultId, entry.vaultId)
        // A copy that is not the entry on show is stale.
        assertEquals(VaultActionResult.STALE, a.vaults.restoreDeletedVault(entry.copy()))
        server.deletedNow.clear()
        assertEquals(VaultActionResult.DONE, a.vaults.restoreDeletedVault(entry))
        assertEquals(3, server.logs.values.single().size, "genesis, delete, restore")
        assertFalse(a.snapshot.account!!.vaults.single().deleted)
        assertEquals(emptyList(), content.state.deletedVaults, "the list was read again")
    }

    /** A compared contact of this account, made on another device and confirmed here: current here, ready to share with. */
    private suspend fun contact(a: EngineAppApi, server: VaultServer, userId: String, label: String): io.silencelen.andvari.core.app.ContactRow {
        val key = Bytes.toB64(crypto.randomBytes(32))
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (userId to io.silencelen.andvari.core.client.state.ContactRecord(
                userId, key, io.silencelen.andvari.core.trust.TrustGrammar.encodeName(label)!!, verifiedAt = server.instance.now, compared = true,
                madeOn = "44444444-4444-4444-8444-444444444444")))
        }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.confirmOnThisDevice(row))
        return a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }.also { assertTrue(it.currentHere && it.compared) }
    }

    /** [userId] with their real identity key [key], compared and confirmed on [a] (as a link there would have made them). */
    private suspend fun knows(a: EngineAppApi, server: VaultServer, userId: String, key: String, label: String): io.silencelen.andvari.core.app.ContactRow {
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (userId to io.silencelen.andvari.core.client.state.ContactRecord(
                userId, key, io.silencelen.andvari.core.trust.TrustGrammar.encodeName(label)!!, verifiedAt = server.instance.now, compared = true,
                madeOn = "44444444-4444-4444-8444-444444444444")))
        }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.confirmOnThisDevice(a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }))
        return a.snapshot.account!!.contacts!!.contacts.single { it.userId == userId }.also { a.contacts.closeContacts() }
    }

    private fun EngineAppApi.me(): Pair<String, String> = keeper.established!!.let { it.userId to Bytes.toB64(it.account.identity.publicKey) }

    /**
     * Bob shares "Family" with Alice, and Alice's first device has Bob as a contact. Her second
     * device, signed in with the password, shows the row as "confirm first" (Bob is the account's contact, not yet
     * current here), never "connect first", without the contacts screen ever being opened; when the opening's read of
     * the account's state got no answer, at once after the next sync.
     */
    @Test fun aSecondDeviceShowsConfirmFirstForAVaultFromAContactOfTheAccountWithoutOpeningContacts() = runBlocking<Unit> {
        val server = VaultServer(FakeInstance(crypto)).also { it.statesByCaller = true }
        val (_, bob) = appOn(server)
        open(bob, "bob@example.com")
        val (_, alice1) = appOn(server)
        open(alice1, "alice@example.com")
        val (aliceId, aliceKey) = alice1.me()
        val (bobId, bobKey) = bob.me()
        val alice = knows(bob, server, aliceId, aliceKey, "Alice")
        assertEquals(VaultActionResult.DONE, bob.vaults.createVault("Family"))
        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.addMember(bob.snapshot.account!!.members!!, alice, io.silencelen.andvari.core.trust.MemberRole.READER))
        bob.vaults.closeMembers()
        knows(alice1, server, bobId, bobKey, "Bob")

        val (_, alice2) = appOn(server)
        var refusing = true
        server.stateRefused = { it == aliceId && refusing && alice2.phase == AppPhase.UNLOCKED }
        alice2.entry.openSignIn(alice2.at())
        alice2.entry.openPasswordSignIn(alice2.at())
        assertEquals(ServerResult.DONE, alice2.entry.chooseOwnServer(alice2.at(), server.instance.origin))
        (alice2.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, alice2.entry.confirmTrustGate(it)) }
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, alice2.entry.submitSignIn(alice2.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, alice2.snapshot.phase)
        assertEquals(VaultLogState.CONNECT_FIRST, alice2.snapshot.account!!.vaults.single().log, "nothing of the account's state could be read yet")

        refusing = false
        alice2.content!!.refresh()
        val row = alice2.snapshot.account!!.vaults.single()
        assertEquals(VaultLogState.CONFIRM_FIRST, row.log)
        assertEquals(bobId, assertNotNull(row.senderToConfirm).userId)
        assertNull(alice2.snapshot.account!!.contacts, "the contacts screen was never opened")
    }

    /** The desktop's first run: a person added as a reader is on the open Members screen at once, and as a reader. */
    @Test fun aMemberAddedAsAReaderIsShownAtOnceAsAReader() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val carol = "33333333-3333-4333-8333-333333333333"
        val c = contact(a, server, carol, "Carol")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        val screen = assertNotNull(a.snapshot.account!!.members)
        assertEquals(VaultActionResult.DONE, a.vaults.addMember(screen, c, io.silencelen.andvari.core.trust.MemberRole.READER))
        val added = assertNotNull(a.snapshot.account!!.members, "the screen stays open").members.firstOrNull { it.userId == carol }
        assertNotNull(added, "the new member is listed without reopening")
        assertEquals(RoleInVault.READER, added.role)
        // What was signed is a reader: the entry on the server's log, read back the way every other member verifies it,
        // and the grant the server keeps from it.
        val vaultId = server.logs.keys.single()
        val signed = assertIs<LogEntry.Add>(VaultLog.parse(crypto, Bytes.fromB64(server.logs.getValue(vaultId).last())).valueOrNull()?.entry)
        assertEquals(carol, signed.member)
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.READER, signed.role)
        val replayed = VaultLog.replay(crypto, vaultId, server.logs.getValue(vaultId).map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
        assertEquals("reader", assertNotNull(replayed).members.getValue(carol).role.literal)
        // Reopened, the same.
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertEquals(RoleInVault.READER, a.snapshot.account!!.members!!.members.single { it.userId == carol }.role)
        // A role change shows at once too.
        val m = a.snapshot.account!!.members!!.members.single { it.userId == carol }
        assertEquals(VaultActionResult.DONE, a.vaults.changeRole(m, io.silencelen.andvari.core.trust.MemberRole.WRITER))
        assertEquals(RoleInVault.WRITER, a.snapshot.account!!.members!!.members.single { it.userId == carol }.role)
    }

    /** The same through the uncompared-share warning: confirmed, the person is on the open screen at once, as a reader. */
    @Test fun aReaderAddedBehindTheUncomparedWarningIsShownAtOnceAsAReader() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val dave = "55555555-5555-4555-8555-555555555555"
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (dave to io.silencelen.andvari.core.client.state.ContactRecord(
                dave, Bytes.toB64(crypto.randomBytes(32)), io.silencelen.andvari.core.trust.TrustGrammar.encodeName("Dave")!!,
                verifiedAt = server.instance.now, compared = false, madeOn = "44444444-4444-4444-8444-444444444444")))
        }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val pending = a.snapshot.account!!.contacts!!.contacts.single { it.userId == dave }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.confirmOnThisDevice(pending))
        val d = a.snapshot.account!!.contacts!!.contacts.single { it.userId == dave }
        assertTrue(d.currentHere && !d.compared)
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING,
            a.vaults.addMember(a.snapshot.account!!.members!!, d, io.silencelen.andvari.core.trust.MemberRole.READER))
        val warning = assertNotNull(a.snapshot.account!!.shareWarning)
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.READER, warning.role)
        assertNotNull(a.snapshot.account!!.members, "the Members screen stays open behind the warning")
        assertEquals(VaultActionResult.DONE, a.vaults.confirmUncomparedShare(warning))
        val added = assertNotNull(a.snapshot.account!!.members!!.members.firstOrNull { it.userId == dave }, "listed without reopening")
        assertEquals(RoleInVault.READER, added.role)
    }

    // ---- §3.13 "Move everything to a new vault", as the web runs it and as decided on 16 November 2026 ----

    private val carol = "33333333-3333-4333-8333-333333333333"
    private val dave = "55555555-5555-4555-8555-555555555555"

    private fun EngineAppApi.row() = snapshot.account!!.vaults.single { !it.deleted && it.name == "Family" }

    /** "Family", owned here, shared with Carol (a writer) and Dave (a reader), both compared contacts current here. */
    private suspend fun family(a: EngineAppApi, server: VaultServer, daveCompared: Boolean = true): String {
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val c = contact(a, server, carol, "Carol")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.addMember(a.snapshot.account!!.members!!, c, io.silencelen.andvari.core.trust.MemberRole.WRITER))
        a.vaults.closeMembers()
        if (daveCompared) {
            val d = contact(a, server, dave, "Dave")
            assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
            assertEquals(VaultActionResult.DONE, a.vaults.addMember(a.snapshot.account!!.members!!, d, io.silencelen.andvari.core.trust.MemberRole.READER))
        } else {
            // Current here, codes never compared: shared only through the warning, which the move cannot show.
            a.vault!!.store.update { doc ->
                doc.copy(contacts = doc.contacts + (dave to io.silencelen.andvari.core.client.state.ContactRecord(
                    dave, Bytes.toB64(crypto.randomBytes(32)), io.silencelen.andvari.core.trust.TrustGrammar.encodeName("Dave")!!,
                    verifiedAt = server.instance.now, compared = false, madeOn = "44444444-4444-4444-8444-444444444444")))
            }
            assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
            assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.confirmOnThisDevice(a.snapshot.account!!.contacts!!.contacts.single { it.userId == dave }))
            val d = a.snapshot.account!!.contacts!!.contacts.single { it.userId == dave }
            assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
            assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, a.vaults.addMember(a.snapshot.account!!.members!!, d, io.silencelen.andvari.core.trust.MemberRole.READER))
            assertEquals(VaultActionResult.DONE, a.vaults.confirmUncomparedShare(assertNotNull(a.snapshot.account!!.shareWarning)))
        }
        return server.logs.keys.single()
    }

    private fun kinds(stored: List<Pair<String, LogEntry?>>, oldId: String) =
        stored.map { (v, e) -> (if (v == oldId) "old " else "new ") + (e?.let { it::class.simpleName } ?: "?") }

    /**
     * From Dave's remove dialog: Dave is removed on the old log before anything else, no tick boxes on a
     * vault in good standing, Carol is added again with her role, and the old vault is deleted last.
     */
    @Test fun moveEverythingFromTheRemoveDialogRemovesThemFirstAddsEveryoneElseAndDeletesTheOldVaultLast() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        val oldId = family(a, server)
        val daveRow = a.snapshot.account!!.members!!.members.single { it.userId == dave }
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(daveRow))
        val screen = assertNotNull(a.snapshot.account!!.moving)
        assertEquals(dave, screen.removing?.userId)
        assertEquals(listOf(carol), screen.members.map { it.userId }, "the removed member is not a remaining member")
        assertFalse(screen.ticksOffered)
        assertTrue(screen.members.single().ticked && screen.members.single().canBeAdded)
        assertNull(screen.oldVaultKept, "the old vault will be deleted at the end")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_ONLY_LIVE_ITEMS, screen.whatMoves)
        // No ticks on a vault in good standing: an untick changes nothing.
        a.vaults.tickMember(screen, screen.members.single(), false)
        assertTrue(assertNotNull(a.snapshot.account!!.moving).members.single().ticked)

        val before = server.stored.size
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertNull(a.snapshot.account!!.moving, "done, and the old vault deleted: the screen closes")
        // The old vault's row says deleted at once, as the stand-in's does, not a live vault until the next read.
        val oldRow = a.snapshot.account!!.vaults.firstOrNull { it.vaultId == oldId }
        println("the old vault's row right after the finished move: deleted=${oldRow?.deleted} writable=${oldRow?.writable} log=${oldRow?.log}")
        assertTrue(oldRow == null || (oldRow.deleted && !oldRow.writable), "the old vault's row reads deleted")
        assertEquals(listOf("old Remove", "new Genesis", "new Add", "old Delete"), kinds(server.stored.drop(before), oldId))
        assertEquals(dave, assertIs<LogEntry.Remove>(server.stored[before].second).member)
        val added = assertIs<LogEntry.Add>(server.stored[before + 2].second)
        assertEquals(carol, added.member)
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.WRITER, added.role, "with the role she holds now")
    }

    /** A remaining member this device cannot add is named before the person starts, and the old vault is kept. */
    @Test fun aRemainingMemberWhoCannotBeAddedHereIsNamedBeforeTheStartAndTheOldVaultIsKept() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        val oldId = family(a, server, daveCompared = false)
        a.vaults.closeMembers()
        assertTrue(a.row().canMoveEverything, "the row carries the offer itself")
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val screen = assertNotNull(a.snapshot.account!!.moving)
        assertNull(screen.removing)
        val d = screen.members.single { it.userId == dave }
        assertFalse(d.canBeAdded || d.ticked)
        assertEquals(io.silencelen.andvari.core.app.MoveKept.MEMBER_CANNOT_BE_ADDED, screen.oldVaultKept, "said before the person starts")

        val before = server.stored.size
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(screen, "Family 2"))
        assertEquals(listOf("new Genesis", "new Add"), kinds(server.stored.drop(before), oldId), "Carol added; nothing signed on the old log")
        val finished = assertNotNull(assertNotNull(a.snapshot.account!!.moving).finished)
        assertEquals(io.silencelen.andvari.core.app.MoveKept.MEMBER_CANNOT_BE_ADDED, finished.oldKept)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_NOT_ADDED, finished.line)
        assertEquals("Family 2", finished.toVaultName)
        assertEquals(1, finished.notAdded.size)
        assertFalse(a.row().deleted, "the old vault is kept")
        a.vaults.closeMoveEverything()
        assertNull(a.snapshot.account!!.moving)
        // A vault in its grace is not offered.
        val fresh = a.snapshot.account!!.vaults.single { it.name == "Family 2" }
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(fresh))
        val deleted = a.snapshot.account!!.vaults.single { it.vaultId == fresh.vaultId }
        assertFalse(deleted.canMoveEverything, "the row and the intent agree")
        assertEquals(VaultActionResult.NOT_ALLOWED, a.vaults.openMoveEverything(deleted))
    }

    /** A stop says where it stopped, the old vault is untouched, and a second run carries on into the same new vault. */
    @Test fun aMoveThatStopsSaysWhereAndTheNextRunCarriesOnIntoTheSameNewVault() = runBlocking<Unit> {
        var refuseAddTo: String? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && refuseAddTo != null && id != refuseAddTo && id != null && id in serverLogs()) {
                        refuseAddTo = null
                        return WireResult.Refused(409, WireError("member_limit", "m"))
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        logsOf = server.logs
        open(a)
        val oldId = family(a, server)
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        // The new vault's first add is refused once (its genesis is the only other log).
        refuseAddTo = oldId
        val before = server.stored.size
        assertEquals(VaultActionResult.MEMBER_LIMIT, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val stopped = assertNotNull(assertNotNull(a.snapshot.account!!.moving).stopped)
        assertEquals(io.silencelen.andvari.core.app.MoveStage.ADD_MEMBERS, stopped.stage)
        assertEquals("Family 2", stopped.toVaultName)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STOPPED, stopped.line)
        assertFalse(a.row().deleted, "the old vault is untouched")
        assertEquals(listOf("new Genesis"), kinds(server.stored.drop(before), oldId))

        // Closed and opened again, the next run carries on: no second vault, the members, then the delete.
        a.vaults.closeMoveEverything()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val again = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "another name")
        assertEquals(VaultActionResult.DONE, again, "stopped at ${a.snapshot.account!!.moving?.stopped?.stage}: ${kinds(server.stored.drop(before), oldId)}")
        assertEquals(listOf("new Genesis", "new Add", "new Add", "old Delete"), kinds(server.stored.drop(before), oldId))
        assertEquals(2, server.logs.size, "one new vault, made once")
        assertTrue(a.snapshot.account!!.vaults.any { it.name == "Family 2" }, "under the name it was made with")
    }

    /** The verified members of [vaultId] on [a], this account left out. */
    private fun EngineAppApi.membersOf(vaultId: String): Set<String> =
        assertNotNull((vault!!.logs.status(vaultId) as? io.silencelen.andvari.core.client.log.VaultLogStatus.Verified)?.state).members.keys - keeper.session!!.userId

    /**
     * A move stops after one member was added to the new vault; the owner then takes "Remove" on
     * that member and "Move everything". The half-made vault holds someone this plan does not add, so the move does not
     * carry on into it (which would leave them its key): it says so before the start, makes a fresh vault, adds only
     * the others, deletes the old vault, and then deletes the half-made one. Before, the resume finished with the
     * removed member still in the new vault.
     */
    @Test fun aResumedMoveThatWouldKeepARemovedMemberStartsAFreshVaultAndDeletesTheHalfMadeOne() = runBlocking<Unit> {
        var appendsToNew = 0
        var refuseSecond = true
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && refuseSecond && firstOld != null && id != null && id != firstOld && id in serverLogs() && ++appendsToNew == 2) {
                        refuseSecond = false
                        return WireResult.Refused(409, WireError("member_limit", "m"))
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        logsOf = server.logs
        open(a)
        val oldId = family(a, server)
        firstOld = oldId
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.MEMBER_LIMIT, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val halfMade = server.logs.keys.single { it != oldId }
        val first = a.membersOf(halfMade).single()
        a.vaults.closeMoveEverything()

        // "Remove" on the member already in the half-made vault, then "Move everything" from there.
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        val row = a.snapshot.account!!.members!!.members.single { it.userId == first }
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(row))
        val screen = assertNotNull(a.snapshot.account!!.moving)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STARTS_FRESH, screen.startsFresh, "said before the start")
        val before = server.stored.size
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(screen, "ignored"))
        val fresh = server.logs.keys.single { it != oldId && it != halfMade }
        assertTrue(first !in a.membersOf(fresh), "the removed member is not in the vault the move ends in")
        val other = if (first == carol) dave else carol
        assertEquals(setOf(other), a.membersOf(fresh))
        val after = server.stored.drop(before)
        assertEquals(LogEntry.Remove::class, after.first().second!!::class, "the removed member goes from the old vault first")
        // The half-made vault goes first (it holds only copies; the old vault still holds everything), and
        // the old vault last.
        val halfGone = after.indexOfFirst { it.first == halfMade && it.second is LogEntry.Delete }
        assertTrue(halfGone >= 0, "the half-made vault is deleted")
        assertEquals(oldId, after.last().first, "and the old vault last")
        assertIs<LogEntry.Delete>(after.last().second)
    }

    // ---- the half-made vault of a stopped move is deleted only after a read shows it holds nothing but the move's copies ----

    /**
     * A move of "Family" (one login) stops after its first add to the new vault; the member it added is the one the next
     * run removes. Returns (old vault, half-made vault, that member, the half-made copy's id).
     */
    private suspend fun stoppedWithACopy(a: EngineAppApi, server: VaultServer): List<String> {
        val oldId = familyWithItems(a, server, count = 1)
        firstOld = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.MEMBER_LIMIT, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val halfMade = server.logs.keys.single { it != oldId }
        val first = a.membersOf(halfMade).single()
        val copy = server.items.values.single { it.vaultId == halfMade }.itemId
        a.vaults.closeMoveEverything()
        return listOf(oldId, halfMade, first, copy)
    }

    private fun refusingSecondAddToNew(): (WireClient) -> WireClient {
        var appendsToNew = 0
        var refuseSecond = true
        return { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && refuseSecond && firstOld != null && id != null && id != firstOld && id in serverLogs() && ++appendsToNew == 2) {
                        refuseSecond = false
                        return WireResult.Refused(409, WireError("member_limit", "m"))
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
    }

    /** "Remove" on [member] and "Move everything" from there, to the end. */
    private suspend fun removeAndMoveAgain(a: EngineAppApi, member: String) {
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == member }))
        val screen = assertNotNull(a.snapshot.account!!.moving)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STARTS_FRESH, screen.startsFresh)
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(screen, "ignored"), "stopped at ${a.snapshot.account!!.moving?.stopped?.stage}")
    }

    @Test fun anItemSavedIntoTheHalfMadeVaultKeepsItAndThePersonIsToldItsNameAndWhoStillHasIt() = runBlocking<Unit> {
        val (server, a) = app(refusingSecondAddToNew())
        logsOf = server.logs
        open(a)
        val (oldId, halfMade, first, _) = stoppedWithACopy(a, server)
        // A member the stopped move added saves an item of their own into the half-made vault (here from this device: the
        // rule is about what the vault holds, whoever saved it).
        val before = server.items.keys.toSet()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, assertNotNull(a.content).saveLogin(null,
            io.silencelen.andvari.core.app.LoginInput("Own", "me", "pw-own", listOf("https://own.test"), "", "", false), halfMade))
        val own = (server.items.keys - before).single()
        // The member as this device shows them, and as the server names them (each with a space: never inside a sealed blob).
        relabel(a, first, "Member As Shown")
        server.displayNames[first] = "Member As Served"

        removeAndMoveAgain(a, first)
        // The next run finished (the old vault deleted last), and the half-made vault is still there, with that item.
        assertTrue(server.stored.none { it.first == halfMade && it.second is LogEntry.Delete }, "the half-made vault is not deleted")
        assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete }, "the old vault is")
        assertFalse(server.items.getValue(own).deleted, "the member's item is still there")
        assertTrue(first in a.membersOf(halfMade), "it stays a vault of its own, with everyone who has it")
        val note = a.snapshot.account!!.moveNotes.single()
        assertEquals(halfMade, note.vaultId)
        assertEquals(listOf(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT, io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS), note.lines.map { it.key })
        assertEquals(listOf("Family 2", "1"), note.lines.first().values, "its name, and one item the move did not make")
        assertEquals(listOf("Family 2"), note.lines[1].values)
        assertEquals("Member As Shown", assertIs<PersonName.Contact>(note.member, "the member being removed, who still has it").label)
        val state = a.engine.state as io.silencelen.andvari.core.client.MemoryDeviceState
        val secure = a.engine.secure as io.silencelen.andvari.core.client.MemoryDeviceState
        // At rest: ids, key names and numbers only; no name of the vault's, nor of the member's (theirs, this device's, the server's).
        val names = listOf("Family 2", "Member As Shown", "Member As Served")
        assertEquals(emptyList(), namesAtRest(names, state, secure), "no name at rest")
        println("A move's note at rest: " + state.get(state.keys().single { it.startsWith(EngineSharedVaults.NOTES_PREFIX) }))
        fun said(n: io.silencelen.andvari.core.app.MoveNote) = listOf(n.oldVaultId, n.vaultId, n.lines.map { it.key.name to it.values }, (n.member as? PersonName.Contact)?.label)
        // Kept at rest until dismissed: a lock and a restart keep it (before: a lock cleared it, and nothing named the vault again).
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(said(note), said(a.snapshot.account!!.moveNotes.single()), "after a lock")
        // A contact renamed since reads by its present name.
        relabel(a, first, "Member Renamed Since")
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals("Member Renamed Since", (a.snapshot.account!!.moveNotes.single().member as PersonName.Contact).label)
        assertEquals(emptyList(), namesAtRest(names + "Member Renamed Since", state, secure), "no name at rest after a lock")
        a.close()
        val b = appOn(server, { it }, state, secure).second
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        val again = b.snapshot.account!!.moveNotes.single()
        assertEquals(said(note).dropLast(1) + "Member Renamed Since", said(again), "after a restart")
        assertEquals(emptyList(), namesAtRest(names + "Member Renamed Since", state, secure), "no name at rest after a restart")
        (b.vaults as io.silencelen.andvari.core.app.MoveNotes).dismissMoveNote(again)
        assertEquals(emptyList(), b.snapshot.account!!.moveNotes)
        assertTrue(state.keys().none { it.startsWith(EngineSharedVaults.NOTES_PREFIX) }, "dismissed: gone at rest")
        b.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertEquals(emptyList(), b.snapshot.account!!.moveNotes, "dismissed: gone at rest too")
    }

    /**
     * The fake keeps a move's notes as the engine does: the same sequence (a half-made vault kept with a member who still
     * holds it; a lock; a restart; the dismissal; a lock) reads the same on both, line by line. Before: the fake had no
     * notes at all.
     */
    @Test fun theFakeKeepsAMovesNotesAsTheEngineDoes() = runBlocking<Unit> {
        fun read(notes: List<io.silencelen.andvari.core.app.MoveNote>) =
            notes.map { n -> n.lines.map { it.key to it.values } to n.member?.let { it::class.simpleName } }

        val engine = Readings()
        val (server, a) = app(refusingSecondAddToNew())
        logsOf = server.logs
        open(a)
        val (_, halfMade, first, _) = stoppedWithACopy(a, server)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, assertNotNull(a.content).saveLogin(null,
            io.silencelen.andvari.core.app.LoginInput("Own", "me", "pw-own", listOf("https://own.test"), "", "", false), halfMade))
        removeAndMoveAgain(a, first)
        engine += read(a.snapshot.account!!.moveNotes)
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        engine += read(a.snapshot.account!!.moveNotes)
        val state = a.engine.state as io.silencelen.andvari.core.client.MemoryDeviceState
        val secure = a.engine.secure as io.silencelen.andvari.core.client.MemoryDeviceState
        a.close()
        val b = appOn(server, { it }, state, secure).second
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        engine += read(b.snapshot.account!!.moveNotes)
        (b.vaults as io.silencelen.andvari.core.app.MoveNotes).dismissMoveNote(b.snapshot.account!!.moveNotes.single())
        engine += read(b.snapshot.account!!.moveNotes)
        b.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        engine += read(b.snapshot.account!!.moveNotes)

        val fake = Readings()
        val f =io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        val pw = io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD
        assertEquals(VaultActionResult.DONE, f.vaults.openMembers(f.snapshot.account!!.vaults.first { it.name == "Family" }))
        val member = f.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        assertEquals(VaultActionResult.DONE, f.vaults.openMoveEverythingRemoving(member))
        f.script.nextMoveKeepsHalfMade = 1
        assertEquals(VaultActionResult.DONE, f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2"))
        fake += read(f.snapshot.account!!.moveNotes)
        f.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, f.unlock(f.snapshot.locked!!, pw))
        fake += read(f.snapshot.account!!.moveNotes)
        f.script.restart()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, f.unlock(f.snapshot.locked!!, pw))
        fake += read(f.snapshot.account!!.moveNotes)
        (f.vaults as io.silencelen.andvari.core.app.MoveNotes).dismissMoveNote(f.snapshot.account!!.moveNotes.single())
        fake += read(f.snapshot.account!!.moveNotes)
        f.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, f.unlock(f.snapshot.locked!!, pw))
        fake += read(f.snapshot.account!!.moveNotes)

        assertTrue(read(listOf()) != engine.first(), "the engine said something: $engine")
        assertEquals<List<Any?>>(engine, fake)
    }

    /** [userId]'s contact on [a] now reads [label] (the same key, still current here). */
    private suspend fun relabel(a: EngineAppApi, userId: String, label: String) {
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (userId to doc.contacts.getValue(userId).copy(label = io.silencelen.andvari.core.trust.TrustGrammar.encodeName(label)!!)))
        }
    }

    /** Every key and every value of [stores] that holds one of [names]. */
    private fun namesAtRest(names: List<String>, vararg stores: io.silencelen.andvari.core.client.MemoryDeviceState): List<String> =
        stores.flatMap { s -> s.keys().flatMap { k -> listOf(k, s.get(k).orEmpty()) } }.filter { t -> names.any { it in t } }

    /**
     * A move's note, read from the device, takes only the move's own lines, each in its own shape: a line of another key, or
     * of a wrong shape, in a record edited at rest is left out, and a note left with no line is not shown. Before: any
     * sentence of the app, with any values, was shown in the place of the notes.
     */
    @Test fun aNoteAtRestShowsOnlyTheMovesOwnLinesInTheirOwnShape() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val vaultId = server.logs.keys.single()
        val key = EngineSharedVaults.NOTES_PREFIX + a.vault!!.origin + "|" + a.vault!!.userId
        a.engine.state.set(key, """[{"old":"o1","vault":"$vaultId","lines":[""" +
            """{"key":"MOVE_HALF_MADE_KEPT_CANNOT_TELL","values":[null]},""" +
            """{"key":"ACCOUNT_DELETED_SERVER_FORGOTTEN","values":[null]},""" +
            """{"key":"MOVE_KEPT_BESIDE_CHANGED","values":[null,3]},""" +
            """{"key":"MOVE_HALF_MADE_KEPT","values":[null,0]},""" +
            """{"key":"MOVE_HALF_MADE_KEPT_MEMBER_HOLDS","values":[null]}]},""" +
            """{"old":"o2","vault":"$vaultId","lines":[{"key":"DEVICE_LINK_TOO_MANY","values":[5]}]}]""")
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val note = a.snapshot.account!!.moveNotes.single()
        assertEquals("o1", note.oldVaultId)
        assertEquals(listOf(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_CANNOT_TELL to listOf("Family")), note.lines.map { it.key to it.values })
        assertNull(note.member, "a member's line with no member is left out, and no member is named")
    }

    /**
     * Earlier copies kept beside a newer one at a move's end: the note names the new vault when read, holds no name at rest,
     * and reads the same after a lock and a restart until dismissed.
     */
    @Test fun earlierCopiesKeptBesideANewerOneAreToldWithTheVaultsNameAndNoNameAtRest() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        server.servesItems = true
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        val c = assertNotNull(a.content)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val newId = server.logs.keys.single { it != oldId }
        val earlier = server.items.values.single { it.vaultId == newId && !it.deleted }.itemId
        // While the delete waits, another member changes the item in the old vault, and someone changes its copy in the new one.
        val original = a.vault!!.items.items().single { it.vaultId == oldId }
        server.items[original.itemId] = server.items.getValue(original.itemId).copy(rev = server.rev++)
        server.items[earlier] = server.items.getValue(earlier).copy(rev = server.rev++)
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.PASS
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        a.vault!!.afterLogAction()
        assertFalse(server.items.getValue(earlier).deleted, "the earlier copy, changed there since, stands beside the newer one")
        val note = a.snapshot.account!!.moveNotes.single()
        assertEquals(oldId, note.oldVaultId)
        assertEquals(newId, note.vaultId)
        assertEquals(listOf(io.silencelen.andvari.core.app.CopyKey.MOVE_KEPT_BESIDE_CHANGED to listOf("1", "Family 2")), note.lines.map { it.key to it.values })
        assertNull(note.member)
        val state = a.engine.state as io.silencelen.andvari.core.client.MemoryDeviceState
        val secure = a.engine.secure as io.silencelen.andvari.core.client.MemoryDeviceState
        assertTrue(state.keys().any { it.startsWith(EngineSharedVaults.NOTES_PREFIX) }, "kept at rest")
        assertEquals(emptyList(), namesAtRest(listOf("Family 2"), state, secure), "no name at rest")
        fun said(n: io.silencelen.andvari.core.app.MoveNote) = listOf(n.oldVaultId, n.vaultId, n.lines.map { it.key.name to it.values })
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(said(note), said(a.snapshot.account!!.moveNotes.single()), "after a lock")
        a.close()
        val b = appOn(server, { it }, state, secure).second
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        val again = b.snapshot.account!!.moveNotes.single()
        assertEquals(said(note), said(again), "after a restart")
        assertEquals(emptyList(), namesAtRest(listOf("Family 2"), state, secure), "no name at rest after a restart")
        (b.vaults as io.silencelen.andvari.core.app.MoveNotes).dismissMoveNote(again)
        assertEquals(emptyList(), b.snapshot.account!!.moveNotes)
        assertTrue(state.keys().none { it.startsWith(EngineSharedVaults.NOTES_PREFIX) }, "dismissed: gone at rest")
    }

    @Test fun aCopyChangedInTheHalfMadeVaultKeepsItAndOnlyCopiesAtTheirRevisionLetItGo() = runBlocking<Unit> {
        for (changed in listOf(true, false)) {
            firstOld = null
            val (server, a) = app(refusingSecondAddToNew())
            logsOf = server.logs
            open(a)
            val (oldId, halfMade, first, copy) = stoppedWithACopy(a, server)
            if (changed) {
                // Someone changed the move's copy in the half-made vault since the move made it.
                assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, assertNotNull(a.content).saveLogin(copy,
                    io.silencelen.andvari.core.app.LoginInput("Site 0", "me", "changed there", listOf("https://s0.test"), "", "", false), halfMade))
            }
            removeAndMoveAgain(a, first)
            val halfDeleted = server.stored.any { it.first == halfMade && it.second is LogEntry.Delete }
            assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete }, "changed=$changed: the move finished")
            if (changed) {
                assertFalse(halfDeleted, "a copy changed since keeps the half-made vault")
                assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT, a.snapshot.account!!.moveNotes.single().lines.first().key)
            } else {
                assertTrue(halfDeleted, "only the move's copies, each at the revision it made: deleted as before")
                assertEquals(emptyList(), a.snapshot.account!!.moveNotes)
            }
        }
    }

    @Test fun aHalfMadeVaultWhoseTrashCannotBeReadIsNotDeletedAndNothingIsSaidOfWhatItHolds() = runBlocking<Unit> {
        var trashFails = false
        val refusing = refusingSecondAddToNew()
        val (server, a) = app { inner ->
            val front = refusing(inner)
            object : WireClient by front {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.ITEMS_DELETED && trashFails) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    return front.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        logsOf = server.logs
        open(a)
        val (oldId, halfMade, first, _) = stoppedWithACopy(a, server)
        trashFails = true
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == first }))
        assertEquals(VaultActionResult.FAILED, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DISCARD_UNREAD, a.snapshot.account!!.moving!!.stopped!!.line)
        assertTrue(server.stored.none { it.second is LogEntry.Delete }, "nothing is deleted")
        assertEquals(emptyList(), a.snapshot.account!!.moveNotes)
        // Read again on the next run: only the move's copy, so it goes, then the old vault.
        trashFails = false
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(listOf(halfMade, oldId), server.stored.filter { it.second is LogEntry.Delete }.map { it.first })
    }

    // ---- The move checks for space before anything is signed or sent ----

    private fun meters(bytes: Pair<Long, Long> = 0L to (1L shl 40), items: Pair<Long, Long> = 0L to 1000L, vaults: Pair<Long, Long> = 1L to 100L) =
        io.silencelen.andvari.core.model.wire.QuotaUse(
            io.silencelen.andvari.core.model.wire.QuotaMeter(bytes.first, bytes.second), io.silencelen.andvari.core.model.wire.QuotaMeter(items.first, items.second),
            io.silencelen.andvari.core.model.wire.QuotaMeter(vaults.first, vaults.second), io.silencelen.andvari.core.model.wire.QuotaMeter(0, 100))

    /** "Family" (Carol and Dave) with [count] logins in it, on a server that stores pushes and serves items. */
    private suspend fun familyWithItems(a: EngineAppApi, server: VaultServer, count: Int = 1, file: Int = 0): String {
        server.servesItems = true
        val oldId = family(a, server)
        a.vaults.closeMembers()
        val c = assertNotNull(a.content)
        for (i in 0 until count) {
            if (file > 0 && i == 0) {
                c.openAttachmentDraft(null)
                assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, c.addAttachment("big.bin", ByteArray(file) { 7 }))
            }
            assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
                c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Site $i", "me", "pw$i", listOf("https://s$i.test"), "", "", false), oldId))
            if (file > 0 && i == 0) c.closeAttachmentDraft()
        }
        a.vault!!.afterLogAction()
        assertEquals(count, server.items.values.count { it.vaultId == oldId })
        return oldId
    }

    /**
     * Short on each meter in turn (the bytes, the items, the owned shared vaults): the run stops before anything is signed
     * or sent (no log entry, no push), and the screen says which limit and by how much.
     */
    @Test fun aMoveShortOnEachMeterInTurnSignsAndSendsNothingAndSaysWhichLimit() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        val oldId = familyWithItems(a, server, count = 2)
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val itemsBefore = server.items.size
        for ((meter, quota) in listOf(
            io.silencelen.andvari.core.model.wire.QuotaName.ACCOUNT_BYTES to meters(bytes = 10L to 10L),
            io.silencelen.andvari.core.model.wire.QuotaName.ITEMS to meters(items = 5L to 6L),
            io.silencelen.andvari.core.model.wire.QuotaName.OWNED_SHARED_VAULTS to meters(vaults = 3L to 3L),
        )) {
            server.quota = quota
            val stored = server.stored.size
            val mark = server.calls.size
            assertEquals(VaultActionResult.OUT_OF_SPACE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"), meter)
            val screen = assertNotNull(a.snapshot.account!!.moving)
            val space = assertNotNull(screen.space, meter)
            assertEquals(io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH, space.verdict, meter)
            assertEquals(meter, space.limits.first().quota)
            assertNotNull(space.line, meter)
            if (meter == io.silencelen.andvari.core.model.wire.QuotaName.ITEMS) assertEquals(1L, space.limits.first().by, "two items into one place left")
            assertEquals(VaultActionResult.OUT_OF_SPACE, assertNotNull(screen.stopped).result)
            assertTrue(screen.shortOfSpace)
            assertEquals(stored, server.stored.size, "$meter: nothing signed")
            assertEquals(itemsBefore, server.items.size, "$meter: nothing copied")
            assertTrue(server.calls.drop(mark).none { it == WireRoute.LOG_APPEND || it == WireRoute.PUSH }, "$meter: nothing sent but the sync: ${server.calls.drop(mark)}")
        }
        assertTrue(server.logs.keys.all { it == oldId }, "no new vault")
    }

    /** Exactly at each limit is room: the move runs to its end and the screen shows no shortage. */
    @Test fun aMoveExactlyAtTheLimitsRuns() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        val oldId = familyWithItems(a, server, count = 2)
        server.quota = meters(items = 4L to 6L, vaults = 2L to 3L)
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete })
        assertEquals(2, server.items.values.count { it.vaultId != oldId })
    }

    /** No use and limits served (an older server): "unknown" starts the move, and the server decides. */
    @Test fun aMoveWithUnknownSpaceStarts() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        val oldId = familyWithItems(a, server)
        server.quota = null
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete })
    }

    /**
     * A carried-on run counts only what is not copied yet: the first run made the new vault and copied both items, then
     * stopped at an add. With every meter now full, the second run adds nothing to any of them and runs to its end.
     */
    @Test fun aCarriedOnMoveCountsOnlyWhatIsNotCopiedYet() = runBlocking<Unit> {
        var refuseAdd = false
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && refuseAdd && id != null && id != firstOld && id in serverLogs() && serverLogs().size > 1) {
                        refuseAdd = false
                        return WireResult.Refused(409, WireError("member_limit", "m"))
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
                override suspend fun <T> callBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, body: ByteArray, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                    inner.callBytes(route, pathParams, query, body, authenticated, decode)
            }
        }
        logsOf = server.logs
        open(a)
        val oldId = familyWithItems(a, server, count = 2)
        firstOld = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        refuseAdd = true
        assertEquals(VaultActionResult.MEMBER_LIMIT, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertEquals(2, server.items.values.count { it.vaultId != oldId }, "both items copied")
        server.quota = meters(bytes = 100L to 100L, items = 4L to 4L, vaults = 2L to 2L)
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete })
    }

    /**
     * Short only because of the size a file's item states (another member may have written it): the move goes on, the
     * server decides, and the screen says so.
     */
    @Test fun aShortageThatRestsOnlyOnDeclaredFileSizesLetsTheMoveGoOnAndSaysSo() = runBlocking<Unit> {
        // The test transport hands downloads to the server; this server serves none (the copy below stops at the file).
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> =
                    WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
                override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?): WireResult<ByteArray> =
                    WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
            }
        }
        server.filesUpTo = 1L shl 20
        open(a)
        val oldId = familyWithItems(a, server, count = 1, file = 500)
        // Room for the item's own sealed bytes, not for the 500-byte file its document states as well.
        val sealed = Bytes.fromB64(server.items.values.single { it.vaultId == oldId }.blob!!).size.toLong()
        server.quota = meters(bytes = 0L to sealed + 250)
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val before = server.stored.size
        a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertTrue(server.stored.drop(before).any { it.first != oldId && it.second is LogEntry.Genesis }, "the move went on")
        // This server does not serve the file for its copy, so the run stops at the copy, with the screen still up.
        val space = assertNotNull(assertNotNull(a.snapshot.account!!.moving, "the screen stays").space, "the screen says so")
        assertEquals(io.silencelen.andvari.core.app.content.SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES, space.verdict)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SPACE_SHORT_DECLARED, space.line?.key)
    }

    // ---- A delete the server never stored is not "deleted" ----

    /**
     * Declining an incoming vault records the decline for the account and signs a `leave` so the owner sees it. When
     * that `leave` gets no answer, the decline is not reported as DONE (the server did not store the leave): it is
     * SENT_PENDING, as every other entry that waits. Before, it answered DONE.
     */
    @Test fun aDeclineWhoseLeaveGetsNoAnswerIsNotReportedAsStored() = runBlocking<Unit> {
        val server = VaultServer(FakeInstance(crypto)).also { it.statesByCaller = true }
        val (_, bob) = appOn(server)
        open(bob, "bob@example.com")
        var loseLeaves = false
        val (_, alice) = appOn(server, front = { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.LOG_APPEND && loseLeaves) {
                        val frame = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry
                        if (VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry is LogEntry.Leave) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        })
        open(alice, "alice@example.com")
        val (aliceId, aliceKey) = alice.me()
        val (bobId, bobKey) = bob.me()
        val a = knows(bob, server, aliceId, aliceKey, "Alice")
        assertEquals(VaultActionResult.DONE, bob.vaults.createVault("Family"))
        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.addMember(bob.snapshot.account!!.members!!, a, io.silencelen.andvari.core.trust.MemberRole.READER))
        bob.vaults.closeMembers()
        knows(alice, server, bobId, bobKey, "Bob")
        alice.content!!.refresh()
        val prompt = assertIs<io.silencelen.andvari.core.app.AccountPrompt.IncomingVault>(
            alice.snapshot.account!!.prompts.singleOrNull { it is io.silencelen.andvari.core.app.AccountPrompt.IncomingVault }, "${alice.snapshot.account!!.prompts}")
        loseLeaves = true
        assertEquals(VaultActionResult.SENT_PENDING, alice.vaults.declineIncoming(prompt))
        assertTrue(server.stored.none { it.second is LogEntry.Leave }, "the server holds no leave")
        assertTrue(alice.snapshot.account!!.prompts.none { it is io.silencelen.andvari.core.app.AccountPrompt.IncomingVault }, "the decline itself is recorded")
    }

    /**
     * The person's own leave, refused by the server: the quiet going the item engine was told to expect before the leave
     * was signed is withdrawn, so when the owner later removes this account the vault's going is said, never taken as the
     * person's own. Before, the expectation stayed and the removal went without a word.
     */
    @Test fun aLeaveTheServerRefusedIsWithdrawnSoALaterRemovalIsSaid() = runBlocking<Unit> {
        val server = VaultServer(FakeInstance(crypto)).also { it.statesByCaller = true }
        val (_, bob) = appOn(server)
        open(bob, "bob@example.com")
        var refuseLeaves = false
        val (_, alice) = appOn(server, front = { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.LOG_APPEND && refuseLeaves) {
                        val frame = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry
                        if (VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry is LogEntry.Leave) return WireResult.Refused(403, WireError("forbidden", "m"))
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        })
        open(alice, "alice@example.com")
        val (aliceId, aliceKey) = alice.me()
        val (bobId, bobKey) = bob.me()
        val a = knows(bob, server, aliceId, aliceKey, "Alice")
        assertEquals(VaultActionResult.DONE, bob.vaults.createVault("Family"))
        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.addMember(bob.snapshot.account!!.members!!, a, io.silencelen.andvari.core.trust.MemberRole.READER))
        bob.vaults.closeMembers()
        knows(alice, server, bobId, bobKey, "Bob")
        alice.content!!.refresh()
        val prompt = assertIs<io.silencelen.andvari.core.app.AccountPrompt.IncomingVault>(
            alice.snapshot.account!!.prompts.singleOrNull { it is io.silencelen.andvari.core.app.AccountPrompt.IncomingVault }, "${alice.snapshot.account!!.prompts}")
        assertEquals(VaultActionResult.DONE, alice.vaults.acceptIncoming(prompt))
        alice.content!!.refresh()
        val vaultId = alice.row().vaultId
        assertTrue(alice.content!!.state.vaults.any { it.vaultId == vaultId }, "the vault is open on Alice's device")

        refuseLeaves = true
        val left = alice.vaults.leaveVault(alice.row())
        assertTrue(left != VaultActionResult.DONE && left != VaultActionResult.SENT_PENDING, "the refused leave is not done: $left")
        assertTrue(server.stored.none { it.second is LogEntry.Leave }, "the server holds no leave")
        alice.content!!.refresh()
        assertTrue(alice.content!!.state.vaults.any { it.vaultId == vaultId }, "the vault is still open after the refused leave")
        val before = alice.content!!.state.vaultNotices.size

        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.removeMember(bob.snapshot.account!!.members!!.members.single { it.userId == aliceId }))
        bob.vaults.closeMembers()
        alice.content!!.refresh()
        assertTrue(alice.content!!.state.vaults.none { it.vaultId == vaultId }, "the vault left Alice's open vaults")
        assertTrue(alice.content!!.state.vaultNotices.size > before,
            "the owner's removal is said, not taken quietly: ${alice.content!!.state.vaultNotices.map { it.text }}")
    }

    /**
     * Removed from a shared vault (the copy kept), added again, and the answer refused by the server: the kept copy opens
     * (decided on 23 November 2026) and the invitation stays among the prompts after the refresh that follows, so that
     * the person can answer it again. The refresh asks whether the vault's adoption is settled, not whether its kept copy
     * may be copied out: a held key that copies out leaves the invitation to be answered.
     */
    @Test fun aKeptCopyWhoseAnswerTheServerRefusedOpensAndItsInvitationStaysToBeAnsweredAgain() = runBlocking<Unit> {
        val server = VaultServer(FakeInstance(crypto)).also { it.statesByCaller = true }
        val (_, bob) = appOn(server)
        open(bob, "bob@example.com")
        var refuseAnswers = false
        val (_, alice) = appOn(server, front = { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.ACCOUNT_STATE_PUT && refuseAnswers) return WireResult.Refused(403, WireError("forbidden", "m"))
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        })
        open(alice, "alice@example.com")
        val (aliceId, aliceKey) = alice.me()
        val (bobId, bobKey) = bob.me()
        val a = knows(bob, server, aliceId, aliceKey, "Alice")
        assertEquals(VaultActionResult.DONE, bob.vaults.createVault("Family"))
        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.addMember(bob.snapshot.account!!.members!!, a, io.silencelen.andvari.core.trust.MemberRole.READER))
        bob.vaults.closeMembers()
        knows(alice, server, bobId, bobKey, "Bob")
        alice.content!!.refresh()
        fun incoming() = alice.snapshot.account!!.prompts.filterIsInstance<io.silencelen.andvari.core.app.AccountPrompt.IncomingVault>()
        assertEquals(VaultActionResult.DONE, alice.vaults.acceptIncoming(incoming().single()))
        alice.content!!.refresh()
        val vaultId = alice.row().vaultId

        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.removeMember(bob.snapshot.account!!.members!!.members.single { it.userId == aliceId }))
        bob.vaults.closeMembers()
        alice.content!!.refresh()
        assertTrue(alice.content!!.state.held.single { it.vaultId == vaultId }.readable, "removed: the copy is kept and opens")

        assertEquals(VaultActionResult.DONE, bob.vaults.openMembers(bob.row()))
        assertEquals(VaultActionResult.DONE, bob.vaults.addMember(bob.snapshot.account!!.members!!, a, io.silencelen.andvari.core.trust.MemberRole.READER))
        bob.vaults.closeMembers()
        alice.content!!.refresh()
        val asked = assertNotNull(incoming().singleOrNull { it.vaultId == vaultId }, "added again: asked: ${alice.snapshot.account!!.prompts}")
        assertFalse(alice.content!!.state.held.single { it.vaultId == vaultId }.readable, "asked: the copy is closed")

        refuseAnswers = true
        val refused = alice.vaults.acceptIncoming(asked)
        refuseAnswers = false
        assertNotEquals(VaultActionResult.DONE, refused, "the server refused the answer")
        alice.content!!.refresh()
        assertTrue(alice.content!!.state.held.single { it.vaultId == vaultId }.readable, "after the refused answer: the copy opens")
        assertTrue(alice.content!!.state.vaults.none { it.vaultId == vaultId }, "and the vault is not one the account may use")
        val again = assertNotNull(incoming().singleOrNull { it.vaultId == vaultId },
            "after the refresh, the invitation is still there to be answered: ${alice.snapshot.account!!.prompts}")
        assertEquals(VaultActionResult.DONE, alice.vaults.acceptIncoming(again), "answered again, and taken")
        alice.content!!.refresh()
        assertTrue(alice.content!!.state.vaults.any { it.vaultId == vaultId }, "the vault is back")
    }

    /** How the front below answers a `delete` (on the vaults [lossy] names): passed on, lost, or stored and unanswered. */
    /** [LIE_STORED]: answered `200` naming the deletion stored at its own place, while the server stores nothing. */
    private enum class DeleteAnswer { PASS, LOST, STORED_UNANSWERED_ONCE, REFUSED, LIE_STORED }

    /**
     * A front that answers every `delete` posted for a vault [lossy] accepts as [mode] says, and keeps each such frame
     * posted (in [posted]), so a test can tell a byte-identical re-post from a newly signed entry.
     */
    private class DeleteFront(val lossy: (String) -> Boolean) {
        var mode = DeleteAnswer.PASS
        val posted = ArrayList<Pair<String, String>>()

        /** The read point each posted `delete` named beside it, in the order of [posted]. */
        val points = ArrayList<Long?>()

        /** Called as each `delete` arrives, before it is answered: what the device holds at that moment. */
        var onDelete: ((String) -> Unit)? = null
        val crypto = createCryptoProvider()

        fun wrap(inner: WireClient): WireClient = object : WireClient by inner {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                val id = pathParams["vaultId"]
                if (route == WireRoute.LOG_APPEND && id != null && lossy(id)) {
                    val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                    val frame = req.entry
                    if (VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry is LogEntry.Delete) {
                        posted += id to frame
                        points += req.itemsAtMost
                        onDelete?.invoke(id)
                        when (mode) {
                            DeleteAnswer.PASS -> {}
                            DeleteAnswer.LOST -> return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                            DeleteAnswer.REFUSED -> return WireResult.Refused(403, WireError("forbidden", "x"))
                            DeleteAnswer.LIE_STORED -> {
                                val bytes = Bytes.fromB64(frame)
                                val seq = VaultLog.parse(crypto, bytes).valueOrNull()!!.entry.seq
                                val head = LogHead(seq, Bytes.toHexLower(crypto.sha256(bytes)), 0)
                                return WireResult.Ok(decode(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(1_000, head))), 200)
                            }
                            DeleteAnswer.STORED_UNANSWERED_ONCE -> {
                                mode = DeleteAnswer.PASS
                                inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                                return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                            }
                        }
                    }
                }
                return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
    }

    private fun EngineAppApi.oldRow(oldId: String) = snapshot.account!!.vaults.single { it.vaultId == oldId }

    private fun EngineAppApi.ownerNotices(): List<String> =
        content!!.state.vaultNotices.map { it.text }.filter { "deleted by its owner" in it || "deleted for good by its owner" in it }

    /**
     * The old vault's delete never gets an answer. The move does not count it as done: it stops at the delete with the
     * run kept, the old vault is still listed (not deleted), and the screen says it still exists and that moving again
     * finishes it. A second run without an answer re-posts the same frame and signs nothing new; once the server answers,
     * the next run finishes with that one delete. Before, the first run closed the screen as done and forgot the run.
     */
    @Test fun anOldVaultsDeleteThatNeverGetsAnAnswerIsNotDoneAndTheNextRunFinishesIt() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val before = server.stored.size
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val screen = assertNotNull(a.snapshot.account!!.moving, "the screen stays: the move is not done")
        val stopped = assertNotNull(screen.stopped)
        assertEquals(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, stopped.stage)
        assertEquals(VaultActionResult.SENT_PENDING, stopped.result)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_UNCONFIRMED, stopped.line)
        assertFalse(a.oldRow(oldId).deleted, "the old vault still exists")
        assertTrue(a.oldRow(oldId).changeWaiting)
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete })
        assertTrue(front.posted.isNotEmpty())

        // Closed and opened again, still no answer: the same frame again, nothing newly signed, nothing else sent.
        a.vaults.closeMoveEverything()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_UNCONFIRMED, assertNotNull(a.snapshot.account!!.moving?.stopped).line)
        assertEquals(1, front.posted.map { it.second }.distinct().size, "one delete, re-posted byte for byte")
        assertEquals(listOf("new Genesis", "new Add", "new Add"), kinds(server.stored.drop(before), oldId))

        // The server answers again: the next run finishes with that same delete.
        front.mode = DeleteAnswer.PASS
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertNull(a.snapshot.account!!.moving, "done: the screen closes")
        assertEquals(listOf("new Genesis", "new Add", "new Add", "old Delete"), kinds(server.stored.drop(before), oldId))
        assertEquals(1, front.posted.map { it.second }.distinct().size, "never signed twice")
        assertTrue(a.oldRow(oldId).deleted, "deleted now that the server stored it")
        assertEquals(emptyList(), a.ownerNotices(), "the person's own delete is not news")
    }

    /**
     * The server stores the delete but its answer is lost. The run still stops at the delete; the late answer (the
     * re-post's) or the next run's own look at the server shows it stored, and the next run finishes without sending a
     * new delete.
     */
    @Test fun aDeleteStoredWhoseAnswerCameLateFinishesAtTheNextRunWithoutASecondDelete() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        front.mode = DeleteAnswer.STORED_UNANSWERED_ONCE
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        // The sync after the send already shows the delete in the verified log: the run counts it as stored then. Had
        // it not, the next run reads the log first and finishes without posting.
        val first = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete }, "the server holds it")
        if (first == VaultActionResult.SENT_PENDING) {
            assertEquals(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, assertNotNull(a.snapshot.account!!.moving?.stopped).stage)
            assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        } else {
            assertEquals(VaultActionResult.DONE, first)
        }
        assertNull(a.snapshot.account!!.moving)
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete }, "one delete")
        assertEquals(1, front.posted.map { it.second }.distinct().size, "no second delete was signed")
        assertTrue(a.oldRow(oldId).deleted)
        assertEquals(emptyList(), a.ownerNotices())
    }

    /**
     * The delete never got an answer, the vault was locked, and the server stores the delete only after the unlock (the
     * re-post after the first sync). The departure the next sync sees is the person's own: no "deleted by its owner".
     */
    @Test fun anOwnDeleteTheServerStoresOnlyAfterALockIsNotShownAsDeletedByItsOwner() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        server.servesItems = true
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            a.content!!.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))

        a.lock()
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        front.mode = DeleteAnswer.PASS
        val posted = front.posted.size
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        a.vault!!.afterLogAction()
        // The unlock re-posts nothing of the move.
        assertEquals(posted, front.posted.size, "nothing of the move is re-posted at the unlock")
        assertEquals(0, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        assertFalse(a.oldRow(oldId).deleted)
        // The move, run again, re-posts it last and finishes.
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 3"))
        a.vault!!.afterLogAction()
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete }, "the held delete, stored once")
        assertTrue(a.content!!.state.vaults.none { it.vaultId == oldId }, "the vault left this device's open vaults")
        assertEquals(emptyList(), a.ownerNotices(), "the person's own delete is not shown as the owner's")
    }

    /**
     * An item put into the old vault between the stop and the second run is copied into the new vault
     * before the held delete is re-posted, so nothing goes into the deleted vault's grace unseen.
     */
    @Test fun anItemAddedWhileTheDeleteWaitsIsCopiedBeforeTheDeleteIsSentAgain() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        server.servesItems = true
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        val c = assertNotNull(a.content)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val newId = server.logs.keys.single { it != oldId }
        assertEquals(1, server.items.values.count { it.vaultId == newId })
        // Another item arrives in the old vault while its delete waits (another member's: this device takes none there).
        assertNotEquals<Any>(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Mail", "me", "pw2", listOf("https://mail.test"), "", "", false), oldId))
        anotherMemberAdds(a, server, oldId, "Mail")
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.PASS
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(2, server.items.values.count { it.vaultId == newId && !it.deleted }, "both items are in the new vault")
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        assertEquals(1, front.posted.map { it.second }.distinct().size, "the held delete, never signed twice")
    }

    /**
     * The account's other device removes [member] from [vaultId]: the owner's own `remove`, signed with the account's key
     * at the head the server holds, stored on the server's log (and the grant gone), as if posted from elsewhere.
     */
    private fun otherDeviceRemoves(a: EngineAppApi, server: VaultServer, vaultId: String, member: String) {
        val log = server.logs.getValue(vaultId)
        val state = assertNotNull(VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state)
        val pos = VaultLog.position(state, server.instance.now + 1_000)
        val me = a.keeper.established!!
        val entry = LogEntry.Remove(vaultId, pos.seq, pos.prev, me.userId, pos.at, member)
        val frame = me.account.signing.use { kp -> VaultLog.sign(crypto, kp, entry) }
        log += Bytes.toB64(frame)
        server.stored += vaultId to entry
        server.grants.remove(vaultId to member)
    }

    /**
     * As decided on 16 November 2026: an item changed in the old vault while the delete waits replaces its earlier copy
     * in the new vault, by the move's own record: the new vault holds the new revision once, never two copies. Before, the
     * second run copied the new revision beside the first copy.
     */
    @Test fun anItemChangedWhileTheDeleteWaitsReplacesItsCopyAndIsNeverInTheNewVaultTwice() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        server.servesItems = true
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        val c = assertNotNull(a.content)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val newId = server.logs.keys.single { it != oldId }
        assertEquals(1, server.items.values.count { it.vaultId == newId && !it.deleted })
        // The item is changed in the old vault while its delete waits (by another member: this device changes nothing there).
        val original = a.vault!!.items.items().single { it.vaultId == oldId }
        assertNotEquals<Any>(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(original.itemId, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw2", listOf("https://bank.test"), "", "", false), oldId))
        server.items[original.itemId] = server.items.getValue(original.itemId).copy(rev = server.rev++)
        a.vault!!.afterLogAction()
        assertTrue(a.vault!!.items.item(original.itemId)!!.rev > original.rev)
        front.mode = DeleteAnswer.PASS
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        a.vault!!.afterLogAction()
        assertEquals(1, server.items.values.count { it.vaultId == newId && !it.deleted }, "the new revision once, not two copies")
        assertEquals(1, server.items.values.count { it.vaultId == newId && it.deleted }, "the earlier copy went to the new vault's trash")
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        assertEquals(1, front.posted.map { it.second }.distinct().size, "the held delete, never signed twice")
    }

    /**
     * A membership change stored on the old vault while its delete waits takes the delete's
     * place. The held delete is dropped and never stored; the next run reads the members again and, since the half-made
     * new vault holds someone no longer to be added, says that a fresh vault is made before it makes one. The old vault
     * is deleted only by a NEW delete, signed when every condition holds again.
     */
    @Test fun aMembershipChangeStoredWhileTheDeleteWaitsDropsItAndOnlyANewDeleteIsEverSigned() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val halfMade = server.logs.keys.single { it != oldId }
        val held = front.posted.single().second
        // Meanwhile the account's other device removes Dave from the old vault: stored where the delete would have gone.
        otherDeviceRemoves(a, server, oldId, dave)
        front.mode = DeleteAnswer.PASS

        // The next run reads the log first: the held delete can never be stored, and the members changed. Nothing is
        // deleted; the screen now says that a fresh vault will be made.
        assertEquals(VaultActionResult.CHANGED_MEANWHILE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertTrue(server.stored.none { it.second is LogEntry.Delete }, "nothing is deleted")
        val screen = assertNotNull(a.snapshot.account!!.moving)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STARTS_FRESH, screen.startsFresh)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_UNFINISHED, a.oldRow(oldId).unfinishedMove?.key, "no deletion waits any more")
        assertTrue(screen.members.none { it.userId == dave })

        // Moving again: a fresh vault with Carol only, the half-made one deleted, and the old vault deleted by a new delete.
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(screen, "ignored"))
        val deletes = server.stored.filter { it.second is LogEntry.Delete }.map { it.first }
        assertEquals(listOf(halfMade, oldId), deletes)
        val oldDeletes = front.posted.filter { it.first == oldId }.map { it.second }.distinct()
        assertTrue(held !in server.logs.getValue(oldId), "the held delete was never stored")
        assertEquals(2, oldDeletes.size, "the old vault's delete is a newly signed one")
        val fresh = server.logs.keys.single { it != oldId && it != halfMade }
        assertEquals(setOf(carol), a.membersOf(fresh) - a.me().first)
        assertNull(a.snapshot.account!!.moving)
        assertEquals(emptyList(), a.snapshot.account!!.unfinishedMoves)
    }

    /**
     * The window between the run's last read of the old vault's log and its delete: a membership change stored there
     * (after the adds) makes the run stop and read again; no delete is signed over members it did not check. Before, the
     * sync after the adds took in the change and the delete was signed over it at once.
     */
    @Test fun aMembershipChangeStoredJustBeforeTheDeleteMakesTheRunReadAgainAndSignNothing() = runBlocking<Unit> {
        var inject: (() -> Unit)? = null
        var oldOf: String? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val r = inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && id != null && oldOf != null && id != oldOf) {
                        val frame = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry
                        val e = VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
                        if (e is LogEntry.Add && e.member == dave) inject?.let { inject = null; it() }
                    }
                    return r
                }
            }
        }
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        // Once Dave is added to the new vault, the account's other device removes Carol from the old one.
        inject = { otherDeviceRemoves(a, server, oldId, carol) }
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val r = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertTrue(server.stored.none { it.second is LogEntry.Delete }, "no delete was signed over the change")
        assertEquals(VaultActionResult.CHANGED_MEANWHILE, r)
        assertEquals(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, assertNotNull(a.snapshot.account!!.moving?.stopped).stage)
        assertFalse(a.oldRow(oldId).deleted)
    }

    /**
     * The window between the run's last read of the old vault's log and the signature of its delete: another device stores
     * a change right after that read. The delete is signed only over the head the run checked, so it is never stored over
     * the change, and the next run reads the log again and signs a new delete only over what it then checked.
     */
    @Test fun aChangeStoredBetweenTheMovesCheckAndItsDeleteMakesTheRunReadAgain() = runBlocking<Unit> {
        var armed = false
        var inject: (() -> Unit)? = null
        var oldOf: String? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val r = inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && id != null && oldOf != null && id != oldOf) {
                        val e = VaultLog.parse(crypto, Bytes.fromB64(WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry)).valueOrNull()?.entry
                        if (e is LogEntry.Add && e.member == dave) armed = true
                    }
                    // Right after a read of the old vault's log that follows the adds: stored, and not in that read.
                    if (route == WireRoute.LOG_FETCH && armed && id == oldOf) inject?.let { inject = null; it() }
                    return r
                }
            }
        }
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        inject = { otherDeviceRemoves(a, server, oldId, carol) }
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val r = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "no delete is stored over the change")
        assertNotEquals(VaultActionResult.DONE, r)
        assertFalse(a.oldRow(oldId).deleted)
        // The next run reads again: Carol is gone from the old vault, so the half-made one (with Carol) is not carried on.
        a.vault!!.afterLogAction()
        val screen = assertNotNull(a.snapshot.account!!.moving)
        assertTrue(screen.members.none { it.userId == carol }, "the members are read again")
    }

    /**
     * The review's sequence for a member whose user ID is all zeros: they are a member of the old vault (added by another
     * device of the account), a compared contact here, and a change of the old vault waits. "Move everything" ends with
     * nothing signed that names that ID and no ownership offer anywhere. Before, the re-post of the held change appended
     * an ownership offer to exactly that ID.
     */
    @Test fun aMoveWithAnAllZeroMemberAndAHeldChangeSignsNoOfferAndNothingNamingThatId() = runBlocking<Unit> {
        val nil = io.silencelen.andvari.core.client.UserIds.NIL
        var loseRoles = false
        var oldOf: String? = null
        val posted = ArrayList<LogEntry?>()
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.LOG_APPEND) {
                        val e = VaultLog.parse(crypto, Bytes.fromB64(WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry)).valueOrNull()?.entry
                        posted += e
                        if (loseRoles && pathParams["vaultId"] == oldOf && e is LogEntry.Role) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        contact(a, server, nil, "Zero")
        a.contacts.closeContacts()
        // The account's other device adds the all-zero account to the old vault (the server registered it).
        val key = a.vault!!.store.local().contacts.getValue(nil).identityPub
        val log = server.logs.getValue(oldId)
        val state = assertNotNull(VaultLog.replay(crypto, oldId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state)
        val pos = VaultLog.position(state, server.instance.now + 1_000)
        val me = a.keeper.established!!
        val add = LogEntry.Add(oldId, pos.seq, pos.prev, me.userId, pos.at, nil, key, io.silencelen.andvari.core.trust.MemberRole.WRITER, Bytes.toB64(crypto.randomBytes(16)))
        log += Bytes.toB64(me.account.signing.use { kp -> VaultLog.sign(crypto, kp, add) })
        server.stored += oldId to add
        a.vault!!.afterLogAction()
        assertTrue(a.membersOf(oldId).contains(nil), "the all-zero account is a member as this device verified")
        // A change of the old vault waits.
        loseRoles = true
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.changeRole(a.memberRow(oldId, carol), io.silencelen.andvari.core.trust.MemberRole.READER))
        a.vaults.closeMembers()
        loseRoles = false
        val from = posted.size

        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        val since = posted.drop(from)
        assertTrue(since.none { it is LogEntry.Offer }, "no ownership offer is signed: $since")
        assertTrue(since.none { e -> (e as? LogEntry.Add)?.member == nil || (e as? LogEntry.Role)?.member == nil || (e as? LogEntry.Remove)?.member == nil },
            "nothing naming the all-zero ID is signed: $since")
        assertTrue(server.stored.none { it.second is LogEntry.Offer })
    }

    /**
     * A move is remembered across a restart (decided on 16 November 2026, with the kept record): the app starts again
     * over the same device stores, the unlock re-posts nothing of the move, the first screen offers to finish it and the
     * old vault's row says its deletion waits; moving again finishes it into the SAME new vault. The record holds no name.
     * Before, the run was dropped at the lock, and moving again made a second new vault.
     */
    @Test fun aMoveIsRememberedAcrossARestartAndTheFirstScreenOffersToFinishIt() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val server = VaultServer(FakeInstance(crypto))
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        var (_, a) = appOn(server, front::wrap, state, secure)
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val record = state.keys().filter { it.startsWith(EngineSharedVaults.MOVE_PREFIX) }.map { state.get(it)!! }.single()
        assertFalse("Family" in record, "no name is kept: $record")

        a.close()
        front.mode = DeleteAnswer.PASS
        a = appOn(server, front::wrap, state, secure).second
        val posted = front.posted.size
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        a.vault!!.afterLogAction()
        assertEquals(posted, front.posted.size, "nothing of the move is re-posted at the unlock")
        assertEquals(0, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        val offer = a.snapshot.account!!.unfinishedMoves.single()
        assertTrue(offer.deleteWaiting)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_WAITING, offer.line.key)
        assertEquals(listOf("Family", "Family 2"), offer.line.values)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_WAITING, a.oldRow(oldId).unfinishedMove?.key)
        // "Not now" puts the offer off; the row still says it.
        a.vaults.unfinishedMoveLater(offer)
        assertEquals(emptyList(), a.snapshot.account!!.unfinishedMoves)
        assertNotNull(a.oldRow(oldId).unfinishedMove)

        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_UNCONFIRMED, a.snapshot.account!!.moving?.stopped?.line)
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(2, server.logs.size, "the same new vault: no second one")
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        assertEquals(1, front.posted.map { it.second }.distinct().size, "the held delete, re-posted, never signed twice")
        assertNull(a.oldRow(oldId).unfinishedMove)
        assertTrue(state.keys().none { it.startsWith(EngineSharedVaults.MOVE_PREFIX) }, "the record goes when the move ends")
    }

    /**
     * Design §6.10 and T-B2: a vault attached to a connect link made here is shared with whoever answered only once this
     * device's own entry of the codes matched, through the vault's log; before that it waits on the links screen, and a
     * release by hand raises the warning and shares nothing until it is confirmed. A vault this account does not own, or
     * the owner's role, cannot be attached. Before, a link with shares was refused as FAILED.
     */
    @Test fun aVaultAttachedToALinkIsSharedOnlyOnceTheCodesMatchedOrBehindTheWarning() = runBlocking<Unit> {
        val vaults = VaultServer(FakeInstance(crypto))
        val links = io.silencelen.andvari.core.client.link.LinkServer(crypto, vaults.instance)
        var mine: String? = null
        val (server, a) = appOn(vaults, front = { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                    if (route.name.startsWith("LINK")) links.client(mine).call(route, pathParams, query, bodyJson, authenticated, decode)
                    else inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        })
        open(a, "bob@example.com")
        val (bobId, bobKey) = a.me()
        mine = bobId
        links.keys[bobId] = bobKey
        val alice = io.silencelen.andvari.core.client.link.LinkPerson(crypto, links, 1, "11111111-1111-4111-8111-111111111111", "Alice").start()
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val family = a.row().vaultId
        val reader = io.silencelen.andvari.core.app.ShareChoice(family, io.silencelen.andvari.core.trust.MemberRole.READER)
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.NOT_ALLOWED,
            a.links.createConnectLink(listOf(reader, reader), 15), "a vault attached twice")
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.NOT_ALLOWED,
            a.links.createConnectLink(listOf(io.silencelen.andvari.core.app.ShareChoice("abababab-abab-4bab-8bab-abababababab", io.silencelen.andvari.core.trust.MemberRole.READER)), 15))
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE, a.links.createConnectLink(listOf(reader), 15))
        val own = assertNotNull(a.snapshot.account!!.links).links.single()
        assertEquals(family, own.shares.single().vaultId)

        // Alice answers; the answer is processed here: she is a contact, uncompared, and nothing is shared yet.
        val confirm = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Confirm>(
            alice.flows.open(assertNotNull(a.links.linkToShare(own)), io.silencelen.andvari.core.client.pin.GateEntry.SCAN_INVITE))
        val answered = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Answered>(alice.flows.confirm(confirm))
        a.linksFlow.processAnswers()
        assertIs<io.silencelen.andvari.core.client.link.RecipientStep.CodeReady>(alice.flows.awaitReveal(answered))
        assertTrue(server.stored.none { it.second is LogEntry.Add }, "nothing is shared before the codes")
        val waiting = assertNotNull(a.snapshot.account!!.links).waitingShares.single()
        assertEquals("Family", waiting.vaultName)
        assertEquals(alice.userId, waiting.userId)
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.READER, waiting.role)

        // By hand: the warning, and nothing until it is confirmed; cancelled, it still waits.
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, a.links.releaseShare(waiting))
        val warning = assertNotNull(a.snapshot.account!!.shareWarning)
        assertEquals(family, warning.vaultId)
        assertTrue(server.stored.none { it.second is LogEntry.Add })
        a.vaults.cancelUncomparedShare(warning)
        assertNull(a.snapshot.account!!.shareWarning)
        assertEquals(1, a.snapshot.account!!.links!!.waitingShares.size)

        // The codes: this device's own correct entry of Alice's code shares the vault, as a reader, through its log.
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single { it.userId == alice.userId }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openCompare(row))
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(a.snapshot.account!!.comparing)
        assertEquals(io.silencelen.andvari.core.app.ComparisonResult.DONE, a.contacts.submitComparison(ready, assertNotNull(alice.flows.code(bobId))))
        val add = assertIs<LogEntry.Add>(server.stored.single { it.second is LogEntry.Add }.second)
        assertEquals(alice.userId, add.member)
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.READER, add.role)
        assertEquals(emptyList(), a.snapshot.account!!.links!!.waitingShares, "shared: it no longer waits")
    }

    /**
     * The same link, with the release by hand confirmed behind the warning: the add is signed as a release to an
     * uncompared contact, and the share leaves the waiting list. A server that does not answer the add leaves it waiting
     * (the release says SENT_PENDING), never shown as shared.
     */
    @Test fun aLinkShareReleasedBehindTheWarningIsSharedOnlyOnceTheServerStoredIt() = runBlocking<Unit> {
        val vaults = VaultServer(FakeInstance(crypto))
        val links = io.silencelen.andvari.core.client.link.LinkServer(crypto, vaults.instance)
        var mine: String? = null
        var loseAdds = false
        val (server, a) = appOn(vaults, front = { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route.name.startsWith("LINK")) return links.client(mine).call(route, pathParams, query, bodyJson, authenticated, decode)
                    if (route == WireRoute.LOG_APPEND && loseAdds) {
                        val frame = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry
                        if (VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry is LogEntry.Add) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        })
        open(a, "bob@example.com")
        val (bobId, bobKey) = a.me()
        mine = bobId
        links.keys[bobId] = bobKey
        val alice = io.silencelen.andvari.core.client.link.LinkPerson(crypto, links, 1, "11111111-1111-4111-8111-111111111111", "Alice").start()
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val family = a.row().vaultId
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE,
            a.links.createConnectLink(listOf(io.silencelen.andvari.core.app.ShareChoice(family, io.silencelen.andvari.core.trust.MemberRole.WRITER)), 15))
        val own = assertNotNull(a.snapshot.account!!.links).links.single()
        val confirm = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Confirm>(
            alice.flows.open(assertNotNull(a.links.linkToShare(own)), io.silencelen.andvari.core.client.pin.GateEntry.SCAN_INVITE))
        assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Answered>(alice.flows.confirm(confirm))
        a.linksFlow.processAnswers()

        loseAdds = true
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, a.links.releaseShare(a.snapshot.account!!.links!!.waitingShares.single()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.confirmUncomparedShare(assertNotNull(a.snapshot.account!!.shareWarning)))
        assertTrue(server.stored.none { it.second is LogEntry.Add }, "the server holds no add")
        assertEquals(1, a.snapshot.account!!.links!!.waitingShares.size, "not shared: it still waits")

        loseAdds = false
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, a.links.releaseShare(a.snapshot.account!!.links!!.waitingShares.single()))
        assertEquals(VaultActionResult.DONE, a.vaults.confirmUncomparedShare(assertNotNull(a.snapshot.account!!.shareWarning)))
        val add = assertIs<LogEntry.Add>(server.stored.single { it.second is LogEntry.Add }.second)
        assertEquals(alice.userId, add.member)
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.WRITER, add.role)
        assertEquals(emptyList(), a.snapshot.account!!.links!!.waitingShares)
    }

    /** The kept record goes with the account's data: signing out takes it. */
    @Test fun anUnfinishedMovesRecordGoesWhenTheAccountSignsOut() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val server = VaultServer(FakeInstance(crypto))
        val state = MemoryDeviceState()
        val (_, a) = appOn(server, front::wrap, state)
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertTrue(state.keys().any { it.startsWith(EngineSharedVaults.MOVE_PREFIX) })
        // The record of the person's own departures sent without an answer: kept per server and account, never by account
        // alone, and it goes with the account's data too. Before, it was keyed by the user id only and outlived sign-out.
        val origin = a.vault!!.origin
        val userId = a.me().first
        assertEquals(listOf(oldId), EngineSharedVaults.ownDepartures(state, origin, userId))
        assertEquals(emptyList(), EngineSharedVaults.ownDepartures(state, "https://other.example", userId), "another server's account of the same id")
        assertTrue(state.keys().none { it == "ovh.app.own-departures|$userId" }, "nothing under the id alone")
        a.signOut()
        assertTrue(state.keys().none { it.startsWith(EngineSharedVaults.MOVE_PREFIX) }, "${state.keys()}")
        assertTrue(state.keys().none { it.startsWith("ovh.app.own-departures|") }, "${state.keys()}")
    }

    /** A record of own departures an earlier version kept under the user id alone is taken over by this server's, once. */
    @Test fun anOwnDeparturesRecordUnderTheIdAloneIsTakenOverOnce() {
        val state = MemoryDeviceState()
        state.set("ovh.app.own-departures|u1", "v1,v2")
        assertEquals(listOf("v1", "v2"), EngineSharedVaults.ownDepartures(state, "https://a.example", "u1"))
        assertNull(state.get("ovh.app.own-departures|u1"))
        assertEquals(emptyList(), EngineSharedVaults.ownDepartures(state, "https://b.example", "u1"))
        EngineSharedVaults.dropOwnDepartures(state, "https://a.example", "u1")
        assertEquals(emptyList(), EngineSharedVaults.ownDepartures(state, "https://a.example", "u1"))
    }

    /**
     * With the half-made vault's delete unanswered: it does not count as gone. The move stops before
     * the old vault is touched and says so; once the server answers, the next run deletes the half-made vault and then
     * the old one. Before, the half-made vault's delete was not looked at, and the run was forgotten.
     */
    @Test fun aHalfMadeVaultsDeleteWithoutAnAnswerKeepsTheRunAndTheOldVault() = runBlocking<Unit> {
        var appendsToNew = 0
        var refuseSecond = true
        var half: String? = null
        val front = DeleteFront { it == half }
        val (server, a) = app { inner ->
            val lossy = front.wrap(inner)
            object : WireClient by lossy {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && refuseSecond && firstOld != null && id != null && id != firstOld && id in serverLogs() && ++appendsToNew == 2) {
                        refuseSecond = false
                        return WireResult.Refused(409, WireError("member_limit", "m"))
                    }
                    return lossy.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        logsOf = server.logs
        open(a)
        val oldId = family(a, server)
        firstOld = oldId
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.MEMBER_LIMIT, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val halfMade = server.logs.keys.single { it != oldId }
        half = halfMade
        val first = a.membersOf(halfMade).single()
        a.vaults.closeMoveEverything()
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == first }))
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        val stopped = assertNotNull(a.snapshot.account!!.moving?.stopped)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DISCARD_UNCONFIRMED, stopped.line)
        assertTrue(server.stored.none { it.second is LogEntry.Delete }, "nothing is deleted yet")
        assertFalse(a.oldRow(oldId).deleted, "the old vault is untouched")

        front.mode = DeleteAnswer.PASS
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        val deletes = server.stored.filter { it.second is LogEntry.Delete }.map { it.first }
        assertEquals(listOf(halfMade, oldId), deletes, "the half-made vault, then the old one")
        assertEquals(1, front.posted.map { it.second }.distinct().size, "the half-made vault's delete signed once")
    }

    /**
     * The move marks its own entries, and a half-made vault's deletion an earlier try signed is never sent unread: its
     * deletion is sent with no answer; a member saves into it; a sync and the next run follow; then the person renames
     * it, locks and unlocks. At no step is it deleted, and the next run drops the held deletion through the log engine's
     * own call. Before, the move signed the person's kind of deletion: it stayed held after the run kept the vault, waiting
     * for a word that would delete a vault holding someone's item.
     */
    @Test fun aHalfMadeVaultsDeletionSentWithoutAnAnswerIsNeverSentUnreadAfterAMembersSave() = runBlocking<Unit> {
        var half: String? = null
        val front = DeleteFront { it == half }
        val (server, a) = app { inner -> refusingSecondAddToNew()(front.wrap(inner)) }
        logsOf = server.logs
        open(a)
        val (_, halfMade, first, _) = stoppedWithACopy(a, server)
        half = halfMade
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == first }))
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DISCARD_UNCONFIRMED, a.snapshot.account!!.moving?.stopped?.line)
        val held = assertNotNull(a.vault!!.logs.heldChange(halfMade), "its deletion waits")
        assertTrue(held.movesOwn, "signed as the move's own")
        assertFalse(held.withdrawable, "never withdrawn one by one")
        assertFalse(held.waitsForWord, "not the person's deletion")
        assertNotNull(front.points.last(), "it names the point its read reached")
        val sent = front.posted.size

        // A member's save into the half-made vault (here from this device: the rule is about what the vault holds).
        val before = server.items.keys.toSet()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, assertNotNull(a.content).saveLogin(null,
            io.silencelen.andvari.core.app.LoginInput("Own", "me", "pw-own", listOf("https://own.test"), "", "", false), halfMade))
        val own = (server.items.keys - before).single()
        a.vault!!.afterLogAction()
        assertEquals(sent, front.posted.size, "a sync sends nothing of it")

        front.mode = DeleteAnswer.PASS
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(sent, front.posted.size, "the next run sends nothing of it: it read the vault first")
        assertTrue(server.stored.none { it.first == halfMade && it.second is LogEntry.Delete }, "the half-made vault is not deleted")
        assertNull(a.vault!!.logs.heldChange(halfMade), "the held deletion was dropped, unsent")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT, a.snapshot.account!!.moveNotes.single().lines.first().key)

        // The person renames it, then locks and unlocks: still nothing deletes it.
        val row = a.snapshot.account!!.vaults.single { it.vaultId == halfMade }
        val metaBefore = server.calls.count { it == WireRoute.VAULT_META }
        val renamed = a.vaults.renameVault(row, "Kept")
        // This test server leaves the name's route unanswered: the rename was sent, and that is the person's act here.
        assertTrue(server.calls.count { it == WireRoute.VAULT_META } > metaBefore, "the rename was sent: $renamed")
        a.vault!!.afterLogAction()
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        a.vault!!.afterLogAction()
        assertEquals(sent, front.posted.size, "never sent again")
        assertTrue(server.stored.none { it.first == halfMade && it.second is LogEntry.Delete })
        assertFalse(server.items.getValue(own).deleted, "the member's item is still there")
        assertFalse(a.snapshot.account!!.vaults.single { it.vaultId == halfMade }.deleted)
    }

    /**
     * The account's other device signs a change of [member]'s role in [vaultId] at the head [log] ends in, at [at], and the
     * server stores it there. Two calls over the same log head, with different times, are two entries at one position.
     */
    private fun otherDeviceChangesRole(a: EngineAppApi, server: VaultServer, vaultId: String, member: String, role: io.silencelen.andvari.core.trust.MemberRole, at: Long) {
        val log = server.logs.getValue(vaultId)
        val state = assertNotNull(VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state)
        val pos = VaultLog.position(state, at)
        val me = a.keeper.established!!
        val entry = LogEntry.Role(vaultId, pos.seq, pos.prev, me.userId, pos.at, member, role)
        log += Bytes.toB64(me.account.signing.use { kp -> VaultLog.sign(crypto, kp, entry) })
        server.stored += vaultId to entry
    }

    /**
     * A half-made vault of an earlier try that is frozen on this device does not stop the move for good: the next run keeps
     * it as a vault of its own with a note (that it is frozen, and that the member the run removes still holds it), sends
     * nothing of it, and goes on with a new vault. The note is kept across a lock and a restart, and a later run of the
     * move makes no second note for it. Before, every later run stopped on it and the move could never finish.
     */
    @Test fun aFrozenHalfMadeVaultIsKeptWithANoteAndTheMoveGoesOnWithANewVault() = runBlocking<Unit> {
        var half: String? = null
        var appendsToHalf = 0
        var refuseFreshAdd = false
        val (server, a) = app { inner ->
            val base = refusingSecondAddToNew()(inner)
            object : WireClient by base {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && id != null && id == half) appendsToHalf++
                    if (route == WireRoute.LOG_APPEND && refuseFreshAdd && id != null && id != firstOld && id != half && id in serverLogs()) {
                        refuseFreshAdd = false
                        return WireResult.Refused(409, WireError("member_limit", "m"))
                    }
                    return base.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        logsOf = server.logs
        open(a)
        val (oldId, halfMade, first, copy) = stoppedWithACopy(a, server)
        half = halfMade

        // Two entries at one position of the half-made vault's log, each signed by the account's other device: this device
        // verified the first, the server then serves the second there. The vault freezes on this device.
        val held = assertNotNull(a.vault!!.logs.status(halfMade).let { (it as? io.silencelen.andvari.core.client.log.VaultLogStatus.Verified)?.state }).members.getValue(first)
        val role = if (held.role == io.silencelen.andvari.core.trust.MemberRole.WRITER.literal) io.silencelen.andvari.core.trust.MemberRole.READER
            else io.silencelen.andvari.core.trust.MemberRole.WRITER
        otherDeviceChangesRole(a, server, halfMade, first, role, server.instance.now + 1_000)
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Verified>(a.vault!!.logs.refresh(halfMade, null, null, force = true))
        val log = server.logs.getValue(halfMade)
        log.removeAt(log.size - 1)
        otherDeviceChangesRole(a, server, halfMade, first, role, server.instance.now + 2_000)
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.refresh(halfMade, null, null, force = true))
        appendsToHalf = 0

        // "Remove" on the member the half-made vault holds, then "Move everything": the run keeps the frozen vault with a note
        // and goes on; it then stops at the new vault's first addition (refused once).
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == first }))
        refuseFreshAdd = true
        assertEquals(VaultActionResult.MEMBER_LIMIT, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"),
            "stopped at ${a.snapshot.account!!.moving?.stopped?.stage}, ${a.snapshot.account!!.moving?.stopped?.line}")
        assertEquals(io.silencelen.andvari.core.app.MoveStage.ADD_MEMBERS, a.snapshot.account!!.moving?.stopped?.stage, "past the frozen vault")
        val note = a.snapshot.account!!.moveNotes.single()
        assertEquals(halfMade, note.vaultId)
        assertEquals(listOf(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN, io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS), note.lines.map { it.key })
        assertEquals(listOf("Family 2"), note.lines.first().values)
        assertIs<PersonName.Contact>(note.member, "the member being removed, who still holds it")
        fun said(n: io.silencelen.andvari.core.app.MoveNote) = listOf(n.oldVaultId, n.vaultId, n.lines.map { it.key.name to it.values }, (n.member as? PersonName.Contact)?.label)

        // A lock keeps the note; the next run (the person's next tap) finishes the move and makes no second note.
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(said(note), said(a.snapshot.account!!.moveNotes.single()), "after a lock")
        if (a.snapshot.account!!.moving == null) assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"),
            "stopped at ${a.snapshot.account!!.moving?.stopped?.stage}, ${a.snapshot.account!!.moving?.stopped?.line}")
        assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete }, "the old vault is deleted: the move finished")
        val fresh = server.logs.keys.single { it != oldId && it != halfMade }
        assertTrue(first !in a.membersOf(fresh), "the removed member is not in the vault the move ends in")
        assertEquals(said(note), said(a.snapshot.account!!.moveNotes.single()), "one note for that vault, after the next run")

        // Nothing of the frozen vault was sent or deleted.
        assertEquals(0, appendsToHalf, "nothing sent on the frozen vault's log")
        assertTrue(server.stored.none { it.first == halfMade && it.second is LogEntry.Delete })
        assertFalse(server.items.getValue(copy).deleted, "its copy is still there")
        assertFalse(a.snapshot.account!!.vaults.single { it.vaultId == halfMade }.deleted)

        // A restart keeps the note.
        val state = a.engine.state as MemoryDeviceState
        val secure = a.engine.secure as MemoryDeviceState
        a.close()
        val b = appOn(server, { it }, state, secure).second
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(b.snapshot.locked!!, strong))
        assertEquals(said(note), said(b.snapshot.account!!.moveNotes.single()), "after a restart")
    }

    // ---- the stand-in plays the move's stops as the engine does: each walked on both, the engine's readings written first ----

    /**
     * What a screen reads after a run of the move: the run's answer; the stop's stage, line and result; the old vault's row
     * (gone or deleted; else its log's state and whether it takes writes); each note's line keys and whether it names a member.
     */
    private fun moveRead(r: VaultActionResult, snapshot: io.silencelen.andvari.core.app.AppSnapshot, oldId: String): List<Any?> {
        val acct = snapshot.account!!
        val stop = acct.moving?.stopped
        val old = acct.vaults.firstOrNull { it.vaultId == oldId }
        val gone = old == null || old.deleted
        return listOf(r, stop?.stage, stop?.line, stop?.result, acct.moving?.finished?.oldKept, gone, old?.log.takeIf { !gone }, old?.writable.takeIf { !gone },
            acct.moveNotes.map { n -> n.lines.map { it.key } to (n.member != null) })
    }

    /**
     * The stand-in at its vaults, "Family"'s "Move everything" open from the remove dialog of its member who is no contact
     * here: everyone left can be added, so the old vault is not kept for a member who cannot be.
     */
    private suspend fun fakeMove(): Pair<io.silencelen.andvari.core.app.fake.FakeAppApi, String> {
        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        val family = f.snapshot.account!!.vaults.first { it.name == "Family" }
        assertEquals(VaultActionResult.DONE, f.vaults.openMembers(family))
        assertEquals(VaultActionResult.DONE, f.vaults.openMoveEverythingRemoving(f.snapshot.account!!.members!!.members.first { it.who is PersonName.Unverified }))
        assertNull(assertNotNull(f.snapshot.account!!.moving).oldVaultKept)
        return f to family.vaultId
    }

    private fun entryOf(bodyJson: String?): LogEntry? =
        VaultLog.parse(crypto, Bytes.fromB64(WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry)).valueOrNull()?.entry

    private val sentPending = VaultActionResult.SENT_PENDING
    private val verified = VaultLogState.VERIFIED

    /**
     * A change of a role in the old vault waits on this device (sent, no answer): it is not the move's, so each run makes and
     * fills the new vault and then stops before the old vault's deletion with a line of its own, sending nothing of it.
     */
    @Test fun theFakePlaysAChangeThatIsNotTheMovesWaitingOnTheOldVaultAsTheEngineDoes() = runBlocking<Unit> {
        var loseRoleOn: String? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                    if (route == WireRoute.LOG_APPEND && pathParams["vaultId"] == loseRoleOn && entryOf(bodyJson) is LogEntry.Role) WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        loseRoleOn = oldId
        assertEquals(sentPending, a.vaults.changeRole(a.memberRow(oldId, carol), io.silencelen.andvari.core.trust.MemberRole.READER))
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val engine = Readings()
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"), a.snapshot, oldId)
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        val stopped = listOf(sentPending, io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, io.silencelen.andvari.core.app.CopyKey.MOVE_OTHER_CHANGE_WAITING,
            sentPending, null, false, verified, true, emptyList<Any>())
        assertEquals<List<Any?>>(listOf(stopped, stopped), engine)
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "nothing of the old vault's deletion is stored")
        assertEquals(false, a.vault!!.logs.heldChange(oldId)?.movesOwn, "the change that waits is the person's, still held")

        val (f, fOld) = fakeMove()
        f.script.moveOtherChangeWaiting = true
        val fake = Readings()
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2"), f.snapshot, fOld)
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored"), f.snapshot, fOld)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * An item of the old vault moves after the move's read: the server refuses the deletion that names that read, nothing is
     * stored or held, the old vault is open for writing again, and moving again finishes.
     */
    @Test fun theFakePlaysTheOldVaultChangedAfterTheMovesReadAsTheEngineDoes() = runBlocking<Unit> {
        var old: String? = null
        var bump = true
        lateinit var srv: VaultServer
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.LOG_APPEND && old != null && pathParams["vaultId"] == old && bump && entryOf(bodyJson) is LogEntry.Delete) {
                        bump = false
                        val item = srv.items.values.first { it.vaultId == old }
                        srv.items[item.itemId] = item.copy(rev = srv.rev++)
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        srv = server
        server.checksReadPoint = true
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        old = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val engine = Readings()
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"), a.snapshot, oldId)
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        val meanwhile = VaultActionResult.CHANGED_MEANWHILE
        assertEquals<List<Any?>>(listOf(
            listOf(meanwhile, io.silencelen.andvari.core.app.MoveStage.TRANSFER_ITEMS, io.silencelen.andvari.core.app.CopyKey.MOVE_STOPPED, meanwhile, null, false, verified, true, emptyList<Any>()),
            listOf(VaultActionResult.DONE, null, null, null, null, true, null, null, emptyList<Any>()),
        ), engine)
        assertEquals(2, server.readPoints.count { it.first == oldId }, "the refused deletion, then the one stored")

        val (f, fOld) = fakeMove()
        f.script.nextMoveStop = io.silencelen.andvari.core.app.fake.FakeScript.MoveStopAt.OLD_VAULT_CHANGED_AFTER_READ
        val fake = Readings()
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2"), f.snapshot, fOld)
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored"), f.snapshot, fOld)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * A copy in the half-made vault of an earlier try moves after the run's read of it: the server refuses its deletion,
     * nothing is stored, the run stops before it makes anything, and the next run reads that vault again (here it now holds
     * a changed copy, so it is kept with a note naming the member the move removes).
     */
    @Test fun theFakePlaysAHalfMadeVaultChangedAfterItsReadAsTheEngineDoes() = runBlocking<Unit> {
        var half: String? = null
        var bump = true
        lateinit var srv: VaultServer
        val (server, a) = app { inner ->
            val base = refusingSecondAddToNew()(inner)
            object : WireClient by base {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (route == WireRoute.LOG_APPEND && half != null && pathParams["vaultId"] == half && bump && entryOf(bodyJson) is LogEntry.Delete) {
                        bump = false
                        val item = srv.items.values.first { it.vaultId == half }
                        srv.items[item.itemId] = item.copy(rev = srv.rev++)
                    }
                    return base.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        srv = server
        logsOf = server.logs
        server.checksReadPoint = true
        open(a)
        val (oldId, halfMade, first, _) = stoppedWithACopy(a, server)
        half = halfMade
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == first }))
        val engine = Readings()
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        assertTrue(server.stored.none { it.first == halfMade && it.second is LogEntry.Delete }, "refused: nothing stored")
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        val meanwhile = VaultActionResult.CHANGED_MEANWHILE
        assertEquals<List<Any?>>(listOf(
            listOf(meanwhile, io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, io.silencelen.andvari.core.app.CopyKey.MOVE_STOPPED, meanwhile, null, false, verified, true, emptyList<Any>()),
            listOf(VaultActionResult.DONE, null, null, null, null, true, null, null,
                listOf(listOf(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT, io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS) to true)),
        ), engine)

        val (f, fOld) = fakeMove()
        f.script.nextMoveStop = io.silencelen.andvari.core.app.fake.FakeScript.MoveStopAt.HALF_MADE_CHANGED_AFTER_READ
        val fake = Readings()
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2"), f.snapshot, fOld)
        f.script.nextMoveKeepsHalfMade = 1
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored"), f.snapshot, fOld)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * The old vault freezes on this device while the move's deletion of it waits unanswered (two entries of the account's
     * other device at one place of its log, the first verified here): the held deletion is dropped with the freeze and never
     * sent again, the old vault stays, read-only here, and the next run stops before anything else with the line that the
     * old vault is frozen, offering no fresh start.
     */
    @Test fun theFakePlaysTheOldVaultFrozenWhileTheMovesDeletionWaitsAsTheEngineDoes() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        old = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val engine = Readings()
        front.mode = DeleteAnswer.LOST
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"), a.snapshot, oldId)
        front.mode = DeleteAnswer.PASS
        // Two entries of the account's other device at one place of the old vault's log, the first verified here: it freezes.
        otherDeviceChangesRole(a, server, oldId, carol, io.silencelen.andvari.core.trust.MemberRole.READER, server.instance.now + 1_000)
        a.vault!!.logs.refresh(oldId, null, null, force = true)
        val log = server.logs.getValue(oldId)
        log.removeAt(log.size - 1)
        otherDeviceChangesRole(a, server, oldId, carol, io.silencelen.andvari.core.trust.MemberRole.READER, server.instance.now + 2_000)
        a.vault!!.logs.refresh(oldId, null, null, force = true)
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.status(oldId))
        assertNull(a.vault!!.logs.heldChange(oldId), "the held deletion is dropped with the freeze")
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        // The run finds the old vault frozen right after its read: it says so, read-only, and offers no fresh start (before:
        // "changed meanwhile" at ADD_MEMBERS, with a fresh start offered).
        val readOnly = VaultActionResult.READ_ONLY
        assertEquals<List<Any?>>(listOf(
            listOf(sentPending, io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_UNCONFIRMED, sentPending, null, false, verified, false, emptyList<Any>()),
            listOf(readOnly, io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN, readOnly, null, false, VaultLogState.FROZEN, false, emptyList<Any>()),
        ), engine)
        assertNull(a.snapshot.account!!.moving?.startsFresh, "no fresh start is offered")
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "no deletion of it is stored")
        assertEquals(1, front.posted.size, "nothing more is sent of it")

        val (f, fOld) = fakeMove()
        f.script.moveDeleteUnanswered = true
        val fake = Readings()
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2"), f.snapshot, fOld)
        f.script.moveDeleteUnanswered = false
        f.script.nextMoveStop = io.silencelen.andvari.core.app.fake.FakeScript.MoveStopAt.OLD_VAULT_FROZEN
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored"), f.snapshot, fOld)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * The move's deletion of the old vault waits (its first send unanswered); its re-send is answered as stored at its own
     * place while the server stores nothing; the account's other device then stores another entry there (an offer, which
     * changes no member). The next run finds the old vault frozen here (at its read, or at the re-send refused for it): the
     * stop says that the old vault is frozen (never "failed"), nothing more is sent, and the vault stays read-only. The
     * stand-in plays the same.
     */
    @Test fun aMovesReSentDeletionRefusedBecauseTheOldVaultIsFrozenSaysItIsFrozenAndLeavesItReadOnly() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        old = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        front.mode = DeleteAnswer.LOST
        assertEquals(sentPending, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        front.mode = DeleteAnswer.LIE_STORED
        val second = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored")
        println("the re-send answered as stored while nothing is stored: $second, ${a.snapshot.account!!.moving?.stopped?.line}")
        front.mode = DeleteAnswer.PASS
        // The account's other device stores another entry at the place the server named for the deletion.
        val log = server.logs.getValue(oldId)
        val state = assertNotNull(VaultLog.replay(crypto, oldId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state)
        val pos = VaultLog.position(state, server.instance.now + 1_000)
        val me = a.keeper.established!!
        val offer = LogEntry.Offer(oldId, pos.seq, pos.prev, me.userId, pos.at, carol, state.members.getValue(carol).key, Bytes.toB64(crypto.randomBytes(16)), pos.at + 86_400_000)
        log += Bytes.toB64(me.account.signing.use { kp -> VaultLog.sign(crypto, kp, offer) })
        server.stored += oldId to offer
        val posted = front.posted.size
        val engine = Readings()
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        println("the run after another entry stood at that place: $engine")
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.status(oldId))
        assertEquals<List<Any?>>(listOf(
            listOf(VaultActionResult.READ_ONLY, io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN,
                VaultActionResult.READ_ONLY, null, false, VaultLogState.FROZEN, false, emptyList<Any>()),
        ), engine)
        assertFalse(a.oldRow(oldId).writable, "not opened for writing again")
        assertFalse(a.vault!!.logs.writeAllowed(oldId))
        assertTrue(front.posted.size <= posted + 1, "nothing more is sent after the refusal")
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "no deletion of it is stored")

        val (f, fOld) = fakeMove()
        f.script.moveDeleteUnanswered = true
        f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2")
        f.script.moveDeleteUnanswered = false
        f.script.nextMoveStop = io.silencelen.andvari.core.app.fake.FakeScript.MoveStopAt.OLD_VAULT_FROZEN_AT_RESEND
        val fake = Readings()
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored"), f.snapshot, fOld)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * The same sequence (the move's deletion sent unanswered; its re-send answered as stored at its place while nothing is
     * stored; another device's entry at that place), read at each step of the run that follows. The old vault freezes at
     * the move's own first read of it: the move looks for that right after the read, before anything else, says that the
     * old vault is frozen and stops as read-only; it sends nothing more, keeps its mark of a waiting deletion on the old
     * vault (it does not clear it as if the deletion had ended), and offers no fresh start, also at a run after it. Before:
     * the read cleared the mark and the run went on, stopping as "changed meanwhile" or at a later read-only refusal.
     */
    @Test fun aMoveThatMeetsTheFreezeAtItsOwnFirstReadSaysSoAndClearsNothing() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        old = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        front.mode = DeleteAnswer.LOST
        assertEquals(sentPending, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        front.mode = DeleteAnswer.LIE_STORED
        val second = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored")
        val markBefore = a.vault!!.items.closedForWriting(oldId)
        println("after the lying re-send: $second, ${a.snapshot.account!!.moving?.stopped?.line}, mark $markBefore, status ${a.vault!!.logs.status(oldId)::class.simpleName}")
        front.mode = DeleteAnswer.PASS
        val log = server.logs.getValue(oldId)
        val state = assertNotNull(VaultLog.replay(crypto, oldId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state)
        val pos = VaultLog.position(state, server.instance.now + 1_000)
        val me = a.keeper.established!!
        val offer = LogEntry.Offer(oldId, pos.seq, pos.prev, me.userId, pos.at, carol, state.members.getValue(carol).key, Bytes.toB64(crypto.randomBytes(16)), pos.at + 86_400_000)
        log += Bytes.toB64(me.account.signing.use { kp -> VaultLog.sign(crypto, kp, offer) })
        server.stored += oldId to offer
        val posted = front.posted.size
        val storedBefore = server.stored.size
        val first = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored")
        val moving = assertNotNull(a.snapshot.account!!.moving)
        println("the run after another entry stood at that place: $first, ${moving.stopped?.stage}, ${moving.stopped?.line}, fresh ${moving.startsFresh}, mark ${a.vault!!.items.closedForWriting(oldId)}")
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.status(oldId))
        assertEquals(VaultActionResult.READ_ONLY, first)
        assertEquals(io.silencelen.andvari.core.app.MoveStage.DELETE_OLD_VAULT, moving.stopped?.stage)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN, moving.stopped?.line)
        assertEquals(VaultActionResult.READ_ONLY, moving.stopped?.result)
        assertNull(moving.startsFresh, "no fresh start is offered")
        assertEquals(markBefore, a.vault!!.items.closedForWriting(oldId), "the mark of a waiting deletion is not cleared")
        assertEquals(posted, front.posted.size, "nothing is sent after the read")
        assertEquals(storedBefore, server.stored.size, "nothing is stored")
        assertFalse(a.oldRow(oldId).writable)
        assertFalse(a.vault!!.logs.writeAllowed(oldId))
        // A run after it says the same, and still sends nothing and offers no fresh start.
        val again = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored")
        assertEquals(VaultActionResult.READ_ONLY, again)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_OLD_VAULT_FROZEN, a.snapshot.account!!.moving?.stopped?.line)
        assertNull(a.snapshot.account!!.moving?.startsFresh)
        assertEquals(posted, front.posted.size)
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "no deletion of it is stored")

        // The stand-in, side by side: the same stop, and no fresh start.
        val engine = moveRead(first, a.snapshot, oldId)
        val (f, fOld) = fakeMove()
        f.script.moveDeleteUnanswered = true
        f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2")
        f.script.moveDeleteUnanswered = false
        f.script.nextMoveStop = io.silencelen.andvari.core.app.fake.FakeScript.MoveStopAt.OLD_VAULT_FROZEN
        val fakeFirst = f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored")
        assertEquals(engine, moveRead(fakeFirst, f.snapshot, fOld))
        assertNull(f.snapshot.account!!.moving?.startsFresh)
        val fakeAgain = f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored")
        assertEquals(moveRead(again, a.snapshot, oldId), moveRead(fakeAgain, f.snapshot, fOld), "a run after it, side by side")
    }

    /**
     * A shared vault whose deletion stands is not writable on its row, whether or not the server sent a day for its end
     * (the content refuses every change into it); a restore makes it writable again at once.
     */
    @Test fun aDeletedSharedVaultsRowIsNotWritableAndARestoreMakesItWritableAgain() = runBlocking<Unit> {
        val (_, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        assertTrue(a.snapshot.account!!.vaults.single().writable)
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(a.snapshot.account!!.vaults.single()))
        val deleted = a.snapshot.account!!.vaults.single()
        assertTrue(deleted.deleted)
        assertFalse(deleted.writable, "a deleted vault takes no change")
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(deleted))
        val back = a.snapshot.account!!.vaults.single()
        assertFalse(back.deleted)
        assertTrue(back.writable, "writable again at once")
    }

    /** A half-made vault of an earlier try frozen on this device: kept with a note, and the move finishes, on both. */
    @Test fun theFakePlaysAFrozenHalfMadeVaultAsTheEngineDoes() = runBlocking<Unit> {
        val (server, a) = app(refusingSecondAddToNew())
        logsOf = server.logs
        open(a)
        val (oldId, halfMade, first, _) = stoppedWithACopy(a, server)
        val held = assertNotNull((a.vault!!.logs.status(halfMade) as? io.silencelen.andvari.core.client.log.VaultLogStatus.Verified)?.state).members.getValue(first)
        val role = if (held.role == io.silencelen.andvari.core.trust.MemberRole.WRITER.literal) io.silencelen.andvari.core.trust.MemberRole.READER
            else io.silencelen.andvari.core.trust.MemberRole.WRITER
        otherDeviceChangesRole(a, server, halfMade, first, role, server.instance.now + 1_000)
        a.vault!!.logs.refresh(halfMade, null, null, force = true)
        val log = server.logs.getValue(halfMade)
        log.removeAt(log.size - 1)
        otherDeviceChangesRole(a, server, halfMade, first, role, server.instance.now + 2_000)
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.refresh(halfMade, null, null, force = true))
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverythingRemoving(a.snapshot.account!!.members!!.members.single { it.userId == first }))
        val engine = Readings()
        engine += moveRead(a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"), a.snapshot, oldId)
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        engine += moveRead(VaultActionResult.DONE, a.snapshot, oldId)
        val note = listOf(listOf(io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN, io.silencelen.andvari.core.app.CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS) to true)
        val done = listOf(VaultActionResult.DONE, null, null, null, null, true, null, null, note)
        assertEquals<List<Any?>>(listOf(done, done), engine)
        assertEquals(VaultLogState.FROZEN, a.snapshot.account!!.vaults.single { it.vaultId == halfMade }.log)

        val (f, fOld) = fakeMove()
        f.script.nextMoveHalfMadeFrozen = true
        val fake = Readings()
        fake += moveRead(f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2"), f.snapshot, fOld)
        f.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, f.unlock(f.snapshot.locked!!, io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD))
        fake += moveRead(VaultActionResult.DONE, f.snapshot, fOld)
        assertEquals<List<Any?>>(engine, fake)
        val fHalf = f.snapshot.account!!.vaults.single { it.vaultId == f.snapshot.account!!.moveNotes.single().vaultId }
        assertEquals(VaultLogState.FROZEN, fHalf.log)
    }

    /**
     * The move's additions and its deletion of the old vault are its own entries, and the deletion names the point up to
     * which the move read the old vault: an addition held without an answer is the move's own (never withdrawn one by one);
     * where a member's change lands in the old vault after that read, the server refuses the deletion, nothing is stored
     * or held, the old vault stays open for writing, the move says it changed meanwhile, and moving again carries what is
     * late and deletes it.
     */
    @Test fun theMovesOwnEntriesAreMarkedAndItsDeletionOfTheOldVaultNamesItsReadPoint() = runBlocking<Unit> {
        var old: String? = null
        var loseAdd = true
        var bump = true
        lateinit var srv: VaultServer
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && id != null && old != null) {
                        val entry = VaultLog.parse(crypto, Bytes.fromB64(WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!).entry)).valueOrNull()?.entry
                        if (entry is LogEntry.Add && id != old && loseAdd) {
                            loseAdd = false
                            return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                        }
                        // Another member's save lands in the old vault after the move's last read, just before its deletion.
                        if (entry is LogEntry.Delete && id == old && bump) {
                            bump = false
                            val item = srv.items.values.first { it.vaultId == old }
                            srv.items[item.itemId] = item.copy(rev = srv.rev++)
                        }
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        srv = server
        server.checksReadPoint = true
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        old = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        val newId = server.logs.keys.single { it != oldId }
        val add = assertNotNull(a.vault!!.logs.heldChange(newId), "the addition waits")
        assertTrue(add.movesOwn, "signed as the move's own")
        assertFalse(add.withdrawable, "never withdrawn one by one")

        assertEquals(VaultActionResult.CHANGED_MEANWHILE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(io.silencelen.andvari.core.app.MoveStage.TRANSFER_ITEMS, a.snapshot.account!!.moving?.stopped?.stage)
        val first = assertNotNull(server.readPoints.single { it.first == oldId }.second, "the deletion named its read point")
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "refused: nothing stored")
        assertNull(a.vault!!.logs.heldChange(oldId), "and nothing held")
        assertFalse(a.oldRow(oldId).deleted, "the old vault stays")
        assertNull(a.vault!!.items.closedForWriting(oldId), "open for writing again")
        assertFalse(a.vaultsFlow.moveDeleteWaiting(oldId))

        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertTrue(server.stored.any { it.first == oldId && it.second is LogEntry.Delete }, "moving again deletes it")
        val points = server.readPoints.filter { it.first == oldId }.map { it.second }
        assertEquals(2, points.size)
        assertTrue(assertNotNull(points.last()) > first, "named at the later read: $points")
    }

    private var firstOld: String? = null

    /**
     * An add the server acknowledged but did not store never counts. The new vault's log, read
     * again before the delete, does not hold the member: the move stops at the adds and the old vault is kept.
     */
    @Test fun anAddTheServerDidNotStoreStopsTheMoveAndTheOldVaultIsKept() = runBlocking<Unit> {
        var drop = true
        var appendsToNew = 0
        var srv: VaultServer? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    val isNew = firstOld != null && id != null && id != firstOld && id in serverLogs()
                    val r = inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                    // The last add of the move (the second member's) is answered as stored and then forgotten.
                    if (route == WireRoute.LOG_APPEND && drop && isNew && r is WireResult.Ok && ++appendsToNew == 2) {
                        // Answered as stored, then forgotten: the log and the grant go back to what they were.
                        drop = false
                        val s = srv!!
                        val log = s.logs.getValue(id!!)
                        log.removeAt(log.size - 1)
                        val (_, entry) = s.stored.removeAt(s.stored.size - 1)
                        if (entry is LogEntry.Add) s.grants.remove(id to entry.member)
                    }
                    return r
                }
            }
        }
        srv = server
        logsOf = server.logs
        open(a)
        val oldId = family(a, server)
        firstOld = oldId
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val r = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertTrue(r != VaultActionResult.DONE, "$r")
        assertEquals(io.silencelen.andvari.core.app.MoveStage.ADD_MEMBERS, assertNotNull(a.snapshot.account!!.moving?.stopped).stage)
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "the old vault is not deleted")
        assertFalse(a.row().deleted)
    }

    /**
     * An item changed in the old vault after it was copied (another member's edit while the members
     * are added). The old vault is read once more before its delete: the change exists only there, so it is kept and the
     * move stops with "changed meanwhile". Before, the old vault was deleted with the change in it.
     */
    @Test fun anItemChangedAfterItsCopyKeepsTheOldVault() = runBlocking<Unit> {
        var bump = true
        var srv: VaultServer? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    val id = pathParams["vaultId"]
                    if (route == WireRoute.LOG_APPEND && bump && firstOld != null && id != null && id != firstOld && id in serverLogs()) {
                        // Another member edits the item in the old vault while the first member is being added.
                        bump = false
                        val s = srv!!
                        val item = s.items.values.single { it.vaultId == firstOld }
                        s.items[item.itemId] = item.copy(rev = s.rev++)
                    }
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        srv = server
        server.servesItems = true
        logsOf = server.logs
        open(a)
        val oldId = family(a, server)
        firstOld = oldId
        a.vaults.closeMembers()
        val c = assertNotNull(a.content)
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        assertTrue(server.items.values.any { it.vaultId == oldId }, "the item is on the server")
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        val r = a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2")
        assertEquals(VaultActionResult.CHANGED_MEANWHILE, r)
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "the old vault is kept")
    }

    // ---- while a move's deletion is signed and waiting, nothing else is signed on that vault's log ----

    private val eve = "66666666-6666-4666-8666-666666666666"

    /**
     * A move of "Family" (Carol and Dave, one item) whose old-vault delete got no answer: its deletion is signed and
     * waiting. Answers the server, the app, and the old vault's id with the front that keeps every delete posted.
     */
    /**
     * [inner], with downloads passed on to [servers]. [BearerTransport]'s client overrides `call` and `callBytes` but not
     * `fetchBytes`, whose default in [WireClient] is no answer: every download through it said "can't reach the server".
     */
    private class Fetching(private val inner: BearerTransport, private val servers: Map<String, WireClient>) : io.silencelen.andvari.core.client.session.WireTransport {
        override fun open(origin: String, tokens: io.silencelen.andvari.core.client.net.TokenSource?): WireClient {
            val c = inner.open(origin, tokens)
            val s = servers[origin] ?: return c
            return object : WireClient by c {
                override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean): WireResult<ByteArray> =
                    s.fetchBytes(route, pathParams, query, authenticated)
                override suspend fun fetchBytes(route: WireRoute, pathParams: Map<String, String>, query: String?, authenticated: Boolean, maxBytes: Long?): WireResult<ByteArray> =
                    s.fetchBytes(route, pathParams, query, authenticated, maxBytes)
            }
        }

        override fun bellSocket(origin: String): io.silencelen.andvari.core.client.items.BellSocket? = inner.bellSocket(origin)
    }

    /**
     * An item with one file, copied by the move, then changed by another member after its copy; the server stores the
     * move's deletion outside a run. Copying what changed since copies the item again with its file, under a fresh file id
     * (re-sealed under a fresh key), and replaces the earlier copy. The test was missing because every download in this
     * file's rig got no answer (see [Fetching]).
     */
    @Test fun anItemWithAFileChangedAfterItsCopyIsCopiedAgainWithItsFileUnderAFreshId() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = appOn(VaultServer(FakeInstance(crypto)), front::wrap, fetches = true)
        server.filesUpTo = 1L shl 20
        open(a)
        val oldId = familyWithItems(a, server, count = 1, file = 64)
        oldOf = oldId
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        a.vaults.closeMoveEverything()
        front.mode = DeleteAnswer.PASS
        val newId = server.logs.keys.single { it != oldId }
        val original = server.items.values.single { it.vaultId == oldId }
        val firstCopy = server.items.values.single { it.vaultId == newId && !it.deleted }
        assertEquals(1, original.attachmentIds.size)
        assertEquals(1, firstCopy.attachmentIds.size, "the move copied the file")
        assertNotEquals(original.attachmentIds, firstCopy.attachmentIds)
        // Another member changes the item after its copy.
        server.items[original.itemId] = original.copy(rev = server.rev++)
        a.vault!!.afterLogAction()
        val frame = front.posted.single().second
        server.logs.getValue(oldId) += frame
        server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        val notice = a.snapshot.account!!.movesStoredOutside.single()
        assertEquals(1, notice.changed)
        assertEquals(VaultActionResult.DONE, a.vaults.bringLateIntoMove(notice), "copied with its file")
        a.vault!!.afterLogAction()
        val live = server.items.values.single { it.vaultId == newId && !it.deleted }
        assertNotEquals(firstCopy.itemId, live.itemId, "the earlier copy is replaced")
        assertTrue(server.items.getValue(firstCopy.itemId).deleted)
        val fileId = live.attachmentIds.single()
        assertTrue(fileId != original.attachmentIds.single() && fileId != firstCopy.attachmentIds.single(), "a fresh file id")
        assertTrue(fileId in server.files, "the file itself was uploaded")
        assertNull(a.snapshot.account!!.movesStoredOutside.single().let { if (it.added + it.changed == 0) null else it }, "nothing left to copy")
    }

    /**
     * A move stopped before it signed anything (short of space), and a change of a member's role in its old vault that got
     * no answer: the change the log engine holds is not the move's deletion, so the old vault is not closed and other actions
     * on it are not refused as "its deletion waits". Before, any held change of such a vault counted as its deletion.
     * (A signed deletion a lock overtook still closes it: [aLockOvertakingTheSignedDeletionKeepsTheOldVaultClosed].)
     */
    @Test fun aRoleChangeWaitingOnTheOldVaultOfAnUnfinishedMoveDoesNotCloseIt() = runBlocking<Unit> {
        var lose: String? = null
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                    if (route == WireRoute.LOG_APPEND && pathParams["vaultId"] == lose) WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
        open(a)
        val oldId = familyWithItems(a, server)
        server.quota = meters(bytes = 0L to 1L)
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.OUT_OF_SPACE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        a.vaults.closeMoveEverything()
        assertNotNull(a.oldRow(oldId).unfinishedMove, "the move is unfinished")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        lose = oldId
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.changeRole(a.memberRow(oldId, carol), io.silencelen.andvari.core.trust.MemberRole.READER))
        lose = null
        a.vaults.closeMembers()
        assertFalse(a.vaultsFlow.moveDeleteWaiting(oldId), "a waiting change of a role is not the move's deletion")
        assertNull(a.vault!!.items.closedForWriting(oldId), "the old vault stays open for writing")
        a.vault!!.afterLogAction()
        assertNull(a.vault!!.items.closedForWriting(oldId))
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.saveLogin(null, login("After"), oldId))
    }

    /**
     * A move's deletion stored outside the move, then the vault restored by its owner: it is a live vault again. The
     * move's record ends there (what was copied stays where it is), its notice goes, the vault is open for writing, and a
     * new "Move everything" of it runs as a fresh move. Before, the record stayed as the old vault of a stored-outside
     * move: its notice kept counting the live vault's items as late, and "Move everything" on it answered DONE having
     * done nothing.
     */
    @Test fun aVaultRestoredAfterItsMoveDeletionWasStoredOutsideIsALiveVaultAgain() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, front) = rest
        val frame = front.posted.single().second
        server.logs.getValue(oldId) += frame
        server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        assertEquals(oldId, a.snapshot.account!!.movesStoredOutside.single().oldVaultId)
        // The owner restores it from "Recently deleted".
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(a.oldRow(oldId)))
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        assertFalse(a.oldRow(oldId).deleted, "live again")
        assertEquals(emptyList(), a.snapshot.account!!.movesStoredOutside, "the move's record ended with the restore")
        assertNull(a.oldRow(oldId).unfinishedMove)
        assertNull(a.vault!!.items.closedForWriting(oldId), "open for writing")
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.saveLogin(null, login("After"), oldId))
        a.vault!!.afterLogAction()
        // "Move everything" on it is a fresh move: a new vault is made.
        val vaultsBefore = server.logs.size
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 3")
        assertEquals(vaultsBefore + 1, server.logs.size, "a fresh move made a new vault")
    }

    /**
     * A move's deletion stored outside the move, then a server that serves the old vault's log as it was before the
     * deletion (an older state, which the log engine withholds judgement on). The move's record, its notice and what it
     * carries stay; served honestly again, the notice is as it was. Before, the withheld log counted as "restored" and the
     * device forgot the move for good.
     */
    @Test fun aServerServingTheOldVaultsLogWithoutItsDeletionNeverEndsTheMovesRecord() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, front) = rest
        val frame = front.posted.single().second
        server.logs.getValue(oldId) += frame
        server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        assertEquals(oldId, a.snapshot.account!!.movesStoredOutside.single().oldVaultId)
        // The server rolls the log back to before the deletion.
        val log = server.logs.getValue(oldId)
        log.removeAt(log.lastIndex)
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Withheld>(a.vault!!.logs.status(oldId), "the log engine refuses the rollback")
        assertEquals(oldId, a.snapshot.account!!.movesStoredOutside.single().oldVaultId, "the move's record and its notice stay")
        // Served honestly again.
        log += frame
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        assertEquals(oldId, a.snapshot.account!!.movesStoredOutside.single().oldVaultId)
    }

    /** Cache files in memory that answer as durable, as the account's SQLite file does: a change with no answer is kept. */
    private class DurableFiles : VaultCacheFiles {
        val caches = HashMap<String, io.silencelen.andvari.core.client.VaultCache>()
        override fun open(fileName: String, userId: String): io.silencelen.andvari.core.client.VaultCache =
            caches.getOrPut(fileName) { object : io.silencelen.andvari.core.client.VaultCache by io.silencelen.andvari.core.client.InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean = caches.remove(fileName) != null
    }

    /**
     * [durable]: the account's copy is kept at rest (a second opening has read the policy that allows it), so a change the
     * server does not answer waits in the queue.
     */
    private suspend fun waitingMove(durable: Boolean = false, state: MemoryDeviceState = MemoryDeviceState()): Triple<VaultServer, EngineAppApi, Pair<String, DeleteFront>> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = appOn(VaultServer(FakeInstance(crypto)), front::wrap, state = state, cacheFiles = if (durable) DurableFiles() else null)
        server.servesItems = true
        open(a)
        if (durable) {
            a.lock()
            assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        }
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            a.content!!.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        a.vaults.closeMoveEverything()
        // From here on the server would store whatever reaches it: a re-post of the held delete would be seen at once.
        front.mode = DeleteAnswer.PASS
        return Triple(server, a, oldId to front)
    }

    private fun EngineAppApi.memberRow(oldId: String, userId: String) =
        assertNotNull(snapshot.account!!.members, "the Members screen of $oldId").members.single { it.userId == userId }

    /**
     * [road], tried on the old vault while the move's deletion waits, is refused before anything is signed or sent, with
     * the one result the screens word; the held delete is not re-posted (and so not stored); then the move's own run
     * still finishes, with that one delete.
     */
    private fun refusedWhileTheDeleteWaits(road: suspend (VaultServer, EngineAppApi, String) -> VaultActionResult) = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, front) = rest
        val stored = server.stored.size
        val posted = front.posted.size
        val log = server.logs.getValue(oldId).toList()
        val meta = server.meta[oldId]
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, road(server, a, oldId))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_WAITING_REFUSED, VaultActionResult.MOVE_DELETE_WAITING.sentence)
        assertEquals(posted, front.posted.size, "the held delete is not re-posted")
        assertEquals(stored, server.stored.size, "nothing is signed or stored")
        assertEquals(log, server.logs.getValue(oldId), "the old vault's log is as it was")
        assertEquals(meta, server.meta[oldId], "the old vault's record is as it was")
        assertFalse(a.oldRow(oldId).deleted, "the old vault is not deleted")
        a.vaults.closeMembers()
        // The move's own run is not refused: it finishes, re-posting the one held delete last.
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        assertEquals(1, front.posted.map { it.second }.distinct().size, "the held delete, never signed twice")
    }

    @Test fun aMemberAddedWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { server, a, oldId ->
        val e = contact(a, server, eve, "Eve")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        a.vaults.addMember(a.snapshot.account!!.members!!, e, io.silencelen.andvari.core.trust.MemberRole.WRITER)
    }

    @Test fun aRoleChangedWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId ->
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        a.vaults.changeRole(a.memberRow(oldId, carol), io.silencelen.andvari.core.trust.MemberRole.READER)
    }

    @Test fun aMemberRemovedWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId ->
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        a.vaults.removeMember(a.memberRow(oldId, carol))
    }

    @Test fun anOwnershipOfferWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId ->
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        a.vaults.offerOwnership(a.memberRow(oldId, carol))
    }

    @Test fun anOffersCancelWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId -> a.vaults.cancelOffer(a.oldRow(oldId)) }

    @Test fun anOffersAcceptWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId -> a.vaults.acceptOwnership(a.oldRow(oldId)) }

    @Test fun aRenameWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId -> a.vaults.renameVault(a.oldRow(oldId), "Family again") }

    @Test fun aDeleteFromOutsideTheMoveWhileItsDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId -> a.vaults.deleteVault(a.oldRow(oldId)) }

    @Test fun aLeaveWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId -> a.vaults.leaveVault(a.oldRow(oldId)) }

    @Test fun aRestoreWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId -> a.vaults.restoreVault(a.oldRow(oldId)) }

    @Test fun aMoveFromARemoveDialogWhileTheMovesDeleteWaitsIsRefused() = refusedWhileTheDeleteWaits { _, a, oldId ->
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        a.vaults.openMoveEverythingRemoving(a.memberRow(oldId, carol))
    }

    /**
     * The review's sequence: the move's delete gets no answer; another member changes an item in the old vault; the
     * person opens the old vault's Members screen and adds someone. The add is refused before anything is signed, so the
     * held delete is not stored there and then (before, the add re-posted it first, and the change went into the deleted
     * vault's grace). The move's own run then copies the change and only then sends the delete.
     */
    @Test fun aMemberActionWhileTheMovesDeleteWaitsStoresNoDeleteAndTheChangeIsNotLost() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, front) = rest
        val newId = server.logs.keys.single { it != oldId }
        val item = server.items.values.single { it.vaultId == oldId }
        server.items[item.itemId] = item.copy(rev = server.rev++)
        a.vault!!.afterLogAction()
        val e = contact(a, server, eve, "Eve")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.oldRow(oldId)))
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, a.vaults.addMember(a.snapshot.account!!.members!!, e, io.silencelen.andvari.core.trust.MemberRole.WRITER))
        assertTrue(server.stored.none { it.first == oldId && it.second is LogEntry.Delete }, "the delete is not stored by the add")
        assertTrue(server.stored.none { it.second is LogEntry.Add && (it.second as LogEntry.Add).member == eve }, "nothing is signed")
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        a.vault!!.afterLogAction()
        assertEquals(1, server.items.values.count { it.vaultId == newId && !it.deleted }, "the change is in the new vault, once")
        assertEquals(1, server.stored.count { it.first == oldId && it.second is LogEntry.Delete })
        assertEquals(1, front.posted.map { it.second }.distinct().size)
    }

    /**
     * The link's own release: a vault attached to a connect link, whose move deletion is signed and waiting. Released by
     * hand, it is refused with nothing signed; when this device's entry of the codes matches, it is not released by itself
     * either: it stays waiting, and the held delete is not stored there and then. The move's own run still finishes.
     */
    @Test fun aLinksShareOfAVaultWhoseMoveDeleteWaitsStaysWaitingByHandAndWhenTheCodesMatch() = runBlocking<Unit> {
        val vaults = VaultServer(FakeInstance(crypto))
        val links = io.silencelen.andvari.core.client.link.LinkServer(crypto, vaults.instance)
        var mine: String? = null
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = appOn(vaults, front = { inner ->
            front.wrap(object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
                    if (route.name.startsWith("LINK")) links.client(mine).call(route, pathParams, query, bodyJson, authenticated, decode)
                    else inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            })
        })
        open(a, "bob@example.com")
        val (bobId, bobKey) = a.me()
        mine = bobId
        links.keys[bobId] = bobKey
        val alice = io.silencelen.andvari.core.client.link.LinkPerson(crypto, links, 1, "11111111-1111-4111-8111-111111111111", "Alice").start()
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val family = a.row().vaultId
        oldOf = family
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE,
            a.links.createConnectLink(listOf(io.silencelen.andvari.core.app.ShareChoice(family, io.silencelen.andvari.core.trust.MemberRole.READER)), 15))
        val own = assertNotNull(a.snapshot.account!!.links).links.single()
        val confirm = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Confirm>(
            alice.flows.open(assertNotNull(a.links.linkToShare(own)), io.silencelen.andvari.core.client.pin.GateEntry.SCAN_INVITE))
        val answered = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Answered>(alice.flows.confirm(confirm))
        a.linksFlow.processAnswers()
        assertIs<io.silencelen.andvari.core.client.link.RecipientStep.CodeReady>(alice.flows.awaitReveal(answered))

        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        a.vaults.closeMoveEverything()
        front.mode = DeleteAnswer.PASS
        val posted = front.posted.size

        // By hand: refused, no warning, nothing signed.
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, a.links.releaseShare(a.snapshot.account!!.links!!.waitingShares.single()))
        assertNull(a.snapshot.account!!.shareWarning)
        // By itself: the codes match; the contact is compared, and the share is not released.
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single { it.userId == alice.userId }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openCompare(row))
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(a.snapshot.account!!.comparing)
        assertEquals(io.silencelen.andvari.core.app.ComparisonResult.DONE, a.contacts.submitComparison(ready, assertNotNull(alice.flows.code(bobId))))
        assertTrue(server.stored.none { it.second is LogEntry.Add }, "nothing is shared")
        assertEquals(posted, front.posted.size, "the held delete is not re-posted")
        assertTrue(server.stored.none { it.first == family && it.second is LogEntry.Delete }, "the delete is not stored by the release")
        assertEquals(family, a.snapshot.account!!.links!!.waitingShares.single().vaultId, "the share stays waiting")

        // The move's own run still finishes.
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(family)))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertEquals(1, server.stored.count { it.first == family && it.second is LogEntry.Delete })
        assertEquals(1, front.posted.map { it.second }.distinct().size)
    }

    /**
     * Another member puts a new item [name] into [vaultId]: sealed under the vault's key (which every member holds) and
     * stored on the server, as their device would. Answers its id.
     */
    private fun anotherMemberAdds(a: EngineAppApi, server: VaultServer, vaultId: String, name: String): String {
        val doc = a.vault!!.items.items().first { it.vaultId == vaultId }.doc.copy(name = name)
        val id = Bytes.uuidV4FromBytes(crypto.randomBytes(16))
        val up = assertNotNull(a.vault!!.logs.withKey(vaultId) { vk -> io.silencelen.andvari.core.client.items.ItemCodec(crypto).seal(vk, vaultId, id, doc) })
        server.items[id] = io.silencelen.andvari.core.model.wire.SyncItem(id, vaultId, server.rev++, server.instance.now, server.instance.now,
            false, false, up.formatVersion, up.attachmentIds, up.blob)
        return id
    }

    /**
     * From the moment the move's deletion is signed, the old vault takes no new item and no change on this device, and its
     * row says why in one line; copying out still works. Before, a save went into the old vault while its deletion waited.
     */
    @Test fun aVaultWhoseMoveDeletionWaitsIsReadOnlyHereAndSaysWhy() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, _) = rest
        val row = a.oldRow(oldId)
        assertFalse(row.writable)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_WAITING_READ_ONLY, row.readOnlyLine?.key)
        assertEquals(listOf("Family", "Family 2"), row.readOnlyLine?.values)
        val before = server.items.values.count { it.vaultId == oldId }
        val c = assertNotNull(a.content)
        assertNotEquals<Any>(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Mail", "me", "pw2", listOf("https://mail.test"), "", "", false), oldId))
        val original = a.vault!!.items.items().single { it.vaultId == oldId }
        assertNotEquals<Any>(io.silencelen.andvari.core.app.ActionResult.Ok,
            c.saveLogin(original.itemId, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw9", listOf("https://bank.test"), "", "", false), oldId))
        assertNotEquals<Any>(io.silencelen.andvari.core.app.ActionResult.Ok, c.deleteItem(original.itemId))
        assertTrue(c.vaultsForNewItems().none { it.vaultId == oldId }, "no new item can be put there")
        a.vault!!.afterLogAction()
        assertEquals(before, server.items.values.count { it.vaultId == oldId }, "nothing new reached the old vault")
        assertTrue(server.items.values.none { it.vaultId == oldId && it.deleted })
        // Once the move is finished the line goes with the vault.
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertNull(a.oldRow(oldId).readOnlyLine)
    }

    private fun closedLine() = io.silencelen.andvari.core.app.content.ContentCopy.closedForWriting(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)

    private fun login(name: String, pw: String = "pw-$name") =
        io.silencelen.andvari.core.app.LoginInput(name, "me", pw, listOf("https://${name.lowercase()}.test"), "", "", false)

    /**
     * Design §3.13: the content's own "closed for writing" is what closes a vault whose deletion is signed and waiting
     * (before, the app interface made the item engine see it as a reader's vault, and the content's mark was never set).
     * Every way into the old vault through the app interface is refused before anything is sealed or sent, with the
     * content's line for that reason; a copy out still works; another vault is untouched; once the move's own run
     * stored the deletion, the mark goes. The log's roads (members, roles, offers, a rename, a delete, a leave, a restore,
     * a link's release) are walked by the tests around [refusedWhileTheDeleteWaits].
     */
    @Test fun everyWayIntoAVaultWhoseDeletionWaitsIsRefusedByTheContentsOwnMarkBeforeAnythingIsSealed() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, _) = rest
        val c = assertNotNull(a.content)
        assertEquals(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING, a.vault!!.items.closedForWriting(oldId))
        // The move's new vault, open for writing: where an item comes from and goes to.
        val personal = server.logs.keys.single { it != oldId }
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, c.saveLogin(null, login("Mine"), personal))
        a.vault!!.afterLogAction()
        val mine = c.state.items.single { it.name == "Mine" }.itemId
        val original = a.vault!!.items.items().single { it.vaultId == oldId }
        fun oldOnServer() = server.items.values.filter { it.vaultId == oldId }.map { Triple(it.itemId, it.rev, it.deleted) }.sortedBy { it.first }
        val before = oldOnServer()

        suspend fun refused(what: String, saying: Boolean = true, road: suspend () -> io.silencelen.andvari.core.app.ActionResult) {
            val r = road()
            assertIs<io.silencelen.andvari.core.app.ActionResult.Failed>(r, what)
            if (saying) assertEquals(closedLine(), r.message, "$what: the content's line for a vault closed for writing")
            assertEquals(emptyList(), a.vault!!.queued().pending.map { it.itemId }, "$what: nothing was sealed for sending")
            a.vault!!.afterLogAction()
            assertEquals(before, oldOnServer(), "$what: nothing reached the old vault")
        }
        // (A new item is refused by the content's choice of vaults for new items first, with its own general line.)
        refused("a new login", saying = false) { c.saveLogin(null, login("New"), oldId) }
        refused("a new note", saying = false) { c.saveNote(null, io.silencelen.andvari.core.app.NoteInput("Note", "text", false), oldId) }
        refused("an edit") { c.saveLogin(original.itemId, login("Bank", "pw9"), oldId) }
        refused("a delete") { c.deleteItem(original.itemId) }
        c.openAttachmentDraft(original.itemId)
        c.addAttachment("f.txt", ByteArray(10) { 1 })
        refused("an edit with a file") { c.saveLogin(original.itemId, login("Bank"), oldId) }
        c.closeAttachmentDraft()
        // (An import, a restore and a delete for good from the trash are refused by the same mark in the content's own
        // road test, WriteClosedTest; this server serves no trash and no whole read an import's duplicate check needs.)
        refused("a move into it", saying = false) { c.moveOrCopyItem(mine, oldId, move = true) }
        refused("a copy into it", saying = false) { c.moveOrCopyItem(mine, oldId, move = false) }
        refused("a move out of it", saying = false) { c.moveOrCopyItem(original.itemId, personal, move = true) }
        assertTrue(c.vaultsForNewItems().none { it.vaultId == oldId }, "no picker offers it")

        // A copy out changes nothing there, and is allowed; another vault takes changes as before.
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, c.moveOrCopyItem(original.itemId, personal, move = false))
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, c.saveLogin(null, login("Also mine"), personal))
        a.vault!!.afterLogAction()
        assertEquals(before, oldOnServer())

        // The move's own run stores the deletion: the mark goes with the waiting.
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.DONE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertNull(a.vault!!.items.closedForWriting(oldId))
    }

    /** The mark is set before the deletion is signed: when the delete reaches the server, the old vault is already closed here. */
    @Test fun theOldVaultIsClosedForWritingFromTheMomentItsDeletionIsSigned() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        server.servesItems = true
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.saveLogin(null, login("Bank"), oldId))
        a.vault!!.afterLogAction()
        assertNull(a.vault!!.items.closedForWriting(oldId), "open for writing before the move")
        val atDelete = ArrayList<io.silencelen.andvari.core.client.items.VaultClosedReason?>()
        front.onDelete = { atDelete += a.vault!!.items.closedForWriting(it) }
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertEquals(listOf<io.silencelen.andvari.core.client.items.VaultClosedReason?>(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING), atDelete)
        assertEquals(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING, a.vault!!.items.closedForWriting(oldId), "and stays closed while it waits")
        // It is kept in the account's cache, across a lock.
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING, a.vault!!.items.closedForWriting(oldId))
    }

    /** A move kept by a version that set no mark: the next opening closes its old vault before anything runs in it. */
    @Test fun anOpeningClosesTheOldVaultOfAKeptMoveWhoseDeletionWaits() = runBlocking<Unit> {
        val (_, a, rest) = waitingMove()
        val (oldId, _) = rest
        a.vault!!.items.markClosedForWriting(oldId, null)
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING, a.vault!!.items.closedForWriting(oldId))
    }

    /** A held deletion the server refuses for good at the move's next run: nothing waits any more, and the old vault is open for writing again. */
    @Test fun aDeletionRefusedForGoodOpensTheOldVaultForWritingAgain() = runBlocking<Unit> {
        val (_, a, rest) = waitingMove()
        val (oldId, front) = rest
        front.mode = DeleteAnswer.REFUSED
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.oldRow(oldId)))
        assertEquals(VaultActionResult.FAILED, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        assertNull(a.vault!!.items.closedForWriting(oldId), "the deletion no longer waits")
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.saveLogin(null, login("After"), oldId))
    }

    /**
     * The review's sequence: the move's deletion gets no answer; another member adds an item and changes the copied one;
     * the server stores the held deletion later, outside any run of the move. It is not the person's quiet departure: a
     * notice of its own kind counts one item added and one changed after the copies, the copy is kept in the holding area,
     * and copying them lands the added item once and replaces the changed item's earlier copy. A second copy copies nothing.
     * Before, the deletion was taken quietly and the two items were left in the deleted vault, unsaid.
     */
    @Test fun aMoveDeletionTheServerStoresLaterIsNeverQuietAndWhatChangedSinceTheCopiesCanBeCopied() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove()
        val (oldId, front) = rest
        val newId = server.logs.keys.single { it != oldId }
        val bank = server.items.values.single { it.vaultId == oldId }
        anotherMemberAdds(a, server, oldId, "Mail")
        server.items[bank.itemId] = bank.copy(rev = server.rev++)
        a.vault!!.afterLogAction()
        assertEquals(2, a.vault!!.items.items().count { it.vaultId == oldId }, "this device received both")
        // The server stores the held deletion now, by itself.
        val frame = front.posted.single().second
        server.logs.getValue(oldId) += frame
        server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()

        val notice = a.snapshot.account!!.movesStoredOutside.single()
        assertEquals(oldId, notice.oldVaultId)
        assertEquals(1, notice.added)
        assertEquals(1, notice.changed)
        assertTrue(notice.canCopy)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STORED_OUTSIDE, notice.line.key)
        assertEquals(listOf("Family", "Family 2", "1", "1"), notice.line.values)
        assertTrue(a.content!!.state.held.any { it.vaultId == oldId }, "the copy is kept in the holding area")
        assertNull(a.oldRow(oldId).unfinishedMove, "the move is no longer offered as unfinished")
        assertEquals(emptyList(), a.snapshot.account!!.unfinishedMoves)
        assertFalse(a.vaultsFlow.moveDeleteWaiting(oldId))

        assertEquals(VaultActionResult.DONE, a.vaults.bringLateIntoMove(notice))
        a.vault!!.afterLogAction()
        assertEquals(2, server.items.values.count { it.vaultId == newId && !it.deleted }, "the added item once and the changed one's new revision")
        assertEquals(1, server.items.values.count { it.vaultId == newId && it.deleted }, "the changed item's earlier copy is replaced")
        val after = a.snapshot.account!!.movesStoredOutside.single()
        assertEquals(0, after.added + after.changed)
        assertFalse(after.canCopy)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STORED_COPIED, after.copiedLine?.key)
        assertEquals("2", after.copiedLine?.values?.first())
        assertEquals(VaultActionResult.DONE, a.vaults.bringLateIntoMove(after))
        a.vault!!.afterLogAction()
        assertEquals(2, server.items.values.count { it.vaultId == newId && !it.deleted }, "a second copy copies nothing")
        assertEquals(1, front.posted.map { it.second }.distinct().size, "the one deletion, never signed again")
        a.vaults.dismissMoveStored(a.snapshot.account!!.movesStoredOutside.single())
        assertEquals(emptyList(), a.snapshot.account!!.movesStoredOutside)
        assertTrue(a.content!!.state.held.any { it.vaultId == oldId }, "the held copy stays after the dismiss")
    }

    /**
     * Decided on 2026-11-17: the person deleted a copied item on this device and the deletion was still waiting when the
     * old vault closed; then the server stored the move's deletion outside a run of the move. The finishing run settles it
     * without a question, also with nothing else late, and it counts as neither added nor changed (before, the notice
     * counted it as changed and offered to copy it, which would have brought the deleted item back). Its copy, untouched
     * since the move made it, is deleted in the new vault at the revision the move recorded (into that vault's trash), and
     * counted as carried; nothing is sent into the closed old vault. (Before the content could delete at a named revision,
     * the copy was kept live and counted as kept.)
     */
    @Test fun thePersonsOwnDeletionWaitingWhenTheVaultClosedIsCarriedWithoutAQuestionAtTheRevisionTheMoveRecorded() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove(durable = true)
        val (oldId, front) = rest
        val newId = server.logs.keys.single { it != oldId }
        val bank = server.items.values.single { it.vaultId == oldId && !it.deleted }
        val copy = server.items.values.single { it.vaultId == newId && !it.deleted }
        // The person's deletion of Bank, made offline before the vault closed (the mark is set again at once after it).
        val items = a.vault!!.items
        items.markClosedForWriting(oldId, null)
        server.servesItems = false
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.deleteItem(bank.itemId), "kept to be sent: the copy is at rest")
        items.markClosedForWriting(oldId, io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)
        server.servesItems = true
        assertEquals(setOf(bank.itemId), items.waitingDeletions(oldId))
        // The server stores the held deletion by itself.
        val frame = front.posted.single().second
        server.logs.getValue(oldId) += frame
        server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()

        val notice = a.snapshot.account!!.movesStoredOutside.single()
        assertEquals(0, notice.added, "a deletion is not an added item")
        assertEquals(0, notice.changed, "a deletion is not a changed item")
        assertFalse(notice.canCopy, "nothing is offered to copy: the deleted item never comes back")
        assertEquals(1, notice.deletionsCarried, "carried without a question")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STORED_DELETIONS_CARRIED, notice.carriedLine?.key)
        assertEquals(0, notice.deletionsKept)
        assertNull(notice.keptLine)
        assertTrue(server.items.getValue(copy.itemId).deleted, "its copy is deleted in the new vault (in its trash)")
        assertFalse(server.items.getValue(bank.itemId).deleted, "nothing is sent into the closed vault")
        // A second look settles nothing again.
        val pushes = server.calls.count { it == WireRoute.PUSH }
        a.vault!!.afterLogAction()
        assertEquals(1, a.snapshot.account!!.movesStoredOutside.single().deletionsCarried)
        assertEquals(pushes, server.calls.count { it == WireRoute.PUSH }, "a second run sends nothing")
    }

    /**
     * The carry names the revision the move recorded: a copy whose recorded revision is not the one it stands at now (here:
     * the record lost its revision, as one kept before revisions were recorded) is kept and counted, never deleted at the
     * revision a sync brought in.
     */
    @Test fun aWaitingDeletionWhoseCopyHasNoRecordedRevisionIsKeptAndCounted() = runBlocking<Unit> {
        val (server, a, rest) = waitingMove(durable = true)
        val (oldId, front) = rest
        val newId = server.logs.keys.single { it != oldId }
        val bank = server.items.values.single { it.vaultId == oldId && !it.deleted }
        val copy = server.items.values.single { it.vaultId == newId && !it.deleted }
        // The kept record without the copy's revision.
        val key = a.engine.state.keys()!!.single { it.startsWith(EngineSharedVaults.MOVE_PREFIX) }
        a.engine.state.set(key, a.engine.state.get(key)!!.replace(Regex(",\"copyRev\":[0-9]+"), ""))
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val items = a.vault!!.items
        items.markClosedForWriting(oldId, null)
        server.servesItems = false
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.deleteItem(bank.itemId))
        items.markClosedForWriting(oldId, io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)
        server.servesItems = true
        val frame = front.posted.single().second
        server.logs.getValue(oldId) += frame
        server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
        a.vault!!.afterLogAction()
        a.vault!!.afterLogAction()
        val notice = a.snapshot.account!!.movesStoredOutside.single()
        assertEquals(0, notice.deletionsCarried)
        assertEquals(1, notice.deletionsKept, "no revision named: kept")
        assertFalse(server.items.getValue(copy.itemId).deleted, "its copy stays live")
    }

    /**
     * The person's own waiting deletion is carried only over a copy that nobody changed since the move made it. Round
     * "changed": another member changed the copy in the new vault after the move, and this device received that change;
     * the later change is the later word, so the copy stays live. Round "refused": the server refuses the copy's
     * deletion. In both, the notice counts the item as kept, not as carried, and says so. Before: the changed copy was
     * deleted, and a refused deletion was counted as carried although the copy stayed.
     */
    @Test fun aWaitingDeletionIsNotCarriedOverACopyChangedSinceOrOneTheServerRefusesAndTheNoticeSaysHowMany() = runBlocking<Unit> {
        for (round in listOf("changed", "refused")) {
            val (server, a, rest) = waitingMove(durable = true)
            val (oldId, front) = rest
            val newId = server.logs.keys.single { it != oldId }
            val bank = server.items.values.single { it.vaultId == oldId && !it.deleted }
            val copy = server.items.values.single { it.vaultId == newId && !it.deleted }
            val items = a.vault!!.items
            items.markClosedForWriting(oldId, null)
            server.servesItems = false
            assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.deleteItem(bank.itemId))
            items.markClosedForWriting(oldId, io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)
            server.servesItems = true
            assertEquals(setOf(bank.itemId), items.waitingDeletions(oldId))
            if (round == "changed") {
                // Another member changes the copy in the new vault; this device receives it.
                server.items[copy.itemId] = copy.copy(rev = server.rev++)
                a.vault!!.afterLogAction()
                assertEquals(server.items.getValue(copy.itemId).rev, items.items().single { it.itemId == copy.itemId }.rev, "received")
            } else {
                server.deniesDeleteOf += copy.itemId
            }
            val frame = front.posted.single().second
            server.logs.getValue(oldId) += frame
            server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
            a.vault!!.afterLogAction()
            a.vault!!.afterLogAction()

            val notice = a.snapshot.account!!.movesStoredOutside.single()
            assertFalse(server.items.getValue(copy.itemId).deleted, "the copy stays live: $round")
            assertEquals(0, notice.deletionsCarried, round)
            assertNull(notice.carriedLine, round)
            assertEquals(1, notice.deletionsKept, round)
            assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STORED_DELETIONS_KEPT, notice.keptLine?.key)
            assertEquals("1", notice.keptLine?.values?.first())
            assertEquals(0, notice.added + notice.changed, "a deletion is neither added nor changed")
            // A second look carries nothing and counts nothing again.
            a.vault!!.afterLogAction()
            assertEquals(1, a.snapshot.account!!.movesStoredOutside.single().deletionsKept)
            assertFalse(server.items.getValue(copy.itemId).deleted)
        }
    }

    /**
     * The carry deletes a copy only at the revision the move made it at, decided against the copy as it stands when the
     * deletion is sent. Form "elsewhere" (the finishing run, right after the sync that saw the move's deletion stored):
     * another member changes the copy in the new vault after this device's last pull, and the change reaches the server
     * just as the carry's own sync runs. Form "waiting" ("copy what is late", where the window runs from the last sync to
     * the person's tap): the finishing run's own sync got no answer, so the deletion still waits; the person then changes
     * the copy on this device while its push gets no answer, and taps; the change goes out in the carry's own sync. (On the
     * finishing run alone a change waiting here is sent by the sync that triggers it, before anything is decided.) In both,
     * the copy stays live with that change, and the notice counts the item as kept, never as carried. Before: the item
     * engine synced first and then deleted the copy at the revision that sync brought in, so the change went into the trash
     * and the notice counted the deletion as carried.
     */
    @Test fun aCopyChangedElsewhereWhenTheCarrysDeletionGoesOutStaysLiveAndCountsAsKept() = carryOverAChangedCopy("elsewhere")

    @Test fun aCopyWithAChangeWaitingHereWhenTheCarrysDeletionGoesOutStaysLiveAndCountsAsKept() = carryOverAChangedCopy("waiting")

    private fun carryOverAChangedCopy(form: String) = runBlocking<Unit> {
        run {
            val state = MemoryDeviceState()
            val (server, a, rest) = waitingMove(durable = true, state = state)
            val (oldId, front) = rest
            val newId = server.logs.keys.single { it != oldId }
            val bank = server.items.values.single { it.vaultId == oldId && !it.deleted }
            val copy = server.items.values.single { it.vaultId == newId && !it.deleted }
            val items = a.vault!!.items
            items.markClosedForWriting(oldId, null)
            server.servesItems = false
            assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok, a.content!!.deleteItem(bank.itemId))
            items.markClosedForWriting(oldId, io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING)
            server.servesItems = true
            assertEquals(setOf(bank.itemId), items.waitingDeletions(oldId))
            // The device has decided that the move's deletion was stored outside it (its record says so at rest).
            fun decided() = state.keys().any { it.startsWith("ovh.app.move|") && state.get(it).orEmpty().contains("\"storedOutside\":true") }
            var changedElsewhere = false
            if (form == "waiting") {
                // Every sync after the decision (the finishing run's own among them) gets no answer, for now.
                server.onSync = { server.syncUnanswered = decided() }
            } else {
                server.onSync = {
                    if (decided() && !changedElsewhere) {
                        changedElsewhere = true
                        server.items[copy.itemId] = server.items.getValue(copy.itemId).copy(rev = server.rev++)
                    }
                }
            }
            val frame = front.posted.single().second
            server.logs.getValue(oldId) += frame
            server.stored += oldId to VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry
            a.vault!!.afterLogAction()
            a.vault!!.afterLogAction()
            if (form == "waiting") {
                server.onSync = null
                server.syncUnanswered = false
                server.pushUnanswered = true
                assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
                    a.content!!.saveLogin(copy.itemId, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw2", listOf("https://bank.test"), "", "", false), newId),
                    "kept to be sent")
                assertTrue(items.hasPendingSync(copy.itemId), "the person's change waits on this device")
                server.pushUnanswered = false
                a.vaults.bringLateIntoMove(a.snapshot.account!!.movesStoredOutside.single())
            }

            val notice = a.snapshot.account!!.movesStoredOutside.single()
            assertFalse(server.items.getValue(copy.itemId).deleted, "the copy stays live: $form")
            assertEquals(0, notice.deletionsCarried, form)
            assertNull(notice.carriedLine, form)
            assertEquals(1, notice.deletionsKept, form)
            assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STORED_DELETIONS_KEPT, notice.keptLine?.key, form)
            // A later sync carries nothing again, and the change stands at the server, live.
            a.vault!!.afterLogAction()
            val live = server.items.getValue(copy.itemId)
            assertFalse(live.deleted, form)
            assertTrue(live.rev > copy.rev, "the change stands: $form")
            if (form == "waiting") assertFalse(items.hasPendingSync(copy.itemId), "the person's change was sent")
            assertEquals(1, a.snapshot.account!!.movesStoredOutside.single().deletionsKept, form)
            assertEquals(0, a.snapshot.account!!.movesStoredOutside.single().deletionsCarried, form)
        }
    }

    /**
     * A lock that overtakes the move's deletion after it was signed and posted (no answer came): the move's record never
     * learned that the deletion was sent, but the log engine holds it. The old vault stays closed for writing after the
     * next unlock and sync, and its roads stay refused. Before, the sync opened the vault again while its signed
     * deletion was held.
     */
    @Test fun aLockOvertakingTheSignedDeletionKeepsTheOldVaultClosed() = runBlocking<Unit> {
        var oldOf: String? = null
        val front = DeleteFront { it == oldOf }
        val (server, a) = app(front::wrap)
        server.servesItems = true
        open(a)
        val oldId = family(a, server)
        oldOf = oldId
        a.vaults.closeMembers()
        assertEquals(io.silencelen.andvari.core.app.ActionResult.Ok,
            a.content!!.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("Bank", "me", "pw1", listOf("https://bank.test"), "", "", false), oldId))
        a.vault!!.afterLogAction()
        front.mode = DeleteAnswer.LOST
        front.onDelete = { a.lock() }
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        assertEquals(VaultActionResult.STALE, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertEquals(1, front.posted.size, "the signed deletion was posted")
        front.onDelete = null
        front.mode = DeleteAnswer.PASS
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING, a.vault!!.items.closedForWriting(oldId), "closed at the opening")
        a.vault!!.afterLogAction()
        assertEquals(io.silencelen.andvari.core.client.items.VaultClosedReason.DELETION_WAITING, a.vault!!.items.closedForWriting(oldId), "and after a sync")
        assertTrue(a.vaultsFlow.moveDeleteWaiting(oldId))
        assertNotEquals<Any>(io.silencelen.andvari.core.app.ActionResult.Ok,
            a.content!!.saveLogin(null, io.silencelen.andvari.core.app.LoginInput("After", "me", "pw2", listOf("https://after.test"), "", "", false), oldId))
    }

    private var logsOf: Map<String, MutableList<String>> = emptyMap()

    private fun serverLogs(): Set<String> = logsOf.keys

    /**
     * A deleted vault is restorable until the server's grace end when the server sent one. Where it sent none the row
     * names no day at all (neither the old value nor an estimate of this device's), stays deleted, and carries the line
     * of its own that names no day.
     */
    @Test fun restorableUntilIsTheServersGraceEndWhenItSentOne() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val end = server.instance.now + 3L * 86_400_000
        server.graceEnd = io.silencelen.andvari.core.model.wire.LogDeleted(server.instance.now, end)
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(a.snapshot.account!!.vaults.single()))
        val served = a.snapshot.account!!.vaults.single()
        assertEquals(end, served.purgeAtMs, "the server's grace end")
        assertTrue(served.deleted)
        assertNull(served.deletedNoDayLine, "a served day is named by the screen itself")
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(served))
        assertFalse(a.snapshot.account!!.vaults.single().deleted)
        assertEquals(0L, a.snapshot.account!!.vaults.single().purgeAtMs)
        // Deleted again by a server that sends none: no day, not the old value and not an estimate of this device's.
        server.graceEnd = null
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(a.snapshot.account!!.vaults.single()))
        val unserved = a.snapshot.account!!.vaults.single()
        assertEquals(0L, unserved.purgeAtMs, "no day the server did not serve")
        assertTrue(unserved.deleted, "and still deleted")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.VAULT_DELETED_NO_DAY, unserved.deletedNoDayLine?.key)
        assertEquals(emptyList(), unserved.deletedNoDayLine?.values)
        assertFalse(unserved.canMoveEverything)
        // The restore is offered from [deleted], not from a day: it works on a row that names none.
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(unserved))
        assertFalse(a.snapshot.account!!.vaults.single().deleted)
        assertNull(a.snapshot.account!!.vaults.single().deletedNoDayLine)
    }

    /**
     * No day unless the server served it, on the engine and the fake side by side: a deletion where the server serves no
     * day, its restore, and a deletion where it serves one. Both read the same at every step.
     */
    @Test fun theFakeNamesADeletedVaultsDayOnlyWhereTheServerServedOneAsTheEngineDoes() = runBlocking<Unit> {
        fun read(r: io.silencelen.andvari.core.app.SharedVaultRow) =
            listOf(r.deleted, r.purgeAtMs > 0L, r.deletedNoDayLine?.key, r.deletedNoDayLine?.values, r.canMoveEverything)
        val notDeleted = listOf(false, false, null, null, true)
        val noDay = listOf(true, false, io.silencelen.andvari.core.app.CopyKey.VAULT_DELETED_NO_DAY, emptyList<String>(), false)
        val withDay = listOf(true, true, null, null, false)

        val engine = Readings()
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        fun eRow() = a.snapshot.account!!.vaults.single()
        engine += read(eRow())
        server.graceEnd = null
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(eRow()))
        engine += read(eRow())
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(eRow()))
        engine += read(eRow())
        server.graceEnd = io.silencelen.andvari.core.model.wire.LogDeleted(server.instance.now, server.instance.now + 86_400_000)
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(eRow()))
        engine += read(eRow())
        assertEquals(listOf<Any?>(notDeleted, noDay, notDeleted, withDay), engine.toList())

        val fake = Readings()
        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        fun fRow() = f.snapshot.account!!.vaults.first { it.name == "Family" }
        fake += read(fRow())
        f.script.servesGraceDay = false
        assertEquals(VaultActionResult.DONE, f.vaults.deleteVault(fRow()))
        fake += read(fRow())
        assertEquals(VaultActionResult.DONE, f.vaults.restoreVault(fRow()))
        fake += read(fRow())
        f.script.servesGraceDay = true
        assertEquals(VaultActionResult.DONE, f.vaults.deleteVault(fRow()))
        fake += read(fRow())
        assertEquals(engine.toList(), fake.toList())
    }

    /**
     * Design §3.11: a member the server's list leaves out is shown as deleted by the operator: the server's word, for
     * the screen only. An unreadable list shows nothing, and the member is still a member for every intent.
     */
    @Test fun aMemberTheServersListLeavesOutIsShownAsDeletedByTheOperatorAndStaysAMember() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val carol = "33333333-3333-4333-8333-333333333333"
        val c = contact(a, server, carol, "Carol")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertEquals(VaultActionResult.DONE, a.vaults.addMember(a.snapshot.account!!.members!!, c, io.silencelen.andvari.core.trust.MemberRole.WRITER))
        fun row(id: String) = a.snapshot.account!!.members!!.members.single { it.userId == id }
        assertTrue(!row(carol).deletedByOperator, "listed")
        a.vaults.closeMembers()

        server.unlisted += carol
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertTrue(row(carol).deletedByOperator, "the server's list leaves her out")
        assertEquals("Carol", row(carol).deletedLine?.values?.firstOrNull())
        assertTrue(!a.snapshot.account!!.members!!.members.single { it.who is PersonName.You }.deletedByOperator)
        // Nothing else changed: she is still a member, and the owner manages her as before.
        assertEquals(RoleInVault.WRITER, row(carol).role)
        assertTrue(a.snapshot.account!!.members!!.canManage)
        assertEquals(VaultActionResult.DONE, a.vaults.changeRole(row(carol), io.silencelen.andvari.core.trust.MemberRole.READER))
        assertTrue(row(carol).deletedByOperator, "read again after the change, against the new head")

        // A list that cannot be read says nothing.
        a.vaults.closeMembers()
        server.membersRefused = true
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertTrue(!row(carol).deletedByOperator)
        // "Remove from the list" is the owner's signed remove.
        server.membersRefused = false
        a.vaults.closeMembers()
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertEquals(VaultActionResult.DONE, a.vaults.removeMember(row(carol)))
        assertTrue(a.snapshot.account!!.members!!.members.none { it.userId == carol })
    }

    /**
     * An ownership offer lasts 14 days (the approved "They have 14 days"), within spec §3.3's bound, and its end is on the
     * vault's row from the signed entry, so no screen adds the days.
     */
    @Test fun anOwnershipOfferLastsFourteenDaysAndItsEndIsOnTheRow() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val carol = "33333333-3333-4333-8333-333333333333"
        val c = contact(a, server, carol, "Carol")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.snapshot.account!!.vaults.single()))
        assertEquals(VaultActionResult.DONE, a.vaults.addMember(a.snapshot.account!!.members!!, c, io.silencelen.andvari.core.trust.MemberRole.WRITER))
        val made = server.instance.now
        assertEquals(VaultActionResult.DONE, a.vaults.offerOwnership(a.snapshot.account!!.members!!.members.single { it.userId == carol }))

        val day = 24L * 60 * 60 * 1000
        assertEquals(14, io.silencelen.andvari.core.app.OwnershipOffer.DAYS)
        assertEquals(14 * day, io.silencelen.andvari.core.app.OwnershipOffer.LIFE_MS)
        assertTrue(io.silencelen.andvari.core.app.OwnershipOffer.LIFE_MS <= VaultLog.MAX_OFFER_WINDOW_MS - 10L * 60 * 1000, "spec §3.3: at most 14 days")
        val offer = assertNotNull(a.snapshot.account!!.vaults.single().offer, "the offer is on the row at once")
        assertTrue(!offer.toMe)
        assertEquals(made + 14 * day, offer.expiresAtMs, "the end the signed entry names")
        val signed = VaultLog.parse(crypto, Bytes.fromB64(server.logs.values.single().last())).valueOrNull()?.entry
        assertEquals(made + 14 * day, assertIs<LogEntry.Offer>(signed).expiresAt)
    }

    @Test fun aRowThatIsNoLongerShownIsStaleAndNothingIsSigned() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val row = a.snapshot.account!!.vaults.single()
        a.lock()
        assertEquals(VaultActionResult.STALE, a.vaults.deleteVault(row))
        assertEquals(1, server.logs.values.single().size)
    }

    /**
     * A lock while a vault's creation waits on the account state. The log
     * engine's guard refuses the rest, so nothing is sealed or sent after the lock, the intent answers STALE (it used to
     * throw the guard's KeysGoneException at the screen), and after the next unlock a vault is created as usual.
     */
    @Test fun aVaultCreationALockOvertakesAnswersStaleSendsNothingAfterTheLockAndTheAppStaysUsable() = runBlocking<Unit> {
        var probe: LockProbe? = null
        val (server, a) = app { LockProbe(it).also { p -> probe = p } }
        val p = probe!!
        open(a)
        var result: VaultActionResult? = null
        with(p) { lockDuring(WireRoute.ACCOUNT_STATE_GET, { a.lock() }) { result = a.vaults.createVault("Family") } }
        assertEquals(emptyList(), p.crashes.map { it.toString() }, "the intent answers, it does not crash")
        assertEquals(VaultActionResult.STALE, result)
        assertEquals(emptyList(), p.sentAfterLock(), "nothing is sent after the lock")
        assertTrue(server.logs.isEmpty(), "no genesis reached the server")
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        assertEquals(1, server.logs.size)
        assertEquals("Family", a.snapshot.account!!.vaults.single().name)
    }

    // ---- a change to a shared vault that waits, for the apps' screens ----

    private fun io.silencelen.andvari.core.app.AppApi.waits() = vaults as io.silencelen.andvari.core.app.WaitingChanges

    private fun appends(server: VaultServer) = server.calls.count { it == WireRoute.LOG_APPEND }

    /** What a screen draws of a waiting change, in one list (the engine's and the stand-in's are compared by it). */
    private fun drawn(w: io.silencelen.andvari.core.app.WaitingChange?): List<Any?> =
        if (w == null) listOf(null) else listOf(w.kind, w.role, w.known, w.sending, w.canWithdraw, w.asksForWord, w.line.key, w.withdrawLabel, w.askLine?.key, w.askLine?.values)

    /**
     * An addition whose answer was lost waits: the row draws it (its kind, whom it names, what is known of it, that it may
     * be withdrawn, its line). "Withdraw" answers with the words of the record the engine acted on, sends nothing, and the
     * read that follows keeps a notice that names the vault until the person dismisses it, across a lock. The stand-in
     * plays the same. Before, the row carried only "a change waits" and no act could withdraw it.
     */
    @Test fun aWaitingAdditionIsDrawnWithdrawnInItsOwnWordsAndItsNoticeIsKeptUntilDismissed() = runBlocking<Unit> {
        var loseAdds = false
        val (server, a) = app { inner ->
            object : WireClient by inner {
                override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                    if (loseAdds && route == WireRoute.LOG_APPEND && entryOf(bodyJson) is LogEntry.Add) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
        open(a)
        val vaultId = family(a, server)
        a.vaults.closeMembers()
        assertNull(a.row().waiting, "nothing waits")
        val erin = "66666666-6666-4666-8666-666666666666"
        val e = contact(a, server, erin, "Erin")
        assertEquals(VaultActionResult.DONE, a.vaults.openMembers(a.row()))
        loseAdds = true
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.addMember(a.snapshot.account!!.members!!, e, io.silencelen.andvari.core.trust.MemberRole.WRITER))
        a.vaults.closeMembers()
        val w = assertNotNull(a.row().waiting)
        assertEquals("Erin", assertIs<PersonName.Contact>(w.names).label)
        val engine = Readings()
        engine += drawn(w)
        assertEquals(listOf(io.silencelen.andvari.core.app.WaitingKind.ADD, RoleInVault.WRITER, io.silencelen.andvari.core.app.WaitingKnown.CANNOT_TELL, false, true, false,
            io.silencelen.andvari.core.app.CopyKey.WAITING_MAY_BE_MADE, io.silencelen.andvari.core.app.CopyKey.WAITING_WITHDRAW, null, null), drawn(w))
        val before = appends(server)
        val r = a.waits().withdrawWaiting(w)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.WAITING_WITHDRAWN_MAY_BE_MADE, r.sentence)
        assertEquals(before, appends(server), "a withdrawal sends nothing")
        assertTrue(server.stored.none { it.first == vaultId && (it.second as? LogEntry.Add)?.member == erin }, "the addition was never stored")
        assertNull(a.row().waiting)
        val n = a.snapshot.account!!.waitingNotices.single()
        engine += listOf(r, drawn(a.row().waiting), n.line.key, n.line.values, n.kind, n.undo)
        assertEquals(listOf(io.silencelen.andvari.core.app.CopyKey.WAITING_FOUND_NOT_MADE_YET, listOf("Family"), vaultId), listOf(n.line.key, n.line.values, n.vaultId))
        assertEquals("Erin", assertIs<PersonName.Contact>(n.names).label)
        kotlin.test.assertSame(n, a.snapshot.account!!.waitingNotices.single(), "the same notice while it says the same")
        // Kept at rest: a lock does not lose it; only the person's dismissal does.
        loseAdds = false
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val kept = a.snapshot.account!!.waitingNotices.single()
        assertEquals(n.noticeId, kept.noticeId)
        assertEquals(before, appends(server), "nothing withdrawn is sent again at the unlock")
        a.waits().dismissWaitingNotice(kept)
        assertTrue(a.snapshot.account!!.waitingNotices.isEmpty())
        // An object drawn before the lock is stale in the next opening; one drawn now finds nothing waiting.
        assertEquals(io.silencelen.andvari.core.app.WaitingResult.STALE, a.waits().withdrawWaiting(w), "a second tap, drawn before the lock")
        assertNull(a.row().waiting, "nothing waits")

        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        val fFamily = f.snapshot.account!!.vaults.first { it.name == "Family" }
        assertEquals(VaultActionResult.DONE, f.vaults.openMembers(fFamily))
        val member = f.snapshot.account!!.members!!.members.first { it.who is PersonName.Contact }
        f.vaults.closeMembers()
        assertTrue(f.script.changeWaits("Family", io.silencelen.andvari.core.app.WaitingKind.ADD, memberId = member.userId, role = RoleInVault.WRITER))
        val fw = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        val fake = Readings()
        fake += drawn(fw)
        val fr = f.waits().withdrawWaiting(fw)
        val fn = f.snapshot.account!!.waitingNotices.single()
        fake += listOf(fr, drawn(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting), fn.line.key, fn.line.values, fn.kind, fn.undo)
        assertEquals<List<Any?>>(engine, fake)
        f.waits().dismissWaitingNotice(fn)
        assertTrue(f.snapshot.account!!.waitingNotices.isEmpty())
    }

    /**
     * The person's deletion of a vault whose answer was lost waits for their word: the general re-send never sends it, and
     * it is asked about only after a look in its log that sends nothing (again in each opening). "Delete it now" sends the
     * deletion as it was signed and answers with its own line; the vault is deleted. The stand-in plays the same. Before,
     * the row carried only "a change waits", and nothing asked or sent it.
     */
    @Test fun aDeletionThatWaitsIsAskedAboutOnlyAfterALookAndDeleteItNowSendsIt() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val vaultId = family(a, server)
        a.vaults.closeMembers()
        old = vaultId
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        assertEquals(1, front.posted.size, "sent once; the re-send after the sync and the look sent nothing more")
        val engine = Readings()
        val w = assertNotNull(a.row().waiting)
        engine += drawn(w)
        assertEquals(listOf(io.silencelen.andvari.core.app.WaitingKind.DELETION, null, io.silencelen.andvari.core.app.WaitingKnown.CANNOT_TELL, false, true, true,
            io.silencelen.andvari.core.app.CopyKey.WAITING_DELETE, io.silencelen.andvari.core.app.CopyKey.WAITING_KEEP_VAULT,
            io.silencelen.andvari.core.app.CopyKey.WAITING_DELETE_ASK, listOf("Family")), drawn(w))
        // A new opening asks again only after its own look; that look sends nothing either.
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(1, front.posted.size)
        val again = assertNotNull(a.row().waiting)
        assertTrue(again.asksForWord)
        front.mode = DeleteAnswer.PASS
        val r = a.waits().deleteWaitingNow(again)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.WAITING_DELETED, r.sentence)
        assertEquals(2, front.posted.size, "sent at the person's word, once")
        assertTrue(server.stored.any { it.first == vaultId && it.second is LogEntry.Delete })
        val gone = a.snapshot.account!!.vaults.single { it.vaultId == vaultId }
        engine += listOf(r, drawn(gone.waiting), gone.deleted)
        assertEquals(io.silencelen.andvari.core.app.WaitingResult.NOTHING_WAITING, a.waits().deleteWaitingNow(again), "a second tap finds nothing")

        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        assertTrue(f.script.changeWaits("Family", io.silencelen.andvari.core.app.WaitingKind.DELETION))
        val notAsked = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        assertFalse(notAsked.asksForWord, "not asked before the look")
        assertEquals(io.silencelen.andvari.core.app.WaitingResult.NOT_OFFERED, f.waits().deleteWaitingNow(notAsked))
        assertTrue(f.script.waitingDeletionLooked("Family"))
        val fake = Readings()
        val fw = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        fake += drawn(fw)
        val fr = f.waits().deleteWaitingNow(fw)
        val fGone = f.snapshot.account!!.vaults.first { it.vaultId == fw.vaultId }
        fake += listOf(fr, drawn(fGone.waiting), fGone.deleted)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * "Keep the vault" withdraws a deletion that waits: nothing is sent, the vault stays, the line is the result's, and the
     * read that follows keeps its notice. The stand-in plays the same.
     */
    @Test fun keepTheVaultWithdrawsTheDeletionAndSaysSoInTheResultsWords() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val vaultId = family(a, server)
        a.vaults.closeMembers()
        old = vaultId
        front.mode = DeleteAnswer.LOST
        assertEquals(VaultActionResult.SENT_PENDING, a.vaults.deleteVault(a.row()))
        val w = assertNotNull(a.row().waiting)
        front.mode = DeleteAnswer.PASS
        val r = a.waits().withdrawWaiting(w)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.WAITING_KEPT_MAY_BE_DELETED, r.sentence)
        assertEquals(1, front.posted.size, "nothing more is sent")
        assertTrue(server.stored.none { it.first == vaultId && it.second is LogEntry.Delete })
        val row = a.snapshot.account!!.vaults.single { it.vaultId == vaultId }
        val n = a.snapshot.account!!.waitingNotices.single()
        val engine = listOf(r, drawn(row.waiting), row.deleted, n.line.key, n.line.values, n.kind, n.undo)

        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        assertTrue(f.script.changeWaits("Family", io.silencelen.andvari.core.app.WaitingKind.DELETION))
        assertTrue(f.script.waitingDeletionLooked("Family"))
        val fr = f.waits().withdrawWaiting(assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting))
        val fRow = f.snapshot.account!!.vaults.first { it.name == "Family" }
        val fn = f.snapshot.account!!.waitingNotices.single()
        assertEquals<List<Any?>>(engine, listOf(fr, drawn(fRow.waiting), fRow.deleted, fn.line.key, fn.line.values, fn.kind, fn.undo))
    }

    /**
     * A vault frozen at the read that shows its server contradicting itself (its answer named the person's deletion stored
     * at a place where another entry stands) takes no act and says so in its own words: the waiting change is gone from the
     * row, nothing is sent, no notice says anything of the change, and both acts answer FROZEN. Before the freeze the change
     * the server called stored cannot be withdrawn, with its own line. The stand-in plays the same.
     */
    @Test fun aVaultFrozenAtTheReadTakesNoActOnItsWaitingChangeAndSaysSo() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val vaultId = family(a, server)
        a.vaults.closeMembers()
        old = vaultId
        front.mode = DeleteAnswer.LIE_STORED
        a.vaults.deleteVault(a.row())
        val w = assertNotNull(a.row().waiting)
        assertEquals(io.silencelen.andvari.core.app.WaitingKnown.SERVER_SAYS_STORED, w.known)
        assertFalse(w.canWithdraw)
        val engine = Readings()
        engine += drawn(w)
        engine += a.waits().withdrawWaiting(w)
        front.mode = DeleteAnswer.PASS
        // Another entry at the place the server's answer named: the next complete read freezes the vault.
        otherDeviceChangesRole(a, server, vaultId, carol, io.silencelen.andvari.core.trust.MemberRole.READER, server.instance.now + 1_000)
        a.vault!!.logs.refresh(vaultId, null, null, force = true)
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.status(vaultId))
        a.publish()
        val posted = front.posted.size
        val appended = appends(server)
        val frozen = a.snapshot.account!!.vaults.single { it.vaultId == vaultId }
        engine += listOf(frozen.log, drawn(frozen.waiting), a.waits().withdrawWaiting(w), a.waits().deleteWaitingNow(w), a.snapshot.account!!.waitingNotices.size)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.WAITING_VAULT_FROZEN, io.silencelen.andvari.core.app.WaitingResult.FROZEN.sentence)
        assertEquals(posted, front.posted.size, "nothing is sent")
        assertEquals(appended, appends(server))

        val f = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        assertTrue(f.script.changeWaits("Family", io.silencelen.andvari.core.app.WaitingKind.DELETION, io.silencelen.andvari.core.app.WaitingKnown.SERVER_SAYS_STORED))
        // As the engine after its look: a deletion the server says it has is never asked about (neither "Delete it now"
        // nor "Keep the vault" is offered), and its line promises no act.
        assertTrue(f.script.waitingDeletionLooked("Family"))
        val fw = assertNotNull(f.snapshot.account!!.vaults.first { it.name == "Family" }.waiting)
        val fake = Readings()
        fake += drawn(fw)
        fake += f.waits().withdrawWaiting(fw)
        assertTrue(f.script.waitingVaultFreezes("Family"))
        val fFrozen = f.snapshot.account!!.vaults.first { it.name == "Family" }
        fake += listOf(fFrozen.log, drawn(fFrozen.waiting), f.waits().withdrawWaiting(fw), f.waits().deleteWaitingNow(fw), f.snapshot.account!!.waitingNotices.size)
        assertEquals<List<Any?>>(engine, fake)
    }

    /**
     * A move that stopped on a frozen old vault after its own deletion was sent can be closed by the person's word: the row
     * says what closing does (the new vault's name, the old one's, how many were copied); the close sends nothing, removes
     * this device's record of the move and its mark of a waiting deletion, and leaves the old vault as frozen and read-only as
     * before; a later "Move everything" out of it is the ordinary move, whose source stays. The stand-in plays the same.
     * Before, such a move could never be finished nor put away.
     */
    @Test fun aMoveStoppedOnAFrozenOldVaultIsClosedByThePersonsWordAndSendsNothing() = runBlocking<Unit> {
        var old: String? = null
        val front = DeleteFront { it == old }
        val (server, a) = app(front::wrap)
        open(a)
        val oldId = familyWithItems(a, server, count = 1)
        a.vaults.closeMembers()
        old = oldId
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(a.row()))
        front.mode = DeleteAnswer.LOST
        assertEquals(sentPending, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "Family 2"))
        assertNull(a.oldRow(oldId).frozenMoveClose, "nothing to close while the old vault is not frozen")
        front.mode = DeleteAnswer.PASS
        otherDeviceChangesRole(a, server, oldId, carol, io.silencelen.andvari.core.trust.MemberRole.READER, server.instance.now + 1_000)
        a.vault!!.logs.refresh(oldId, null, null, force = true)
        val log = server.logs.getValue(oldId)
        log.removeAt(log.size - 1)
        otherDeviceChangesRole(a, server, oldId, carol, io.silencelen.andvari.core.trust.MemberRole.READER, server.instance.now + 2_000)
        a.vault!!.logs.refresh(oldId, null, null, force = true)
        assertEquals(VaultActionResult.READ_ONLY, a.vaults.moveEverything(assertNotNull(a.snapshot.account!!.moving), "ignored"))
        a.vaults.closeMoveEverything()
        val row = a.oldRow(oldId)
        val close = assertNotNull(row.frozenMoveClose)
        val posted = front.posted.size
        val appended = appends(server)
        val stored = server.stored.size
        val engine = Readings()
        // {2} is the number the move copied: one item here.
        assertEquals(listOf("Family 2", "Family", "1"), close.values)
        engine += listOf(close.key, close.values.take(2), row.unfinishedMove?.key)
        engine += a.waits().closeFrozenMove(row)
        val after = a.oldRow(oldId)
        engine += listOf(after.log, after.writable, after.unfinishedMove, after.frozenMoveClose, a.snapshot.account!!.unfinishedMoves.any { it.vault.vaultId == oldId })
        assertIs<io.silencelen.andvari.core.client.log.VaultLogStatus.Frozen>(a.vault!!.logs.status(oldId))
        assertFalse(a.vault!!.logs.writeAllowed(oldId))
        assertEquals(posted, front.posted.size, "nothing is sent")
        assertEquals(appended, appends(server))
        assertEquals(stored, server.stored.size, "nothing changes in either vault")
        assertEquals(VaultActionResult.STALE, a.waits().closeFrozenMove(after), "nothing more to close")
        // A later move out of it is the ordinary one: its source stays.
        assertEquals(VaultActionResult.DONE, a.vaults.openMoveEverything(after))
        val next = assertNotNull(a.snapshot.account!!.moving)
        engine += listOf(next.stopped, next.sourceStays)
        a.vaults.closeMoveEverything()

        val (f, fOld) = fakeMove()
        f.script.moveDeleteUnanswered = true
        f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "Family 2")
        f.script.moveDeleteUnanswered = false
        f.script.nextMoveStop = io.silencelen.andvari.core.app.fake.FakeScript.MoveStopAt.OLD_VAULT_FROZEN
        assertEquals(VaultActionResult.READ_ONLY, f.vaults.moveEverything(assertNotNull(f.snapshot.account!!.moving), "ignored"))
        val fCopied = assertNotNull(f.snapshot.account!!.moving?.stopped).copied
        f.vaults.closeMoveEverything()
        val fRow = f.snapshot.account!!.vaults.single { it.vaultId == fOld }
        val fClose = assertNotNull(fRow.frozenMoveClose)
        assertEquals(fCopied.toString(), fClose.values[2], "the number the stand-in's move copied")
        val fake = Readings()
        fake += listOf(fClose.key, fClose.values.take(2), fRow.unfinishedMove?.key)
        fake += f.waits().closeFrozenMove(fRow)
        val fAfter = f.snapshot.account!!.vaults.single { it.vaultId == fOld }
        fake += listOf(fAfter.log, fAfter.writable, fAfter.unfinishedMove, fAfter.frozenMoveClose, f.snapshot.account!!.unfinishedMoves.any { it.vault.vaultId == fOld })
        assertEquals(VaultActionResult.DONE, f.vaults.openMoveEverything(fAfter))
        val fNext = assertNotNull(f.snapshot.account!!.moving)
        fake += listOf(fNext.stopped, fNext.sourceStays)
        assertEquals<List<Any?>>(engine, fake)
    }
}
