package io.silencelen.andvari.core.app.engine

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
import io.silencelen.andvari.core.client.MemoryDeviceState
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
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A shared vault whose deletion stands in its verified log (it can still be restored for a time) is read-only on the
 * device: the server ended every grant with the deletion and refuses a write into it. Over the real engine and a server
 * that stores each vault's log and the items pushed, and refuses (`denied`) a change into a vault whose log ends in a
 * deletion.
 */
class EngineDeletedVaultWritesTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private inner class Server(val instance: FakeInstance) {
        val logs = LinkedHashMap<String, MutableList<String>>()
        val meta = HashMap<String, String>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        val items = LinkedHashMap<String, SyncItem>()
        var rev = 1L

        /** Every change pushed, as (vault, op, answer). */
        val pushed = ArrayList<Triple<String, String, String>>()

        private fun head(log: List<String>) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last())))

        fun deleted(vaultId: String): Boolean =
            logs[vaultId]?.lastOrNull()?.let { VaultLog.parse(crypto, Bytes.fromB64(it)).valueOrNull()?.entry is LogEntry.Delete } == true

        fun client(caller: () -> String?): WireClient = object : WireClient by instance {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                val user = caller()
                fun ok(text: String): WireResult<T> = WireResult.Ok(decode(text), 200)
                return when (route) {
                    WireRoute.SYNC -> {
                        val mine = grants.values.filter { it.userId == user }
                        val vaults = mine.mapNotNull { g ->
                            val log = logs[g.vaultId] ?: return@mapNotNull null
                            SyncVault(g.vaultId, "shared", rev, meta[g.vaultId].orEmpty(), 0, SyncLogHead(log.size - 1L, head(log)))
                        }
                        val pv = instance.accounts.values.lastOrNull()?.personalWrap?.vaultId
                        // Never a full snapshot (this fixture lists no personal grant, which a full one would need).
                        val full = false
                        val served = items.values.filter { i -> i.vaultId == pv || mine.any { it.vaultId == i.vaultId } }
                        val all = vaults + listOfNotNull(pv?.let { SyncVault(it, "personal", 1, "", instance.now) })
                        ok(WireJson.json.encodeToString(SyncResponse.serializer(), SyncResponse(rev++, full, all, mine, served, emptyList(), emptyList(), 0, 0)))
                    }
                    WireRoute.PUSH -> {
                        val req = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                        val results = req.mutations.map { m ->
                            // The deletion ended every grant: a change into the vault is refused.
                            if (deleted(m.vaultId)) {
                                pushed += Triple(m.vaultId, m.op, "denied")
                                return@map MutationResult(m.mutationId, "denied")
                            }
                            val r = rev++
                            val body = m.item
                            items[m.itemId] = SyncItem(m.itemId, m.vaultId, r, instance.now, instance.now, m.op == "delete", false,
                                body?.formatVersion ?: 1, body?.attachmentIds ?: emptyList(), body?.blob)
                            pushed += Triple(m.vaultId, m.op, "applied")
                            MutationResult(m.mutationId, "applied", newItemRev = r)
                        }
                        ok(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results)))
                    }
                    WireRoute.LOG_FETCH -> {
                        val log = logs[pathParams.getValue("vaultId")] ?: return WireResult.Refused(403, WireError("no_grant", "m"))
                        val from = ((query?.removePrefix("after=")?.toLong() ?: -1) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        ok(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, LogHead(log.size - 1L, head(log), 0))))
                    }
                    WireRoute.VAULT_MEMBERS -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val rows = grants.keys.filter { it.first == vaultId }.map { (_, u) ->
                            VaultMemberSummary(u, "$u@example.com", "", grants.getValue(vaultId to u).role, Bytes.toB64(ByteArray(32)), 0)
                        }
                        ok(WireJson.json.encodeToString(kotlinx.serialization.builtins.ListSerializer(VaultMemberSummary.serializer()), rows))
                    }
                    WireRoute.LOG_APPEND -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val log = logs.getOrPut(vaultId) { ArrayList() }
                        val req = WireJson.json.decodeFromString(LogAppendRequest.serializer(), bodyJson!!)
                        if (req.entry !in log) {
                            val frame = Bytes.fromB64(req.entry)
                            val prior = if (log.isEmpty()) null else VaultLog.replay(crypto, vaultId, log.map { Bytes.fromB64(it) }, from = null, known = KnownHashes.NONE_HELD).state
                            if (VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD) !is io.silencelen.andvari.core.trust.Checked.Ok) {
                                return WireResult.Refused(400, WireError("bad_entry", "m"))
                            }
                            log += req.entry
                            val entry = VaultLog.parse(crypto, frame).valueOrNull()?.entry
                            if (entry is LogEntry.Genesis) grants[vaultId to user!!] = SyncGrant(vaultId, user, "owner", req.wrappedVk!!, rev)
                            req.metaBlob?.let { meta[vaultId] = it }
                        }
                        ok(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(rev++, LogHead(log.size - 1L, head(log), 0))))
                    }
                    WireRoute.VAULT_SELF_WRAP -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                        grants[vaultId to user!!] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk)
                        ok("{\"rev\":${rev++}}")
                    }
                    WireRoute.VAULTS_DELETED -> ok("[]")
                    WireRoute.VAULT_META -> WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
                    else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
    }

    private fun app(): Pair<Server, EngineAppApi> {
        val server = Server(FakeInstance(crypto))
        var self: EngineAppApi? = null
        val client = server.client { self?.keeper?.session?.userId }
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to client)), MemoryDeviceState(), MemoryDeviceState(),
                crypto, { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return server to app
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

    private class Family(val vaultId: String, val inside: String, val mine: String)

    /** Signed up; a shared vault "Family" with one login in it and one login in the personal vault; then the vault deleted. */
    private suspend fun deletedFamily(a: EngineAppApi, server: Server, syncAfter: Boolean): Family {
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val vaultId = server.logs.keys.single()
        val c = assertNotNull(a.content)
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("inside"), vaultId))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("mine"), null))
        val inside = c.state.items.single { it.name == "inside" }.itemId
        val mine = c.state.items.single { it.name == "mine" }.itemId
        assertEquals(VaultActionResult.DONE, a.vaults.deleteVault(a.snapshot.account!!.vaults.single()))
        assertTrue(server.deleted(vaultId))
        if (syncAfter) assertEquals(ActionResult.Ok, c.syncQuietly())
        server.pushed.clear()
        return Family(vaultId, inside, mine)
    }

    /**
     * A save, an edit, a deletion of an item and a move of an item INTO a deleted vault, before and after the device's
     * next sync: each is refused on the device with the line of its own, nothing is queued and nothing reaches the
     * server. Before, nothing was queued either, but the person read "You can't add items to that vault." for a save or
     * a move, and "This item is no longer here." for an edit or a deletion of an item that was still on the screen. What
     * is read from the vault stays: its items are held, readable.
     */
    @Test fun eachWriteIntoADeletedVaultIsRefusedBeforeAnythingIsQueuedWithALineOfItsOwn() = runBlocking<Unit> {
        for (syncAfter in listOf(false, true)) {
            val (server, a) = app()
            val f = deletedFamily(a, server, syncAfter)
            val c = assertNotNull(a.content)
            val refused = ActionResult.Failed(io.silencelen.andvari.core.app.content.ContentCopy.VAULT_DELETED_READ_ONLY)
            val said = linkedMapOf(
                "save" to c.saveLogin(null, login("new"), f.vaultId),
                "edit" to c.saveLogin(f.inside, login("inside2"), f.vaultId),
                "delete" to c.deleteItem(f.inside),
                "move in" to c.moveOrCopyItem(f.mine, f.vaultId, move = true),
                "copy in" to c.moveOrCopyItem(f.mine, f.vaultId, move = false),
            )
            for ((what, r) in said) assertEquals(refused, r, "$what (sync after the deletion: $syncAfter)")
            assertTrue(a.vault!!.items.pendingSyncItemIds().isEmpty(), "nothing queued")
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertTrue(server.pushed.isEmpty(), "nothing sent: ${server.pushed}")
            assertTrue(c.vaultsForNewItems().none { it.vaultId == f.vaultId }, "not offered for a new item")
            val held = c.state.held.single { it.vaultId == f.vaultId }
            assertTrue(held.readable, "its items are still read")
            assertEquals(listOf("inside"), c.heldItems(f.vaultId).map { it.name }, "the item is still there, unchanged")
            assertTrue(c.state.items.any { it.itemId == f.mine }, "the item that was to move in stays where it was")
        }
    }

    /** A restore of the vault makes it writable again at once: a save into it and an edit of its item are made. */
    @Test fun aRestoreMakesTheDeletedVaultWritableAgainAtOnce() = runBlocking<Unit> {
        val (server, a) = app()
        val f = deletedFamily(a, server, syncAfter = true)
        val c = assertNotNull(a.content)
        assertEquals(VaultActionResult.DONE, a.vaults.restoreVault(a.snapshot.account!!.vaults.single()))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("new"), f.vaultId))
        assertEquals(ActionResult.Ok, c.saveLogin(f.inside, login("inside2"), f.vaultId))
        assertEquals(listOf("applied", "applied"), server.pushed.filter { it.first == f.vaultId }.map { it.third }, "${server.pushed}")
    }
}
