package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.KeyCopy
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KeyEscapeException
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
import io.silencelen.andvari.core.model.wire.VaultMetaPut
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.tripwire.ZeroKeyTripwire
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/**
 * On the app engine and its content (the screens' model): a shared
 * vault is named with each text form of its own key; the content lists it, syncs, publishes, and after a lock and an
 * unlock lists and syncs it again, like any other vault. Before the fix every step after the rename threw
 * `KeyEscapeException` (the content listed no vault after the unlock and never synced again). The name is sealed here
 * by the owner's own rename on this device; that it arrives from another account is `KeyTextIsDataTest` in the
 * hostile-server bench, on the real server. A shipped build is played with [ZeroKeyTripwire.asShipped].
 */
class KeyTextIsDataContentTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** The vault routes over [FakeInstance], as `EngineSharedVaultsTest` serves them, plus the owner's rename. */
    private inner class VaultServer(val instance: FakeInstance) {
        val logs = LinkedHashMap<String, MutableList<String>>()
        val meta = HashMap<String, String>()
        val grants = HashMap<Pair<String, String>, SyncGrant>()
        var rev = 1L

        private fun head(log: List<String>) = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(log.last())))

        fun client(caller: () -> String?): WireClient = object : WireClient {
            override val origin: String = instance.origin
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
                        val full = query?.removePrefix("since=")?.toLongOrNull() == 0L
                        ok(WireJson.json.encodeToString(SyncResponse.serializer(), SyncResponse(rev++, full, vaults, mine, emptyList(), emptyList(), emptyList(), 0, 0)))
                    }
                    WireRoute.LOG_FETCH -> {
                        val log = logs[pathParams.getValue("vaultId")] ?: return WireResult.Refused(403, WireError("no_grant", "m"))
                        val from = ((query?.removePrefix("after=")?.toLong() ?: -1) + 1).toInt()
                        val page = if (from < log.size) log.subList(from, log.size).toList() else emptyList()
                        ok(WireJson.json.encodeToString(LogPage.serializer(), LogPage(page, LogHead(log.size - 1L, head(log), 0))))
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
                        ok(WireJson.json.encodeToString(LogAppendResponse.serializer(), LogAppendResponse(rev++, LogHead(log.size - 1L, head(log), 0), null)))
                    }
                    WireRoute.VAULT_SELF_WRAP -> {
                        val vaultId = pathParams.getValue("vaultId")
                        val w = WireJson.json.decodeFromString(SelfWrapPut.serializer(), bodyJson!!)
                        grants[vaultId to user!!] = grants.getValue(vaultId to user).copy(wrappedVk = w.wrappedVk)
                        ok("{\"rev\":${rev++}}")
                    }
                    WireRoute.VAULT_META -> {
                        val vaultId = pathParams.getValue("vaultId")
                        meta[vaultId] = WireJson.json.decodeFromString(VaultMetaPut.serializer(), bodyJson!!).metaBlob
                        ok("{\"rev\":${rev++}}")
                    }
                    WireRoute.PUSH -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                    else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
                }
            }
        }
    }

    private fun app(): Pair<VaultServer, EngineAppApi> {
        val instance = FakeInstance(crypto)
        val server = VaultServer(instance)
        var self: EngineAppApi? = null
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(instance.origin to server.client { self?.keeper?.session?.userId })),
                MemoryDeviceState(), MemoryDeviceState(), crypto, { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
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

    private fun forms(vk: ByteArray): List<String> = listOf(
        Bytes.toHexLower(vk),
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(vk),
        java.util.Base64.getEncoder().encodeToString(vk),
    )

    /** The shared vault's name as the content lists it, and as the account's vault list does. */
    private fun names(a: EngineAppApi, vaultId: String): Pair<String?, String?> =
        a.content?.state?.vaults?.firstOrNull { it.vaultId == vaultId }?.name to a.snapshot.account?.vaults?.firstOrNull { it.vaultId == vaultId }?.name

    @Test fun aVaultNamedWithItsKeysTextIsListedSyncedAndUnlockedLikeAnyOtherAsShipped() = runBlocking<Unit> {
        ZeroKeyTripwire.asShipped {
            val (server, a) = app()
            open(a)
            assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
            val v = server.logs.keys.single()
            assertEquals(ActionResult.Ok, assertNotNull(a.content).refresh(), "the sync before")
            assertEquals("Family" to "Family", names(a, v))
            val vk = assertNotNull(a.vault!!.logs.withKey(v) { KeyCopy(it.copyOf()) }).bytes
            for (f in forms(vk)) {
                val content = assertNotNull(a.content)
                assertEquals(ActionResult.Ok, content.renameSharedVault(v, f), "rename to $f")
                assertEquals(ActionResult.Ok, content.refresh(), "a sync with the vault named $f")
                assertEquals(ActionResult.Ok, content.syncQuietly(), "a quiet sync, which publishes in its finally")
                assertEquals(f to f, names(a, v), "listed under $f")
            }
            val last = forms(vk).last()
            a.lock()
            assertEquals(VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
            assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
            assertEquals(ActionResult.Ok, assertNotNull(a.content).refresh(), "the sync after the unlock")
            assertEquals(last to last, names(a, v), "after the lock and the unlock")
            vk.fill(0)
        }
    }

    /** Checked (every test's default), the same name still trips the development net: the reason the test above asks for "as shipped". */
    @Test fun checkedTheSameNameTripsTheNet() = runBlocking<Unit> {
        val (server, a) = app()
        open(a)
        assertEquals(VaultActionResult.DONE, a.vaults.createVault("Family"))
        val v = server.logs.keys.single()
        val vk = assertNotNull(a.vault!!.logs.withKey(v) { KeyCopy(it.copyOf()) }).bytes
        ZeroKeyTripwire.asShipped { assertEquals(ActionResult.Ok, assertNotNull(a.content).renameSharedVault(v, forms(vk).first())) }
        assertFailsWith<KeyEscapeException> { assertNotNull(a.content).refresh() }
        vk.fill(0)
    }
}
