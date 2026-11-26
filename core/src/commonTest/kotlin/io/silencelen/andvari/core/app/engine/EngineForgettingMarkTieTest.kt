package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.ItemCacheNames
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.model.wire.MutationResult
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.PushResponse
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The forgetting of an earlier account, cut at each of its writes and finished at the next start, ends exactly as the
 * forgetting that was not cut: what is kept by the account's id alone, and whether the second server's copy is deleted.
 * The account is held at two addresses of one server (h.example and copy.example), with two changes not sent at the
 * second. The tie at the second address is read once, before anything is removed, and kept with the forgetting's mark:
 * where it runs only through the first server's address record (the second holds a copy of the account and a device's
 * row for the address, but no address record of its own), a finish that read it again after that record had gone lost it
 * and removed the records kept by the account's id. A mark an earlier build wrote, without the tie, is read afresh.
 */
class EngineForgettingMarkTieTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    private class Files(val caches: HashMap<String, VaultCache> = HashMap()) : VaultCacheFiles {
        val deleted = ArrayList<String>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            caches.remove(fileName)
            return true
        }
    }

    /** A store that fails once, [failInWrites] writes from now (0: the next write); -1: never. */
    private class Store(val inner: MemoryDeviceState) : DeviceState {
        var failInWrites = -1
        var failedOn: String? = null
        override fun get(key: String): String? = inner.get(key)
        override fun keys(): Set<String> = inner.keys()
        override fun set(key: String, value: String?) {
            if (failInWrites == 0) {
                failInWrites = -1
                failedOn = key
                throw IllegalStateException("store failed on $key")
            }
            if (failInWrites > 0) failInWrites--
            inner.set(key, value)
        }
    }

    private class ItemServer(val instance: FakeInstance, private val vaultOf: () -> String?) : WireClient {
        override val origin: String get() = instance.origin
        var down = false
        var rev = 1L
        val items = ArrayList<SyncItem>()

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            when (route) {
                WireRoute.SYNC -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val since = query?.substringAfter("since=")?.toLongOrNull() ?: 0L
                    val vaults = vaultOf()?.let { listOf(SyncVault(it, "personal", 1, "", instance.now)) }.orEmpty()
                    val r = SyncResponse(rev, since == 0L, vaults, emptyList(), items.filter { it.rev > since }, emptyList(), emptyList(), 0, 0)
                    WireResult.Ok(decode(WireJson.json.encodeToString(SyncResponse.serializer(), r)), 200)
                }
                WireRoute.PUSH -> if (down) WireResult.NoAnswer(NoAnswerKind.TRANSPORT) else {
                    val b = WireJson.json.decodeFromString(PushRequest.serializer(), bodyJson!!)
                    val results = b.mutations.map { m ->
                        rev++
                        items.removeAll { it.itemId == m.itemId }
                        val up = m.item
                        items += SyncItem(m.itemId, m.vaultId, rev, instance.now, instance.now, m.op == MutationOp.DELETE, false,
                            up?.formatVersion ?: 1, up?.attachmentIds.orEmpty(), up?.blob)
                        MutationResult(m.mutationId, MutationStatus.APPLIED, rev)
                    }
                    WireResult.Ok(decode(WireJson.json.encodeToString(PushResponse.serializer(), PushResponse(rev, results))), 200)
                }
                else -> instance.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
    }

    private class World(val home: FakeInstance, val copy: FakeInstance, val copyWire: ItemServer, val state: Store, val secure: Store, val files: Files) {
        lateinit var app: EngineAppApi
        lateinit var u: String
    }

    private fun device(w: World): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(w.home.origin to w.home, w.copy.origin to w.copyWire)), w.state, w.secure,
            crypto, { w.home.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined,
            work = Dispatchers.Unconfined, cacheFiles = w.files, keepsAtRest = { true }),
    ).also { it.start() }

    private fun otherDevice(server: FakeInstance): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(),
            crypto, { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun register(a: EngineAppApi, address: String, email: String): String {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), address))
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
        return assertNotNull(a.keeper.session).userId
    }

    private suspend fun signInAt(a: EngineAppApi, origin: String, email: String): SignInAnswer {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
        if (a.snapshot.entry !is EntryScreen.SignIn) {
            a.entry.openSignIn(a.at())
            a.entry.openPasswordSignIn(a.at())
            assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), origin))
            (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        }
        return a.entry.submitSignIn(a.at(), email, strong)
    }

    private fun restart(w: World) {
        w.app.close()
        w.app = device(w)
    }

    private fun loseSession(w: World) {
        w.app.lock()
        w.app.close()
        w.secure.inner.set(SessionKeeper.KEY, null)
        w.app = device(w)
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    private fun held(w: World): List<String> = w.state.inner.get(EngineAppApi.HELD_KEY).orEmpty().split('\n').filter { it.isNotEmpty() }

    /** The keys of what is kept by [w]'s account id alone, with the id written as `U` (two worlds compare). */
    private fun byId(w: World): Set<String> = w.state.inner.keys().filter { k ->
        BY_ID.any { p -> k == p + w.u || k.startsWith("${p}${w.u}|") }
    }.map { it.replace(w.u, "U") }.toSet()

    private fun copyFile(w: World, origin: String) = ItemCacheNames.fileName(crypto, origin, w.u)

    /** Account u at h.example and at copy.example (the same server's two addresses), two changes not sent at copy.example. */
    private suspend fun twoAddresses(): World {
        val home = FakeInstance(crypto)
        val copy = FakeInstance(crypto, origin = "https://copy.example", instanceId = home.instanceId)
        val w = World(home, copy, ItemServer(copy) { copy.accounts[alice]?.personalWrap?.vaultId }, Store(MemoryDeviceState()), Store(MemoryDeviceState()), Files())
        w.app = device(w)
        w.u = register(w.app, "h.example", alice)
        copy.accounts[alice] = assertNotNull(home.accounts[alice])
        loseSession(w)
        assertEquals(SignInAnswer.DONE, signInAt(w.app, copy.origin, alice))
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), strong))
        val c = assertNotNull(w.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        w.copyWire.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Shop"), null))
        assertEquals(2, assertNotNull(w.app.vault).queued().pending.size)
        loseSession(w)
        assertEquals(SignInAnswer.DONE, signInAt(w.app, home.origin, alice))
        assertTrue(held(w).containsAll(listOf("${home.origin}|${w.u}", "${copy.origin}|${w.u}")))
        w.files.deleted.clear()
        return w
    }

    /**
     * [twoAddresses], then the account at h.example made again elsewhere, so the sign-in there meets the earlier account and
     * offers to forget it. [dropCopyAddressRecord]: copy.example's own address record is removed, so the only tie there is
     * its device's row for the address, through h.example's address record.
     */
    private suspend fun offered(dropCopyAddressRecord: Boolean): World {
        val w = twoAddresses()
        loseSession(w)
        if (dropCopyAddressRecord) w.state.inner.set(SessionKeeper.EMAIL_BINDING_PREFIX + w.copy.origin + "|" + alice, null)
        w.home.accounts.remove(alice)
        register(otherDevice(w.home), "h.example", alice)
        assertEquals(SignInAnswer.IDENTITY_FAULT, signInAt(w.app, w.home.origin, alice))
        return w
    }

    private suspend fun forgetEarlierNow(w: World): Result<ForgetEarlierResult> = runCatching {
        val offer = assertNotNull(w.app.snapshot.earlierAccount)
        assertTrue(w.app.entry.askToForgetEarlierAccount(offer))
        val confirm = assertNotNull(w.app.snapshot.earlierAccount)
        w.app.entry.forgetEarlierAccount(confirm)
    }

    /**
     * The forgetting uncut, then cut at each of its writes in turn and finished at a start, compared. [asAnEarlierBuild]: the
     * mark left by the cut is rewritten as an earlier build wrote it (without the tie it read) before the start.
     */
    private fun cutAtEachWrite(dropCopyAddressRecord: Boolean, asAnEarlierBuild: Boolean = false) = runBlocking<Unit> {
        val ref = offered(dropCopyAddressRecord)
        assertTrue(PinStore.tiedElsewhere(ref.state, ref.u, ref.home.origin), "copy.example ties the account before the forgetting")
        assertEquals(ForgetEarlierResult.FORGOTTEN, forgetEarlierNow(ref).getOrThrow())
        restart(ref)
        val refById = byId(ref)
        val refCopyGone = copyFile(ref, ref.copy.origin) in ref.files.deleted
        assertTrue(refById.isNotEmpty(), "the uncut forgetting keeps what copy.example's tie keeps: $refById")
        assertEquals(false, refCopyGone, "the uncut forgetting does not delete copy.example's copy")
        val bad = ArrayList<String>()
        var marksRewritten = 0
        var n = 0
        var finished = 0
        while (n < 60) {
            val w = offered(dropCopyAddressRecord)
            val before = byId(w)
            w.state.failInWrites = n
            forgetEarlierNow(w)
            val failedOn = w.state.failedOn
            w.state.failInWrites = -1
            if (failedOn == null) break
            if (asAnEarlierBuild) w.state.inner.get(EngineAppApi.FORGETTING_KEY)?.let { text ->
                val old = asEarlierBuildsMark(text)
                if (old != text) marksRewritten++
                w.state.inner.set(EngineAppApi.FORGETTING_KEY, old)
            }
            restart(w)
            // A cut before the keeper removed its record of the address forgot nothing: everything stays as it was. Every
            // later cut is finished at the start, and ends as the uncut forgetting.
            val forgotten = w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + alice)?.substringBefore('|') != w.u
            if (forgotten) finished++
            val ids = byId(w)
            val copyGone = copyFile(w, w.copy.origin) in w.files.deleted
            if (ids != (if (forgotten) refById else before) || copyGone != refCopyGone) bad += "#$n $failedOn (forgotten=$forgotten): byId=$ids copyDeleted=$copyGone"
            n++
        }
        assertTrue(finished > 3, "more than three cuts fall after the keeper's record of the address went: $finished of $n")
        if (asAnEarlierBuild) assertTrue(marksRewritten > 0, "some cut leaves a mark with the tie in it")
        assertEquals(emptyList(), bad, "a forgetting cut at a write and finished at a start ends as the uncut one")
    }

    /** [text] (the forgettings' marks) as an earlier build wrote them: each mark without its tie. */
    private fun asEarlierBuildsMark(text: String): String {
        val all = WireJson.json.parseToJsonElement(text) as kotlinx.serialization.json.JsonArray
        return kotlinx.serialization.json.JsonArray(all.map { e ->
            kotlinx.serialization.json.JsonArray((e as kotlinx.serialization.json.JsonArray).filterNot {
                (it as kotlinx.serialization.json.JsonPrimitive).content.startsWith("tie:")
            })
        }).toString()
    }

    @Test fun aForgettingCutAtEachWriteEndsAsTheUncutOneWhereTheOnlyTieRunsThroughTheFirstServersAddressRecord() =
        cutAtEachWrite(dropCopyAddressRecord = true)

    @Test fun aForgettingCutAtEachWriteEndsAsTheUncutOneWithTheSecondServersOwnAddressRecord() =
        cutAtEachWrite(dropCopyAddressRecord = false)

    @Test fun aMarkAnEarlierBuildWroteWithoutTheTieIsFinishedByReadingTheTieAfresh() =
        cutAtEachWrite(dropCopyAddressRecord = false, asAnEarlierBuild = true)

    private companion object {
        val BY_ID = listOf("ovh.acct|", "ovh.log|", "ovh.items|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.identity|")
    }
}
