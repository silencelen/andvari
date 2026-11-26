package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
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
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One account id held at two addresses on one device (the first server O, and a second O2 that serves the same instance
 * and accounts), and the ends of its session at O: an end of the person's own that a stop interrupted and the next start
 * settles, the tie that decides a confirmed deletion's records kept by the id alone (read once, before anything of the
 * deletion is removed), a sign-out at O, and a deletion that the store stops at each of its writes in turn. In each, what
 * the device holds for the account at O2 stays as it was: its held entry, its copy with changes not sent yet, its
 * records there, and what is kept by the account's id while O2 ties it.
 */
class EngineSameIdEndsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    /** Cache files kept in memory, durable, so changes made offline wait in them; every deletion asked for is recorded. */
    private class Files(val caches: HashMap<String, VaultCache> = HashMap()) : VaultCacheFiles {
        val deleted = ArrayList<String>()
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            return true
        }
    }

    /** The writes of both stores, counted together; [failAt]: the write (from 0, counted from [arm]) that fails once. */
    private class Writes {
        var count = -1
        var failAt = -1
        fun arm(at: Int) { count = 0; failAt = at }
        fun disarm() { count = -1; failAt = -1 }
    }

    /**
     * A device store that fails once: at the [Writes.failAt]-th write since [Writes.arm], or at the next write after the
     * removal of [armAfterRemovalOf].
     */
    private class Store(val inner: MemoryDeviceState, val writes: Writes) : DeviceState {
        var armAfterRemovalOf: String? = null
        private var failNext = false
        override fun get(key: String): String? = inner.get(key)
        override fun keys(): Set<String> = inner.keys()
        override fun set(key: String, value: String?) {
            if (failNext) {
                failNext = false
                throw IllegalStateException("store failed on $key")
            }
            if (writes.count >= 0) {
                val n = writes.count++
                if (n == writes.failAt) {
                    writes.failAt = -1
                    throw IllegalStateException("store failed on write $n: $key")
                }
            }
            inner.set(key, value)
            if (value == null && key == armAfterRemovalOf) {
                armAfterRemovalOf = null
                failNext = true
            }
        }
    }

    /** [instance] with an item plane: the personal vault's row and the items pushed; [down]: no answer to either. */
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

    private class World(val home: FakeInstance, val copy: FakeInstance, val copyWire: ItemServer, val writes: Writes,
                        val state: Store, val secure: Store, val files: Files) {
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

    /** The app stops and starts again over the same stores. */
    private fun restart(w: World) {
        w.app.close()
        w.app = device(w)
    }

    /** The platform lost the kept session's record: the copy stays held, and the app starts again over the same stores. */
    private fun loseSession(w: World) {
        w.app.lock()
        w.app.close()
        w.secure.inner.set(SessionKeeper.KEY, null)
        w.app = device(w)
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    /**
     * Alice's account (and, with [bobAtFirst], Bob's signed out before it) at the first server; at the second, which serves
     * the same instance and account, Alice's copy holds two logins saved while it answered nothing (not sent); the session
     * is kept at the first, both copies held.
     */
    private suspend fun world(bobAtFirst: Boolean): World {
        val home = FakeInstance(crypto)
        val copy = FakeInstance(crypto, origin = "https://copy.example", instanceId = home.instanceId)
        val writes = Writes()
        val w = World(home, copy, ItemServer(copy) { copy.accounts[alice]?.personalWrap?.vaultId }, writes,
            Store(MemoryDeviceState(), writes), Store(MemoryDeviceState(), writes), Files())
        w.app = device(w)
        if (bobAtFirst) {
            register(w.app, "h.example", bob)
            assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        }
        w.u = register(w.app, "h.example", alice)
        copy.accounts[alice] = assertNotNull(home.accounts[alice])
        loseSession(w)
        assertEquals(SignInAnswer.DONE, signInAt(w.app, copy.origin, alice))
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
        // Two changes made at the second address while it answers nothing: they wait in its copy.
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), strong))
        val c = assertNotNull(w.app.content)
        assertEquals(ActionResult.Ok, c.syncQuietly())
        w.copyWire.down = true
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Bank"), null))
        assertEquals(ActionResult.Ok, c.saveLogin(null, login("Shop"), null))
        assertEquals(2, assertNotNull(w.app.vault).queued().pending.size)
        // The second address stays silent from here: what waits in its copy is never sent.
        loseSession(w)
        assertEquals(SignInAnswer.DONE, signInAt(w.app, home.origin, alice))
        val kept = assertNotNull(w.app.keeper.session)
        assertEquals(w.u to home.origin, kept.userId to kept.origin)
        assertTrue(held(w).containsAll(listOf("${home.origin}|${w.u}", "${copy.origin}|${w.u}")), "both copies held: ${held(w)}")
        w.files.deleted.clear()
        return w
    }

    private fun held(w: World): List<String> = w.state.inner.get(EngineAppApi.HELD_KEY).orEmpty().split('\n').filter { it.isNotEmpty() }

    private fun byId(w: World): Map<String, String> = w.state.inner.keys().filter { k ->
        BY_ID.any { p -> k == p + w.u || k.startsWith("${p}${w.u}|") }
    }.sorted().associateWith { w.state.inner.get(it).orEmpty() }

    /** Every record of the second address, by key and value (the held list line by line; the index of servers as a yes). */
    private fun atCopy(w: World): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for ((which, store) in listOf("state" to w.state.inner, "secure" to w.secure.inner)) for (k in store.keys().sorted()) {
            val v = store.get(k) ?: continue
            if (w.copy.origin !in k && w.copy.origin !in v) continue
            if (k == PinStore.KEY_INDEX) out["$which:$k"] = (w.copy.origin in v).toString()
            else if (k != EngineAppApi.HELD_KEY && w.home.origin !in k && w.home.origin !in v) out["$which:$k"] = v
            else v.split('\n').filter { w.copy.origin in it }.forEachIndexed { i, line -> out["$which:$k#line$i"] = line }
        }
        return out
    }

    /** What is kept at the first server that names the account or its address. */
    private fun atHomeNamingAlice(w: World): List<String> = listOf("state" to w.state.inner, "secure" to w.secure.inner).flatMap { (which, store) ->
        store.keys().filter { k -> w.home.origin in k && store.get(k).orEmpty().let { v -> listOf(w.u, alice).any { it in k || it in v } } }.map { "$which:$it" }
    }.sorted()

    private fun copyFile(w: World, origin: String) = ItemCacheNames.fileName(crypto, origin, w.u)

    private suspend fun deleteAtFirst(w: World) {
        w.home.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        w.home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, w.app.settings.openDeletion())
        assertEquals(DeletionResult.DONE, w.app.settings.deleteAccount(assertNotNull(w.app.snapshot.account!!.deletion), alice, strong, null))
    }

    /** The second address's copy, its held entry and its records are as they were; the copy was never deleted. */
    private fun copyAsItWas(w: World, copyBefore: Map<String, String>, label: String) {
        assertEquals(copyBefore, atCopy(w), "$label: every record of the second address")
        assertTrue("${w.copy.origin}|${w.u}" in held(w), "$label: the second address's copy is held")
        assertFalse(copyFile(w, w.copy.origin) in w.files.deleted, "$label: the second address's copy is not deleted: ${w.files.deleted}")
    }

    /** The second address's account signs in, and its copy holds the two changes not sent yet. */
    private suspend fun opensAtCopyWithItsChanges(w: World) {
        assertTrue(w.copyWire.down)
        assertEquals(SignInAnswer.DONE, signInAt(w.app, w.copy.origin, alice))
        assertEquals(w.u to w.copy.origin, assertNotNull(w.app.keeper.session).let { it.userId to it.origin })
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), strong))
        assertEquals(2, assertNotNull(w.app.vault).queued().pending.size, "the two changes not sent still wait")
    }

    // ---- (a) an end of the person's own that a stop interrupted ----

    /**
     * The store stops the deletion right after the keeper forgot the session (its record of the end written, the first
     * server's address record removed) and before the app's own end: the next start settles that end by taking only what
     * the first server held. Before: the settling took the account's copies at every address, the second's among them.
     */
    @Test fun aDeletionStoppedAfterTheKeepersForgettingIsSettledAtTheNextStartAtTheFirstServerOnly() = runBlocking<Unit> {
        val w = world(bobAtFirst = false)
        val copyBefore = atCopy(w)
        w.state.armAfterRemovalOf = SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + alice
        assertIs<IllegalStateException>(runCatching { deleteAtFirst(w) }.exceptionOrNull())
        assertNull(w.app.keeper.session, "the keeper forgot the session")
        assertTrue((w.home.origin to w.u) in w.app.keeper.endedByOwnAct(), "the end is recorded with its server")
        assertTrue("${w.home.origin}|${w.u}" in held(w), "the app's end did not run")
        restart(w)
        assertNull(w.state.inner.get(SessionKeeper.OWN_ENDS_KEY), "the end is settled")
        assertTrue(copyFile(w, w.home.origin) in w.files.deleted, "the first server's copy goes: ${w.files.deleted}")
        assertFalse("${w.home.origin}|${w.u}" in held(w))
        copyAsItWas(w, copyBefore, "after the start")
        opensAtCopyWithItsChanges(w)
    }

    /**
     * A record of an own end in the form earlier builds wrote (its server and account, without the reason) is settled as
     * those builds settled it, as a sign-out, and like every end now only at its server and its former addresses.
     */
    @Test fun anOwnEndRecordedByAnEarlierBuildIsSettledAsASignOutAtItsServerOnly() = runBlocking<Unit> {
        val w = world(bobAtFirst = false)
        val copyBefore = atCopy(w)
        w.app.lock()
        w.app.close()
        w.secure.inner.set(SessionKeeper.KEY, null)
        w.state.inner.set(SessionKeeper.OWN_ENDS_KEY, "${w.home.origin}|${w.u}")
        w.app = device(w)
        assertNull(w.state.inner.get(SessionKeeper.OWN_ENDS_KEY), "the end is settled")
        assertTrue(copyFile(w, w.home.origin) in w.files.deleted, "the first server's copy goes: ${w.files.deleted}")
        copyAsItWas(w, copyBefore, "after the start")
        opensAtCopyWithItsChanges(w)
    }

    // ---- (b) the tie is read once, before anything of the deletion is removed ----

    /** What the second server holds for the deleted account's address, besides the device's row there. */
    private enum class AtTheOther {
        /** Its own account under the address, signed out: the address's record there names that other account. */
        ANOTHER_ACCOUNTS_RECORD,
        /** No address record for the address: only the device's row there (made by that server's own account's sign-ins). */
        NO_ADDRESS_RECORD,
        /** An address record for the address that names the deleted account itself. */
        THE_SAME_ACCOUNTS_RECORD,
    }

    /**
     * The tie that runs through the first server's address record: the second server keeps a record for the same address
     * (the device's row there, and [atTheOther]), and no record there is keyed by the deleted account's id. Read before the
     * keeper removes the first server's address record, on both roads. Where the address's record at the second server
     * names ANOTHER account, the address there is someone else's: no tie, and nothing of the deleted account stays (before:
     * its identity record and the records kept by its id stayed for good). Where the second server holds an address record
     * that names the deleted account, it is a tie: those records stay. Where it holds no address record for it, only the
     * device's row, the records go at the end of the deletion: nothing on the device names the account any more.
     */
    private suspend fun tieThroughTheAddress(bobAtFirst: Boolean, atTheOther: AtTheOther = AtTheOther.ANOTHER_ACCOUNTS_RECORD) {
        val home = FakeInstance(crypto)
        val other = FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val writes = Writes()
        val w = World(home, other, ItemServer(other) { null }.also { it.down = true }, writes, Store(MemoryDeviceState(), writes), Store(MemoryDeviceState(), writes), Files())
        w.app = device(w)
        val atOther = register(w.app, "other.example", alice)
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        if (bobAtFirst) {
            register(w.app, "h.example", bob)
            assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        }
        w.u = register(w.app, "h.example", alice)
        assertNotEquals(atOther, w.u)
        // Nothing at the second server names the deleted account: only its address does.
        assertTrue(w.state.inner.keys().filter { w.copy.origin in it }.none { w.u in it || w.u in w.state.inner.get(it).orEmpty() })
        assertNotNull(w.state.inner.get("ovh.dev|${w.copy.origin}|$alice"))
        val atOtherKey = SessionKeeper.EMAIL_BINDING_PREFIX + w.copy.origin + "|" + alice
        assertEquals(atOther, assertNotNull(w.state.inner.get(atOtherKey)).substringBefore('|'), "the address's record there names its own account")
        when (atTheOther) {
            AtTheOther.ANOTHER_ACCOUNTS_RECORD -> Unit
            AtTheOther.NO_ADDRESS_RECORD -> w.state.inner.set(atOtherKey, null)
            AtTheOther.THE_SAME_ACCOUNTS_RECORD -> w.state.inner.set(atOtherKey,
                assertNotNull(w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + alice)))
        }
        val byIdBefore = byId(w)
        assertTrue(byIdBefore.keys.any { it.startsWith("ovh.identity|") } && byIdBefore.keys.any { it.startsWith("ovh.rmirror|") }, "$byIdBefore")
        deleteAtFirst(w)
        assertEquals(!bobAtFirst, assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten)
        if (atTheOther == AtTheOther.ANOTHER_ACCOUNTS_RECORD) {
            assertEquals(emptyMap(), byId(w), "kept by the id alone, the identity record among it: no tie, so it goes")
        } else if (atTheOther == AtTheOther.NO_ADDRESS_RECORD) {
            // A device's row names an address, not an account: with no address record there nothing on the device says whose
            // row it is (here it is another account's), so it does not make the deleted account known, and the sweep takes it.
            assertEquals(emptyMap(), byId(w), "kept by the id alone, the identity record among it: only a row there, so it goes")
        } else {
            assertEquals(byIdBefore, byId(w), "kept by the id alone, the identity record among it: a tie through the address ($atTheOther)")
        }
        assertEquals(emptyList(), atHomeNamingAlice(w), "everything kept for the account at the first server goes")
        assertTrue("ovh.dev|${w.copy.origin}|$alice" in w.state.inner.keys(), "the second server's row for the address stays")
    }

    @Test fun anAddressRecordAtAnotherServerNamingAnotherAccountIsNoTieWhereNothingElseIsKeptAtTheFirst() = runBlocking<Unit> {
        tieThroughTheAddress(bobAtFirst = false)
    }

    @Test fun anAddressRecordAtAnotherServerNamingAnotherAccountIsNoTieBesideAnotherAccountAtTheFirst() = runBlocking<Unit> {
        tieThroughTheAddress(bobAtFirst = true)
    }

    /**
     * Another server with an address record that names the deleted account is still a tie, and the records kept by the id
     * stay; another server with only a device's row for the address (no address record) keeps nothing of it; on both roads.
     */
    @Test fun anotherServerWithARecordNamingTheSameAccountIsStillATieAndOneWithOnlyARowKeepsNothing() = runBlocking<Unit> {
        for (atTheOther in listOf(AtTheOther.NO_ADDRESS_RECORD, AtTheOther.THE_SAME_ACCOUNTS_RECORD)) for (bobAtFirst in listOf(false, true)) {
            tieThroughTheAddress(bobAtFirst, atTheOther)
        }
    }

    // ---- (c) a sign-out at the first server ----

    /**
     * A sign-out of the account at the first server takes what is held there; the second server's copy stays, with the two
     * changes made in it that were not sent yet. Before: the sign-out deleted the copies at every address it was held at.
     */
    @Test fun aSignOutAtTheFirstServerLeavesTheSecondServersCopyWithItsChangesNotSent() = runBlocking<Unit> {
        val w = world(bobAtFirst = false)
        val copyBefore = atCopy(w)
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        assertNull(w.app.keeper.session)
        assertEquals(listOf(copyFile(w, w.home.origin)), w.files.deleted, "the first server's copy goes, once")
        assertFalse("${w.home.origin}|${w.u}" in held(w))
        copyAsItWas(w, copyBefore, "after the sign-out")
        opensAtCopyWithItsChanges(w)
    }

    // ---- the store failing once at each write of a confirmed deletion, each followed by a start ----

    private fun copyOf(m: MemoryDeviceState): MemoryDeviceState = MemoryDeviceState().also { c -> for (k in m.keys()) c.set(k, m.get(k)) }

    /** A device over a copy of [w]'s stores and files, its session kept at the first server and locked. */
    private fun cloneOf(w: World): World {
        val writes = Writes()
        val c = World(w.home, w.copy, w.copyWire, writes, Store(copyOf(w.state.inner), writes), Store(copyOf(w.secure.inner), writes), Files(HashMap(w.files.caches)))
        c.u = w.u
        c.app = device(c)
        return c
    }

    private suspend fun eachWriteOfADeletion(bobAtFirst: Boolean, road: String) {
        val base = world(bobAtFirst)
        base.app.lock()
        base.app.close()
        val copyBefore = atCopy(base)
        val byIdBefore = byId(base)
        // How many writes a whole deletion makes.
        val dry = cloneOf(base)
        assertEquals(VaultUnlockResult.DONE, dry.app.unlock(assertNotNull(dry.app.snapshot.locked), strong))
        dry.writes.arm(Int.MAX_VALUE)
        deleteAtFirst(dry)
        val total = dry.writes.count
        dry.writes.disarm()
        assertTrue(total > 0)
        val rows = ArrayList<String>()
        for (i in 0 until total) {
            val c = cloneOf(base)
            assertEquals(VaultUnlockResult.DONE, c.app.unlock(assertNotNull(c.app.snapshot.locked), strong))
            c.writes.arm(i)
            val failed = runCatching { deleteAtFirst(c) }.exceptionOrNull()
            c.writes.disarm()
            restart(c)
            val left = atHomeNamingAlice(c)
            rows += "SAMEID-WRITE $road #$i ${failed?.message ?: "no failure"} | kept session=${c.app.keeper.session?.origin} | " +
                "held at O=${"${c.home.origin}|${c.u}" in held(c)} | pin O=${c.app.trust.pinState(c.home.origin)::class.simpleName} | left at O=$left"
            copyAsItWas(c, copyBefore, "$road, the store failed at write $i of $total (${failed?.message})")
            // What is kept by the id alone, while the second address ties the account, is as it was too.
            assertEquals(byIdBefore.filterKeys { it.startsWith("ovh.identity|") || it.startsWith("ovh.acct|") || it.startsWith("ovh.rmirror|") }.keys,
                byId(c).keys.filter { it.startsWith("ovh.identity|") || it.startsWith("ovh.acct|") || it.startsWith("ovh.rmirror|") }.toSet(),
                "$road, write $i: kept by the id alone")
            c.app.close()
        }
        rows.forEach { println(it) }
        println("SAMEID-WRITE $road: $total writes")
    }

    @Test fun aDeletionTheStoreStopsAtEachOfItsWritesInTurnLeavesTheSecondAddressAsItWasWhereNothingElseIsKeptAtTheFirst() = runBlocking<Unit> {
        eachWriteOfADeletion(bobAtFirst = false, road = "road-b")
    }

    @Test fun aDeletionTheStoreStopsAtEachOfItsWritesInTurnLeavesTheSecondAddressAsItWasBesideAnotherAccountAtTheFirst() = runBlocking<Unit> {
        eachWriteOfADeletion(bobAtFirst = true, road = "road-a")
    }

    private companion object {
        val BY_ID = listOf("ovh.acct|", "ovh.log|", "ovh.items|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.identity|")
    }
}
