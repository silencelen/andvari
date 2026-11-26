package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
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
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
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
 * One account id held at two addresses on one device: the first server (O) and a second (O2) that serves a copy of the
 * first's accounts, so the same user id signs in at both. Each address has its own copy held here and its own address
 * record naming the account. A deletion that O confirms is O's word about O alone: what is kept by the account's id alone
 * (its state copy and marks, its vault logs, its recovery mirror, its escrow mark, the item engine's records, its identity
 * record) stays while anything at O2 ties the account (`PinStore.tiedElsewhere`), and nothing kept for the account at O2
 * goes (its entry in the held list, its copy, its per-server records, its name). Everything kept for it at O goes, as
 * before, on both roads of a confirmed deletion: where something of another account is kept at O (the server stays
 * known) and where nothing is (the server is forgotten). The forgetting of an earlier account is established here, not
 * changed: it removes that account from this device without condition.
 */
class EngineSameIdTwoAddressesTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    /** Cache files kept in memory per name, so a copy opens again; every deletion asked for is recorded (nothing is removed). */
    private class Files : VaultCacheFiles {
        val deleted = ArrayList<String>()
        private val caches = HashMap<String, VaultCache>()
        override fun open(fileName: String, userId: String): VaultCache = caches.getOrPut(fileName) { InMemoryVaultCache() }
        override fun delete(fileName: String): Boolean {
            deleted += fileName
            return true
        }
    }

    /**
     * The device state, which can be made to answer that it cannot list its keys ([unlisted]: `keys()` is null), to throw at
     * the read of chosen keys ([unreadable]), and to fail once at the removal of a key starting with [failAt].
     */
    private class Store(val inner: MemoryDeviceState) : DeviceState {
        var unlisted = false
        val unreadable = HashSet<String>()
        var failAt: String? = null
        override fun get(key: String): String? {
            if (key in unreadable) throw IllegalStateException("cannot read $key")
            return inner.get(key)
        }
        override fun keys(): Set<String>? = if (unlisted) null else inner.keys()
        override fun set(key: String, value: String?) {
            val f = failAt
            if (f != null && value == null && key.startsWith(f)) {
                failAt = null
                throw IllegalStateException("store failed on $key")
            }
            inner.set(key, value)
        }
    }

    private class World(val home: FakeInstance, val copy: FakeInstance, val state: Store, val secure: MemoryDeviceState, val files: Files) {
        lateinit var app: EngineAppApi
        lateinit var u: String
    }

    private fun device(w: World): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(w.home.origin to w.home, w.copy.origin to w.copy)), w.state, w.secure,
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

    private suspend fun signInAt(a: EngineAppApi, server: FakeInstance, email: String): SignInAnswer {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
        if (a.snapshot.entry !is EntryScreen.SignIn) {
            a.entry.openSignIn(a.at())
            a.entry.openPasswordSignIn(a.at())
            assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.origin))
            (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        }
        return a.entry.submitSignIn(a.at(), email, strong)
    }

    /** The platform lost the kept session's record: the copy stays held, and the app starts again over the same stores. */
    private fun loseSession(w: World) {
        w.app.lock()
        w.app.close()
        w.secure.set(SessionKeeper.KEY, null)
        w.app = device(w)
    }

    /**
     * Alice's account (and, with [bobAtFirst], Bob's account signed out before it, so something of another account is
     * kept at the first server), held at the first server and, with [atCopy], at the second, which serves the same
     * account: the session is kept at the first, both copies held.
     */
    private suspend fun world(bobAtFirst: Boolean, atCopy: Boolean = true): World {
        val home = FakeInstance(crypto)
        // The same instance served at a second address (an account's keys are bound to the instance it was made at).
        val copy = FakeInstance(crypto, origin = "https://copy.example", instanceId = home.instanceId)
        val w = World(home, copy, Store(MemoryDeviceState()), MemoryDeviceState(), Files())
        w.app = device(w)
        if (bobAtFirst) {
            register(w.app, "h.example", bob)
            assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        }
        w.u = register(w.app, "h.example", alice)
        if (atCopy) {
            copy.accounts[alice] = assertNotNull(home.accounts[alice])
            loseSession(w)
            assertEquals(SignInAnswer.DONE, signInAt(w.app, copy, alice))
            assertEquals(w.u, assertNotNull(w.app.keeper.session).userId, "the same account id at the second address")
            loseSession(w)
            assertEquals(SignInAnswer.DONE, signInAt(w.app, home, alice))
            val kept = assertNotNull(w.app.keeper.session)
            assertEquals(w.u to home.origin, kept.userId to kept.origin)
            assertTrue(held(w).containsAll(listOf("${home.origin}|${w.u}", "${copy.origin}|${w.u}")), "both copies held: ${held(w)}")
            // The name the account goes by at the second address, as a registration there keeps it (a sign-in keeps none).
            w.state.inner.set("${EngineAppApi.NAME_KEY}${copy.origin}|${w.u}", "Alice")
        }
        return w
    }

    private fun held(w: World): List<String> = w.state.inner.get(EngineAppApi.HELD_KEY).orEmpty().split('\n').filter { it.isNotEmpty() }

    /** The records kept by the account's id alone, with their values. */
    private fun byId(w: World): Map<String, String> = w.state.inner.keys().filter { k ->
        BY_ID.any { p -> k == p + w.u || k.startsWith("${p}${w.u}|") }
    }.sorted().associateWith { w.state.inner.get(it).orEmpty() }

    /**
     * Every record of the second address, by key and value: whatever names its origin (a shared list such as the held one is
     * read line by line; the index of known servers only for whether it names the second).
     */
    private fun atCopy(w: World): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for ((which, store) in listOf("state" to w.state.inner, "secure" to w.secure)) for (k in store.keys().sorted()) {
            val v = store.get(k) ?: continue
            if (w.copy.origin !in k && w.copy.origin !in v) continue
            if (k == PinStore.KEY_INDEX) out["$which:$k"] = (w.copy.origin in v).toString()
            else if (k != EngineAppApi.HELD_KEY && w.home.origin !in k && w.home.origin !in v) out["$which:$k"] = v
            else v.split('\n').filter { w.copy.origin in it }.forEachIndexed { i, line -> out["$which:$k#line$i"] = line }
        }
        return out
    }

    /** What is kept at the first server that names the account (its id in the key or the value) or its address. */
    private fun atHomeNamingAlice(w: World): List<String> = listOf("state" to w.state.inner, "secure" to w.secure).flatMap { (which, store) ->
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

    /** One line for the report of what a step left: by id, and of the account at the second address. */
    private fun probe(label: String, w: World) {
        println("SAMEID $label: byId=${byId(w).keys} heldAtCopy=${"${w.copy.origin}|${w.u}" in held(w)} " +
            "copyFileDeleted=${copyFile(w, w.copy.origin) in w.files.deleted} name=${w.state.inner.get("${EngineAppApi.NAME_KEY}${w.copy.origin}|${w.u}")} " +
            "copyKeys=${atCopy(w).keys} homeNamingAlice=${atHomeNamingAlice(w)}")
    }

    /** The second address's account signs in by its password and its copy opens again by its own unlock. */
    private suspend fun opensAtCopy(w: World) {
        assertEquals(SignInAnswer.DONE, signInAt(w.app, w.copy, alice))
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
        assertEquals(w.u to w.copy.origin, assertNotNull(w.app.keeper.session).let { it.userId to it.origin })
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), strong))
    }

    /** After a deletion O confirmed, with the second address tying the account: what the second relies on is as it was. */
    private suspend fun secondAsItWas(w: World, byIdBefore: Map<String, String>, copyBefore: Map<String, String>, label: String) {
        probe(label, w)
        assertEquals(byIdBefore, byId(w), "what is kept by the id alone stays, marks and identity record among it")
        assertEquals(copyBefore, atCopy(w), "every record of the second address stays")
        assertTrue("${w.copy.origin}|${w.u}" in held(w), "the second address's copy stays held")
        assertFalse(copyFile(w, w.copy.origin) in w.files.deleted, "the second address's copy is not deleted: ${w.files.deleted}")
        assertEquals(listOf(copyFile(w, w.home.origin)), w.files.deleted, "the first address's copy goes, once")
        assertNotNull(w.state.inner.get("${EngineAppApi.NAME_KEY}${w.copy.origin}|${w.u}"), "its name at the second address")
        // Everything kept for the account at the first server goes: O serving the id again is a first sight there.
        assertEquals(emptyList(), atHomeNamingAlice(w))
        assertNull(w.app.keeper.addressBinding(w.home.origin, alice))
        assertNotNull(w.app.keeper.knownIdentity(w.u), "the identity record the second address relies on")
        opensAtCopy(w)
    }

    // ---- a confirmed deletion at the first address, with the second tying the account ----

    @Test fun aDeletionTheFirstServerConfirmsWhereItKeepsNothingElseLeavesTheSecondAddressAsItWas() = runBlocking<Unit> {
        val w = world(bobAtFirst = false)
        val byIdBefore = byId(w)
        val copyBefore = atCopy(w)
        assertTrue(byIdBefore.keys.any { it.startsWith("ovh.acct|") }, "the account's state copy: $byIdBefore")
        w.files.deleted.clear()
        deleteAtFirst(w)
        assertTrue(assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten)
        assertEquals(PinState.None, w.app.trust.pinState(w.home.origin), "the first server is new to this device")
        secondAsItWas(w, byIdBefore, copyBefore, "road-b with O2")
    }

    @Test fun aDeletionTheFirstServerConfirmsBesideAnotherAccountThereLeavesTheSecondAddressAsItWas() = runBlocking<Unit> {
        val w = world(bobAtFirst = true)
        val byIdBefore = byId(w)
        val copyBefore = atCopy(w)
        w.files.deleted.clear()
        deleteAtFirst(w)
        assertFalse(assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten, "Bob's records keep the first server")
        assertIs<PinState.Pinned>(w.app.trust.pinState(w.home.origin))
        secondAsItWas(w, byIdBefore, copyBefore, "road-a with O2")
    }

    // ---- the same deletions with no second address: everything of the account goes, as before ----

    private fun nothingOfAlice(w: World, label: String) {
        probe(label, w)
        for ((which, store) in listOf("state" to w.state.inner, "secure" to w.secure)) {
            val left = store.keys().sorted().filter { k -> store.get(k).orEmpty().let { v -> listOf(w.u, alice).any { it in k || it in v } } }
            assertEquals(emptyList(), left, "$which: nothing of the deleted account")
        }
    }

    @Test fun withNoSecondAddressADeletionWhereTheServerKeepsNothingElseLeavesNothingOfTheAccount() = runBlocking<Unit> {
        val w = world(bobAtFirst = false, atCopy = false)
        deleteAtFirst(w)
        nothingOfAlice(w, "road-b without O2")
    }

    @Test fun withNoSecondAddressADeletionBesideAnotherAccountLeavesNothingOfTheAccount() = runBlocking<Unit> {
        val w = world(bobAtFirst = true, atCopy = false)
        deleteAtFirst(w)
        nothingOfAlice(w, "road-a without O2")
    }

    // ---- address records that cannot be read, and a store that cannot list its keys ----

    @Test fun anAddressRecordAtTheSecondAddressThatCannotBeReadIsATie() = runBlocking<Unit> {
        val w = world(bobAtFirst = true)
        val byIdBefore = byId(w)
        val copyBefore = atCopy(w)
        val record = SessionKeeper.EMAIL_BINDING_PREFIX + w.copy.origin + "|" + alice
        assertNotNull(w.state.inner.get(record))
        w.files.deleted.clear()
        w.state.unreadable += record
        deleteAtFirst(w)
        w.state.unreadable.clear()
        secondAsItWas(w, byIdBefore, copyBefore, "road-a, O2's address record unreadable")
    }

    @Test fun anAddressRecordAtTheFirstServerThatCannotBeReadIsNoTie() = runBlocking<Unit> {
        val w = world(bobAtFirst = true, atCopy = false)
        val bobs = SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + bob
        assertNotNull(w.state.inner.get(bobs))
        w.state.unreadable += bobs
        deleteAtFirst(w)
        w.state.unreadable.clear()
        nothingOfAlice(w, "road-a without O2, Bob's address record at O unreadable")
    }

    /**
     * A store that cannot list its keys cannot tell whether another server ties the account: the records kept by its id
     * that the deletion names in full stay (a tie, the safer side), and what it keeps at the first server by name goes.
     */
    @Test fun aStoreThatCannotListItsKeysCountsAsATie() = runBlocking<Unit> {
        val w = world(bobAtFirst = false, atCopy = false)
        val named = listOf("ovh.acct|${w.u}|sealed", "ovh.acct|${w.u}|hw", "ovh.acct|${w.u}|cas", "ovh.acct|${w.u}|seen",
            "ovh.acct|${w.u}|checkpoint", "ovh.rmirror|${w.u}", "ovh.escrowfp|${w.u}", "ovh.items|${w.u}|lost")
        val before = named.associateWith { w.state.inner.get(it) }
        assertTrue(before.values.any { it != null }, "some are kept: $before")
        val name = "${EngineAppApi.NAME_KEY}${w.home.origin}|${w.u}"
        assertNotNull(w.state.inner.get(name))
        w.state.unlisted = true
        deleteAtFirst(w)
        w.state.unlisted = false
        probe("unlisted store, road-a", w)
        assertEquals(before, named.associateWith { w.state.inner.get(it) }, "kept by the id alone: a store that cannot list is a tie")
        assertNull(w.state.inner.get(name), "its name at the first server goes")
        assertNull(w.app.keeper.addressBinding(w.home.origin, alice))
    }

    // ---- a deletion stopped part-way and run again ----

    @Test fun aDeletionStoppedPartWayAndRunAgainFinishesAndLeavesWhatTheSecondAddressReliesOn() = runBlocking<Unit> {
        val w = world(bobAtFirst = true)
        val byIdBefore = byId(w)
        val copyBefore = atCopy(w)
        val name = "${EngineAppApi.NAME_KEY}${w.home.origin}|${w.u}"
        assertNotNull(w.state.inner.get(name))
        w.files.deleted.clear()
        w.state.failAt = name
        runCatching { deleteAtFirst(w) }
        assertNull(w.state.failAt, "the store failed once, part-way")
        assertNotNull(w.state.inner.get(name), "stopped before its name at the first server went")
        // Run again with the tie the deletion read before it removed anything: the second address ties the account.
        w.app.dropDeletedAccountOnly(w.home.origin, alice, w.u, tied = true)
        assertNull(w.state.inner.get(name))
        secondAsItWas(w, byIdBefore, copyBefore, "road-a stopped part-way, run again")
    }

    @Test fun withNoSecondAddressADeletionStoppedPartWayAndRunAgainLeavesNothingOfTheAccount() = runBlocking<Unit> {
        val w = world(bobAtFirst = true, atCopy = false)
        w.state.failAt = "${EngineAppApi.NAME_KEY}${w.home.origin}|${w.u}"
        runCatching { deleteAtFirst(w) }
        assertNull(w.state.failAt, "the store failed once, part-way")
        assertNotNull(w.state.inner.get("${EngineAppApi.NAME_KEY}${w.home.origin}|${w.u}"), "stopped before its name went")
        // Run again with the tie the deletion read: nothing at another server ties the account.
        w.app.dropDeletedAccountOnly(w.home.origin, alice, w.u, tied = false)
        // The mark of the deletion begun names the account until a start finishes the deletion and takes it.
        w.app.close()
        w.app = device(w)
        nothingOfAlice(w, "road-a without O2, stopped part-way, run again")
    }

    // ---- the forgetting of an earlier account at the first server, where the second ties the account ----

    /**
     * "Forget the earlier account on this device" at the first server, where the same id is held at the second: like a
     * deletion, it is the first server's word alone. It takes what the first server held (its copy, its held entry), and
     * what the second relies on is as it was: its held entry, its copy, its name, every record of it (what waits unsent
     * there among them), and what is kept by the account's id alone (its marks against an older state, its identity
     * record). Before: the second's held entry, copy and name went, and so did everything kept by the id but the identity
     * record.
     */
    @Test fun theForgettingOfAnEarlierAccountAtTheFirstServerWhereTheSecondTiesIt() = runBlocking<Unit> {
        val w = world(bobAtFirst = false)
        loseSession(w)
        // Alice's account at the first server is made again from another device: another account under the address.
        w.home.accounts.remove(alice)
        val remade = register(otherDevice(w.home), "h.example", alice)
        assertNotEquals(w.u, remade)
        assertEquals(SignInAnswer.IDENTITY_FAULT, signInAt(w.app, w.home, alice))
        val copyBefore = atCopy(w)
        val byIdBefore = byId(w)
        assertTrue("state:${EngineAppApi.NAME_KEY}${w.copy.origin}|${w.u}" in copyBefore)
        assertTrue(byIdBefore.keys.any { it.startsWith("ovh.acct|") }, "$byIdBefore")
        w.files.deleted.clear()
        assertTrue(w.app.entry.askToForgetEarlierAccount(assertNotNull(w.app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, w.app.entry.forgetEarlierAccount(assertNotNull(w.app.snapshot.earlierAccount)))
        probe("forgetting of the earlier account at O", w)
        for (label in listOf("after the forgetting", "after a start")) {
            assertEquals(byIdBefore, byId(w), "$label: what is kept by the id alone stays, marks and identity record among it")
            assertEquals(copyBefore, atCopy(w), "$label: every record of the second address stays, its held entry and name among them")
            assertFalse(copyFile(w, w.copy.origin) in w.files.deleted, "$label: the second address's copy is not deleted: ${w.files.deleted}")
            assertEquals(listOf(copyFile(w, w.home.origin)), w.files.deleted, "$label: the first server's copy goes, once")
            assertFalse("${w.home.origin}|${w.u}" in held(w), label)
            assertNull(w.app.keeper.addressBinding(w.home.origin, alice), label)
            // The app starts again: the sign-in screen it stands on is the first server's.
            if (label == "after the forgetting") {
                w.app.close()
                w.app = device(w)
            }
        }
        // The second address's account still signs in, by its password, and its copy opens by its own unlock.
        opensAtCopy(w)
    }

    private companion object {
        val BY_ID = listOf("ovh.acct|", "ovh.log|", "ovh.items|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.identity|")
    }
}
