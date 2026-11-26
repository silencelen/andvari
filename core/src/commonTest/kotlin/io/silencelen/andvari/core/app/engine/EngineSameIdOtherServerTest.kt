package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
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
 * The account's own ends at one server beside another server, over the real engine:
 * - the same email address used for ANOTHER account at an unrelated server: a confirmed deletion (on both roads) and
 *   "Forget this server" leave nothing of the account on the device, also after the other server is forgotten too and the
 *   app starts again;
 * - the same account id served at a second address (a server that serves the same instance and accounts), with two changes
 *   waiting unsent in its copy: an end at the first that waits while the session is kept at the second is settled at the
 *   first only; "Forget the earlier account" at the first takes only what the first holds, and its offer counts no copy
 *   held at the second; "Forget this server" at the first leaves everything the second holds.
 */
class EngineSameIdOtherServerTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    /** Cache files kept in memory, durable; a deletion takes the copy's content with it, as on a device. */
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

    private class World(val home: FakeInstance, val copy: FakeInstance, val copyWire: ItemServer, val state: MemoryDeviceState,
                        val secure: MemoryDeviceState, val files: Files) {
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

    /** Signs in; [gate] is told whether a Trust Gate (a first sight) was shown on the way. */
    private suspend fun signInAt(a: EngineAppApi, origin: String, email: String, gate: (Boolean) -> Unit = {}): SignInAnswer {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
        if (a.snapshot.entry !is EntryScreen.SignIn) {
            a.entry.openSignIn(a.at())
            a.entry.openPasswordSignIn(a.at())
            assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), origin))
            val g = a.snapshot.entry as? EntryScreen.TrustGate
            gate(g != null)
            g?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
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
        w.secure.set(SessionKeeper.KEY, null)
        w.app = device(w)
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test"), "", "", false)

    private fun held(w: World): List<String> = w.state.get(EngineAppApi.HELD_KEY).orEmpty().split('\n').filter { it.isNotEmpty() }

    /** Every record kept by the account's id alone, by key and value. */
    private fun byId(w: World): Map<String, String> = w.state.keys().filter { k ->
        BY_ID.any { p -> k == p + w.u || k.startsWith("${p}${w.u}|") }
    }.sorted().associateWith { w.state.get(it).orEmpty() }

    /** Every key in either store whose key or value names the account. */
    private fun naming(w: World): List<String> = listOf("state" to w.state, "secure" to w.secure).flatMap { (which, s) ->
        s.keys().filter { k -> w.u in k || w.u in s.get(k).orEmpty() }.map { "$which:$it" }
    }.sorted()

    /** Every record of the second address, by key and value (the held list line by line; the index of servers as a yes). */
    private fun atCopy(w: World): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for ((which, store) in listOf("state" to w.state, "secure" to w.secure)) for (k in store.keys().sorted()) {
            val v = store.get(k) ?: continue
            if (w.copy.origin !in k && w.copy.origin !in v) continue
            if (k == PinStore.KEY_INDEX) out["$which:$k"] = (w.copy.origin in v).toString()
            else if (k != EngineAppApi.HELD_KEY && w.home.origin !in k && w.home.origin !in v) out["$which:$k"] = v
            else v.split('\n').filter { w.copy.origin in it }.forEachIndexed { i, line -> out["$which:$k#line$i"] = line }
        }
        return out
    }

    private fun copyFile(w: World, origin: String) = ItemCacheNames.fileName(crypto, origin, w.u)

    private suspend fun deleteAt(w: World) {
        w.home.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        w.home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, w.app.settings.openDeletion())
        assertEquals(DeletionResult.DONE, w.app.settings.deleteAccount(assertNotNull(w.app.snapshot.account!!.deletion), alice, strong, null))
        w.home.override.remove(WireRoute.ACCOUNT_DELETE_PREVIEW)
        w.home.override.remove(WireRoute.ACCOUNT_DELETE)
    }

    // ---- the same email address used for another account at an unrelated server ----

    /**
     * Alice has account v at other.example (another instance), signed out; then account u at h.example under the same
     * address ([bobAtFirst]: Bob's account at h.example before it, signed out, so that a deletion keeps the server). Nothing
     * at other.example names u; its address record for alice names v.
     */
    private suspend fun unrelated(bobAtFirst: Boolean): World {
        val home = FakeInstance(crypto)
        val other = FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val w = World(home, other, ItemServer(other) { null }.also { it.down = true }, MemoryDeviceState(), MemoryDeviceState(), Files())
        w.app = device(w)
        val v = register(w.app, "other.example", alice)
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        if (bobAtFirst) {
            register(w.app, "h.example", bob)
            assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        }
        w.u = register(w.app, "h.example", alice)
        assertNotEquals(v, w.u)
        assertTrue(w.state.keys().filter { other.origin in it }.none { w.u in it || w.u in w.state.get(it).orEmpty() })
        assertEquals(v, w.state.get(SessionKeeper.EMAIL_BINDING_PREFIX + other.origin + "|" + alice)?.substringBefore('|'))
        assertTrue(byId(w).keys.any { it.startsWith("ovh.identity|") } && byId(w).keys.any { it.startsWith("ovh.rmirror|") }, "${byId(w)}")
        return w
    }

    /** Nothing of u is on the device now, and still after Alice signs in to v, forgets other.example too, and a start. */
    private suspend fun nothingOfTheAccountLeft(w: World, label: String) {
        assertEquals(emptyList(), naming(w), "$label: nothing of the account is left")
        assertEquals(SignInAnswer.DONE, signInAt(w.app, w.copy.origin, alice))
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        assertEquals(emptyList(), naming(w), "$label, then other.example forgotten too")
        restart(w)
        assertEquals(emptyList(), naming(w), "$label, then a start")
    }

    @Test fun aDeletionThatForgetsTheServerLeavesNothingOfTheAccountWhereTheSameAddressIsAnotherAccountsAtAnUnrelatedServer() = runBlocking<Unit> {
        val w = unrelated(bobAtFirst = false)
        deleteAt(w)
        assertEquals(true, assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten)
        nothingOfTheAccountLeft(w, "a deletion, the server forgotten")
    }

    @Test fun aDeletionThatKeepsTheServerLeavesNothingOfTheAccountWhereTheSameAddressIsAnotherAccountsAtAnUnrelatedServer() = runBlocking<Unit> {
        val w = unrelated(bobAtFirst = true)
        deleteAt(w)
        assertEquals(false, assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten)
        nothingOfTheAccountLeft(w, "a deletion, the server kept for Bob's account")
    }

    @Test fun forgetThisServerLeavesNothingOfTheAccountWhereTheSameAddressIsAnotherAccountsAtAnUnrelatedServer() = runBlocking<Unit> {
        val w = unrelated(bobAtFirst = false)
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        nothingOfTheAccountLeft(w, "Forget this server")
    }

    @Test fun forgetThisServerWithOneAccountAtOneServerLeavesNothingOfTheAccount() = runBlocking<Unit> {
        val home = FakeInstance(crypto)
        val other = FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val w = World(home, other, ItemServer(other) { null }, MemoryDeviceState(), MemoryDeviceState(), Files())
        w.app = device(w)
        w.u = register(w.app, "h.example", alice)
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        assertEquals(emptyList(), naming(w))
    }

    // ---- the same account id at two addresses ----

    /**
     * The same id at two addresses (copy.example serves h.example's instance and accounts): Alice's copy at copy.example
     * holds two logins saved while it answered nothing (never sent); the session is kept at h.example, both copies held.
     */
    private suspend fun twoAddresses(): World {
        val home = FakeInstance(crypto)
        val copy = FakeInstance(crypto, origin = "https://copy.example", instanceId = home.instanceId)
        val w = World(home, copy, ItemServer(copy) { copy.accounts[alice]?.personalWrap?.vaultId }, MemoryDeviceState(), MemoryDeviceState(), Files())
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
        assertTrue(held(w).containsAll(listOf("${home.origin}|${w.u}", "${copy.origin}|${w.u}")), "both copies held: ${held(w)}")
        w.files.deleted.clear()
        return w
    }

    /** The second address's copy, its held entry and its records are as they were; the copy was never deleted. */
    private fun copyAsItWas(w: World, copyBefore: Map<String, String>, label: String) {
        assertEquals(copyBefore, atCopy(w), "$label: every record of the second address")
        assertTrue("${w.copy.origin}|${w.u}" in held(w), "$label: the second address's copy is held")
        assertFalse(copyFile(w, w.copy.origin) in w.files.deleted, "$label: the second address's copy is not deleted: ${w.files.deleted}")
    }

    /** The account signs in at the second address, and its copy holds the two changes not sent yet. */
    private suspend fun opensAtCopyWithItsChanges(w: World) {
        assertEquals(SignInAnswer.DONE, signInAt(w.app, w.copy.origin, alice))
        w.app.lock()
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), strong))
        assertEquals(2, assertNotNull(w.app.vault).queued().pending.size, "the second address's two changes not sent still wait")
    }

    /**
     * An end of the account at h.example still waits (the state a settling that failed part-way leaves, followed by a sign-in
     * at the second address) while the kept session is the same account at copy.example. The start settles it at h.example:
     * h.example's copy goes there and then (before: the end was settled away, and that copy stayed for good); copy.example's
     * copy, the kept session's, stays with its two changes not sent.
     */
    @Test fun anEndAtTheFirstServerThatWaitsWhileTheSameIdIsKeptAtTheSecondIsSettledAtTheFirstServer() = runBlocking<Unit> {
        val w = twoAddresses()
        loseSession(w)
        assertEquals(SignInAnswer.DONE, signInAt(w.app, w.copy.origin, alice))
        w.app.lock()
        w.app.close()
        val copyBefore = atCopy(w)
        w.files.deleted.clear()
        w.state.set(SessionKeeper.OWN_ENDS_KEY, "${w.home.origin}|${w.u}|SIGNED_OUT")
        w.app = device(w)
        assertNull(w.state.get(SessionKeeper.OWN_ENDS_KEY), "the end is settled")
        assertEquals(listOf(copyFile(w, w.home.origin)), w.files.deleted, "h.example's copy goes at the start, once")
        assertFalse("${w.home.origin}|${w.u}" in held(w), "h.example's copy is no longer held")
        assertEquals(w.u to w.copy.origin, assertNotNull(w.app.keeper.session).let { it.userId to it.origin }, "the session at copy.example is kept")
        copyAsItWas(w, copyBefore, "after the start")
        assertEquals(VaultUnlockResult.DONE, w.app.unlock(assertNotNull(w.app.snapshot.locked), strong))
        assertEquals(2, assertNotNull(w.app.vault).queued().pending.size, "copy.example's two changes not sent still wait")
    }

    /** h.example (remade, or lying) serves another account under Alice's address: the sign-in there is an identity fault. */
    private suspend fun remadeAtTheFirst(w: World) {
        w.home.accounts.remove(alice)
        val remade = register(otherDevice(w.home), "h.example", alice)
        assertNotEquals(w.u, remade)
        assertEquals(SignInAnswer.IDENTITY_FAULT, signInAt(w.app, w.home.origin, alice))
    }

    /** The person asks to forget the earlier account, confirms, and it is forgotten; the confirmation is returned. */
    private suspend fun forgetTheEarlierAccount(w: World): io.silencelen.andvari.core.app.EarlierAccountKnown {
        val offer = assertNotNull(w.app.snapshot.earlierAccount)
        assertEquals(w.home.origin, offer.instance.origin)
        assertTrue(w.app.entry.askToForgetEarlierAccount(offer))
        val confirm = assertNotNull(w.app.snapshot.earlierAccount)
        assertEquals(ForgetEarlierResult.FORGOTTEN, w.app.entry.forgetEarlierAccount(confirm))
        return confirm
    }

    /**
     * "Forget the earlier account" at h.example, after h.example served another account under Alice's address, while
     * copy.example serves the same account id: it takes what h.example holds (its copy, its held entry), and leaves
     * copy.example's copy, its two changes not sent, its records, and what is kept by the account's id (its marks against
     * an older state among them), all as they were. Before: copy.example's copy went with its changes, on h.example's word.
     */
    @Test fun forgettingTheEarlierAccountAtTheFirstServerLeavesTheSecondServersCopyItsChangesNotSentAndItsMarks() = runBlocking<Unit> {
        val w = twoAddresses()
        loseSession(w)
        remadeAtTheFirst(w)
        val copyBefore = atCopy(w)
        val byIdBefore = byId(w)
        assertTrue(byIdBefore.keys.any { it.startsWith("ovh.acct|${w.u}|") }, "marks of the account's state are kept by its id: $byIdBefore")
        w.files.deleted.clear()
        val confirm = forgetTheEarlierAccount(w)
        assertTrue(confirm.keptCopy, "h.example's own copy is held, and the confirmation says so")
        assertEquals(listOf(copyFile(w, w.home.origin)), w.files.deleted, "h.example's copy goes, and only it")
        assertFalse("${w.home.origin}|${w.u}" in held(w))
        copyAsItWas(w, copyBefore, "after the forgetting")
        assertEquals(byIdBefore, byId(w), "kept by the account's id, as it was: copy.example ties the account")
        restart(w)
        copyAsItWas(w, copyBefore, "after a start")
        opensAtCopyWithItsChanges(w)
    }

    /**
     * What the offer says goes is what goes: with no copy held at h.example (Alice signed out there) and one held at
     * copy.example, the offer at h.example names no kept copy and counts nothing unsent, and the forgetting leaves
     * copy.example's copy with its two changes. Before: the offer counted copy.example's copy as one that goes, and it went.
     */
    @Test fun theOfferToForgetTheEarlierAccountCountsNoCopyHeldAtAnotherServer() = runBlocking<Unit> {
        val w = twoAddresses()
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        assertEquals(listOf("${w.copy.origin}|${w.u}"), held(w).filter { it.endsWith("|${w.u}") }, "only copy.example's copy is held")
        remadeAtTheFirst(w)
        val offer = assertNotNull(w.app.snapshot.earlierAccount)
        assertFalse(offer.keptCopy, "no copy of the account is held at h.example")
        assertEquals(0, offer.unsentChanges, "nothing that goes waits unsent")
        val copyBefore = atCopy(w)
        val byIdBefore = byId(w)
        w.files.deleted.clear()
        val confirm = forgetTheEarlierAccount(w)
        assertFalse(confirm.keptCopy)
        assertEquals(0, confirm.unsentChanges)
        assertFalse(copyFile(w, w.copy.origin) in w.files.deleted, "copy.example's copy does not go: ${w.files.deleted}")
        copyAsItWas(w, copyBefore, "after the forgetting")
        assertEquals(byIdBefore, byId(w), "kept by the account's id, as it was")
        // The app starts again: the sign-in screen it stands on is h.example's.
        restart(w)
        opensAtCopyWithItsChanges(w)
    }

    /**
     * "Forget this server" at h.example while copy.example serves the same id (two changes wait unsent in its copy): nothing
     * copy.example's account relies on goes, nothing of the account is left at h.example, and h.example is a first sight
     * afterwards.
     */
    @Test fun forgetThisServerAtTheFirstWhileTheSecondServesTheSameIdLeavesEverythingTheSecondHolds() = runBlocking<Unit> {
        val w = twoAddresses()
        val copyBefore = atCopy(w)
        val byIdBefore = byId(w)
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        val atHome = listOf("state" to w.state, "secure" to w.secure).flatMap { (which, s) ->
            s.keys().filter { k -> w.home.origin in k && s.get(k).orEmpty().let { v -> w.u in k || w.u in v || alice in k || alice in v } }.map { "$which:$it" }
        }
        assertEquals(byIdBefore, byId(w), "kept by the id alone, as it was")
        copyAsItWas(w, copyBefore, "after Forget this server")
        assertEquals(emptyList(), atHome, "nothing of the account is left at h.example")
        restart(w)
        opensAtCopyWithItsChanges(w)
        w.app.lock()
        w.app.close()
        w.secure.set(SessionKeeper.KEY, null)
        w.app = device(w)
        var gate: Boolean? = null
        assertEquals(SignInAnswer.DONE, signInAt(w.app, w.home.origin, alice) { gate = it })
        assertEquals(true, gate, "h.example is a first sight")
    }

    private companion object {
        val BY_ID = listOf("ovh.acct|", "ovh.log|", "ovh.items|", "ovh.rmirror|", "ovh.escrowfp|", "ovh.identity|")
    }
}
