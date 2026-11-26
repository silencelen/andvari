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
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
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
 * The same email address only TRIED at an unrelated server (a sign-in there with a wrong password: the device's row for the
 * address is written before the request is sent and holds no device id, and no address record is written there) ties
 * nothing. An account under that address at another server, then deleted (on both roads), or that server forgotten, or the
 * account forgotten as an earlier account there: nothing of the account is left on the device, also after the other
 * server is forgotten and the app starts again. Before, the attempt's row kept the account's identity key, its state copy
 * and marks, its vault-log mark and its recovery mirror for good. A device's row there ties only where a session was
 * opened for it (its record holds a device id), or where its record cannot be read as a device's record.
 */
class EngineSameEmailOnlyTriedElsewhereTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"
    private val bob = "bob@example.com"

    private class Files(val caches: HashMap<String, VaultCache> = HashMap()) : VaultCacheFiles {
        override fun open(fileName: String, userId: String): VaultCache =
            caches.getOrPut(fileName) { object : VaultCache by InMemoryVaultCache() { override val durable: Boolean get() = true } }
        override fun delete(fileName: String): Boolean {
            caches.remove(fileName)
            return true
        }
    }

    private class World(val home: FakeInstance, val other: FakeInstance, val state: MemoryDeviceState, val secure: MemoryDeviceState, val files: Files) {
        lateinit var app: EngineAppApi
        lateinit var u: String
    }

    private fun device(w: World): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(w.home.origin to w.home, w.other.origin to w.other)), w.state, w.secure,
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

    private suspend fun signInAt(a: EngineAppApi, origin: String, email: String, password: String = strong): SignInAnswer {
        (a.snapshot.entry as? EntryScreen.FirstRun)?.let { if (it.accountDeleted != null) a.entry.dismissNotice(it) }
        if (a.snapshot.entry !is EntryScreen.SignIn) {
            a.entry.openSignIn(a.at())
            a.entry.openPasswordSignIn(a.at())
            assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), origin))
            (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        }
        return a.entry.submitSignIn(a.at(), email, password)
    }

    private fun restart(w: World) {
        w.app.close()
        w.app = device(w)
    }

    private fun loseSession(w: World) {
        w.app.lock()
        w.app.close()
        w.secure.set(SessionKeeper.KEY, null)
        w.app = device(w)
    }

    /** Back to the first screen: the entry's back, or a start. */
    private fun toFirstScreen(w: World) {
        var n = 0
        while (w.app.snapshot.entry !is EntryScreen.FirstRun && n++ < 8) if (!w.app.entry.back()) break
        if (w.app.snapshot.entry !is EntryScreen.FirstRun) restart(w)
    }

    /** Every record, in either store, whose key or value names [w]'s account. */
    private fun naming(w: World): List<String> = listOf("state" to w.state, "secure" to w.secure).flatMap { (which, s) ->
        s.keys().filter { k -> w.u in k || w.u in s.get(k).orEmpty() }.map { "$which:$it" }
    }.sorted()

    private suspend fun deleteAt(w: World) {
        w.home.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        w.home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, w.app.settings.openDeletion())
        assertEquals(DeletionResult.DONE, w.app.settings.deleteAccount(assertNotNull(w.app.snapshot.account!!.deletion), alice, strong, null))
        w.home.override.remove(WireRoute.ACCOUNT_DELETE_PREVIEW)
        w.home.override.remove(WireRoute.ACCOUNT_DELETE)
    }

    private fun world(): World {
        val home = FakeInstance(crypto)
        val other = FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        return World(home, other, MemoryDeviceState(), MemoryDeviceState(), Files()).also { it.app = device(it) }
    }

    /** A sign-in at other.example with the address and a wrong password: only the device's row is left there, with no device id. */
    private suspend fun triedAtTheOther(w: World) {
        assertEquals(SignInAnswer.WRONG, signInAt(w.app, w.other.origin, alice, password = "not her password at all 77"))
        val row = assertNotNull(w.state.get("ovh.dev|${w.other.origin}|$alice"), "the attempt left the device's row")
        assertTrue("deviceId" !in row, "no session was opened there: $row")
        assertTrue(w.state.keys().none { it.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin) }, "no address record there")
        toFirstScreen(w)
    }

    /** q1's state: the attempt at other.example, then account u at h.example under the same address. */
    private suspend fun triedElsewhere(): World {
        val w = world()
        triedAtTheOther(w)
        w.u = register(w.app, "h.example", alice)
        return w
    }

    private suspend fun forgetEarlierNow(w: World): ForgetEarlierResult {
        val offer = assertNotNull(w.app.snapshot.earlierAccount)
        assertTrue(w.app.entry.askToForgetEarlierAccount(offer))
        val confirm = assertNotNull(w.app.snapshot.earlierAccount)
        return w.app.entry.forgetEarlierAccount(confirm)
    }

    @Test fun aDeletionThatForgetsTheServerLeavesNothingWhereTheSameAddressWasOnlyTriedAtAnUnrelatedServer() = runBlocking<Unit> {
        val w = triedElsewhere()
        deleteAt(w)
        assertEquals(emptyList(), naming(w), "nothing of the deleted account stays")
        w.app.instancePart.forgetOrigin(w.other.origin)
        restart(w)
        assertEquals(emptyList(), naming(w), "nothing of the deleted account stays after other.example is forgotten and a start")
    }

    @Test fun aDeletionBesideAnotherAccountLeavesNothingWhereTheSameAddressWasOnlyTriedAtAnUnrelatedServer() = runBlocking<Unit> {
        val w = world()
        triedAtTheOther(w)
        register(w.app, "h.example", bob)
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        w.u = register(w.app, "h.example", alice)
        deleteAt(w)
        assertEquals(emptyList(), naming(w), "nothing of the deleted account stays; the server stays for bob")
        w.app.instancePart.forgetOrigin(w.other.origin)
        restart(w)
        assertEquals(emptyList(), naming(w), "nothing of the deleted account stays after other.example is forgotten and a start")
    }

    @Test fun forgetThisServerLeavesNothingWhereTheSameAddressWasOnlyTriedAtAnUnrelatedServer() = runBlocking<Unit> {
        val w = triedElsewhere()
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        assertEquals(emptyList(), naming(w), "nothing of the account stays after Forget this server")
        restart(w)
        assertEquals(emptyList(), naming(w), "nothing of the account stays after a start")
    }

    @Test fun theForgettingOfAnEarlierAccountLeavesOnlyTheServersRecordOfItsKeyWhereTheSameAddressWasOnlyTriedElsewhere() = runBlocking<Unit> {
        val w = triedElsewhere()
        loseSession(w)
        w.home.accounts.remove(alice)
        assertNotEquals(w.u, register(otherDevice(w.home), "h.example", alice))
        assertEquals(SignInAnswer.IDENTITY_FAULT, signInAt(w.app, w.home.origin, alice))
        assertEquals(ForgetEarlierResult.FORGOTTEN, forgetEarlierNow(w))
        restart(w)
        // Two records of h.example itself stay by design, and go with the server: the keeper's record of the forgotten
        // account's key, and the mark of the session once kept there (here lost from the secure store, so nothing in this
        // process took the mark at its end). Nothing kept by the account's id stays.
        val ofTheServer = listOf("state:${SessionKeeper.EARLIER_IDENTITY_PREFIX}${w.home.origin}|${w.u}", "state:${EngineAppApi.KEPT_MARK_PREFIX}${w.home.origin}")
        assertEquals(emptyList(), naming(w) - ofTheServer.toSet(), "the forgetting leaves nothing of the account but h.example's own records")
        toFirstScreen(w)
        w.app.instancePart.forgetOrigin(w.home.origin)
        restart(w)
        assertEquals(emptyList(), naming(w), "after h.example is forgotten too and a start, nothing")
    }

    // ---- what another server holds for the address, over a bare store ----

    private val h = "https://h.example"
    private val o2 = "https://copy.example"
    private val u = "11111111-1111-4111-8111-111111111111"
    private val secret = "BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSY"
    private val row = "ovh.dev|$o2|$alice"

    private fun bare(vararg recs: Pair<String, String>): MemoryDeviceState = MemoryDeviceState().also { s ->
        s.set(SessionKeeper.EMAIL_BINDING_PREFIX + "$h|$alice", "$u|$secret")
        for ((k, value) in recs) s.set(k, value)
    }

    private class Throwing(val inner: MemoryDeviceState, val bad: String) : DeviceState {
        override fun get(key: String): String? = if (key == bad) throw IllegalStateException("cannot read") else inner.get(key)
        override fun set(key: String, value: String?) = inner.set(key, value)
        override fun keys(): Set<String> = inner.keys()
    }

    @Test fun aDevicesRowAtAnotherServerTiesWhereItHoldsADeviceIdOrCannotBeReadAndNotWhereItRecordsOnlyAnAttempt() {
        val rows: List<Triple<String, DeviceState, Boolean>> = listOf(
            Triple("nothing there", bare(), false),
            Triple("a row holding a device id", bare(row to """{"deviceSecret":"$secret","deviceId":"55555555-5555-4555-8555-555555555555"}"""), true),
            Triple("a row holding no device id", bare(row to """{"deviceSecret":"$secret"}"""), false),
            Triple("a row that is not a device's record", bare(row to "v"), true),
            Triple("a row whose secret is not one", bare(row to """{"deviceSecret":"short"}"""), true),
            Triple("a row whose device id is not an id", bare(row to """{"deviceSecret":"$secret","deviceId":"not an id"}"""), true),
            Triple("a row the store cannot read", Throwing(bare(row to """{"deviceSecret":"$secret"}"""), row), true),
        )
        val wrong = rows.filter { (_, s, ties) -> PinStore.tiedElsewhere(s, u, h) != ties }.map { it.first }
        assertEquals(emptyList(), wrong, "rows whose tie is wrong")
    }
}
