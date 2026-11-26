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
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
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
 * One address known at two servers: the account at the first is the one kept; at the second this device holds what a
 * sign-out leaves (the address's record, the account's key record, the device's own row). Whatever is done at the first
 * server (a confirmed deletion of its account, with and without something of another account kept there; the forgetting
 * of an earlier account there; "Forget this server"), every record of the second server stays byte for byte as it was,
 * and the second server serving another account under that address is still refused. (A command-line tool's deletion
 * once removed records by the address at every server, which opened exactly that.)
 */
class EngineDeletionOtherServerTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    private class World(val home: FakeInstance, val other: FakeInstance, val app: EngineAppApi, val state: MemoryDeviceState, val secure: MemoryDeviceState) {
        lateinit var atOther: String
    }

    private fun device(vararg servers: FakeInstance, state: MemoryDeviceState = MemoryDeviceState(), secure: MemoryDeviceState = MemoryDeviceState()) = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(servers.associateBy { it.origin }), state, secure, crypto,
            { servers.first().now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
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
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "P", strong, true)))
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

    /**
     * Alice signed out at the second server, then [between] at the first, then Alice's account made and kept at the first.
     * The second server's records are compared from here.
     */
    private suspend fun world(between: suspend World.() -> Unit = {}): World {
        val home = FakeInstance(crypto)
        val other = FakeInstance(crypto, origin = "https://other.example", instanceId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val w = World(home, other, device(home, other, state = state, secure = secure), state, secure)
        w.atOther = register(w.app, "other.example", alice)
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        w.between()
        register(w.app, "h.example", alice)
        return w
    }

    /**
     * Every record of [w]'s second server, by key and by value: whatever names its address or its account's id, and
     * names nothing of the first server or of the account kept there (a shared list, such as the held copies, is read
     * line by line).
     */
    private fun secondServer(w: World, firstAccount: String?): Map<String, String> {
        val out = HashMap<String, String>()
        for ((which, store) in listOf("state" to w.state, "secure" to w.secure)) for (k in store.keys()) {
            val v = store.get(k) ?: continue
            val names = listOf(w.other.origin, w.atOther).any { it in k || it in v }
            if (!names) continue
            val first = listOf(w.home.origin).plus(listOfNotNull(firstAccount)).any { it in k || it in v }
            // The index of known servers is one shared list: only whether it still names the second server is its.
            if (k == io.silencelen.andvari.core.client.pin.PinStore.KEY_INDEX) out["$which:$k"] = (w.other.origin in v).toString()
            else if (!first) out["$which:$k"] = v
            else v.split('\n').filter { w.other.origin in it || w.atOther in it }.forEachIndexed { i, line -> out["$which:$k#line$i"] = line }
        }
        return out
    }

    /** The second server serves another account under the address: refused, and nothing of it kept. */
    private suspend fun stillRefused(w: World) {
        w.other.accounts.remove(alice)
        register(device(w.other), "other.example", alice)
        // The same device, opened again over its stores, signs in there.
        w.app.close()
        val again = device(w.home, w.other, state = w.state, secure = w.secure)
        assertEquals(SignInAnswer.IDENTITY_FAULT, signInAt(again, w.other, alice))
        val kept = again.keeper.session
        assertTrue(kept == null || kept.origin != w.other.origin || kept.userId == w.atOther, "another account is not taken: $kept")
    }

    private suspend fun deleteAtFirst(w: World) {
        w.home.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok(
            """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        w.home.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
        assertEquals(PlainResult.DONE, w.app.settings.openDeletion())
        assertEquals(DeletionResult.DONE, w.app.settings.deleteAccount(assertNotNull(w.app.snapshot.account!!.deletion), alice, strong, null))
    }

    @Test fun aConfirmedDeletionAtTheFirstServerLeavesEveryRecordOfTheSecond() = runBlocking<Unit> {
        val w = world()
        val first = assertNotNull(w.app.keeper.session).userId
        val before = secondServer(w, first)
        assertTrue(before.keys.any { it.startsWith("state:" + SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin) }, "the address's record: $before")
        assertTrue(before.keys.any { it == "state:ovh.identity|${w.atOther}" }, "the key's record: $before")
        assertTrue(before.keys.any { it == "state:ovh.dev|${w.other.origin}|$alice" }, "the device's row: $before")
        deleteAtFirst(w)
        assertTrue(assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten, "nothing of another account at the first server")
        assertEquals(before, secondServer(w, first))
        stillRefused(w)
    }

    @Test fun aConfirmedDeletionBesideAnotherAccountAtTheFirstServerLeavesEveryRecordOfTheSecond() = runBlocking<Unit> {
        val w = world {
            register(app, "h.example", "bob@example.com")
            assertEquals(PlainResult.DONE, app.signOutConfirmed(assertNotNull(app.signOutCheck())))
        }
        val first = assertNotNull(w.app.keeper.session).userId
        val before = secondServer(w, first)
        deleteAtFirst(w)
        assertEquals(false, assertNotNull(w.app.at<EntryScreen.FirstRun>().accountDeleted).serverForgotten, "Bob's records keep the first server")
        assertEquals(before, secondServer(w, first))
        stillRefused(w)
    }

    @Test fun theForgettingOfAnEarlierAccountAtTheFirstServerLeavesEveryRecordOfTheSecond() = runBlocking<Unit> {
        val w = world()
        val earlier = assertNotNull(w.app.keeper.session).userId
        assertEquals(PlainResult.DONE, w.app.signOutConfirmed(assertNotNull(w.app.signOutCheck())))
        // Alice's account at the first server is made again from another device: a new account under the address.
        w.home.accounts.remove(alice)
        val remade = register(device(w.home), "h.example", alice)
        assertNotEquals(earlier, remade)
        val before = secondServer(w, earlier)
        assertEquals(SignInAnswer.IDENTITY_FAULT, signInAt(w.app, w.home, alice))
        assertTrue(w.app.entry.askToForgetEarlierAccount(assertNotNull(w.app.snapshot.earlierAccount)))
        assertEquals(ForgetEarlierResult.FORGOTTEN, w.app.entry.forgetEarlierAccount(assertNotNull(w.app.snapshot.earlierAccount)))
        assertEquals(before, secondServer(w, earlier))
        stillRefused(w)
    }

    @Test fun forgettingTheFirstServerLeavesEveryRecordOfTheSecond() = runBlocking<Unit> {
        val w = world()
        val first = assertNotNull(w.app.keeper.session).userId
        val before = secondServer(w, first)
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        assertEquals(before, secondServer(w, first))
        stillRefused(w)
    }
}
