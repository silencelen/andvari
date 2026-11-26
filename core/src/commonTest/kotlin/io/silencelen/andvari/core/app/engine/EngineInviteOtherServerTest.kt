package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkPerson
import io.silencelen.andvari.core.client.link.LinkServer
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * An invite for another server opened while signed in (design §6.7, the dead end "The link's instance is not the one the
 * app is signed in to"): the prompt names both servers; cancelling leaves no pin of the other server; "Switch to …" signs
 * out here and goes on with the invite signed out, at the other server. Before, the app interface answered FAILED and
 * dropped the link.
 */
class EngineInviteOtherServerTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /** [home] is the server the app is signed in to; [other] the invite's. [otherDown]: the other server answers nothing. */
    private class World(val home: LinkServer, val other: LinkServer, val alice: LinkPerson, val carol: LinkPerson, val app: EngineAppApi) {
        var otherDown = false
    }

    private suspend fun world(): World {
        val home = LinkServer(crypto)
        val other = LinkServer(crypto, FakeInstance(crypto, origin = "https://b.example"))
        val alice = LinkPerson(crypto, home, 1, "11111111-1111-4111-8111-111111111111", "Alice").start()
        val carol = LinkPerson(crypto, other, 3, "33333333-3333-4333-8333-333333333333", "Carol").start()
        var self: EngineAppApi? = null
        lateinit var w: World
        fun asApp(server: LinkServer, down: () -> Boolean) = object : WireClient {
            override val origin: String = server.instance.origin
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                if (down()) return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
                // Each server knows the caller by the account the app holds there.
                val caller = self?.keeper?.session?.takeIf { it.origin == server.instance.origin }?.userId
                return server.client(caller).call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel",
                BearerTransport(mapOf(home.instance.origin to asApp(home) { false }, other.instance.origin to asApp(other) { w.otherDown })),
                MemoryDeviceState(), MemoryDeviceState(), crypto, { home.instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        w = World(home, other, alice, carol, app)
        return w
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun link(p: LinkPerson, kind: String = "connect"): String =
        assertIs<CreateOutcome.Created>(p.flows.create(kind, 60 * 60 * 1000L, emptyList())).link.url

    /** From a join screen: sign-up by email, then the kit. The vault opens. */
    private suspend fun EngineAppApi.joinAndSignUp(email: String) {
        assertEquals(ServerResult.DONE, entry.joinFromInvite(at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, entry.startSignUp(at(), email, true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, entry.verifySignUpCode(at(), "482915"))
        assertEquals(CreateAccountResult.DONE, entry.createAccount(at(), NewAccountInput("", "Bob", strong, true)))
        val kit = at<EntryScreen.Kit>()
        val doc = assertNotNull(kit.kit.let { this.kit.kitDocument(it) })
        this.kit.proceedToConfirm(kit.kit)
        val confirm = at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, this.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, snapshot.phase)
    }

    /** Signed in at [World.home], through Alice's connect link. */
    private suspend fun World.signedInAtHome() {
        app.entry.openInviteEntry(app.at())
        assertEquals(InviteResult.DONE, app.entry.submitInvite(app.at(), link(alice), PayloadSource.SCANNED))
        app.joinAndSignUp("bob@example.com")
    }

    @Test fun anInviteForAnotherServerNamesBothAndCancellingLeavesNoPinThere() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        w.signedInAtHome()
        val homeOrigin = w.home.instance.origin
        val otherOrigin = w.other.instance.origin
        val session = a.keeper.session

        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        val ask = assertIs<OpenedInvite.OtherInstance>(a.snapshot.account!!.opened)
        assertEquals(otherOrigin, ask.inviteInstance.origin)
        assertEquals(homeOrigin, ask.signedInTo.origin)
        assertEquals(CopyKey.OTHER_INSTANCE, ask.line.key)
        assertEquals(listOf(ask.inviteInstance.name, otherOrigin, ask.signedInTo.name), ask.line.values)
        assertEquals(CopyKey.OTHER_INSTANCE_SWITCH, ask.switchLabel.key)
        // This device never set "New devices must be linked", and the server serves no read of it: it cannot tell.
        assertEquals(CopyKey.OTHER_INSTANCE_SIGNS_OUT_LINK_UNKNOWN, ask.signOutLine.key)
        assertEquals(listOf(ask.signedInTo.name, homeOrigin), ask.signOutLine.values)
        // The link's signed offer anchored the other server's pin; nothing was answered there.
        assertIs<PinState.Pinned>(a.trust.pinState(otherOrigin))
        assertTrue(w.other.rows.values.all { it.state == "open" }, "nothing answered at the other server")

        a.links.dismissOpened()
        assertNull(a.snapshot.account!!.opened)
        assertEquals(PinState.None, a.trust.pinState(otherOrigin), "the pin the opening made goes with the cancel")
        assertEquals<String?>(session?.userId, a.keeper.session?.userId, "still signed in here")
        assertEquals<String?>(session?.origin, a.keeper.session?.origin)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Test fun switchingSignsOutHereAndGoesOnWithTheInviteAtTheOtherServer() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        w.signedInAtHome()
        val homeOrigin = w.home.instance.origin
        val otherOrigin = w.other.instance.origin

        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        val ask = assertIs<OpenedInvite.OtherInstance>(a.snapshot.account!!.opened)
        assertEquals(ServerResult.DONE, a.links.switchInstance(ask))
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertNull(a.keeper.session, "signed out here")
        assertIs<PinState.Pinned>(a.trust.pinState(homeOrigin), "this server's pin outlives the sign-out")
        val join = a.at<EntryScreen.JoinInvite>()
        assertEquals(otherOrigin, join.instance.origin)
        assertEquals("Carol", join.from)
        assertEquals(ServerResult.STALE, a.links.switchInstance(ask), "the prompt is gone")

        // A new account there; once its vault opens the connection is answered there, and only there.
        a.joinAndSignUp("bob@b.example")
        assertEquals(otherOrigin, a.keeper.session!!.origin)
        assertEquals("answered", w.other.rows.values.single().state, "the connection was answered at the other server")
        assertTrue(w.home.rows.values.none { it.answerer == a.keeper.session!!.userId }, "nothing of it reached this server")
    }

    /** A lying or absent other server: "Switch" asks it first, so nothing here is signed out for a server that does not answer. */
    @Test fun aSwitchToAServerThatDoesNotAnswerKeepsThisSession() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        w.signedInAtHome()
        val session = a.keeper.session
        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        val ask = assertIs<OpenedInvite.OtherInstance>(a.snapshot.account!!.opened)
        w.otherDown = true
        assertEquals(ServerResult.UNREACHABLE, a.links.switchInstance(ask))
        assertEquals<String?>(session?.userId, a.keeper.session?.userId, "still signed in here")
        assertEquals<String?>(session?.origin, a.keeper.session?.origin)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertSame(ask,a.snapshot.account!!.opened, "the prompt stays, for a retry or a cancel")
        w.otherDown = false
        assertEquals(ServerResult.DONE, a.links.switchInstance(ask))
        a.at<EntryScreen.JoinInvite>()
    }

    /**
     * The instance details show the first card's hash for every kind of pin, labelled as what this device pinned (here a
     * link offer's pin). Before, only the device that signed card 0 showed a hash.
     */
    @Test fun theInstanceDetailsShowTheFirstCardsHashForALinkOffersPin() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        w.signedInAtHome()
        val pin = assertNotNull(a.trust.pinFor(w.home.instance.origin))
        val details = assertNotNull(a.snapshot.instance).details
        assertTrue(pin.card0Hash.isNotEmpty())
        assertEquals(pin.card0Hash, details.pinnedCard0Hash)
        assertEquals(CopyKey.INSTANCE_CARD0_PINNED, details.pinnedCard0Label)
        assertEquals("", details.card0Hash, "the value a store build bakes stays the signing device's alone")
    }

    /** A lock while the other server is asked: nothing is signed out, and nothing of the invite is shown afterwards. */
    @Test fun aLockDuringTheSwitchSignsNothingOut() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        w.signedInAtHome()
        assertEquals(InviteResult.DONE, a.links.openInvite(link(w.carol), PayloadSource.SCANNED))
        val ask = assertIs<OpenedInvite.OtherInstance>(a.snapshot.account!!.opened)
        a.lock()
        assertEquals(ServerResult.STALE, a.links.switchInstance(ask))
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertNotNull(a.keeper.session, "a lock is not a sign-out")
        assertEquals(PinState.None, a.trust.pinState(w.other.instance.origin), "the lock closed the invite and its pin")
    }
}
