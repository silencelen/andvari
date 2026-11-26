package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Link from your other device" on the engine (§8.2, new device): the app API drives the engine's new-device steps
 * against [DeviceLinkServer], while an existing device (E) with a real registered account drives the other side.
 */
class EngineDeviceLinkTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val email = "alice@example.com"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    private class World(
        val instance: FakeInstance, val server: DeviceLinkServer, val e: WireDeviceLinks, val transport: BearerTransport, val app: EngineAppApi,
        /** Routes the server does not answer for the app. */
        val silent: MutableSet<WireRoute>,
        /** Run once, when the app's request on the route arrives, before it is answered. */
        val meanwhile: MutableMap<WireRoute, () -> Unit> = HashMap(),
    )

    /** [inner], except that a route in [silent] gets no answer, and a route in [meanwhile] runs its act once first. */
    private class Silenced(
        private val inner: io.silencelen.andvari.core.client.net.WireClient, private val silent: Set<WireRoute>,
        private val meanwhile: MutableMap<WireRoute, () -> Unit> = HashMap(),
    ) : io.silencelen.andvari.core.client.net.WireClient {
        override val origin: String get() = inner.origin
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            meanwhile.remove(route)?.invoke()
            return if (route in silent) io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT)
            else inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private suspend fun world(): World {
        val instance = FakeInstance(crypto)
        val server = DeviceLinkServer(instance)
        val eState = MemoryDeviceState()
        val eTrust = instance.pinnedTrust(eState)
        val sink = Sink()
        val onboarding = WireOnboarding(instance.origin, server.client(null), eTrust, KnownDevices(eState, crypto), sink, crypto, eState, "desktop", "Laptop",
            { instance.now }, work = Dispatchers.Unconfined)
        onboarding.signupStart(email, true)
        val ticket = assertIs<SignupVerify.Ticket>(onboarding.signupVerify(email, "482915"))
        val reg = assertIs<Registration.Registered>(onboarding.register(RegistrationAuth.Ticket(ticket),
            RegistrationForm(email, "Alice", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Laptop", "desktop")))
        val session = sink.sessions.single()
        val acct = LinkAccount.of(session, "Alice", StoredAccountState(reg.userId, session.account.uvk, server.client(reg.userId), crypto, eState))
        val e = WireDeviceLinks({ server.client(reg.userId, it) }, eTrust, eState, crypto, { instance.now }, { acct }, KnownDevices(eState, crypto), sink,
            { _, _ -> }, "Laptop", "desktop")
        val silent = HashSet<WireRoute>()
        val meanwhile = HashMap<WireRoute, () -> Unit>()
        val transport = BearerTransport(mapOf(instance.origin to Silenced(server.client(null), silent, meanwhile)))
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel 9", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { instance.now }, baked = null,
                storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        return World(instance, server, e, transport, app, silent, meanwhile)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun EngineAppApi.toLinkEntry() {
        // Back from a link's end, the journey is at the link's first screen already.
        if (snapshot.entry is EntryScreen.LinkDeviceEntry) return
        entry.openSignIn(at())
        entry.openLinkDevice(at())
        at<EntryScreen.LinkDeviceEntry>()
    }

    /** The link scanned on the app, through the device-link Trust Gate, to the code; E types it and approves. */
    private suspend fun World.toPassword(): EntryScreen.LinkDevicePassword {
        val a = app
        a.toLinkEntry()
        val shown = assertIs<ExistingStep.Shown>(e.create())
        assertEquals(DeviceLinkScanResult.DONE, a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED))
        val gate = a.at<EntryScreen.TrustGate>()
        assertEquals(TrustGateWording.DEVICE_LINK, gate.prompt.wording)
        assertTrue(server.rows.values.single().claim == null, "nothing is claimed before the gate is confirmed")
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(gate))
        a.at<EntryScreen.LinkDeviceWaiting>()
        assertFalse(a.entry.back(), "a claimed link is left only by starting over")
        val fixed = assertIs<ExistingStep.ClaimFixed>(e.advance(shown))
        assertEquals("Pixel 9", fixed.name)
        assertTrue(a.entryFlow.pollDeviceLink())
        val code = a.at<EntryScreen.LinkDeviceCode>().code
        val type = assertIs<ExistingStep.TypeDigits>(e.advance(fixed))
        val ok = assertIs<ExistingStep.Approvable>(e.typeDigits(type, code))
        assertIs<ExistingStep.Approved>(e.approve(ok))
        // Nothing derived from the password went anywhere before the password screen.
        assertTrue(server.calls.none { it.second == WireRoute.PRELOGIN || it.second == WireRoute.DEVICE_LINK_PICKUP })
        assertFalse(a.entryFlow.pollDeviceLink(), "the poll stops at the password")
        val pw = a.at<EntryScreen.LinkDevicePassword>()
        assertEquals(email, pw.prompt.email)
        assertEquals(instance.origin, pw.prompt.instance.origin)
        assertFalse(pw.codeNeeded)
        return pw
    }

    @Test fun aLinkedDeviceOpensTheVaultAfterThePassword() = runBlocking<Unit> {
        val w = world()
        w.instance.account(email).recoveryConfirmed = true
        val pw = w.toPassword()
        assertEquals(LinkPasswordResult.WRONG, w.app.entry.submitLinkPassword(pw, "not the password at all 1"))
        assertEquals(LinkPasswordResult.DONE, w.app.entry.submitLinkPassword(w.app.at(), password))
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
        assertEquals(email, w.app.snapshot.account!!.email)
        assertEquals(w.instance.origin, w.app.keeper.session!!.origin)
    }

    @Test fun aPickupTheServerDoesNotAnswerEndsTheLinkAsNoAnswer() = runBlocking<Unit> {
        val w = world()
        w.instance.account(email).recoveryConfirmed = true
        val pw = w.toPassword()
        w.silent += WireRoute.DEVICE_LINK_PICKUP
        assertEquals(LinkPasswordResult.UNREACHABLE, w.app.entry.submitLinkPassword(pw, password))
        assertEquals(LinkDeviceEnd.NO_ANSWER, w.app.at<EntryScreen.LinkDeviceEnded>().outcome)
        assertNull(w.app.keeper.session, "nothing was linked")
    }

    /**
     * A code the server does not take at the pickup, within the link's time, leaves the link open: said as a refused code
     * (never "wrong password"), the screen back at the password, and the password and a current code link the device.
     * Before: WRONG, the line of a wrong password.
     */
    @Test fun aRefusedCodeAtThePickupLeavesTheLinkOpenAndSaysSo() = runBlocking<Unit> {
        val w = world()
        w.instance.account(email).totp = "123456"
        val pw = w.toPassword()
        assertEquals(LinkPasswordResult.CODE_NEEDED, w.app.entry.submitLinkPassword(pw, password))
        val r = w.app.entry.submitLinkCode(w.app.at(), "000000")
        assertEquals(LinkPasswordResult.CODE_REFUSED_LINK_STAYS, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_CODE_REFUSED_LINK_STAYS, r.sentence)
        val again = w.app.at<EntryScreen.LinkDevicePassword>()
        assertFalse(again.codeNeeded, "back at the password")
        assertEquals(LinkPasswordResult.CODE_NEEDED, w.app.entry.submitLinkPassword(again, password))
        assertEquals(LinkPasswordResult.DONE, w.app.entry.submitLinkCode(w.app.at(), "123456"))
        assertTrue(w.app.snapshot.entry !is EntryScreen.LinkDeviceEnded)
    }

    /**
     * A pickup the server refuses as one of too many requests ends the link with an end of its own and the wait the server
     * named: never "unreachable", never "the link ended" with no reason. Before: ENDED, and "a check failed".
     */
    @Test fun aPickupRefusedAsTooManyEndsTheLinkWithItsOwnEndAndTheWait() = runBlocking<Unit> {
        val w = world()
        val pw = w.toPassword()
        w.server.tooMany[WireRoute.DEVICE_LINK_PICKUP] = 1
        val r = w.app.entry.submitLinkPassword(pw, password)
        assertEquals(LinkPasswordResult.RATE_LIMITED, r)
        val ended = w.app.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.TOO_MANY, ended.outcome)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_TOO_MANY, ended.outcome.sentence)
        assertEquals(30, w.app.retryAfterSeconds())
        assertTrue(w.app.snapshot.phase != AppPhase.UNLOCKED)
    }

    /**
     * The fake plays a link's "too many requests" as the engine does, each said as that with the wait: on the new device the
     * claim (nothing claimed) and the pickup (the link's own end); on the showing device the approval (the link ends with
     * its own line) and a link's start (no link). Before: the fake played none of them.
     */
    @Test fun theFakePlaysALinksTooManyRequestsAsTheEngineDoes() = runBlocking<Unit> {
        val engine = Readings()
        // The claim, after the scan and the link's Trust Gate.
        val w1 = world()
        w1.app.toLinkEntry()
        val shown = assertIs<ExistingStep.Shown>(w1.e.create())
        assertEquals(DeviceLinkScanResult.DONE, w1.app.entry.submitDeviceLink(w1.app.at(), shown.url, PayloadSource.SCANNED))
        w1.server.tooMany[WireRoute.DEVICE_LINK_CLAIM] = 1
        engine += listOf(w1.app.entry.confirmTrustGate(w1.app.at()), w1.app.snapshot.entry?.let { it::class.simpleName }, w1.app.retryAfterSeconds())
        // The pickup.
        val w2 = world()
        val pw = w2.toPassword()
        w2.server.tooMany[WireRoute.DEVICE_LINK_PICKUP] = 1
        engine += listOf(w2.app.entry.submitLinkPassword(pw, password), w2.app.at<EntryScreen.LinkDeviceEnded>().outcome, w2.app.retryAfterSeconds())
        // The approval on the showing device, then a link's start there.
        val w3 = world()
        val (e, approvable) = w3.approvableOn(io.silencelen.andvari.core.client.session.TestKeyWrap(), quickOn = false)
        w3.server.tooMany[WireRoute.DEVICE_LINK_APPROVE] = 1
        val approved = e.devices.approveWithPassword(approvable, password)
        val ended = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Ended>(e.snapshot.account!!.deviceLink)
        engine += listOf(approved, ended.outcome, ended.line, e.retryAfterSeconds())
        w3.server.tooMany[WireRoute.DEVICE_LINK_CREATE] = 1
        engine += listOf(e.devices.startDeviceLink(), e.snapshot.account!!.deviceLink, e.retryAfterSeconds())

        val fake = Readings()
        val pwFake = io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD
        val f1 = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.LINK_DEVICE_ENTRY)
        val home = f1.script.addServer("https://h.example", "Home", io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER)
        val other = home.addAccount(io.silencelen.andvari.core.app.fake.FakeScenes.EMAIL, pwFake)
        assertEquals(DeviceLinkScanResult.DONE, f1.entry.submitDeviceLink(assertIs(f1.snapshot.entry), f1.script.deviceLinkFrom(other, "MacBook"), PayloadSource.SCANNED))
        f1.script.linkTooMany = true
        fake += listOf(f1.entry.confirmTrustGate(assertIs(f1.snapshot.entry)), f1.snapshot.entry?.let { it::class.simpleName }, f1.retryAfterSeconds())
        val f2 = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.LINK_DEVICE_PASSWORD)
        f2.script.linkTooMany = true
        fake += listOf(f2.entry.submitLinkPassword(assertIs<EntryScreen.LinkDevicePassword>(f2.snapshot.entry), pwFake),
            assertIs<EntryScreen.LinkDeviceEnded>(f2.snapshot.entry).outcome, f2.retryAfterSeconds())
        val f3 = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.HOST_LINK_APPROVABLE)
        f3.script.linkTooMany = true
        val fApproved = f3.devices.approveWithPassword(assertIs(f3.snapshot.account!!.deviceLink), pwFake)
        val fEnded = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Ended>(f3.snapshot.account!!.deviceLink)
        fake += listOf(fApproved, fEnded.outcome, fEnded.line, f3.retryAfterSeconds())
        f3.script.linkTooMany = true
        fake += listOf(f3.devices.startDeviceLink(), f3.snapshot.account!!.deviceLink, f3.retryAfterSeconds())

        assertEquals<List<Any?>>(listOf(
            listOf(ServerResult.RATE_LIMITED, "LinkDeviceEntry", 30),
            listOf(LinkPasswordResult.RATE_LIMITED, LinkDeviceEnd.TOO_MANY, 30),
            listOf(io.silencelen.andvari.core.app.ProofResult.RATE_LIMITED, io.silencelen.andvari.core.app.DeviceLinkHostEnd.DID_NOT_CHECK_OUT,
                io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_HOST_TOO_MANY, 30),
            listOf(io.silencelen.andvari.core.app.PlainResult.RATE_LIMITED, null, 30),
        ), engine)
        assertEquals<List<Any?>>(engine, fake)

        // The digits, which the engine ends the same way ([EngineDevices.submitDeviceDigits]): on the fake too.
        val f4 = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.HOST_LINK_TYPE_DIGITS)
        f4.script.linkTooMany = true
        assertEquals(io.silencelen.andvari.core.app.DigitsResult.RATE_LIMITED,
            f4.devices.submitDeviceDigits(assertIs(f4.snapshot.account!!.deviceLink), f4.script.joiningDeviceCode))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_HOST_TOO_MANY,
            assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Ended>(f4.snapshot.account!!.deviceLink).line)
    }

    /**
     * An ended link keeps the moment the wait the server named runs out: while it runs, the end says what is left of it;
     * after it, the end's line says that the wait is over, never that the server named none; where the server named none,
     * the end has no wait. On the new device (the pickup) and on the device that showed the link (the approval), the
     * engine and the stand-in alike. Before: the end kept no wait, and the apps read the app's current wait, which reads
     * as none once it has run out.
     */
    @Test fun anEndedLinkKeepsTheMomentItsNamedWaitRunsOut() = runBlocking<Unit> {
        fun read(wait: io.silencelen.andvari.core.app.NamedWait?, line: io.silencelen.andvari.core.app.CopyKey?) =
            listOf(wait?.secondsLeft(), wait?.over, line)
        val engine = Readings()
        // The new device: the pickup refused as too many, the server naming 30 seconds.
        val w = world()
        val pw = w.toPassword()
        w.server.tooMany[WireRoute.DEVICE_LINK_PICKUP] = 1
        assertEquals(LinkPasswordResult.RATE_LIMITED, w.app.entry.submitLinkPassword(pw, password))
        val ended = w.app.at<EntryScreen.LinkDeviceEnded>()
        engine += read(ended.wait, ended.lineNow())
        w.instance.now += 20_000
        engine += read(ended.wait, ended.lineNow())
        w.instance.now += 10_000
        engine += read(ended.wait, ended.lineNow())
        engine += w.app.retryAfterSeconds()
        // The device that showed the link: the approval refused as too many.
        val w3 = world()
        val (e, approvable) = w3.approvableOn(io.silencelen.andvari.core.client.session.TestKeyWrap(), quickOn = false)
        w3.server.tooMany[WireRoute.DEVICE_LINK_APPROVE] = 1
        e.devices.approveWithPassword(approvable, password)
        val hostEnded = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Ended>(e.snapshot.account!!.deviceLink)
        engine += read(hostEnded.wait, hostEnded.lineNow())
        w3.instance.now += 20_000
        engine += read(hostEnded.wait, hostEnded.lineNow())
        w3.instance.now += 10_000
        engine += read(hostEnded.wait, hostEnded.lineNow())
        engine += e.retryAfterSeconds()

        val tooMany = io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_TOO_MANY
        val hostTooMany = io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_HOST_TOO_MANY
        assertEquals<List<Any?>>(listOf(
            listOf(30, false, tooMany), listOf(10, false, tooMany),
            listOf(0, true, io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_TOO_MANY_WAIT_OVER), 0,
            listOf(30, false, hostTooMany), listOf(10, false, hostTooMany),
            listOf(0, true, io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_HOST_TOO_MANY_WAIT_OVER), 0,
        ), engine)

        // The stand-in, side by side (its server names 30 seconds).
        val fake = Readings()
        val pwFake = io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD
        val f2 = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.LINK_DEVICE_PASSWORD)
        f2.script.linkTooMany = true
        f2.entry.submitLinkPassword(assertIs<EntryScreen.LinkDevicePassword>(f2.snapshot.entry), pwFake)
        val fEnded = assertIs<EntryScreen.LinkDeviceEnded>(f2.snapshot.entry)
        fake += read(fEnded.wait, fEnded.lineNow())
        f2.script.advance(20_000)
        fake += read(fEnded.wait, fEnded.lineNow())
        f2.script.advance(10_000)
        fake += read(fEnded.wait, fEnded.lineNow())
        fake += f2.retryAfterSeconds()
        val f3 = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.HOST_LINK_APPROVABLE)
        f3.script.linkTooMany = true
        f3.devices.approveWithPassword(assertIs(f3.snapshot.account!!.deviceLink), pwFake)
        val fHost = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Ended>(f3.snapshot.account!!.deviceLink)
        fake += read(fHost.wait, fHost.lineNow())
        f3.script.advance(20_000)
        fake += read(fHost.wait, fHost.lineNow())
        f3.script.advance(10_000)
        fake += read(fHost.wait, fHost.lineNow())
        fake += f3.retryAfterSeconds()
        assertEquals<List<Any?>>(engine, fake)

        // Where the server named no wait: the end has none, and its line is the plain one at any time.
        val w4 = world()
        val pw4 = w4.toPassword()
        w4.server.waitSeconds = null
        w4.server.tooMany[WireRoute.DEVICE_LINK_PICKUP] = 1
        assertEquals(LinkPasswordResult.RATE_LIMITED, w4.app.entry.submitLinkPassword(pw4, password))
        val none = w4.app.at<EntryScreen.LinkDeviceEnded>()
        assertNull(none.wait)
        w4.instance.now += 60_000
        assertEquals(tooMany, none.lineNow())
    }

    /**
     * A link the session keeper refuses because this device knows the link's address at that server under another
     * account stops with that address, at the pickup and at the approval, and its end offers the forgetting there as a
     * sign-in does; after the forgetting the next link links. Before: the bare identity fault, with no offer at the
     * approval.
     */
    @Test fun aLinkForAnAddressKnownHereUnderAnotherAccountOffersTheForgettingAtItsEnd() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        // The app signed in to the account and signed out: it remembers the address's account, kept nowhere here.
        w.instance.account(email).recoveryConfirmed = true
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), w.instance.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, a.entry.submitSignIn(a.at(), email, password))
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.signOut())
        val bindingKey = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX + w.instance.origin + "|" + email
        val identityKey = assertNotNull(a.engine.state.get(bindingKey)).substringAfter('|')
        // A stop before the pickup carries no served key: where this device holds a record of the link's account's key it
        // cannot tell a remade account from a substitution, and offers nothing (EngineDeviceLinkJoinTest). Here it holds none.
        a.engine.state.set("ovh.identity|" + w.instance.account(email).userId, null)
        // As after an account deleted and made again under the same address elsewhere: the record names an earlier one.
        val earlier = "00000000-0000-4000-8000-0000000000dd"
        fun pickups() = w.server.calls.count { it.second == WireRoute.DEVICE_LINK_PICKUP }

        // Just before the pickup.
        val pw = w.linkToPassword()
        a.engine.state.set(bindingKey, "$earlier|$identityKey")
        val before = pickups()
        assertEquals(LinkPasswordResult.IDENTITY_FAULT, a.entry.submitLinkPassword(pw, password))
        assertEquals(before, pickups(), "nothing picked up")
        val endedAtPickup = a.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT, endedAtPickup.outcome)
        assertEquals(email, assertNotNull(a.snapshot.earlierAccount, "offered at the pickup's end").email)
        a.entry.dismissLinkDevice(endedAtPickup)
        assertNull(a.snapshot.earlierAccount, "the offer goes with the screen it was raised on")

        // At the approval, before any password is asked.
        a.toLinkEntry()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        assertEquals(DeviceLinkScanResult.DONE, a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        assertTrue(a.entryFlow.pollDeviceLink())
        val code = a.at<EntryScreen.LinkDeviceCode>().code
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        assertIs<ExistingStep.Approved>(w.e.approve(assertIs<ExistingStep.Approvable>(w.e.typeDigits(type, code))))
        assertFalse(a.entryFlow.pollDeviceLink())
        val endedAtApproval = a.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT, endedAtApproval.outcome)
        assertEquals(before, pickups(), "nothing picked up")
        val offer = assertNotNull(a.snapshot.earlierAccount, "offered at the approval's end")
        assertEquals(email, offer.email)
        assertFalse(offer.keptCopy)

        // The forgetting there, after its second confirmation; then a link that links.
        assertTrue(a.entry.askToForgetEarlierAccount(offer))
        assertEquals(io.silencelen.andvari.core.app.ForgetEarlierResult.FORGOTTEN, a.entry.forgetEarlierAccount(assertNotNull(a.snapshot.earlierAccount)))
        assertNull(a.engine.state.get(bindingKey))
        (a.snapshot.entry as? EntryScreen.LinkDeviceEnded)?.let { a.entry.dismissLinkDevice(it) }
        assertEquals(LinkPasswordResult.DONE, a.entry.submitLinkPassword(w.linkToPassword(), password))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /**
     * The address's record here names the SAME account the server serves, under another identity key: the link ends with
     * the identity fault and offers no forgetting, whether the device's own record of that account's key is absent or
     * equals the key the server serves (the substitution the record exists to stop). Before: the pickup's end offered the
     * forgetting for that account, and after it the next link took the account under the server's key.
     */
    @Test fun aLinkForTheSameAccountUnderAnotherKeyEndsWithTheIdentityFaultAndOffersNothing() = runBlocking<Unit> {
        for (ownRecord in listOf("absent", "the served key")) {
            val w = world()
            val a = w.app
            w.instance.account(email).recoveryConfirmed = true
            a.entry.openSignIn(a.at())
            a.entry.openPasswordSignIn(a.at())
            assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), w.instance.origin))
            (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
            assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, a.entry.submitSignIn(a.at(), email, password))
            assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.signOut())
            val bindingKey = io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX + w.instance.origin + "|" + email
            val (userId, served) = assertNotNull(a.engine.state.get(bindingKey)).split('|')
            val another = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.randomBytes(32))
            a.engine.state.set(bindingKey, "$userId|$another")
            a.engine.state.set("ovh.identity|$userId", if (ownRecord == "absent") null else served)

            val pw = w.linkToPassword()
            assertEquals(LinkPasswordResult.IDENTITY_FAULT, a.entry.submitLinkPassword(pw, password), "own record $ownRecord")
            assertEquals(LinkDeviceEnd.IDENTITY_FAULT, a.at<EntryScreen.LinkDeviceEnded>().outcome)
            assertNull(a.snapshot.earlierAccount, "no offer to forget: own record $ownRecord")
            assertTrue(a.snapshot.phase != AppPhase.UNLOCKED)
            assertEquals("$userId|$another", a.engine.state.get(bindingKey), "the address's record stays")
        }
    }

    @Test fun twoStepAsksForTheCodeAndAKitNeverSavedIsMadeWithThePasswordGivenFirst() = runBlocking<Unit> {
        val w = world()
        w.instance.account(email).totp = "123456"
        val pw = w.toPassword()
        assertEquals(LinkPasswordResult.CODE_NEEDED, w.app.entry.submitLinkPassword(pw, password))
        val code = w.app.at<EntryScreen.LinkDevicePassword>()
        assertTrue(code.codeNeeded)
        assertEquals(LinkPasswordResult.DONE, w.app.entry.submitLinkCode(code, "123456"))
        // The account never confirmed a kit: the vault stays shut until a fresh one is saved.
        val kit = w.app.at<EntryScreen.Kit>()
        assertEquals(KitReason.NEVER_SAVED, kit.kit.reason)
        assertNotNull(w.app.kit.kitDocument(kit.kit))
    }

    @Test fun aPhoneRefusesTheOperatorAccountAfterTheLink() = runBlocking<Unit> {
        val w = world()
        w.instance.account(email).recoveryConfirmed = true
        w.server.pickupRole = "operator"
        val pw = w.toPassword()
        assertEquals(LinkPasswordResult.OPERATOR_NEEDS_COMPUTER, w.app.entry.submitLinkPassword(pw, password))
        assertEquals(AppPhase.ENTRY, w.app.snapshot.phase)
        assertEquals(FirstRunNotice.OPERATOR_NEEDS_COMPUTER, w.app.at<EntryScreen.FirstRun>().notice)
        assertNull(w.app.keeper.session, "nothing of the account is kept")
    }

    @Test fun digitsMistypedOnTheOtherDeviceEndTheLinkHere() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        a.toLinkEntry()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        assertEquals(DeviceLinkScanResult.DONE, a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        val fixed = assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
        assertTrue(a.entryFlow.pollDeviceLink())
        val code = a.at<EntryScreen.LinkDeviceCode>().code
        val type = assertIs<ExistingStep.TypeDigits>(w.e.advance(fixed))
        val wrong = ((code.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
        assertIs<ExistingStep.Stopped>(w.e.typeDigits(type, wrong))
        assertFalse(a.entryFlow.pollDeviceLink())
        val ended = a.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.CANCELLED, ended.outcome)
        a.entry.dismissLinkDevice(ended)
        a.at<EntryScreen.LinkDeviceEntry>()
    }

    @Test fun startingOverCancelsTheLinkAndItsPoll() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        a.toLinkEntry()
        val shown = assertIs<ExistingStep.Shown>(w.e.create())
        a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED)
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        a.at<EntryScreen.LinkDeviceWaiting>()
        a.entry.startOver()
        a.at<EntryScreen.FirstRun>()
        val polls = w.server.calls.count { it.second == WireRoute.DEVICE_LINK_POLL }
        assertFalse(a.entryFlow.pollDeviceLink())
        assertEquals(polls, w.server.calls.count { it.second == WireRoute.DEVICE_LINK_POLL }, "nothing polls a link given up")
        // E sees the claim, but the new device holds nothing to go on with: the engine dropped the link's keys.
        assertIs<ExistingStep.ClaimFixed>(w.e.advance(shown))
    }

    /** The device-link server, as the account [caller] (set once the existing device's account exists). */
    private class AsCaller(val server: DeviceLinkServer) : io.silencelen.andvari.core.client.net.WireClient {
        var caller: String? = null
        /** The step that waits for the approval ran out at the server: the approval is refused as the real server does. */
        var approvalStepRanOut = false
        override val origin: String get() = server.instance.origin
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            if (route == WireRoute.DEVICE_LINK_APPROVE && approvalStepRanOut) {
                server.calls += origin to route
                return io.silencelen.andvari.core.client.net.WireResult.Refused(410, io.silencelen.andvari.core.model.wire.WireError("link_expired", "m"))
            }
            return server.client(caller).call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /**
     * §8.2 from the existing device on the engine ([io.silencelen.andvari.core.app.DeviceLinkHost]): the link with the
     * server's name and origin to compare, the claim, the digits typed here, the approval behind the local unlock (a
     * wrong password sends nothing), and the new device signed in with the password afterwards.
     */
    @Test fun aLinkMadeOnThisDeviceIsApprovedWithTheMasterPasswordAndTheNewDeviceSignsIn() = runBlocking<Unit> {
        val w = world()
        val bobEmail = "bob@example.com"
        val wire = AsCaller(w.server)
        val e = EngineAppApi(
            AppEngine(AppPlatform.MACOS, "Laptop", BearerTransport(mapOf(w.instance.origin to wire)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { w.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        e.entry.openOwnServer(e.at())
        assertEquals(ServerResult.DONE, e.entry.submitServerAddress(e.at(), "h.example"))
        assertEquals(ServerResult.DONE, e.entry.confirmTrustGate(e.at()))
        assertEquals(ServerResult.DONE, e.entry.createAccountHere(e.at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, e.entry.startSignUp(e.at(), bobEmail, true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, e.entry.verifySignUpCode(e.at(), "482915"))
        assertEquals(io.silencelen.andvari.core.app.CreateAccountResult.DONE, e.entry.createAccount(e.at(), io.silencelen.andvari.core.app.NewAccountInput("", "Bob", password, true)))
        val kit = e.at<EntryScreen.Kit>()
        val doc = assertNotNull(e.kit.kitDocument(kit.kit))
        e.kit.proceedToConfirm(kit.kit)
        val confirm = e.at<EntryScreen.Kit>().kit
        assertEquals(io.silencelen.andvari.core.app.KitConfirmResult.DONE, e.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, e.snapshot.phase)
        wire.caller = e.keeper.session!!.userId
        w.instance.account(bobEmail).recoveryConfirmed = true
        val host = e.devices as EngineDevices

        // A link the server refuses to make as one of too many requests is said as that, with the wait it named: never
        // "unreachable" and never a general failure. Before: FAILED.
        w.server.tooMany[WireRoute.DEVICE_LINK_CREATE] = 1
        assertEquals(io.silencelen.andvari.core.app.PlainResult.RATE_LIMITED, e.devices.startDeviceLink())
        assertEquals(30, e.retryAfterSeconds())
        assertNull(e.snapshot.account!!.deviceLink, "no link was made")

        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, e.devices.startDeviceLink())
        val shown = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Shown>(e.snapshot.account!!.deviceLink)
        assertEquals(w.instance.origin, shown.instance.origin, "the address to compare with the new device's")
        val url = assertNotNull(e.devices.deviceLinkToShow(shown))
        assertTrue(e.devices.deviceLinkTimeLeftMs() > 0L)

        // The new device scans it.
        val n = w.app
        n.toLinkEntry()
        assertEquals(DeviceLinkScanResult.DONE, n.entry.submitDeviceLink(n.at(), url, PayloadSource.SCANNED))
        assertEquals(ServerResult.DONE, n.entry.confirmTrustGate(n.at<EntryScreen.TrustGate>()))
        assertTrue(host.pollDeviceLinkHost(), "claimed: it waits on the new device's reveal")
        val claimed = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Claimed>(e.snapshot.account!!.deviceLink)
        assertEquals("Pixel 9", claimed.deviceName)
        assertNull(e.devices.deviceLinkToShow(shown), "the link is no longer shown once claimed")
        assertTrue(n.entryFlow.pollDeviceLink())
        val code = n.at<EntryScreen.LinkDeviceCode>().code
        assertFalse(host.pollDeviceLinkHost(), "the poll stops at the digits")
        val type = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.TypeDigits>(e.snapshot.account!!.deviceLink)
        assertEquals(io.silencelen.andvari.core.app.DigitsResult.DONE, e.devices.submitDeviceDigits(type, code.chunked(3).joinToString(" ")))
        val approvable = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Approvable>(e.snapshot.account!!.deviceLink)
        assertFalse(approvable.biometricsOffered)
        val sent = w.server.calls.size
        assertEquals(io.silencelen.andvari.core.app.ProofResult.WRONG_PASSWORD, e.devices.approveWithPassword(approvable, "not the password at all 1"))
        assertEquals(sent, w.server.calls.size, "a wrong password sends nothing")
        // "Your devices" is open: once the link completes it is read again, without the person reopening it.
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, e.devices.openDevices())
        val reads = w.server.calls.count { it.second == WireRoute.DEVICES }
        assertEquals(io.silencelen.andvari.core.app.ProofResult.DONE, e.devices.approveWithPassword(approvable, password))
        assertEquals(reads + 1, w.server.calls.count { it.second == WireRoute.DEVICES }, "the devices list is read again after the link completed")
        assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Approved>(e.snapshot.account!!.deviceLink)
        assertEquals(AppPhase.UNLOCKED, e.snapshot.phase, "this device's account stays open")
        e.devices.dismissDeviceLink()
        assertNull(e.snapshot.account!!.deviceLink)

        assertFalse(n.entryFlow.pollDeviceLink())
        assertEquals(LinkPasswordResult.DONE, n.entry.submitLinkPassword(n.at(), password))
        assertEquals(AppPhase.UNLOCKED, n.snapshot.phase)
        assertEquals(bobEmail, n.snapshot.account!!.email)
    }

    /**
     * An existing device with quick unlock ([wrap], on unless [quickOn] is false) and an account of its own, with a link
     * it made claimed by [World.app] and the digits typed: answers it at "approve".
     */
    private suspend fun World.approvableOn(
        wrap: io.silencelen.andvari.core.client.session.TestKeyWrap, quickOn: Boolean = true,
        clocks: io.silencelen.andvari.core.client.session.TestClocks = io.silencelen.andvari.core.client.session.TestClocks(wall = instance.now),
        wire: AsCaller = AsCaller(server),
        /** How long the link waits, shown, before the new device claims it. */
        beforeClaimMs: Long = 0L,
    ): Pair<EngineAppApi, io.silencelen.andvari.core.app.DeviceLinkHost.Approvable> {
        val bobEmail = "bob@example.com"
        val e = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Phone", BearerTransport(mapOf(instance.origin to wire)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                keyWrap = wrap, clocks = clocks),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        e.entry.openOwnServer(e.at())
        assertEquals(ServerResult.DONE, e.entry.submitServerAddress(e.at(), "h.example"))
        assertEquals(ServerResult.DONE, e.entry.confirmTrustGate(e.at()))
        assertEquals(ServerResult.DONE, e.entry.createAccountHere(e.at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, e.entry.startSignUp(e.at(), bobEmail, true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, e.entry.verifySignUpCode(e.at(), "482915"))
        assertEquals(io.silencelen.andvari.core.app.CreateAccountResult.DONE, e.entry.createAccount(e.at(), io.silencelen.andvari.core.app.NewAccountInput("", "Bob", password, true)))
        val kit = e.at<EntryScreen.Kit>()
        val doc = assertNotNull(e.kit.kitDocument(kit.kit))
        e.kit.proceedToConfirm(kit.kit)
        val confirm = e.at<EntryScreen.Kit>().kit
        assertEquals(io.silencelen.andvari.core.app.KitConfirmResult.DONE, e.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        wire.caller = e.keeper.session!!.userId
        instance.account(bobEmail).recoveryConfirmed = true
        if (quickOn) {
            assertEquals(io.silencelen.andvari.core.app.QuickEnrolResult.DONE, e.settings.turnOnQuickUnlock(e.snapshot.account!!.quickUnlock))
        }
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, e.devices.startDeviceLink())
        val url = assertNotNull(e.devices.deviceLinkToShow(assertIs(e.snapshot.account!!.deviceLink)))
        clocks.advance(beforeClaimMs)
        val n = app
        n.toLinkEntry()
        assertEquals(DeviceLinkScanResult.DONE, n.entry.submitDeviceLink(n.at(), url, PayloadSource.SCANNED))
        assertEquals(ServerResult.DONE, n.entry.confirmTrustGate(n.at<EntryScreen.TrustGate>()))
        val host = e.devices as EngineDevices
        host.pollDeviceLinkHost()
        assertTrue(n.entryFlow.pollDeviceLink())
        val code = n.at<EntryScreen.LinkDeviceCode>().code
        host.pollDeviceLinkHost()
        assertEquals(io.silencelen.andvari.core.app.DigitsResult.DONE, e.devices.submitDeviceDigits(assertIs(e.snapshot.account!!.deviceLink), code))
        return e to assertIs(e.snapshot.account!!.deviceLink)
    }

    private fun World.approvals() = server.calls.count { it.second == WireRoute.DEVICE_LINK_APPROVE }

    /**
     * §8.2 step 6 with the device's own lock (rule of 2026-11-17): the session code's check behind the system's prompt.
     * A cancelled prompt leaves the link as it is; a lockout asks for the password; only a confirmed check approves,
     * and the prompt says what the app passed. Before, every call answered "use the password" and showed no prompt.
     */
    @Test fun aNewDeviceIsApprovedWithTheFingerprintOrFaceCheckOnlyWhenItConfirms() = runBlocking<Unit> {
        val w = world()
        val wrap = io.silencelen.andvari.core.client.session.TestKeyWrap()
        val (e, approvable) = w.approvableOn(wrap)
        assertTrue(approvable.biometricsOffered, "quick unlock is on here")
        wrap.next = io.silencelen.andvari.core.client.session.TestKeyWrap.Next.CANCEL
        assertEquals(io.silencelen.andvari.core.app.ProofResult.CANCELLED, e.devices.approveWithBiometrics(approvable, "Add Pixel 9 (android)?"))
        assertTrue(e.snapshot.account!!.deviceLink === approvable, "the link is as it was")
        wrap.next = io.silencelen.andvari.core.client.session.TestKeyWrap.Next.REFUSE
        assertEquals(io.silencelen.andvari.core.app.ProofResult.BIOMETRICS_NOT_USED, e.devices.approveWithBiometrics(approvable, null))
        assertEquals(0, w.approvals(), "nothing was approved")
        assertEquals(io.silencelen.andvari.core.app.QuickUnlockState.ON, e.snapshot.account!!.quickUnlock.state, "a lockout keeps quick unlock")
        assertEquals(io.silencelen.andvari.core.app.ProofResult.DONE, e.devices.approveWithBiometrics(approvable, "Add Pixel 9 (android)?"))
        assertEquals(1, w.approvals())
        assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Approved>(e.snapshot.account!!.deviceLink)
        assertEquals(3, wrap.confirmPrompts, "each was the confirmation prompt, never an unlock")
        assertEquals(listOf("Add Pixel 9 (android)?", null, "Add Pixel 9 (android)?"), wrap.reasons)
        assertTrue(wrap.released.all { s -> s.all { it == 0.toByte() } }, "every opened key was wiped")
        assertEquals(AppPhase.UNLOCKED, e.snapshot.phase)
    }

    /** A record that no longer opens switches quick unlock off and asks for the password; so does quick unlock never set up. */
    @Test fun aSwitchedOffOrMissingQuickUnlockAsksForTheMasterPasswordAndApprovesNothing() = runBlocking<Unit> {
        val w = world()
        val wrap = io.silencelen.andvari.core.client.session.TestKeyWrap()
        val (e, approvable) = w.approvableOn(wrap)
        wrap.next = io.silencelen.andvari.core.client.session.TestKeyWrap.Next.INVALIDATED
        assertEquals(io.silencelen.andvari.core.app.ProofResult.BIOMETRICS_NOT_USED, e.devices.approveWithBiometrics(approvable, null))
        assertEquals(io.silencelen.andvari.core.app.QuickUnlockState.OFF, e.snapshot.account!!.quickUnlock.state, "switched off by the check")
        val prompts = wrap.confirmPrompts
        assertEquals(io.silencelen.andvari.core.app.ProofResult.BIOMETRICS_NOT_USED, e.devices.approveWithBiometrics(approvable, null))
        assertEquals(prompts, wrap.confirmPrompts, "no prompt once it is off")
        assertEquals(0, w.approvals())
        assertEquals(io.silencelen.andvari.core.app.ProofResult.DONE, e.devices.approveWithPassword(approvable, password))
        assertEquals(1, w.approvals())

        val w2 = world()
        val wrap2 = io.silencelen.andvari.core.client.session.TestKeyWrap()
        val (e2, never) = w2.approvableOn(wrap2, quickOn = false)
        assertFalse(never.biometricsOffered)
        assertEquals(io.silencelen.andvari.core.app.ProofResult.BIOMETRICS_NOT_USED, e2.devices.approveWithBiometrics(never, null))
        assertEquals(0, wrap2.confirmPrompts)
        assertEquals(0, w2.approvals())
    }

    /** A lock while the prompt is up wins (spec 01, rule 5): nothing is approved and the link goes with the session. */
    @Test fun aLockWhileTheFingerprintOrFacePromptIsUpApprovesNothing() = runBlocking<Unit> {
        val w = world()
        val wrap = io.silencelen.andvari.core.client.session.TestKeyWrap()
        val (e, approvable) = w.approvableOn(wrap)
        val up = kotlinx.coroutines.CompletableDeferred<Unit>()
        wrap.openUp = up
        var result: io.silencelen.andvari.core.app.ProofResult? = null
        val job = kotlinx.coroutines.CoroutineScope(Dispatchers.Unconfined).launch { result = e.devices.approveWithBiometrics(approvable, null) }
        assertEquals(1, wrap.confirmPrompts, "the prompt is up")
        e.lock()
        up.complete(Unit)
        job.join()
        assertEquals(io.silencelen.andvari.core.app.ProofResult.STALE, result)
        assertEquals(0, w.approvals(), "nothing was approved")
        assertNull(e.snapshot.account)
        assertTrue(wrap.released.all { s -> s.all { it == 0.toByte() } }, "what was opened is wiped")
    }

    @Test fun aLinkMadeOnThisDeviceIsCancelledByALock() = runBlocking<Unit> {
        val w = world()
        val wire = AsCaller(w.server)
        val e = EngineAppApi(
            AppEngine(AppPlatform.MACOS, "Laptop", BearerTransport(mapOf(w.instance.origin to wire)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { w.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        e.entry.openOwnServer(e.at())
        assertEquals(ServerResult.DONE, e.entry.submitServerAddress(e.at(), "h.example"))
        assertEquals(ServerResult.DONE, e.entry.confirmTrustGate(e.at()))
        assertEquals(ServerResult.DONE, e.entry.createAccountHere(e.at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, e.entry.startSignUp(e.at(), "bob@example.com", true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, e.entry.verifySignUpCode(e.at(), "482915"))
        assertEquals(io.silencelen.andvari.core.app.CreateAccountResult.DONE, e.entry.createAccount(e.at(), io.silencelen.andvari.core.app.NewAccountInput("", "Bob", password, true)))
        val kit = e.at<EntryScreen.Kit>()
        val doc = assertNotNull(e.kit.kitDocument(kit.kit))
        e.kit.proceedToConfirm(kit.kit)
        val confirm = e.at<EntryScreen.Kit>().kit
        assertEquals(io.silencelen.andvari.core.app.KitConfirmResult.DONE, e.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        wire.caller = e.keeper.session!!.userId
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, e.devices.startDeviceLink())
        assertEquals(1, w.server.rows.size)
        e.lock()
        assertEquals(0, w.server.rows.size, "the link is cancelled at the server")
        assertEquals(0L, e.devices.deviceLinkTimeLeftMs())
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, e.unlock(e.snapshot.locked!!, password))
        assertNull(e.snapshot.account!!.deviceLink, "nothing of it comes back")
    }

    @Test fun onlyADeviceLinkIsTakenHere() = runBlocking<Unit> {
        val w = world()
        w.app.toLinkEntry()
        assertEquals(DeviceLinkScanResult.NOT_A_DEVICE_LINK, w.app.entry.submitDeviceLink(w.app.at(), "https://andvaripass.com/l#nope", PayloadSource.PASTED))
        assertEquals(DeviceLinkScanResult.NOT_A_DEVICE_LINK, w.app.entry.submitDeviceLink(w.app.at(), "hello", PayloadSource.PASTED))
        w.app.at<EntryScreen.LinkDeviceEntry>()
    }

    // ---- spec 01 §7: a device link on a device that already keeps the account ----

    private val second = "a whole Other master password 7"

    /**
     * The app signs in to Alice's account with the password (it now keeps it), then its server signs it out; the copy
     * stays. Answers the account's key, for the test to serve. The journey is back at the first screen.
     */
    private suspend fun World.keepsAliceSignedOut(): ByteArray {
        val a = app
        instance.account(email).recoveryConfirmed = true
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), instance.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        assertEquals(io.silencelen.andvari.core.app.SignInAnswer.DONE, a.entry.submitSignIn(a.at(), email, password))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        val uvk = assertNotNull(a.keeper.established).account.uvk.copyOut()
        a.keeper.endedByServer(instance.origin)
        a.signInAgain(assertNotNull(a.snapshot.locked))
        return uvk
    }

    /** The server holds [key] for Alice, wrapped under [typed] at a fresh salt, with that password's verifier. */
    private fun World.serves(key: ByteArray, typed: String) {
        val account = instance.account(email)
        val salt = crypto.randomBytes(io.silencelen.andvari.core.crypto.KdfParams.SALT_BYTES)
        val keys = assertNotNull(io.silencelen.andvari.core.client.onboard.PasswordKeys.derive(crypto, typed.toCharArray(), salt,
            io.silencelen.andvari.core.crypto.KdfParams.DEFAULT, served = false))
        try {
            account.kdfSalt = io.silencelen.andvari.core.crypto.Bytes.toB64(salt)
            account.kdfParams = io.silencelen.andvari.core.crypto.KdfParams.DEFAULT
            account.wrappedUvk = io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, keys.wrapKey, key, io.silencelen.andvari.core.crypto.Ad.uvk(account.userId))
            account.authKey = keys.authKeyB64
        } finally {
            keys.wipe()
        }
    }

    /** As [toPassword], on a device that may already hold a password pin for the server (no Trust Gate then). */
    private suspend fun World.linkToPassword(): EntryScreen.LinkDevicePassword {
        val a = app
        a.toLinkEntry()
        val shown = assertIs<ExistingStep.Shown>(e.create())
        assertEquals(DeviceLinkScanResult.DONE, a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val fixed = assertIs<ExistingStep.ClaimFixed>(e.advance(shown))
        assertTrue(a.entryFlow.pollDeviceLink())
        val code = a.at<EntryScreen.LinkDeviceCode>().code
        val type = assertIs<ExistingStep.TypeDigits>(e.advance(fixed))
        assertIs<ExistingStep.Approved>(e.approve(assertIs<ExistingStep.Approvable>(e.typeDigits(type, code))))
        assertFalse(a.entryFlow.pollDeviceLink())
        return a.at()
    }

    /**
     * The server serves another key for the account this device keeps, under the same password. The link ends with the
     * sign-in's own answer and sentence (before, "a check failed" with no way out), the session the pickup opened is
     * ended alone, by its refresh token (before, the logout, which ends every session of this device at that server),
     * and the kept copy is still this account's, as its server left it.
     */
    @Test fun aLinkWhoseServerServesAnotherKeyForTheKeptAccountEndsWithTheSignInsAnswerAndEndsOnlyItsOwnSession() = runBlocking<Unit> {
        val w = world()
        val uvk = w.keepsAliceSignedOut()
        uvk.fill(0)
        val userId = assertNotNull(w.app.keeper.session).userId
        val other = crypto.randomBytes(32)
        w.serves(other, password)
        other.fill(0)
        val pw = w.linkToPassword()
        val sentBefore = w.transport.sent.size
        val r = w.app.entry.submitLinkPassword(pw, password)
        assertEquals(LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, r, "never a general failure")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, r.sentence)
        val ended = w.app.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE, ended.outcome)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, ended.outcome.sentence)
        val after = w.transport.sent.drop(sentBefore).map { it.route }
        assertTrue(WireRoute.DEVICE_LINK_PICKUP in after)
        assertEquals(1, after.count { it == WireRoute.END_SESSION }, "the pickup's session is ended alone: $after")
        assertTrue(WireRoute.LOGOUT !in after, "never the logout, which ends every session of this device: $after")
        val kept = assertNotNull(w.app.keeper.session, "the kept copy stays")
        assertEquals(userId, kept.userId)
        assertTrue(kept.endedByServer)
        assertTrue(w.app.snapshot.phase != AppPhase.UNLOCKED)
    }

    /** The same key under another master password (changed elsewhere): linked, and said in the sign-in's one line. */
    @Test fun aLinkOverACopySealedUnderAnotherPasswordLinksAndSaysTheSignInsOneLine() = runBlocking<Unit> {
        val w = world()
        val uvk = w.keepsAliceSignedOut()
        try {
            w.serves(uvk, second)
        } finally {
            uvk.fill(0)
        }
        val pw = w.linkToPassword()
        assertEquals(LinkPasswordResult.DONE, w.app.entry.submitLinkPassword(pw, second))
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER, assertNotNull(w.app.snapshot.account).signInNotice?.key)
        w.app.dismissSignInNotice()
        assertNull(assertNotNull(w.app.snapshot.account).signInNotice)
    }

    /**
     * The password was changed on another device: the former one still opens this device's copy, and the server refuses
     * its proof. That is a result of its own with its own line, never "wrong password"; the link and its password screen
     * stay, a typo is still a wrong password, and the account's current password links (before: WRONG).
     */
    @Test fun aRefusedProofOfAPasswordThatOpensTheCopyHereKeepsTheLinksPasswordScreen() = runBlocking<Unit> {
        val w = world()
        val uvk = w.keepsAliceSignedOut()
        try {
            w.serves(uvk, second)
        } finally {
            uvk.fill(0)
        }
        val pw = w.linkToPassword()
        val r = w.app.entry.submitLinkPassword(pw, password)
        assertEquals(LinkPasswordResult.PROOF_REFUSED, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT, r.sentence)
        val still = w.app.at<EntryScreen.LinkDevicePassword>()
        assertFalse(still.codeNeeded)
        assertEquals(LinkPasswordResult.PROOF_REFUSED, w.app.entry.submitLinkPassword(still, password), "again: the link stays")
        assertEquals(LinkPasswordResult.WRONG, w.app.entry.submitLinkPassword(w.app.at(), "not the password at all 3"))
        assertEquals(LinkPasswordResult.DONE, w.app.entry.submitLinkPassword(w.app.at(), second))
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
    }

    /**
     * The fingerprint or face prompt is answered after the step that waits for the approval ran out at the server: the
     * server's refusal says so, the result says that the link expired, the screen shows the link ended as expired, and
     * nothing is cancelled for it.
     */
    @Test fun aFingerprintAnsweredAfterTheLinksTimeRanOutSaysTheLinkExpired() = runBlocking<Unit> {
        val w = world()
        val wrap = io.silencelen.andvari.core.client.session.TestKeyWrap()
        val clocks = io.silencelen.andvari.core.client.session.TestClocks(wall = w.instance.now)
        val wire = AsCaller(w.server)
        val (e, approvable) = w.approvableOn(wrap, clocks = clocks, wire = wire)
        clocks.advance(60 * 60_000L)
        wire.approvalStepRanOut = true
        val r = e.devices.approveWithBiometrics(approvable, "Add Pixel 9 (android)?")
        assertEquals(io.silencelen.andvari.core.app.ProofResult.LINK_EXPIRED, r)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_APPROVAL_LINK_EXPIRED, r.sentence)
        assertTrue(w.server.rows.values.none { it.state == "approved" }, "nothing was approved")
        assertEquals(0, w.server.calls.count { it.second == WireRoute.DEVICE_LINK_CANCEL }, "nothing is cancelled for it")
        val ended = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Ended>(e.snapshot.account!!.deviceLink)
        assertEquals(io.silencelen.andvari.core.app.DeviceLinkHostEnd.EXPIRED, ended.outcome)
    }

    /**
     * The server gives each step of a link its own five minutes, counted from when that step began. A link claimed four
     * minutes after it was made and approved by fingerprint two minutes later is still in time: it is approved, as with
     * the master password, and nothing is cancelled. Before, the device judged it by the time the link was made, refused
     * it as expired and cancelled the link.
     */
    @Test fun aFingerprintApprovalInTheStepsOwnTimeIsApprovedWhateverTheLinksFirstTimeSaid() = runBlocking<Unit> {
        for (byFingerprint in listOf(true, false)) {
            val w = world()
            val wrap = io.silencelen.andvari.core.client.session.TestKeyWrap()
            val clocks = io.silencelen.andvari.core.client.session.TestClocks(wall = w.instance.now)
            val (e, approvable) = w.approvableOn(wrap, clocks = clocks, beforeClaimMs = 4 * 60_000L)
            clocks.advance(2 * 60_000L)
            val r = if (byFingerprint) e.devices.approveWithBiometrics(approvable, "Add Pixel 9 (android)?") else e.devices.approveWithPassword(approvable, password)
            assertEquals(io.silencelen.andvari.core.app.ProofResult.DONE, r, "fingerprint: $byFingerprint")
            assertEquals(1, w.approvals())
            assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Approved>(e.snapshot.account!!.deviceLink)
            assertEquals(0, w.server.calls.count { it.second == WireRoute.DEVICE_LINK_CANCEL }, "nothing was cancelled")
        }
    }

    /** Each stop of a pickup that says its own way out has its own end and result; the rest stay as they were. */
    @Test fun eachPickupStopWithAWayOutHasItsOwnEndAndResult() = runBlocking<Unit> {
        val w = world()
        val f = w.app.entryFlow
        val stop = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.ANOTHER_SESSION_KEPT
        assertEquals(LinkDeviceEnd.ANOTHER_SESSION_KEPT, f.ended(stop))
        assertEquals(LinkPasswordResult.ANOTHER_SESSION_KEPT, f.pickupStopped(stop))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_ANOTHER_SESSION_KEPT, f.pickupStopped(stop).sentence)
        val keys = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.SERVER_KEYS_NOT_KNOWN_HERE
        assertEquals(LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE, f.ended(keys))
        assertEquals(LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, f.pickupStopped(keys))
        val unreachable = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.UNREACHABLE
        assertEquals(LinkPasswordResult.UNREACHABLE, f.pickupStopped(unreachable))
        // The keeper's identity fault (an address known here under another account or key) and the pickup's own identity
        // verdicts: the identity fault a sign-in has, never "a check failed" (before: ENDED with DID_NOT_CHECK_OUT).
        val identity = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.IDENTITY_MISMATCH
        assertEquals(LinkPasswordResult.IDENTITY_FAULT, f.pickupStopped(identity))
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT, f.ended(identity))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, f.ended(identity).sentence)
        assertEquals(LinkDeviceEnd.DID_NOT_CHECK_OUT, f.ended(io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.BUNDLE_UNOPENABLE))
        // The engine's newest stops (before: DID_NOT_CHECK_OUT and ENDED, "a check failed"): each its own end and result,
        // with its own sentence; the operator's account held here is never "another account is kept".
        val held = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.OPERATOR_ACCOUNT_HELD
        assertEquals(LinkDeviceEnd.OPERATOR_ACCOUNT_HELD, f.ended(held))
        assertEquals(LinkPasswordResult.OPERATOR_ACCOUNT_HELD, f.pickupStopped(held))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.OPERATOR_ACCOUNT_HELD_HERE, f.ended(held).sentence)
        val damaged = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.KEPT_COPY_DAMAGED
        assertEquals(LinkDeviceEnd.KEPT_COPY_DAMAGED, f.ended(damaged))
        assertEquals(LinkPasswordResult.KEPT_COPY_DAMAGED, f.pickupStopped(damaged))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.KEPT_COPY_DAMAGED, f.pickupStopped(damaged).sentence)
        val afterCode = io.silencelen.andvari.core.client.devicelink.DeviceLinkStop.REFUSED_AFTER_CODE
        assertEquals(LinkDeviceEnd.REFUSED_AFTER_CODE, f.ended(afterCode))
        assertEquals(LinkPasswordResult.REFUSED_AFTER_CODE, f.pickupStopped(afterCode))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_REFUSED_AFTER_CODE, f.ended(afterCode).sentence)
    }

    /**
     * "Forget the earlier account on this device" at a device link's pickup only for ANOTHER account (decided on 2026-11-19):
     * the address comes to be tied here, while the pickup is under way, to the link's own account under another key: the
     * identity fault and no offer (before: offered, and two taps removed the record that stops the substitution). Tied to
     * another account instead: offered as before.
     */
    @Test fun aPickupOffersTheForgettingOnlyForAnotherAccount() = runBlocking<Unit> {
        for (another in listOf(false, true)) {
            val w = world()
            val pw = w.toPassword()
            val u = w.instance.account(email).userId
            val earlier = if (another) "00000000-0000-4000-8000-0000000000aa" else u
            val otherKey = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey)
            // As a take writes it, after the keeper's ask before the pickup is sent: that account, a key that is not U's.
            w.meanwhile[WireRoute.DEVICE_LINK_PICKUP] = {
                w.app.engine.state.set(io.silencelen.andvari.core.client.session.SessionKeeper.EMAIL_BINDING_PREFIX + w.instance.origin + "|" + email, "$earlier|$otherKey")
            }
            assertEquals(LinkPasswordResult.IDENTITY_FAULT, w.app.entry.submitLinkPassword(pw, password), "another account: $another")
            assertNull(w.app.keeper.session, "nothing was taken")
            if (another) {
                assertEquals(earlier, assertNotNull(w.app.snapshot.earlierAccount, "another account: offered as before").earlierUserId)
            } else {
                assertNull(w.app.snapshot.earlierAccount, "the same account under another key: nothing is offered")
            }
        }
    }
}
