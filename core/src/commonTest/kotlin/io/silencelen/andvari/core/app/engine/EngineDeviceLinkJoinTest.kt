package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.EarlierAccountKnown
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.WireDeviceLinks
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
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A device link's end offers "Forget the earlier account on this device" only where the engine's stop names the address
 * AND the account served there is ANOTHER account than the one this device ties the address to (decided on 2026-11-19):
 * at the approval, at the ask just before the pickup, and at the pickup's take, once each and never twice. A stop before
 * the pickup carries the link's account id but no served key, so where this device holds a record of that account's key
 * (its identity record, or the record a forgetting kept) it cannot tell a remade account from a substitution, and offers
 * nothing. Over the real engine, against [DeviceLinkServer]; the account U is registered there by an existing device.
 */
class EngineDeviceLinkJoinTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"
    private val email = "alice@example.com"
    /** The account this device ties the address to, as after U was deleted and made again elsewhere (V here). */
    private val v = "00000000-0000-4000-8000-0000000000bb"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    /** [inner], except that a route in [meanwhile] runs its act once, when the app's request on it arrives. */
    private class Meanwhile(
        private val inner: io.silencelen.andvari.core.client.net.WireClient, val meanwhile: MutableMap<WireRoute, () -> Unit>,
    ) : io.silencelen.andvari.core.client.net.WireClient {
        override val origin: String get() = inner.origin
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
            meanwhile.remove(route)?.invoke()
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private class World(
        val instance: FakeInstance, val server: DeviceLinkServer, val e: WireDeviceLinks, val app: EngineAppApi,
        val meanwhile: MutableMap<WireRoute, () -> Unit>,
    ) {
        /** Every distinct offer object the app published, in order. */
        val offers = ArrayList<EarlierAccountKnown>()
        val u: String get() = instance.account("alice@example.com").userId
        val uKey: String get() = instance.account("alice@example.com").identityPub
        val bindingKey: String get() = SessionKeeper.EMAIL_BINDING_PREFIX + instance.origin + "|alice@example.com"
        fun pickups() = server.calls.count { it.second == WireRoute.DEVICE_LINK_PICKUP }
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
        instance.account(email).recoveryConfirmed = true
        val meanwhile = HashMap<WireRoute, () -> Unit>()
        val transport = BearerTransport(mapOf(instance.origin to Meanwhile(server.client(null), meanwhile)))
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel 9", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { instance.now }, baked = null,
                storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
        val w = World(instance, server, e, app, meanwhile)
        app.observe { s -> s.earlierAccount?.let { o -> if (w.offers.none { it === o }) w.offers += o } }
        return w
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun randomKey(): String = Bytes.toB64(crypto.randomBytes(32))

    /** The link scanned, its server confirmed, the code typed on the existing device and approved; then the app's poll. */
    private suspend fun World.approved() {
        val a = app
        if (a.snapshot.entry !is EntryScreen.LinkDeviceEntry) {
            a.entry.openSignIn(a.at())
            a.entry.openLinkDevice(a.at())
        }
        val shown = assertIs<ExistingStep.Shown>(e.create())
        assertEquals(DeviceLinkScanResult.DONE, a.entry.submitDeviceLink(a.at(), shown.url, PayloadSource.SCANNED))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        val fixed = assertIs<ExistingStep.ClaimFixed>(e.advance(shown))
        assertTrue(a.entryFlow.pollDeviceLink())
        val code = a.at<EntryScreen.LinkDeviceCode>().code
        val type = assertIs<ExistingStep.TypeDigits>(e.advance(fixed))
        assertIs<ExistingStep.Approved>(e.approve(assertIs<ExistingStep.Approvable>(e.typeDigits(type, code))))
        assertFalse(a.entryFlow.pollDeviceLink())
    }

    /** The link's end, with the identity fault, and back to the link's first screen. */
    private fun World.endedWithTheIdentityFault(end: LinkDeviceEnd = LinkDeviceEnd.IDENTITY_FAULT): EntryScreen.LinkDeviceEnded {
        val ended = app.at<EntryScreen.LinkDeviceEnded>()
        assertEquals(end, ended.outcome)
        assertNull(app.keeper.session, "nothing was taken")
        assertTrue(app.snapshot.phase != AppPhase.UNLOCKED)
        return ended
    }

    /** What this device holds of U's key, for the cases that hold one. */
    private enum class UKey { NONE, IDENTITY_RECORD, KEPT_RECORD }

    private fun World.plant(record: UKey) {
        val st = app.engine.state
        st.set(bindingKey, "$v|${randomKey()}")
        when (record) {
            UKey.NONE -> {}
            UKey.IDENTITY_RECORD -> st.set("ovh.identity|$u", uKey)
            UKey.KEPT_RECORD -> st.set(SessionKeeper.EARLIER_IDENTITY_PREFIX + instance.origin + "|" + u, uKey)
        }
    }

    // ---- 1 and 2: at the approval ----

    @Test fun atTheApprovalTheOfferIsMadeOnlyWhereThisDeviceHoldsNoRecordOfTheLinkedAccountsKey() = runBlocking<Unit> {
        for (record in UKey.entries) {
            val w = world()
            w.plant(record)
            w.approved()
            // Where it cannot tell, the link's end says a line of its own, which points to the password sign-in.
            val ended = w.endedWithTheIdentityFault(if (record == UKey.NONE) LinkDeviceEnd.IDENTITY_FAULT else LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL)
            if (record != UKey.NONE) assertEquals(io.silencelen.andvari.core.app.CopyKey.DEVICE_LINK_IDENTITY_CANNOT_TELL, ended.outcome.sentence)
            assertEquals(0, w.pickups(), "$record: nothing picked up")
            if (record == UKey.NONE) {
                val offer = assertNotNull(w.app.snapshot.earlierAccount, "no record of U's key: offered")
                assertEquals(v, offer.earlierUserId)
                assertEquals(w.u, offer.servedUserId, "the served account")
                assertEquals(1, w.offers.size, "one offer")
            } else {
                assertNull(w.app.snapshot.earlierAccount, "$record: the device cannot tell, and offers nothing")
                assertEquals(0, w.offers.size, "$record: never offered")
            }
        }
    }

    // ---- 3: the same two at the ask just before the pickup ----

    @Test fun atTheAskBeforeThePickupTheOfferIsMadeOnlyWhereThisDeviceHoldsNoRecordOfTheLinkedAccountsKey() = runBlocking<Unit> {
        for (record in UKey.entries) {
            val w = world()
            w.approved()
            val pw = w.app.at<EntryScreen.LinkDevicePassword>()
            w.plant(record)
            assertEquals(LinkPasswordResult.IDENTITY_FAULT, w.app.entry.submitLinkPassword(pw, password), "$record")
            w.endedWithTheIdentityFault()
            assertEquals(0, w.pickups(), "$record: nothing picked up")
            if (record == UKey.NONE) {
                val offer = assertNotNull(w.app.snapshot.earlierAccount, "no record of U's key: offered")
                assertEquals(v, offer.earlierUserId)
                assertEquals(w.u, offer.servedUserId)
                assertEquals(1, w.offers.size, "one offer")
            } else {
                assertNull(w.app.snapshot.earlierAccount, "$record: the device cannot tell, and offers nothing")
                assertEquals(0, w.offers.size, "$record: never offered")
            }
        }
    }

    // ---- 4: at the pickup's take ----

    @Test fun atThePickupsTakeTheSameAccountUnderAnotherKeyIsNotOfferedAndAnotherAccountIsOfferedOnce() = runBlocking<Unit> {
        for (another in listOf(false, true)) {
            val w = world()
            w.approved()
            val pw = w.app.at<EntryScreen.LinkDevicePassword>()
            val tiedTo = if (another) v else w.u
            // As a take writes it, after the ask before the pickup was answered: the take meets it.
            w.meanwhile[WireRoute.DEVICE_LINK_PICKUP] = { w.app.engine.state.set(w.bindingKey, "$tiedTo|${randomKey()}") }
            assertEquals(LinkPasswordResult.IDENTITY_FAULT, w.app.entry.submitLinkPassword(pw, password), "another account: $another")
            assertEquals(1, w.pickups(), "picked up")
            w.endedWithTheIdentityFault()
            if (another) {
                val offer = assertNotNull(w.app.snapshot.earlierAccount, "another account: offered")
                assertEquals(v, offer.earlierUserId)
                assertEquals(w.u, offer.servedUserId)
                assertEquals(1, w.offers.size, "exactly one offer, not two")
            } else {
                assertNull(w.app.snapshot.earlierAccount, "the same account under another key: nothing is offered")
                assertEquals(0, w.offers.size)
            }
        }
    }

    // ---- 5: U forgotten, V taken, a link for U served under another key ----

    @Test fun anEarlierAccountKeptOnRecordAndServedUnderAnotherKeyIsRefusedWithNoOfferAtTheApprovalAndAtTheTake() = runBlocking<Unit> {
        for (at in listOf("approval", "take")) {
            val w = world()
            val vKey = randomKey()
            // U was forgotten here (its key kept on record: not the key the server serves now), and V was taken under the address.
            fun plant() {
                val st = w.app.engine.state
                st.set(SessionKeeper.EARLIER_IDENTITY_PREFIX + w.instance.origin + "|" + w.u, randomKey())
                st.set(w.bindingKey, "$v|$vKey")
                st.set("ovh.identity|$v", vKey)
            }
            if (at == "approval") {
                plant()
                w.approved()
                assertEquals(0, w.pickups())
            } else {
                w.approved()
                val pw = w.app.at<EntryScreen.LinkDevicePassword>()
                w.meanwhile[WireRoute.DEVICE_LINK_PICKUP] = { plant() }
                assertEquals(LinkPasswordResult.IDENTITY_FAULT, w.app.entry.submitLinkPassword(pw, password))
                assertEquals(1, w.pickups())
            }
            // At the approval the device cannot tell from the link alone; at the take it can, with the served key.
            w.endedWithTheIdentityFault(if (at == "approval") LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL else LinkDeviceEnd.IDENTITY_FAULT)
            assertNull(w.app.snapshot.earlierAccount, "at the $at: no offer to forget V")
            assertEquals(0, w.offers.size, "at the $at: never offered")
            assertEquals("$v|$vKey", w.app.engine.state.get(w.bindingKey), "at the $at: the address's record stays")
        }
    }

    // ---- 6: a forgetting from the link's end, then a link that links ----

    @Test fun aForgettingFromTheLinksEndIsFollowedByALinkThatLinks() = runBlocking<Unit> {
        val w = world()
        w.plant(UKey.NONE)
        w.approved()
        w.endedWithTheIdentityFault()
        val offer = assertNotNull(w.app.snapshot.earlierAccount)
        assertTrue(w.app.entry.askToForgetEarlierAccount(offer))
        assertEquals(ForgetEarlierResult.FORGOTTEN, w.app.entry.forgetEarlierAccount(assertNotNull(w.app.snapshot.earlierAccount)))
        assertNull(w.app.engine.state.get(w.bindingKey), "the address is new to this device")
        (w.app.snapshot.entry as? EntryScreen.LinkDeviceEnded)?.let { w.app.entry.dismissLinkDevice(it) }
        w.approved()
        assertEquals(LinkPasswordResult.DONE, w.app.entry.submitLinkPassword(w.app.at(), password))
        assertEquals(AppPhase.UNLOCKED, w.app.snapshot.phase)
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
    }
}
