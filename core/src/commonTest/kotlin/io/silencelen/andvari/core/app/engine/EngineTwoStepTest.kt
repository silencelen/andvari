package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.client.session.TestClocks
import io.silencelen.andvari.core.client.session.TestKeyWrap
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.TotpCodeRequest
import io.silencelen.andvari.core.model.wire.TotpDisableRequest
import io.silencelen.andvari.core.model.wire.TotpSetupRequest
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.TotpStatus
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
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
 * Settings › Two-step sign-in on the engine (spec 03 rows 13 to 16): the engine's `WireTwoStep` over the kept session,
 * and the life of the key being set up, as the old controller gave it (kept across a lock and back on the confirm step
 * after the next unlock; ended by closing the screen, a sign-out, or its time running out, locked or not).
 */
class EngineTwoStepTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    /**
     * The TOTP routes of spec 03 §2 over [inner] (whose LOGIN already asks an enrolled account for its code): the
     * authenticator's current code is [code]; a confirmed setup makes it the account's.
     */
    private class TotpServer(val inner: FakeInstance) : WireClient {
        override val origin: String get() = inner.origin
        val code = "135790"
        var pendingSecret: String? = null
        var minted = 0

        /** A back-off of the proofs' or of the codes' is on: `429` after a right proof, before the code is looked at. */
        var lockedOut = false
        val bodies = ArrayList<String>()

        private fun refuse(status: Int, c: String): WireResult<Nothing> = WireResult.Refused(status, WireError(c, c))

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val a by lazy { inner.accounts.values.last() }
            if (route in TOTP) bodies += bodyJson ?: ""
            return when (route) {
                WireRoute.TOTP_STATUS -> WireResult.Ok(decode(WireJson.json.encodeToString(TotpStatus.serializer(), TotpStatus(a.totp != null, pendingSecret != null))), 200)
                WireRoute.TOTP_SETUP -> {
                    val b = WireJson.json.decodeFromString(TotpSetupRequest.serializer(), bodyJson ?: "{}")
                    // The server's order since 2026-11-16, for an enrolled account too: the proof, its back-off, the
                    // codes' back-off, then the code.
                    if (b.currentAuthKey == null) return refuse(403, "reauth_required")
                    if (b.currentAuthKey != a.authKey) return refuse(403, "reauth_failed")
                    if (lockedOut) return WireResult.Refused(429, WireError("rate_limited", "m"), retryAfterSeconds = 60)
                    if (a.totp != null && b.code != a.totp) return refuse(400, "bad_totp_code")
                    val secret = "JBSWY3DPEHPK3PX" + ('A' + minted++)
                    pendingSecret = secret
                    WireResult.Ok(decode(WireJson.json.encodeToString(TotpSetupResponse.serializer(),
                        TotpSetupResponse(secret, "otpauth://totp/andvari:alice@example.com?secret=$secret&issuer=andvari"))), 200)
                }
                WireRoute.TOTP_CONFIRM -> {
                    val b = WireJson.json.decodeFromString(TotpCodeRequest.serializer(), bodyJson!!)
                    if (pendingSecret == null) return refuse(400, "no_pending_totp")
                    if (b.code != code) return refuse(400, "bad_totp_code")
                    pendingSecret = null
                    a.totp = code
                    WireResult.Ok(decode("{}"), 200)
                }
                WireRoute.TOTP_DISABLE -> {
                    val b = WireJson.json.decodeFromString(TotpDisableRequest.serializer(), bodyJson!!)
                    val on = a.totp ?: return refuse(400, "totp_not_enrolled")
                    if (b.currentAuthKey != a.authKey) return refuse(403, "reauth_failed")
                    if (lockedOut) return WireResult.Refused(429, WireError("rate_limited", "m"), retryAfterSeconds = 60)
                    if (b.code != on) return refuse(400, "bad_totp_code")
                    a.totp = null
                    WireResult.Ok(decode("{}"), 200)
                }
                else -> inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }

        companion object {
            val TOTP = setOf(WireRoute.TOTP_STATUS, WireRoute.TOTP_SETUP, WireRoute.TOTP_CONFIRM, WireRoute.TOTP_DISABLE)
        }
    }

    private class Env(val server: FakeInstance, val totp: TotpServer, val transport: BearerTransport, val clocks: TestClocks, val app: EngineAppApi)

    private fun env(): Env {
        val server = FakeInstance(crypto)
        val totp = TotpServer(server)
        val transport = BearerTransport(mapOf(server.origin to totp))
        val clocks = TestClocks(wall = server.now)
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now }, baked = null, storeBuild = false,
                stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, keyWrap = TestKeyWrap(), clocks = clocks),
        ).also { it.start() }
        return Env(server, totp, transport, clocks, app)
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

    private fun EngineAppApi.twoStep() = snapshot.account?.twoStep

    @Test fun itIsTurnedOnWithThePasswordAndAFirstCodeAndOffWithACode() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertNull(a.twoStep())
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        val off = assertNotNull(a.twoStep())
        assertFalse(off.enabled)
        assertNull(off.enrolment)

        // Spec 01 §7: a wrong password sends no request at all, of any route (counted at the transport).
        val sent = e.transport.sent.size
        assertEquals(TwoStepResult.WRONG_PASSWORD, a.settings.startTwoStep(off, "not the password"))
        assertEquals(emptyList(), e.transport.sent.drop(sent).map { it.route }, "a wrong password sends nothing")
        assertNull(assertNotNull(a.twoStep()).enrolment)
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(off, strong))
        val enrolment = assertNotNull(assertNotNull(a.twoStep()).enrolment)
        val key = assertNotNull(a.settings.twoStepKey(enrolment))
        assertEquals(e.totp.pendingSecret, key.secret)
        assertTrue(key.uri.startsWith("otpauth://totp/andvari:h.example?secret=${key.secret}"), key.uri)
        // The password is never sent as such: the setup carries the re-authentication key only.
        assertTrue(e.totp.bodies.none { it.contains(strong) })
        assertTrue(e.totp.bodies.any { it.contains("currentAuthKey") })

        assertEquals(TwoStepResult.WRONG_CODE, a.settings.confirmTwoStep(enrolment, "000000"))
        assertEquals(TwoStepResult.WRONG_CODE, a.settings.confirmTwoStep(enrolment, "12345"), "not six digits: answered without a call")
        assertNotNull(a.settings.twoStepKey(enrolment), "a wrong code keeps the key up")
        assertEquals(TwoStepResult.DONE, a.settings.confirmTwoStep(enrolment, e.totp.code))
        val on = assertNotNull(a.twoStep())
        assertTrue(on.enabled)
        assertNull(on.enrolment)
        assertNull(a.settings.twoStepKey(enrolment), "the key is readable only while its enrolment is on show")
        assertEquals(e.totp.code, e.server.accounts.values.last().totp)
        assertEquals(TwoStepResult.STALE, a.settings.confirmTwoStep(enrolment, e.totp.code))
        assertEquals(TwoStepResult.NOT_PENDING, a.settings.startTwoStep(on, strong), "it is on already")

        // A code alone (decided on 2026-11-16): nothing is sent, and the answer says the password is needed.
        val bodiesBefore = e.totp.bodies.size
        assertEquals(TwoStepResult.PASSWORD_NEEDED, a.settings.turnOffTwoStep(on, e.totp.code))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.TWO_STEP_PASSWORD_NEEDED, TwoStepResult.PASSWORD_NEEDED.sentence)
        assertEquals(bodiesBefore, e.totp.bodies.size, "nothing was sent")
        // The server's order: a wrong password is said whatever the code; then the wait; then a wrong code.
        assertEquals(TwoStepResult.WRONG_PASSWORD, a.settings.turnOffTwoStepWithPassword(on, e.totp.code, "not the password at all"))
        assertEquals(TwoStepResult.WRONG_PASSWORD, a.settings.turnOffTwoStepWithPassword(on, e.totp.code, ""))
        e.totp.lockedOut = true
        assertEquals(TwoStepResult.TOO_MANY_TRIES, a.settings.turnOffTwoStepWithPassword(on, e.totp.code, strong))
        assertEquals(60, a.retryAfterSeconds(), "the wait the server named")
        e.totp.lockedOut = false
        assertEquals(TwoStepResult.WRONG_CODE, a.settings.turnOffTwoStepWithPassword(on, "000000", strong))
        val disable = WireJson.json.decodeFromString(TotpDisableRequest.serializer(), e.totp.bodies.last())
        assertEquals(e.server.accounts.values.last().authKey, disable.currentAuthKey, "the password's proof beside the code")
        assertEquals(TwoStepResult.DONE, a.settings.turnOffTwoStepWithPassword(on, e.totp.code, strong))
        assertFalse(assertNotNull(a.twoStep()).enabled)
        assertNull(e.server.accounts.values.last().totp)
        assertEquals(TwoStepResult.STALE, a.settings.turnOffTwoStepWithPassword(on, e.totp.code, strong), "only the screen on show")
        a.settings.closeTwoStep()
        assertNull(a.twoStep())
    }

    /**
     * A new authenticator key while two-step sign-in is on: the current code and the master password (decided on
     * 2026-11-16: the server checks the password first). The new key waits for its first code; the old one is in force
     * until then. Before, a code alone replaced the key.
     */
    @Test fun aNewKeyWhileItIsOnTakesTheCodeAndThePassword() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(assertNotNull(a.twoStep()), strong))
        assertEquals(TwoStepResult.DONE, a.settings.confirmTwoStep(assertNotNull(assertNotNull(a.twoStep()).enrolment), e.totp.code))
        val on = assertNotNull(a.twoStep())
        assertTrue(on.enabled)
        val minted = e.totp.minted
        assertEquals(TwoStepResult.WRONG_PASSWORD, a.settings.replaceTwoStepKey(on, e.totp.code, "not the password at all"))
        assertEquals(TwoStepResult.WRONG_CODE, a.settings.replaceTwoStepKey(on, "000000", strong))
        e.totp.lockedOut = true
        assertEquals(TwoStepResult.TOO_MANY_TRIES, a.settings.replaceTwoStepKey(on, e.totp.code, strong))
        e.totp.lockedOut = false
        assertEquals(minted, e.totp.minted, "no key was minted for a refusal")
        assertEquals(TwoStepResult.DONE, a.settings.replaceTwoStepKey(on, e.totp.code, strong))
        val body = WireJson.json.decodeFromString(TotpSetupRequest.serializer(), e.totp.bodies.last())
        assertEquals(e.totp.code, body.code)
        assertEquals(e.server.accounts.values.last().authKey, body.currentAuthKey, "the password's proof beside the code")
        val replacing = assertNotNull(a.twoStep())
        assertTrue(replacing.enabled, "the old key is in force until the new one is confirmed")
        val enrolment = assertNotNull(replacing.enrolment)
        assertEquals(e.totp.pendingSecret, assertNotNull(a.settings.twoStepKey(enrolment)).secret)
        assertEquals(TwoStepResult.DONE, a.settings.confirmTwoStep(enrolment, e.totp.code))
        assertNull(assertNotNull(a.twoStep()).enrolment)
        // Off: there is no key to replace, and nothing is sent.
        e.server.accounts.values.last().totp = null
        a.settings.closeTwoStep()
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        val bodies = e.totp.bodies.size
        assertEquals(TwoStepResult.NOT_PENDING, a.settings.replaceTwoStepKey(assertNotNull(a.twoStep()), e.totp.code, strong))
        assertEquals(bodies, e.totp.bodies.size)
    }

    @Test fun theKeyBeingSetUpOutlivesALockAndTheScreenComesBackOnItsConfirmStep() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(a.twoStep()!!, strong))
        val before = assertNotNull(a.settings.twoStepKey(a.twoStep()!!.enrolment!!))
        a.lock()
        assertTrue(a.twoStepFlow.holdsKey(), "a lock keeps the key for the trip to the authenticator")
        e.clocks.advance(EngineTwoStep.PENDING_MS - 60_000L)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val back = assertNotNull(a.twoStep(), "the screen is open again")
        val enrolment = assertNotNull(back.enrolment, "on its confirm step")
        assertEquals(before.secret, assertNotNull(a.settings.twoStepKey(enrolment)).secret)
        assertEquals(TwoStepResult.DONE, a.settings.confirmTwoStep(enrolment, e.totp.code))
        assertTrue(a.twoStep()!!.enabled)
    }

    @Test fun aKeyPastItsTimeIsGoneLockedOrNot() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(a.twoStep()!!, strong))
        a.lock()
        e.clocks.advance(EngineTwoStep.PENDING_MS)
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertNull(a.twoStep(), "nothing to resume")
        assertFalse(a.twoStepFlow.holdsKey())

        // Unlocked: the screen goes back to its start once the time is up.
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(a.twoStep()!!, strong))
        val enrolment = a.twoStep()!!.enrolment!!
        e.clocks.advance(EngineTwoStep.PENDING_MS)
        assertNull(a.settings.twoStepKey(enrolment))
        val sent = e.totp.bodies.size
        assertEquals(TwoStepResult.NOT_PENDING, a.settings.confirmTwoStep(enrolment, e.totp.code))
        assertEquals(sent, e.totp.bodies.size, "nothing is sent for a key past its time")
        assertNull(a.twoStep()!!.enrolment)
        assertFalse(a.twoStepFlow.holdsKey())
    }

    @Test fun closingTheScreenOrSigningOutEndsTheKey() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(a.twoStep()!!, strong))
        a.settings.closeTwoStep()
        assertFalse(a.twoStepFlow.holdsKey())
        assertNull(a.twoStep())

        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertNull(a.twoStep()!!.enrolment, "the server still waits, but this device no longer holds the key")
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(a.twoStep()!!, strong))
        a.lock()
        assertEquals(PlainResult.DONE, a.signOutConfirmed(kotlin.test.assertNotNull(a.signOutCheck())))
        assertFalse(a.twoStepFlow.holdsKey(), "a sign-out ends it, locked or not")
        assertEquals(PlainResult.STALE, a.settings.openTwoStep())
    }

    @Test fun aConfirmTheServerNoLongerWaitsForSaysSoAndShowsWhatIs() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        open(a)
        assertEquals(PlainResult.DONE, a.settings.openTwoStep())
        assertEquals(TwoStepResult.DONE, a.settings.startTwoStep(a.twoStep()!!, strong))
        // Confirmed from elsewhere meanwhile.
        e.totp.pendingSecret = null
        e.server.accounts.values.last().totp = e.totp.code
        assertEquals(TwoStepResult.NOT_PENDING, a.settings.confirmTwoStep(a.twoStep()!!.enrolment!!, e.totp.code))
        val now = assertNotNull(a.twoStep())
        assertTrue(now.enabled)
        assertNull(now.enrolment)
        assertFalse(a.twoStepFlow.holdsKey())
    }
}
