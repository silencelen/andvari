package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.TwoStepSetup
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.account.WireRecoverySettings
import io.silencelen.andvari.core.client.account.WireTwoStep
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.client.deletion.WireAccountDeletion
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The server's refusal of a password proof is a result of its own, apart from a wrong password typed here (spec 01 §7;
 * the re-key rule of 2026-11-16). On the engine's session a password is proven against this device's own wrap before
 * anything is sent, so a wrong one answers "wrong password" with nothing sent. A proof made with the right password that
 * the server refuses means that the server holds other keys for the account than this device knows: before, every place
 * that sends a proof answered that as "wrong password" too, and the person could only be told the password was wrong.
 */
class ProofRefusedApartTest {
    private val plain = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val newer = "a newer Battery 7 horse staple"

    /** The routes the fake instance does not serve, answered as the server would for the proof each carries. */
    private class Proofs(private val inner: WireClient, private val server: FakeInstance) : WireClient by inner {
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            val answer = when (route) {
                WireRoute.ACCOUNT_DELETE_PREVIEW -> """{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}"""
                WireRoute.TOTP_SETUP, WireRoute.ACCOUNT_DELETE -> {
                    server.calls += route
                    val key = Json.parseToJsonElement(bodyJson!!).jsonObject["currentAuthKey"]?.jsonPrimitive?.content
                    if (key != server.accounts.values.single().authKey) return WireResult.Refused(403, WireError("reauth_failed", "m"))
                    if (route == WireRoute.TOTP_SETUP) """{"secretBase32":"JBSWY3DPEHPK3PXP","otpauthUri":"otpauth://totp/x"}""" else """{"deletedAt":1}"""
                }
                else -> return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
            return WireResult.Ok(decode(answer), 200)
        }
    }

    private class Env(val server: FakeInstance, val liar: QuietReKeyTest.Liar, val keeper: SessionKeeper, val policies: KeptPolicies, val clocks: TestClocks, val trust: io.silencelen.andvari.core.client.pin.CardTrust, val state: MemoryDeviceState) {
        val client get() = keeper.clientFor(server.origin)
        val est get() = assertNotNull(keeper.established)
        val reauth get() = assertNotNull(keeper.reauth())

        fun settings() = WireAccountSettings(est.origin, est.emailNorm, assertNotNull(trust.pinFor(server.origin)).card0Hash, est.account, client, createCryptoProvider(), reauth, KdfParams.DEFAULT, thisDevice = est.deviceId)
        fun recovery() = WireRecoverySettings(est.origin, est.account, client, createCryptoProvider(), state, trust, reauth, settings()) { server.now }
        fun deletion() = WireAccountDeletion(est.userId, est.emailNorm, est.account.signing, client, createCryptoProvider(), reauth, { null }, { server.now }) {}
        fun twoStep() = WireTwoStep(client, reauth)

        /** How many requests that carry a proof reached the server. */
        fun proofsSent() = server.calls.count { it in PROOF_ROUTES }
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val liar = QuietReKeyTest.Liar(server)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to Proofs(liar, server))), secure, state, trust, plain)
        val clocks = TestClocks()
        val policies = KeptPolicies(state)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, plain), keeper, plain, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        assertNotNull(policies.fetch(keeper.clientFor(server.origin), clocks.wall))
        return Env(server, liar, keeper, policies, clocks, trust, state)
    }

    /** A re-key the server answered "done" and never stored: this device's proofs are under a salt the server does not hold. */
    private suspend fun Env.lied() {
        server.policyKdf = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)
        liar.change = QuietReKeyTest.Change.DONE_NOT_APPLIED
        keeper.lock()
        assertEquals(KeptUnlock.Unlocked, keeper.unlock(strong.toCharArray()))
        assertEquals(ReKeyOutcome.DONE, keeper.reKeyAfterOpening(strong.toCharArray()) { policies.fetch(it, clocks.wall)?.kdfParams })
        liar.change = QuietReKeyTest.Change.PASS
    }

    @Test fun everyPlaceThatSendsAProofAnswersTheServersRefusalApartFromAWrongPasswordTypedHere() = runBlocking<Unit> {
        val e = registered()
        e.lied()
        val refused = Reauthed.Refused(Reauthed.PROOF_REFUSED)

        // A wrong password typed here: proven on this device, nothing sent, at every place.
        val before = e.proofsSent()
        assertEquals(Reauthed.WrongPassword, e.settings().change("not it at all 1".toCharArray(), newer.toCharArray()))
        assertEquals(Reauthed.WrongPassword, e.settings().revoke("4fa07b6c-8b9e-4f1a-8b2c-3d4e5f6a7b8c", "not it at all 2".toCharArray()))
        assertEquals(Reauthed.WrongPassword, e.settings().setRequireLink(true, "not it at all 3".toCharArray()))
        assertEquals(Reauthed.WrongPassword, e.settings().rotateKit("not it at all 4".toCharArray()))
        assertEquals(Reauthed.WrongPassword, e.recovery().setPosture(RecoveryChoiceKind.PRIVATE, null, false, "not it at all 5".toCharArray()))
        assertEquals(DeletionOutcome.WrongPassword, e.deletion().delete("alice@example.com", "not it at all 6".toCharArray(), null))
        assertEquals(TwoStepSetup.WrongPassword, e.twoStep().setup("not it at all 7".toCharArray()))
        assertEquals(before, e.proofsSent(), "a wrong password typed here sends nothing")

        // The right password, whose proof the server refuses: its own result at every place, never a wrong password.
        assertEquals(refused, e.settings().change(strong.toCharArray(), newer.toCharArray()), "the password change")
        assertEquals(refused, e.settings().revoke("4fa07b6c-8b9e-4f1a-8b2c-3d4e5f6a7b8c", strong.toCharArray()), "a device's removal")
        assertEquals(refused, e.settings().setRequireLink(true, strong.toCharArray()), "the device-link requirement")
        assertEquals(refused, e.settings().rotateKit(strong.toCharArray()), "a new recovery kit")
        assertEquals(refused, e.recovery().setPosture(RecoveryChoiceKind.PRIVATE, null, false, strong.toCharArray()), "the recovery setting")
        assertEquals(DeletionOutcome.Refused(Reauthed.PROOF_REFUSED), e.deletion().delete("alice@example.com", strong.toCharArray(), null), "the account's deletion")
        assertEquals(TwoStepSetup.Refused(Reauthed.PROOF_REFUSED), e.twoStep().setup(strong.toCharArray()), "two-step sign-in's setup")
        assertEquals(before + 7, e.proofsSent(), "each sent its proof once")

        // The next opening settles the lie, and the same proofs are accepted.
        e.keeper.lock()
        assertEquals(KeptUnlock.Unlocked, e.keeper.unlock(strong.toCharArray()))
        e.keeper.reKeyAfterOpening(strong.toCharArray()) { e.policies.fetch(it, e.clocks.wall)?.kdfParams }
        assertTrue(e.settings().setRequireLink(true, strong.toCharArray()) is Reauthed.Done, "a proof after the settle is accepted")
    }

    private companion object {
        val PROOF_ROUTES = setOf(
            WireRoute.PASSWORD_CHANGE, WireRoute.DEVICE_REVOKE, WireRoute.REQUIRE_LINK, WireRoute.RECOVERY_SELF_SETUP,
            WireRoute.ACCOUNT_RECOVERY_PUT, WireRoute.ACCOUNT_DELETE, WireRoute.TOTP_SETUP,
        )
    }
}
