package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PreloginRequest
import io.silencelen.andvari.core.model.wire.PreloginResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Password change, kit rotation, devices and require-link (spec 03 §3, §16.7, §16.8), every one through [Reauth]. */
class AccountSettingsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val next = "a whole new Passphrase 42 here"

    private class Env(val server: FakeInstance, val onboarding: WireOnboarding, val session: EstablishedSession, val settings: WireAccountSettings, val pins: MutableList<GatePin>)

    private suspend fun env(): Env {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val sessions = ArrayList<EstablishedSession>()
        val o = WireOnboarding(server.origin, server, server.pinnedTrust(state), KnownDevices(state, crypto), SessionSink { sessions += it }, crypto, state,
            "android", "Pixel", { server.now }, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = o.signupVerify("alice@example.com", "482915") as SignupVerify.Ticket
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
            RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")))
        val pins = mutableListOf(GatePin(server.origin, PinRoot.TRUST_GATE))
        val reauth = Reauth(object : ReauthSession {
            override val origin = server.origin
            override val emailNorm = "alice@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? {
                val p = (server.call(WireRoute.PRELOGIN, bodyJson = WireJson.json.encodeToString(PreloginRequest.serializer(), PreloginRequest(emailNorm)),
                    decode = { WireJson.json.decodeFromString(PreloginResponse.serializer(), it) }) as WireResult.Ok).value
                val k = PasswordKeys.derive(crypto, password.copyOf(), Bytes.fromB64(p.kdfSalt), p.kdfParams, served = true) ?: return null
                return k.authKeyB64.also { k.wipe() }
            }
        }) { pins }
        val s = sessions.single()
        return Env(server, o, s, WireAccountSettings(server.origin, "alice@example.com", server.card0Hash, s.account, server, crypto, reauth, io.silencelen.andvari.core.crypto.KdfParams.DEFAULT), pins)
    }

    @Test fun changeThePasswordThenSignInWithIt() = runBlocking<Unit> {
        val e = env()
        val cur = strong.toCharArray()
        val nw = next.toCharArray()
        assertEquals(Reauthed.PasswordTooWeak, e.settings.change(strong.toCharArray(), "weak".toCharArray()))
        // This session derives its proof without a wrap of its own: the server's refusal is its own result.
        assertEquals(Reauthed.Refused(Reauthed.PROOF_REFUSED), e.settings.change("not it at all 7A!".toCharArray(), next.toCharArray()))
        assertIs<Reauthed.Done<Unit>>(e.settings.change(cur, nw))
        assertTrue(cur.all { it == '\u0000' } && nw.all { it == '\u0000' })
        assertEquals(SignIn.InvalidCredentials, e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        assertIs<SignIn.SignedIn>(e.onboarding.signIn("alice@example.com", next.toCharArray()))
    }

    @Test fun noSessionPinSendsNothing() = runBlocking<Unit> {
        val e = env()
        e.pins.clear()
        e.pins += GatePin(e.server.origin, PinRoot.TRUST_GATE, blocked = true)
        val before = e.server.calls.size
        assertEquals(Reauthed.NoSession, e.settings.setRequireLink(true, strong.toCharArray()))
        assertEquals(before, e.server.calls.size)
    }

    @Test fun rotateTheKitAndManageDevices() = runBlocking<Unit> {
        val e = env()
        val a = e.server.account("alice@example.com")
        val oldPiece = a.pieceId
        val kit = assertIs<Reauthed.Done<io.silencelen.andvari.core.client.onboard.RevealedKit>>(e.settings.rotateKit(strong.toCharArray())).value
        assertNotEquals(oldPiece, a.pieceId)
        assertEquals(a.pieceId, kit.pieceId)
        assertEquals(e.server.card0Hash, RecoveryKit.parseQr(kit.qr)!!.card0Hash)
        assertEquals(e.session.account.accountId(crypto), kit.accountId)
        val devices = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.Device>>>(e.settings.list()).value
        assertEquals(1, devices.size)
        assertEquals(Reauthed.Done(true), e.settings.setRequireLink(true, strong.toCharArray()))
        assertTrue(a.requireLink)
        assertEquals("bad_device_id", assertIs<Reauthed.Refused>(e.settings.revoke("../x", strong.toCharArray())).code)
        assertIs<Reauthed.Done<Unit>>(e.settings.revoke(devices.single().deviceId, strong.toCharArray()))
        assertFalse(a.devices.isNotEmpty())
    }
}
