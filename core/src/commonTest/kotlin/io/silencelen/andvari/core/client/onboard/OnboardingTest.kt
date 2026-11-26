package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.pin.CardTrust
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.recovery.RecoveryMirror
import io.silencelen.andvari.core.client.state.StoredAccountState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RegisterAuth
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.SignedFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Sign-up, registration and sign-in (design §7.2, §7.3, §8.7, §5.2) against [FakeInstance]. */
class OnboardingTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private class Sink : SessionSink {
        val sessions = ArrayList<EstablishedSession>()
        override suspend fun established(session: EstablishedSession) { sessions += session }
    }

    private class Env(val server: FakeInstance, val trust: CardTrust, val state: MemoryDeviceState, val sink: Sink, val onboarding: WireOnboarding)

    private fun env(server: FakeInstance, trust: CardTrust, state: MemoryDeviceState = MemoryDeviceState(), links: LinkRegistrations? = null): Env {
        val sink = Sink()
        val o = WireOnboarding(server.origin, server, trust, KnownDevices(state, crypto), sink, crypto, state, "android", "Pixel", { server.now },
            links = links, work = Dispatchers.Unconfined)
        return Env(server, trust, state, sink, o)
    }

    private suspend fun pinned(server: FakeInstance = FakeInstance(crypto), state: MemoryDeviceState = MemoryDeviceState(), links: LinkRegistrations? = null) =
        env(server, server.pinnedTrust(state), state, links)

    private fun form(email: String = "alice@example.com", password: String = strong, recovery: RecoveryChoiceKind = RecoveryChoiceKind.PRIVATE,
                     offer: OperatorRecoveryOffer? = null, understood: Boolean = false) =
        RegistrationForm(email, "Alice", password.toCharArray(), true, recovery, "Pixel", "android", offer, understood)

    private suspend fun ticket(e: Env, email: String = "alice@example.com"): SignupVerify.Ticket {
        assertEquals(SignupStart.Sent, e.onboarding.signupStart(email, true))
        return assertIs<SignupVerify.Ticket>(e.onboarding.signupVerify(email, "482915"))
    }

    /**
     * A new session's tokens are handed over once ([EstablishedSession.takeTokens]), and a
     * host rebuilds an established session from the tokens it kept with the public [EstablishedSession.reopened]: tokens
     * in, none out, and only for the account its password opened.
     */
    @Test fun aSessionsTokensAreHandedOverOnceAndAReopenedSessionIsTheAccountsOwn() = runBlocking<Unit> {
        val e = pinned()
        registered(e)
        val s = e.sink.sessions.single()
        val t = assertNotNull(s.takeTokens())
        assertEquals(s.accessToken, t.accessToken)
        assertEquals(s.refreshToken, t.refreshToken)
        assertNull(s.takeTokens(), "once")

        val keys = e.server.keys(e.server.account("alice@example.com"))
        val opened = assertIs<PasswordOpen.Opened>(AccountOpen.openWithPassword(crypto, s.userId, strong.toCharArray(), keys, e.server.instanceId)).account
        fun reopen(userId: String = s.userId, access: String = t.accessToken, k: io.silencelen.andvari.core.model.wire.AccountKeys = keys) =
            EstablishedSession.reopened(s.origin, s.emailNorm, userId, s.deviceId, s.role, s.totpEnrolled, s.mustEnrollTotp, SessionHow.PASSWORD,
                access, t.refreshToken, k, opened)
        val again = assertNotNull(reopen())
        assertEquals(s.userId, again.userId)
        assertEquals(t.accessToken, again.accessToken)
        assertNull(again.takeTokens(), "tokens in, none out")
        assertNull(reopen(userId = "22222222-2222-4222-8222-222222222222"), "another account's id")
        assertNull(reopen(access = ""), "an empty token")
        assertNull(reopen(k = keys.copy(identityPub = io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 7 }))), "another account's keys")

        // The command line's need: the password proven against the session's own wrap in one pass, nothing dialed.
        val sent = e.server.calls.size
        val pw = strong.toCharArray()
        val proof = assertIs<io.silencelen.andvari.core.client.account.ReauthKey.Key>(again.proveAuthKey(crypto, pw))
        assertEquals(e.server.account("alice@example.com").authKey, proof.currentAuthKey, "the server's own auth key")
        assertTrue(pw.all { it == '\u0000' }, "the password is wiped")
        assertEquals(io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword, again.proveAuthKey(crypto, "not the password at all 1".toCharArray()))
        val weak = assertNotNull(reopen(k = keys.copy(kdfParams = io.silencelen.andvari.core.crypto.KdfParams(ops = 1, memBytes = 8192))))
        assertEquals(io.silencelen.andvari.core.client.account.ReauthKey.Refused, weak.proveAuthKey(crypto, strong.toCharArray()), "a kept cost outside the fence")
        assertEquals(sent, e.server.calls.size, "nothing is dialed")
        opened.wipe()
    }

    /**
     * The command line's need: a password changed through a session the host holds is
     * proven by that same session, with no stand-in rebuilt over the new wrap. While the change's answer is unknown
     * either password proves; a refusal drops the new one; once the server took it only the new one proves.
     */
    @Test fun aSessionProvesThePasswordItChangedEitherWhileTheAnswerIsUnknownAndOnlyTheNewOnceTaken() = runBlocking<Unit> {
        val e = pinned()
        registered(e)
        val s = e.sink.sessions.single()
        val oldAuth = e.server.account("alice@example.com").authKey
        val next = "a brand new Master password 7"
        val nk = assertNotNull(PasswordKeys.derive(crypto, next.toCharArray(), crypto.randomBytes(io.silencelen.andvari.core.crypto.KdfParams.SALT_BYTES), s.accountKeys.kdfParams, served = false))
        val newAuth = nk.authKeyB64
        val wrap = try {
            io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap(io.silencelen.andvari.core.crypto.Bytes.toB64(nk.salt), nk.params,
                s.account.uvk.use { io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, nk.wrapKey, it, io.silencelen.andvari.core.crypto.Ad.uvk(s.userId)) })
        } finally {
            nk.wipe()
        }
        fun prove(pw: String) = s.proveAuthKey(crypto, pw.toCharArray())
        val key = io.silencelen.andvari.core.client.account.ReauthKey.Key::class
        assertEquals(io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword, prove(next), "before the change, the new password is not this session's")

        assertTrue(s.passwordChangePending(wrap))
        assertTrue(s.hasPendingWrap())
        assertEquals(oldAuth, assertIs<io.silencelen.andvari.core.client.account.ReauthKey.Key>(prove(strong)).currentAuthKey, "pending: the old one proves")
        assertEquals(newAuth, assertIs<io.silencelen.andvari.core.client.account.ReauthKey.Key>(prove(next)).currentAuthKey, "pending: the new one proves")
        // A second change never replaces an unsettled one.
        val other = io.silencelen.andvari.core.client.account.WireAccountSettings.NewWrap(wrap.kdfSalt, wrap.kdfParams, "x" + wrap.wrappedUvk.drop(1))
        assertTrue(!s.passwordChangePending(other), "refused while the first is pending")
        s.passwordChangeNotTaken(other)
        assertEquals(newAuth, assertIs<io.silencelen.andvari.core.client.account.ReauthKey.Key>(prove(next)).currentAuthKey, "another request's refusal leaves it")
        s.passwordChangeNotTaken(wrap)
        assertEquals(io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword, prove(next), "not taken: the new one goes")
        assertTrue(key.isInstance(prove(strong)))

        s.passwordChangePending(wrap)
        s.passwordChanged(wrap)
        assertEquals(io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword, prove(strong), "taken: the old one no longer proves")
        assertEquals(newAuth, assertIs<io.silencelen.andvari.core.client.account.ReauthKey.Key>(prove(next)).currentAuthKey, "taken: the new one is the session's own")
    }

    /** A host reopening a session it kept (the command-line tool) opens the served keys with the password, holding no key. */
    @Test fun aKeptSessionsKeysOpenWithThePasswordAndNothingElse() = runBlocking<Unit> {
        val e = pinned()
        val reg = registered(e)
        val keys = e.server.keys(e.server.account("alice@example.com"))
        val userId = e.sink.sessions.single().userId
        val pw = strong.toCharArray()
        val opened = assertIs<PasswordOpen.Opened>(AccountOpen.openWithPassword(crypto, userId, pw, keys, e.server.instanceId))
        assertEquals(userId, opened.account.userId)
        assertEquals(e.sink.sessions.single().account.signingKeyB64(), opened.account.signingKeyB64())
        assertTrue(pw.all { it == '\u0000' }, "the password is wiped")
        opened.account.wipe()
        val wrong = "not the password at all 1".toCharArray()
        assertEquals(PasswordOpen.WrongPassword, AccountOpen.openWithPassword(crypto, userId, wrong, keys, e.server.instanceId))
        assertTrue(wrong.all { it == '\u0000' })
        assertEquals(PasswordOpen.Refused(PasswordOpen.BAD_KDF_SALT), AccountOpen.openWithPassword(crypto, userId, strong.toCharArray(), keys.copy(kdfSalt = "!"), e.server.instanceId))
        assertEquals(PasswordOpen.Refused(PasswordOpen.KDF_REFUSED),
            AccountOpen.openWithPassword(crypto, userId, strong.toCharArray(), keys.copy(kdfParams = io.silencelen.andvari.core.crypto.KdfParams(ops = 1, memBytes = 8192)), e.server.instanceId))
        assertIs<PasswordOpen.IdentityFault>(AccountOpen.openWithPassword(crypto, userId, strong.toCharArray(), keys, "ffffffff-ffff-4fff-8fff-ffffffffffff"))
        assertNotNull(reg)
    }

    @Test fun signUpWithProofOfWorkThenRegisterOpensTheAccountAndRecordsTheChoice() = runBlocking<Unit> {
        val e = pinned()
        e.server.powBits = 8
        var progress = -1f
        assertEquals(SignupStart.Sent, e.onboarding.signupStart("Alice@Example.com ", true) { progress = it })
        assertEquals(1f, progress)
        assertEquals(SignupVerify.BadCode, e.onboarding.signupVerify("alice@example.com", "000000"))
        val t = assertIs<SignupVerify.Ticket>(e.onboarding.signupVerify("alice@example.com", "482915"))
        val f = form()
        val reg = assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.Ticket(t), f))
        assertTrue(f.password.all { it == '\u0000' }, "the password is wiped once derived")
        val body = e.server.lastRegister!!
        assertIs<RegisterAuth.Ticket>(body.auth)
        assertEquals("private", body.recovery.posture)
        assertNull(body.recovery.escrow)
        // The kit names this origin, card 0 and the address; its account ID is the identity's short fingerprint.
        val kit = RecoveryKit.parseQr(reg.kit.qr)!!
        assertEquals(e.server.origin, kit.origin)
        assertEquals(e.server.card0Hash, kit.card0Hash)
        assertEquals("alice@example.com", kit.emailNorm)
        assertEquals(11, reg.kit.groups.size)
        val s = e.sink.sessions.single()
        assertEquals(SessionHow.REGISTERED, s.how)
        assertEquals(reg.userId, s.userId)
        assertEquals(s.account.accountId(crypto), reg.kit.accountId)
        assertEquals(body.personalVault.vaultId, s.account.personalVaultId)
        assertEquals(e.server.instanceId, s.account.genesis.fields.instanceId)
        // The choice: the device's own mirror and the UVK-sealed record.
        assertEquals("private", RecoveryMirror(e.state).get(reg.userId)!!.posture)
        val doc = StoredAccountState(reg.userId, s.account.uvk, e.server, crypto, e.state).local()
        assertEquals("private", doc.recovery!!.posture)
        assertEquals("none", doc.recovery!!.fp)
        // The device secret was sent and the device row remembered.
        val a = e.server.account("alice@example.com")
        assertEquals(KnownDevices(e.state, crypto).deviceId(e.server.origin, "alice@example.com"), a.devices.keys.single())
    }

    @Test fun theProofOfWorkIsTheServersRuleOnTheVectorsInputs() {
        val doc = kotlinx.serialization.json.Json.parseToJsonElement(io.silencelen.andvari.core.readVector("signup.json")).let { it as kotlinx.serialization.json.JsonObject }
        val rows = (doc.getValue("pow") as kotlinx.serialization.json.JsonArray).map { it as kotlinx.serialization.json.JsonObject }
        for (r in rows) {
            fun s(k: String) = (r[k] as kotlinx.serialization.json.JsonPrimitive).content
            val now = s("serverNow").toLong()
            assertEquals(s("serverNowUtc").take(10), WireOnboarding.utcDate(now), s("name"))
            val bits = s("powBits").toInt()
            if (bits == 0 || bits > 20) continue
            val norm = io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(s("email"))!!
            assertEquals(s("emailNorm"), norm)
            val nonce = io.silencelen.andvari.core.trust.SignupPow.search(crypto, norm, WireOnboarding.utcDate(now), bits, 0, 1 shl 22)!!
            assertTrue(io.silencelen.andvari.core.trust.SignupPow.accepts(crypto, norm, WireOnboarding.utcDate(now), nonce, bits), s("name"))
        }
        assertEquals("1970-01-01", WireOnboarding.utcDate(0))
        assertEquals("1969-12-31", WireOnboarding.utcDate(-1))
        assertEquals("2000-02-29", WireOnboarding.utcDate(951_782_400_000))
    }

    @Test fun registrationRefusesBeforeSendingWhatItCanCheckItself() = runBlocking<Unit> {
        val e = pinned()
        val t = ticket(e)
        val before = e.server.calls.size
        assertEquals(Registration.PasswordTooWeak, e.onboarding.register(RegistrationAuth.Ticket(t), form(password = "short")))
        assertEquals("bad_ticket", assertIs<Registration.Refused>(e.onboarding.register(RegistrationAuth.Ticket(t), form(email = "bob@example.com"))).code)
        assertEquals("operator_recovery_unavailable",
            assertIs<Registration.Refused>(e.onboarding.register(RegistrationAuth.Ticket(t), form(recovery = RecoveryChoiceKind.OPERATOR))).code)
        assertEquals("link_stale", assertIs<Registration.Refused>(e.onboarding.register(RegistrationAuth.EnrolLink(confirmStep()), form())).code)
        assertEquals(before, e.server.calls.size, "nothing was sent")
        // No pin: the Trust Gate first.
        val bare = env(e.server, e.server.trust())
        assertEquals("trust_gate_first", assertIs<Registration.Refused>(bare.onboarding.register(RegistrationAuth.Ticket(t), form())).code)
        // A ticket from another origin is refused too.
        val other = FakeInstance(crypto, origin = "https://other.example")
        val o = pinned(other)
        assertEquals("bad_ticket", assertIs<Registration.Refused>(o.onboarding.register(RegistrationAuth.Ticket(t), form())).code)
    }

    private fun confirmStep() = RecipientStep.Confirm(io.silencelen.andvari.core.client.link.OfferView("enrol", "https://h.example", "Home", null, null, 0, null), true,
        false, io.silencelen.andvari.core.client.link.RecipientToken("t"))

    @Test fun registrationMapsTheServersAnswers() = runBlocking<Unit> {
        val e = pinned()
        val t = ticket(e)
        e.server.override[WireRoute.REGISTER] = io.silencelen.andvari.core.client.net.WireResult.Refused(403, io.silencelen.andvari.core.model.wire.WireError("signup_full", "x"))
        assertEquals("signup_full", assertIs<Registration.Refused>(e.onboarding.register(RegistrationAuth.Ticket(t), form())).code)
        e.server.override[WireRoute.REGISTER] = io.silencelen.andvari.core.client.net.WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TIMEOUT)
        assertEquals(Registration.Unknown, e.onboarding.register(RegistrationAuth.Ticket(t), form()))
        assertTrue(e.sink.sessions.isEmpty())
    }

    @Test fun aServerThatEchoesAnotherIdentityIsTheIdentityFault() = runBlocking<Unit> {
        val e = pinned()
        val t = ticket(e)
        // The server stores the account but serves back a genesis for another instance.
        val real = e.server
        val wrapper = object : io.silencelen.andvari.core.client.net.WireClient by real {
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): io.silencelen.andvari.core.client.net.WireResult<T> {
                if (route == WireRoute.REGISTER) {
                    val r = real.call(route, pathParams, query, bodyJson, authenticated) { it }
                    val text = (r as io.silencelen.andvari.core.client.net.WireResult.Ok).value
                    val a = real.accounts.values.single()
                    return io.silencelen.andvari.core.client.net.WireResult.Ok(decode(text.replace(a.identityPub, Bytes.toB64(ByteArray(32) { 1 }))), 200)
                }
                return real.call(route, pathParams, query, bodyJson, authenticated, decode)
            }
        }
        val sink = Sink()
        val o = WireOnboarding(real.origin, wrapper, e.trust, KnownDevices(e.state, crypto), sink, crypto, e.state, "android", "Pixel", { real.now }, work = Dispatchers.Unconfined)
        assertEquals("identity_mismatch", assertIs<Registration.IdentityFault>(o.register(RegistrationAuth.Ticket(t), form())).reason)
        assertTrue(sink.sessions.isEmpty(), "nothing is handed to the session sink")
    }

    private suspend fun registered(e: Env, email: String = "alice@example.com"): Registration.Registered =
        assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.Ticket(ticket(e, email)), form(email = email)))

    @Test fun signInFromAKnownDeviceAndRequireLink() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val e = pinned(state = state)
        val reg = registered(e)
        val pw = strong.toCharArray()
        val ok = assertIs<SignIn.SignedIn>(e.onboarding.signIn("alice@example.com", pw))
        assertEquals(reg.userId, ok.userId)
        assertTrue(pw.all { it == '\u0000' })
        val a = e.server.account("alice@example.com")
        assertEquals(1, a.devices.size, "the same device row: a known device")
        assertEquals(SessionHow.PASSWORD, e.sink.sessions.last().how)
        assertEquals(SignIn.InvalidCredentials, e.onboarding.signIn("alice@example.com", "wrong password 1A!".toCharArray()))
        // requireLink: the known device still signs in; a new device is refused after the password verified.
        a.requireLink = true
        assertIs<SignIn.SignedIn>(e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        val other = pinned(e.server)
        assertEquals(SignIn.LinkRequired, other.onboarding.signIn("alice@example.com", strong.toCharArray()))
        // A device whose secret was cleared (a revoke) is new again.
        a.devices.clear()
        assertEquals(SignIn.LinkRequired, e.onboarding.signIn("alice@example.com", strong.toCharArray()))
    }

    @Test fun twoStepSignInKeepsTheKeysNotThePassword() = runBlocking<Unit> {
        val e = pinned()
        registered(e)
        e.server.account("alice@example.com").totp = "123456"
        val pw = strong.toCharArray()
        val step = assertIs<SignIn.TotpRequired>(e.onboarding.signIn("alice@example.com", pw))
        assertTrue(pw.all { it == '\u0000' })
        // The server took the password a moment before and answers a wrong code as it answers a wrong password: said as
        // what is known, never as a wrong password (before: InvalidCredentials, the screens' "wrong password").
        assertEquals(SignIn.Refused(WireOnboarding.REFUSED_AFTER_CODE), e.onboarding.signInCode(step, "654321"))
        val again = assertIs<SignIn.TotpRequired>(e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        assertIs<SignIn.SignedIn>(e.onboarding.signInCode(again, "123456"))
        val third = assertIs<SignIn.TotpRequired>(e.onboarding.signIn("alice@example.com", strong.toCharArray(), null))
        e.onboarding.cancelSignIn(third)
        assertTrue(third.pending.keys.authKeyB64 == Bytes.toB64(ByteArray(32)), "cancel wipes the derived keys")
        // A code given with the first send, before the server asked for one, proves nothing about the password: a refusal
        // there stays the uniform one.
        assertEquals(SignIn.InvalidCredentials, e.onboarding.signIn("alice@example.com", "wrong password 1A!".toCharArray(), "123456"))
    }

    @Test fun theSecondStepAsksThePasswordRuleAgain() = runBlocking<Unit> {
        val state = MemoryDeviceState()
        val e = pinned(state = state)
        registered(e)
        e.server.account("alice@example.com").totp = "123456"
        val step = assertIs<SignIn.TotpRequired>(e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        val logins = e.server.calls.count { it == WireRoute.LOGIN }
        // The pin forks between the two steps: authKey and the code are not sent again.
        io.silencelen.andvari.core.client.pin.PinStore(state).markForked(e.trust.pinFor(e.server.origin)!!)
        assertEquals(SignIn.Refused(WireOnboarding.INSTANCE_BLOCKED), e.onboarding.signInCode(step, "123456"))
        assertEquals(logins, e.server.calls.count { it == WireRoute.LOGIN }, "nothing sent once the pin is forked")
        assertTrue(step.pending.keys.authKeyB64 == Bytes.toB64(ByteArray(32)), "the kept keys are wiped")
    }

    @Test fun trustGateFirstSendsNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val bare = env(server, server.trust())
        val pw = strong.toCharArray()
        assertEquals(SignIn.TrustGateFirst, bare.onboarding.signIn("alice@example.com", pw))
        assertTrue(pw.all { it == '\u0000' })
        assertFalse(WireRoute.PRELOGIN in server.calls)
        // A link-offer pin is not a password pin.
        val state = MemoryDeviceState()
        val t = server.trust(state)
        t.pinFromLinkOffer(server.origin, server.instanceId, server.card0Hash)
        assertEquals(PinRoot.LINK_OFFER, t.pinFor(server.origin)!!.root)
        assertEquals(SignIn.TrustGateFirst, env(server, t, state).onboarding.signIn("alice@example.com", strong.toCharArray()))
        assertFalse(WireRoute.PRELOGIN in server.calls)
    }

    @Test fun signInChecksTheGenesisAgainstThePinnedInstance() = runBlocking<Unit> {
        val e = pinned()
        registered(e)
        val a = e.server.account("alice@example.com")
        // The server replaces the genesis with one for another account: the identity fault, nothing handed over.
        val sessions = e.sink.sessions.size
        a.genesis = null
        assertEquals("no_genesis", assertIs<SignIn.IdentityFault>(e.onboarding.signIn("alice@example.com", strong.toCharArray())).reason)
        a.genesis = e.server.lastRegister!!.genesis
        a.personalWrap = a.personalWrap!!.copy(vaultId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
        assertEquals("personal_vault_mismatch", assertIs<SignIn.IdentityFault>(e.onboarding.signIn("alice@example.com", strong.toCharArray())).reason)
        a.personalWrap = null
        val ok = assertIs<SignIn.SignedIn>(e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        assertNull(e.sink.sessions.last().account.personalVaultId, "a withheld wrap leaves no personal vault, not a fault")
        assertEquals(sessions + 1, e.sink.sessions.size)
        assertNotNull(ok)
        // A served wrappedUvk this account never had.
        a.wrappedUvk = e.server.lastRegister!!.personalWrap.wrappedVk
        assertEquals("uvk_unopenable", assertIs<SignIn.IdentityFault>(e.onboarding.signIn("alice@example.com", strong.toCharArray())).reason)
    }

    @Test fun theKitCaptureGate() = runBlocking<Unit> {
        val e = pinned()
        val reg = registered(e)
        val kit = reg.kit
        val asked = e.onboarding.kitChallenge(kit)
        assertEquals(3, asked.size)
        assertEquals(asked, e.onboarding.kitChallenge(kit), "the same challenge until it is answered")
        val right = asked.associateWith { kit.groups[it - 1] }
        val wrong = asked.associateWith { "AAAA" }
        assertEquals(KitConfirm.Wrong, e.onboarding.confirmKit(kit, mapOf(99 to "x")))
        assertEquals(KitConfirm.Wrong, e.onboarding.confirmKit(kit, wrong))
        assertEquals(KitConfirm.Wrong, e.onboarding.confirmKit(kit, wrong))
        assertEquals(KitConfirm.ShowAgain, e.onboarding.confirmKit(kit, wrong))
        assertFalse(e.server.account("alice@example.com").recoveryConfirmed)
        val again = e.onboarding.kitChallenge(kit)
        assertEquals(KitConfirm.Confirmed, e.onboarding.confirmKit(kit, again.associateWith { kit.groups[it - 1] }))
        assertTrue(e.server.account("alice@example.com").recoveryConfirmed)
        assertTrue(kit.secret.all { it == 0.toByte() })
        assertNotNull(right)
    }

    @Test fun operatorRecoveryIsOfferedOnlyFromThePinnedCardAndNeedsConsent() = runBlocking<Unit> {
        val recovery = crypto.boxKeypairFromSeed(ByteArray(32) { 2 })
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val server = FakeInstance(crypto, recoveryFp = fp)
        server.recoveryPub = recovery.publicKey
        val e = pinned(server)
        val offer = assertNotNull(e.onboarding.operatorRecoveryOffer())
        assertFalse(offer.unsignedChange)
        assertEquals("Home", offer.instanceName)
        val t = ticket(e)
        assertEquals("consent_required",
            assertIs<Registration.Refused>(e.onboarding.register(RegistrationAuth.Ticket(t), form(recovery = RecoveryChoiceKind.OPERATOR, offer = offer))).code)
        val reg = assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.Ticket(t),
            form(recovery = RecoveryChoiceKind.OPERATOR, offer = offer, understood = true)))
        val body = e.server.lastRegister!!
        assertEquals("operator", body.recovery.posture)
        assertEquals(fp, body.recovery.escrow!!.fingerprint)
        assertEquals(fp, RecoveryMirror(e.state).get(reg.userId)!!.fp)
        // A served key that does not hash to the card's recoveryFp: not offered.
        server.recoveryPub = crypto.boxKeypairFromSeed(ByteArray(32) { 3 }).publicKey
        assertNull(e.onboarding.operatorRecoveryOffer())
        // A public card never offers it.
        val pub = FakeInstance(crypto, kind = InstanceKind.PUBLIC, recoveryFp = fp)
        pub.recoveryPub = recovery.publicKey
        assertNull(pinned(pub).onboarding.operatorRecoveryOffer())
    }

    @Test fun setupSignsAndPinsCardZero() = runBlocking<Unit> {
        val server = FakeInstance(crypto, withCard = false)
        val setup = LinkRegistration.Setup(server.origin, server.instanceId, "Family", "private", "none", "bGlua2lkbGlua2lkbGlua2", Bytes.toB64(ByteArray(32) { 6 }))
        var done: String? = null
        val links = object : LinkRegistrations {
            override fun resolve(step: RecipientStep.Confirm) = setup
            override suspend fun registered(registration: LinkRegistration, session: EstablishedSession) { done = session.userId }
        }
        val state = MemoryDeviceState()
        val e = env(server, server.trust(state), state, links)
        val reg = assertIs<Registration.Registered>(e.onboarding.register(RegistrationAuth.SetupLink(confirmStep()), form(email = "op@example.org")))
        assertFalse(reg.cardPending)
        assertEquals(reg.userId, done)
        assertIs<RegisterAuth.Setup>(server.lastRegister!!.auth)
        val card = InstanceCard.verifyChain(crypto, server.cards).chain.cards.single().fields
        assertEquals(reg.userId, card.operator)
        assertEquals(server.origin, card.origin)
        val pin = e.trust.pinFor(server.origin)!!
        assertEquals(PinRoot.SETUP, pin.root)
        assertEquals("op@example.org", pin.rootAccount)
        assertEquals(SignedFrame.hash(crypto, server.cards[0]), RecoveryKit.parseQr(reg.kit.qr)!!.card0Hash)
        // The setup pin lets the operator sign in, and no one else.
        assertIs<SignIn.SignedIn>(e.onboarding.signIn("op@example.org", strong.toCharArray()))
        assertEquals(SignIn.TrustGateFirst, e.onboarding.signIn("alice@example.com", strong.toCharArray()))
        // A second setup is refused here: the origin is pinned.
        assertEquals("setup_done", assertIs<Registration.Refused>(e.onboarding.register(RegistrationAuth.SetupLink(confirmStep()), form(email = "x@example.org"))).code)
    }
}
