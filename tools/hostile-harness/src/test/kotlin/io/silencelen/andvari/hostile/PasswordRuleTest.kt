package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkStop
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Trust on first use and the password rule (design §4.4, §8.2 step 0, §16.2 R22; T2-B1, FS-B1): a value derived from an
 * account's secrets goes only to an origin with a password pin for that purpose. Every assertion here is on the proxy's
 * recording: what is not in it never left the device.
 */
class PasswordRuleTest {
    private val password get() = Steps.PASSWORD.toCharArray()

    private fun World.assertNoSecretSent(tag: String, mark: Int, what: String) {
        val sent = secretSends(tag, mark)
        assertTrue(sent.isEmpty(), "$what: nothing secret-derived may leave the device, but it sent\n${sent.joinToString("\n")}")
        val named = proxy.requests(tag = tag, since = mark).filter { it.text.contains("@example.org") }
        assertTrue(named.isEmpty(), "$what: no request may even name an account, but these did\n${named.joinToString("\n")}")
    }

    /**
     * §17 "Flow conformance": "the hostile-server harness serves a device link from an unpinned origin and asserts
     * that no prelogin, claim or pickup reaches it before the Trust Gate is accepted". §8.2 step 0: "Declining ends the
     * flow, and nothing has been sent to the origin."
     */
    @Test fun aDeviceLinkFromAnUnpinnedOriginSendsNoPreloginClaimOrPickupBeforeTheTrustGateIsAccepted() = world {
        operator()
        val eh = member("alice")
        val nh = device("new")
        val first = assertIs<ExistingStep.Shown>(eh.deviceLinks.create())
        var mark = proxy.mark()
        val gate = assertIs<NewStep.TrustGate>(nh.deviceLinks.start(first.url, GateEntry.LINK_DEVICE_SCREEN), "an origin nothing vouches for shows the Trust Gate first")
        assertEquals(origin, gate.gate.origin, "the gate names the link's origin")
        assertNoSecretSent("new", mark, "before the Trust Gate is answered")
        assertEquals(listOf(WireRoute.INSTANCE), proxy.requests(tag = "new", since = mark).map { it.route }, "only the public card chain was read")

        // Declined: the flow ends, nothing is pinned, and nothing more is sent.
        assertEquals(NewStep.Stopped(DeviceLinkStop.TRUST_GATE_DECLINED), nh.deviceLinks.afterTrustGate(gate, confirmed = false))
        assertEquals(PinState.None, nh.trust.pinState(origin))
        assertNoSecretSent("new", mark, "after the Trust Gate was declined")
        assertEquals(NewStep.Stopped(DeviceLinkStop.STALE), nh.deviceLinks.afterTrustGate(gate, confirmed = true), "a declined gate cannot be confirmed afterwards")
        assertNoSecretSent("new", mark, "after a declined gate was confirmed late")

        // Accepted: only now is the claim sent, and still no prelogin or pickup (those wait for E's approval and the password).
        mark = proxy.mark()
        val again = assertIs<NewStep.TrustGate>(nh.deviceLinks.start(first.url, GateEntry.LINK_DEVICE_SCREEN))
        assertNoSecretSent("new", mark, "before the second gate is answered")
        assertIs<NewStep.Claimed>(nh.deviceLinks.afterTrustGate(again, confirmed = true))
        assertEquals(PinRoot.TRUST_GATE, nh.trust.pinFor(origin)!!.root)
        assertEquals(listOf(WireRoute.DEVICE_LINK_CLAIM), secretSends("new", mark).map { it.route }, "the claim, and nothing else")
    }

    /**
     * §8.2 step 0 and §17: "none at all when the link did not come through 'Link from your other device'". A `/d` link
     * tapped, opened by another app, or scanned or pasted on "Scan an invite" starts nothing, pin or no pin.
     */
    @Test fun aDeviceLinkThatDidNotArriveThroughTheLinkDeviceScreenStartsNothingAtAll() = world {
        operator()
        val eh = member("alice")
        val shown = assertIs<ExistingStep.Shown>(eh.deviceLinks.create())
        for (pinned in listOf(false, true)) {
            val tag = if (pinned) "pinned" else "fresh"
            val nh = device(tag)
            if (pinned) {
                val g = assertIs<FirstPin.NeedsTrustGate>(nh.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
                assertIs<FirstPin.Pinned>(nh.trust.confirmTrustGate(g.confirm))
            }
            val mark = proxy.mark()
            for (entry in listOf(GateEntry.SCAN_INVITE, GateEntry.PASTE_INVITE, GateEntry.APP_LINK, GateEntry.SERVER_CHOICE, GateEntry.KIT_RECOVERY_SCREEN)) {
                assertEquals(NewStep.Stopped(DeviceLinkStop.WRONG_ENTRY), nh.deviceLinks.start(shown.url, entry), "a /d link from ${entry.code}")
            }
            // The invite screens do not forward it to the device-link flow either.
            assertEquals(RecipientStep.Stopped(LinkStop.WRONG_SCREEN_DEVICE_LINK), nh.links.open(shown.url, GateEntry.SCAN_INVITE))
            assertEquals(RecipientStep.Stopped(LinkStop.WRONG_SCREEN_DEVICE_LINK), nh.links.open(shown.url, GateEntry.PASTE_INVITE))
            assertTrue(proxy.requests(tag = tag, since = mark).isEmpty(), "nothing at all was sent ($tag device):\n${proxy.since(mark).joinToString("\n")}")
        }
    }

    /**
     * §4.4: signing in needs a password pin. A pin that came only from someone else's link offer, an enrol link, a kit
     * (even for the kit's own account) or a setup link of another account shows the Trust Gate first, and before it
     * neither prelogin nor `authKey` is sent.
     */
    @Test fun signingInSendsNoPreloginAndNoAuthKeyThroughAPinThatIsNotAPasswordPin() = world {
        operator()
        val ah = member("alice")
        member("bob")

        // No pin at all.
        val none = device("none")
        var mark = proxy.mark()
        assertEquals(SignIn.TrustGateFirst, none.onboarding(origin).signIn("alice@example.org", password))
        assertTrue(proxy.requests(tag = "none", since = mark).isEmpty(), "a device with no pin sends nothing at all")

        // An enrol pin (Bob's own registration device, signed out).
        val enrol = device("enrol")
        Steps.registerThrough(enrol, origin, Steps.enrolLink(server), "carol@example.org", trustGate = true)
        assertEquals(PinRoot.ENROL, enrol.trust.pinFor(origin)!!.root)
        enrol.client(origin).call(WireRoute.LOGOUT, decode = { })
        enrol.dropSession(origin)
        mark = proxy.mark()
        assertEquals(SignIn.TrustGateFirst, enrol.onboarding(origin).signIn("carol@example.org", password))
        assertEquals(SignIn.TrustGateFirst, enrol.onboarding(origin).signIn("alice@example.org", password))
        assertNoSecretSent("enrol", mark, "sign-in through an enrol pin")

        // A link-offer pin: someone's invitation was opened here.
        val offered = device("offered")
        val invite = assertIs<CreateOutcome.Created>(ah.links.create("register", 3_600_000L, emptyList()), "a member of a private instance makes a register link").link
        assertIs<RecipientStep.Confirm>(offered.links.open(invite.url, GateEntry.PASTE_INVITE))
        assertEquals(PinRoot.LINK_OFFER, offered.trust.pinFor(origin)!!.root)
        mark = proxy.mark()
        assertEquals(SignIn.TrustGateFirst, offered.onboarding(origin).signIn("alice@example.org", password))
        assertNoSecretSent("offered", mark, "sign-in through a link-offer pin")

        // A kit pin: for the kit's own recovery alone, never for a sign-in, not even to the kit's own account.
        val kitted = device("kitted")
        val kit = assertNotNull(RecoveryKit.parseQr(registration(ah).kit.qr))
        assertNull(assertIs<KitRecoveryStep.ConfirmTarget>(kitted.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN)).gate)
        assertEquals(PinRoot.KIT, kitted.trust.pinFor(origin)!!.root)
        mark = proxy.mark()
        assertEquals(SignIn.TrustGateFirst, kitted.onboarding(origin).signIn("bob@example.org", password))
        assertEquals(SignIn.TrustGateFirst, kitted.onboarding(origin).signIn("alice@example.org", password))
        assertIs<NewStep.TrustGate>(kitted.deviceLinks.start(assertIs<ExistingStep.Shown>(ah.deviceLinks.create()).url, GateEntry.LINK_DEVICE_SCREEN), "a kit pin does not count for a device link")
        assertNoSecretSent("kitted", mark, "sign-in or a device link through a kit pin")
    }

    /** §4.4: "a setup pin (this device signed card 0) only for the operator account it enrolled". */
    @Test fun aSetupPinLetsOnlyItsOwnOperatorAccountSignIn() = world {
        val oh = operator()
        member("alice")
        assertEquals(PinRoot.SETUP, oh.trust.pinFor(origin)!!.root)
        oh.client(origin).call(WireRoute.LOGOUT, decode = { })
        oh.dropSession(origin)
        val mark = proxy.mark()
        assertEquals(SignIn.TrustGateFirst, oh.onboarding(origin).signIn("alice@example.org", password))
        assertNoSecretSent("op", mark, "another account through a setup pin")
        assertIs<SignIn.SignedIn>(oh.onboarding(origin).signIn("op@example.org", password), "the operator account the pin enrolled signs in")
    }

    /**
     * §10 (FS-B1), §12.1: a kit is accepted only on "Scan your recovery kit". Anywhere else it starts nothing; and on its
     * own screen nothing is sent before the person has seen "Recover *email* on *name* (*origin*)" and confirmed.
     */
    @Test fun aRecoveryKitStartsNothingOutsideItsOwnScreenAndSendsNoProofBeforeThePersonConfirmsTheTarget() = world {
        operator()
        val ah = member("alice")
        val text = registration(ah).kit.qr
        val kit = assertNotNull(RecoveryKit.parseQr(text))
        val d = device("d")
        var mark = proxy.mark()
        assertEquals(RecipientStep.Stopped(LinkStop.WRONG_SCREEN_KIT), d.links.open(text, GateEntry.SCAN_INVITE), "\"This is a recovery kit, not an invite.\"")
        assertEquals(RecipientStep.Stopped(LinkStop.WRONG_SCREEN_KIT), d.links.open(text, GateEntry.PASTE_INVITE))
        assertEquals(NewStep.Stopped(DeviceLinkStop.BAD_LINK), d.deviceLinks.start(text, GateEntry.LINK_DEVICE_SCREEN))
        for (entry in listOf(GateEntry.SCAN_INVITE, GateEntry.PASTE_INVITE, GateEntry.APP_LINK, GateEntry.LINK_DEVICE_SCREEN, GateEntry.SERVER_CHOICE)) {
            assertEquals(KitRecoveryStep.Stopped("wrong_screen_kit"), d.kitRecovery.start(kit, entry), "a kit from ${entry.code}")
            assertEquals(KitRecoveryStep.Stopped("wrong_screen_kit"), d.kitRecovery.startTyped("alice@example.org", origin, registration(ah).kit.groups.joinToString(" "), entry))
        }
        assertTrue(proxy.requests(tag = "d", since = mark).isEmpty(), "a kit outside its screen sends nothing at all")
        assertEquals(PinState.None, d.trust.pinState(origin))

        // On its own screen, scanned: pinned from the kit's card 0, the target shown, and still no proof sent.
        mark = proxy.mark()
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        assertEquals("alice@example.org", target.email)
        assertEquals(origin, target.origin)
        assertNoSecretSent("d", mark, "before the person confirms the recovery target")
        // The person backs out: the kit pin this flow made goes with it.
        d.kitRecovery.cancel(target)
        assertEquals(PinState.None, d.trust.pinState(origin), "a cancelled kit recovery leaves no pin")
        assertEquals(KitRecoveryStep.Stopped("stale"), d.kitRecovery.verify(target))
        assertNoSecretSent("d", mark, "after the person backed out")

        // Typed: no card 0 hash, so the Trust Gate is part of the same confirmation, and nothing is sent before it.
        val t = device("typed")
        mark = proxy.mark()
        val typed = assertIs<KitRecoveryStep.ConfirmTarget>(t.kitRecovery.startTyped("alice@example.org", origin, registration(ah).kit.groups.joinToString(" "), GateEntry.KIT_RECOVERY_SCREEN))
        assertNotNull(typed.gate, "a typed kit has no anchor: the Trust Gate")
        assertEquals(PinState.None, t.trust.pinState(origin), "nothing is pinned before the gate is confirmed")
        assertNoSecretSent("typed", mark, "before the typed kit's Trust Gate is confirmed")
    }

    /**
     * §4.4, §10: a scanned kit whose `card0Hash` is not the served card 0 (an operator reset, or a server that is not the
     * kit's) "falls back to the Trust Gate with the warning"; the recovery proof is not sent on the kit's say-so.
     */
    @Test fun aKitWhoseCardZeroIsNotTheServedOneFallsBackToTheTrustGateBeforeAnyProofIsSent() = world {
        operator()
        val ah = member("alice")
        val parts = registration(ah).kit.qr.split(':').toMutableList()
        parts[3] = "ab".repeat(32) // a kit made for another chain
        val kit = assertNotNull(RecoveryKit.parseQr(parts.joinToString(":")))
        val d = device("d")
        val mark = proxy.mark()
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(d.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
        assertTrue(target.kitAnchorMismatch, "\"This server's identity changed since your kit was made.\"")
        assertNotNull(target.gate)
        assertEquals(PinState.None, d.trust.pinState(origin))
        assertNoSecretSent("d", mark, "a kit whose anchor does not match")
    }

    /**
     * §9.3 step 1, §4.4: assisted recovery to an origin without a password pin shows the Trust Gate first; "Assisted
     * recovery through a kit or a setup pin shows the Trust Gate." Before the person confirms, no request is opened.
     */
    @Test fun assistedRecoveryOpensNoRequestBeforeTheTrustGateAndAKitPinDoesNotStandInForIt() {
        val crypto = createCryptoProvider()
        val recoveryPub = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            operator()
            val ah = member("alice")
            val fresh = device("fresh")
            var mark = proxy.mark()
            val target = assertIs<AssistedStep.ConfirmTarget>(fresh.assisted.start("alice@example.org", origin))
            assertNotNull(target.gate, "no pin: the Trust Gate is part of the confirmation")
            assertNoSecretSent("fresh", mark, "before the assisted-recovery target is confirmed")
            fresh.assisted.cancel(target)
            assertNoSecretSent("fresh", mark, "after the person gave up")
            assertEquals(PinState.None, fresh.trust.pinState(origin))

            val kitted = device("kitted")
            val kit = assertNotNull(RecoveryKit.parseQr(registration(ah).kit.qr))
            assertIs<KitRecoveryStep.ConfirmTarget>(kitted.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN))
            assertEquals(PinRoot.KIT, kitted.trust.pinFor(origin)!!.root)
            mark = proxy.mark()
            val viaKit = assertIs<AssistedStep.ConfirmTarget>(kitted.assisted.start("alice@example.org", origin))
            assertNotNull(viaKit.gate, "a kit pin is not a password pin for assisted recovery")
            assertNoSecretSent("kitted", mark, "assisted recovery through a kit pin")
        }
    }
}
