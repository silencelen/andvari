package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.trust.RecoveryKit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/** Journey 6: kit recovery on a fresh device (scanned and typed); password change; kit rotation; the require-link switch. */
class J6KitAndSettingsTest {
    private val pw2 = "second Password for 2 recover"
    private val pw3 = "third Password, changed 33 x"

    @Test fun kitRecoveryPasswordChangeKitRotationAndRequireLink() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val reg = Steps.registerThrough(s.device("alice old"), s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)

            // Scanned: the kit pins the server from its card0Hash and recovers.
            val d1 = s.device("alice scanned")
            val kit = assertNotNull(RecoveryKit.parseQr(reg.kit.qr))
            val t1 = assertIs<KitRecoveryStep.ConfirmTarget>(d1.kitRecovery.start(kit, GateEntry.KIT_RECOVERY_SCREEN), "scanned kit target")
            assertEquals(null, t1.gate, "a scanned kit that matches card 0 needs no Trust Gate")
            val c1 = assertIs<KitRecoveryStep.ChoosePassword>(d1.kitRecovery.verify(t1), "phase 1")
            val r1 = assertIs<KitRecoveryStep.Recovered>(d1.kitRecovery.commit(c1, Steps.PASSWORD.toCharArray()), "phase 2")
            assertEquals(reg.userId, r1.userId)
            Steps.confirmKit(d1.onboarding(s.origin), r1.newKit)
            val newKit: RevealedKit = r1.newKit

            // Typed: the groups of the new kit, through the Trust Gate.
            val d2 = s.device("alice typed")
            val t2 = assertIs<KitRecoveryStep.ConfirmTarget>(
                d2.kitRecovery.startTyped("alice@example.org", s.origin, newKit.groups.joinToString(" "), GateEntry.KIT_RECOVERY_SCREEN), "typed kit target")
            assertNotNull(t2.gate, "a typed kit has no card0Hash: the Trust Gate")
            val c2 = assertIs<KitRecoveryStep.ChoosePassword>(d2.kitRecovery.verify(t2))
            val r2 = assertIs<KitRecoveryStep.Recovered>(d2.kitRecovery.commit(c2, pw2.toCharArray()))
            Steps.confirmKit(d2.onboarding(s.origin), r2.newKit)

            // Password change, then sign-in with the new password on the same device.
            val h2 = d2.session(s.origin)!!
            assertEquals(Reauthed.Done(Unit), d2.settings(h2).change(pw2.toCharArray(), pw3.toCharArray()))
            assertIs<SignIn.SignedIn>(d2.onboarding(s.origin).signIn("alice@example.org", pw3.toCharArray()), "sign-in with the changed password")

            // Kit rotation.
            val h3 = d2.session(s.origin)!!
            val rotated = assertIs<Reauthed.Done<RevealedKit>>(d2.settings(h3).rotateKit(pw3.toCharArray()), "kit rotation").value
            Steps.confirmKit(d2.onboarding(s.origin), rotated)

            // Require-link: a new device is refused, the known one signs in.
            assertEquals(Reauthed.Done(true), d2.settings(h3).setRequireLink(true, pw3.toCharArray()))
            val d3 = s.device("alice stranger")
            val g = assertIs<FirstPin.NeedsTrustGate>(d3.trust.beginTrustGate(s.origin, TrustGateWording.TYPED_ADDRESS))
            assertIs<FirstPin.Pinned>(d3.trust.confirmTrustGate(g.confirm))
            assertEquals(SignIn.LinkRequired, d3.onboarding(s.origin).signIn("alice@example.org", pw3.toCharArray()))
            assertIs<SignIn.SignedIn>(d2.onboarding(s.origin).signIn("alice@example.org", pw3.toCharArray()))
        } }
    }
}
