package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.core.client.devicelink.BundleCheckpoints
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.link.Currency
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.client.pin.GateEntry
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Journey 5: a second device joins by device link, in both roles of the engine, with the code typed; the bundle carries contacts and vault checkpoints. */
class J5DeviceLinkTest {
    @Test fun aSecondDeviceJoinsByDeviceLinkAndInheritsContactsAndCheckpoints() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = s.device("alice laptop")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val bh = s.device("bob")
            Steps.registerThrough(bh, s.origin, Steps.enrolLink(s), "bob@example.org", trustGate = true)
            connect(ah, bh, s.origin)
            val a = ah.account(s.origin)!!
            val b = bh.account(s.origin)!!
            a.synced()
            val v = a.ok(null, LogAction.Create("Family"))
            a.ok(v, LogAction.Add(b.userId, "writer"))
            accept(b, v)
            a.synced()
            a.putItem(v, doc("shared login"))
            val head = assertIs<VaultLogStatus.Verified>(a.logs.status(v)).state

            // The existing device shows the link; the new one claims it from its own entry (andvari-cli link-device).
            val nh = s.device("alice desktop")
            val shown = assertIs<ExistingStep.Shown>(ah.deviceLinks.create(), "the existing device shows a link")
            var n = nh.deviceLinks.start(shown.url, GateEntry.CLI_LINK_DEVICE)
            if (n is NewStep.TrustGate) n = nh.deviceLinks.afterTrustGate(n, confirmed = true)
            val claimed = assertIs<NewStep.Claimed>(n, "the new device claims: $n")
            val fixed = assertIs<ExistingStep.ClaimFixed>(ah.deviceLinks.advance(shown), "the claim is fixed")
            assertEquals("alice desktop", fixed.name)
            val code = assertIs<NewStep.ShowCode>(nh.deviceLinks.advance(claimed), "the new device shows its code")
            val type = assertIs<ExistingStep.TypeDigits>(ah.deviceLinks.advance(fixed))
            val approvable = assertIs<ExistingStep.Approvable>(ah.deviceLinks.typeDigits(type, code.code), "the typed code matches")
            assertIs<ExistingStep.Approved>(ah.deviceLinks.approve(approvable))
            val need = assertIs<NewStep.PasswordNeeded>(nh.deviceLinks.advance(code), "the new device asks for the password")
            assertEquals("alice@example.org", need.email)
            val linked = assertIs<NewStep.Linked>(nh.deviceLinks.pickup(need, Steps.PASSWORD.toCharArray()), "pickup")
            assertEquals(a.userId, linked.userId)
            assertNotEquals(a.held.session.deviceId, linked.deviceId)
            val nSession = assertNotNull(nh.session(s.origin))
            assertEquals(SessionHow.LINKED, nSession.session.how)

            // The bundle: bob is a current contact here, and the vault's checkpoint is held.
            val na = nh.account(s.origin)!!
            na.synced()
            assertEquals(Currency.BUNDLE, na.contacts.list().single { it.record.userId == b.userId }.current)
            val cp = assertNotNull(BundleCheckpoints(nh.state).get(s.origin, a.userId, v), "the bundle carried the vault checkpoint")
            // The bundle carries the account's vault record, which the log engine writes in batches (design §5.4), so it
            // may stand below the showing device's verified head: a lower bound, verified on the new device.
            assertTrue(cp.seq in 0..head.headSeq, "checkpoint ${cp.seq} vs head ${head.headSeq}")
            assertIs<Adoption.Adopted>(na.logs.adoption(v), "the new device adopts the shared vault's key")
            assertEquals(listOf("shared login"), na.items(v).map { it.doc["name"]!!.jsonPrimitive.content })
            // The new device can show a link in its turn.
            assertIs<ExistingStep.Shown>(nh.deviceLinks.create())
        } }
    }
}
