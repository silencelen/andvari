package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.KeptAccountKeys
import io.silencelen.andvari.core.client.onboard.SessionSink
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.recovery.WireKitRecovery
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.hostile.proxy.Req
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Every new wrap of a master password is made at a cost the REAL server takes, when its operator raised the hashing
 * cost's floor (`ANDVARI_MIN_KDF_*`) above the default or after accounts were made: figure by figure the higher of what
 * the account already has and what the server serves, inside the client's limits (decided on 2026-11-17). Before, the
 * shared code registered at the fixed default, so the operator's own setup through the setup link and every invitation
 * were refused as `kdf_too_weak`; and an account that stands above the served cost on one figure and below it on the
 * other could neither change its password nor recover on a device that keeps it. Nothing is ever sent at a cost outside
 * the client's fence.
 */
class NewWrapCostTest {
    private val mib = 1024L * 1024L
    private val next = "a whole new Passphrase 42 here"

    private fun cost(r: Req, field: String): KdfParams =
        WireJson.json.decodeFromJsonElement(KdfParams.serializer(), assertNotNull(assertNotNull(r.json, "a JSON body")[field], "$field in ${r.route}"))

    /** The costs [h] sent on [route] in [field], each answered 200 by the real server, and inside the fence. */
    private fun World.taken(h: Host, route: WireRoute, field: String): KdfParams {
        val ex = assertNotNull(proxy.last(route, tag(h)), "${tag(h)} sent $route")
        assertEquals(200, ex.upstream?.status, "the real server took ${tag(h)}'s $route: ${ex.upstream?.body?.decodeToString()}")
        for (r in sent(h, route)) assertTrue(KdfUpgrade.withinFence(cost(r, field)), "${tag(h)} sent $route at ${cost(r, field)}")
        return cost(ex.req, field)
    }

    @Test fun theOperatorsSetupAndARegistrationFromAnInvitationAreTakenWhereTheFloorWasRaised() = world(
        extraEnv = mapOf("ANDVARI_MIN_KDF_OPS" to "4", "ANDVARI_MIN_KDF_MEM" to "${128 * mib}"),
    ) {
        val op = operator()
        val bob = member("bob")
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), taken(op, WireRoute.REGISTER, "kdfParams"), "the setup link's registration")
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), taken(bob, WireRoute.REGISTER, "kdfParams"), "the invitation's registration")
    }

    @Test fun accountsMadeBeforeTheFloorWasRaisedChangeTheirPasswordAndRecoverWithTheirKit() = world {
        operator()
        // Made at the default: 3 passes, 64 MiB.
        val carol = member("carol")
        // Made at 4 passes, 64 MiB (the floor raised to 4 passes for a while).
        server.restart(mapOf("ANDVARI_MIN_KDF_OPS" to "4"))
        val alice = member("alice")
        val bob = member("bob")
        assertEquals(KdfParams(ops = 4), taken(alice, WireRoute.REGISTER, "kdfParams"))
        // Then 3 passes and 128 MiB: carol is below it, alice and bob straddle it (above on passes, below on memory).
        server.restart(mapOf("ANDVARI_MIN_KDF_OPS" to "3", "ANDVARI_MIN_KDF_MEM" to "${128 * mib}"))

        assertIs<Reauthed.Done<Unit>>(carol.changePassword(assertNotNull(carol.session(origin)), Steps.PASSWORD.toCharArray(), next.toCharArray()))
        assertEquals(KdfParams(ops = 3, memBytes = 128 * mib), taken(carol, WireRoute.PASSWORD_CHANGE, "newKdfParams"), "made before the floor was raised")

        assertIs<Reauthed.Done<Unit>>(alice.changePassword(assertNotNull(alice.session(origin)), Steps.PASSWORD.toCharArray(), next.toCharArray()))
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), taken(alice, WireRoute.PASSWORD_CHANGE, "newKdfParams"), "a straddle: the higher on each figure")

        // Bob recovers with his kit on his own device, which keeps his account (its own cost: 4 passes, 64 MiB).
        val held = assertNotNull(bob.session(origin))
        val kept = KeptAccountKeys(held.userId, held.session.accountKeys, null)
        val keeping = object : SessionSink {
            override suspend fun established(session: EstablishedSession) = bob.sink.established(session)
            override fun keptForSignIn(origin: String): KeptAccountKeys? = kept.takeIf { origin == this@world.origin }
        }
        val kits = WireKitRecovery({ bob.client(it) }, bob.trust, bob.devices, keeping, bob.crypto, bob.platform, bob.deviceName)
        val target = assertIs<KitRecoveryStep.ConfirmTarget>(kits.start(assertNotNull(RecoveryKit.parseQr(registration(bob).kit.qr)), GateEntry.KIT_RECOVERY_SCREEN))
        val choose = assertIs<KitRecoveryStep.ChoosePassword>(kits.verify(target))
        assertIs<KitRecoveryStep.Recovered>(kits.commit(choose, next.toCharArray()))
        assertEquals(KdfParams(ops = 4, memBytes = 128 * mib), taken(bob, WireRoute.RECOVERY_SELF_COMMIT, "newKdfParams"), "a straddle kept on the device")
    }
}
