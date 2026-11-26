package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.KitScanResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Flows of the app interface that had only ever run against stand-ins of the server, now against the REAL server, with
 * the desktop app's engine on each side, driven as the desktop drives it. Every account is made with the command-line
 * tool. The polls the apps run on a timer are stepped by hand here (the poll interval is set out of reach), so each step
 * of a flow is one request the recording shows.
 */
class AppFlowsRealServerTest {
    private val crypto = createCryptoProvider()
    private val newPassword = "a brand new Master password 7 here"

    private fun World.desktop(tag: String): EngineDesktopAppApi {
        val state = MemoryDeviceState()
        val engine = AppEngine(AppPlatform.LINUX, "Desk $tag", dialingTransport(state, server.httpFor(proxy.dial(tag)), AppPlatform.LINUX), state,
            MemoryDeviceState(), crypto, server::now, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.IO)
        return EngineDesktopAppApi(engine).also {
            it.linkPollMs = Long.MAX_VALUE
            it.start()
        }
    }

    private inline fun <reified T : EntryScreen> EngineDesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** The person types the server's address, confirms its Trust Gate and signs in: the vault opens. */
    private suspend fun World.signedInDesktop(tag: String, email: String, password: String = Steps.PASSWORD): EngineDesktopAppApi {
        val app = desktop(tag)
        app.entry.openOwnServer(app.at())
        assertEquals(ServerResult.DONE, app.entry.submitServerAddress(app.at(), origin))
        assertEquals(ServerResult.DONE, app.entry.confirmTrustGate(app.at()))
        assertEquals(ServerResult.DONE, app.entry.signInHere(app.at()))
        assertEquals(SignInAnswer.DONE, app.entry.submitSignIn(app.at(), email, password), "signed in: ${proxy.tail()}")
        if (app.snapshot.entry is EntryScreen.Kit) confirmKit(app)
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "the vault opens")
        return app
    }

    /** The kit on show is saved: its groups typed back. */
    private suspend fun confirmKit(app: EngineDesktopAppApi) {
        val kit = app.at<EntryScreen.Kit>()
        val doc = assertNotNull(app.kit.kitDocument(kit.kit))
        app.kit.proceedToConfirm(kit.kit)
        val confirm = app.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, app.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
    }

    private fun EngineDesktopAppApi.host(): DeviceLinkHost? = snapshot.account?.deviceLink

    /**
     * (a) "Link a new device", both sides: the signed-in desktop shows the link, a fresh desktop takes it behind the
     * device-link Trust Gate, each shows the other what it must, the six digits are typed on the old device, the old
     * device approves with the master password, the new one types it and opens the vault, with the item saved before.
     */
    @Test fun aDeviceLinkFromASignedInDesktopToAFreshOneOpensTheVaultOnTheNewOne() = world {
        operator()
        member("alice")
        val old = signedInDesktop("old", "alice@example.org")
        val c = assertNotNull(old.content)
        assertEquals(ActionResult.Ok, c.saveLogin(null, LoginInput("Bank", "me", "pw-bank", listOf("https://bank.test"), "", "", false), null), "saved: ${proxy.tail()}")
        assertEquals(PlainResult.DONE, old.devices.startDeviceLink(), "the link is made: ${proxy.tail()}")
        val shown = assertIs<DeviceLinkHost.Shown>(old.host())
        val url = assertNotNull(old.devices.deviceLinkToShow(shown))

        val fresh = desktop("new")
        fresh.entry.openSignIn(fresh.at())
        fresh.entry.openLinkDevice(fresh.at())
        assertEquals(DeviceLinkScanResult.DONE, fresh.entry.submitDeviceLink(fresh.at(), url, PayloadSource.PASTED), "the link is taken: ${proxy.tail()}")
        assertEquals(ServerResult.DONE, fresh.entry.confirmTrustGate(fresh.at<EntryScreen.TrustGate>()), "claimed: ${proxy.tail()}")
        fresh.at<EntryScreen.LinkDeviceWaiting>()

        assertTrue(old.devicesFlow.pollDeviceLinkHost(), "the old device sees the claim: ${proxy.tail()}")
        assertIs<DeviceLinkHost.Claimed>(old.host(), "the claim is shown: ${old.host()}")
        fresh.entryFlow.pollDeviceLink()
        val code = fresh.at<EntryScreen.LinkDeviceCode>().code
        old.devicesFlow.pollDeviceLinkHost()
        val type = assertIs<DeviceLinkHost.TypeDigits>(old.host(), "the old device asks for the digits: ${proxy.tail()}")
        assertEquals("Desk new", type.deviceName)
        assertEquals(DigitsResult.DONE, old.devices.submitDeviceDigits(type, code))
        val approvable = assertIs<DeviceLinkHost.Approvable>(old.host())
        assertEquals(ProofResult.DONE, old.devices.approveWithPassword(approvable, Steps.PASSWORD), "approved: ${proxy.tail()}")
        assertIs<DeviceLinkHost.Approved>(old.host())

        fresh.entryFlow.pollDeviceLink()
        val pw = fresh.at<EntryScreen.LinkDevicePassword>()
        assertEquals("alice@example.org", pw.prompt.email)
        val r = fresh.entry.submitLinkPassword(pw, Steps.PASSWORD)
        assertEquals(LinkPasswordResult.DONE, r, "picked up: ${proxy.tail()}")
        if (fresh.snapshot.entry is EntryScreen.Kit) confirmKit(fresh)
        assertEquals(AppPhase.UNLOCKED, fresh.snapshot.phase, "the new device opens the vault")
        assertTrue(proxy.requests(WireRoute.DEVICE_LINK_PICKUP, "new").isNotEmpty())
        val content = assertNotNull(fresh.content)
        assertEquals(ActionResult.Ok, content.syncQuietly(), "synced: ${proxy.tail()}")
        assertTrue(content.state.items.any { it.name == "Bank" }, "the item saved on the old device is here: ${content.state.items.map { it.name }}")
    }

    /**
     * (b) A recovery with the kit on a fresh desktop, then a sign-in with the new password on a second one: the old
     * password no longer opens the account, the new one does.
     */
    @Test fun aKitRecoveryOnADesktopThenASignInWithTheNewPasswordOnAnother() = world {
        operator()
        val alice = member("alice")
        // The kit's groups as the person reads them (its secret bytes are wiped once the kit was confirmed).
        val kit = registration(alice).kit.groups.joinToString(" ")
        val one = desktop("one")
        one.entry.openSignIn(one.at())
        one.entry.openForgot(one.at())
        one.entry.openKitEntry(one.at())
        assertEquals(KitScanResult.DONE, one.entry.submitTypedKit(one.at(), "alice@example.org", origin, kit), "the kit is taken: ${proxy.tail()}")
        (one.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, one.entry.confirmTrustGate(it)) }
        assertEquals(KitRecoverResult.DONE, one.entry.confirmKitRecovery(one.at()), "the kit is proved: ${proxy.tail()}")
        assertEquals(ReplacePasswordResult.DONE, one.entry.chooseReplacementPassword(one.at(), newPassword), "committed: ${proxy.tail()}")
        assertEquals(KitReason.AFTER_RECOVERY, one.at<EntryScreen.Kit>().kit.reason)
        confirmKit(one)
        assertEquals(AppPhase.UNLOCKED, one.snapshot.phase, "the vault opens after the new kit")

        val two = desktop("two")
        two.entry.openOwnServer(two.at())
        assertEquals(ServerResult.DONE, two.entry.submitServerAddress(two.at(), origin))
        assertEquals(ServerResult.DONE, two.entry.confirmTrustGate(two.at()))
        assertEquals(ServerResult.DONE, two.entry.signInHere(two.at()))
        assertEquals(SignInAnswer.WRONG, two.entry.submitSignIn(two.at(), "alice@example.org", Steps.PASSWORD), "the old password is dead")
        assertEquals(SignInAnswer.DONE, two.entry.submitSignIn(two.at(), "alice@example.org", newPassword), "the new one opens it: ${proxy.tail()}")
        if (two.snapshot.entry is EntryScreen.Kit) confirmKit(two)
        assertEquals(AppPhase.UNLOCKED, two.snapshot.phase)
    }
}
