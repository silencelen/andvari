package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.devicelink.DeviceLinkServer
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Walks over the shared code's REAL engine, on this computer's stores, against the shared code's test server, as the
 * window's model ([TrustModel]) runs them: "Forget the earlier account on this device" from the refusal to the notice, and
 * the earlier account served afterwards under another key; a device link whose two-step code the server refuses while the
 * link stays open. Each step prints what the desktop draws (`WALK|<step>|<line>`, in the test report's output), and the
 * assertions are of what the screen must say.
 */
class RealEngineWalksTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /** One process of the desktop over [dir]'s stores, reaching [client] for the test server's origin. */
    private class Run(dir: File, val instance: FakeInstance, client: WireClient, c: CryptoProvider) {
        val home = DesktopHome(dir, NoKeyStore, log = {}, keyStorePause = {})
        val transport = BearerTransport(mapOf(instance.origin to client))
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test", transport = transport,
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = c, clock = { instance.now }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined,
                cacheFiles = home.cacheFiles, contentStores = home.content.stores, keepsAtRest = home::keepsAtRest,
            ),
        )
        val faults = ArrayList<String>()
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, HomeSignInKeeping(home), faultLog = { faults += it })

        init {
            home.consentWithdrawn = api::atRestConsentChanged
            m.start()
            m.onSnapshot(api.snapshot)
        }

        /** One intent through the model, as a screen runs it, to its end: its result. */
        fun <R : IntentResult> done(intent: suspend DesktopAppApi.() -> R): R {
            var result: R? = null
            runBlocking { m.run(intent) { result = it }.join() }
            m.onSnapshot(api.snapshot)
            return assertNotNull(result, "the intent ended without a result: ${m.said.value?.text?.shown()}")
        }

        /** What the window says in place on the screen on show now. */
        fun saidNow(): UiText? = m.saidOn(api.snapshot)?.text

        inline fun <reified T : EntryScreen> at(): T = assertIs<T>(api.snapshot.entry, "on ${api.snapshot.phase} ${api.snapshot.entry}")
    }

    /** A random source that hands [next] once, for the next 16 bytes asked (an account id the server will serve). */
    private class FixedId(val inner: CryptoProvider) : CryptoProvider by inner {
        var next: ByteArray? = null
        override fun randomBytes(n: Int): ByteArray {
            val fixed = next
            if (n == 16 && fixed != null) {
                next = null
                return fixed.copyOf()
            }
            return inner.randomBytes(n)
        }
    }

    private fun temp(name: String): File = java.nio.file.Files.createTempDirectory("andvari-walk-$name").toFile()

    /** Prints what the desktop draws at [step], one line each, and flags a line without wording. */
    private fun draws(step: String, lines: List<UiText?>) {
        val shown = lines.filterNotNull()
        if (shown.isEmpty()) println("WALK|$step|(nothing)")
        for (l in shown) {
            val bare = (l as? UiText.Ph)?.placeholder in setOf(Placeholder.TROUBLE, Placeholder.REFUSAL, Placeholder.RESERVED_COPY)
            println("WALK|$step|${if (bare) "WITHOUT WORDING: " else ""}${l.shown()}")
        }
    }

    /** The registration through the screens up to the kit, then the kit typed back: the vault is open. */
    private fun signUp(r: Run, email: String, before: () -> Unit = {}) {
        r.m.act { entry.openOwnServer(r.at()) }
        r.m.onSnapshot(r.api.snapshot)
        assertEquals(ServerResult.DONE, r.done { entry.submitServerAddress(r.at(), "h.example") })
        (r.api.snapshot.entry as? EntryScreen.TrustGate)?.let { g -> assertEquals(ServerResult.DONE, r.done { entry.confirmTrustGate(g) }) }
        assertEquals(ServerResult.DONE, r.done { entry.createAccountHere(r.at()) })
        assertEquals(SignUpStartResult.DONE, r.done { entry.startSignUp(r.at(), email, true) })
        assertEquals(CodeResult.DONE, r.done { entry.verifySignUpCode(r.at(), r.instance.codes.getValue(email)) })
        before()
        assertEquals(CreateAccountResult.DONE, r.done { entry.createAccount(r.at(), NewAccountInput("", "P", strong, true)) })
        confirmKit(r)
        assertEquals(AppPhase.UNLOCKED, r.api.snapshot.phase)
    }

    private fun confirmKit(r: Run) {
        val kit = r.at<EntryScreen.Kit>().kit
        val doc = assertNotNull(r.api.kit.kitDocument(kit))
        r.m.act { this.kit.proceedToConfirm(kit) }
        r.m.onSnapshot(r.api.snapshot)
        val confirm = r.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, r.done { this.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
    }

    /** The password sign-in screen for the test server, past any Trust Gate. */
    private fun toSignIn(r: Run): EntryScreen.SignIn {
        r.m.act { entry.openSignIn(r.at()) }
        r.m.act { entry.openPasswordSignIn(r.at()) }
        r.m.onSnapshot(r.api.snapshot)
        assertEquals(ServerResult.DONE, r.done { entry.chooseOwnServer(r.at(), r.instance.origin) })
        (r.api.snapshot.entry as? EntryScreen.TrustGate)?.let { g -> assertEquals(ServerResult.DONE, r.done { entry.confirmTrustGate(g) }) }
        return r.at()
    }

    /** Waits (real time: the links poll every two seconds) until [what] holds, redrawing the model's view of the snapshot. */
    private fun until(r: Run, label: String, what: () -> Boolean) {
        val end = System.currentTimeMillis() + 30_000
        while (!what()) {
            assertTrue(System.currentTimeMillis() < end, "waited for $label: ${r.api.snapshot.phase} ${r.api.snapshot.entry} ${r.api.snapshot.account?.deviceLink}")
            Thread.sleep(100)
            r.m.onSnapshot(r.api.snapshot)
        }
        r.m.onSnapshot(r.api.snapshot)
    }

    // ---- (b) "Forget the earlier account on this device" ----

    /**
     * Alice's account was made on this computer and signed out; it was deleted and made again elsewhere. Her sign-in is
     * refused with both possibilities and the offer; the second step; the forgetting; the new account taken, and the notice
     * that this computer now remembers it. Then the account taken is deleted with the server's confirmation (the server is
     * kept, since the earlier account's key is kept there), and the earlier account served again under another key is
     * refused with the security fault and NO offer.
     */
    @Test
    fun forgetTheEarlierAccountFromTheRefusalToTheNoticeAndTheEarlierAccountUnderAnotherKeyIsRefusedWithNoOffer() {
        val server = FakeInstance(crypto)
        val dir = temp("forget")
        val elsewhere = temp("forget-else")
        val third = temp("forget-third")
        val runs = ArrayList<Run>()
        try {
            val r = Run(dir, server, server, crypto).also { runs += it }
            signUp(r, alice)
            val earlierId = server.account(alice).userId
            assertEquals(PlainResult.DONE, r.done { signOut() })
            server.accounts.remove(alice)
            signUp(Run(elsewhere, server, server, crypto).also { runs += it }, alice)

            // The refusal and the offer (its first step).
            val refused = r.done { entry.submitSignIn(toSignIn(r), alice, strong) }
            assertEquals(SignInAnswer.IDENTITY_FAULT, refused)
            val offer = assertNotNull(r.api.snapshot.earlierAccount, "the offer")
            // The answer carries the identity fault's own line, said above the offer as handed; never a line without wording.
            val above = assertNotNull(saidDrawn(r.m, r.api.snapshot), "the identity fault's line above the offer")
            assertEquals(UiText.of(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN).shown(), above.text.shown())
            assertFalse((above.text as? UiText.Ph)?.placeholder in setOf(Placeholder.TROUBLE, Placeholder.REFUSAL), "no line without wording above the offer")
            draws("b1 said", listOf(saidDrawn(r.m, r.api.snapshot)?.text))
            draws("b1 the offer", earlierOfferLines(offer) + UiText.of(offer.forgetLabel))
            // The second step.
            r.m.quietly { r.api.entry.askToForgetEarlierAccount(offer) }
            r.m.onSnapshot(r.api.snapshot)
            val confirming = assertNotNull(r.api.snapshot.earlierAccount)
            assertTrue(confirming.confirming)
            draws("b2 the second step", earlierConfirmLines(confirming) + listOfNotNull(confirming.confirmLabel?.let { UiText.of(it) }))
            // The person's own press on it, as the second step's button runs it.
            var forgot: ForgetEarlierResult? = null
            runBlocking { r.m.runSaying({ entry.forgetEarlierAccount(confirming) }, words = { x -> earlierResultLine(confirming, x) }) { forgot = it }.join() }
            r.m.onSnapshot(r.api.snapshot)
            assertEquals(ForgetEarlierResult.FORGOTTEN, forgot)
            assertEquals(assertNotNull(earlierResultLine(confirming, ForgetEarlierResult.FORGOTTEN)).shown(), r.saidNow()?.shown())
            draws("b3 forgotten, said", listOf(r.saidNow()))
            assertIs<EntryScreen.SignIn>(r.api.snapshot.entry)
            // The new account is taken; the notice that this computer now remembers it.
            assertEquals(SignInAnswer.DONE, r.done { entry.submitSignIn(r.at(), alice, strong) })
            assertEquals(AppPhase.UNLOCKED, r.api.snapshot.phase)
            val remembered = assertNotNull(r.api.snapshot.rememberedNewAccount, "the notice")
            assertEquals(CopyKey.REMADE_ACCOUNT_REMEMBERED, remembered.line.key)
            draws("b4 the notice", listOf(UiText.of(remembered.line)))
            r.m.quietly { r.api.dismissNewAccountRemembered(remembered) }
            r.m.onSnapshot(r.api.snapshot)
            assertNull(r.api.snapshot.rememberedNewAccount)
            val newId = server.account(alice).userId
            assertNotEquals(earlierId, newId)

            // The account taken is deleted, with the server's confirmation.
            server.override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok("""{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
            server.override[WireRoute.ACCOUNT_DELETE] = WireResult.Ok("""{"deletedAt":1}""", 200)
            assertEquals(PlainResult.DONE, r.done { settings.openDeletion() })
            val deletion = assertNotNull(r.api.snapshot.account?.deletion)
            assertEquals(DeletionResult.DONE, r.done { settings.deleteAccount(deletion, alice, strong, null) })
            server.override.remove(WireRoute.ACCOUNT_DELETE)
            server.override.remove(WireRoute.ACCOUNT_DELETE_PREVIEW)
            val deleted = assertNotNull(r.at<EntryScreen.FirstRun>().accountDeleted)
            assertFalse(deleted.serverForgotten, "the server is kept: the earlier account's key is kept there")
            draws("b5 the deletion's notice", listOf(UiText.of(deleted.line)))

            // The earlier account served again, under another key.
            server.accounts.remove(alice)
            val fixed = FixedId(crypto)
            signUp(Run(third, server, server, fixed).also { runs += it }, alice) { fixed.next = assertNotNull(Bytes.fromHexLower(earlierId.replace("-", ""))) }
            assertEquals(earlierId, server.account(alice).userId)
            val again = r.done { entry.submitSignIn(toSignIn(r), alice, strong) }
            println("WALK|b6 the earlier account under another key|$again")
            assertEquals(SignInAnswer.IDENTITY_FAULT, again)
            assertNull(r.api.snapshot.earlierAccount, "NO offer")
            assertTrue(r.api.snapshot.phase != AppPhase.UNLOCKED, "not taken")
            draws("b6 said", listOf(r.saidNow()))
            assertEquals(UiText.of(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN).shown(), r.saidNow()?.shown(), "the identity fault's own line, with no offer")
            assertEquals(emptyList(), r.faults)
        } finally {
            for (x in runs) x.api.close()
            dir.deleteRecursively()
            elsewhere.deleteRecursively()
            third.deleteRecursively()
        }
    }

    // ---- (c) a device-link code refused while the link stays open ----

    /** The showing computer's link routes, as the account it is signed in to ([caller]). */
    private class AsCaller(val link: DeviceLinkServer) : WireClient {
        var caller: String? = null
        override val origin: String get() = link.instance.origin
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> =
            link.client(caller).call(route, pathParams, query, bodyJson, authenticated, decode)
    }

    /**
     * This computer shows a device link; another computer opens it, the digits are typed here and the link approved with
     * the master password. On the new computer the account's two-step code is refused: the link stays open, the screen is
     * back at the password; the password and the current code then link it.
     */
    @Test
    fun aDeviceLinksTwoStepCodeRefusedWhileTheLinkStaysOpen() {
        val server = FakeInstance(crypto)
        val link = DeviceLinkServer(server)
        val hostDir = temp("link-host")
        val newDir = temp("link-new")
        val runs = ArrayList<Run>()
        try {
            val routes = AsCaller(link)
            val host = Run(hostDir, server, routes, crypto).also { runs += it }
            signUp(host, alice)
            routes.caller = server.account(alice).userId
            server.account(alice).totp = "123456"

            assertEquals(PlainResult.DONE, host.done { devices.startDeviceLink() })
            val shown = assertIs<DeviceLinkHost.Shown>(host.api.snapshot.account?.deviceLink)
            val url = assertNotNull(host.api.devices.deviceLinkToShow(shown))
            draws("c1 this computer shows the link", listOf(UiText.of(shown.line), UiText.ph(Placeholder.DEVICE_LINK_TIME_LEFT, countdown(host.api.devices.deviceLinkTimeLeftMs()))))

            val fresh = Run(newDir, server, link.client(null), crypto).also { runs += it }
            fresh.m.act { entry.openSignIn(fresh.at()) }
            fresh.m.act { entry.openLinkDevice(fresh.at()) }
            fresh.m.onSnapshot(fresh.api.snapshot)
            assertEquals(io.silencelen.andvari.core.app.DeviceLinkScanResult.DONE, fresh.done { entry.submitDeviceLink(fresh.at(), url, PayloadSource.PASTED) })
            (fresh.api.snapshot.entry as? EntryScreen.TrustGate)?.let { g -> assertEquals(ServerResult.DONE, fresh.done { entry.confirmTrustGate(g) }) }
            fresh.at<EntryScreen.LinkDeviceWaiting>()
            draws("c2 the new computer waits", listOf(UiText.ph(Placeholder.LINK_DEVICE_WAITING), fresh.saidNow()))

            until(host, "the digits to type") { host.api.snapshot.account?.deviceLink is DeviceLinkHost.TypeDigits }
            val type = assertIs<DeviceLinkHost.TypeDigits>(host.api.snapshot.account?.deviceLink)
            draws("c3 this computer: type the digits", listOf(UiText.of(type.line)))
            until(fresh, "the code on show") { fresh.api.snapshot.entry is EntryScreen.LinkDeviceCode }
            val code = fresh.at<EntryScreen.LinkDeviceCode>().code
            println("WALK|c3 the new computer shows its six digits|${code.length} digits")
            assertEquals(DigitsResult.DONE, host.done { devices.submitDeviceDigits(type, code) })
            val approvable = assertIs<DeviceLinkHost.Approvable>(host.api.snapshot.account?.deviceLink)
            draws("c4 this computer: approve", listOf(UiText.ph(Placeholder.DEVICE_LINK_APPROVE, approvable.deviceName, approvable.platform.wireName), host.saidNow()))
            assertEquals(ProofResult.DONE, host.done { devices.approveWithPassword(approvable, strong) })
            val approved = assertIs<DeviceLinkHost.Approved>(host.api.snapshot.account?.deviceLink)
            draws("c5 this computer: approved", listOf(UiText.ph(Placeholder.DEVICE_LINK_APPROVED, approved.deviceName)))

            until(fresh, "the password") { fresh.api.snapshot.entry is EntryScreen.LinkDevicePassword }
            val pw = fresh.at<EntryScreen.LinkDevicePassword>()
            assertFalse(pw.codeNeeded)
            draws("c6 the new computer: password", listOf(pw.prompt.title?.let { UiText.of(it) }, UiText.ph(Placeholder.PASSWORD_FIELD)))
            assertEquals(LinkPasswordResult.CODE_NEEDED, fresh.done { entry.submitLinkPassword(pw, strong) })
            assertTrue(fresh.at<EntryScreen.LinkDevicePassword>().codeNeeded)
            assertNull(fresh.saidNow(), "the screen asks for the code in its field; nothing is said as refused")
            draws("c7 the new computer: the two-step code", listOf(UiText.ph(Placeholder.TWO_STEP_CODE_FIELD), fresh.saidNow()))

            // The code refused: the link stays, and the screen says so, never "wrong password".
            val refused = fresh.done { entry.submitLinkCode(fresh.at(), "000000") }
            assertEquals(LinkPasswordResult.CODE_REFUSED_LINK_STAYS, refused)
            val back = fresh.at<EntryScreen.LinkDevicePassword>()
            assertFalse(back.codeNeeded, "back at the password")
            assertEquals(UiText.of(CopyKey.DEVICE_LINK_CODE_REFUSED_LINK_STAYS).shown(), fresh.saidNow()?.shown(), "the refused code, said as the shared code's line")
            draws("c8 the new computer: code refused, link stays", listOf(fresh.saidNow(), UiText.ph(Placeholder.PASSWORD_FIELD)))
            host.m.onSnapshot(host.api.snapshot)
            draws("c8 this computer meanwhile", listOf((host.api.snapshot.account?.deviceLink as? DeviceLinkHost.Approved)?.let { UiText.ph(Placeholder.DEVICE_LINK_APPROVED, it.deviceName) }))
            assertIs<DeviceLinkHost.Approved>(host.api.snapshot.account?.deviceLink, "the link is still open on this computer")

            // The password and the current code link it.
            assertEquals(LinkPasswordResult.CODE_NEEDED, fresh.done { entry.submitLinkPassword(back, strong) })
            assertEquals(LinkPasswordResult.DONE, fresh.done { entry.submitLinkCode(fresh.at(), "123456") })
            assertEquals(AppPhase.UNLOCKED, fresh.api.snapshot.phase)
            println("WALK|c9 the new computer is linked|${fresh.api.snapshot.account?.email}")
            assertEquals(emptyList(), host.faults + fresh.faults)
        } finally {
            for (x in runs) x.api.close()
            hostDir.deleteRecursively()
            newDir.deleteRecursively()
        }
    }
}
