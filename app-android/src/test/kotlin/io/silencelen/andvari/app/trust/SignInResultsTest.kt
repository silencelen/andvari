package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.RecoveryChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
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
 * The sign-in's new results on the phone: the server's keys are not this account's as this phone knows them (said with
 * the way out); a copy that followed the server's master password (said once above whatever opens); a registration the
 * server refuses for its recovery copy's form; and a server's refusal of a right proof, which never reads as a wrong
 * password on any screen that asks for the master password or a code.
 */
class SignInResultsTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private inline fun <reified S : EntryScreen> FakeAppApi.on(): S = assertIs<S>(snapshot.entry)

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    private fun sentence(key: CopyKey): String = UiText.of(key).shown()

    /** The server signed this phone's account out; it is kept, and the sign-in screen of the same server is open. */
    private fun signInOverTheKeptAccount(): Pair<FakeAppApi, TrustModel> {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.sessionEndedByServer()
        api.signInAgain(assertNotNull(api.snapshot.locked))
        assertNotNull(api.snapshot.keptSignedOut)
        api.entry.openSignIn(api.on())
        api.entry.openPasswordSignIn(api.on())
        assertEquals(ServerResult.DONE, runBlocking { api.entry.choosePublicInstance(api.on()) })
        return api to m
    }

    @Test
    fun theServersKeysNotKnownHereIsSaidWithTheWayOutWhichSaysFirstWhatIsLost() {
        val (api, m) = signInOverTheKeptAccount()
        api.script.signInServerKeysNotKnown = true
        m.run({ entry.submitSignIn(api.on(), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        val said = assertNotNull(m.saidOn(api.snapshot), "said on the sign-in screen")
        assertEquals(SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE, said.result)
        assertEquals(sentence(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE), said.text.shown())
        assertNotEquals(m.wordsFor(SignInAnswer.WRONG)?.shown(), said.text.shown(), "never a wrong password")
        assertIs<EntryScreen.SignIn>(api.snapshot.entry, "nothing was opened")
        assertNotNull(api.snapshot.keptSignedOut, "nothing kept was replaced")

        // The way out is said under the sentence, and the removal of this phone's copy is offered (the shared code's one
        // way out for this cause: the copy of the same account, never "sign out of that account").
        val here = src("TrustUi.kt").substringAfter("internal fun SaidHere(").substringBefore("\n}\n")
        assertTrue("if (said.result == SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE) Say(Placeholder.SIGN_IN_KEYS_WAY_OUT)" in here)
        assertEquals(WayOut.COPY_REMOVAL, wayOutFor(said.result))
        assertFalse(offersKeptSignOut(api.snapshot, said.result), "not as the sign-out of another account")
        // Its copy is not open, so this phone cannot count what was not sent: it says so first, and asks twice.
        val ask = m.signOutAsk()
        ask.open()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, assertNotNull(ask.check?.line).key)
        ask.confirm()
        assertNotNull(api.snapshot.keptSignedOut, "the first confirmation deletes nothing")
        ask.confirm()
        assertNull(api.snapshot.keptSignedOut)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)

        // Then sign in again.
        api.entry.openSignIn(api.on())
        api.entry.openPasswordSignIn(api.on())
        assertEquals(ServerResult.DONE, runBlocking { api.entry.choosePublicInstance(api.on()) })
        m.run({ entry.submitSignIn(api.on(), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        assertTrue(api.snapshot.phase == AppPhase.UNLOCKED || api.snapshot.entry is EntryScreen.Kit || api.snapshot.phase == AppPhase.LOCKED, "signed in: ${api.snapshot.entry}")
    }

    @Test
    fun aCopyThatFollowedTheServersPasswordIsSaidOnceAboveWhateverOpensUntilClosed() {
        val (api, m) = signInOverTheKeptAccount()
        api.script.signInOverOtherPasswordCopy = true
        m.run({ entry.submitSignIn(api.on(), FakeScenes.EMAIL, FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val notice = assertNotNull(assertNotNull(api.snapshot.account).signInNotice)
        assertEquals(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER, notice.key)
        val app = src("TrustApp.kt")
        assertTrue("if (s.phase == AppPhase.UNLOCKED) s.account?.signInNotice?.let { SignInNotice(model, it) }" in app)
        assertTrue(app.indexOf("SignInNotice(model, it)") < app.indexOf("Box(Modifier.weight(1f))"), "above whatever opens")
        assertTrue("model.act { dismissSignInNotice() }" in app.substringAfter("internal fun SignInNotice("))
        m.act { dismissSignInNotice() }
        assertNull(assertNotNull(api.snapshot.account).signInNotice, "once")
    }

    @Test
    fun aRegistrationRefusedForTheRecoveryCopysFormSaysSo() {
        val (api, m) = at(FakeScene.CREATE_ACCOUNT)
        api.script.escrowWrongForm = true
        val form = assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        m.run({ entry.createAccount(form, NewAccountInput(form.fixedEmail ?: "new@example.com", "Ada", "a much longer master password, 2026!", true)) })
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(CreateAccountResult.ESCROW_WRONG_FORM, said.result)
        assertEquals(sentence(CopyKey.REGISTER_ESCROW_WRONG_FORM), said.text.shown())
        assertIs<EntryScreen.CreateAccount>(api.snapshot.entry, "no account was made")
    }

    /** Every result type that can carry a server's refusal of a proof says the shared code's sentence for it. */
    @Test
    fun aRefusedProofHasTheSameSentenceInEveryResultTypeAndItIsNeverAWrongPassword() {
        val refused = sentence(CopyKey.SERVER_REFUSED_PROOF)
        val pairs: List<Pair<IntentResult, IntentResult>> = listOf(
            ProofResult.PROOF_REFUSED to ProofResult.WRONG_PASSWORD,
            TwoStepResult.PROOF_REFUSED to TwoStepResult.WRONG_PASSWORD,
            PasswordChangeResult.PROOF_REFUSED to PasswordChangeResult.WRONG_PASSWORD,
            DeletionResult.PROOF_REFUSED to DeletionResult.WRONG_PASSWORD,
            RecoveryChangeResult.PROOF_REFUSED to RecoveryChangeResult.WRONG_PASSWORD,
            KitConfirmResult.PROOF_REFUSED to KitConfirmResult.WRONG_PASSWORD,
            OperatorResult.PROOF_REFUSED to OperatorResult.WRONG_PASSWORD,
            ServerResult.PROOF_REFUSED to ServerResult.WRONG_PASSWORD,
        )
        for ((r, wrong) in pairs) {
            assertEquals(refused, assertNotNull(UiText.forResult(r, 0)).shown(), "$r")
            assertNotEquals(UiText.forResult(wrong, 0)?.shown(), refused, "$wrong")
        }
        // The screens' own words for these results leave a refusal to the shared code's sentence.
        assertEquals(refused, passwordChangeWords(PasswordChangeResult.PROOF_REFUSED, 0)?.shown())
        assertEquals(refused, deviceLinkProofWords(ProofResult.PROOF_REFUSED, 0)?.shown())
        assertEquals(refused, twoStepWords(TwoStepResult.PROOF_REFUSED, 0)?.shown())
        assertEquals(refused, deletionWords(DeletionResult.PROOF_REFUSED, 0)?.shown())
    }

    /** Walked against the fake: each screen that asks for the master password, with the server refusing the proof. */
    @Test
    fun everyScreenThatAsksForTheMasterPasswordSaysARefusedProofAsTheServersRefusal() {
        val refused = sentence(CopyKey.SERVER_REFUSED_PROOF)
        fun check(m: TrustModel, api: FakeAppApi, section: String? = null, what: String) {
            val said = assertNotNull(if (section == null) m.saidOn(api.snapshot) else m.saidIn(api.snapshot, section), what)
            assertEquals("PROOF_REFUSED", (said.result as Enum<*>).name, what)
            assertEquals(refused, said.text.shown(), what)
        }

        // Settings: the password change, two-step sign-in, the devices list and its switch.
        var (api, m) = at(FakeScene.VAULTS)
        api.script.serverRefusesProof = true
        m.runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeWords(it, 0) })
        check(m, api, PASSWORD_CHANGE_SECTION, "the password change")
        m.run({ settings.openTwoStep() })
        m.runSaying({ settings.startTwoStep(assertNotNull(assertNotNull(snapshot.account).twoStep), FakeScenes.PASSWORD) }, { twoStepWords(it, 0) })
        check(m, api, what = "turning two-step sign-in on")
        m.run({ devices.openDevices() })
        val other = assertNotNull(assertNotNull(assertNotNull(api.snapshot.account).devices).devices.firstOrNull { !it.current })
        m.run({ devices.revokeDevice(other, FakeScenes.PASSWORD) })
        check(m, api, what = "signing a device out")
        m.run({ devices.setRequireLink(true, FakeScenes.PASSWORD) })
        check(m, api, what = "new devices must be linked")
        m.run({ recovery.makeKit(FakeScenes.PASSWORD) })
        check(m, api, what = "a new kit")

        // Approving a new device.
        at(FakeScene.HOST_LINK_TYPE_DIGITS).let { (a, mm) -> api = a; m = mm }
        api.script.serverRefusesProof = true
        m.run({ devices.submitDeviceDigits(assertIs(assertNotNull(snapshot.account).deviceLink), api.script.joiningDeviceCode) })
        val host = assertIs<DeviceLinkHost.Approvable>(assertNotNull(api.snapshot.account).deviceLink)
        m.runIn(DEVICE_LINK_SECTION, { devices.approveWithPassword(host, FakeScenes.PASSWORD) }, { deviceLinkProofWords(it, 0) })
        check(m, api, DEVICE_LINK_SECTION, "approving a new device")
        assertIs<DeviceLinkHost.Approvable>(assertNotNull(api.snapshot.account).deviceLink, "nothing was approved")

        // Operator recovery off.
        at(FakeScene.RECOVERY).let { (a, mm) -> api = a; m = mm }
        api.script.serverRefusesProof = true
        m.run({ recovery.turnOffOperatorRecovery(assertNotNull(assertNotNull(snapshot.account).recovery), FakeScenes.PASSWORD) })
        check(m, api, what = "operator recovery off")

        // Deleting the account (its email, the password and any code).
        at(FakeScene.DELETION).let { (a, mm) -> api = a; m = mm }
        api.script.serverRefusesProof = true
        val deletion = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        m.runIn(DELETION_SECTION, { settings.deleteAccount(deletion, deletion.email, FakeScenes.PASSWORD, null) }, { deletionWords(it, 0) }) { m.deletionAnswered(it) }
        check(m, api, DELETION_SECTION, "deleting the account")
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "nothing was deleted")

        // A kit that was not made, made again with the password.
        at(FakeScene.KIT_NOT_MADE).let { (a, mm) -> api = a; m = mm }
        api.script.serverRefusesProof = true
        m.run({ kit.retryKit(assertIs<EntryScreen.Kit>(snapshot.entry).kit, FakeScenes.PASSWORD) })
        check(m, api, what = "making the kit again")
    }
}
