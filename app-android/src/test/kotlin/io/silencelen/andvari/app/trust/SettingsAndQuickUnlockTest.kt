package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.MoveResult
import io.silencelen.andvari.core.app.QuickEnrolResult
import io.silencelen.andvari.core.app.QuickUnlockResult
import io.silencelen.andvari.core.app.QuickUnlockState
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Over the fake: quick unlock on the lock screen and in Settings, two-step sign-in, the client policy
 * driving the idle lock, the new kit after a followed move, the kit covered on background, and the notice for a saved
 * sign-in that could not be read.
 */
class SettingsAndQuickUnlockTest {
    private var now = 0L

    private fun at(scene: FakeScene, unreadable: () -> Boolean = { false }, replaced: () -> Unit = {}): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { now }, unreadable, replaced)
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    // ---- quick unlock on the lock screen (author notes 1 and 3) ----

    @Test
    fun quickUnlockOpensTheVaultWhileTheLockScreenOffersIt() {
        val (api, m) = at(FakeScene.LOCKED)
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.quickUnlock)
        m.runSaying({ quickUnlock(locked) }, { quickUnlockWords(it, 0) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(m.said.value)
    }

    @Test
    fun aCancelledPromptSaysNothingAndBiometricsThatChangedSayQuickUnlockIsOff() {
        val (api, m) = at(FakeScene.LOCKED)
        api.script.biometricsCancelled = true
        m.runSaying({ quickUnlock(assertNotNull(snapshot.locked)) }, { quickUnlockWords(it, 0) })
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.saidOn(api.snapshot), "CANCELLED says nothing")

        api.script.biometricsChanged = true
        m.runSaying({ quickUnlock(assertNotNull(snapshot.locked)) }, { quickUnlockWords(it, 0) })
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(QuickUnlockResult.TURNED_OFF, said.result)
        assertEquals(Placeholder.QUICK_UNLOCK_TURNED_OFF, (said.text as UiText.Ph).placeholder)
        assertFalse(assertNotNull(api.snapshot.locked).quickUnlock, "the button goes with it")
    }

    @Test
    fun theWordsForEachOutcomeFollowTheAuthorNote() {
        assertNull(quickUnlockWords(QuickUnlockResult.DONE, 0))
        assertNull(quickUnlockWords(QuickUnlockResult.CANCELLED, 0))
        assertEquals(Placeholder.QUICK_UNLOCK_USE_PASSWORD, (quickUnlockWords(QuickUnlockResult.USE_PASSWORD, 0) as UiText.Ph).placeholder)
        // SERVER_BLOCKED and IDENTITY_FAULT say what the password unlock says for them.
        assertEquals(
            UiText.forResult(io.silencelen.andvari.core.app.VaultUnlockResult.SERVER_BLOCKED, 0)?.shown(),
            quickUnlockWords(QuickUnlockResult.SERVER_BLOCKED, 0)?.shown(),
        )
        assertNull(quickEnrolWords(QuickEnrolResult.CANCELLED, 0))
        assertNull(quickEnrolWords(QuickEnrolResult.NOT_AVAILABLE, 0), "the setting's state says why")
    }

    @Test
    fun theLockScreenShowsTheButtonOnlyWhenOfferedAndKeepsThePasswordField() {
        val lock = src("AccountScreens.kt")
        assertTrue(lock.contains("if (locked.quickUnlock) {"))
        assertTrue(lock.contains("quickUnlock(locked)"))
        assertTrue(lock.indexOf("SecretField(") in 0 until lock.indexOf("if (locked.quickUnlock)"), "the password field is always there")
    }

    @Test
    fun theKeyWrapKeepsTheOldKeystoreParametersAndIsHandedToTheEngine() {
        val wrap = src("AndroidKeyWrap.kt")
        for (p in listOf("BIOMETRIC_STRONG", "setInvalidatedByBiometricEnrollment(true)", "setUserAuthenticationRequired(true)", "setUnlockedDeviceRequired(true)", "AUTH_BIOMETRIC_STRONG")) {
            assertTrue(wrap.contains(p), p)
        }
        assertFalse(wrap.contains("DEVICE_CREDENTIAL"), "a device passcode never counts")
        assertTrue(src("TrustSeam.kt").contains("keyWrap = keyWrap"))
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText().contains(".attach(this)"))
    }

    @Test
    fun theSealedFormParsesBackAndRefusesOtherShapes() {
        val iv = ByteArray(12) { it.toByte() }
        val ct = ByteArray(20) { 7 }
        val (piv, pct) = assertNotNull(AndroidKeyWrap.parse(byteArrayOf(1, 12) + iv + ct))
        assertTrue(piv.contentEquals(iv) && pct.contentEquals(ct))
        assertNull(AndroidKeyWrap.parse(byteArrayOf(2, 12) + iv + ct), "unknown version")
        assertNull(AndroidKeyWrap.parse(byteArrayOf(1, 12) + iv + ByteArray(15)), "shorter than a GCM tag")
        assertNull(AndroidKeyWrap.parse(byteArrayOf(1)))
    }

    // ---- quick unlock in Settings (author note 2) ----

    @Test
    fun settingsTurnsQuickUnlockOnAndOffAndTheOfferHasNotNow() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.quickUnlock = false
        api.script.changed()
        var setting = assertNotNull(api.snapshot.account).quickUnlock
        assertEquals(QuickUnlockState.OFF, setting.state)
        m.runSaying({ settings.turnOnQuickUnlock(setting) }, { quickEnrolWords(it, 0) })
        setting = assertNotNull(api.snapshot.account).quickUnlock
        assertEquals(QuickUnlockState.ON, setting.state)
        m.act { settings.turnOffQuickUnlock(setting) }
        assertEquals(QuickUnlockState.OFF, assertNotNull(api.snapshot.account).quickUnlock.state)
        val screen = src("SettingsScreens.kt")
        assertTrue(screen.contains("settings.quickUnlockNotNow(setting)") && screen.contains("if (setting.offerNow)"))
    }

    @Test
    fun quickUnlockWithoutABiometricSaysSo() {
        val (api, _) = at(FakeScene.VAULTS)
        api.script.biometricAvailable = false
        api.script.changed()
        val setting = assertNotNull(api.snapshot.account).quickUnlock
        assertEquals(Placeholder.QUICK_UNLOCK_UNAVAILABLE, (quickUnlockStateLine(setting) as UiText.Ph).placeholder)
    }

    // ---- two-step sign-in (author note 4) ----

    @Test
    fun twoStepIsTurnedOnWithThePasswordAndAFirstCodeAndOffWithACode() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ settings.openTwoStep() })
        var ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        assertFalse(ts.enabled)
        m.run({ settings.startTwoStep(ts, "wrong") })
        assertEquals(TwoStepResult.WRONG_PASSWORD, m.said.value?.result)
        m.run({ settings.startTwoStep(ts, FakeScenes.PASSWORD) })
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        val enrolment = assertNotNull(ts.enrolment)
        val key = assertNotNull(api.settings.twoStepKey(enrolment))
        assertTrue(key.uri.startsWith("otpauth://"))
        m.run({ settings.confirmTwoStep(enrolment, api.script.authenticatorCode) })
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        assertTrue(ts.enabled)
        assertNull(ts.enrolment)
        m.run({ settings.turnOffTwoStepWithPassword(ts, api.script.authenticatorCode, FakeScenes.PASSWORD) })
        assertFalse(assertNotNull(assertNotNull(api.snapshot.account).twoStep).enabled)
        // The key is read through twoStepKey, never from a snapshot, and shown as a QR code and as typed text.
        val screen = src("SettingsScreens.kt")
        assertTrue(screen.contains("settings.twoStepKey(enrolment)") && screen.contains("qrBitmap(shown.uri") && screen.contains("shown.secret"))
    }

    @Test
    fun turningTwoStepOffOrANewKeyTakeThePasswordAndEachRefusalSaysWhatItIs() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ settings.openTwoStep() })
        var ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.startTwoStep(ts, FakeScenes.PASSWORD) })
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.confirmTwoStep(assertNotNull(ts.enrolment), api.script.authenticatorCode) })
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        assertTrue(ts.enabled)
        // A code alone no longer turns it off: the shared code's own sentence, and it stays on.
        m.run({ settings.turnOffTwoStep(ts, api.script.authenticatorCode) })
        assertEquals(TwoStepResult.PASSWORD_NEEDED, m.said.value?.result)
        // A wrong password, then a wrong code: each said as what it is, and nothing changed.
        val wrongPassword = twoStepWords(TwoStepResult.WRONG_PASSWORD, 0)?.shown()
        val wrongCode = twoStepWords(TwoStepResult.WRONG_CODE, 0)?.shown()
        assertTrue(wrongPassword != null && wrongCode != null && wrongPassword != wrongCode)
        assertTrue(wrongPassword.contains("master password"), wrongPassword)
        assertTrue(wrongCode.contains("code"), wrongCode)
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.turnOffTwoStepWithPassword(ts, api.script.authenticatorCode, "not the password") })
        assertEquals(TwoStepResult.WRONG_PASSWORD, m.said.value?.result)
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.turnOffTwoStepWithPassword(ts, "000000", FakeScenes.PASSWORD) })
        assertEquals(TwoStepResult.WRONG_CODE, m.said.value?.result)
        // Too many tries: the shared code's sentence, with the wait when the server gave one.
        api.script.twoStepTriesLocked = true
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.replaceTwoStepKey(ts, api.script.authenticatorCode, FakeScenes.PASSWORD) })
        assertEquals(TwoStepResult.TOO_MANY_TRIES, m.said.value?.result)
        val tooMany = assertNotNull(twoStepWords(TwoStepResult.TOO_MANY_TRIES, 0)).shown()
        assertEquals(UiText.of(io.silencelen.andvari.core.app.CopyKey.TWO_STEP_TOO_MANY_TRIES).shown(), tooMany)
        // With a known wait: one sentence that names it, in place of the shared code's (never both: they say the same).
        val withWait = assertIs<UiText.Ph>(twoStepWords(TwoStepResult.TOO_MANY_TRIES, 42))
        assertEquals(Placeholder.TWO_STEP_WAIT, withWait.placeholder)
        assertEquals(listOf("42"), withWait.args)
        assertFalse(withWait.shown().contains(tooMany), withWait.shown())
        assertEquals(Placeholder.TWO_STEP_WAIT_ONE, assertIs<UiText.Ph>(twoStepWords(TwoStepResult.TOO_MANY_TRIES, 1)).placeholder)
        assertTrue(assertNotNull(assertNotNull(api.snapshot.account).twoStep).enabled, "still on after every refusal")
        // The right password and code: a new key waits for its first code, then turning it off works.
        api.script.twoStepTriesLocked = false
        ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.run({ settings.replaceTwoStepKey(ts, api.script.authenticatorCode, FakeScenes.PASSWORD) })
        assertNotNull(assertNotNull(assertNotNull(api.snapshot.account).twoStep).enrolment)
        // The screen: a master password field in that step, the two new calls, and both fields emptied at the tap.
        val screen = src("SettingsScreens.kt")
        val on = screen.substring(screen.indexOf("twoStep.enabled -> {"), screen.indexOf("else -> {", screen.indexOf("twoStep.enabled -> {")))
        assertTrue(on.contains("MasterPasswordField(s, password)"))
        assertTrue(on.contains("settings.turnOffTwoStepWithPassword(twoStep, c, p)") && on.contains("settings.replaceTwoStepKey(twoStep, c, p)"))
        assertFalse(on.contains("settings.turnOffTwoStep(twoStep"), "the call that takes a code alone is gone from the screen")
        for (call in listOf("turnOffTwoStepWithPassword", "replaceTwoStepKey")) {
            val at = on.indexOf("settings.$call(")
            val tap = on.lastIndexOf("val p = password", at)
            assertTrue(tap in 0 until at && on.substring(tap, at).contains("password = \"\"") && on.substring(tap, at).contains("code = \"\""), call)
        }
    }

    // ---- the client policy (author note 5) ----

    @Test
    fun theIdleLockReadsTheServersPolicy() {
        val (api, m) = at(FakeScene.VAULTS)
        val server = assertNotNull(api.script.server(assertNotNull(api.snapshot.instance).label.origin))
        server.autoLockSeconds = 60
        api.script.changed()
        assertEquals(60_000L, m.autoLockMs())
        now = 59_000
        m.tick()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        now = 60_000
        m.tick()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
    }

    @Test
    fun theClipboardWindowReadsThePolicyAndThePolicyIsShownReadOnly() {
        val (api, m) = at(FakeScene.VAULTS)
        val policy = assertNotNull(api.snapshot.account).policy
        assertEquals(policy.clipboardClearSeconds * 1000L, m.clipboardClearMs())
        // The policy's lines, by their keys, each filled with the policy's own number (whatever the words are).
        val lines = policyLines(policy).map { assertIs<UiText.Ph>(it) }
        assertEquals(Placeholder.POLICY_AUTO_LOCK, lines[0].placeholder)
        assertEquals(listOf(policy.autoLockSeconds.toString()), lines[0].args)
        assertEquals(Placeholder.POLICY_CLIPBOARD, lines[1].placeholder)
        assertEquals(listOf(policy.clipboardClearSeconds.toString()), lines[1].args)
    }

    // ---- change master password (map §3.18, slice 17) ----

    @Test
    fun theMasterPasswordIsChangedWithTheCurrentOneAndAWrongOneIsSaidInPlace() {
        val (api, m) = at(FakeScene.VAULTS)
        val strong = "a much longer master password, 2026!"
        assertFalse(passwordChangeReady(FakeScenes.PASSWORD, strong, strong + "x"), "typed differently twice")
        assertTrue(passwordChangeReady(FakeScenes.PASSWORD, strong, strong))
        m.run({ settings.changeMasterPassword("wrong", strong) })
        assertEquals(io.silencelen.andvari.core.app.PasswordChangeResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "a wrong current password is never an expired session")
        m.run({ settings.changeMasterPassword(FakeScenes.PASSWORD, strong) })
        assertNull(m.saidOn(api.snapshot))
        m.act { lock() }
        m.run({ unlock(assertNotNull(snapshot.locked), strong) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the new password opens the vault")
        // §4.4: the screen names the account and the instance, and says what the change does.
        val screen = src("SettingsScreens.kt")
        assertTrue(screen.contains("MasterPasswordField(s, current)") && screen.contains("Placeholder.CHANGE_PASSWORD_EFFECT"))
    }

    // ---- your devices and adding a device (map §3.10, §3.17, slice 16) ----

    @Test
    fun devicesListThisDeviceFirstAndNeverOfferToRevokeIt() {
        val (api, m) = at(FakeScene.DEVICES)
        val screen = assertNotNull(assertNotNull(api.snapshot.account).devices)
        val rows = devicesInOrder(screen)
        assertTrue(rows.first().current, "this device first")
        assertFalse(canRevoke(rows.first()))
        val other = assertNotNull(rows.firstOrNull { canRevoke(it) }, "another live device to revoke")
        m.run({ devices.revokeDevice(other, "wrong") })
        assertEquals(io.silencelen.andvari.core.app.ProofResult.WRONG_PASSWORD, m.saidOn(api.snapshot)?.result)
        m.run({ devices.revokeDevice(other, FakeScenes.PASSWORD) })
        assertNull(m.saidOn(api.snapshot))
        val after = assertNotNull(assertNotNull(api.snapshot.account).devices).devices.firstOrNull { it.deviceId == other.deviceId }
        assertTrue(after == null || !after.live, "the revoked device is gone or signed out")
        assertTrue(rows.all { assertIs<UiText.Ph>(howJoinedLine(it)).placeholder.name.startsWith("DEVICE_JOINED_") }, "how each joined, by its key")
    }

    /** Revoke for every device but this one, live or not; the switch with no state. */
    @Test
    fun revokeIsOfferedForADeviceThatIsNotLiveAndTheSwitchHasNoStateUntilThisDeviceSetsIt() {
        // A fresh session (the DEVICES scene sets the switch itself, so it is known there).
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ devices.openDevices() })
        val screen = assertNotNull(assertNotNull(api.snapshot.account).devices)
        val asleep = assertNotNull(screen.devices.firstOrNull { !it.live && !it.current }, "the scene has a device that is not live")
        assertTrue(canRevoke(asleep), "a device that is not live can still be revoked")
        assertTrue(screen.devices.filter { it.current }.none { canRevoke(it) })
        // The server serves no read of the setting: no state, both choices offered.
        assertFalse(screen.requireLinkKnown)
        assertEquals(listOf(true, false), requireLinkChoices(screen))
        m.run({ devices.setRequireLink(true, FakeScenes.PASSWORD) })
        val set = assertNotNull(assertNotNull(api.snapshot.account).devices)
        assertTrue(set.requireLinkKnown && set.requireLink)
        assertEquals(listOf(false), requireLinkChoices(set), "known and on: only \"off\" is offered")
        val view = src("DevicesScreens.kt").substringAfter("internal fun DevicesSection(").substringBefore("internal fun DeviceLinkHostView(")
        assertTrue(view.contains("Quiet(UiText.ph(requireLinkState(screen)))"))
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_UNKNOWN, requireLinkState(screen))
        assertTrue(view.contains("for (next in requireLinkChoices(screen))"))
    }

    @Test
    fun theApprovingSideTypesTheDigitsAndNeverShowsACode() {
        val (api, m) = at(FakeScene.HOST_LINK_TYPE_DIGITS)
        val host = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.TypeDigits>(assertNotNull(api.snapshot.account).deviceLink)
        m.run({ devices.submitDeviceDigits(host, api.script.joiningDeviceCode) })
        val approvable = assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Approvable>(assertNotNull(api.snapshot.account).deviceLink)
        m.run({ devices.approveWithPassword(approvable, FakeScenes.PASSWORD) })
        assertIs<io.silencelen.andvari.core.app.DeviceLinkHost.Approved>(assertNotNull(api.snapshot.account).deviceLink)
        val view = src("DevicesScreens.kt").substringAfter("internal fun DeviceLinkHostView(")
        assertFalse(view.contains("joiningDeviceCode") || view.contains(".code"), "this side never shows a code")
        assertTrue(view.contains("deviceLinkTimeLeftMs()"), "the countdown is the API's, never the device clock")
        assertFalse(view.contains("System.currentTimeMillis"))
    }

    // ---- recovery settings (map §3.16, slice 17) ----

    @Test
    fun operatorRecoveryIsTurnedOnOnlyThroughTheTickedWarningAndOffWithThePassword() {
        val (api, m) = at(FakeScene.RECOVERY_WARNING_IN_SETTINGS)
        val warning = assertNotNull(assertNotNull(assertNotNull(api.snapshot.account).recovery).warning)
        m.run({ recovery.turnOnOperatorRecovery(warning, false, FakeScenes.PASSWORD) })
        assertEquals(io.silencelen.andvari.core.app.RecoveryChangeResult.NOT_TICKED, m.saidOn(api.snapshot)?.result)
        val again = assertNotNull(assertNotNull(assertNotNull(api.snapshot.account).recovery).warning)
        m.run({ recovery.turnOnOperatorRecovery(again, true, FakeScenes.PASSWORD) })
        var screen = assertNotNull(assertNotNull(api.snapshot.account).recovery)
        assertEquals(io.silencelen.andvari.core.app.WhoCanRecover.ME_OR_OPERATOR, screen.whoCanRecover, "said: ${m.said.value?.text?.shown()}")
        m.run({ recovery.turnOffOperatorRecovery(screen, FakeScenes.PASSWORD) })
        screen = assertNotNull(assertNotNull(api.snapshot.account).recovery)
        assertEquals(io.silencelen.andvari.core.app.WhoCanRecover.ONLY_ME, screen.whoCanRecover)
        val src = src("RecoverySettingsScreens.kt")
        assertTrue(src.contains("enabled = understood && password.isNotEmpty()"), "turning on needs the tick")
        assertTrue(src.contains("CopyKey.RECOVERY_TURN_OFF_NOTE"))
    }

    // ---- people, the comparison codes and the prompts (map §3.11, §3.16, §3.22; slices 13 and 17) ----

    @Test
    fun comparingCodesTakesTheirDigitsRefusesOurOwnAndHasNoTheyMatchButton() {
        val (api, m) = at(FakeScene.COMPARE_READY)
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(assertNotNull(api.snapshot.account).comparing)
        assertTrue(ownCodeTypedBack(ready, ready.code), "our own code typed back is refused before anything is sent")
        val theirs = assertNotNull(api.script.codeTheyReadOut(ready.userId))
        assertFalse(ownCodeTypedBack(ready, theirs))
        m.run({ contacts.submitComparison(ready, theirs) })
        assertIs<io.silencelen.andvari.core.app.CompareScreen.Matched>(assertNotNull(api.snapshot.account).comparing, "said: ${m.said.value?.text?.shown()}")
        val view = src("PeopleScreens.kt").substringAfter("internal fun CompareView(").substringBefore("internal fun ownCodeTypedBack")
        assertFalse(view.contains("match\") {") || view.contains("THEY_MATCH"), "no 'they match' button")
        // Our own code typed back goes to the shared code like any entry (the codes may be equal), and its mismatch says so.
        assertTrue(view.contains("model.runSaying({ contacts.submitComparison(c, d) }, { r -> comparisonWords(model, c, d, r) })"))
    }

    @Test
    fun aWrongCodeSaysTheDesignsSentence() {
        val (api, m) = at(FakeScene.COMPARE_READY)
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(assertNotNull(api.snapshot.account).comparing)
        val wrong = (0..999_999).asSequence().map { it.toString().padStart(6, '0') }
            .first { it != ready.code && it != api.script.codeTheyReadOut(ready.userId) }
        m.run({ contacts.submitComparison(ready, wrong) })
        assertEquals(io.silencelen.andvari.core.app.CopyKey.CODES_DO_NOT_MATCH.english, m.saidOn(api.snapshot)?.text?.shown())
    }

    @Test
    fun theKeepOperatorRecoveryPromptDefaultsToNotNowAndSendsNothing() {
        val (api, m) = at(FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY)
        if (api.snapshot.phase != AppPhase.UNLOCKED) m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val prompt = assertNotNull(assertNotNull(api.snapshot.account).prompts.filterIsInstance<io.silencelen.andvari.core.app.AccountPrompt.KeepOperatorRecovery>().firstOrNull())
        m.act { recovery.keepOperatorRecoveryNotNow(prompt) }
        assertTrue(assertNotNull(api.snapshot.account).prompts.none { it is io.silencelen.andvari.core.app.AccountPrompt.KeepOperatorRecovery })
        val src = src("PeopleScreens.kt")
        assertTrue(src.indexOf("CopyKey.KEEP_OPERATOR_NOT_NOW") < src.indexOf("CopyKey.KEEP_OPERATOR_KEEP"), "Not now first, as the default")
        assertTrue(src.indexOf("CopyKey.RECOVERY_KEY_CHANGED_TURN_OFF") < src.indexOf("CopyKey.RECOVERY_KEY_CHANGED_KEEP"), "Turn off first, as the default")
    }

    @Test
    fun theOneTapPeopleListUsesTheTickedPeople() {
        val (api, m) = at(FakeScene.PEOPLE_LIST)
        val prompt = assertNotNull(assertNotNull(api.snapshot.account).prompts.filterIsInstance<io.silencelen.andvari.core.app.AccountPrompt.PeopleList>().firstOrNull())
        m.run({ contacts.usePeople(prompt, prompt.people.map { it.userId }) })
        assertTrue(assertNotNull(api.snapshot.account).prompts.none { it is io.silencelen.andvari.core.app.AccountPrompt.PeopleList }, "said: ${m.said.value?.text?.shown()}")
    }

    // ---- links (map §3.11, slice 14) ----

    @Test
    fun aConnectLinkIsMadeSharedAndRevoked() {
        val (api, m) = at(FakeScene.LINKS)
        val before = assertNotNull(assertNotNull(api.snapshot.account).links).links.size
        m.run({ links.createConnectLink(emptyList(), connectLifetimes.first()) })
        val screen = assertNotNull(assertNotNull(api.snapshot.account).links)
        assertEquals(before + 1, screen.links.size, "said: ${m.said.value?.text?.shown()}")
        val link = screen.links.last()
        assertNotNull(api.links.linkToShare(link))
        assertTrue(api.links.linkTimeLeftMs(link) > 0)
        m.run({ links.revokeLink(link) })
        assertEquals(before, assertNotNull(assertNotNull(api.snapshot.account).links).links.size)
        assertTrue(connectLifetimes.all { it in io.silencelen.andvari.core.app.LinkLifetimes.SHORTEST_MINUTES..io.silencelen.andvari.core.app.LinkLifetimes.CONNECT_LONGEST_MINUTES })
        val src = src("LinksScreens.kt")
        assertTrue(src.contains("ExternalExcursion.begin()"), "the share sheet does not lock the vault")
        assertTrue(src.contains("model.clipboardClearMs()"), "a copied link is cleared after the policy's window")
    }

    @Test
    fun anOpenedConnectInviteConnectsAndCancelComesFirst() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        val opened = assertIs<io.silencelen.andvari.core.app.OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        m.run({ links.connect(opened) })
        assertTrue(assertNotNull(api.snapshot.account).opened !is io.silencelen.andvari.core.app.OpenedInvite.Connect, "said: ${m.said.value?.text?.shown()}")
        val view = src("LinksScreens.kt").substringAfter("internal fun OpenedInviteView(")
        assertTrue(view.indexOf("links.dismissOpened()") < view.indexOf("when (opened)"))
    }

    @Test
    fun theUncomparedWarningReleasesOneShare() {
        val (api, m) = at(FakeScene.SHARE_WARNING)
        val w = assertNotNull(assertNotNull(api.snapshot.account).shareWarning)
        m.run({ vaults.confirmUncomparedShare(w) })
        assertNull(assertNotNull(api.snapshot.account).shareWarning, "said: ${m.said.value?.text?.shown()}")
    }

    // ---- shared vaults, members and moving everything (map §3.12 to §3.14, slice 15) ----

    @Test
    fun everyVaultLogStateHasALineAndTheDesignsSentencesAreUsed() {
        val (api, _) = at(FakeScene.VAULT_STATES)
        val rows = assertNotNull(api.snapshot.account).vaults
        val states = rows.map { it.log }.toSet()
        assertTrue(states.size > 3, "the scene shows many states: $states")
        for (r in rows) {
            val line = logStateLine(r)
            if (r.log == io.silencelen.andvari.core.app.VaultLogState.VERIFIED) assertNull(line) else assertNotNull(line, r.log.name)
            r.log.sentence?.let { assertEquals(it.english, line?.shown()) }
            // A person the server names is never shown bare (T-R5).
            (r.owner as? io.silencelen.andvari.core.app.PersonName.Unverified)?.let {
                assertTrue(personLine(it).shown().startsWith(io.silencelen.andvari.core.app.CopyKey.MEMBER_UNVERIFIED.english))
            }
        }
    }

    @Test
    fun aMemberIsAddedAndRemovedByTheOwner() {
        val (api, m) = at(FakeScene.MEMBERS)
        var screen = assertNotNull(assertNotNull(api.snapshot.account).members)
        assertTrue(screen.canManage)
        val other = assertNotNull(screen.members.firstOrNull { it.who !is io.silencelen.andvari.core.app.PersonName.You && it.role != io.silencelen.andvari.core.app.RoleInVault.OWNER })
        m.run({ vaults.removeMember(other) })
        screen = assertNotNull(assertNotNull(api.snapshot.account).members)
        assertTrue(screen.members.none { it.userId == other.userId }, "said: ${m.said.value?.text?.shown()}")
        val src = src("VaultScreens.kt")
        assertTrue(src.contains("Say(CopyKey.REMOVE_MEMBER_WARNING)") && src.contains("moveEverythingRemoving(model, m)"), "remove is behind the warning, which offers the move for that member")
    }

    @Test
    fun movingEverythingFromAFrozenVaultTicksNobodyAndWarns() {
        val (api, _) = at(FakeScene.MOVE_EVERYTHING_FROZEN)
        val screen = assertNotNull(assertNotNull(api.snapshot.account).moving)
        assertTrue(screen.members.none { it.ticked })
        assertTrue(screen.sourceStays)
        assertTrue(src("VaultScreens.kt").contains("if (screen.sourceStays) {\n        Say(CopyKey.CHECK_WHAT_YOU_COPY"))
    }

    // ---- delete account (map §3.19, slice 17) ----

    @Test
    fun deletionNeedsTheTypedAddressAndThePasswordAndEndsAtTheFirstScreen() {
        val (api, m) = at(FakeScene.DELETION)
        var screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        val plan = assertNotNull(screen.plan)
        assertTrue(plan.canProceed)
        assertFalse(deletionReady(screen, "", FakeScenes.PASSWORD, "246810"))
        val code = if (plan.codeNeeded) api.script.authenticatorCode else null
        m.run({ settings.deleteAccount(screen, "someone.else@example.com", FakeScenes.PASSWORD, code) })
        assertEquals(io.silencelen.andvari.core.app.DeletionResult.EMAIL_MISMATCH, m.saidOn(api.snapshot)?.result)
        screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        assertTrue(deletionReady(screen, screen.email, FakeScenes.PASSWORD, code ?: ""))
        m.run({ settings.deleteAccount(screen, screen.email, FakeScenes.PASSWORD, code) })
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "said: ${m.said.value?.text?.shown()}")
    }

    @Test
    fun aBlockedDeletionOffersNoWayPastItsBlockers() {
        val (api, _) = at(FakeScene.DELETION_BLOCKED)
        val screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        val plan = assertNotNull(screen.plan)
        assertFalse(plan.canProceed)
        assertFalse(deletionReady(screen, screen.email, FakeScenes.PASSWORD, "246810"))
        assertTrue(plan.blockers.all { assertIs<UiText.Ph>(deletionBlockerLine(it)).placeholder.name.startsWith("DELETION_BLOCKER_") }, "each blocker, by its key")
        assertTrue(src("SettingsScreens.kt").contains("if (plan.canProceed) {"))
    }

    @Test
    fun anUnknownOutcomeIsCheckedNeverReportedAsDoneOrFailed() {
        val (api, _) = at(FakeScene.DELETION_OUTCOME_UNKNOWN)
        val screen = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        assertTrue(screen.outcomeUnknown)
        assertFalse(deletionReady(screen, screen.email, FakeScenes.PASSWORD, "246810"))
        assertTrue(src("SettingsScreens.kt").contains("settings.checkDeletion(screen)"))
    }

    // ---- a new kit after a followed move (author note 6) ----

    @Test
    fun afterAFollowedMoveTheShellAsksForANewKit() {
        val (api, m) = at(FakeScene.CARD_MOVED)
        val moved = assertIs<InstanceCardState.Moved>(assertNotNull(api.snapshot.instance).card)
        m.run({ instance.followMove(moved) })
        assertEquals(MoveResult.DONE, m.said.value?.result ?: MoveResult.DONE)
        val prompt = assertNotNull(assertNotNull(api.snapshot.account).kitAfterMove, "a followed move asks for a new kit")
        m.act { recovery.kitAfterMoveLater(prompt) }
        assertNull(assertNotNull(api.snapshot.account).kitAfterMove, "Later puts it off until the next unlock")
        assertTrue(src("AccountScreens.kt").contains("account.kitAfterMove?.let { KitAfterMoveCard("))
        assertTrue(src("SettingsScreens.kt").contains("recovery.makeKit(p)"))
    }

    // ---- the kit before the vault opens, on background (item 6) ----

    @Test
    fun theKitBeforeTheVaultOpensLocksWhenTheAppGoesToTheBackground() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        assertIs<EntryScreen.Kit>(api.snapshot.entry)
        m.backgrounded()
        // lock() acts on the kit step now: the kit and the keys go, the lock screen comes up.
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the kit's keys do not wait in the background")
        assertNull(api.snapshot.entry)
        m.onSnapshot(api.snapshot)
        assertFalse(m.kitCovered.value, "the cover goes with the kit")
        // The idle window acts there too (as on the desktop).
        assertTrue(m.locksNow(api.snapshot).not())
        assertTrue(src("KitScreens.kt").contains("if (covered && (kit.step == KitStep.REVEAL || kit.step == KitStep.CONFIRM))"))
    }

    @Test
    fun theKitStepLocksAfterTheIdleWindow() {
        val (api, m) = at(FakeScene.KIT_REVEAL)
        assertTrue(m.locksNow(api.snapshot))
        now += m.autoLockMs() - 1
        m.tick()
        assertIs<EntryScreen.Kit>(api.snapshot.entry, "not before the window")
        now += 1
        m.tick()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
    }

    // ---- a saved sign-in that could not be read (item 5) ----

    @Test
    fun anUnreadableSavedSignInIsNotSilentOnTheFirstScreen() {
        var replacedCalls = 0
        val (api, m) = at(FakeScene.FIRST_RUN, unreadable = { true }, replaced = { replacedCalls++ })
        m.onSnapshot(api.snapshot)
        assertTrue(m.savedSignInUnreadable.value)
        assertEquals(0, replacedCalls, "the unreadable file is kept until a new session replaces it")
        m.dismissSavedSignInNotice()
        m.onSnapshot(api.snapshot)
        assertFalse(m.savedSignInUnreadable.value)
        assertTrue(src("EntryScreens.kt").contains("Placeholder.SAVED_SIGN_IN_UNREADABLE"))
    }

    @Test
    fun theKeptCopyGoesOnceANewSessionIsOpen() {
        var replacedCalls = 0
        val (api, m) = at(FakeScene.VAULTS, unreadable = { true }, replaced = { replacedCalls++ })
        m.onSnapshot(api.snapshot)
        assertEquals(1, replacedCalls)
        assertFalse(m.savedSignInUnreadable.value, "not on the first screen")
    }
}
