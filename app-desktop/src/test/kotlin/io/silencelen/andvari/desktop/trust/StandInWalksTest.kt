package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.KitRecoverResult
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeScript
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KeptWayOut
import io.silencelen.andvari.core.app.KitWipedNotice
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Seven walks of the desktop over the shared code's stand-in, as the window's model ([TrustModel]) runs each step: a deletion
 * that kept the server; a device link's "too many requests" on both computers; the offer to forget an account after a
 * deletion of unknown outcome, across a lock; a session this computer could not confirm; a proof refused at a device
 * link; and, under a server's policy that keeps the account's keys at the server, the server's end and the unlocks the
 * server does not let through. Each step prints what the desktop draws (`WALK|<step>|<line>`, in the test report's output), and the assertions
 * are of what the screen must say. Nothing here leans on the stand-in's restart.
 */
class StandInWalksTest {
    private val pw = FakeScenes.PASSWORD
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")

    private fun model(api: FakeDesktopAppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }

    private inline fun <reified T : EntryScreen> on(api: FakeDesktopAppApi): T = assertIs<T>(api.snapshot.entry, "on ${api.snapshot.phase} ${api.snapshot.entry}")

    private fun unlocked(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        m.run({ unlock(assertNotNull(snapshot.locked), pw) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun account(api: FakeDesktopAppApi, email: String = FakeScenes.EMAIL): FakeAccount =
        api.script.publicInstance.accounts.values.first { it.email == email }

    private val bare = setOf(Placeholder.TROUBLE, Placeholder.REFUSAL, Placeholder.RESERVED_COPY)

    private fun isBare(t: UiText?): Boolean = (t as? UiText.Ph)?.placeholder in bare

    /** Prints what the desktop draws at [step], one line each, and flags a line without wording. */
    private fun draws(step: String, lines: List<UiText?>) {
        val shown = lines.filterNotNull()
        if (shown.isEmpty()) println("WALK|$step|(nothing)")
        for (l in shown) println("WALK|$step|${if (isBare(l)) "WITHOUT WORDING: " else ""}${l.shown()}")
    }

    /** What the window says in place on the screen on show now, as [SaidHere] draws it. */
    private fun said(api: FakeDesktopAppApi, m: TrustModel): UiText? = saidDrawn(m, api.snapshot)?.text

    /** The whole window over [m], drawn, with the words of each control the keyboard reaches. */
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    private class Window(m: TrustModel) {
        val focus = ArrayList<String>()
        private var t = 0L
        private val scene = ImageComposeScene(900, 3000, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides focus) { MaterialTheme { TrustApp(m, null, "log") } }
        }

        fun render() = repeat(2) {
            t += 50_000_000L
            scene.render(t)
        }

        init {
            render()
        }

        private fun press(key: Key) {
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyDown))
            scene.sendKeyEvent(KeyEvent(key, KeyEventType.KeyUp))
            render()
        }

        /** Every control the keyboard reaches, in one round of Tab. */
        fun controls(most: Int = 60): Set<String> {
            repeat(most) { press(Key.Tab) }
            return focus.toSet()
        }

        fun tabUntil(words: String, most: Int = 80) {
            repeat(most) {
                if (focus.lastOrNull() == words) return
                press(Key.Tab)
            }
            assertEquals(words, focus.lastOrNull(), focus.toString())
        }

        fun enter() = press(Key.Enter)

        fun close() = scene.close()
    }

    // ---- 1. a deletion with the server kept ----

    /**
     * The open account is deleted with the server's confirmation while this computer keeps something of another account at
     * that server. The first screen says the shared code's notice as handed (the server kept), the keyboard's dismiss takes
     * it away, and nothing on the screen offers to forget anything.
     */
    @Test
    fun aDeletionWithTheServerKeptSaysItsNoticeAsHandedGoesByItsDismissAndOffersNoForgetting() {
        val (api, m) = unlocked()
        api.script.anotherAccountKnownAtServer = true
        m.run({ settings.openDeletion() })
        m.onSnapshot(api.snapshot)
        val deletion = assertNotNull(api.snapshot.account?.deletion)
        var answer: DeletionResult? = null
        m.deleteAccount(deletion, FakeScenes.EMAIL, pw, null) { answer = it }
        m.onSnapshot(api.snapshot)
        assertEquals(DeletionResult.DONE, answer)

        // 1a. The first screen: the notice, as handed.
        val first = on<EntryScreen.FirstRun>(api)
        val deleted = assertNotNull(first.accountDeleted, "the notice")
        assertFalse(deleted.serverForgotten, "the server is kept")
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, deleted.line.key)
        assertTrue(FakeScenes.EMAIL in deleted.line.values && api.script.publicInstance.origin in deleted.line.values, "the account and its server, named")
        assertSame(deleted, m.accountDeletedNotice())
        assertTrue(body("EntryScreens.kt", "internal fun FirstRunScreen(").contains("Say(UiText.of(deleted.line))"), "drawn as handed")
        draws("1a the first screen's notice", listOf(UiText.of(deleted.line)))
        assertNull(said(api, m), "nothing said beside it")
        draws("1a said", listOf(said(api, m)))
        // Nothing offers to forget anything: no earlier account, no forgetting after an unknown deletion, no first-screen
        // notice of a deletion of unknown outcome.
        assertNull(api.snapshot.earlierAccount)
        assertNull(m.forgetUnknownCheck())
        assertNull(first.deletionOutcomeUnknown)
        val forgetWords = setOf(
            UiText.of(CopyKey.REMADE_ACCOUNT_FORGET).shown(), UiText.of(CopyKey.REMADE_ACCOUNT_CONFIRM_FORGET).shown(),
            UiText.of(CopyKey.DELETION_UNKNOWN_FORGET_OFFER).shown(), UiText.ph(Placeholder.FORGET_UNKNOWN_CONFIRM).shown(),
        )
        val w = Window(m)
        try {
            val controls = w.controls()
            println("WALK|1a the first screen's controls|$controls")
            assertTrue(UiText.ph(Placeholder.DISMISS).shown() in controls, "the notice's dismiss is in reach: $controls")
            assertTrue(controls.none { it in forgetWords }, "nothing offers to forget: $controls")
            // 1b. The dismiss, from the keyboard.
            w.tabUntil(UiText.ph(Placeholder.DISMISS).shown())
            w.enter()
        } finally {
            w.close()
        }
        m.onSnapshot(api.snapshot)
        assertNull(on<EntryScreen.FirstRun>(api).accountDeleted, "dismissed")
        assertNull(m.accountDeletedNotice())
        draws("1b after the dismiss", listOfNotNull(on<EntryScreen.FirstRun>(api).accountDeleted?.let { UiText.of(it.line) }, said(api, m)))
        assertNull(api.snapshot.earlierAccount)
        assertNull(m.forgetUnknownCheck())
    }

    // ---- 2. a device link's "too many requests" ----

    /**
     * On the computer that joins: the claim after the scan refused as too many (it stays at the scan, and says so with
     * the wait), then the pickup after the password refused as too many (the link's end, with the wait). On the computer
     * that shows the link: its start, the digits and the approval, each refused as too many. Every line says the wait as a
     * length of time, on the screen the person is on, and none is a line without wording.
     */
    @Test
    fun aDeviceLinksTooManyRequestsIsSaidWithItsWaitOnTheScreenThePersonLandsOnOnBothComputers() {
        // The computer that joins.
        val api = FakeScenes.desktopAt(FakeScene.LINK_DEVICE_ENTRY)
        val m = model(api)
        val ada = api.script.publicInstance.addAccount(FakeScenes.EMAIL, pw)
        api.script.linkTooMany = true
        var scanned: DeviceLinkScanResult? = null
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(ada, "MacBook"), PayloadSource.PASTED) }) { scanned = it }
        m.onSnapshot(api.snapshot)
        assertEquals(DeviceLinkScanResult.RATE_LIMITED, scanned)
        on<EntryScreen.LinkDeviceEntry>(api)
        val wait = api.retryAfterSeconds()
        assertTrue(wait > 0, "the stand-in keeps a wait")
        val claim = said(api, m)
        draws("2a the joining computer: the claim refused, at the scan", listOf(claim))
        assertNotNull(claim, "said where the person is")
        assertFalse(isBare(claim), "a line with words, not 'without wording': ${claim.shown()}")
        assertTrue(claim.shown().contains(waitText(wait).shown()), "the wait as a length of time: ${claim.shown()}")

        // The scan again, once the wait ran out, goes through; the pickup after the password is refused as too many: the
        // link's end.
        api.script.advance((wait + 1) * 1000L)
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(ada, "MacBook"), PayloadSource.PASTED) })
        api.script.otherDeviceAnswers()
        api.script.otherDeviceApproves()
        m.onSnapshot(api.snapshot)
        val password = on<EntryScreen.LinkDevicePassword>(api)
        api.script.linkTooMany = true
        var picked: LinkPasswordResult? = null
        m.run({ entry.submitLinkPassword(password, pw) }) { picked = it }
        m.onSnapshot(api.snapshot)
        assertEquals(LinkPasswordResult.RATE_LIMITED, picked)
        val ended = on<EntryScreen.LinkDeviceEnded>(api)
        assertEquals(LinkDeviceEnd.TOO_MANY, ended.outcome)
        val endLine = linkDeviceEndLine(ended.outcome, api.retryAfterSeconds())
        draws("2b the joining computer: the link's end", listOf(endLine, said(api, m)))
        assertEquals(UiText.filled(CopyKey.DEVICE_LINK_TOO_MANY, waitText(api.retryAfterSeconds()).shown()).shown(), endLine.shown())
        assertNull(said(api, m), "the end says it; nothing is said twice")
        assertTrue(body("LinkAndRecoveryScreens.kt", "internal fun LinkDeviceEndedScreen(").contains("Say(linkDeviceEndLine(screen.outcome, model.readOr(0) { model.api.retryAfterSeconds() }))"))
        // Once the wait has run out, the same screen says "a while".
        api.script.advance((api.retryAfterSeconds() + 1) * 1000L)
        draws("2b the joining computer: the link's end after the wait ran out", listOf(linkDeviceEndLine(ended.outcome, api.retryAfterSeconds())))

        // The computer that shows the link: its start.
        val host = FakeScenes.desktopAt(FakeScene.VAULTS)
        val h = model(host)
        host.script.linkTooMany = true
        var started: PlainResult? = null
        h.run({ devices.startDeviceLink() }) { started = it }
        h.onSnapshot(host.snapshot)
        assertEquals(PlainResult.RATE_LIMITED, started)
        assertNull(host.snapshot.account?.deviceLink, "no link")
        val start = said(host, h)
        draws("2c the showing computer: the link's start refused", listOf(start))
        assertNotNull(start)
        assertFalse(isBare(start), "a line with words, not 'without wording': ${start.shown()}")
        assertTrue(start.shown().contains(waitText(host.retryAfterSeconds()).shown()), "the wait: ${start.shown()}")

        // The digits refused as too many: the link ends with its own line; nothing else is said.
        host.script.advance(60_000L)
        typeDigitsUpTo(host, h)
        val type = assertIs<DeviceLinkHost.TypeDigits>(host.snapshot.account?.deviceLink)
        host.script.linkTooMany = true
        var digits: DigitsResult? = null
        h.run({ devices.submitDeviceDigits(type, host.script.joiningDeviceCode) }) { digits = it }
        h.onSnapshot(host.snapshot)
        assertEquals(DigitsResult.RATE_LIMITED, digits)
        val endedAtDigits = assertIs<DeviceLinkHost.Ended>(host.snapshot.account?.deviceLink)
        assertEquals(CopyKey.DEVICE_LINK_HOST_TOO_MANY, endedAtDigits.line)
        val digitsEnd = deviceLinkHostEndText(endedAtDigits, host.retryAfterSeconds())
        draws("2d the showing computer: the digits refused, the link's end", listOf(digitsEnd))
        draws("2d said beside it", listOf(said(host, h)))
        assertEquals(UiText.filled(CopyKey.DEVICE_LINK_HOST_TOO_MANY, waitText(host.retryAfterSeconds()).shown()).shown(), digitsEnd.shown())
        assertNull(said(host, h), "the link's end says it with the wait; no second line, and none without wording")

        // The approval refused as too many, as the approve button runs it.
        h.act { devices.dismissDeviceLink() }
        host.script.advance(60_000L)
        typeDigitsUpTo(host, h)
        h.run({ devices.submitDeviceDigits(assertIs(snapshot.account?.deviceLink), host.script.joiningDeviceCode) })
        h.onSnapshot(host.snapshot)
        val approvable = assertIs<DeviceLinkHost.Approvable>(host.snapshot.account?.deviceLink)
        host.script.linkTooMany = true
        var approved: ProofResult? = null
        h.runSaying({ devices.approveWithPassword(approvable, pw) }, { deviceLinkApproveLine(it, h.api.retryAfterSeconds()) }) { approved = it }
        h.onSnapshot(host.snapshot)
        assertEquals(ProofResult.RATE_LIMITED, approved)
        val endedAtApproval = assertIs<DeviceLinkHost.Ended>(host.snapshot.account?.deviceLink)
        val approvalEnd = deviceLinkHostEndText(endedAtApproval, host.retryAfterSeconds())
        draws("2e the showing computer: the approval refused, the link's end", listOf(approvalEnd))
        draws("2e said beside it", listOf(said(host, h)))
        assertEquals(UiText.filled(CopyKey.DEVICE_LINK_HOST_TOO_MANY, waitText(host.retryAfterSeconds()).shown()).shown(), approvalEnd.shown())
        assertNull(said(host, h), "the link's end says it with the wait; no second line, and none without wording")
        assertTrue(body("SettingsScreens.kt", "internal fun DeviceLinkHostView(").contains("model.runSaying({ devices.approveWithPassword(host, p) }, { deviceLinkApproveLine(it, model.api.retryAfterSeconds()) })"), "as the button runs it")
    }

    /** The showing computer: a new link, claimed and revealed, at the digits. */
    private fun typeDigitsUpTo(host: FakeDesktopAppApi, h: TrustModel) {
        var started: PlainResult? = null
        h.run({ devices.startDeviceLink() }) { started = it }
        assertEquals(PlainResult.DONE, started)
        host.script.joiningDeviceClaims("Laptop", AppPlatform.WINDOWS)
        host.script.joiningDeviceReveals(true)
        h.onSnapshot(host.snapshot)
    }

    // ---- 3. the offer after a deletion of unknown outcome ----

    /**
     * The deletion's answer is lost: its screen offers to forget the account here; its second step says the shared code's
     * confirmation and its count of changes not sent. A lock takes that step back; the lock screen offers a NEW offer
     * object, whose count is what this computer can tell with the copy closed; its second step draws that object's lines,
     * and the forgetting answers with the first screen.
     */
    @Test
    fun theOfferAfterADeletionOfUnknownOutcomeAcrossALockWithItsCountItsLinesAndItsAnswer() {
        val (api, m) = unlocked()
        m.run({ settings.openDeletion() })
        api.script.deletionAnswerLost = true
        m.deleteAccount(assertNotNull(api.snapshot.account?.deletion), FakeScenes.EMAIL, pw, null)
        m.onSnapshot(api.snapshot)
        assertTrue(assertNotNull(api.snapshot.account?.deletion).outcomeUnknown)
        draws("3a the deletion's screen says", listOf(said(api, m)))
        assertEquals(Placeholder.DELETION_OUTCOME_UNKNOWN, (said(api, m) as? UiText.Ph)?.placeholder)

        // 3a. The offer, then its second step.
        val open = assertNotNull(m.forgetUnknownCheck(), "the offer")
        draws("3a the offer", listOf(UiText.of(open.offerLine)))
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_OFFER, open.offerLine.key)
        m.askToForgetAfterUnknownDeletion(open)
        assertSame(open, m.forgetUnknownAsked.value)
        println("WALK|3a the count of changes not sent, the copy open|${open.unsentChanges}")
        draws("3a the second step", forgetUnknownConfirmLines(open) + listOf(UiText.of(CopyKey.CANCEL), UiText.ph(Placeholder.FORGET_UNKNOWN_CONFIRM)))
        assertEquals(listOf(UiText.of(open.confirmLine).shown(), UiText.of(open.unsentLine).shown()), forgetUnknownConfirmLines(open).map { it.shown() })

        // 3b. A lock: the step goes back; the lock screen offers a new object, with its own count.
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.forgetUnknownAsked.value, "the lock took the second step back")
        assertNull(m.forgetAfterUnknownDeletion(open), "the old confirmation sends nothing")
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.deletionOutcomeUnknown)
        draws("3b the lock screen", listOf(UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN_LOCKED), said(api, m)))
        val onLock = assertNotNull(m.forgetUnknownCheck(), "the lock screen's offer")
        assertNotSame(open, onLock, "a new offer object")
        println("WALK|3b the count of changes not sent, the copy closed|${onLock.unsentChanges}")
        draws("3b the offer", listOf(UiText.of(onLock.offerLine)))
        assertNull(onLock.unsentChanges, "with the copy closed this computer cannot tell")

        // 3c. Its second step: the new object's confirmation and count.
        m.askToForgetAfterUnknownDeletion(onLock)
        assertSame(onLock, m.forgetUnknownAsked.value)
        val lines = forgetUnknownConfirmLines(onLock)
        draws("3c the second step", lines + listOf(UiText.of(CopyKey.CANCEL), UiText.ph(Placeholder.FORGET_UNKNOWN_CONFIRM)))
        assertEquals(listOf(CopyKey.DELETION_UNKNOWN_FORGET_CONFIRM, CopyKey.DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL), listOf(onLock.confirmLine.key, onLock.unsentLine.key))
        assertEquals(listOf(UiText.of(onLock.confirmLine).shown(), UiText.of(onLock.unsentLine).shown()), lines.map { it.shown() })
        assertTrue(FakeScenes.EMAIL in onLock.confirmLine.values, "the account named")
        assertTrue(lines.none { isBare(it) })

        // 3d. The answer: the first screen, the account gone from this computer; nothing said of its own.
        assertNotNull(m.forgetAfterUnknownDeletion(onLock))
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        val first = on<EntryScreen.FirstRun>(api)
        assertNull(api.snapshot.keptSignedOut, "the account is gone from this computer")
        assertNull(m.forgetUnknownCheck(), "no offer any more")
        assertNull(first.deletionOutcomeUnknown)
        assertNull(first.accountDeleted, "never 'deleted'")
        draws("3d the answer", listOf(said(api, m), first.notice?.let { firstRunNotice(it) }))
        assertNull(said(api, m))
    }

    // ---- 4. a session this computer could not confirm ----

    /**
     * The kept session's end is this computer's own (it could not confirm it in time). The lock screen says that end, the
     * first screen after "Sign in again" says it, and the way out that signs the kept account out (another account's
     * sign-in refused while it is kept) says it without "sign in again". Never the server's end.
     */
    @Test
    fun aSessionThisComputerCouldNotConfirmIsSaidAsItsOwnEndNeverTheServers() {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        val m = model(api)
        api.script.sessionNotConfirmed()
        m.onSnapshot(api.snapshot)

        // 4a. The lock screen.
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.signedOutByServer && locked.sessionNotConfirmed)
        val end = serverEndText(api.snapshot)
        draws("4a the lock screen's card", listOf(end, UiText.ph(Placeholder.SIGN_IN_AGAIN)))
        assertEquals(UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown(), end.shown(), "that end, as the shared code says it")
        assertNotEquals(Placeholder.SIGNED_OUT_BY_SERVER, (end as? UiText.Ph)?.placeholder, "never the server's end")
        draws("4a said", listOf(said(api, m)))
        assertNull(said(api, m))

        // 4b. "Sign in again": the first screen.
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        val first = on<EntryScreen.FirstRun>(api)
        assertTrue(first.sessionNotConfirmed)
        assertNull(first.notice, "no notice of the server's end")
        draws("4b the first screen", listOfNotNull(if (first.sessionNotConfirmed) UiText.of(CopyKey.SESSION_NOT_CONFIRMED) else null, first.notice?.let { firstRunNotice(it) }, said(api, m)))
        assertTrue(body("EntryScreens.kt", "internal fun FirstRunScreen(").contains("if (screen.sessionNotConfirmed) {\n            Say(UiText.of(CopyKey.SESSION_NOT_CONFIRMED))"))

        // 4c. Another account's sign-in while this one is kept: refused, with the kept account's sign-out as the way out.
        api.script.publicInstance.addAccount("bo@example.com", pw)
        m.act { entry.openSignIn(first) }
        m.act { entry.openPasswordSignIn(on(api)) }
        var chosen: ServerResult? = null
        m.run({ entry.choosePublicInstance(on(api)) }) { chosen = it }
        assertEquals(ServerResult.DONE, chosen)
        var answer: SignInAnswer? = null
        m.run({ entry.submitSignIn(on(api), "bo@example.com", pw) }) { answer = it }
        m.onSnapshot(api.snapshot)
        assertEquals(SignInAnswer.ANOTHER_ACCOUNT_KEPT, answer)
        val refusal = assertNotNull(saidDrawn(m, api.snapshot), "the refusal is said on the sign-in screen")
        val way = assertIs<WayOut.SignOutKept>(wayOutOf(refusal.result, refusal.text, api.snapshot), "the kept account's sign-out")
        draws("4c the way out's lines", way.lines + way.button)
        assertTrue(api.snapshot.keptSignedOutNotConfirmed)
        assertEquals(Placeholder.KEPT_ACCOUNT_NOT_CONFIRMED_SIGN_OUT_FIRST, (way.lines.first() as? UiText.Ph)?.placeholder, "the account named without the server's end")
        assertTrue(way.lines.any { it.shown() == UiText.of(CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST).shown() }, "the shared code's line for that end beside a sign-out")
        assertTrue(way.lines.none { it.shown() == UiText.of(CopyKey.SESSION_NOT_CONFIRMED).shown() }, "never 'sign in again' beside a sign-out")
        assertTrue(way.lines.none { (it as? UiText.Ph)?.placeholder in setOf(Placeholder.KEPT_ACCOUNT_SIGN_OUT_FIRST, Placeholder.SIGNED_OUT_BY_SERVER) }, "never the server's end")
        assertTrue(way.lines.none { isBare(it) })
    }

    // ---- 5. a proof refused at a device link ----

    /**
     * This computer keeps the account, signed out by its server, and its copy still opens with the password from before a
     * change it could not follow. A device link to that account, with that password: the server refuses the proof. The
     * password step stays and says the shared code's line for it, never a wrong password; the current password then links.
     */
    @Test
    fun aProofRefusedAtADeviceLinkIsSaidAsItselfOnThePasswordStepWhichStays() {
        val (api, m) = unlocked()
        val ada = account(api)
        val newer = "a whole new Master password 9"
        api.script.deviceCannotFollowPassword = true
        var changed: PasswordChangeResult? = null
        m.run({ settings.changeMasterPassword(pw, newer) }) { changed = it }
        assertEquals(PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE, changed)
        api.script.sessionEndedByServer()
        m.onSnapshot(api.snapshot)
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openLinkDevice(on(api)) }
        var scanned: DeviceLinkScanResult? = null
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(ada, "MacBook"), PayloadSource.PASTED) }) { scanned = it }
        assertEquals(DeviceLinkScanResult.DONE, scanned)
        api.script.otherDeviceAnswers()
        api.script.otherDeviceApproves()
        m.onSnapshot(api.snapshot)
        val step = on<EntryScreen.LinkDevicePassword>(api)
        draws("5a the password step", listOf(step.prompt.title?.let { UiText.of(it) }, UiText.ph(Placeholder.PASSWORD_FIELD)))

        // 5b. The former password: the proof refused.
        var refused: LinkPasswordResult? = null
        m.run({ entry.submitLinkPassword(step, pw) }) { refused = it }
        m.onSnapshot(api.snapshot)
        assertEquals(LinkPasswordResult.PROOF_REFUSED, refused)
        assertSame(step, api.snapshot.entry, "the password step stays")
        val line = assertNotNull(said(api, m), "said on the password step")
        draws("5b the proof refused", listOf(line, UiText.ph(Placeholder.PASSWORD_FIELD)))
        assertNull(wayOutOf(saidDrawn(m, api.snapshot)?.result, line, api.snapshot), "said as itself, with no way out drawn in its place")
        assertEquals(UiText.of(CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT).shown(), line.shown())
        assertNotEquals(UiText.forResult(LinkPasswordResult.WRONG, 0)?.shown(), line.shown(), "never a wrong password")
        assertFalse(isBare(line))
        assertTrue(body("LinkAndRecoveryScreens.kt", "internal fun LinkDevicePasswordScreen(").contains("SaidHere(model, s)"))

        // 5c. The current password links.
        var linked: LinkPasswordResult? = null
        m.run({ entry.submitLinkPassword(on(api), newer) }) { linked = it }
        m.onSnapshot(api.snapshot)
        println("WALK|5c the current password|$linked ${api.snapshot.phase}")
        assertEquals(LinkPasswordResult.DONE, linked)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    // ---- 6 and 7. a server's policy that keeps the account's keys at the server ----

    /** Opened once under a policy that keeps the account's keys at the server, then locked: the lock screen with its line. */
    private fun keysAtServerLocked(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.LOCKED)
        api.script.publicInstance.offlineCacheAllowed = false
        val m = model(api)
        m.run({ unlock(assertNotNull(snapshot.locked), pw) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        api.lock()
        m.onSnapshot(api.snapshot)
        assertNotNull(api.snapshot.locked?.keysAtServerLine, "the lock screen carries the keys' line")
        return api to m
    }

    /** The person types [password] on the lock screen and presses Unlock: the answer and what the screen then says. */
    private fun unlockOnScreen(api: FakeDesktopAppApi, m: TrustModel, password: String): Pair<VaultUnlockResult?, UiText?> {
        var answer: VaultUnlockResult? = null
        m.run({ unlock(assertNotNull(snapshot.locked), password) }) { answer = it }
        m.onSnapshot(api.snapshot)
        return answer to said(api, m)
    }

    /** Every line the lock screen draws, in its order: the keys' line, the card for the session's end, and what is said in place. */
    private fun lockLines(api: FakeDesktopAppApi, m: TrustModel): List<UiText?> {
        val locked = assertNotNull(api.snapshot.locked)
        return listOf(
            locked.keysAtServerLine?.let { UiText.of(it) },
            if (locked.signedOutByServer) serverEndText(api.snapshot) else null,
            if (locked.previousPasswordOpensCopy) UiText.ph(Placeholder.LOCKED_PREVIOUS_PASSWORD_OPENS) else null,
            if (locked.deletionOutcomeUnknown) UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN_LOCKED) else null,
            said(api, m),
        )
    }

    /** Nothing opened and nothing removed: the same lock screen for the same account, and no account open. */
    private fun nothingOpened(api: FakeDesktopAppApi, title: UiText, step: String) {
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, step)
        assertNull(api.snapshot.account, step)
        assertEquals(title.shown(), lockTitle(assertNotNull(api.snapshot.locked, step)).shown(), "$step: the same account is kept")
    }

    /**
     * A notice that a kit was wiped which names the kept session of [mark] as what stands in the way, with its sign-out as
     * the way out: the stand-in has no road to it on the lock screen, so it is made as the shared code makes it (through
     * the constructor whose parameters are its fields; a field added later fails here loudly).
     */
    private fun kitWipedNaming(mark: String): KitWipedNotice {
        val c = KitWipedNotice::class.java
        val fields = c.declaredFields.filter { !java.lang.reflect.Modifier.isStatic(it.modifiers) && !it.isSynthetic }
        val ctor = c.declaredConstructors.single { k -> k.parameterTypes.toList() == fields.map { it.type } }.also { it.isAccessible = true }
        val values = mapOf<String, Any>(
            "email" to "bo@example.com", "line" to CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, "whyHere" to CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT,
            "wayOut" to KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, "unseen" to false, "namedKept" to mark,
        )
        return ctor.newInstance(*fields.map { values.getValue(it.name) }.toTypedArray()) as KitWipedNotice
    }

    /**
     * The server ends the session while the account's keys are kept at the server. The lock screen says the shared code's
     * line for that end in place of the desktop's own card, with "Sign in again", and nothing on it says that a copy opens;
     * an unlock says the end's own sentence and opens nothing; beside a way out that signs the kept account out, the line
     * for that end does not say "sign in again"; after "Sign in again", another account's refusal names the kept account
     * and its sign-out, never "sign in again".
     */
    @Test
    fun theServersEndWhileTheKeysAreAtTheServerIsTheSharedCodesLineAndNothingOpens() {
        val (api, m) = keysAtServerLocked()
        val title = lockTitle(assertNotNull(api.snapshot.locked))
        api.script.sessionEndedByServer()
        m.onSnapshot(api.snapshot)

        // 6a. The lock screen.
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        val lines = lockLines(api, m)
        draws("6a the lock screen", lines + UiText.ph(Placeholder.SIGN_IN_AGAIN))
        assertEquals(UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER).shown(), serverEndText(api.snapshot).shown(), "the shared code's line for that end")
        val opensCopy = setOf(Placeholder.SIGNED_OUT_BY_SERVER, Placeholder.LOCKED_PREVIOUS_PASSWORD_OPENS)
        assertTrue(lines.filterNotNull().none { (it as? UiText.Ph)?.placeholder in opensCopy || isBare(it) }, "nothing says that a copy opens; every line has words")
        assertEquals(lines.filterNotNull().size, lines.filterNotNull().map { it.shown() }.distinct().size, "no line twice")
        val window = Window(m)
        val controls = window.controls()
        window.close()
        println("WALK|6a the keyboard's controls|$controls")
        assertTrue(UiText.ph(Placeholder.SIGN_IN_AGAIN).shown() in controls, "Sign in again beside it")

        // 6b. An unlock, right and wrong password alike: the end's own sentence, once, and nothing opens.
        for (password in listOf(pw, "not the password at all 1")) {
            val (answer, line) = unlockOnScreen(api, m, password)
            draws("6b unlock (${if (password == pw) "right" else "wrong"} password)", lockLines(api, m))
            assertEquals(VaultUnlockResult.KEYS_AT_SERVER_ENDED, answer)
            assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).shown(), line?.shown())
            assertEquals(1, lockLines(api, m).count { it?.shown() == line?.shown() }, "said once")
            nothingOpened(api, title, "6b")
        }

        // 6c. Beside a way out that signs this kept account out (a wiped kit's notice names it): the line for that end
        // that does not say "sign in again". A notice that names another kept session leaves the end's usual line.
        val mark = locked.prompt.keptMark
        assertTrue(mark.isNotEmpty())
        val beside = serverEndText(rebuilt(api.snapshot, "kitWiped" to kitWipedNaming(mark)))
        draws("6c beside the kept account's sign-out", listOf(beside))
        assertEquals(UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER_SIGN_OUT_FIRST).shown(), beside.shown())
        assertEquals(
            UiText.of(CopyKey.SIGNED_OUT_KEYS_AT_SERVER).shown(),
            serverEndText(rebuilt(api.snapshot, "kitWiped" to kitWipedNaming(mark + "-another"))).shown(),
        )

        // 6d. "Sign in again", then another account's sign-in: refused, with the kept account's sign-out as the way out.
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        val first = on<EntryScreen.FirstRun>(api)
        draws("6d the first screen", listOf(first.notice?.let { firstRunNotice(it) }, said(api, m)))
        api.script.publicInstance.addAccount("bo@example.com", pw)
        m.act { entry.openSignIn(first) }
        m.act { entry.openPasswordSignIn(on(api)) }
        m.run({ entry.choosePublicInstance(on(api)) })
        var answer: SignInAnswer? = null
        m.run({ entry.submitSignIn(on(api), "bo@example.com", pw) }) { answer = it }
        m.onSnapshot(api.snapshot)
        assertEquals(SignInAnswer.ANOTHER_ACCOUNT_KEPT, answer)
        val refusal = assertNotNull(saidDrawn(m, api.snapshot))
        val way = assertIs<WayOut.SignOutKept>(wayOutOf(refusal.result, refusal.text, api.snapshot))
        draws("6d the way out's lines", way.lines + way.button)
        val saysSignInAgain = listOf(CopyKey.SIGNED_OUT_KEYS_AT_SERVER, CopyKey.UNLOCK_KEYS_AT_SERVER_ENDED).map { UiText.of(it).shown() }
        assertTrue(way.lines.none { it.shown() in saysSignInAgain || isBare(it) || (it as? UiText.Ph)?.placeholder == Placeholder.SIGNED_OUT_BY_SERVER })
    }

    /**
     * Under the same policy, unlocks the server does not let through: one it did not answer (its own sentence, once, a
     * right and a wrong password alike), one it refused, and one it held back as too many requests (the wait). Nothing
     * opens and nothing is removed in any of them; the same password opens once the server lets it.
     */
    @Test
    fun anUnlockTheServerDidNotAnswerRefusedOrHeldBackIsSaidOnceAndOpensNothing() {
        val (api, m) = keysAtServerLocked()
        val title = lockTitle(assertNotNull(api.snapshot.locked))
        val unanswered = UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_UNREACHABLE).shown()

        // 7a. The server does not answer.
        api.script.publicInstance.reachable = false
        for (password in listOf(pw, "not the password at all 1")) {
            val (answer, line) = unlockOnScreen(api, m, password)
            val lines = lockLines(api, m)
            draws("7a unanswered (${if (password == pw) "right" else "wrong"} password)", lines)
            assertEquals(VaultUnlockResult.KEYS_AT_SERVER_UNREACHABLE, answer)
            assertEquals(unanswered, line?.shown())
            assertEquals(1, lines.count { it?.shown() == unanswered }, "said once")
            assertTrue(lines.filterNotNull().none { isBare(it) || (it as? UiText.Ph)?.placeholder == Placeholder.TROUBLE_UNREACHABLE }, "no general trouble line, nothing without wording")
            nothingOpened(api, title, "7a")
        }
        api.script.publicInstance.reachable = true

        // 7b. The server refuses the keys.
        api.script.forceNext(VaultUnlockResult.KEYS_AT_SERVER_REFUSED)
        val (refused, refusedLine) = unlockOnScreen(api, m, pw)
        draws("7b refused", lockLines(api, m))
        assertEquals(VaultUnlockResult.KEYS_AT_SERVER_REFUSED, refused)
        assertEquals(UiText.of(CopyKey.UNLOCK_KEYS_AT_SERVER_REFUSED).shown(), refusedLine?.shown())
        assertNotEquals(unanswered, refusedLine?.shown(), "never 'did not answer'")
        nothingOpened(api, title, "7b")

        // 7c. Too many requests: the wait.
        api.script.rateLimitNext(120)
        val (held, heldLine) = unlockOnScreen(api, m, pw)
        draws("7c too many requests", lockLines(api, m))
        assertEquals(VaultUnlockResult.RATE_LIMITED, held)
        assertEquals(Placeholder.TROUBLE_TOO_MANY, (heldLine as? UiText.Ph)?.placeholder)
        assertTrue(assertNotNull(heldLine).shown().contains(waitText(120).shown()), "the wait, as a length of time")
        nothingOpened(api, title, "7c")

        // 7d. The server lets it through: the same password opens.
        val (opened, _) = unlockOnScreen(api, m, pw)
        println("WALK|7d the server answers|$opened ${api.snapshot.phase}")
        assertEquals(VaultUnlockResult.DONE, opened)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    // ---- 8 to 10. the identity fault, a link that ends where this computer cannot tell, a frozen old vault ----

    /**
     * [screen] as the shared code would hand it with the identity fault's line: through its constructor, whose parameters
     * are the screen's journey (held by [EntryScreen]) and then its own fields; every other field is carried as it is, and
     * a constructor that no longer matches fails here loudly.
     */
    private fun withIdentityFault(screen: EntryScreen.OperatorHelp): EntryScreen.OperatorHelp {
        val c = screen.javaClass
        val fields = c.declaredFields.filter { !java.lang.reflect.Modifier.isStatic(it.modifiers) && !it.isSynthetic }
        val flow = EntryScreen::class.java.declaredFields.single { it.name == "flow" }.also { it.isAccessible = true }
        val ctor = c.declaredConstructors.single { k -> k.parameterTypes.toList() == listOf(flow.type) + fields.map { it.type } }.also { it.isAccessible = true }
        val args = listOf(flow.get(screen)) + fields.map { f -> if (f.name == "identityFault") CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN else f.also { it.isAccessible = true }.get(screen) }
        return ctor.newInstance(*args.toTypedArray()) as EntryScreen.OperatorHelp
    }

    /**
     * The identity fault says its own line: at a sign-in (above the offer to forget the earlier account), at a kit's check
     * and at a new account's making, and on an operator's request's screen with no way out. A forgetting confirmed after the
     * address came to name the account the server serves says its own sentence, with no offer and nothing to read again.
     */
    @Test
    fun theIdentityFaultAndAForgettingOvertakenSayTheirOwnLines() {
        val fault = UiText.of(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN).shown()
        // 8a. The results of a kit's check and a new account's making, as the desktop says any result in place.
        for (r in listOf(SignInAnswer.IDENTITY_FAULT, KitRecoverResult.IDENTITY_FAULT, CreateAccountResult.IDENTITY_FAULT)) {
            val line = UiText.forResult(r, 0)
            draws("8a ${r.javaClass.simpleName}.IDENTITY_FAULT", listOf(line))
            assertEquals(fault, line?.shown(), "${r.javaClass.simpleName}: the result's own line")
        }

        // 8b. A sign-in refused for the identity fault, where the shared code offers to forget the earlier account.
        val api = FakeScenes.desktopAt(FakeScene.SIGN_IN)
        val m = model(api)
        api.script.publicInstance.addAccount("eve@example.com", pw)
        api.script.earlierAccountKnown = true
        api.script.identityFault = true
        m.run({ entry.submitSignIn(on(api), "eve@example.com", pw) })
        m.onSnapshot(api.snapshot)
        val offer = assertNotNull(api.snapshot.earlierAccount, "the offer")
        val above = assertNotNull(saidDrawn(m, api.snapshot), "said above the offer")
        draws("8b above the offer", listOf(above.text))
        assertSame(SignInAnswer.IDENTITY_FAULT, above.result)
        assertEquals(fault, above.text.shown())

        // 8c. The forgetting's second step; the address comes to name the account the server serves; the confirmation.
        m.quietly { api.entry.askToForgetEarlierAccount(offer) }
        m.onSnapshot(api.snapshot)
        val confirming = assertNotNull(api.snapshot.earlierAccount)
        assertTrue(confirming.confirming)
        api.script.addressTiedToServed = true
        var forgot: ForgetEarlierResult? = null
        kotlinx.coroutines.runBlocking { m.runSaying({ entry.forgetEarlierAccount(confirming) }, words = { x -> earlierResultLine(confirming, x) }) { forgot = it }.join() }
        m.onSnapshot(api.snapshot)
        val said = said(api, m)
        draws("8c the forgetting overtaken", listOf(said))
        assertEquals(ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT, forgot)
        assertEquals(assertNotNull(earlierResultLine(confirming, ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT)).shown(), said?.shown())
        assertEquals(CopyKey.REMADE_ACCOUNT_FORGET_ADDRESS_NOW_SERVED, ForgetEarlierResult.ADDRESS_NOW_THE_SERVED_ACCOUNT.sentence)
        assertNull(api.snapshot.earlierAccount, "no offer")
        assertNotEquals(earlierResultLine(confirming, ForgetEarlierResult.NOT_CONFIRMED)?.shown(), said?.shown(), "nothing to read again")
        assertFalse(isBare(said))

        // 8d. The operator's answer for the kept account under another key: the identity fault's line on the request's
        // screen, in place of its stage, with no way out (the stand-in has no road to it: the shared code's screen with
        // that field, through the constructor of its fields).
        val held = FakeScenes.desktopAt(FakeScene.OPERATOR_HELP_HOLDING)
        val request = withIdentityFault(assertIs<EntryScreen.OperatorHelp>(held.snapshot.entry))
        val stop = operatorHelpStop(request)
        draws("8d the request's screen", listOf(stop?.let { UiText.of(it) }))
        assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, stop)
        assertNull(request.wayOut)
        assertNull(operatorHelpWayOut(request, held.snapshot), "no offer")
        assertNull(held.snapshot.earlierAccount)
    }

    /**
     * A device link ends where this computer cannot tell from the link alone a remade account from a substitution: the ended
     * link says its line, offers the password sign-in that the line points to beside another link, and no offer to forget
     * anything. The password sign-in, as its button runs it, is the password's way, and it signs in.
     */
    @Test
    fun aLinkThatEndedWhereThisComputerCannotTellOffersThePasswordSignInBesideAnotherLink() {
        val (api, m) = unlocked()
        val ada = account(api)
        api.script.sessionEndedByServer()
        m.onSnapshot(api.snapshot)
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openLinkDevice(on(api)) }
        api.script.linkIdentityCannotTell = true
        m.run({ entry.submitDeviceLink(on(api), api.script.deviceLinkFrom(ada, "MacBook"), PayloadSource.PASTED) })
        api.script.otherDeviceAnswers()
        api.script.otherDeviceApproves()
        m.onSnapshot(api.snapshot)
        val ended = on<EntryScreen.LinkDeviceEnded>(api)
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL, ended.outcome)

        // 9a. The ended link's screen.
        val line = linkDeviceEndLine(ended.outcome, 0)
        draws("9a the ended link", listOf(line, said(api, m)))
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_IDENTITY_CANNOT_TELL).shown(), line.shown())
        assertNull(said(api, m), "said once")
        assertNull(api.snapshot.earlierAccount, "no offer to forget")
        assertNull(linkEndWayOut(ended, api.snapshot))
        assertTrue(offersPasswordSignIn(ended))
        val window = Window(m)
        val controls = window.controls()
        window.close()
        println("WALK|9a the keyboard's controls|$controls")
        assertTrue(UiText.of(CopyKey.SIGN_IN_PASSWORD).shown() in controls, "the password sign-in the line points to")
        assertTrue(UiText.of(CopyKey.SIGN_IN_LINK_DEVICE).shown() in controls, "beside another link")

        // 9b. The password sign-in, as its button runs it: the password's way, and the kept account signs in.
        m.act { toPasswordSignIn(ended) }
        println("WALK|9b the password sign-in|${api.snapshot.entry?.javaClass?.simpleName}")
        var chosen: ServerResult? = null
        m.run({ entry.choosePublicInstance(on(api)) }) { chosen = it }
        assertEquals(ServerResult.DONE, chosen)
        var answer: SignInAnswer? = null
        m.run({ entry.submitSignIn(on(api), ada.email, pw) }) { answer = it }
        m.onSnapshot(api.snapshot)
        println("WALK|9b signed in|$answer ${api.snapshot.phase}")
        assertEquals(SignInAnswer.DONE, answer)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    /** A move whose deletion of the old vault meets that vault frozen: the frozen line, no line without wording, and the old vault read-only. */
    @Test
    fun aMoveThatMeetsAFrozenOldVaultSaysSoAndLeavesItReadOnly() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        fun family() = assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }
        api.script.nextMoveStop = FakeScript.MoveStopAt.OLD_VAULT_FROZEN_AT_RESEND
        m.run({ vaults.openMoveEverything(family()) })
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        m.onSnapshot(api.snapshot)
        val screen = assertNotNull(api.snapshot.account?.moving)
        val stop = assertNotNull(screen.stopped)
        val lines = moveStopLines(screen, 0)
        draws("10a the move's stop", lines)
        assertEquals(MoveStage.DELETE_OLD_VAULT, stop.stage)
        assertEquals(VaultActionResult.READ_ONLY, stop.result)
        assertEquals(CopyKey.MOVE_OLD_VAULT_FROZEN, stop.line)
        assertTrue(lines.none { isBare(it) }, "no line without wording")
        assertEquals(2, lines.size, "the step and the frozen line")
        val old = family()
        println("WALK|10b the old vault|deleted=${old.deleted} writable=${old.writable} log=${old.log}")
        assertFalse(old.writable, "read-only")
        assertFalse(old.deleted, "its deletion was not sent")
    }
}
