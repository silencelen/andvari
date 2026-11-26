package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeviceLinkHost
import io.silencelen.andvari.core.app.DeviceLinkScanResult
import io.silencelen.andvari.core.app.DigitsResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.LinkPasswordResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ServerKind
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * A device link the server refuses as one of too many requests, walked through this app's model over the shared code's
 * fake, which plays the engine's answers at each step (the claim, the pickup, the link's start, the digits, the
 * approval): the wait is said as a length of time and never as "unreachable"; a link that ends says its own line, on the
 * new phone and on the one that showed it, never "a check failed".
 */
class DeviceLinkTooManyWalksTest {
    private fun phone(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)
        return fake to m
    }

    /** What the screen says after the model ran [intent] as a screen runs it. */
    private fun FakeAppApi.say(m: TrustModel, intent: suspend io.silencelen.andvari.core.app.AppApi.() -> io.silencelen.andvari.core.app.IntentResult): TrustModel.Said {
        runBlocking { m.run(intent).join() }
        m.onSnapshot(snapshot)
        return assertNotNull(m.saidOn(snapshot), "said on the screen")
    }

    private val unreachable = UiText.ph(Placeholder.TROUBLE_UNREACHABLE).shown()

    private fun body(file: String, head: String) =
        java.io.File("src/main/kotlin/io/silencelen/andvari/app/trust/$file").readText().substringAfter(head).substringBefore("\n}\n")

    private fun <R : io.silencelen.andvari.core.app.IntentResult> TrustModel.answer(intent: suspend io.silencelen.andvari.core.app.AppApi.() -> R): R {
        var r: R? = null
        runBlocking { run(intent) { r = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(r)
    }

    /** The showing phone: a new link, claimed and revealed, at the digits. */
    private fun typeDigitsUpTo(host: FakeAppApi, h: TrustModel) {
        assertEquals(PlainResult.DONE, h.answer { devices.startDeviceLink() })
        host.script.joiningDeviceClaims("Laptop", AppPlatform.WINDOWS)
        host.script.joiningDeviceReveals(true)
        h.onSnapshot(host.snapshot)
    }

    /** As the link's card runs a step: its answer in the link's own section. */
    private fun <R : io.silencelen.andvari.core.app.IntentResult> TrustModel.inLink(intent: suspend io.silencelen.andvari.core.app.AppApi.() -> R, words: (R) -> UiText?): R {
        var r: R? = null
        runBlocking { runIn(DEVICE_LINK_SECTION, intent, words) { r = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(r)
    }

    /**
     * The whole walk, step by step, on the screen the person lands on each time. The joining phone: the claim at the scan
     * refused (it stays where a link is handed in, and says so with the wait), then the pickup after the password refused
     * (the link's end, with the wait, said once). The showing phone: its start, the digits and the approval, each refused.
     * Never a line without wording, never "unreachable", never a second line beside an ended link's card.
     */
    @Test
    fun aDeviceLinksTooManyRequestsIsSaidOnceWithItsWaitOnEveryScreenThePersonLandsOnAsJoinerAndAsHost() {
        val (fake, m) = phone(FakeScene.LINK_DEVICE_ENTRY)
        val ada = fake.script.publicInstance.addAccount(FakeScenes.EMAIL, FakeScenes.PASSWORD)
        fake.script.linkTooMany = true

        // b1. The joining phone: the claim at the scan refused.
        val claim = fake.say(m) { entry.submitDeviceLink(assertIs(snapshot.entry), fake.script.deviceLinkFrom(ada, "MacBook"), PayloadSource.SCANNED) }
        assertEquals(DeviceLinkScanResult.RATE_LIMITED, claim.result)
        assertIs<EntryScreen.LinkDeviceEntry>(fake.snapshot.entry, "stays where a link is handed in")
        val wait = fake.retryAfterSeconds()
        WalkPrint.draws("b1 the joining phone: the claim refused, at the scan", listOf(claim.text))
        kotlin.test.assertFalse(WalkPrint.isBare(claim.text), "a line with words")
        assertNotEquals(unreachable, claim.text.shown(), "never \"unreachable\"")
        assertEquals(assertNotNull(UiText.forResult(ServerResult.RATE_LIMITED, wait)).shown(), claim.text.shown(), "the wait")
        kotlin.test.assertTrue(claim.text.shown().contains(wait.toString()), claim.text.shown())

        // b2. After the wait the scan goes through; the pickup after the password is refused: the link's end.
        fake.script.advance((wait + 1) * 1000L)
        assertEquals(DeviceLinkScanResult.DONE, m.answer { entry.submitDeviceLink(assertIs(snapshot.entry), fake.script.deviceLinkFrom(ada, "MacBook"), PayloadSource.SCANNED) })
        fake.script.otherDeviceAnswers()
        fake.script.otherDeviceApproves()
        m.onSnapshot(fake.snapshot)
        val password = assertIs<EntryScreen.LinkDevicePassword>(fake.snapshot.entry)
        fake.script.linkTooMany = true
        assertEquals(LinkPasswordResult.RATE_LIMITED, m.answer { entry.submitLinkPassword(password, FakeScenes.PASSWORD) })
        val ended = assertIs<EntryScreen.LinkDeviceEnded>(fake.snapshot.entry)
        assertEquals(LinkDeviceEnd.TOO_MANY, ended.outcome)
        val endLine = OutcomeWords.linkDeviceEnd(ended.outcome, m.api.retryAfterSeconds())
        WalkPrint.draws("b2 the joining phone: the link's end", listOf(endLine))
        assertEquals(UiText.of(CopyKey.DEVICE_LINK_TOO_MANY, OutcomeWords.waitLength(fake.retryAfterSeconds()).shown()).shown(), endLine.shown())
        // Said once: the ended screen draws no answer in place, and no way out or offer beside its line.
        val endedScreen = body("LinkAndRecoveryScreens.kt", "internal fun LinkDeviceEndedScreen(")
        kotlin.test.assertTrue(endedScreen.contains("Say(OutcomeWords.linkDeviceEnd(screen.outcome, model.api.retryAfterSeconds()))"))
        kotlin.test.assertFalse(endedScreen.contains("SaidHere"), "nothing said beside the end")
        assertNull(wayOutFor(ended.outcome))
        assertNull(fake.snapshot.earlierAccount)
        WalkPrint.draws("b2 said beside it", emptyList())
        // Once the wait has run out, the same screen reads the wait as it stands now.
        fake.script.advance((fake.retryAfterSeconds() + 1) * 1000L)
        WalkPrint.draws("b2 the joining phone: the link's end after the wait ran out", listOf(OutcomeWords.linkDeviceEnd(ended.outcome, m.api.retryAfterSeconds())))

        // b3. The showing phone: its start refused; no link.
        val (host, h) = phone(FakeScene.VAULTS)
        host.script.linkTooMany = true
        val start = host.say(h) { devices.startDeviceLink() }
        assertEquals(PlainResult.RATE_LIMITED, start.result)
        assertNull(assertNotNull(host.snapshot.account).deviceLink, "no link")
        WalkPrint.draws("b3 the showing phone: the link's start refused", listOf(start.text))
        kotlin.test.assertFalse(WalkPrint.isBare(start.text))
        assertNotEquals(unreachable, start.text.shown())
        kotlin.test.assertTrue(start.text.shown().contains(host.retryAfterSeconds().toString()), start.text.shown())

        // The ended card draws its own line and no answer in place beside it (SaidIn only while the link is shown or
        // claimed, or at the digits and the approval before they end; the top's SaidHere skips a section's answer).
        val endedCard = body("DevicesScreens.kt", "internal fun DeviceLinkHostView(").substringAfter("is DeviceLinkHost.Ended -> {").substringBefore("        }\n")
        kotlin.test.assertFalse(endedCard.contains("SaidIn") || endedCard.contains("SaidHere"), endedCard)
        kotlin.test.assertTrue(body("DevicesScreens.kt", "internal fun DeviceLinkHostView(").contains("if (host is DeviceLinkHost.Shown || host is DeviceLinkHost.Claimed) SaidIn(model, s, DEVICE_LINK_SECTION)"))

        // b4. The digits refused, as the card runs them.
        host.script.advance(60_000L)
        typeDigitsUpTo(host, h)
        val type = assertIs<DeviceLinkHost.TypeDigits>(assertNotNull(host.snapshot.account).deviceLink)
        host.script.linkTooMany = true
        assertEquals(DigitsResult.RATE_LIMITED, h.inLink({ devices.submitDeviceDigits(type, host.script.joiningDeviceCode) }, { deviceDigitsWords(it, h.api.retryAfterSeconds()) }))
        val atDigits = assertIs<DeviceLinkHost.Ended>(assertNotNull(host.snapshot.account).deviceLink)
        val digitsEnd = hostEndedLines(atDigits, h.api.retryAfterSeconds())
        WalkPrint.draws("b4 the showing phone: the digits refused, the link's end", digitsEnd)
        WalkPrint.draws("b4 said beside it", emptyList())
        assertEquals(listOf(UiText.of(CopyKey.DEVICE_LINK_HOST_TOO_MANY, OutcomeWords.waitLength(host.retryAfterSeconds()).shown()).shown()), digitsEnd.map { it.shown() })
        assertNull(h.saidOn(host.snapshot)?.takeIf { it.section == null }, "nothing under the top either")

        // b5. The approval refused, as the card's button runs it.
        h.act { devices.dismissDeviceLink() }
        h.onSnapshot(host.snapshot)
        host.script.advance(60_000L)
        typeDigitsUpTo(host, h)
        assertEquals(DigitsResult.DONE, h.inLink({ devices.submitDeviceDigits(assertIs(snapshot.account?.deviceLink), host.script.joiningDeviceCode) }, { deviceDigitsWords(it, h.api.retryAfterSeconds()) }))
        val approvable = assertIs<DeviceLinkHost.Approvable>(assertNotNull(host.snapshot.account).deviceLink)
        host.script.linkTooMany = true
        assertEquals(ProofResult.RATE_LIMITED, h.inLink({ devices.approveWithPassword(approvable, FakeScenes.PASSWORD) }, { deviceLinkProofWords(it, h.api.retryAfterSeconds()) }))
        val atApproval = assertIs<DeviceLinkHost.Ended>(assertNotNull(host.snapshot.account).deviceLink)
        val approvalEnd = hostEndedLines(atApproval, h.api.retryAfterSeconds())
        WalkPrint.draws("b5 the showing phone: the approval refused, the link's end", approvalEnd)
        WalkPrint.draws("b5 said beside it", emptyList())
        assertEquals(listOf(UiText.of(CopyKey.DEVICE_LINK_HOST_TOO_MANY, OutcomeWords.waitLength(host.retryAfterSeconds()).shown()).shown()), approvalEnd.map { it.shown() })
        assertNull(h.saidOn(host.snapshot)?.takeIf { it.section == null })
        // After the wait ran out, the card's line as it stands then.
        host.script.advance((host.retryAfterSeconds() + 1) * 1000L)
        WalkPrint.draws("b5 the showing phone's card after the wait ran out", hostEndedLines(atApproval, h.api.retryAfterSeconds()))
    }

    @Test
    fun theClaimRefusedAsTooManySaysTheWaitAndNothingIsClaimed() {
        val (fake, m) = phone(FakeScene.LINK_DEVICE_ENTRY)
        val home = fake.script.addServer("https://h.example", "Home", ServerKind.PRIVATE_SERVER)
        val other = home.addAccount(FakeScenes.EMAIL, FakeScenes.PASSWORD)
        assertEquals(DeviceLinkScanResult.DONE, runBlocking { fake.entry.submitDeviceLink(assertIs(fake.snapshot.entry), fake.script.deviceLinkFrom(other, "MacBook"), PayloadSource.SCANNED) })
        m.onSnapshot(fake.snapshot)
        fake.script.linkTooMany = true
        val said = fake.say(m) { entry.confirmTrustGate(assertIs(snapshot.entry)) }
        assertEquals(ServerResult.RATE_LIMITED, said.result)
        assertEquals(30, fake.retryAfterSeconds())
        assertEquals(assertNotNull(UiText.forResult(ServerResult.RATE_LIMITED, 30)).shown(), said.text.shown(), "the trouble line with the wait")
        assertEquals(Placeholder.TROUBLE_RATE_LIMITED, assertIs<UiText.Ph>(said.text).placeholder)
        assertNotEquals(unreachable, said.text.shown(), "never \"unreachable\"")
        assertIs<EntryScreen.LinkDeviceEntry>(fake.snapshot.entry, "nothing claimed: back where a link is handed in")
    }

    @Test
    fun thePickupRefusedAsTooManyEndsTheLinkWithItsOwnLineAndTheWait() {
        val (fake, m) = phone(FakeScene.LINK_DEVICE_PASSWORD)
        fake.script.linkTooMany = true
        var result: io.silencelen.andvari.core.app.IntentResult? = null
        runBlocking { m.run({ entry.submitLinkPassword(assertIs(snapshot.entry), FakeScenes.PASSWORD) }) { result = it }.join() }
        m.onSnapshot(fake.snapshot)
        assertEquals(LinkPasswordResult.RATE_LIMITED, result)
        val ended = assertIs<EntryScreen.LinkDeviceEnded>(fake.snapshot.entry)
        // The ended screen says it in its own line; nothing else is said above it (no "unreachable").
        assertNull(m.saidOn(fake.snapshot)?.takeIf { it.text.shown() == unreachable })
        assertEquals(LinkDeviceEnd.TOO_MANY, ended.outcome)
        // As the ended screen draws it: OutcomeWords.linkDeviceEnd(screen.outcome, model.api.retryAfterSeconds()).
        assertEquals(
            UiText.of(CopyKey.DEVICE_LINK_TOO_MANY, OutcomeWords.waitLength(30).shown()).shown(),
            OutcomeWords.linkDeviceEnd(ended.outcome, m.api.retryAfterSeconds()).shown(),
        )
    }

    @Test
    fun theShowingPhoneSaysTheWaitAtTheStartAndItsOwnLineWhenTheApprovalOrTheDigitsEndTheLink() {
        // The approval.
        val (fake, m) = phone(FakeScene.HOST_LINK_APPROVABLE)
        fake.script.linkTooMany = true
        val approved = runBlocking { fake.devices.approveWithPassword(assertIs(assertNotNull(fake.snapshot.account).deviceLink), FakeScenes.PASSWORD) }
        assertEquals(ProofResult.RATE_LIMITED, approved)
        m.onSnapshot(fake.snapshot)
        val ended = assertIs<DeviceLinkHost.Ended>(assertNotNull(fake.snapshot.account).deviceLink)
        assertEquals(CopyKey.DEVICE_LINK_HOST_TOO_MANY, ended.line)
        assertEquals(
            listOf(UiText.of(CopyKey.DEVICE_LINK_HOST_TOO_MANY, OutcomeWords.waitLength(30).shown()).shown()),
            hostEndedLines(ended, m.api.retryAfterSeconds()).map { it.shown() },
            "its own line with the wait, never \"a check failed\"",
        )

        // The link's start: refused as one of too many, no link is shown, and the wait is said.
        fake.script.linkTooMany = true
        val said = fake.say(m) { devices.startDeviceLink() }
        assertEquals(PlainResult.RATE_LIMITED, said.result)
        assertNull(assertNotNull(fake.snapshot.account).deviceLink, "no link made or shown")
        assertEquals(Placeholder.TROUBLE_RATE_LIMITED, assertIs<UiText.Ph>(said.text).placeholder)
        assertNotEquals(unreachable, said.text.shown())

        // The digits.
        val (fake2, m2) = phone(FakeScene.HOST_LINK_TYPE_DIGITS)
        fake2.script.linkTooMany = true
        val digits = runBlocking { fake2.devices.submitDeviceDigits(assertIs(assertNotNull(fake2.snapshot.account).deviceLink), fake2.script.joiningDeviceCode) }
        assertEquals(DigitsResult.RATE_LIMITED, digits)
        m2.onSnapshot(fake2.snapshot)
        val ended2 = assertIs<DeviceLinkHost.Ended>(assertNotNull(fake2.snapshot.account).deviceLink)
        assertEquals(
            listOf(UiText.of(CopyKey.DEVICE_LINK_HOST_TOO_MANY, OutcomeWords.waitLength(30).shown()).shown()),
            hostEndedLines(ended2, m2.api.retryAfterSeconds()).map { it.shown() },
        )
    }
}
