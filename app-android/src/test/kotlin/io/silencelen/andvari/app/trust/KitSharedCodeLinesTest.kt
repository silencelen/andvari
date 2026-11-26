package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.SignInAnswer
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
 * The kit screens draw what the shared code hands them: every kit's limit and warning (the Settings kit's too), the
 * line on a kit that replaces one shown here before, the way out of each stop, and the reason line under the notice
 * that a kit is gone. Over the shared code's fake, which plays the engine's rules.
 */
class KitSharedCodeLinesTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun at(scene: FakeScene, clock: () -> Long): Triple<FakeAppApi, EngineLike, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val api = EngineLike(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock)
        m.onSnapshot(api.snapshot)
        return Triple(fake, api, m)
    }

    // ---- every kit's limit and warning, the Settings kit's too ----

    @Test
    fun aKitMadeInSettingsWarnsAndLocksAtItsOwnLimit() {
        var now = 0L
        val (_, api, m) = at(FakeScene.KIT_IN_SETTINGS) { now }
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val kit = assertNotNull(api.snapshot.account?.kit, "a kit made in Settings, over the open vault")
        val limit = assertNotNull(kit.idleLockAfterMs, "the shared code's limit")
        val warnBefore = assertNotNull(kit.idleWarnBeforeMs)
        val line = assertNotNull(kit.idleWarningLine)
        assertEquals(limit, m.idleLockDueInMs(), "the clock runs from the kit's own limit")
        now = limit - warnBefore - 1
        m.tick()
        assertNull(m.kitIdleWarning.value)
        now += 1
        m.tick()
        assertEquals(line, m.kitIdleWarning.value?.key, "the kit's warning, at its time, over the open vault too")
        m.touched()
        assertNull(m.kitIdleWarning.value, "a touch ends it")
        val touchedAt = now
        now = touchedAt + limit - 1
        m.tick()
        assertEquals(0, api.locks)
        now = touchedAt + limit
        m.tick()
        assertEquals(1, api.locks, "at the kit's limit the app locks")
        assertNull(m.kitIdleWarning.value)
    }

    // ---- a kit that replaces one shown here before ----

    @Test
    fun aKitThatReplacesOneShownHereAndNeverConfirmedSaysSoFirstOnItsFirstStep() {
        val (fake, api, m) = at(FakeScene.LOCKED) { 0L }
        fake.script.publicInstance.accounts.values.first().kitSaved = false
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val first = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitReason.NEVER_SAVED, first.reason)
        assertNull(first.earlierKitVoidLine, "no kit was shown here before")
        assertNull(kitVoidLine(first))
        // A lock takes it before it was typed back; the next unlock shows a new kit, and the earlier one no longer works.
        m.act { lock() }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        val second = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.REVEAL, second.step)
        assertEquals(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID, second.earlierKitVoidLine)
        assertEquals(UiText.of(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID).shown(), assertNotNull(kitVoidLine(second)).shown())
        // Only on the kit's first step.
        m.act { this.kit.proceedToConfirm(second) }
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        assertEquals(KitStep.CONFIRM, confirm.step)
        assertNull(kitVoidLine(confirm))

        // Drawn before anything else of the kit (after the cover, which shows nothing of it), in the error tone.
        val view = main("trust/KitScreens.kt").substringAfter("internal fun KitScreenView(").substringBefore("\n}\n")
        val void = view.indexOf("kitVoidLine(kit)?.let {")
        assertTrue(void > view.indexOf("if (covered &&"), "after the cover")
        assertTrue(void < view.indexOf("kitRefusalLines(kit, refusal)") && void < view.indexOf("kitIdleWarning") && void < view.indexOf("when (kit.step)"), "before anything else")
        assertTrue("Say(it, color = MaterialTheme.colorScheme.error)" in view.substring(void).lineSequence().take(2).joinToString("\n"), "in the error tone")
    }

    // ---- the reason lines under the notice, each with its way out ----

    @Test
    fun theNoticeThatAKitIsGoneSaysEachReasonLineUnderItsLineWithItsOwnWayOut() {
        // (the keeper's reason, whether another account is kept here at the lock) -> (the reason line, the way out)
        val cases = listOf(
            Triple(null, true, CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT to WayOut.KEPT_SIGN_OUT),
            Triple("operator_account_held", true, CopyKey.KIT_NOT_HERE_WHY_OPERATOR_HELD to WayOut.HELD_OPERATOR_REMOVAL),
            Triple("self_identity_mismatch", false, CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT to null),
            Triple("server_keys_not_known_here", false, CopyKey.KIT_NOT_HERE_WHY_SERVER_KEYS to WayOut.COPY_REMOVAL),
            Triple("kept_copy_damaged", false, CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED to WayOut.COPY_REMOVAL),
            Triple("a_reason_this_device_cannot_name", false, CopyKey.KIT_NOT_HERE_WHY_NOT_OPENED to null),
        )
        for ((reason, kept, expected) in cases) {
            val notice = if (kept) FakeKitNotices.afterRecoveryWhileKept(refusal = reason) else FakeKitNotices.afterRecovery(refusal = reason)
            val (why, way) = expected
            assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, notice.line, "$reason")
            assertEquals(why, notice.whyHere, "$reason")
            assertEquals(
                listOf(UiText.of(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE).shown(), UiText.of(why).shown()),
                kitWipedLines(notice).map { it.shown() },
                "the notice's line, then its reason line: $reason",
            )
            // The notice's own way out; whether it is offered also depends on the kept session it named still being kept
            // (KitScreensLeakAndWayOutTest, KeptMarkAndSharedCodeRowsTest).
            assertEquals(way, wayOutOf(notice.wayOut), "the notice's own way out: $reason")
        }
        assertEquals(6, cases.map { it.third.first }.toSet().size, "the six reason lines")
    }

    // ---- one cause, one way out: the shared code's, everywhere ----

    @Test
    fun theWayOutOfEachStopIsTheSharedCodesAndTheAppKeepsNoTableOfItsOwn() {
        // This phone's own copy of the same account stands in the way: its removal, never "sign out of that account".
        assertEquals(WayOut.COPY_REMOVAL, wayOutFor(SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE))
        assertEquals(WayOut.COPY_REMOVAL, wayOutFor(LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE))
        assertEquals(WayOut.KEPT_SIGN_OUT, wayOutFor(LinkDeviceEnd.ANOTHER_SESSION_KEPT), "a link stopped by a kept account offers its sign-out")
        assertEquals(WayOut.KEPT_SIGN_OUT, wayOutFor(SignInAnswer.ANOTHER_ACCOUNT_KEPT))
        assertNull(wayOutFor(SignInAnswer.REFUSED_AFTER_CODE))
        for (kept in io.silencelen.andvari.core.app.KeptWayOut.entries) assertNotNull(wayOutOf(kept), "$kept")

        // The app's mapping is gone: every way out is read from the shared code (KeptStops, the notice, the request's screen).
        val src = main("trust/KeptAccountScreens.kt")
        assertEquals(3, Regex("-> WayOut\\.").findAll(src).count(), "only the one translation of the shared code's act: ${src.length}")
        assertTrue("KeptStops.wayOut(it)" in src.substringAfter("internal fun wayOutFor(r: IntentResult?)").lineSequence().first())
        assertTrue("KeptStops.linkWayOut(end)" in src.substringAfter("internal fun wayOutFor(end: LinkDeviceEnd)").lineSequence().first())
        assertTrue("wayOutOf(screen.wayOut)" in src.substringAfter("internal fun operatorHelpStop(").substringBefore("\n\n"))
        assertTrue("wayOutOf(notice.wayOut)" in src.substringAfter("internal fun kitWipedWayOut(").substringBefore("\n\n"))
        assertFalse("internal fun wayOutFor(line: CopyKey?)" in src, "no mapping of the notice's lines of the app's own")
    }
}
