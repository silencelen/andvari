package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PlainResult
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
 * The kit's clock runs for as long as the app is visible, and the mark of the person's own end does not outlive its
 * moment. Q1, Q2 and Q3 are an independent check's probes of the earlier code: a kit visible without the focus kept the
 * screen on and was never locked (no tick ran while the activity was paused); after a sign-out the mark stayed for any
 * time and any later journey; and an end whose act threw left the mark, so that the server's later end was said as the
 * person's.
 */
class KitClockVisibleAndPersonMarkTest {
    private val newPassword = "a brand new master password"

    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun model(api: io.silencelen.andvari.core.app.AppApi, clock: () -> Long = { 0L }) =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock).also { it.onSnapshot(api.snapshot) }

    private fun signOut(m: TrustModel) {
        val ask = m.signOutAsk()
        ask.open()
        ask.confirm()
        if (ask.step == SignOutAsk.Step.SECOND) ask.confirm()
    }

    // ---- the kit's clock while the app is visible ----

    @Test
    fun q1_aKitVisibleWithoutTheFocusIsTickedSoItsWarningLimitAndTheEndOfTheHoldCome() {
        // The activity's ticker: started at ON_START and stopped at ON_STOP (repeatOnLifecycle(STARTED)), not only while
        // resumed; the excursion's arm is still dropped at the resumed entry, the one a dialog-style picker fires.
        val activity = main("MainActivity.kt").lines().joinToString("\n") { it.substringBefore("//") }
        val ticker = activity.substringBefore("model.tick()").substringAfterLast("lifecycleScope.launch")
        assertTrue("repeatOnLifecycle(Lifecycle.State.STARTED)" in ticker, "the tick follows started and stopped: $ticker")
        assertEquals(1, Regex("""model\.tick\(\)""").findAll(activity).count(), "one ticker")
        val resumed = activity.substringAfter("repeatOnLifecycle(Lifecycle.State.RESUMED)").substringBefore("lifecycleScope.launch")
        assertTrue("ExternalExcursion.clear()" in resumed && "model.tick()" !in resumed)

        // Probe Q1's state: a refusal kit after a recovery's commit, the activity started but not resumed (split screen
        // with the other app focused, another app's dialog on top): no touch, no stop, only the ticker's ticks.
        var now = 0L
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.REPLACE_PASSWORD)
        val api = EngineLike(fake)
        val m = model(api) { now }
        fake.script.anotherAccountTakenDuringCommit = true
        m.run({ entry.chooseReplacementPassword(assertIs(snapshot.entry), newPassword) })
        val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val limit = assertNotNull(kit.idleLockAfterMs)
        assertTrue(m.keepScreenOn.value)
        now = limit - (kit.idleWarnBeforeMs ?: 0L)
        m.tick()
        assertEquals(kit.idleWarningLine, m.kitIdleWarning.value?.key, "the warning comes")
        assertTrue(m.keepScreenOn.value)
        now = limit
        m.tick()
        assertEquals(1, api.locks, "locked at its limit, as with the focus")
        assertFalse(m.keepScreenOn.value, "the hold ends with it: the screen may sleep")
        assertNull(m.kitIdleWarning.value)
    }

    // ---- the mark of the person's own end ----

    @Test
    fun q2_theFirstThingThePersonAsksAfterTheLandingTakesTheMarkAway() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        signOut(m)
        assertIs<EntryScreen.FirstRun>(fake.snapshot.entry)
        assertEquals(Placeholder.PERSON_ENDED_OVERTOOK, m.overtookWords(fake.snapshot), "the moment of the landing")
        m.run({ PlainResult.DONE })
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, m.overtookWords(fake.snapshot), "gone at the first thing asked after it")

        // A plain act counts as asking too.
        val other = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val o = model(other)
        signOut(o)
        o.act { }
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, o.overtookWords(other.snapshot))
    }

    @Test
    fun workAskedBeforeTheEndStillSaysThePersonsEndAfterTheNextAsk() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        fake.script.holdNext()
        var answered: PasswordChangeResult? = null
        m.runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeWords(it, 0) }) { answered = it }
        assertTrue(fake.script.holding)
        signOut(m)
        assertIs<EntryScreen.FirstRun>(fake.snapshot.entry)
        m.act { }
        fake.script.releaseHold()
        m.onSnapshot(fake.snapshot)
        val said = assertNotNull(m.saidOn(fake.snapshot), "said on the first screen: $answered")
        assertEquals(Placeholder.PERSON_ENDED_OVERTOOK, assertIs<UiText.Ph>(said.text).placeholder, "it was the person's end that overtook it")
    }

    @Test
    fun q3_anEndWhoseActThrewIsNotMadeSoTheServersLaterEndIsSaidAsTheServers() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        // The end's act throws a contained fault: its answer never comes ([after] is not called on a throw).
        m.personEnds()
        m.run<PlainResult>({ throw IllegalStateException("a fault of the shared code") })
        assertNotNull(m.saidOn(fake.snapshot), "the fault is said")
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase)
        // Then the server ends the session, and the person taps "Sign in again": the journey.
        fake.script.sessionEndedByServer()
        fake.signInAgain(assertNotNull(fake.snapshot.locked))
        m.onSnapshot(fake.snapshot)
        assertEquals(AppPhase.ENTRY, fake.snapshot.phase)
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, m.overtookWords(fake.snapshot), "the server's end, not the person's")

        // An end asked on the journey itself ("Forget this server" on the first screen) counts as landed at once; its throw
        // takes the mark away all the same.
        val first = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN)
        val f = model(first)
        f.personEnds()
        f.onSnapshot(first.snapshot)
        f.run<PlainResult>({ throw IllegalStateException("a fault of the shared code") })
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, f.overtookWords(first.snapshot))
    }
}
