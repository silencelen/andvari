package io.silencelen.andvari.app.trust

import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.platform.TextToolbar
import androidx.compose.ui.platform.TextToolbarStatus
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PasswordChangeResult
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
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * What the kit screens could still let out, and the lines around them, as an independent check found them: the typed
 * groups' Copy and Cut, the print adapter's copy surviving a lock, "the server ended this phone's session" after the
 * person's own end, and a notice that names a way out the screen did not offer.
 */
class KitScreensLeakAndWayOutTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    private fun model(api: io.silencelen.andvari.core.app.AppApi, clock: () -> Long = { 0L }) =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock).also { it.onSnapshot(api.snapshot) }

    // ---- item 4: no Copy, no Cut; a lock reaches the print adapter ----

    private class Shown(val copy: Boolean, val paste: Boolean, val cut: Boolean, val selectAll: Boolean)

    private class RecordingToolbar : TextToolbar {
        val shown = ArrayList<Shown>()
        override val status: TextToolbarStatus get() = TextToolbarStatus.Hidden
        override fun hide() = Unit
        override fun showMenu(rect: Rect, onCopyRequested: (() -> Unit)?, onPasteRequested: (() -> Unit)?, onCutRequested: (() -> Unit)?, onSelectAllRequested: (() -> Unit)?) {
            shown += Shown(onCopyRequested != null, onPasteRequested != null, onCutRequested != null, onSelectAllRequested != null)
        }
    }

    @Test
    fun whatIsTypedBackCannotBeCopiedOutByTheMenuOrTheKeyboard() {
        val system = RecordingToolbar()
        PasteOnlyToolbar(system).showMenu(Rect.Zero, {}, {}, {}, {})
        val menu = system.shown.single()
        assertFalse(menu.copy, "no Copy")
        assertFalse(menu.cut, "no Cut")
        assertTrue(menu.paste && menu.selectAll, "the rest of the system's menu stays")

        for (key in listOf(Key.C, Key.X, Key.Insert)) assertTrue(copiesOut(key, ctrl = true, shift = false), "$key with Ctrl")
        assertTrue(copiesOut(Key.Delete, ctrl = false, shift = true), "Shift+Delete cuts")
        assertTrue(copiesOut(Key.Copy, ctrl = false, shift = false) && copiesOut(Key.Cut, ctrl = false, shift = false))
        assertFalse(copiesOut(Key.V, ctrl = true, shift = false), "paste stays")
        assertFalse(copiesOut(Key.C, ctrl = false, shift = false), "typing a c stays")

        val confirm = main("trust/KitScreens.kt").substringAfter("private fun KitConfirm(").substringBefore("\n}\n")
        val wrapped = confirm.substringAfter("NoCopyOut {")
        assertTrue("Field(UiText.ph(Placeholder.KIT_GROUP_FIELD" in wrapped, "every field the kit is typed into is inside it")
        assertFalse("Field(" in confirm.substringBefore("NoCopyOut {"))
        val wrap = main("trust/KitScreens.kt").substringAfter("internal fun NoCopyOut(").substringBefore("\n}\n")
        assertTrue("LocalTextToolbar provides toolbar" in wrap && "onPreviewKeyEvent" in wrap)
    }

    @Test
    fun aLockDropsWhatTheAppStillHoldsOfAKitForPrinting() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        fake.script.publicInstance.accounts.values.first().kitSaved = false
        val m = model(fake)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertIs<EntryScreen.Kit>(fake.snapshot.entry)
        var dropped = 0
        val printing = KitHolds.Held { dropped++ }
        KitHolds.hold(printing)
        m.tick()
        assertEquals(0, dropped, "held while the kit is on show")
        m.act { lock() }
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
        assertEquals(1, dropped, "the lock took the kit, and the print adapter's copy with it")
        assertEquals(0, KitHolds.count)

        // The adapter is a holder from the moment it is made until the print framework is done with it.
        val kits = main("trust/KitScreens.kt")
        val adapter = kits.substringAfter("private class KitPrintAdapter(")
        assertTrue("KitHolds.Held" in adapter.substringBefore("{") && "KitHolds.hold(this)" in adapter)
        val drop = adapter.substringAfter("override fun drop() {").substringBefore("}")
        assertTrue("doc = null" in drop && "pdf?.close()" in drop && "pdf = null" in drop)
        assertTrue("KitHolds.release(this)" in adapter.substringAfter("override fun onFinish() {").substringBefore("}"))
        assertTrue("if (d == null || p == null) return cb.onWriteFailed(null)" in adapter, "a write after the drop draws nothing")
    }

    // ---- item 5: the person's own end is not the server's ----

    @Test
    fun p2_workOvertakenByThePersonsOwnSignOutIsNotSaidAsTheServersEnd() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase)
        fake.script.holdNext()
        var answered: PasswordChangeResult? = null
        m.runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeWords(it, 0) }) { answered = it }
        assertTrue(fake.script.holding, "the change is under way")
        val ask = m.signOutAsk()
        ask.open()
        ask.confirm()
        if (ask.step == SignOutAsk.Step.SECOND) ask.confirm()
        assertIs<EntryScreen.FirstRun>(fake.snapshot.entry, "the person's own sign-out")
        fake.script.releaseHold()
        m.onSnapshot(fake.snapshot)
        val said = assertNotNull(m.saidOn(fake.snapshot), "said on the first screen: ${answered}")
        val ph = assertIs<UiText.Ph>(said.text)
        assertEquals(Placeholder.PERSON_ENDED_OVERTOOK, ph.placeholder, "not done, by the person's own end")

        // The server's own end is still said as that.
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, model(FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN)).overtookWords(fake.snapshot))
        // Every end the person asks for marks it; nothing else does.
        val ends = listOf(
            main("trust/SignOutConfirm.kt").substringAfter("private fun go(").substringBefore("\n    }\n"),
            main("trust/SettingsScreens.kt").substringAfter("model.personEnds()").substringBefore("model.deletionAnswered(it)"),
            main("trust/EntryScreens.kt").substringAfter("internal fun ForgetServerButton(").substringBefore("\n}\n"),
        )
        assertTrue("model.personEnds()" in ends[0] && "model.personEndAnswered(r.done)" in ends[0], "sign-out, the kept account's, and the switch")
        assertTrue("settings.deleteAccount(" in ends[1], "the deletion")
        assertTrue("model.personEnds()" in ends[2] && "model::personEnded" in ends[2], "Forget this server")
        assertTrue("personEndAnswered(result.done)" in main("trust/TrustModel.kt").substringAfter("fun personEnded(").substringBefore("\n    }\n"), "its answer through personEnded")
    }

    @Test
    fun afterTheLandingASessionOnShowAgainEndsThePersonsMark() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val m = model(fake)
        val ask = m.signOutAsk()
        ask.open()
        ask.confirm()
        if (ask.step == SignOutAsk.Step.SECOND) ask.confirm()
        assertEquals(Placeholder.PERSON_ENDED_OVERTOOK, m.overtookWords(fake.snapshot))
        // A sign-out that did not happen leaves nothing.
        val other = model(FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS))
        other.personEnds()
        other.personEndAnswered(false)
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, other.overtookWords(FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN).snapshot))
    }

    // ---- item 6: the way out a wiped kit's notice names, on the first screen ----

    @Test
    fun underANoticeThatNamesAKeptAccountTheFirstScreenOffersItsSignOutWithNoSignInFirst() {
        // The fake's own notice, made by its lock while the account it signed out is still kept here.
        val fake = FakeKitNotices.keptSignedOut()
        val notice = FakeKitNotices.afterRecoveryWhileKept(fake)
        assertNotNull(fake.snapshot.keptSignedOut)
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT, notice.whyHere)
        assertEquals(io.silencelen.andvari.core.app.KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, notice.wayOut, "the notice carries its way out")
        val api = EngineLike(fake)
        val m = model(api)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertSame(notice, api.snapshot.kitWiped)
        assertNull(m.saidOn(api.snapshot), "nothing was tried here")
        assertEquals(WayOut.KEPT_SIGN_OUT, kitWipedWayOut(notice, null, api.snapshot), "the way out is the notice's own")
        assertTrue(namedKeptStands(notice, api.snapshot), "offered while the kept session it named is kept")
        // The offer is the kept account's sign-out, with its count and both confirmations.
        val ask = m.signOutAsk()
        ask.open()
        assertEquals(CopyKey.SIGN_OUT_UNSENT_UNKNOWN, assertNotNull(ask.check?.line).key, "its count first")
        ask.confirm()
        assertEquals(SignOutAsk.Step.SECOND, ask.step, "the second confirmation")
        ask.confirm()
        assertNull(api.snapshot.keptSignedOut, "signed out, without a sign-in tried first")
        assertSame(notice, api.snapshot.kitWiped, "the notice stays until its Close")
        // The kept session it named is gone: its way out is no longer offered under it.
        assertNull(kitWipedWayOut(notice, null, api.snapshot), "the named kept session is gone")

        // Offered once only where a said result already offers the same (each notice's own way out: KitSharedCodeLinesTest).
        val other = FakeKitNotices.keptSignedOut()
        val again = FakeKitNotices.afterRecoveryWhileKept(other)
        assertEquals(WayOut.KEPT_SIGN_OUT, kitWipedWayOut(again, null, other.snapshot))
        assertNull(kitWipedWayOut(again, io.silencelen.andvari.core.app.CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, other.snapshot), "not twice")

        // Drawn on the first screen, not in the notice: the notice's only button is its Close.
        val first = main("trust/EntryScreens.kt").substringAfter("internal fun FirstRunScreen(").substringBefore("\n}\n")
        assertTrue("s.kitWiped?.let { KitWipedWayOut(model, s, it) }" in first)
        val view = main("trust/TrustApp.kt").substringAfter("internal fun KitWipedNoticeView(").substringBefore("\n}\n")
        assertEquals(1, Regex("Quieter\\(|Second\\(|Main\\(|Button\\(").findAll(view).count(), "one button")
        assertTrue("model.dismissKitWiped(notice)" in view)
        val wayOut = main("trust/KeptAccountScreens.kt").substringAfter("internal fun KitWipedWayOut(").substringBefore("\n}\n")
        assertTrue("KeptAccountSignOut(model, s, it)" in wayOut && "KeptAccountSignOut(model, s, it, removal = true)" in wayOut)
    }
}
