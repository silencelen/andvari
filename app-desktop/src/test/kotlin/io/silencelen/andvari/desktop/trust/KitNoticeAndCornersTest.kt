package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.material3.Surface
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.platform.WindowInfo
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.KeptWayOut
import io.silencelen.andvari.core.app.KitWipedNotice
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.session.WireTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The check of 2026-11-18, besides the print and the clipboard: the notice that a kit was wiped proved drawn above every
 * phase by a test that runs; the idle warning's line taking the focus where the window has it; three wording corners; under a notice
 * that names what stands in the way here, that way out; and "the server ended this session" only where the server did.
 */
class KitNoticeAndCornersTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")
    private fun saidPh(m: TrustModel): Placeholder = assertIs<UiText.Ph>(assertNotNull(m.said.value).text).placeholder

    private fun model(api: DesktopAppApi): TrustModel = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }

    // ---- the notice above every phase, drawn ----

    /** A start over this computer's own stores, as [TrustSeam] builds the engine, with a transport that reaches no server. */
    private fun startedReal(): Pair<TrustModel, EngineDesktopAppApi> {
        val home = DesktopHome(Files.createTempDirectory("andvari-notice").toFile().also { it.deleteOnExit() }, NoKeyStore, log = {}, keyStorePause = {})
        // The app was closed with a kit shown with a refusal on show, after a recovery: the shared code's mark at rest.
        JsonDeviceState(home.stateFile()).set("ovh.kit.notkept.onshow", "recovery|ada@example.com")
        val api = EngineDesktopAppApi(
            AppEngine(
                platform = TrustSeam.desktopPlatform(), deviceName = "test",
                transport = WireTransport { origin, _ -> error("no server in this test: $origin") },
                state = JsonDeviceState(home.stateFile()), secure = JsonDeviceState(home.secureFile), requestStore = JsonDeviceState(home.requestFile),
                crypto = createCryptoProvider(), clock = { System.currentTimeMillis() }, baked = null, storeBuild = false, stores = null,
                main = Dispatchers.Unconfined, work = Dispatchers.Unconfined, cacheFiles = home.cacheFiles, contentStores = home.content.stores,
                keepsAtRest = home::keepsAtRest,
            ),
        )
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.start()
        m.onSnapshot(api.snapshot)
        return m to api
    }

    /** What [TrustApp] drew of the notice, with the phase it stood above. */
    private fun drawnNotices(m: TrustModel): List<Pair<KitWipedNotice, AppPhase>> {
        val seen = ArrayList<Pair<KitWipedNotice, AppPhase>>()
        val scene = ImageComposeScene(480, 1000, Density(1f)) {
            CompositionLocalProvider(LocalNoticeDrawn provides { n, p -> seen += n to p }) { MaterialTheme { TrustApp(m, null, "log") } }
        }
        try {
            scene.render()
        } finally {
            scene.close()
        }
        return seen
    }

    /**
     * [s] with [notice] on it. The real engine cannot reach the lock screen or an open vault without a server, and the fake
     * never sets the notice, so the fake's lock screen and open vault are given the real engine's notice here, through
     * the snapshot's own constructor: the one whose parameters are the snapshot's own fields, in their order, each taken
     * from [s] except the notice. A field the shared code adds to the snapshot is carried along as it is; a constructor
     * that no longer matches the fields, or a snapshot with no field or more than one for the notice, fails this test
     * loudly, never silently.
     */
    private fun withNotice(s: AppSnapshot, notice: KitWipedNotice): AppSnapshot {
        val fields = AppSnapshot::class.java.declaredFields.filter { !java.lang.reflect.Modifier.isStatic(it.modifiers) && !it.isSynthetic }
        check(fields.count { it.type == KitWipedNotice::class.java } == 1) { "the snapshot holds one notice that a kit was wiped" }
        val c = AppSnapshot::class.java.declaredConstructors.single { k -> k.parameterTypes.toList() == fields.map { it.type } }
        c.isAccessible = true
        val args = fields.map { f -> if (f.type == KitWipedNotice::class.java) notice else f.also { it.isAccessible = true }.get(s) }
        return c.newInstance(*args.toTypedArray()) as AppSnapshot
    }

    private class Shown(fake: FakeDesktopAppApi, shown: AppSnapshot) : DesktopAppApi by fake {
        private val flow = MutableStateFlow(shown)
        override val snapshot: AppSnapshot get() = flow.value
        override val snapshots: StateFlow<AppSnapshot> get() = flow
    }

    @Test
    fun theNoticeIsDrawnAboveTheFirstScreenTheLockScreenAndAnOpenVault() {
        val (real, api) = startedReal()
        val notice = assertNotNull(api.snapshot.kitWiped, "the real engine says it at the start")
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertEquals(listOf(notice to AppPhase.ENTRY), drawnNotices(real).distinct(), "above the first screen")
        for ((scene, phase) in listOf(FakeScene.LOCKED to AppPhase.LOCKED, FakeScene.VAULTS to AppPhase.UNLOCKED)) {
            val fake = FakeScenes.desktopAt(scene)
            assertEquals(phase, fake.snapshot.phase)
            val m = model(Shown(fake, withNotice(fake.snapshot, notice)))
            assertEquals(listOf(notice to phase), drawnNotices(m).distinct(), "above $phase")
        }
        // Without the notice, nothing of it is drawn.
        assertTrue(drawnNotices(model(FakeScenes.desktopAt(FakeScene.VAULTS))).isEmpty())
        // The dismiss is still the only way it goes (the real engine's).
        real.quietly { real.api.dismissKitWiped(notice) }
        assertNull(api.snapshot.kitWiped)
        assertTrue(drawnNotices(real).isEmpty())
    }

    // ---- the idle warning: the line takes the focus where the window has it ----

    private class WindowFocus(override val isWindowFocused: Boolean) : WindowInfo

    /**
     * The words of each marked control the focus reached while [frames] were drawn, the warning line on show in a frame
     * where its entry is true; the window has the focus or not ([windowFocused]).
     */
    private fun focusWhile(windowFocused: Boolean, line: UiText, frames: List<Boolean>): List<String> {
        val log = ArrayList<String>()
        val shown = androidx.compose.runtime.mutableStateOf(false)
        val scene = ImageComposeScene(480, 400, Density(1f)) {
            CompositionLocalProvider(LocalFocusLog provides log, LocalWindowInfo provides WindowFocus(windowFocused)) {
                MaterialTheme { Surface { if (shown.value) KitIdleWarningLine(line) } }
            }
        }
        try {
            var t = 0L
            for (on in frames) {
                shown.value = on
                repeat(2) {
                    t += 50_000_000L
                    scene.render(t)
                }
            }
        } finally {
            scene.close()
        }
        return log
    }

    /**
     * Compose for desktop announces no line that appears (no live region reaches the platform), so the warning line takes
     * the keyboard's focus when it comes, which the toolkit reports to assistive technology; only where the window has the
     * focus; once each time the line comes, not at every frame while it stays. (That a screen reader then speaks it is
     * for a Windows computer to show; the operating system's own signals are [TrustModel.kitWarningSignal]'s, walked in
     * [KeeperAnswersTest].)
     */
    @Test
    fun theKitsIdleWarningLineTakesTheFocusOnceEachTimeItComesWhereTheWindowHasIt() {
        val line = UiText.of(CopyKey.KIT_IDLE_WARNING)
        val words = line.shown()
        assertEquals(listOf(words), focusWhile(true, line, listOf(true, true, true)), "once, while it stays")
        assertEquals(listOf(words, words), focusWhile(true, line, listOf(true, true, false, true, true)), "again when it comes again")
        assertTrue(focusWhile(false, line, listOf(true, true)).isEmpty(), "never taken from another window")
        // No mark is set in the place of the focus any more: the line carries no live region.
        val drawn = body("TrustUi.kt", "internal fun KitIdleWarningLine(")
        assertFalse(drawn.contains("liveRegion"))
    }

    // ---- three corners ----

    /** A move whose number an earlier stored card held signed nothing now: never "signed and stored". */
    @Test
    fun aMoveThatFoundAnEarlierStoredCardDoesNotSayItSignedOne() {
        val held = assertNotNull(operatorWords(OperatorResult.CARD_STORED_NOT_SHOWN, 0, OperatorModel.Action.MOVE, cardHeldBefore = true))
        assertNotEquals(Placeholder.OP_MOVE_CARD_STORED, (held as? UiText.Ph)?.placeholder)
        assertEquals(assertNotNull(UiText.forResult(OperatorResult.CARD_STORED_NOT_SHOWN, 0)).shown(), held.shown(), "the shared code's own sentence")
        assertEquals(Placeholder.OP_MOVE_CARD_STORED, assertIs<UiText.Ph>(operatorWords(OperatorResult.CARD_STORED_NOT_SHOWN, 0, OperatorModel.Action.MOVE)).placeholder)
        val act = body("OperatorModel.kt", "    internal fun act(").substringBefore("\n    }\n")
        assertTrue(act.indexOf("val cardHeldBefore = api.operatorApi.console?.cardStoredNotShown == true") in 0 until act.indexOf("model.runSaying("), "read before the intent runs")
        assertTrue(act.contains("operatorWords(r, api.retryAfterSeconds(), action, cardHeldBefore)"))
    }

    /** The file the "left beside it as" line names is still there after the app ends, whichever name it kept. */
    @Test
    fun aCheckedCopyKeptAsideIsNotRemovedAtTheAppsEnd() {
        val root = Files.createTempDirectory("andvari-kept").toFile().also { it.deleteOnExit() }
        // The place picked is a folder that holds a file: the checked copy cannot take its place.
        val dest = File(root, "export.csv").also { it.mkdir(); File(it, "inside").writeText("x") }
        val renamed = writeVerified(dest, "a,b\n".toByteArray())
        assertEquals(ExportWrite.NOT_WRITTEN, renamed.result)
        val survivor = File(root, assertNotNull(renamed.keptAs))
        assertTrue(survivor.isFile && survivor.name.startsWith("export.csv.recovered-"))
        assertFalse(TempsDeletedAtExit.has(survivor))
        // Even the rename to that name fails: the copy is kept under its temporary name, and that file stays too.
        val stuck = writeVerified(dest, "a,b\n".toByteArray()) { File(File(root, "no-such-folder"), "x") }
        val kept = File(root, assertNotNull(stuck.keptAs))
        assertTrue(kept.isFile && kept.name.startsWith("andvari-") && kept.name.endsWith(".tmp"))
        assertFalse(TempsDeletedAtExit.has(kept), "taken off the exit's list before it was named")
        // A write that worked leaves nothing on the list either.
        val good = File(root, "good.csv")
        assertEquals(ExportWrite.SAVED, writeVerified(good, "c\n".toByteArray()).result)
        assertEquals(listOf("export.csv", good.name, kept.name, survivor.name).sorted(), root.list()!!.sorted())
    }

    /** In a session the server ended earlier, a lock of andvari's own is said as the lock, never "andvari did not lock". */
    @Test
    fun aLockOfAndvarisOwnInASessionTheServerEndedIsTheLock() {
        // The fake's server end goes straight to the lock screen (the engine keeps the read-only copy open), so the lock
        // screen of a session the server ended, after a lock of andvari's own, is walked here in the other order: the
        // person locks (Ctrl+L, the menu, the idle limit: the one lockHere), and the session is the server's ended one.
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        api.script.sessionEndedByServer()
        m.onSnapshot(api.snapshot)
        assertTrue(assertNotNull(api.snapshot.locked).signedOutByServer)
        m.lockOvertook()
        assertEquals(Placeholder.LOCK_OVERTOOK, saidPh(m))
        assertTrue(body("TrustModel.kt", "    private fun contentClosed(").contains("s.locked?.signedOutByServer == true && !lockedHere"))
        // The next opening of the vault forgets it: a later server end is the server's again.
        val again = FakeScenes.desktopAt(FakeScene.VAULTS)
        val e = model(again)
        again.script.sessionEndedByServer()
        e.onSnapshot(again.snapshot)
        e.lockOvertook()
        assertEquals(Placeholder.SERVER_ENDED_BEFORE_DONE, saidPh(e))
    }

    // ---- the server's end only where the server did ----

    /** The person's own sign-out ended the session: work still under way is said as not done, never as the server's end. */
    @Test
    fun afterTheirOwnSignOutWorkStillUnderWayIsSaidAsNotDone() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        val before = api.snapshot
        m.run({ signOut() })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertEquals(Placeholder.STOPPED_BEFORE_DONE, assertIs<UiText.Ph>(m.overtookWords(before, api.snapshot)).placeholder)
        m.lockOvertook()
        assertEquals(Placeholder.STOPPED_BEFORE_DONE, saidPh(m))
    }

    // ---- the way out under a notice that names what stands in the way here ----

    @Test
    fun underANoticeThatNamesTheKeptAccountTheWindowOffersItsSignOut() {
        val (api, _) = keptAda()
        val kept = assertNotNull(api.snapshot.keptSignedOut)
        val mark = kept.keptMark
        assertTrue(mark.isNotEmpty(), "the shared code marks the kept session")
        val lines = listOf(keptAccountLine(kept))
        // The shared code's act for the notice ([KitWipedNotice.wayOut]) is what is offered, for the very session the notice
        // named: its mark equal to the kept account's.
        val way = assertIs<WayOut.SignOutKept>(kitWipedWayOut(KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, kept, mark, lines))
        assertSame(kept, way.kept)
        assertEquals(lines.map { it.shown() }, way.lines.map { it.shown() }, "the kept account named; the notice says why")
        // With the mark, the removal of this computer's damaged copy comes back under the notice (its two questions follow).
        assertSame(kept, assertIs<WayOut.RemoveDamagedCopy>(kitWipedWayOut(KeptWayOut.REMOVE_THIS_COPY, kept, mark, emptyList())).kept)
        // Another mark (a session taken since), an empty one, or none: nothing, for either act.
        for (other in listOf(mark + "-later", "", null)) {
            assertNull(kitWipedWayOut(KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, kept, other, lines), "$other")
            assertNull(kitWipedWayOut(KeptWayOut.REMOVE_THIS_COPY, kept, other, emptyList()), "$other")
        }
        // The held operator account: the first screen under the notice offers its removal itself.
        assertNull(kitWipedWayOut(KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT, kept, mark, lines))
        // No act (an identity fault); none where no account is kept.
        assertNull(kitWipedWayOut(KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, null, mark, lines))
        assertNull(kitWipedWayOut(null, kept, mark, lines))
        // The address no longer decides: the comparison by address is gone from the window's code.
        assertFalse(File(dir + "KeptAccountRefusal.kt").readText().contains("sameAddress"))
        // The real engine's notice names a kept account that this computer does not keep: nothing is offered.
        val (_, real) = startedReal()
        assertNull(kitWipedWayOut(real.snapshot))
        // Drawn in the window right under the notice, apart from it (the notice keeps only its dismiss).
        val column = body("TrustApp.kt", "fun TrustApp(").substringAfter("Column(Modifier.fillMaxSize()) {")
        assertTrue(column.indexOf("KitWipedWayOut(model, s)") == column.indexOf("KitWipedBar(model, s)") + "KitWipedBar(model, s)\n            ".length)
        val bar = body("TrustApp.kt", "private fun KitWipedBar(")
        assertFalse(bar.contains("KeptAccountRefusal") || bar.contains("SignOut"))
        assertTrue(body("TrustApp.kt", "private fun KitWipedWayOut(").contains("KeptAccountRefusal(model, s, way)"))
    }

    /**
     * The shared code's notice that a kit for [email] was wiped while [whyHere] stood here, with [wayOut] as its act: the
     * real engine's notice at a start ([startedReal]) with those fields and its line replaced, every other field carried
     * from it (no walk of the fake reaches a notice for any address and any reason).
     */
    private fun noticeFor(email: String, whyHere: CopyKey, wayOut: KeptWayOut?, namedKept: String?): KitWipedNotice {
        val made = assertNotNull(startedReal().second.snapshot.kitWiped)
        return rebuilt(made, "email" to email, "line" to CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, "whyHere" to whyHere, "wayOut" to wayOut, "namedKept" to namedKept)
    }

    /**
     * The check's two sequences: the notice names the kept session that stood in the way when the kit was wiped, and the
     * session kept now was taken since (a recovery kit for Ada wiped while Bea was kept; Bea signed out, the notice left on
     * show, Ada signed in and her server ended the session; or a damaged copy of Ada's, and a copy of Ada's taken again).
     * The session taken since has another mark, so no way out is offered under such a notice, whatever the addresses;
     * where the notice names the very session kept now, the sign-out and the removal of the copy are.
     */
    @Test
    fun theWayOutUnderANoticeIsOfferedOnlyWhileWhatItNamedStillStands() {
        val (api, _) = keptAda()
        val before = api.snapshot
        val first = assertNotNull(before.keptSignedOut).keptMark
        assertTrue(first.isNotEmpty())
        // Ada's copy taken again since (the shared code gives every take a new mark, opaque to the window): the same
        // account, another mark.
        val s = rebuilt(before, "keptSignedOut" to rebuilt(assertNotNull(before.keptSignedOut), "keptMark" to "a later take"))
        assertEquals(AppPhase.ENTRY, s.phase)
        val kept = assertNotNull(s.keptSignedOut)
        val ada = assertNotNull(kept.email)
        assertNotEquals(first, kept.keptMark, "a new take, a new mark")
        val another = CopyKey.KIT_NOT_HERE_WHY_ANOTHER_KEPT
        // Named the session kept before: nothing, whatever the addresses say.
        for (email in listOf(ada, "bea@example.com")) {
            assertNull(kitWipedWayOut(withNotice(s, noticeFor(email, another, KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, first))), email)
        }
        assertNull(
            kitWipedWayOut(withNotice(s, noticeFor(ada, CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED, KeptWayOut.REMOVE_THIS_COPY, first))),
            "no removal of a copy taken since, which may be healthy",
        )
        assertNull(kitWipedWayOut(withNotice(s, noticeFor("bea@example.com", another, KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, null))), "a notice that names no session")
        // Named the session kept now: the way out stands, for the account kept, its lines the shared code's naming of it.
        val other = assertIs<WayOut.SignOutKept>(kitWipedWayOut(withNotice(s, noticeFor("bea@example.com", another, KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, kept.keptMark))))
        assertSame(kept, other.kept)
        assertEquals(keptAccountNamed(s).map { it.shown() }, other.lines.map { it.shown() })
        val removal = assertIs<WayOut.RemoveDamagedCopy>(kitWipedWayOut(withNotice(s, noticeFor(ada, CopyKey.KIT_NOT_HERE_WHY_COPY_DAMAGED, KeptWayOut.REMOVE_THIS_COPY, kept.keptMark))))
        assertSame(kept, removal.kept)
        // The act is the shared code's: the same notice with no act offers nothing.
        assertNull(kitWipedWayOut(withNotice(s, noticeFor("bea@example.com", another, null, kept.keptMark))))
    }

    private fun keptAda(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = model(api)
        api.script.sessionEndedByServer()
        m.signInAgain()
        m.onSnapshot(api.snapshot)
        assertNotNull(api.snapshot.keptSignedOut)
        return api to m
    }
}
