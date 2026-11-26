package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.pointer.PointerButton
import androidx.compose.ui.input.pointer.PointerButtons
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitStep
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.session.Establishing
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.awt.image.BufferedImage
import java.awt.print.PageFormat
import java.awt.print.Pageable
import java.awt.print.Printable
import java.awt.print.PrinterJob
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The check of 2026-11-18: a lock takes a recovery kit off the screen and out of memory on EVERY road. Two roads it did
 * not reach: a system print dialog left open still printed the kit after the lock, and three groups the person typed back
 * could be copied out of the confirm fields and stayed on the clipboard after a lock that left the phase as it was.
 */
class KitLockReachesTest {
    private val pw = FakeScenes.PASSWORD

    private inline fun <reified T : EntryScreen> on(api: FakeDesktopAppApi): T = assertIs<T>(api.snapshot.entry)

    private fun model(api: FakeDesktopAppApi, clears: () -> Unit = {}): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }, clearClipboard = clears).also { it.onSnapshot(api.snapshot) }

    /** A printer job that prints nothing and counts its cancels. */
    private class CountedJob : PrinterJob() {
        var cancels = 0
        override fun setPrintable(painter: Printable?) {}
        override fun setPrintable(painter: Printable?, format: PageFormat?) {}
        override fun setPageable(document: Pageable?) {}
        override fun printDialog(): Boolean = true
        override fun pageDialog(page: PageFormat?): PageFormat? = page
        override fun defaultPage(page: PageFormat?): PageFormat? = page
        override fun validatePage(page: PageFormat?): PageFormat? = page
        override fun print() {}
        override fun setCopies(copies: Int) {}
        override fun getCopies(): Int = 1
        override fun getUserName(): String = ""
        override fun setJobName(jobName: String?) {}
        override fun getJobName(): String = ""
        override fun cancel() {
            cancels++
        }
        override fun isCancelled(): Boolean = cancels > 0
    }

    private fun page(p: Printable): Int {
        val g = BufferedImage(612, 792, BufferedImage.TYPE_INT_RGB).createGraphics()
        try {
            return p.print(g, PageFormat(), 0)
        } finally {
            g.dispose()
        }
    }

    /** Nothing reachable from [p] (its own fields, and theirs) is the kit's document or one of its groups. */
    private fun holdsNothingOf(p: Any, doc: KitDocument) {
        val seen = HashSet<Int>()
        fun walk(o: Any?, depth: Int) {
            if (o == null || depth > 3 || !seen.add(System.identityHashCode(o))) return
            assertFalse(o === doc, "the document is still held")
            assertFalse(o is String && o in doc.groups, "a group is still held")
            assertFalse(o === doc.groups || o === doc.qrPayload, "a part of the kit is still held")
            if (o is String || o is Number || o is Boolean || o.javaClass.isPrimitive) return
            if (o.javaClass.name.startsWith("java.")) return
            var c: Class<*>? = o.javaClass
            while (c != null && c != Any::class.java) {
                for (f in c.declaredFields) {
                    if (java.lang.reflect.Modifier.isStatic(f.modifiers)) continue
                    f.isAccessible = true
                    walk(f.get(o), depth + 1)
                }
                c = c.superclass
            }
        }
        walk(p, 0)
    }

    @Test
    fun aPrintAskedForItsPageAfterTheLockHasNoPageAndHoldsNothingOfTheKit() {
        val api = FakeScenes.desktopAt(FakeScene.KIT_REVEAL)
        val m = model(api)
        val kit = on<EntryScreen.Kit>(api).kit
        val doc = assertNotNull(api.kit.kitDocument(kit))
        // Print was pressed: the dialog is open, its job attached.
        val hold = m.holdForPrint(doc)
        val printable = KitPrintable(hold)
        val job = CountedJob()
        hold.attach(job)
        assertEquals(Printable.PAGE_EXISTS, page(printable), "before the lock the page is there")
        assertEquals(0, job.cancels)
        // The lock (Ctrl+L, the menu, the idle limit: all of them come through the one lockHere).
        assertTrue(m.lockable())
        m.lockNow()
        // "Print" pressed in the dialog afterwards: no page, the job cancelled, nothing of the kit held.
        assertFalse(hold.held)
        assertNull(hold.doc)
        assertEquals(Printable.NO_SUCH_PAGE, page(printable))
        assertTrue(job.cancels >= 1, "the job is cancelled")
        holdsNothingOf(printable, doc)
        // A dialog that attaches its job only after the lock (it opened late) is cancelled at once.
        val late = CountedJob()
        hold.attach(late)
        assertEquals(1, late.cancels)
    }

    @Test
    fun aPrintLetsGoOfTheKitOnceNoKitIsOnShowLockOrNot() {
        val api = FakeScenes.desktopAt(FakeScene.KIT_REVEAL)
        val m = model(api)
        val kit = on<EntryScreen.Kit>(api).kit
        val doc = assertNotNull(api.kit.kitDocument(kit))
        val hold = m.holdForPrint(doc)
        // The step to the confirm is the same kit on show: the print still has its page.
        m.act { this.kit.proceedToConfirm(kit) }
        m.onSnapshot(api.snapshot)
        assertEquals(KitStep.CONFIRM, on<EntryScreen.Kit>(api).kit.step)
        assertTrue(hold.held)
        // Typed back: the vault opens, no kit is on show, and the print has nothing of it.
        val confirm = on<EntryScreen.Kit>(api).kit
        m.run({ this.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(hold.doc)
        assertEquals(Printable.NO_SUCH_PAGE, page(KitPrintable(hold)))
    }

    /** The kit's print thread reaches the kit only through its hold, and checks it after the dialog. */
    @Test
    fun thePrintThreadHoldsTheKitOnlyThroughItsHold() {
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/KitScreens.kt").readText()
        val thread = src.substringAfter("internal fun printKit(").substringBefore("\n}\n")
        assertTrue(thread.startsWith("hold: KitPrintHold, failed: (String) -> Unit, stopped: () -> Unit)"), "no document is handed to the thread")
        assertTrue(thread.contains("printKitHere(hold, failed, stopped) { PrinterJob.getPrinterJob() }"))
        val print = src.substringAfter("internal fun printKitHere(").substringBefore("\n}\n")
        assertTrue(print.contains("job.setPrintable(KitPrintable(hold))"))
        assertTrue(print.contains("hold.attach(job)"))
        assertTrue(print.contains("if (pressed && hold.held) job.print()"))
        assertTrue(print.contains("finally {\n        hold.drop()"))
    }

    /** A job whose dialog and print run what the test gives them. */
    private class StepJob(private val dialog: () -> Boolean, private val printing: () -> Unit) : PrinterJob() {
        var prints = 0
        override fun setPrintable(painter: Printable?) {}
        override fun setPrintable(painter: Printable?, format: PageFormat?) {}
        override fun setPageable(document: Pageable?) {}
        override fun printDialog(): Boolean = dialog()
        override fun pageDialog(page: PageFormat?): PageFormat? = page
        override fun defaultPage(page: PageFormat?): PageFormat? = page
        override fun validatePage(page: PageFormat?): PageFormat? = page
        override fun print() {
            prints++
            printing()
        }
        override fun setCopies(copies: Int) {}
        override fun getCopies(): Int = 1
        override fun getUserName(): String = ""
        override fun setJobName(jobName: String?) {}
        override fun getJobName(): String = ""
        override fun cancel() {}
        override fun isCancelled(): Boolean = false
    }

    /** What one print said ("stopped", or "failed: <class>"), over a kit on show in a fresh model; [dialog] and [printing] act on that model. */
    private fun printSays(dialog: (TrustModel) -> Boolean, printing: (TrustModel) -> Unit = {}): Pair<List<String>, Int> {
        val api = FakeScenes.desktopAt(FakeScene.KIT_REVEAL)
        val m = model(api)
        val doc = assertNotNull(api.kit.kitDocument(on<EntryScreen.Kit>(api).kit))
        val said = ArrayList<String>()
        val job = StepJob({ dialog(m) }, { printing(m) })
        printKitHere(m.holdForPrint(doc), { said += "failed: $it" }, { said += "stopped" }) { job }
        return said to job.prints
    }

    /**
     * A print that a lock stopped is said when it returns, in one line ([Placeholder.KIT_PRINT_STOPPED_BY_LOCK], drawn by
     * the kit's Print button): Print pressed in the dialog after the lock, and a lock during the print (the job aborted).
     * A dialog the person cancelled says nothing, a print that went through says nothing, and a print whose kit's screen
     * ended without a lock says nothing.
     */
    @Test
    fun aPrintThatALockStoppedIsSaidWhenItReturns() {
        assertEquals(listOf("stopped") to 0, printSays({ it.lockNow(); true }), "Print pressed after the lock: no print, and it is said")
        assertEquals(listOf("stopped") to 1, printSays({ true }, { it.lockNow(); throw java.awt.print.PrinterAbortException() }), "the lock aborted the print")
        assertEquals(emptyList<String>() to 0, printSays({ it.lockNow(); false }), "the person cancelled the dialog")
        assertEquals(emptyList<String>() to 1, printSays({ true }), "printed")
        assertEquals(listOf("failed: PrinterAbortException") to 1, printSays({ true }, { throw java.awt.print.PrinterAbortException() }), "another abort is a failure")
        // The kit's screen ended without a lock (the hold dropped as no kit is on show): nothing said, as before.
        assertEquals(emptyList<String>() to 0, printSays({ it.dropKitPrints(); true }))
        // A lock of another road (the lock screen now on show, no kit) is the lock's too.
        assertEquals(listOf("stopped") to 0, printSays({ m -> m.api.lock(); m.onSnapshot(m.api.snapshot); true }))
        val button = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/KitScreens.kt").readText()
        assertTrue(button.contains("{ model.say(UiText.ph(Placeholder.KIT_PRINT_STOPPED_BY_LOCK)) }"))
    }

    private fun toNewPassword(api: FakeDesktopAppApi, m: TrustModel, who: FakeAccount): EntryScreen.ReplacePassword {
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openForgot(on(api)) }
        m.act { entry.openKitEntry(on(api)) }
        m.run({ entry.submitKit(on(api), api.script.kitOf(who), PayloadSource.PASTED) })
        m.run({ entry.confirmKitRecovery(on(api)) })
        return on(api)
    }

    /**
     * A kit shown with a refusal, no session established: the lock leaves the phase as it was (here ENTRY), so the
     * clear that follows a phase change never came. Every lock clears what the app put on the clipboard now.
     */
    @Test
    fun everyLockClearsTheClipboardAlsoWhereThePhaseStaysAsItWas() {
        var clears = 0
        val api = FakeScenes.desktopAt(FakeScene.FIRST_RUN)
        val m = model(api) { clears++ }
        val dee = api.script.publicInstance.addAccount("dee@example.com", pw)
        val replace = toNewPassword(api, m, dee)
        api.script.refusedAfterCommit = Establishing.KEPT_COPY_DAMAGED
        m.run({ entry.chooseReplacementPassword(replace, "a brand new master password") })
        assertTrue(showsNotKeptKit(api.snapshot))
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertEquals(0, clears)
        m.lockNow()
        assertEquals(AppPhase.ENTRY, api.snapshot.phase, "the phase did not change")
        assertEquals(1, clears, "the lock cleared the clipboard")
        // An ordinary journey kit too, and the idle lock.
        var n = 0
        val kitApi = FakeScenes.desktopAt(FakeScene.KIT_REVEAL)
        var now = 0L
        val timed = TrustModel(kitApi, CoroutineScope(Dispatchers.Unconfined), { now }, clearClipboard = { n++ }).also { it.onSnapshot(kitApi.snapshot) }
        // The kit's own limit, counted from the first tick it is on show.
        val limit = assertNotNull(kitIdleLimitOf(kitApi.snapshot)?.idleLockAfterMs)
        while (now < limit + 1_000L) {
            now += 1_000L
            timed.tick()
        }
        assertEquals(1, n, "the idle lock cleared it")
    }

    // ---- the fields a kit is typed back into ----

    @Test
    fun theKitsConfirmFieldsAreTheOnesThatTakeNoCopy() {
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/KitScreens.kt").readText()
        val confirm = src.substringAfter("private fun KitConfirm(").substringBefore("\n}\n")
        assertTrue(confirm.contains("KitGroupField(UiText.ph(Placeholder.KIT_GROUP_FIELD"))
        assertFalse(Regex("""\bField\(""").containsMatchIn(confirm.replace("KitGroupField(", "")), "no plain field on the confirm step")
    }

    @Test
    fun copyAndCutByTheKeyboardAreToldApart() {
        for ((key, ctrl, meta, shift) in listOf(
            Quad(Key.C, true, false, false), Quad(Key.X, true, false, false), Quad(Key.C, false, true, false), Quad(Key.X, false, true, false),
            Quad(Key.Insert, true, false, false), Quad(Key.Delete, false, false, true), Quad(Key.Copy, false, false, false), Quad(Key.Cut, false, false, false),
        )) assertTrue(isCopyOrCut(key, ctrl, meta, shift), "$key")
        for ((key, ctrl, meta, shift) in listOf(
            Quad(Key.V, true, false, false), Quad(Key.A, true, false, false), Quad(Key.C, false, false, false), Quad(Key.X, false, false, true),
            Quad(Key.Delete, false, false, false), Quad(Key.Insert, false, false, true), Quad(Key.Backspace, true, false, false),
        )) assertFalse(isCopyOrCut(key, ctrl, meta, shift), "$key")
    }

    private data class Quad(val key: Key, val ctrl: Boolean, val meta: Boolean, val shift: Boolean)

    private class Recorded : ClipboardManager {
        val copied = ArrayList<String>()
        override fun setText(annotatedString: AnnotatedString) {
            copied += annotatedString.text
        }
        override fun getText(): AnnotatedString? = AnnotatedString("pasted")
        override fun hasText(): Boolean = true
    }

    @Test
    fun theFieldsClipboardTakesNoCopyAndStillPastes() {
        val base = Recorded()
        val board = TakesNoCopy(base)
        board.setText(AnnotatedString("ABCD"))
        assertTrue(base.copied.isEmpty())
        assertEquals("pasted", board.getText()?.text)
        assertTrue(board.hasText())
    }

    @OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
    @Test
    fun theFieldsMenuOffersNoCopyAndNoCut() {
        var pasted = 0
        var all = 0
        val manager = object : androidx.compose.foundation.text.TextContextMenu.TextManager {
            override val selectedText = AnnotatedString("ABCD")
            override val cut: (() -> Unit) = {}
            override val copy: (() -> Unit) = {}
            override val paste: (() -> Unit) = { pasted++ }
            override val selectAll: (() -> Unit) = { all++ }
            override fun selectWordAtPositionIfNotAlreadySelected(offset: Offset) {}
        }
        val without = noCopyOrCut(manager)
        assertNull(without.copy)
        assertNull(without.cut)
        assertNotNull(without.paste).invoke()
        assertNotNull(without.selectAll).invoke()
        assertEquals(1, pasted)
        assertEquals(1, all)
    }

    /**
     * In a real composition: the field focused by a click, everything selected, then Ctrl+C and Ctrl+X. A plain field
     * copies (so the keys do reach a field here); the kit's field copies nothing and keeps what was typed.
     */
    @Test
    fun inTheWindowCtrlCAndCtrlXCopyNothingOutOfAKitsField() {
        assertEquals(listOf("ABCD", "ABCD"), keysOn(kitField = false).first, "a plain field copies and cuts: the keys reach it")
        val (copied, left) = keysOn(kitField = true)
        assertTrue(copied.isEmpty(), "nothing reached the clipboard: $copied")
        assertEquals("ABCD", left, "Ctrl+X took nothing out")
    }

    private fun keysOn(kitField: Boolean): Pair<List<String>, String> {
        val board = Recorded()
        val value = mutableStateOf("ABCD")
        val scene = ImageComposeScene(400, 200, Density(1f)) {
            MaterialTheme {
                CompositionLocalProvider(LocalClipboardManager provides board) {
                    if (kitField) {
                        KitGroupField(UiText.Plain("Group 2"), value.value) { value.value = it }
                    } else {
                        Field(UiText.Plain("Group 2"), value.value, mono = true) { value.value = it }
                    }
                }
            }
        }
        try {
            scene.render()
            val at = Offset(100f, 30f)
            scene.sendPointerEvent(PointerEventType.Press, at, buttons = PointerButtons(isPrimaryPressed = true), button = PointerButton.Primary)
            scene.sendPointerEvent(PointerEventType.Release, at, button = PointerButton.Primary)
            scene.render()
            for ((k, code) in listOf(Key.A to java.awt.event.KeyEvent.VK_A, Key.C to java.awt.event.KeyEvent.VK_C, Key.X to java.awt.event.KeyEvent.VK_X)) {
                scene.sendKeyEvent(ctrl(k, code, true))
                scene.sendKeyEvent(ctrl(k, code, false))
                scene.render()
            }
            return board.copied.toList() to value.value
        } finally {
            scene.close()
        }
    }

    private val source = javax.swing.JPanel()

    /** Ctrl with [key], as the window hands it to the scene (the AWT event beside it, as the window gives one). */
    // The scene's own key event (the one way a test hands it a key; the window builds the same one from AWT's).
    @OptIn(androidx.compose.ui.InternalComposeUiApi::class)
    private fun ctrl(key: Key, code: Int, down: Boolean): androidx.compose.ui.input.key.KeyEvent {
        val id = if (down) java.awt.event.KeyEvent.KEY_PRESSED else java.awt.event.KeyEvent.KEY_RELEASED
        val awt = java.awt.event.KeyEvent(source, id, System.currentTimeMillis(), java.awt.event.KeyEvent.CTRL_DOWN_MASK, code, java.awt.event.KeyEvent.CHAR_UNDEFINED)
        return androidx.compose.ui.input.key.KeyEvent(
            key = key,
            type = if (down) androidx.compose.ui.input.key.KeyEventType.KeyDown else androidx.compose.ui.input.key.KeyEventType.KeyUp,
            isCtrlPressed = true,
            nativeEvent = awt,
        )
    }
}
