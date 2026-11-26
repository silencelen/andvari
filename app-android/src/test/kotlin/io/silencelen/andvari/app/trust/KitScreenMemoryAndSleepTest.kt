package io.silencelen.andvari.app.trust

import androidx.compose.runtime.State
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsConfiguration
import io.silencelen.andvari.app.autofill.ContentFillSession
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitScreen
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.lang.reflect.Modifier as Reflect
import java.util.IdentityHashMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What a lock leaves of a kit in the screens' own memory, a lock that falls due while the phone sleeps, and an
 * accessibility service's Copy and Cut on the fields the kit is typed into. An independent check found the composition
 * keeping the kit's document, its QR picture and the typed groups (in `remember`) until the person came back, also after
 * a lock made while the app was away; the timer behind the print screen standing still while the phone slept, with the
 * kit not covered on that road; and TalkBack's Copy reaching the typed groups.
 */
class KitScreenMemoryAndSleepTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    /** A never-saved account unlocked as the autofill window does: a kit in the journey, the app not on show. */
    private fun kitAfterAFillUnlock(clock: () -> Long): Triple<FakeAppApi, TrustModel, KitScreen> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        fake.script.publicInstance.accounts.values.first().kitSaved = false
        val m = TrustModel(fake, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, clock).also { it.onSnapshot(fake.snapshot) }
        m.touched()
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        return Triple(fake, m, assertIs<EntryScreen.Kit>(fake.snapshot.entry).kit)
    }

    /** What the screens hold of [kit] once drawn: its document, a picture made from it, and three typed groups. */
    private fun drawn(m: TrustModel, kit: KitScreen): List<Any> {
        val hold = m.kitScreen
        val doc = assertNotNull(hold.documentFor(kit) { m.api.kit.kitDocument(kit) })
        val picture = hold.pictureFor(doc) { Any() }
        hold.typed(kit, 3)
        hold.type(kit, 0, doc.groups[0])
        assertEquals(doc.groups[0], hold.typed(kit, 3)[0])
        return listOf(doc, picture, doc.groups, doc.groups[0])
    }

    /**
     * Whether any of [targets] can be reached from [root] through fields, collections, arrays and Compose or flow state,
     * leaving out the shared code's engine itself (the `api`: what it keeps is its own and its lock's) and the scope.
     */
    private fun reaches(root: Any, targets: List<Any>): Boolean {
        val wanted = IdentityHashMap<Any, Unit>().apply { targets.forEach { put(it, Unit) } }
        val seen = IdentityHashMap<Any, Unit>()
        val queue = ArrayDeque<Any>().apply { add(root) }
        while (queue.isNotEmpty() && seen.size < 200_000) {
            val o = queue.removeFirst()
            if (seen.put(o, Unit) != null) continue
            if (o in wanted) return true
            when (o) {
                is CharSequence, is Number, is Boolean, is Class<*>, is Enum<*>, is io.silencelen.andvari.core.app.AppApi -> continue
                is Array<*> -> o.filterNotNull().forEach(queue::add)
                is Collection<*> -> o.filterNotNull().forEach(queue::add)
                is Map<*, *> -> o.entries.forEach { (k, v) -> k?.let(queue::add); v?.let(queue::add) }
                is State<*> -> o.value?.let(queue::add)
                is kotlinx.coroutines.flow.StateFlow<*> -> o.value?.let(queue::add)
            }
            var c: Class<*>? = o.javaClass
            if (c!!.name.startsWith("java.") || c.name.startsWith("kotlin.") && !c.name.startsWith("kotlin.jvm.internal.Ref")) continue
            while (c != null && c != Any::class.java) {
                for (f in c.declaredFields) {
                    if (Reflect.isStatic(f.modifiers) || f.type.isPrimitive || f.name == "api" || f.name == "scope") continue
                    val v = runCatching { f.isAccessible = true; f.get(o) }.getOrNull() ?: continue
                    queue.add(v)
                }
                c = c.superclass
            }
        }
        return false
    }

    // ---- item 3: out of memory at a lock means out of the screens' memory too ----

    @Test
    fun aLockWhileTheAppIsAwayEmptiesWhatTheScreensDrawFromWithNothingRecomposing() {
        var now = 0L
        val (fake, m, kit) = kitAfterAFillUnlock { now }
        val held = drawn(m, kit)
        assertTrue(reaches(m, held), "the walk finds the kit while it is on show")
        // The hard lock's check, with the app away and no composition running: only the model acts.
        now = m.autoLockMs()
        m.tick()
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
        val hold = m.kitScreen
        assertNull(hold.document)
        assertNull(hold.picture)
        assertFalse(reaches(m, held), "nothing the model or the screens' holder can reach refers to the kit")
        assertFalse(reaches(hold, held))
        // A keystroke the lock overtook is not taken; a screen drawn again for that kit starts with empty fields.
        hold.type(kit, 1, "late")
        assertTrue(hold.typed(kit, 3).all { it.isEmpty() })
    }

    @Test
    fun theModelsOwnLockAndEveryCoverEmptyItTooAndTheScreensKeepNothingButTheHolder() {
        // The background lock (the kit covered as the lock is made).
        val (_, m, kit) = kitAfterAFillUnlock { 0L }
        val held = drawn(m, kit)
        m.backgrounded()
        assertFalse(reaches(m, held))

        // A kit the person left for the print screen: covered, and out of the screens' memory.
        val (fake2, m2, kit2) = kitAfterAFillUnlock { 0L }
        m2.returnedToForeground()
        m2.uncoverKit()
        val held2 = drawn(m2, kit2)
        m2.wentAway()
        assertIs<EntryScreen.Kit>(fake2.snapshot.entry, "not locked yet: the print screen is the person's")
        assertTrue(m2.kitCovered.value)
        assertFalse(reaches(m2, held2))

        // The screens read the kit only through the holder: no remember of the document, the picture or the groups, and
        // the Print button takes the document from the holder when it is tapped.
        val src = main("trust/KitScreens.kt")
        val reveal = src.substringAfter("private fun KitReveal(").substringBefore("\n}\n")
        val confirm = src.substringAfter("private fun KitConfirm(").substringBefore("\n}\n")
        for (body in listOf(reveal, confirm)) assertFalse("remember(" in body, body)
        assertTrue("hold.documentFor(kit)" in reveal && "hold.pictureFor(doc)" in reveal)
        assertTrue("(hold.picture as? Bitmap)" in reveal, "the picture is read from the holder as it is drawn")
        assertTrue("{ hold.document?.let { printKit(context, it) } }" in reveal)
        assertTrue("hold.typed(kit, kit.groupsToType.size)" in confirm && "hold.type(kit, i, v)" in confirm)
        val model = main("trust/TrustModel.kt")
        assertTrue("internal val kitScreen = KitScreenHold()" in model)
        assertTrue("KitHolds.hold(this)" in main("trust/KitHolds.kt").substringAfter("fun documentFor("), "dropAll reaches it")
    }

    // ---- item 4: a lock that falls due while the phone sleeps ----

    @Test
    fun theHardLocksClockCountsSleepingTimeAndItsWaitIsShort() {
        var now = 0L
        val (fake, m, _) = kitAfterAFillUnlock { now }
        // The wait is in awake time and never longer than a few seconds; the clock it checks is elapsed realtime.
        assertEquals(ContentFillSession.HARD_LOCK_MAX_WAIT_MS, ContentFillSession.hardLockWaitMs(m, 5_000L))
        assertTrue(ContentFillSession.HARD_LOCK_MAX_WAIT_MS <= 10_000L)
        val hard = main("autofill/ContentFillSession.kt").substringAfter("object HardLock {").substringBefore("\n    }\n")
        assertTrue("internal fun nextCheckInMs(m: TrustModel): Long? = hardLockWaitMs(m, SLACK_MS)" in hard, "the hard lock waits by it")
        assertTrue("SystemClock.elapsedRealtime()" in main("trust/TrustSeam.kt").substringAfter("val model = TrustModel(").lineSequence().first())
        // An hour of sleep with no check at all: the first check after waking locks.
        now = 3_600_000
        m.tick()
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
        assertNull(ContentFillSession.hardLockWaitMs(m, 5_000L), "nothing left under the clock")
    }

    @Test
    fun aKitThePersonLeftForThePrintScreenIsCoveredSoTheReturnShowsNothingBeforeTheLock() {
        var now = 0L
        val (fake, m, _) = kitAfterAFillUnlock { now }
        m.returnedToForeground()
        m.uncoverKit()
        assertFalse(m.kitCovered.value)
        assertTrue(m.keepScreenOn.value)
        m.wentAway()
        assertTrue(m.kitCovered.value, "covered as the app goes to the print screen")
        assertFalse(m.keepScreenOn.value)
        // The phone slept past the limit; the person comes back to andvari before any check ran: the first frame finds
        // the cover, and the started activity's first tick locks.
        now = 3_600_000
        m.returnedToForeground()
        assertTrue(m.kitCovered.value, "nothing of the kit at the return")
        m.tick()
        assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
    }

    // ---- item 5: an accessibility service's Copy and Cut ----

    @Test
    fun anAccessibilityServicesCopyAndCutOnTheTypedGroupsDoNothing() {
        val config = SemanticsConfiguration().apply(noCopyOutActions)
        assertEquals(false, config[SemanticsActions.CopyText].action?.invoke(), "Copy does nothing")
        assertEquals(false, config[SemanticsActions.CutText].action?.invoke(), "Cut does nothing")
        val confirm = main("trust/KitScreens.kt").substringAfter("private fun KitConfirm(").substringBefore("\n}\n")
        val field = confirm.lines().first { "Field(UiText.ph(Placeholder.KIT_GROUP_FIELD" in it }
        assertTrue("modifier = Modifier.semantics(properties = noCopyOutActions)" in field, "on every field the kit is typed into")
        // The field's own modifier is the outer one, applied after the text field's semantics, whose actions it replaces.
        val ui = main("trust/TrustUi.kt").substringAfter("internal fun Field(").substringBefore("\n}\n")
        assertTrue("modifier: Modifier = Modifier" in ui && "Modifier.fillMaxWidth().padding(vertical = 4.dp).then(modifier)" in ui)
    }
}
