package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The notes a "Move everything" leaves, drawn over the fake (whose move notes are walked side by side with the engine's,
 * a restart included): each line as handed, the member the move removes as the desktop names that person, and the
 * dismiss as the one way a note goes.
 */
class MoveNotesDrawnTest {
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

    private fun unlock(api: FakeDesktopAppApi, m: TrustModel) {
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
    }

    @Test
    fun aMovesNoteIsDrawnAsHandedWithItsMemberAndGoesOnlyByItsDismissAcrossALockAndARestart() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
        m.run({ vaults.openMembers(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        val member = assertNotNull(api.snapshot.account?.members).members.first { it.who is PersonName.Contact }
        m.run({ vaults.openMoveEverythingRemoving(member) })
        api.script.nextMoveKeepsHalfMade = 1
        m.run({ vaults.moveEverything(assertNotNull(snapshot.account?.moving), "Family 2") })
        m.onSnapshot(api.snapshot)
        val note = assertNotNull(api.snapshot.account).moveNotes.single()
        assertTrue(note.lines.any { it.key == CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS })
        val held = assertNotNull(note.member)
        // Each line as handed, in order; after the member's line, the member as the desktop names that person.
        val expected = note.lines.flatMap { l ->
            listOf(UiText.of(l).shown()) + if (l.key == CopyKey.MOVE_HALF_MADE_KEPT_MEMBER_HOLDS) listOf(personLine(held).shown()) else emptyList()
        }
        assertEquals(expected, moveNoteLines(note).map { it.shown() })
        // Kept across a lock and a restart (the shared code keeps it).
        m.lockNow()
        m.onSnapshot(api.snapshot)
        unlock(api, m)
        assertEquals(1, assertNotNull(api.snapshot.account).moveNotes.size)
        api.script.restart()
        m.onSnapshot(api.snapshot)
        unlock(api, m)
        val after = assertNotNull(api.snapshot.account).moveNotes.single()
        assertEquals(note.lines.map { it.key }, after.lines.map { it.key })
        // Drawn in the open account, and taken away by its dismiss from the keyboard.
        val w = Window(m)
        try {
            w.tabUntil(UiText.ph(Placeholder.DISMISS).shown())
            w.enter()
        } finally {
            w.close()
        }
        assertTrue(assertNotNull(api.snapshot.account).moveNotes.isEmpty(), "dismissed")
        m.lockNow()
        m.onSnapshot(api.snapshot)
        unlock(api, m)
        assertTrue(assertNotNull(api.snapshot.account).moveNotes.isEmpty(), "and not said again")
    }

    /**
     * A move that meets a frozen half-made vault of an earlier try: the note's line that the member the move removes still
     * holds that vault is followed by that member, named as the desktop names that person, as beside the older note's line.
     */
    @Test
    fun aFrozenHalfMadeVaultsNoteNamesTheMemberWhoStillHoldsIt() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
        m.run({ vaults.openMembers(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        val member = assertNotNull(api.snapshot.account?.members).members.first { it.who is PersonName.Contact }
        m.run({ vaults.openMoveEverythingRemoving(member) })
        api.script.nextMoveHalfMadeFrozen = true
        m.run({ vaults.moveEverything(assertNotNull(snapshot.account?.moving), "Family 2") })
        m.onSnapshot(api.snapshot)
        val note = assertNotNull(api.snapshot.account).moveNotes.single()
        assertEquals(listOf(CopyKey.MOVE_HALF_MADE_FROZEN, CopyKey.MOVE_HALF_MADE_FROZEN_MEMBER_HOLDS), note.lines.map { it.key })
        val held = assertNotNull(note.member, "the note names the member")
        val drawn = moveNoteLines(note).map { it.shown() }
        println("WALK|the frozen half-made vault's note|$drawn")
        assertEquals(
            listOf(UiText.of(note.lines[0]).shown(), UiText.of(note.lines[1]).shown(), personLine(held).shown()),
            drawn,
            "the member named right after the line that they still hold the vault",
        )
        // Drawn in the open account; its dismiss is in reach of the keyboard and takes it away.
        val w = Window(m)
        try {
            w.tabUntil(UiText.ph(Placeholder.DISMISS).shown())
            w.enter()
        } finally {
            w.close()
        }
        assertTrue(assertNotNull(api.snapshot.account).moveNotes.isEmpty(), "dismissed")
    }
}
