package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A move's notes ([io.silencelen.andvari.core.app.AccountSnapshot.moveNotes]) are drawn where the account's other move
 * notices are, at the top of every signed-in page (the vault, Sharing and a shared vault's page, Settings), read from the
 * snapshot only, each with its dismissal, which is the person's own and the app's only call of it. The walk over the real
 * engine is in [PolicyWipeEngineWalksTest].
 */
class MoveNotesDrawnTest {
    private fun main(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    @Test
    fun eachNoteIsDrawnBesideTheOtherMoveNoticesWithItsDismissal() {
        val screens = main("trust/AccountScreens.kt")
        val lines = screens.substringAfter("private fun AccountLines(").substringBefore("\n}\n")
        val stored = lines.indexOf("for (n in account.movesStoredOutside) MoveStoredOutsideNotice(model, s, n)")
        val notes = lines.indexOf("for (n in account.moveNotes) MoveNoteView(model, s, n)")
        assertTrue(stored > 0 && notes > stored, "beside the other move notices, on every page's header")
        val view = screens.substringAfter("internal fun MoveNoteView(").substringBefore("\n}\n")
        assertTrue("moveNoteLines(note)" in view && "model.dismissMoveNote(note)" in view)
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        fun usersOf(token: String) = sources.filter { f -> f.readLines().any { token in it.substringBefore("//") } }.map { it.name }.toSet()
        assertEquals(setOf("TrustModel.kt"), usersOf("MoveNotes)?.dismissMoveNote("), "one call, from the person's dismiss")
        assertEquals(setOf("AccountScreens.kt"), usersOf("MoveNoteView("))
        assertEquals(setOf("AccountScreens.kt"), usersOf("account.moveNotes"), "read from the snapshot, never kept")
    }
}
