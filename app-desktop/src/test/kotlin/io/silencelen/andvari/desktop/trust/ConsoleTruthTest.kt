package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.OperatorResult
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The operator's console says what is so (the reader of 2026-11-17): each line true of every road that reaches it. */
class ConsoleTruthTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")
    private fun ph(t: UiText?): Placeholder = assertIs<UiText.Ph>(assertNotNull(t)).placeholder

    /** A refresh the server answered inside its grace is a line of its own; every other kind is shown as the server sent it. */
    @Test
    fun aRefreshAnsweredInsideTheGraceIsALineOfItsOwnInTheAudit() {
        assertEquals(Placeholder.OP_AUDIT_REFRESH_GRACE, ph(auditKindLine("refresh_grace")))
        assertEquals("device_revoked", assertIs<UiText.Plain>(auditKindLine("device_revoked")).shown())
        val rows = body("OperatorScreens.kt", "private fun AuditSection(")
        assertTrue(rows.contains("auditKindLine(row.type).shown()"), "the row")
        assertTrue(rows.contains("parts = listOfNotNull(who, row.deviceId, row.ip, row.meta)"), "with the account, the device and the address")
        assertTrue(body("OperatorScreens.kt", "private fun AuditTypeChooser(").contains("auditKindLine(t).shown()"), "and in the type's menu")
    }

    /**
     * The identity card's results in words true of every road the shared code sends them on: not current (another
     * device, or a chain not read just now), refused (by the server or before sending), and for a recovery key with a
     * rotation statement, that the statement may already be stored. A move's card stored and never current here is said
     * as that; finishing the set-up says its own two roads.
     */
    @Test
    fun theCardsResultsAreSaidAsTrueOfEveryRoad() {
        assertEquals(Placeholder.OP_CARD_NOT_CURRENT, ph(operatorWords(OperatorResult.CARD_MOVED_ON, 0, OperatorModel.Action.RENAME)))
        assertEquals(Placeholder.OP_CARD_REFUSED_EITHER, ph(operatorWords(OperatorResult.CARD_REFUSED, 0, OperatorModel.Action.MOVE)))
        assertEquals(Placeholder.OP_CARD_REFUSED_EITHER, ph(operatorWords(OperatorResult.CARD_REFUSED, 0)))
        assertEquals(Placeholder.OP_ROTATION_CARD_NOT_CURRENT, ph(operatorWords(OperatorResult.CARD_MOVED_ON, 0, OperatorModel.Action.RECOVERY_SET)))
        assertEquals(Placeholder.OP_ROTATION_CARD_REFUSED, ph(operatorWords(OperatorResult.CARD_REFUSED, 0, OperatorModel.Action.RECOVERY_SET)))
        assertEquals(Placeholder.OP_MOVE_CARD_STORED, ph(operatorWords(OperatorResult.CARD_STORED_NOT_SHOWN, 0, OperatorModel.Action.MOVE)))
        // Any other card change stored and not shown keeps the shared code's sentence.
        assertEquals(UiText.forResult(OperatorResult.CARD_STORED_NOT_SHOWN, 0)?.shown(), operatorWords(OperatorResult.CARD_STORED_NOT_SHOWN, 0, OperatorModel.Action.RENAME)?.shown())
        assertEquals(Placeholder.OP_SETUP_CARD_NOT_TAKEN, ph(setupWords(OperatorResult.CARD_REFUSED, 0)))
        assertEquals(ph(operatorWords(OperatorResult.WRONG_PASSWORD, 0)), ph(setupWords(OperatorResult.WRONG_PASSWORD, 0)))
        // The console's act passes its action (and whether a stored card held the number before), and the set-up its own words.
        assertTrue(body("OperatorModel.kt", "    internal fun act(").contains("operatorWords(r, api.retryAfterSeconds(), action, cardHeldBefore)"))
        assertTrue(body("OperatorModel.kt", "    fun finishServerSetup(").contains("setupWords(it, api.retryAfterSeconds())"))
    }

    /** The recovery copy is handed over once: a save that failed says that a new download is the way, never "another place". */
    @Test
    fun aRecoveryCopyThatWasNotSavedSaysANewDownloadIsTheWay() {
        assertEquals(Placeholder.OP_ESCROW_NOT_SAVED, ph(escrowWrittenLine(FileWritten(ExportWrite.NOT_WRITTEN), "ada@example.com", "/x")))
        assertEquals(Placeholder.FILE_KEPT_ASIDE, ph(escrowWrittenLine(FileWritten(ExportWrite.NOT_WRITTEN, "copy.recovered-1"), "ada@example.com", "/x")))
        assertEquals(Placeholder.OP_ESCROW_SAVED, ph(escrowWrittenLine(FileWritten(ExportWrite.SAVED), "ada@example.com", "/x")))
        val controls = body("OperatorScreens.kt", "private fun EscrowControls(")
        assertTrue(controls.contains("val line = escrowWrittenLine(written, email, pick.file.absolutePath)"))
        // Before anything was taken (a name outside the folder), another place can be tried: that line stays.
        assertTrue(controls.contains("FilePicker.SavePick.Outside -> op.sayAt(OperatorModel.Area.ACCOUNT, a.userId, UiText.ph(Placeholder.ATTACHMENT_NOT_WRITTEN), escrow)"))
        assertNotEquals(Placeholder.ATTACHMENT_NOT_WRITTEN, ph(escrowWrittenLine(FileWritten(ExportWrite.NOT_WRITTEN), "a", "/x")))
    }
}
