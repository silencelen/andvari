package io.silencelen.andvari.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ux-error--3 (polish audit 2026-07-27): [copyPlain]/[copyWithAutoClear] were the file's only
 * UNguarded AWT clipboard calls — `setContents` throws IllegalStateException on a busy Windows
 * clipboard (RDP, clipboard managers, Office), escaping straight out of a Compose click handler.
 * Both now return false instead of throwing, so a Copy click can never crash the app.
 *
 * The test JVM runs headless (forced below, before AWT initializes), where the systemClipboard
 * access itself throws — exercising exactly the guard: any throw inside the copy helpers must
 * become a false, never a propagated exception.
 */
class ClipboardGuardTest {
    private companion object {
        init {
            // Must land before the first Toolkit touch; gradle test JVMs are headless by
            // default, this just makes the precondition explicit instead of environmental.
            System.setProperty("java.awt.headless", "true")
        }
    }

    @Test
    fun copyPlainReturnsFalseInsteadOfThrowing() {
        assertFalse(copyPlain("otpauth://totp/example"))
    }

    @Test
    fun copyWithAutoClearReturnsFalseInsteadOfThrowing() {
        assertFalse(copyWithAutoClear("hunter2", clearSeconds = 1))
    }

    // The failure line the four Copy surfaces render — byte-twin of web/extension errors.ts
    // CLIPBOARD_FAILED (the sentence is pinned cross-package from web/src; this pins desktop's
    // local copy so a one-sided reword fails here).
    @Test
    fun failureSentenceIsTheCrossClientTwin() {
        assertEquals("Couldn't copy to the clipboard — try again.", CLIPBOARD_COPY_FAILED)
    }

    // ---- the clear is by ownership, with retries, on two clocks ----

    /** A clipboard as AWT runs one: the owner of what it replaces is told. [failClears] clears throw first. */
    private class FakeBoard(var failClears: Int = 0, var failPuts: Int = 0) : ClipboardPort {
        var owner: SensitiveTextSelection? = null
        var text: String? = null
        var clears = 0

        override fun put(selection: SensitiveTextSelection) {
            if (failPuts > 0) { failPuts--; throw IllegalStateException("cannot open system clipboard") }
            owner?.lostOwnership(null, null)
            owner = selection
            text = selection.getTransferData(java.awt.datatransfer.DataFlavor.stringFlavor) as String
        }

        override fun clear() {
            if (failClears > 0) { failClears--; throw IllegalStateException("cannot open system clipboard") }
            owner?.lostOwnership(null, null)
            owner = null
            text = ""
            clears++
        }

        /** Another program copies something. */
        fun otherProgramCopies(t: String) {
            owner?.lostOwnership(null, null)
            owner = null
            text = t
        }

        /** A clipboard manager (xfce4-clipman, parcellite, CopyQ) takes the clipboard over with the same text. */
        fun managerTakesItOver() {
            owner?.lostOwnership(null, null)
            owner = null
        }

        var failReads = 0

        override fun text(): String? {
            if (failReads > 0) { failReads--; throw IllegalStateException("cannot open system clipboard") }
            return text
        }
    }

    // ---- a clipboard manager that takes the clipboard over ----

    /** The path that showed it: the manager re-owns the copied password; the clear still happens at its time. */
    @Test
    fun aSecretAClipboardManagerTookOverIsStillClearedAtItsTime() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("the-copied-password", 30))
        board.managerTakesItOver()
        pass(c, 5_000)
        assertTrue(c.holding, "still the secret: the clear stays due")
        assertEquals("the-copied-password", board.text, "not cleared before its time")
        pass(c, 26_000)
        assertEquals("", board.text)
        assertEquals(1, board.clears)
        assertFalse(c.holding)
    }

    @Test
    fun aSecretAClipboardManagerTookOverIsClearedAtALockAndAtExit() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("the-copied-password", 30))
        board.managerTakesItOver()
        c.clearNow()
        assertEquals("", board.text, "the lock's clear")
        assertFalse(c.holding)
    }

    @Test
    fun aCopyThePersonMadeAfterTheTakeOverIsNeverCleared() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("the-copied-password", 30))
        board.managerTakesItOver()
        pass(c, 2_000)
        assertTrue(c.holding)
        board.text = "a url the person copied after pasting"
        pass(c, 30_000)
        c.clearNow()
        assertEquals("a url the person copied after pasting", board.text)
        assertEquals(0, board.clears)
        assertFalse(c.holding)
    }

    @Test
    fun aLookThatFailsIsTriedAgainAndNeverForgetsTheSecret() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("the-copied-password", 30))
        board.managerTakesItOver()
        board.failReads = 3
        pass(c, 3_000)
        assertTrue(c.holding, "not forgotten for a read that failed")
        pass(c, 28_000)
        assertEquals("", board.text)
    }

    private var mono = 0L
    private var wall = 1_700_000_000_000L

    private fun clipboard(board: FakeBoard) = SecretClipboard({ board }, { mono }, { wall })

    private fun pass(c: SecretClipboard, ms: Long) {
        var left = ms
        while (left > 0) {
            val step = minOf(1000L, left)
            mono += step; wall += step; left -= step
            c.tick()
        }
    }

    @Test
    fun aNewerCopyOwnsTheOnlyClear() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("hunter2", 30))
        pass(c, 25_000)
        assertTrue(c.copy("hunter2", 30))
        pass(c, 5_000)
        assertEquals("hunter2", board.text, "the older copy's clear does not cut the newer one's window short")
        pass(c, 25_000)
        assertEquals("", board.text)
        assertFalse(c.holding)
    }

    @Test
    fun aClearThatFailsIsTriedAgainAndTheSecretIsForgottenOnlyOnceItWorked() {
        val board = FakeBoard(failClears = 2)
        val c = clipboard(board)
        assertTrue(c.copy("hunter2", 30))
        pass(c, 30_000)
        assertTrue(c.holding, "the first clear failed: still due")
        assertEquals("hunter2", board.text)
        pass(c, 1000)
        assertTrue(c.holding, "and the second")
        pass(c, 1000)
        assertFalse(c.holding)
        assertEquals("", board.text)
    }

    @Test
    fun aLockClearsNowAndAFailedLockClearIsTriedAgainAtTheNextTick() {
        val board = FakeBoard(failClears = 1)
        val c = clipboard(board)
        assertTrue(c.copy("hunter2", 30))
        c.clearNow()
        assertTrue(c.holding, "the lock's clear failed")
        pass(c, 1000)
        assertFalse(c.holding, "the next tick cleared it, long before the window's end")
        assertEquals("", board.text)
    }

    @Test
    fun somethingElseOnTheClipboardIsNeverTouched() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("hunter2", 30))
        board.otherProgramCopies("a url the person copied after pasting")
        pass(c, 31_000)
        c.clearNow()
        assertEquals("a url the person copied after pasting", board.text)
        assertEquals(0, board.clears)
        assertFalse(c.holding, "seen to hold something else: forgotten")
    }

    @Test
    fun timeAsleepCountsTowardTheClear() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("hunter2", 30))
        wall += 60L * 60 * 1000
        mono += 1
        c.tick()
        assertEquals("", board.text)
    }

    @Test
    fun aCopyThatFailedLeavesTheOlderClearDue() {
        val board = FakeBoard()
        val c = clipboard(board)
        assertTrue(c.copy("first", 30))
        board.failPuts = 1
        assertFalse(c.copy("second", 30))
        pass(c, 30_000)
        assertEquals("", board.text)
    }
}
