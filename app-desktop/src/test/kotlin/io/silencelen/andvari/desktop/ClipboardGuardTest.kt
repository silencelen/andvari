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

    // ---- ux-parity--5: only the NEWEST copy owns the scheduled clear ----

    /**
     * The bug the generation counter fixes: copy the same password at t=0 and again at t=25 s with
     * a 30 s window and the FIRST timer's `current == value` guard still passed at t=30 s — the
     * clipboard emptied 5 s into a window the CopyRow had just promised was 30 s. The equal-value
     * guard alone only ever covered the different-value case.
     */
    @Test
    fun aSupersededTimerDoesNotClearTheNewerCopysWindow() {
        assertFalse(
            shouldClearClipboard(scheduledGeneration = 1, currentGeneration = 2, clipboardNow = "hunter2", copiedValue = "hunter2"),
            "a re-copy of the SAME secret must retire the older timer, not truncate the new window",
        )
        assertTrue(
            shouldClearClipboard(scheduledGeneration = 2, currentGeneration = 2, clipboardNow = "hunter2", copiedValue = "hunter2"),
            "the newest copy still owns its own clear",
        )
    }

    /** The pre-existing ownership guard is unchanged: never stomp something the user copied from
     *  another app since, and never clear on an unreadable clipboard. */
    @Test
    fun theClipboardIsOnlyClearedWhileItStillHoldsOurSecret() {
        assertFalse(shouldClearClipboard(1, 1, clipboardNow = "a url the user copied after pasting", copiedValue = "hunter2"))
        assertFalse(shouldClearClipboard(1, 1, clipboardNow = null, copiedValue = "hunter2"), "null = can't verify ownership, NEVER 'still ours'")
    }
}
