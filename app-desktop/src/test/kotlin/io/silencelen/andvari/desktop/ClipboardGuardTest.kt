package io.silencelen.andvari.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

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
}
