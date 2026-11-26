package io.silencelen.andvari.desktop.trust

import java.awt.Taskbar
import java.awt.Toolkit
import java.awt.Window

/**
 * What the app asks of the operating system the moment a kit's idle warning first shows ([TrustModel.tick]): once per
 * warning, never at every tick, never for the ordinary lock. Compose for desktop hands no live region to the platform's
 * accessibility, so a line that appears is not announced by itself; and the warning cannot be drawn over a system dialog
 * such as the print dialog. Nothing of the kit is handed over: no text, no title, no image.
 */
internal fun interface KitWarningSignal {
    /** A kit's idle warning has just come on show. */
    fun warningCame()

    companion object {
        /** Nothing is asked (no window yet, or a test that does not listen). */
        val None = KitWarningSignal {}
    }
}

/**
 * The system's own signals on [window]: the taskbar's request for attention (on Windows the taskbar button flashes until
 * the window is brought forward), where the platform offers it, and the system's alert sound, once. Either one failing
 * still tries the other; a failure is thrown to the caller, which logs it.
 */
internal class WindowKitWarningSignal(private val window: Window) : KitWarningSignal {
    override fun warningCame() {
        try {
            if (Taskbar.isTaskbarSupported()) {
                val taskbar = Taskbar.getTaskbar()
                if (taskbar.isSupported(Taskbar.Feature.USER_ATTENTION_WINDOW)) taskbar.requestWindowUserAttention(window)
            }
        } finally {
            Toolkit.getDefaultToolkit().beep()
        }
    }
}
