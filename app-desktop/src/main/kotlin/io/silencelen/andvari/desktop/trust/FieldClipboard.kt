package io.silencelen.andvari.desktop.trust

import androidx.compose.ui.platform.ClipboardManager
import androidx.compose.ui.text.AnnotatedString
import io.silencelen.andvari.desktop.copyWithAutoClear

/**
 * A text field's own Ctrl+C, Ctrl+X and context menu used Compose's clipboard, which put
 * the editor's revealed password, a note, a card number, a one-time-code key or a pasted kit on the clipboard unmarked
 * and never cleared it. Provided at the window's root as `LocalClipboardManager`, this sends every such copy through
 * [copyWithAutoClear], the app's one secret clipboard: marked sensitive where the platform has a mark, cleared after
 * the policy's window ([clearSeconds]), and cleared at a lock and at exit. Reading (a paste) is the platform's own.
 *
 * Compose 1.7 on desktop copies text through [setText] only ([ClipboardManager.setClip] takes an entry that carries
 * nothing there), so that is the one way out.
 */
internal class SensitiveClipboardManager(
    private val base: ClipboardManager,
    private val clearSeconds: () -> Int,
    private val copy: (String, Int) -> Boolean = ::copyWithAutoClear,
) : ClipboardManager {
    override fun setText(annotatedString: AnnotatedString) {
        copy(annotatedString.text, clearSeconds())
    }

    override fun getText(): AnnotatedString? = base.getText()

    override fun hasText(): Boolean = base.hasText()
}
