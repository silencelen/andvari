package io.silencelen.andvari.desktop

import java.io.File

/** Shown when a Save destination would leave the chosen folder ([SaveTarget.resolve]). */
const val SAVE_OUTSIDE_FOLDER = "That file name points outside the folder you chose. Pick a plain file name inside it."

/**
 * Where an attachment Save may write (security review 2026-10, root cause D). An attachment's name
 * is authored by whoever wrote the item — any writer of a shared vault — and it used to pre-fill
 * `FileDialog(SAVE)` verbatim, so `..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat`
 * (or `.config/autostart/x.desktop` from a launcher whose cwd is $HOME) could put the attacker's
 * bytes outside the folder the user meant, and run them at next login. Web hands the name to the
 * browser's `a.download` and Android to SAF CreateDocument, both of which sanitise it; the desktop
 * is the one client that must do it itself. The backup-cli `sanitizeFileName` rules, plus Windows'
 * reserved characters and device names and a length cap.
 */
object SaveTarget {
    const val MAX_NAME_CHARS = 200
    private const val FALLBACK = "attachment"
    private const val RESERVED = "/\\:*?\"<>|"
    private val DEVICE_NAMES = Regex("^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\\..*)?$", RegexOption.IGNORE_CASE)

    /** A bare file name safe to pre-fill: no separator, drive or stream colon, control character,
     *  leading dot, trailing dot/space, or Windows device name; never empty, never over the cap. */
    fun defaultName(raw: String): String {
        var name = buildString(raw.length) {
            for (c in raw) append(if (c in RESERVED || c.code < 0x20 || c.code == 0x7F) '_' else c)
        }
        name = name.trimStart('.', ' ').trimEnd('.', ' ')
        if (name.length > MAX_NAME_CHARS) {
            // Keep a short extension so the saved file still opens with the right program.
            val dot = name.lastIndexOf('.')
            val ext = if (dot > 0 && name.length - dot <= 16) name.substring(dot) else ""
            name = name.take(MAX_NAME_CHARS - ext.length).trimEnd('.', ' ') + ext
        }
        if (name.isEmpty()) return FALLBACK
        if (DEVICE_NAMES.matches(name)) name = "_$name"
        return name
    }

    /**
     * The file a dialog's (directory, file) pair names — or null when it would land anywhere but
     * DIRECTLY inside [dir]. The belt behind [defaultName]: a native dialog may hand back a name it
     * resolved itself, and the user may type one; either way nothing is written outside the folder
     * the dialog showed.
     */
    fun resolve(dir: String, file: String): File? {
        if (file.isEmpty() || file == "." || file == "..") return null
        val folder = File(dir).canonicalFile
        val dest = File(folder, file).canonicalFile
        return if (dest.parentFile == folder && dest.name.isNotEmpty()) dest else null
    }
}
