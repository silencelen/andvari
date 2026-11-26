package io.silencelen.andvari.core.app.content

/**
 * What the content does with text an item's writer chose, before a list or a fill suggestion shows it. Every item in a
 * shared vault was written by a co-member, and every item at all comes through a server; either may be hostile.
 *
 * A label ([label]) is one line: control characters, line and paragraph separators and the characters that change the
 * reading direction or are invisible formatting (Unicode category Cf: the bidi embeddings, overrides and isolates, the
 * marks, zero-width joiners and spaces) become nothing or a space, and it is cut to [LABEL_MAX_CHARS] characters. So a
 * name cannot reverse what follows it, break the row it is in, hide part of itself, or push the rest off the screen.
 * Only what is shown is changed: the item, its search and what a fill hands out stay as written.
 */
object ItemText {
    /** The longest label a list row or a fill suggestion shows, in characters; a longer one ends with "…". */
    const val LABEL_MAX_CHARS = 200

    /** [text] as one safe line of at most [max] characters (see the class). */
    fun label(text: String, max: Int = LABEL_MAX_CHARS): String {
        val out = StringBuilder(minOf(text.length, max + 1))
        var lastSpace = true
        var cut = false
        var i = 0
        while (i < text.length) {
            val c = text[i]
            i++
            val space = c.isWhitespace() || c.category == CharCategory.CONTROL || c == '\u2028' || c == '\u2029'
            when {
                space -> if (!lastSpace) {
                    out.append(' ')
                    lastSpace = true
                }
                c.category == CharCategory.FORMAT -> Unit
                // A lone surrogate half is not a character: dropped, so no cut ever splits a pair into one.
                c.isHighSurrogate() -> {
                    if (i < text.length && text[i].isLowSurrogate()) {
                        out.append(c).append(text[i])
                        i++
                        lastSpace = false
                    }
                }
                c.isLowSurrogate() -> Unit
                else -> {
                    out.append(c)
                    lastSpace = false
                }
            }
            if (out.length > max) {
                cut = true
                break
            }
        }
        if (!cut) return out.toString().trimEnd()
        var end = max
        if (end > 0 && out[end - 1].isHighSurrogate()) end--
        return out.substring(0, end).trimEnd() + "…"
    }

    /**
     * The address a saved site may be opened at, or null: an `http` or `https` address as written, a bare host with
     * `https://` in front, and nothing else. Refused: any other scheme (`javascript:`, `data:`, `file:`, `intent:`, an
     * app address), an address with a space, a control or an invisible formatting character in it, and one that names a
     * user or password before its host (`https://bank.example@evil.example/` opens evil.example; a backslash counts as
     * a slash, as browsers read it). The one rule for every screen that opens a saved address.
     */
    fun openableAddress(site: String): String? {
        val s = site.trim()
        if (s.isEmpty() || s.any { it.isWhitespace() || it.category == CharCategory.CONTROL || it.category == CharCategory.FORMAT }) return null
        if (carriesUserInfo(s)) return null
        val lower = s.lowercase()
        if (lower.startsWith("https://") || lower.startsWith("http://")) return s.takeIf { it.length > it.indexOf("//") + 2 }
        if (SCHEME.containsMatchIn(lower)) return null
        if (s.startsWith("/") || s.startsWith("\\")) return null
        return "https://$s"
    }

    private val SCHEME = Regex("^[a-z][a-z0-9+.-]*:")

    /** Whether [site] names a user or password before its host: an `@` between the scheme's `//` and the first `/ ? # \`. */
    internal fun carriesUserInfo(site: String): Boolean {
        val s = site.trim()
        val slashes = s.indexOf("//")
        val start = if (slashes >= 0 && SCHEME.containsMatchIn(s.substring(0, slashes).lowercase())) slashes + 2 else 0
        val rest = s.substring(start)
        val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' || it == '\\' }.let { if (it < 0) rest.length else it }
        return '@' in rest.substring(0, end)
    }
}
