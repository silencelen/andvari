package io.silencelen.andvari.server

/**
 * `/selfhost` content (design 2026-07-15 §8.1, B2-4): every instance carries its own self-host
 * docs — a bundled HTML render of `docs/self-hosting.md` plus the three deploy artifacts as
 * downloads. Sources are baked into the jar at build time (server/build.gradle.kts
 * processResources → the classpath `selfhost/` dir) from files the DOCS/DEPLOY lane owns
 * (NB: Kotlin nests block comments, so no literal slash-star glob in this KDoc):
 *
 *   docs/self-hosting.md          → the guide (rendered)
 *   deploy/docker-compose.yml       → download
 *   deploy/docker-compose.caddy.yml → download (the recommended --caddy auto-HTTPS overlay)
 *   deploy/andvari.env.template     → download
 *   deploy/bringup.sh               → download
 *
 * A build made before those files exist serves a stub page and 404s the absent artifacts —
 * never the SPA fallback (the route itself is what §8.1 mandates exists).
 */
internal object SelfHost {
    /** Downloadable artifact allowlist — FIXED names; no request input reaches the classpath lookup. */
    val ARTIFACTS = listOf("docker-compose.yml", "docker-compose.caddy.yml", "andvari.env.template", "bringup.sh")

    /** The page is static text + links: everything locked down except the inline <style>. */
    const val CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"

    private fun resource(name: String): ByteArray? =
        SelfHost::class.java.getResourceAsStream("/selfhost/$name")?.use { it.readBytes() }

    fun artifact(name: String): ByteArray? = if (name in ARTIFACTS) resource(name) else null

    fun pageHtml(): String {
        val body = resource("self-hosting.md")?.decodeToString()?.let { renderMarkdown(it) }
            ?: ("<p>The self-hosting guide was not bundled into this build — see the project's " +
                "<code>docs/self-hosting.md</code>. The deployment artifacts below still apply.</p>")
        val downloads = ARTIFACTS.joinToString("\n") { name ->
            if (resource(name) != null) {
                """      <li><a href="/selfhost/${name}">${name}</a></li>"""
            } else {
                """      <li>${name} <em>(not bundled in this build)</em></li>"""
            }
        }
        return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Self-hosting andvari</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; line-height: 1.55; color: #222; background: #fff; }
  pre { background: #f4f4f4; padding: .75rem 1rem; overflow-x: auto; border-radius: 6px; }
  code { background: #f4f4f4; padding: .1em .3em; border-radius: 4px; font-size: .95em; }
  pre code { background: none; padding: 0; }
  h1, h2, h3 { line-height: 1.25; }
  aside { border: 1px solid #ddd; border-radius: 8px; padding: .75rem 1rem; margin: 1.5rem 0; background: #fafafa; }
  @media (prefers-color-scheme: dark) {
    body { color: #ddd; background: #151515; }
    pre, code { background: #242424; }
    aside { background: #1c1c1c; border-color: #333; }
  }
</style>
</head>
<body>
<aside>
  <strong>Deployment artifacts</strong>
  <ul>
$downloads
  </ul>
</aside>
$body</body>
</html>
"""
    }

    /**
     * Minimal, ESCAPE-FIRST Markdown renderer: headings, fenced code, unordered lists, inline
     * code/bold, http(s) links, paragraphs. Every character is HTML-escaped BEFORE any markup is
     * re-introduced, so document content can never smuggle live HTML/scripts into the page (only
     * scheme-pinned http(s) hrefs are emitted). Deliberately tiny and dependency-free; unsupported
     * constructs (tables, images) degrade to escaped text.
     */
    internal fun renderMarkdown(md: String): String {
        val out = StringBuilder()
        var inCode = false
        var inList = false
        val para = StringBuilder()
        fun flushPara() {
            if (para.isNotBlank()) out.append("<p>").append(inline(para.toString().trim())).append("</p>\n")
            para.setLength(0)
        }
        fun closeList() {
            if (inList) { out.append("</ul>\n"); inList = false }
        }
        for (line in md.lines()) {
            if (line.trimStart().startsWith("```")) {
                flushPara(); closeList()
                out.append(if (inCode) "</code></pre>\n" else "<pre><code>")
                inCode = !inCode
                continue
            }
            if (inCode) { out.append(esc(line)).append('\n'); continue }
            val t = line.trim()
            when {
                t.isEmpty() -> { flushPara(); closeList() }
                t.startsWith("#") -> {
                    flushPara(); closeList()
                    val level = t.takeWhile { it == '#' }.length.coerceAtMost(4)
                    out.append("<h$level>").append(inline(t.dropWhile { it == '#' }.trim())).append("</h$level>\n")
                }
                t.startsWith("- ") || t.startsWith("* ") -> {
                    flushPara()
                    if (!inList) { out.append("<ul>\n"); inList = true }
                    out.append("<li>").append(inline(t.drop(2).trim())).append("</li>\n")
                }
                else -> { closeList(); para.append(t).append(' ') }
            }
        }
        flushPara(); closeList()
        if (inCode) out.append("</code></pre>\n") // unterminated fence: close rather than leak state
        return out.toString()
    }

    private fun esc(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    /** Inline markup over ALREADY-ESCAPED text: `code`, **bold**, [text](http(s)-url). */
    private fun inline(s: String): String {
        var r = esc(s)
        r = Regex("`([^`]+)`").replace(r) { "<code>${it.groupValues[1]}</code>" }
        r = Regex("""\*\*([^*]+)\*\*""").replace(r) { "<strong>${it.groupValues[1]}</strong>" }
        // href source is escaped text (quotes are &quot;) and the scheme is pinned — no attribute escape.
        r = Regex("""\[([^\]]+)\]\((https?://[^)\s]+)\)""").replace(r) { "<a href=\"${it.groupValues[2]}\">${it.groupValues[1]}</a>" }
        return r
    }
}
