package io.silencelen.andvari.server

/**
 * The HTML part of every mail: the shell of the design the product's owner approved on 21 November 2026, as it is, and the
 * one way it is filled ([fill]). The shell holds no value; every changing value goes into a named slot:
 *
 * - `{{name}}`: that value, escaped with [MailTemplates.escape];
 * - `{{.}}`: the current item of a list, escaped;
 * - `{{#name}}…{{/name}}`: once per item of a list, once for a map or `true`, not at all for an empty list or `false`.
 *   No section holds a section of its own name.
 *
 * A slot whose value is missing is an error, never an empty string: every value and every section the shell names must be
 * given (a section that is not drawn is given as an empty list or `false`). Values are given per template by
 * [MailTemplates.render], never read back out of a rendered line.
 */
internal object MailShell {
    /** The approved shell, character for character. Its only fixed words are `andvari`, `Help:` and the footer's sentence. */
    const val SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="supported-color-schemes" content="light dark">
<title>{{subject}}</title><style>
@media (prefers-color-scheme: dark) {
  .a-page { background:#14120E !important; }
  .a-card { background:#1E1B15 !important; border-color:#38311F !important; }
  .a-ink { color:#EDE4D0 !important; }
  .a-dim { color:#A79C85 !important; }
  .a-gold, .a-gold a { color:#D0A94A !important; }
  .a-code { background:#262119 !important; border-color:#4A3F28 !important; color:#E8C66A !important; }
  .a-rule { border-color:#38311F !important; }
}</style></head>
<body class="a-page" style="margin:0;padding:0;background:#F4EFE4;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="a-page" style="background:#F4EFE4;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;">
<tr><td style="padding:0 4px 12px;">
<span class="a-ink" style="font-family:Georgia,'Times New Roman',Times,serif;font-size:26px;font-weight:bold;color:#2C2517;letter-spacing:0.3px;">andvari</span>
<span class="a-dim" style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;color:#6B6047;">&nbsp;·&nbsp;{{host}}</span>
</td></tr>
<tr><td class="a-card" style="background:#FBF8F1;border:1px solid #E0D8C5;border-radius:12px;padding:24px 22px 20px;">
<h1 class="a-ink" style="margin:0 0 14px;font-family:Georgia,'Times New Roman',Times,serif;font-size:22px;line-height:1.25;font-weight:bold;color:#2C2517;">{{subject}}</h1>
{{#message}}<p class="a-ink" style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55;font-size:16px;color:#2C2517;">{{.}}</p>
{{/message}}{{#code}}<div class="a-code" style="margin:6px 0 16px;padding:14px 16px;border:1px solid #C9BFA2;border-radius:10px;background:#F1EADB;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:30px;letter-spacing:4px;color:#2C2517;font-weight:bold;">{{.}}</div>
{{/code}}{{#code_lines}}<p class="a-dim" style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55;font-size:14px;color:#6B6047;">{{.}}</p>
{{/code_lines}}{{#mailbox}}<p class="a-ink" style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55;font-size:16px;color:#2C2517;">{{paragraph}}</p>
<div class="a-code" style="margin:6px 0 16px;padding:14px 16px;border:1px solid #C9BFA2;border-radius:10px;background:#F1EADB;text-align:center;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:20px;letter-spacing:2px;color:#2C2517;font-weight:bold;">{{value}}</div>
{{/mailbox}}{{#facts}}<table role="presentation" cellpadding="0" cellspacing="0" class="a-rule" style="width:100%;margin:4px 0 16px;border-top:1px solid #E0D8C5;border-bottom:1px solid #E0D8C5;padding:6px 0;">{{#rows}}<tr><td class="a-dim" style="padding:5px 14px 5px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:13px;color:#6B6047;white-space:nowrap;vertical-align:top;">{{label}}:&nbsp;</td>{{#plain}}<td class="a-ink" style="padding:5px 0;color:#2C2517;word-break:break-all;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;">{{value}}</td>{{/plain}}{{#time}}<td class="a-ink" style="padding:5px 0;color:#2C2517;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:14px;">{{value}}</td>{{/time}}{{#id}}<td class="a-ink" style="padding:5px 0;color:#2C2517;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace;font-size:13px;">{{value}}</td>{{/id}}</tr>{{/rows}}</table>
{{/facts}}{{#todo}}<p class="a-ink" style="margin:0 0 14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55;font-size:16px;color:#2C2517;font-weight:600;">{{.}}</p>
{{/todo}}{{#help}}<p class="a-gold" style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:15px;color:#7D5E14;">Help: <a href="{{href}}" style="color:#7D5E14;text-decoration:underline;">{{shown}}</a></p>
{{/help}}</td></tr>
<tr><td style="padding:14px 6px 0;">
<p class="a-dim" style="margin:0 0 6px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.5;color:#6B6047;">{{instance_name}}&nbsp;·&nbsp;{{origin}}</p>
<p class="a-dim" style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:12px;line-height:1.5;color:#6B6047;">Our emails never contain a password, a recovery kit or a link that signs you in, and never ask for one.</p>
</td></tr>
</table></td></tr></table></body></html>
"""

    /** The footer's sentence, the same in the plain-text part. */
    const val FOOTER = "Our emails never contain a password, a recovery kit or a link that signs you in, and never ask for one."

    /** [template] with its slots filled from [values]: strings, booleans, lists of strings or of maps, and maps. */
    fun fill(template: String, values: Map<String, Any>): String = StringBuilder().also { fill(template, listOf(values), null, it) }.toString()

    private fun fill(t: String, scopes: List<Map<String, Any>>, item: String?, out: StringBuilder) {
        var i = 0
        while (true) {
            val open = t.indexOf("{{", i)
            if (open < 0) { out.append(t, i, t.length); return }
            out.append(t, i, open)
            val close = t.indexOf("}}", open)
            check(close > open) { "a slot is not closed" }
            val tag = t.substring(open + 2, close)
            i = close + 2
            when {
                tag == "." -> out.append(MailTemplates.escape(item ?: error("{{.}} outside a list of values")))
                tag.startsWith("/") -> error("a section closes that did not open: $tag")
                tag.startsWith("#") -> {
                    val name = tag.substring(1)
                    val end = "{{/$name}}"
                    val e = t.indexOf(end, i)
                    check(e >= 0) { "the section $name is not closed" }
                    val inner = t.substring(i, e)
                    i = e + end.length
                    when (val v = lookup(name, scopes)) {
                        is Boolean -> if (v) fill(inner, scopes, item, out)
                        is Map<*, *> -> fill(inner, scopes + scope(v, name), item, out)
                        is List<*> -> for (x in v) when (x) {
                            is String -> fill(inner, scopes, x, out)
                            is Map<*, *> -> fill(inner, scopes + scope(x, name), null, out)
                            else -> error("an item of the section $name is neither text nor a map")
                        }
                        else -> error("the section $name is not a list, a map or a flag")
                    }
                }
                else -> out.append(MailTemplates.escape(lookup(tag, scopes) as? String ?: error("the slot $tag is not text")))
            }
        }
    }

    /** The value of [name] in the innermost scope that has it; a slot no scope has is an error. */
    private fun lookup(name: String, scopes: List<Map<String, Any>>): Any =
        scopes.asReversed().firstNotNullOfOrNull { it[name] } ?: error("no value for the slot $name")

    @Suppress("UNCHECKED_CAST")
    private fun scope(m: Map<*, *>, name: String): Map<String, Any> {
        check(m.keys.all { it is String } && m.values.all { it != null }) { "the section $name holds a key that is not text or a missing value" }
        return m as Map<String, Any>
    }
}
