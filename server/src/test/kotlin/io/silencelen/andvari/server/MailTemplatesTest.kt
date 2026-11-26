package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Every template's content against design §11.2 (content rules) and §11.3 (subjects and essentials). */
class MailTemplatesTest {
    private val accountId = "0123456789abcdef0123456789abcdef"
    private val at = 1_800_000_000_000L
    /** A device the server added five days before the mail's time, by the server's own words for it ([MailDevices.words]). */
    private fun before(platform: String) = MailDevices.words(MailDevice(platform, "Pixel <9>", "password", at - 5 * Clock.DAY_MS, isNew = false))

    private val vars = mapOf(
        "code" to "042137", "device" to MailDevices.words(MailDevice("android", "Pixel <9>", "password", at, isNew = true)),
        "how" to "linked from ${before("linux")}", "why" to "Your account was recovered.",
        "old" to "private", "new" to "operator", "removed" to before("ios"), "by" to "the operator", "platform" to "android",
        "reason" to "abuse", "disabledSince" to "2027-01-01 00:00 UTC",
    )

    private val contact = "help@family.example"

    private fun render(t: String, account: String? = accountId) = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example", contact, Mail.Ctx(account, at, vars))

    private val subjects = mapOf(
        "signup_code" to "Your andvari sign-up code",
        "signup_existing" to "Someone tried to sign up with your address",
        "new_device" to "A new device was added to your andvari account",
        "password_changed" to "Your andvari master password was changed",
        "two_step_off" to "Two-step sign-in was turned off",
        "recovery_changed" to "Your recovery settings changed",
        "device_removed" to "A device was removed from your account",
        "operator_escrow_read" to "The operator downloaded your recovery copy",
        "recovery_request_code" to "Your andvari account recovery code",
        "recovery_request_open" to "Someone asked the operator to reset your account",
        "recovery_request_cancelled" to "The request to reset your account was cancelled",
        "recovery_request_private" to "About your andvari recovery request",
        "recovery_applied" to "Your master password was reset",
        "account_disabled" to "Your andvari account was disabled",
        "account_enabled" to "Your andvari account was re-enabled",
        "account_deleted" to "Your andvari account was deleted",
        "account_deleted_by_operator" to "Your andvari account was deleted by the operator",
        "require_link_cleared" to "New-device protection was turned off",
    )

    @Test
    fun everyTemplate_hasItsSubject_theInstance_theTime_andOnlyItsHelpLink() {
        assertEquals(subjects.keys, MailTemplates.ALL)
        for ((t, subject) in subjects) {
            val m = render(t)
            assertEquals(subject, m.subject, t)
            assertTrue(m.text.contains("Home (https://vault.example)"), "$t names the instance and origin")
            if (t != "signup_code" && t != "recovery_request_code") assertTrue(m.text.contains("2027-01-15 08:00 UTC"), "$t says when, in UTC: ${m.text}")
            val links = Regex("https?://[^\\s<]+").findAll(m.text).map { it.value }.filter { it != "https://vault.example" && !it.startsWith("https://vault.example)") }.toList()
            val page = MailTemplates.HELP_PAGE[t]
            if (page == null) assertEquals(emptyList(), links, "$t carries no link") else assertEquals(listOf("https://andvaripass.com/help/$page/"), links, t)
            // A mail about an assisted recovery carries none, nor does the sign-up code mail, which goes out before any
            // account exists; every other mail carries it.
            if (t in noId || t == "signup_code") assertFalse(accountId in m.text || "account ID" in m.text, "$t carries no account ID")
            else assertTrue(m.text.contains("Your account ID: $accountId"), "$t carries the account ID")
        }
        assertEquals(noId, MailTemplates.ABOUT_A_REQUEST)
        // The notices of the reset an assisted request ends in carry none; the same notices after a kit recovery keep it.
        for (t in listOf("recovery_applied", "two_step_off", "require_link_cleared")) {
            val assisted = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example", contact, Mail.Ctx(accountId, at, vars + ("how" to MailTemplates.HOW_ASSISTED)))
            assertFalse(accountId in assisted.text || "account ID" in assisted.text, "$t: ${assisted.text}")
            val kit = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example", contact, Mail.Ctx(accountId, at, vars + ("how" to "recovered")))
            assertTrue("Your account ID: $accountId" in kit.text, "$t: ${kit.text}")
        }
    }

    /** The templates that never carry the account ID, whoever sends them (spec 03 §14.5). */
    private val noId = setOf("recovery_request_code", "recovery_request_open", "recovery_request_cancelled", "recovery_request_private", "operator_escrow_read")

    /**
     * The code mail of a recovery request carries its mailbox value (spec 03 §18.1) in the body, on a line of its own under
     * the paragraph for the person who did not ask ([MailTemplates.MAILBOX_VALUE_PARAGRAPH], named by its constant, so
     * that this holds before and after the paragraph gets its words); the subject never carries it, and no other mail does.
     */
    @Test
    fun theRecoveryCodeMail_carriesItsMailboxValue_underItsParagraph_inTheBodyOnly() {
        val value = "ABCD EFGH JKLM NPQR"
        val ctx = Mail.Ctx(null, at, vars + ("mailboxValue" to value))
        val m = MailTemplates.render("recovery_request_code", "me@example.com", "Home", "https://vault.example", contact, ctx)
        val lines = m.text.lines()
        val p = lines.indexOf(MailTemplates.MAILBOX_VALUE_PARAGRAPH)
        assertTrue(p >= 0, m.text)
        assertEquals("    $value", lines.drop(p + 1).first { it.isNotBlank() })
        assertTrue(lines.indexOfFirst { "042137" in it } in 0 until p, "the code comes first")
        // The paragraph tells the person who did not ask to keep the value: nothing in the mail tells them to ignore it.
        assertFalse("ignore this email" in m.text, m.text)
        assertTrue(lines.indexOfFirst { "Nothing happens without this code." in it } in 0 until p, m.text)
        println(m.text)
        assertFalse(m.subject.contains(value))
        assertTrue(MailTemplates.escape(value) in m.html)
        for (t in subjects.keys - "recovery_request_code") {
            val other = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example", contact, ctx)
            assertFalse(other.text.contains(value) || other.text.contains(MailTemplates.MAILBOX_VALUE_PARAGRAPH), t)
        }
    }

    @Test
    fun codes_areInTheBodyOnly_withTheirExpiryAndTheIgnoreLine() {
        for (t in listOf("signup_code", "recovery_request_code")) {
            val m = render(t, account = null)
            assertFalse(m.subject.contains("042137"), t)
            assertTrue(m.text.contains("042137") && m.text.contains("expires in 15 minutes"), t)
            assertTrue(m.text.contains("Nothing happens without this code. If you didn't ask for it, ignore this email."), t)
        }
        // No other template carries a six-digit code.
        for (t in subjects.keys - setOf("signup_code", "recovery_request_code")) assertFalse(Regex("\\b\\d{6}\\b").containsMatchIn(render(t).text.replace(accountId, "")), t)
    }

    @Test
    fun notices_sayWhatToDo_andNameTheDevice_asPlainText() {
        for (t in listOf("new_device", "password_changed", "two_step_off", "recovery_changed", "device_removed", "recovery_request_open", "require_link_cleared")) {
            if (t in setOf("recovery_request_open", "require_link_cleared")) continue
            assertTrue(render(t).text.contains("If this wasn't you"), t)
        }
        val named = "\"Pixel 9\" ${MailDevices.NAMED_ITSELF}"
        assertTrue("Device: Android (as the device reported it), $named" in render("new_device").text.lines(), render("new_device").text)
        assertTrue("How: linked from the Linux app added on 2027-01-10 08:00 UTC, $named" in render("new_device").text.lines(), render("new_device").text)
        assertTrue("Removed: the iPhone or iPad app added on 2027-01-10 08:00 UTC, $named" in render("device_removed").text.lines() && render("device_removed").text.contains("By: the operator"))
        assertTrue(render("recovery_changed").text.contains("from private to operator"))
        assertTrue("Device: Android (as the request reported it)" in render("recovery_request_open").text.lines())
        assertTrue(render("recovery_request_open").text.contains("It waits 7 days"))
        assertTrue(render("account_disabled").text.contains("Reason: abuse"))
        assertTrue(render("account_deleted_by_operator").text.contains("disabled since 2027-01-01 00:00 UTC"))
        assertTrue(render("recovery_request_private").text.contains("This account has no operator recovery. Use your recovery kit."))
    }

    /**
     * What a reader of each part reads, as one run of words: the plain text without its subject's underline and the
     * footer's `--`, its help address without the scheme the HTML part's link text leaves out; the HTML part's body without
     * its tags, its entities read.
     */
    private fun wordsOfText(text: String): String = text.lines().filterNot { l -> l == "--" || (l.isNotEmpty() && l.all { it == '=' }) }
        .joinToString(" ").replace("Help: https://", "Help: ").split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")

    private fun wordsOfHtml(html: String): String = html.substringAfter("<body").substringAfter('>').replace(Regex("<[^>]*>"), " ")
        .replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&")
        .split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")

    /**
     * For all 18 templates, with and without the account ID and the mailbox value: both parts say the same sentences in the
     * same order; the HTML part has no image, no remote content and exactly the one link of its help page, whose shown text
     * is the address without its scheme, while the plain text has the whole address; the HTML is the approved shell.
     */
    @Test
    fun bothParts_sayTheSameSentencesInTheSameOrder_andTheOnlyLinkIsTheHelpPage() {
        val ctxs = listOf(Mail.Ctx(accountId, at, vars), Mail.Ctx(null, at, vars), Mail.Ctx(accountId, at, vars + ("mailboxValue" to "ABCD EFGH JKLM NPQR")))
        for (t in subjects.keys) for (ctx in ctxs) {
            val m = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example", contact, ctx)
            assertEquals(wordsOfText(m.text), wordsOfHtml(m.html), t)
            assertFalse(m.html.contains("<img") || m.html.contains("src=") || m.html.contains("url("), t)
            assertTrue(m.html.startsWith(MailShell.SHELL.substringBefore("{{subject}}")), t)
            val links = Regex("<a href=\"([^\"]*)\"[^>]*>([^<]*)</a>").findAll(m.html).map { it.groupValues[1] to it.groupValues[2] }.toList()
            val page = MailTemplates.HELP_PAGE[t]
            if (page == null) {
                assertEquals(emptyList(), links, t)
                assertFalse(m.text.lines().any { it.startsWith("Help:") }, t)
            } else {
                assertEquals(listOf("https://andvaripass.com/help/$page/" to "andvaripass.com/help/$page/"), links, t)
                assertEquals(listOf("Help: https://andvaripass.com/help/$page/"), m.text.lines().filter { it.startsWith("Help:") }, t)
            }
            assertEquals(links.size, Regex("<a ").findAll(m.html).count(), t)
        }
        // A value with markup in it (any caller's value, the server's own words included) is escaped text in the HTML part.
        val markup = MailTemplates.render("new_device", "me@example.com", "Home", "https://vault.example", contact, Mail.Ctx(accountId, at, vars + ("device" to "Pixel <9> & \"x\"")))
        assertFalse(markup.html.contains("Pixel <9>"))
        assertTrue(markup.html.contains("Pixel &lt;9&gt; &amp; &quot;x&quot;"))
        // The device's own name, which the server holds as "Pixel <9>", stands in both parts only in the form a mail shows
        // ("Pixel 9", in quotation marks), and never in a subject.
        for (t in subjects.keys) {
            val m = render(t)
            assertFalse("Pixel <9>" in m.text || "Pixel &lt;9&gt;" in m.html || "Pixel" in m.subject, t)
            assertEquals(m.text.lines().count { "\"Pixel 9\"" in it }, Regex("&quot;Pixel 9&quot;").findAll(m.html).count(), t)
        }
        // Every template is given a device among its values, so a mail without a row about a device that printed it would
        // show "Pixel": no such mail holds it in either part, and in a mail with such a row it stands in that row alone.
        // A device's words are given as `how` only to the new-device mail, as the server's callers do (the other mails
        // that read `how` are given the server's own phrase for a recovery there).
        val deviceRows = Regex("(?:Device|Removed|By|How):&nbsp;</td><td[^>]*>[^<]*</td>")
        for (t in subjects.keys) {
            val m = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example", contact, Mail.Ctx(accountId, at, if (t == "new_device") vars else vars - "how"))
            if (t !in DEVICE_TEMPLATES) assertFalse("Pixel" in m.text || "Pixel" in m.html, t)
            for (line in m.text.lines().filter { "Pixel" in it }) {
                assertTrue(listOf("Device: ", "Removed: ", "By: ", "How: ").any { line.startsWith(it) }, "$t: $line")
            }
            assertEquals(Regex("Pixel").findAll(m.html).count(), deviceRows.findAll(m.html).sumOf { r -> Regex("Pixel").findAll(r.value).count() }, t)
        }
    }

    /** A slot the shell names and no value fills is an error, never an empty line; so is a section with no value. */
    @Test
    fun aMissingSlotValue_isAnError_neverAnEmptyLine() {
        val all = mapOf<String, Any>("a" to "x", "list" to listOf("1", "2"), "flag" to false)
        assertEquals("x|1;2;|", MailShell.fill("{{a}}|{{#list}}{{.}};{{/list}}|{{#flag}}no{{/flag}}", all))
        for (t in listOf("{{b}}", "{{#none}}x{{/none}}", "{{.}}", "{{#list}}{{c}}{{/list}}")) {
            assertFailsWith<IllegalStateException>(t) { MailShell.fill(t, all) }
        }
        val missingHost = mapOf<String, Any>("subject" to "s")
        assertFailsWith<IllegalStateException> { MailShell.fill(MailShell.SHELL, missingHost) }
        // A value with markup in a slot is text.
        assertEquals("&lt;b&gt;x&lt;/b&gt; &amp; &quot;y&quot; &#39;z&#39;", MailShell.fill("{{a}}", mapOf("a" to "<b>x</b> & \"y\" 'z'")))
    }

    /** What [MailTemplates.oneLine] does with each class of character, and that it leaves ordinary text as it is. */
    @Test
    fun oneLine_makesEveryValueOneLineInItsOwnOrder() {
        for (br in listOf("\r", "\n", "\r\n", "\u000B", "\u000C", "\u0085", "\u2028", "\u2029", "\t", "\n\n\r\n")) {
            assertEquals("Pixel 9 Help: x", MailTemplates.oneLine("Pixel 9${br}Help: x"), br.map { it.code }.toString())
        }
        assertEquals("Help: x", MailTemplates.oneLine("\nHelp: x"))
        for (c in listOf(0x00, 0x07, 0x1B, 0x7F, 0x80, 0x9B, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x061C, 0x200B, 0xFEFF, 0xAD)) {
            assertEquals("ab", MailTemplates.oneLine("a${c.toChar()}b"), "U+%04X".format(c))
        }
        assertEquals("a�b", MailTemplates.oneLine("a\uD800b"))
        for (plain in listOf("Jordan's Pixel (Android)", "Família “Casa” — 7 items", "日本語のメモ", "emoji 🔑 key", "<b>x</b> & y", "")) {
            assertEquals(plain, MailTemplates.oneLine(plain))
        }
    }

    /** The instance's origin and its contact pass the same function as every other value, in both parts. */
    @Test
    fun theOriginAndTheContact_areOneLineInBothParts() {
        for (ch in listOf("\n", "\u2028", "\u0000", "\u202E")) {
            for (t in subjects.keys) {
                val m = MailTemplates.render(t, "me@example.com", "Home", "https://vault.example${ch}Help: x", "help${ch}Forged: y", Mail.Ctx(accountId, at, vars))
                assertFalse(m.text.any { it != '\n' && (it.code < 0x20 || it.code in 0x2028..0x2029 || it.code in 0x202A..0x202E) }, "$t ${ch.map { it.code }}")
                assertFalse(m.html.any { it != '\n' && (it.code < 0x20 || it.code in 0x2028..0x2029 || it.code in 0x202A..0x202E) }, "$t ${ch.map { it.code }}")
                assertFalse(m.text.lines().any { it.startsWith("Help: x") || it.startsWith("Forged:") }, "$t: ${m.text}")
            }
        }
    }

    private companion object {
        /** The templates that have a row about a device ("Device", "Removed", "By" or the "How" of a link) with these values. */
        val DEVICE_TEMPLATES = setOf("new_device", "password_changed", "two_step_off", "recovery_changed", "device_removed", "recovery_request_cancelled", "recovery_applied")
    }
}
