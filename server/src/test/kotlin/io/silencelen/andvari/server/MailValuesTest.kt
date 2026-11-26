package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.InstanceKind
import java.io.File
import java.nio.file.Files
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * What enters a mail, through the server's own outbox: a mail queued by [Mail.enqueue] on an instance, read back as it
 * would be sent (nothing is sent: the transport given here is never called). A mail is where text someone else chose (a
 * device's name, an instance's name) is put in front of a person under the product's name, so every value is treated as
 * hostile: it is one line in both parts, it cannot forge a line of its own, it cannot reorder what is drawn around it, and
 * in the HTML part it is text, never markup. The contact a mail names is the instance's own.
 */
class MailValuesTest {
    private val accountId = "0123456789abcdef0123456789abcdef"

    /** What the outbox holds for one mail. */
    private class Queued(val subject: String, val text: String, val html: String)

    /** An instance's settings: the address its mails are sent from is the SMTP sender or the Graph sender, when set. */
    private fun config(
        kind: String = InstanceKind.PRIVATE, origin: String = "https://vault.example.org", smtpFrom: String? = null, graphSender: String? = null,
    ): Config {
        val dir = Files.createTempDirectory("andvari-mail").toFile()
        return Config(
            dbPath = File(dir, "andvari.db").path, blobDir = File(dir, "blobs").path, canonicalOrigin = origin, forceHsts = true,
            instanceKind = kind, enumSecret = ByteArray(32) { 7 },
            smtpHost = smtpFrom?.let { "smtp.example.org" }, smtpUser = smtpFrom?.let { "user" }, smtpPass = smtpFrom?.let { "pass" }, smtpFrom = smtpFrom,
            graphTenantId = graphSender?.let { "tenant" }, graphClientId = graphSender?.let { "client" }, graphClientSecret = graphSender?.let { "secret" },
            graphSender = graphSender,
        )
    }

    /** An instance's mail with its own database, named [name], its clock at [at]. */
    private class Instance(val config: Config, val name: String = "Home", at: Long = 1_800_000_000_000L) {
        private val db = Db(config.dbPath, durable = false)
        private val clock = Clock { at }
        private val mail = Mail(config, db, clock, Audit(clock), MailTransport { error("nothing is sent from these tests") }) { name }
        private var n = 0

        /** Queues [template] (to a recipient of its own unless [to] is given, so no cap of a recipient is reached) and reads it back. */
        fun queue(template: String, ctx: Mail.Ctx, to: String? = null): Queued {
            val recipient = to ?: "member${n++}@example.org"
            assertTrue(db.tx { c -> mail.enqueue(c, template, recipient, ctx) }, "$template was queued")
            return db.read { c ->
                c.queryOne("SELECT subject,text,html FROM mail_outbox ORDER BY id DESC LIMIT 1") { Queued(it.getString(1), it.getString(2), it.getString(3)) }!!
            }
        }
    }

    /** The values a notice can carry, each as the server's callers pass it. */
    private val values = mapOf(
        "code" to "042137", "mailboxValue" to "ABCD EFGH JKLM NPQR", "device" to "Pixel 9 (android)", "how" to "linked from laptop (linux)",
        "why" to "Your account was recovered, which turns two-step sign-in off.", "old" to "private", "new" to "operator",
        "removed" to "old phone (ios)", "by" to "you, from Pixel 9 (android)", "platform" to "android", "reason" to "abuse",
        "disabledSince" to "2027-01-01 00:00 UTC",
    )

    /** Each class of character that must never reach a mail as it is: line breaks, the other controls, direction controls. */
    private val lineBreaks = listOf("\r", "\n", "\r\n", "\u2028", "\u2029", "\u000B", "\u000C", "\u0085")
    private val otherControls = listOf("\u0000", "\u0007", "\t", "\u001B", "\u007F", "\u0080", "\u009B")
    private val directionControls = listOf("\u200E", "\u200F", "\u202A", "\u202B", "\u202C", "\u202D", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069", "\u061C")
    private val classes = mapOf("line break" to lineBreaks, "control character" to otherControls, "direction control" to directionControls)

    /** Whether [ch] may stand in a part of a mail: the mail's own line ends ('\n') only, nothing else of the three classes. */
    private fun refused(ch: Char): Boolean =
        (ch.code <= 0x1F && ch != '\n') || ch.code in 0x7F..0x9F || ch.code in 0x2028..0x2029 ||
            ch.code in 0x200E..0x200F || ch.code in 0x202A..0x202E || ch.code in 0x2066..0x2069 || ch.code == 0x61C

    /** The lines of text a reader sees in an HTML part: its body without the tags, the entities read, line by line, trimmed. */
    private fun shownLines(html: String): List<String> =
        html.substringAfter("<body").substringAfter('>').replace(Regex("<[^>]*>"), "\n")
            .replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&")
            .lines().map { it.trim() }.filter { it.isNotEmpty() }

    /**
     * A device name that holds a line break followed by a line of its own ("Help:" with another address): until now the
     * plain-text part showed that line as a line of the mail, under the product's name, and the HTML part (the text in a
     * preformatted block) showed it the same way. Now the name stays on its own line in both parts, and the only "Help:"
     * line is the mail's own.
     */
    @Test fun aDeviceNameWithALineBreakCannotForgeAHelpLineInEitherPart() {
        val home = Instance(config(smtpFrom = "help@family.example"))
        for (br in lineBreaks) {
            val m = home.queue("new_device", Mail.Ctx(accountId, 1_800_000_000_000L, mapOf("device" to "Pixel 9${br}Help: https://evil.example/help/compromised/ (android)")))
            val help = m.text.lines().filter { it.startsWith("Help:") }
            assertEquals(listOf("Help: https://andvaripass.com/help/compromised/"), help, "plain text, ${br.codes()}: ${m.text}")
            val shownHelp = shownLines(m.html).filter { it.startsWith("Help:") }
            assertEquals(1, shownHelp.size, "HTML, ${br.codes()}: $shownHelp")
            assertFalse("evil.example" in shownHelp.single(), "HTML, ${br.codes()}: $shownHelp")
            assertTrue(m.text.lines().any { it.startsWith("Device: Pixel 9") && "evil.example" in it }, "the name stays on its own line: ${m.text}")
        }
    }

    /**
     * Every value, in every template, with a character of each class in it (a line break, another control character, a
     * direction control): no character of the three classes reaches either part (the plain text keeps only its own line
     * ends), neither part has a line more than the same mail with the value without that character, and no line of
     * either part begins with the text after the character. The values: every one a notice can carry, the recipient's
     * address, the account ID, the instance's name and the address its mails are sent from.
     */
    @Test fun noValueOfAnyTemplateBringsALineBreakAControlOrADirectionControlIntoEitherPart() {
        for ((kind, chars) in classes) for (ch in chars) {
            fun hostile(key: String, sep: String) = "$key-start${sep}Forged: $key-end"
            val forged = Instance(config(smtpFrom = "help${ch}@family.example"), name = hostile("instance", ch))
            val plain = Instance(config(smtpFrom = "help@family.example"), name = hostile("instance", ""))
            for (template in MailTemplates.ALL) {
                val ctxOf = { sep: String -> Mail.Ctx(hostile("id", sep), 1_800_000_000_000L, values.mapValues { (k, _) -> hostile(k, sep) }) }
                val m = forged.queue(template, ctxOf(ch), to = "x${ch}y-${template}-${ch.codes()}@example.org")
                val base = plain.queue(template, ctxOf(""), to = "xy-${template}-${ch.codes()}@example.org")
                val what = "$template, $kind ${ch.codes()}"
                assertFalse(m.text.any(::refused), "$what: the plain text holds ${m.text.filter(::refused).codes()}")
                assertFalse(m.html.any(::refused), "$what: the HTML part holds ${m.html.filter(::refused).codes()}")
                assertFalse(m.subject.any(::refused), "$what: the subject")
                assertEquals(base.text.lines().size, m.text.lines().size, "$what: no line more in the plain text: ${m.text}")
                assertEquals(shownLines(base.html).size, shownLines(m.html).size, "$what: no line more in the HTML part: ${shownLines(m.html)}")
                assertFalse(m.text.lines().any { it.trimStart().startsWith("Forged:") }, "$what: a line of the value's own in the plain text: ${m.text}")
                assertFalse(shownLines(m.html).any { it.startsWith("Forged:") }, "$what: a line of the value's own in the HTML part")
            }
        }
    }

    /**
     * The contact the mails name (the operator read an account's recovery copy; a recovery was applied; an account was
     * disabled, enabled, deleted by the operator) is the instance's own: the address its mails are sent from, which is
     * also where a reply goes. A private instance never names the product's own support address, which until now every
     * one of these mails named; the public instance names it because its mails are sent from it.
     */
    @Test fun theContactAMailNamesIsTheAddressTheInstancesMailsAreSentFrom() {
        val contactMails = mapOf(
            "operator_escrow_read" to emptyMap(), "recovery_applied" to mapOf("device" to "Pixel 9 (android)"), "account_disabled" to mapOf("reason" to "abuse"),
            "account_enabled" to emptyMap(), "account_deleted_by_operator" to mapOf("disabledSince" to "2027-01-01 00:00 UTC"),
        )
        val ours = "support@andvaripass.com"
        val viaSmtp = Instance(config(smtpFrom = "help@family.example"))
        val viaGraph = Instance(config(graphSender = "family@example.net"))
        val named = Instance(config(smtpFrom = "Our family <help@family.example>"))
        val public = Instance(config(kind = InstanceKind.PUBLIC, origin = "https://vault.andvaripass.com", graphSender = ours), name = "andvari")
        for ((t, v) in contactMails) {
            val ctx = Mail.Ctx(accountId, 1_800_000_000_000L, v)
            for ((instance, address) in listOf(viaSmtp to "help@family.example", viaGraph to "family@example.net", named to "help@family.example")) {
                val m = instance.queue(t, ctx)
                assertFalse(ours in m.text || ours in m.html, "$t on a private instance names the product's address: ${m.text}")
                assertTrue(address in m.text && address in m.html, "$t names the address the instance's mails are sent from: ${m.text}")
                assertFalse("Our family" in m.text, "$t names the address alone: ${m.text}")
            }
            val p = public.queue(t, ctx)
            assertTrue(ours in p.text && ours in p.html, "$t on the public instance: ${p.text}")
        }
    }

    /** The order of the lines in both parts, as the approved design sets them: in `account_deleted` the gone sentence comes before the facts. */
    @Test fun bothPartsFollowTheApprovedOrderOfLines() {
        val home = Instance(config(smtpFrom = "help@family.example"))
        val m = home.queue("account_deleted", Mail.Ctx(accountId, 1_800_000_000_000L))
        val lines = m.text.lines()
        val gone = lines.indexOf("Its vaults and everything stored only in them are gone.")
        val time = lines.indexOfFirst { it.startsWith("Time: ") }
        assertTrue(gone in 0 until time, m.text)
        val shown = shownLines(m.html)
        assertTrue(shown.indexOf("Its vaults and everything stored only in them are gone.") in 0 until shown.indexOfFirst { it.startsWith("Time:") }, shown.toString())
    }

    /** The sign-up code mail is sent before any account exists: it carries no account ID, whatever the caller passes. */
    @Test fun theSignUpCodeMailCarriesNoAccountId() {
        val home = Instance(config(smtpFrom = "help@family.example"))
        val m = home.queue("signup_code", Mail.Ctx(accountId, 1_800_000_000_000L, mapOf("code" to "042137")))
        assertFalse(accountId in m.text || "account ID" in m.text || accountId in m.html, m.text)
    }

    /**
     * The HTML part is built from the approved design's shell: its own head, the help page's address as the one link
     * (shown without its scheme; the plain text has the whole address), the product's name and the instance's host above
     * the card, and the footer's sentence in both parts.
     */
    @Test fun theHtmlPartIsTheApprovedShellWithTheHelpLinkAndTheFooterInBothParts() {
        val home = Instance(config(smtpFrom = "help@family.example"))
        val m = home.queue("new_device", Mail.Ctx(accountId, 1_800_000_000_000L, mapOf("device" to "Pixel 9 (android)", "how" to "signed in with your master password")))
        assertTrue(m.html.startsWith("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"), m.html.take(200))
        assertEquals(1, Regex("<a ").findAll(m.html).count(), m.html)
        assertTrue("<a href=\"https://andvaripass.com/help/compromised/\" style=\"color:#7D5E14;text-decoration:underline;\">andvaripass.com/help/compromised/</a>" in m.html, m.html)
        assertTrue("Help: https://andvaripass.com/help/compromised/" in m.text.lines(), m.text)
        assertEquals("andvari · vault.example.org", m.text.lines().first(), m.text)
        val footer = "Our emails never contain a password, a recovery kit or a link that signs you in, and never ask for one."
        assertEquals(listOf("--", "Home · https://vault.example.org", footer), m.text.trimEnd().lines().takeLast(3), m.text)
        assertTrue(footer in shownLines(m.html), m.html)
    }

    /** A value with markup in it comes out as text in the HTML part, escaped by the server's own escaping, and as it is in the plain text. */
    @Test fun aValueWithMarkupComesOutAsText() {
        val home = Instance(config(smtpFrom = "help@family.example"))
        val device = "<b>Pixel</b> & \"9\" 'x' <a href=\"https://evil.example/\">help</a> (android)"
        val m = home.queue("new_device", Mail.Ctx(accountId, 1_800_000_000_000L, mapOf("device" to device)))
        assertTrue("Device: $device" in m.text.lines(), m.text)
        assertFalse("<b>" in m.html || "evil.example/\">" in m.html, m.html)
        assertTrue(MailTemplates.escape(device) in m.html, m.html)
    }

    /**
     * All 18 mails with the approved design's example data, on the public instance (whose mails are sent from the product's
     * support address), written as one `.txt` and one `.html` file per template into the folder `MAIL_RENDER_DIR` names, or
     * into a new folder of its own, for a comparison by eye with the design's samples. The new-device mail's plain text is
     * the approved sample's, character for character, but for its rows that speak of a device, which hold the server's
     * own words for it and, since 22 November 2026, the device's own name in quotation marks with its mark ([MailDevices]).
     */
    @Test fun theEighteenMailsWithTheDesignsExampleData() {
        val at = Instant.parse("2026-11-21T21:14:00Z").toEpochMilli()
        val public = Instance(
            config(kind = InstanceKind.PUBLIC, origin = "https://vault.andvaripass.com", graphSender = "support@andvaripass.com"), name = "andvari", at = at,
        )
        val id = "9f3a21c788b04d12e5a7c0b9d4f2a618"
        // The design's example devices as the server holds them: Jordan's Pixel, an Android app added on 2 October, and the
        // office laptop, a Windows app added on 14 September; a new device is one the event itself added. A row about a
        // device shows its name after the kind of app ([MailDevices]).
        fun device(platform: String, name: String, day: String, isNew: Boolean = false) =
            MailDevices.words(MailDevice(platform, name, "password", Instant.parse("${day}T10:00:00Z").toEpochMilli(), isNew))
        val pixel = device("android", "Jordan's Pixel", "2026-10-02")
        val laptop = device("windows", "the office laptop", "2026-09-14")
        val added = device("android", "Jordan's Pixel", "2026-11-21", isNew = true)
        val example: Map<String, Pair<String?, Map<String, String>>> = mapOf(
            "signup_code" to (null to mapOf("code" to "482 917")),
            "signup_existing" to (id to emptyMap()),
            "new_device" to (id to mapOf("device" to added, "how" to "linked from $laptop")),
            "password_changed" to (id to mapOf("device" to pixel)),
            "two_step_off" to (id to mapOf("device" to pixel)),
            "recovery_changed" to (id to mapOf("device" to pixel, "old" to "your kit only", "new" to "your kit and the operator", "kit" to "A new recovery kit was made.")),
            "device_removed" to (id to mapOf("removed" to laptop, "by" to "you, from $pixel")),
            "operator_escrow_read" to (id to emptyMap()),
            "recovery_request_code" to (null to mapOf("code" to "305 166", "mailboxValue" to "MBX-7Q2K-91ZD")),
            "recovery_request_open" to (id to mapOf("platform" to "android")),
            "recovery_request_cancelled" to (id to mapOf("device" to pixel)),
            "recovery_request_private" to (id to emptyMap()),
            "recovery_applied" to (id to mapOf("device" to added)),
            "account_disabled" to (id to mapOf("reason" to "request")),
            "account_enabled" to (id to emptyMap()),
            "account_deleted" to (id to emptyMap()),
            "account_deleted_by_operator" to (id to mapOf("disabledSince" to "2026-10-30 09:02 UTC")),
            "require_link_cleared" to (id to emptyMap()),
        )
        assertEquals(MailTemplates.ALL, example.keys)
        val out = System.getenv("MAIL_RENDER_DIR")?.let { File(it).apply { mkdirs() } } ?: Files.createTempDirectory("andvari-mails").toFile()
        val rendered = example.mapValues { (t, e) -> public.queue(t, Mail.Ctx(e.first, at, e.second), to = "jordan@example.com") }
        for ((t, m) in rendered) {
            File(out, "$t.txt").writeText(m.text)
            File(out, "$t.html").writeText(m.html)
        }
        println("The 18 mails are in ${out.path}")
        val approved = listOf(
            "andvari · vault.andvaripass.com", "", "A new device was added to your andvari account", "==============================================", "",
            "A new device was added to your account on andvari (https://vault.andvaripass.com).", "",
            "Device: Android (as the device reported it), \"Jordan's Pixel\" ${MailDevices.NAMED_ITSELF}",
            "How: linked from the Windows app added on 2026-09-14 10:00 UTC, \"the office laptop\" ${MailDevices.NAMED_ITSELF}", "Time: 2026-11-21 21:14 UTC",
            "Your account ID: 9f3a21c788b04d12e5a7c0b9d4f2a618", "",
            "If this wasn't you, open andvari on a device you trust → Settings → Your devices, and change your master password. If no device is left, use your recovery kit.",
            "", "Help: https://andvaripass.com/help/compromised/", "", "--", "andvari · https://vault.andvaripass.com",
            "Our emails never contain a password, a recovery kit or a link that signs you in, and never ask for one.", "",
        ).joinToString("\n")
        assertEquals(approved, rendered.getValue("new_device").text)
    }

    private fun String.codes(): String = map { "U+%04X".format(it.code) }.joinToString(" ")
}
