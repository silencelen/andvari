package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.Parameters
import io.ktor.http.contentType
import io.ktor.http.formUrlEncode
import io.ktor.http.isSuccess
import jakarta.mail.Authenticator
import jakarta.mail.Message
import jakarta.mail.MessagingException
import jakarta.mail.PasswordAuthentication
import jakarta.mail.SendFailedException
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeBodyPart
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.sql.Connection
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Properties

/** The outcome of one send attempt. A permanent failure is dropped at once (spec 03 §14.5). */
sealed class SendResult {
    object Ok : SendResult()
    class Transient(val errorClass: String) : SendResult()
    class Permanent(val errorClass: String) : SendResult()
}

/** One rendered message. */
class OutgoingMail(val template: String, val to: String, val subject: String, val text: String, val html: String)

/** A mail transport (spec 03 §14.5): Microsoft Graph app-only, SMTP, or the test sink. */
fun interface MailTransport {
    fun send(m: OutgoingMail): SendResult
}

/**
 * `ANDVARI_MAIL_SINK` (test mode only): each message is written as one JSON file `{template, to, subject,
 * text}` instead of being sent.
 */
class SinkTransport(private val dir: File) : MailTransport {
    private var n = 0L
    override fun send(m: OutgoingMail): SendResult {
        dir.mkdirs()
        val body = buildJsonObject {
            put("template", m.template); put("to", m.to); put("subject", m.subject); put("text", m.text)
        }.toString()
        synchronized(this) {
            n++
            File(dir, "%d-%06d-%s.json".format(System.currentTimeMillis(), n, m.template)).writeText(body)
        }
        return SendResult.Ok
    }
}

/**
 * The message as MIME (spec 03 §14.5 "Format"): `multipart/alternative` with the plain text first and the
 * HTML alternative of the same content second, so a reader that shows one body shows the text. Both the SMTP
 * and the Graph transports send exactly this.
 */
fun mimeOf(m: OutgoingMail, from: InternetAddress, session: Session = Session.getInstance(Properties())): MimeMessage {
    val msg = MimeMessage(session)
    msg.setFrom(from)
    msg.setRecipient(Message.RecipientType.TO, InternetAddress(m.to, true))
    msg.setSubject(m.subject, "utf-8")
    val text = MimeBodyPart().apply { setText(m.text, "utf-8") }
    val html = MimeBodyPart().apply { setContent(m.html, "text/html; charset=utf-8") }
    msg.setContent(MimeMultipart("alternative").apply { addBodyPart(text); addBodyPart(html) })
    msg.saveChanges()
    return msg
}

/**
 * Microsoft Graph app-only `sendMail` (design §11.1). Failures are logged by HTTP status only.
 *
 * The message goes through Graph's MIME send (`POST /users/{sender}/sendMail` with `Content-Type: text/plain`
 * and the base64 of a MIME message, [mimeOf]), so it carries the plain text and its HTML alternative exactly
 * as the SMTP transport sends them; Graph's JSON form takes only one body, which would make it HTML only.
 * The sender's display name is "andvari".
 */
class GraphTransport(
    private val http: HttpClient, private val tenantId: String, private val clientId: String,
    private val clientSecret: String, private val sender: String,
) : MailTransport {
    override fun send(m: OutgoingMail): SendResult = runBlocking {
        try {
            withTimeout(20_000) {
                val tok = http.post("https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token") {
                    contentType(ContentType.Application.FormUrlEncoded)
                    setBody(Parameters.build {
                        append("client_id", clientId); append("client_secret", clientSecret)
                        append("scope", "https://graph.microsoft.com/.default"); append("grant_type", "client_credentials")
                    }.formUrlEncode())
                }
                if (!tok.status.isSuccess()) return@withTimeout classify(tok.status.value, "token")
                val token = io.silencelen.andvari.core.model.wire.WireJson.json.parseToJsonElement(tok.bodyAsText())
                    .jsonObject["access_token"]?.jsonPrimitive?.content ?: return@withTimeout SendResult.Transient("token_shape")
                val mime = try {
                    java.io.ByteArrayOutputStream().also { mimeOf(m, InternetAddress(sender, "andvari", "utf-8")).writeTo(it) }.toByteArray()
                } catch (e: jakarta.mail.internet.AddressException) {
                    return@withTimeout SendResult.Permanent("graph_address")
                }
                val resp = http.post("https://graph.microsoft.com/v1.0/users/$sender/sendMail") {
                    header(HttpHeaders.Authorization, "Bearer $token")
                    setBody(io.ktor.http.content.TextContent(java.util.Base64.getEncoder().encodeToString(mime), ContentType.Text.Plain))
                }
                if (resp.status.isSuccess()) SendResult.Ok else classify(resp.status.value, "send")
            }
        } catch (e: Exception) {
            SendResult.Transient(e::class.simpleName ?: "io")
        }
    }

    /** An HTTP 4xx other than 429 is permanent (spec 03 §14.5). */
    private fun classify(status: Int, where: String): SendResult =
        if (status in 400..499 && status != 429) SendResult.Permanent("http_$status") else SendResult.Transient("${where}_http_$status")
}

/** SMTP submission with STARTTLS required and the server identity checked. */
class SmtpTransport(
    private val host: String, private val port: Int, private val user: String, private val pass: String, private val from: String,
) : MailTransport {
    override fun send(m: OutgoingMail): SendResult = try {
        val props = Properties().apply {
            put("mail.smtp.host", host); put("mail.smtp.port", port.toString()); put("mail.smtp.auth", "true")
            put("mail.smtp.starttls.enable", "true"); put("mail.smtp.starttls.required", "true")
            put("mail.smtp.ssl.checkserveridentity", "true")
            put("mail.smtp.connectiontimeout", "10000"); put("mail.smtp.timeout", "15000"); put("mail.smtp.writetimeout", "15000")
            put("mail.debug", "false")
        }
        val session = Session.getInstance(props, object : Authenticator() {
            override fun getPasswordAuthentication() = PasswordAuthentication(user, pass)
        })
        Transport.send(mimeOf(m, InternetAddress(from), session))
        SendResult.Ok
    } catch (e: SendFailedException) {
        SendResult.Permanent("smtp_rejected")
    } catch (e: jakarta.mail.internet.AddressException) {
        SendResult.Permanent("smtp_address")
    } catch (e: MessagingException) {
        val code = Regex("^(\\d{3})").find(e.message ?: "")?.value?.toIntOrNull()
        if (code != null && code in 500..599) SendResult.Permanent("smtp_$code") else SendResult.Transient("smtp")
    } catch (e: Exception) {
        SendResult.Transient("smtp_io")
    }
}

/**
 * The durable mail outbox (spec 03 §14.5, design §11.4).
 *
 * Every message is written to `mail_outbox` **inside the transaction that caused it** ([enqueue]); the
 * sender worker ([drain]) retries with backoff (1 min, 5 min, 30 min, 2 h, 12 h) and gives up after
 * 24 hours, or at once on a permanent failure, auditing `email_failed` with the template name only.
 * Rows are deleted the moment they are sent; a code message is deleted unsent when its code expires.
 * Per recipient: 5 code messages and 20 security notices a day, and the unsolicited notices on a separate
 * cap ([CapClass]); anything over is dropped and audited.
 *
 * Nothing here logs a recipient, a body, a code or a link.
 */
class Mail(
    private val config: Config,
    private val db: Db,
    private val clock: Clock,
    private val audit: Audit,
    private val transport: MailTransport?,
    private val instanceName: (Connection) -> String,
) {
    private val caps = RateLimiter { clock.now() }
    @Volatile var failedTotal: Long = 0; private set

    /** The contact this instance's mails name ([contactOf]). */
    private val contact = contactOf(config)

    /**
     * Common values a notice carries (spec 03 §14.5): the account ID (left out of the mails about a recovery request,
     * [MailTemplates.carriesAccountId]) and, where it applies, the device.
     */
    class Ctx(val accountId: String?, val at: Long, val vars: Map<String, String> = emptyMap())

    /**
     * The per-recipient caps (spec 03 §14.5: 5 code messages and 20 notices a day), each class on its own
     * counter so one can never spend another's budget. "A day" is a window of 24 hours that starts at the first mail the
     * window counts ([RateLimiter]), per recipient and class, not a calendar day; [perWindow] is the cap in one window.
     * The notices anyone can trigger without proving anything — `signup_existing` from `POST /signup/start`, `recovery_request_private` from
     * `POST /recovery/requests` — form a third class with its own cap of [UNSOLICITED_PER_DAY], so a stranger
     * flooding those routes can never use up the 20 a day of the security notices (`new_device`,
     * `password_changed`, `recovery_applied`, `two_step_off`, ...).
     */
    enum class CapClass(val perWindow: Int) {
        CODE(5), UNSOLICITED(UNSOLICITED_PER_DAY), SECURITY(20),

        /**
         * The code mails of recovery requests taken past the address's five because they named a mailbox value (spec 03
         * §18.1): a cap of their own, as the requests have a ceiling of their own, so that the person's own request is not
         * dropped here by the five code mails someone else's requests spent. Within one window of each cap an address
         * receives at most five code mails of plain requests and five of requests taken by a value; the two windows start
         * independently, so across their edges more than ten can fall inside 24 hours (spec 03 §18.1 states the bound).
         *
         * Its cap is DERIVED from the requests' ceiling ([Assisted.MAILBOX_BUCKET]), never a figure of its own: a request
         * taken by a value uses the value up before its mail is queued, so a cap below the ceiling would spend values with no
         * mail sent. Both count one per request in windows of [windowMs] started at the same clock reading (the recovery
         * request route passes one reading to both); `RecoveryRequestGiveBackTest` holds the two together.
         */
        MAILBOX_CODE(Assisted.MAILBOX_BUCKET.limit),
        ;

        /** Every class counts per window of 24 hours that starts at the first mail it counts. */
        val windowMs: Long get() = Clock.DAY_MS
    }

    fun capClassOf(template: String, isCode: Boolean): CapClass = when {
        isCode -> CapClass.CODE
        template in UNSOLICITED_TEMPLATES -> CapClass.UNSOLICITED
        else -> CapClass.SECURITY
    }

    /**
     * Queue [template] to [to] inside [c]. [codeExpiresAt] makes it a code message (deleted unsent at
     * expiry). Returns false when the per-recipient cap of its class ([CapClass]) dropped it. [capClass] names the class
     * when the template's own is not the one ([CapClass.MAILBOX_CODE]). [at] is the reading of the clock the mail is
     * counted and queued at, when the caller already drew another budget for the same event at that reading (a recovery
     * request's address and its code mail: one reading for both, so their windows start and lapse together).
     */
    fun enqueue(c: Connection, template: String, to: String, ctx: Ctx, codeExpiresAt: Long? = null, capClass: CapClass? = null, at: Long? = null): Boolean {
        val cls = capClass ?: capClassOf(template, codeExpiresAt != null)
        val key = "mailcap_${cls.name.lowercase()}:" + sha256Hex(to)
        val t = at ?: clock.now()
        val drawn = caps.draw(key, cls.perWindow, cls.windowMs, t)
        val admitted = drawn.admitted ?: run {
            audit.on(c, "email_dropped", null, null, null, "template=$template")
            return false
        }
        // A mail whose transaction rolls back is never queued, so it gives its place under the cap back.
        onRollback(c) { caps.refund(admitted) }
        val m = MailTemplates.render(template, to, instanceName(c), config.canonicalOrigin, contact, ctx)
        c.exec(
            "INSERT INTO mail_outbox(template,recipient,subject,text,html,createdAt,attempts,nextAttemptAt,discardAt) VALUES(?,?,?,?,?,?,0,?,?)",
            template, to, m.subject, m.text, m.html, t, t, codeExpiresAt ?: (t + Clock.DAY_MS),
        )
        if (transport == null) {
            System.err.println("[andvari] mail: no transport configured; '$template' notice not sent (the action itself happened)")
        }
        return true
    }

    /**
     * Stalled (spec 03 §14.5): the outbox is non-empty and nothing has been sent successfully for 10 minutes.
     * A row already past its `discardAt` does not count: it will never be sent (the next drain deletes it,
     * audited `email_failed`), so it is not waiting for the transport, and counting it would keep sign-up and
     * recovery requests refused after the transport recovered, or forever on a server whose sender never runs.
     */
    fun stalled(c: Connection): Boolean {
        val oldest = c.queryOne("SELECT MIN(createdAt) FROM mail_outbox WHERE discardAt>?", clock.now()) { it.longOrNull("MIN(createdAt)") } ?: return false
        val lastOk = c.queryOne("SELECT value FROM meta WHERE key='mailLastSentAt'") { it.getString(1).toLong() } ?: 0L
        return clock.now() - maxOf(lastOk, oldest) >= STALL_MS
    }

    fun oldestQueuedAt(c: Connection): Long? = c.queryOne("SELECT MIN(createdAt) FROM mail_outbox") { it.longOrNull("MIN(createdAt)") }

    /** One pass of the sender worker. Returns the number of messages sent. */
    fun drain(): Int {
        val nowMs = clock.now()
        // Expired rows first, with or without a transport (without one the outbox was never
        // purged, so a deleted account's address stayed for good): code messages past their code, everything
        // past 24 hours.
        db.tx { c ->
            c.queryAll("SELECT id,template FROM mail_outbox WHERE discardAt<=?", nowMs) { it.getLong(1) to it.getString(2) }.forEach { (id, tpl) ->
                c.exec("DELETE FROM mail_outbox WHERE id=?", id)
                audit.on(c, "email_failed", null, null, null, "template=$tpl reason=expired")
                failedTotal++
            }
        }
        val tr = transport ?: return 0
        val due = db.read { c ->
            c.queryAll("SELECT id,template,recipient,subject,text,html,attempts FROM mail_outbox WHERE nextAttemptAt<=? ORDER BY id LIMIT 50", nowMs) {
                Triple(it.getLong(1), it.getInt(7), OutgoingMail(it.getString(2), it.getString(3), it.getString(4), it.getString(5), it.getString(6)))
            }
        }
        var sent = 0
        for ((id, attempts, m) in due) {
            val r = runCatching { tr.send(m) }.getOrElse { SendResult.Transient("exception") }
            db.tx { c ->
                when (r) {
                    is SendResult.Ok -> {
                        c.exec("DELETE FROM mail_outbox WHERE id=?", id)
                        c.exec("INSERT INTO meta(key,value) VALUES('mailLastSentAt',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", clock.now().toString())
                        audit.on(c, "email_sent", null, null, null, "template=${m.template}")
                        sent++
                    }
                    is SendResult.Permanent -> {
                        c.exec("DELETE FROM mail_outbox WHERE id=?", id)
                        audit.on(c, "email_failed", null, null, null, "template=${m.template} class=${r.errorClass}")
                        failedTotal++
                    }
                    is SendResult.Transient -> {
                        val next = BACKOFF_MS.getOrElse(attempts) { BACKOFF_MS.last() }
                        c.exec("UPDATE mail_outbox SET attempts=attempts+1, nextAttemptAt=?, lastErrorClass=? WHERE id=?", clock.now() + next, r.errorClass, id)
                    }
                }
            }
        }
        return sent
    }

    companion object {
        const val STALL_MS = 10 * 60_000L

        /** Notices an unauthenticated request can trigger (see [CapClass]). */
        val UNSOLICITED_TEMPLATES = setOf("signup_existing", "recovery_request_private")
        const val UNSOLICITED_PER_DAY = 5
        val BACKOFF_MS = longArrayOf(60_000L, 5 * 60_000L, 30 * 60_000L, 2 * 3_600_000L, 12 * 3_600_000L)

        fun transportFor(config: Config, http: () -> HttpClient): MailTransport? = when {
            config.testMode && config.mailSinkDir != null -> SinkTransport(File(config.mailSinkDir))
            config.graphConfigured -> GraphTransport(http(), config.graphTenantId!!, config.graphClientId!!, config.graphClientSecret!!, config.graphSender!!)
            config.smtpConfigured -> SmtpTransport(config.smtpHost!!, config.smtpPort, config.smtpUser!!, config.smtpPass!!, config.smtpFrom!!)
            else -> null
        }

        /** The 32-hex short identity fingerprint of an X25519 `identityPub` (base64url): the account ID. */
        fun accountId(identityPubB64: String): String = runCatching {
            sha256Hex(io.silencelen.andvari.core.crypto.Bytes.fromB64(identityPubB64)).take(32)
        }.getOrDefault("unknown")

        fun utc(ms: Long): String = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(ms))

        /**
         * The contact a mail names where it tells the person whom to ask (the operator read the recovery copy, a recovery
         * was applied, the account was disabled, enabled or deleted by the operator): the address this instance's mails are
         * sent from (the Graph sender, else the SMTP sender), which is also where a reply goes (design §11.2: no Reply-To).
         * Only the address, never a display name the setting carries, and only an address of the `emailNorm` form. The
         * product's own support address appears only where it is the instance's sender, which is the public instance's
         * configuration. An instance with no such address (no transport, or the test sink) names [NO_CONTACT]; no address
         * is ever made up.
         */
        fun contactOf(config: Config): String {
            val sender = when {
                config.graphConfigured -> config.graphSender
                config.smtpConfigured -> config.smtpFrom
                else -> null
            }
            val address = sender?.let { runCatching { InternetAddress(it, true).address }.getOrNull() }?.let { Grammar.emailNorm(it) }
            return address ?: NO_CONTACT
        }

        /** What a mail names as the contact on an instance whose mails are sent from no address. */
        const val NO_CONTACT = "this instance's operator"
    }
}

/**
 * What the server holds of one device, as [MailDevices.words] reads it: the kind of app the device said it is
 * (`devices.platform`, checked against the closed list when the row was made, not again when it is read), the name it gave
 * itself (`devices.name`), how it joined (`devices.how`), and when the server added it (`devices.createdAt`). [isNew] is
 * true for the device the event itself added (a sign-in, a link's pickup, a recovery), whose day is the mail's own time.
 */
class MailDevice(val platform: String?, val name: String?, val how: String?, val addedAt: Long, val isNew: Boolean)

/**
 * What a mail says of a device: what the server itself knows of it, and the name the device gave itself (decided on 22
 * November 2026). That name is chosen by whoever signs in on the device, claims a device link or applies a recovery, and
 * the notices that speak of a device go to the account's person to warn of exactly such an event; so a mail shows it only
 * in the narrow form of [name]: in quotation marks, cut to forty characters, marked as the device's own words, and made of
 * nothing but letters and digits of any alphabet, spaces, apostrophes and hyphens. It can then hold no sentence's
 * punctuation, no address a mail program turns into a link, and no line that looks like the mail's own.
 *
 * [words] is the one place that decides what a mail says of a device, for every row that speaks of one ("Device",
 * "Removed", "By", and the "linked from" of "How"): the kind of app, as one of the server's own fixed words ([kind]: every
 * value the platform column can hold maps to fixed words, anything else to one fallback), for a device that was there
 * before the event the day and time the server added it, in UTC, and then the device's own name ([name]). How the device
 * joined is carried and not read.
 */
object MailDevices {
    /** One kind of app: [word] where a row names the kind alone, [app] where it names the device by its kind. */
    class Kind internal constructor(val word: String, val app: String)

    /** Every value of the closed platform list ([io.silencelen.andvari.core.model.wire.WirePlatform]). */
    private val KINDS: Map<String, Kind> = mapOf(
        io.silencelen.andvari.core.model.wire.WirePlatform.ANDROID to Kind("Android", "the Android app"),
        io.silencelen.andvari.core.model.wire.WirePlatform.IOS to Kind("iPhone or iPad", "the iPhone or iPad app"),
        io.silencelen.andvari.core.model.wire.WirePlatform.WINDOWS to Kind("Windows", "the Windows app"),
        io.silencelen.andvari.core.model.wire.WirePlatform.MACOS to Kind("Mac", "the Mac app"),
        io.silencelen.andvari.core.model.wire.WirePlatform.LINUX to Kind("Linux", "the Linux app"),
        io.silencelen.andvari.core.model.wire.WirePlatform.WEB to Kind("Web browser", "the web app"),
        io.silencelen.andvari.core.model.wire.WirePlatform.CLI to Kind("Command line", "the command-line tool"),
        io.silencelen.andvari.core.model.wire.WirePlatform.EXTENSION to Kind("Browser extension", "the browser extension"),
    )

    /** The words for a platform value the list does not hold (a row of an older database or a restored file, say). */
    val UNKNOWN = Kind("Unknown", "an app of unknown kind")

    /** The server's words for the kind of app [platform] names: exact values only, never the stored text itself. */
    fun kind(platform: String?): Kind = KINDS[platform] ?: UNKNOWN

    /** The mark after a device's own name shown whole. Both marks are in this one place, so their words change here alone. */
    const val NAMED_ITSELF = "(as the device named itself)"

    /** The mark after a device's own name that was cut to [NAME_MAX]. */
    const val NAME_CUT = "(the start of the name the device gave itself)"

    /** The most characters of a device's own name a mail shows: a letter or a digit with its marks counts as one. */
    const val NAME_MAX = 40

    /** The most combining marks a mail keeps after one letter or digit of a device's own name. */
    const val NAME_MARKS = 3

    /** Every quotation mark and apostrophe-like character, each of which a name shows as the plain apostrophe U+0027. */
    private val QUOTES: Set<Int> =
        (listOf(0x22, 0x60, 0xAB, 0xB4, 0xBB, 0x2039, 0x203A, 0xFF02, 0xFF07) + (0x2B9..0x2BC) + (0x2018..0x201F) + (0x300C..0x300F)).toSet()

    /** The hyphens a name shows as the hyphen-minus U+002D. */
    private val HYPHENS = setOf(0x2010, 0x2011)

    private val LETTERS = setOf(
        Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER, Character.MODIFIER_LETTER, Character.OTHER_LETTER,
    )

    private fun isNameMark(cp: Int): Boolean = Character.getType(cp).toByte().let { it == Character.NON_SPACING_MARK || it == Character.COMBINING_SPACING_MARK }

    /**
     * The letters that are drawn like a full stop, a colon, a slash or an apostrophe, which a device's own name shows as a
     * space (decided on 22 November 2026), so that a name cannot draw an address or a row of the mail's own; with the
     * Unicode standard's name for each range. Only [name] reads this table: no other value of a mail passes it. Letters
     * that are drawn alike but belong to ordinary words (U+30CE, U+4E3F) or are drawn like an apostrophe, which a name may
     * hold anyway (U+07F4, U+07F5, U+A78C), are not in it.
     */
    internal val LOOK_ALIKES: List<MailTemplates.Range> = listOf(
        MailTemplates.Range(0x01C0, 0x01C3, "LATIN LETTER DENTAL CLICK..LATIN LETTER RETROFLEX CLICK", MailTemplates.Becomes.SPACE),
        MailTemplates.Range(0x02D0, 0x02D1, "MODIFIER LETTER TRIANGULAR COLON..MODIFIER LETTER HALF TRIANGULAR COLON", MailTemplates.Becomes.SPACE),
        MailTemplates.Range(0x02EE, 0x02EE, "MODIFIER LETTER DOUBLE APOSTROPHE", MailTemplates.Becomes.SPACE),
        MailTemplates.Range(0x141E, 0x1428, "CANADIAN SYLLABICS GLOTTAL STOP..CANADIAN SYLLABICS FINAL SHORT HORIZONTAL STROKE", MailTemplates.Becomes.SPACE),
        MailTemplates.Range(0x18DF, 0x18DF, "CANADIAN SYLLABICS FINAL RAISED DOT", MailTemplates.Becomes.SPACE),
        MailTemplates.Range(0xA4F8, 0xA4FD, "LISU LETTER TONE MYA TI..LISU LETTER TONE MYA JEU", MailTemplates.Becomes.SPACE),
        MailTemplates.Range(0xA78F, 0xA78F, "LATIN LETTER SINOLOGICAL DOT", MailTemplates.Becomes.SPACE),
    )

    /** A mark that draws nothing at all: a combining mark that [MailTemplates.UNLISTED_KINDS] lists as removed. */
    private fun drawsNothing(cp: Int): Boolean =
        isNameMark(cp) && MailTemplates.UNLISTED_KINDS.any { cp in it.first..it.last && it.becomes == MailTemplates.Becomes.NOTHING }

    /**
     * A device's own name as a mail shows it (decided on 22 November 2026): in quotation marks and followed by its mark,
     * [NAMED_ITSELF] or, when it was cut, [NAME_CUT]; null for no name, and then the row is the row without one. In this
     * order:
     * 0. The marks that draw nothing at all ([drawsNothing]: the variation selectors, the Mongolian free variation
     *    selectors, U+034F, U+17B4 and U+17B5) are taken out of the stored name. They stand inside a word, and the
     *    characters on both sides of one were drawn together already; every later step sees a name without them.
     * 1. The name is brought to its composed form (NFC), and to no other: a letter never becomes another letter.
     * 2. Every quotation mark and apostrophe-like character ([QUOTES]) becomes the apostrophe U+0027, and U+2010 and
     *    U+2011 become the hyphen-minus U+002D.
     * 3. Kept are the letters (general category L), the decimal digits (Nd), the space U+0020, the apostrophe and the
     *    hyphen-minus; a combining mark (Mn, Mc) only directly after a kept letter, digit or mark, and at most
     *    [NAME_MARKS] after one letter or digit (further ones are dropped). Every other character becomes a space: controls,
     *    breaks and tabs, every other kind of space, every format and invisible character, every symbol, punctuation mark
     *    and emoji, every digit that is not a decimal digit, every dash but the hyphens, a lone surrogate, a mark anywhere
     *    else. So does every other character of [MailTemplates.UNLISTED_KINDS]: those that draw a blank (the Hangul
     *    fillers among them) and the format characters. So do the 26 letters of [LOOK_ALIKES], which are drawn like
     *    punctuation; no composed form makes or unmakes one of them.
     * 4. A run of spaces becomes one space, and spaces at both ends go.
     * 5. At most [NAME_MAX] characters are kept, a letter or digit with its marks counting as one (a pair of surrogates is
     *    one character); the cut never splits a letter from its marks, and a space it leaves at the end goes.
     * 6. What is left to show must hold a letter or a digit: a name of only apostrophes, hyphens and spaces is no name.
     *
     * The result can hold no working web address, no working mail address, no line of its own and no markup; a run of
     * digits, a telephone number say, stays. Letters of other scripts that are drawn somewhat like punctuation and are not
     * in [LOOK_ALIKES] stay letters.
     * The HTML part escapes it like every value ([MailTemplates.escape]): the apostrophe there is `&#39;`.
     */
    fun name(stored: String?): String? {
        if (stored == null) return null
        val visible = StringBuilder(stored.length)
        stored.codePoints().forEach { if (!drawsNothing(it)) visible.appendCodePoint(it) }
        val composed = java.text.Normalizer.normalize(visible, java.text.Normalizer.Form.NFC)
        val kept = StringBuilder(composed.length)
        // How many marks were kept after the letter or digit before; -1 when the character before is no kept letter, digit or mark.
        var marks = -1
        var i = 0
        while (i < composed.length) {
            val raw = composed.codePointAt(i)
            i += Character.charCount(raw)
            val cp = when (raw) { in QUOTES -> 0x27; in HYPHENS -> 0x2D; else -> raw }
            val type = Character.getType(cp).toByte()
            when {
                MailTemplates.UNLISTED_KINDS.any { cp in it.first..it.last } -> { kept.append(' '); marks = -1 }
                LOOK_ALIKES.any { cp in it.first..it.last } -> { kept.append(' '); marks = -1 }
                cp == 0x20 || cp == 0x27 || cp == 0x2D -> { kept.appendCodePoint(cp); marks = -1 }
                type in LETTERS || type == Character.DECIMAL_DIGIT_NUMBER -> { kept.appendCodePoint(cp); marks = 0 }
                isNameMark(cp) && marks >= 0 -> if (marks < NAME_MARKS) { kept.appendCodePoint(cp); marks++ }
                else -> { kept.append(' '); marks = -1 }
            }
        }
        val line = kept.split(' ').filter { it.isNotEmpty() }.joinToString(" ")
        if (line.isEmpty()) return null
        var units = 0
        var end = line.length
        var j = 0
        while (j < line.length) {
            val cp = line.codePointAt(j)
            if (!isNameMark(cp) && ++units > NAME_MAX) { end = j; break }
            j += Character.charCount(cp)
        }
        val cut = end < line.length
        val shown = line.substring(0, end).trimEnd(' ')
        // A name with no letter and no digit (only apostrophes, hyphens and spaces), as it would be shown, is no name.
        if (shown.none { it != ' ' && it != '\'' && it != '-' }) return null
        return "\"$shown\" ${if (cut) NAME_CUT else NAMED_ITSELF}"
    }

    /**
     * The words for [d] in a mail. A device the event itself added is named by its kind, marked as its own report
     * ("Android (as the device reported it)"); a device that was there before, by its kind and the day and time it was
     * added, in UTC ("the Android app added on 2026-10-02 10:00 UTC"). Its own name, where [name] shows one, follows
     * after a comma ("Android (as the device reported it), "Jordan's Pixel" (as the device named itself)").
     */
    fun words(d: MailDevice): String {
        val k = kind(d.platform)
        val server = if (d.isNew) "${k.word} (as the device reported it)" else "${k.app} added on ${Mail.utc(d.addedAt)}"
        return name(d.name)?.let { "$server, $it" } ?: server
    }

    /**
     * [words] for the device [deviceId], from its row; null when the server holds no such row. [ownName] false leaves
     * the stored name out: the caller knows that the name on the row is the server's own fallback, not the device's.
     */
    fun of(c: Connection, deviceId: String, isNew: Boolean = false, ownName: Boolean = true): String? =
        c.queryOne("SELECT platform,name,how,createdAt FROM devices WHERE deviceId=?", deviceId) {
            MailDevice(it.getString(1), if (ownName) it.getString(2) else null, it.getString(3), it.getLong(4), isNew)
        }?.let(::words)
}

/**
 * The email templates (spec 03 §14.5, design §11.3). Content rules (design §11.2): no password, recovery
 * data, link secret, token or session id; no vault, item, attachment or contact name; links only to the
 * static help pages under `https://andvaripass.com/help/`, each template to the page that fits it; the
 * only code ever sent is the 6-digit sign-up or recovery-request code, in the body, and beside the recovery-request code
 * its mailbox value (spec 03 §18.1), which opens nothing but one more request for the same address. Every notice names
 * the instance (name and origin), what happened, when (UTC), the device where relevant, and the account
 * ID.
 *
 * The layout is the design the product's owner approved on 21 November 2026, with today's sentences and labels kept word
 * for word: both parts are drawn from the same slots, in the same order ([Slots]); the HTML part is the approved shell
 * ([MailShell]) with every value escaped there by [escape]. A row that speaks of a device holds the server's own words for
 * it and the device's own name in the narrow form [MailDevices.name] gives it ([MailDevices]). Every value (an instance's name, an address, a
 * code, a time, an account ID, the contact, the device words themselves) is treated as text someone else chose: it passes
 * [oneLine] before it enters a template, whatever was checked when it was stored. The only link is the help page's, built
 * from [HELP] and [HELP_PAGE].
 */
object MailTemplates {
    const val HELP = "https://andvaripass.com/help"
    private const val NOTHING_WITHOUT_THE_CODE = "Nothing happens without this code."
    private const val IGNORE = "$NOTHING_WITHOUT_THE_CODE If you didn't ask for it, ignore this email."

    /**
     * The code mail's paragraph above its mailbox value (spec 03 §18.1). Awaiting the owner's words on his wording page
     * ([MAILBOX_VALUE_PARAGRAPH_AWAITING]): until they are approved it is a marked placeholder that says what the
     * paragraph must say. It never stands under a sentence that tells the reader to ignore the mail. A test names it by
     * this constant, never by its text.
     */
    const val MAILBOX_VALUE_PARAGRAPH =
        "⟦Says: someone typed your address to ask the operator for help with an account; if that was not you, you need " +
            "do nothing else, but keep the value below; if you ever ask for help yourself, enter it with your request, under " +
            "the app's line for a value from a mail (the line as the apps word it); it works once, for this address, for " +
            "seven days⟧"

    /** Whether [MAILBOX_VALUE_PARAGRAPH] still awaits the owner's words. */
    const val MAILBOX_VALUE_PARAGRAPH_AWAITING = true

    private const val NEXT_STEP ="If this wasn't you, open andvari on a device you trust → Settings → Your devices, and change your master password. If no device is left, use your recovery kit."

    val ALL = setOf(
        "signup_code", "signup_existing", "new_device", "password_changed", "two_step_off", "recovery_changed",
        "device_removed", "operator_escrow_read", "recovery_request_code", "recovery_request_open",
        "recovery_request_cancelled", "recovery_request_private", "recovery_applied", "account_disabled",
        "account_enabled", "account_deleted", "account_deleted_by_operator", "require_link_cleared",
    )

    /** Which help page each template links to (spec 03 §14.5); templates absent here carry no link. */
    val HELP_PAGE: Map<String, String> = mapOf(
        "new_device" to "compromised", "device_removed" to "compromised", "password_changed" to "compromised",
        "two_step_off" to "compromised", "recovery_changed" to "compromised", "operator_escrow_read" to "compromised",
        "recovery_request_open" to "compromised", "require_link_cleared" to "compromised",
        "signup_existing" to "lost-password", "recovery_request_private" to "lost-password",
        "recovery_applied" to "recovery-kit",
        "account_deleted" to "delete-account", "account_deleted_by_operator" to "delete-account",
    )

    /** `recovery_applied`'s `how` for an operator-assisted commit (spec 03 §18.5). */
    const val HOW_ASSISTED = "with the operator's help"

    /**
     * The mails about an operator-assisted recovery request: its code and every notice about it, and the operator's
     * download of the recovery copy (an operator reads a copy for that one purpose only, so the mail reaches the person
     * in the middle of the very flow).
     */
    val ABOUT_A_REQUEST = setOf(
        "recovery_request_code", "recovery_request_open", "recovery_request_cancelled", "recovery_request_private", "operator_escrow_read",
    )

    /** The notices of a credential reset, which carry no account ID when an assisted commit sends them (`how` = [HOW_ASSISTED]). */
    val OF_A_RESET = setOf("recovery_applied", "two_step_off", "require_link_cleared")

    /**
     * Whether [template] carries the account ID (spec 03 §14.5). No mail the server sends because of an operator-assisted
     * recovery does: the ID is the server's own word, and a person checks it against the
     * operator's answer, so a hostile server that minted an identity for the person's address would be mailing them the
     * very ID that confirms it. That covers the request's code and its notices, the operator's download of the copy
     * ([ABOUT_A_REQUEST]), and the notices of the reset it ends in ([OF_A_RESET] with [HOW_ASSISTED]). Every other mail
     * keeps it, so that a notice older than any request can serve as a source; the same reset notices after a kit
     * recovery keep it too.
     */
    fun carriesAccountId(template: String, vars: Map<String, String>): Boolean =
        template !in ABOUT_A_REQUEST && !(template in OF_A_RESET && vars["how"] == HOW_ASSISTED)

    /** How a fact's value is set: plain text, a time, or the account ID. */
    internal enum class FactKind { PLAIN, TIME, ID }

    /** One row of a mail's facts: `Label: value`. */
    internal class Fact(val label: String, val value: String, val kind: FactKind = FactKind.PLAIN)

    /**
     * One mail's content, slot by slot, in the order both parts draw it (the approved design's order): the statement
     * sentences, the code and the code's own lines, the mailbox value under its paragraph, the facts, what to do, the help
     * page. Built per template from its own values, never by reading a rendered line back.
     */
    internal class Slots(
        val subject: String,
        val message: List<String>,
        val code: String? = null,
        val codeLines: List<String> = emptyList(),
        val mailbox: Pair<String, String>? = null,
        val facts: List<Fact> = emptyList(),
        val todo: List<String> = emptyList(),
    )

    /** What [oneLine] makes of a character of [UNLISTED_KINDS]: a space, or nothing. */
    internal enum class Becomes { SPACE, NOTHING }

    /** One range of [UNLISTED_KINDS], with the Unicode standard's name for it. */
    internal class Range(val first: Int, val last: Int, val name: String, val becomes: Becomes)

    /**
     * The characters whose kind the platform's character tables do not tell, and the one table [oneLine] keeps: the set the
     * Unicode standard lists as ignorable by default (the property Default_Ignorable_Code_Point of DerivedCoreProperties.txt,
     * Unicode 15.0.0, every range of it), and the characters that draw a blank without being spaces (the Hangul fillers,
     * which the same set lists, the braille blank and the object replacement character). The fillers, the braille blank
     * and the object mark become a space; every other range is removed. The first range that holds a character decides.
     */
    internal val UNLISTED_KINDS: List<Range> = listOf(
        Range(0x115F, 0x1160, "HANGUL CHOSEONG FILLER..HANGUL JUNGSEONG FILLER", Becomes.SPACE),
        Range(0x3164, 0x3164, "HANGUL FILLER", Becomes.SPACE),
        Range(0xFFA0, 0xFFA0, "HALFWIDTH HANGUL FILLER", Becomes.SPACE),
        Range(0x2800, 0x2800, "BRAILLE PATTERN BLANK", Becomes.SPACE),
        Range(0xFFFC, 0xFFFC, "OBJECT REPLACEMENT CHARACTER", Becomes.SPACE),
        Range(0x00AD, 0x00AD, "SOFT HYPHEN", Becomes.NOTHING),
        Range(0x034F, 0x034F, "COMBINING GRAPHEME JOINER", Becomes.NOTHING),
        Range(0x061C, 0x061C, "ARABIC LETTER MARK", Becomes.NOTHING),
        Range(0x17B4, 0x17B5, "KHMER VOWEL INHERENT AQ..KHMER VOWEL INHERENT AA", Becomes.NOTHING),
        Range(0x180B, 0x180F, "MONGOLIAN FREE VARIATION SELECTOR ONE..MONGOLIAN FREE VARIATION SELECTOR FOUR (with MONGOLIAN VOWEL SEPARATOR)", Becomes.NOTHING),
        Range(0x200B, 0x200F, "ZERO WIDTH SPACE..RIGHT-TO-LEFT MARK", Becomes.NOTHING),
        Range(0x202A, 0x202E, "LEFT-TO-RIGHT EMBEDDING..RIGHT-TO-LEFT OVERRIDE", Becomes.NOTHING),
        Range(0x2060, 0x206F, "WORD JOINER..NOMINAL DIGIT SHAPES", Becomes.NOTHING),
        Range(0xFE00, 0xFE0F, "VARIATION SELECTOR-1..VARIATION SELECTOR-16", Becomes.NOTHING),
        Range(0xFEFF, 0xFEFF, "ZERO WIDTH NO-BREAK SPACE", Becomes.NOTHING),
        Range(0xFFF0, 0xFFF8, "<reserved-FFF0>..<reserved-FFF8>", Becomes.NOTHING),
        Range(0x1BCA0, 0x1BCA3, "SHORTHAND FORMAT LETTER OVERLAP..SHORTHAND FORMAT UP STEP", Becomes.NOTHING),
        Range(0x1D173, 0x1D17A, "MUSICAL SYMBOL BEGIN BEAM..MUSICAL SYMBOL END PHRASE", Becomes.NOTHING),
        Range(0xE0000, 0xE0FFF, "<reserved-E0000>..<reserved-E0FFF> (LANGUAGE TAG, TAG SPACE..CANCEL TAG, VARIATION SELECTOR-17..VARIATION SELECTOR-256)", Becomes.NOTHING),
    )

    /** The most combining marks [oneLine] keeps in a row. */
    const val MAX_MARKS_IN_A_ROW = 4

    /** Whether the platform's tables say [cp] is a space or a break of some kind (a space separator, white space, a bidi break or space). */
    private fun isSpaceKind(cp: Int): Boolean = Character.isSpaceChar(cp) || Character.isWhitespace(cp) ||
        when (Character.getDirectionality(cp)) {
            Character.DIRECTIONALITY_PARAGRAPH_SEPARATOR, Character.DIRECTIONALITY_SEGMENT_SEPARATOR, Character.DIRECTIONALITY_WHITESPACE -> true
            else -> false
        }

    private fun isMark(cp: Int): Boolean = when (Character.getType(cp).toByte()) {
        Character.NON_SPACING_MARK, Character.ENCLOSING_MARK, Character.COMBINING_SPACING_MARK -> true
        else -> false
    }

    /**
     * The one function every value passes before it enters a mail, whatever was checked when it was stored: the value as
     * one line of plain text that shows what it holds. By kind of character, as the platform's character tables tell it,
     * and for the kinds they do not tell by the one table [UNLISTED_KINDS]:
     * - every space and every break of any kind (a line break, a tab, NEL, U+2028, U+2029, the no-break and the wide
     *   spaces), and every character of the table that draws a blank, becomes a space; a run of them becomes one space and
     *   both ends are trimmed;
     * - every other control character, every format character (the direction marks, embeddings, overrides and isolates,
     *   the joiners, the tags, the byte-order mark and the like) and every character of the table ignorable by default
     *   (the variation selectors among them) is removed;
     * - no more than [MAX_MARKS_IN_A_ROW] combining marks stay in a row;
     * - a lone surrogate becomes U+FFFD.
     * So no value holds a line break of its own, and no run of blanks can push a part of it to the start of a line on the
     * screen; a value long enough to wrap still wraps where the reader's screen wraps it. Letters, digits, punctuation and
     * symbols are kept as they are (look-alike letters too), so a code, an address, an account ID or a time is unchanged,
     * byte for byte. A value of which nothing is left is empty, and [render] shows its row's fallback words. Escaping for
     * the HTML part comes after, in the shell ([MailShell]).
     */
    fun oneLine(raw: String): String {
        val out = StringBuilder(raw.length)
        var marks = 0
        var i = 0
        while (i < raw.length) {
            val ch = raw[i]
            val cp = if (ch.isHighSurrogate() && i + 1 < raw.length && raw[i + 1].isLowSurrogate()) Character.toCodePoint(ch, raw[i + 1]) else ch.code
            i += Character.charCount(cp)
            val listed = UNLISTED_KINDS.firstOrNull { cp in it.first..it.last }?.becomes
            when {
                Character.isSurrogate(ch) && cp == ch.code -> { out.append('�'); marks = 0 }
                listed == Becomes.SPACE || isSpaceKind(cp) -> { if (out.isNotEmpty() && out.last() != ' ') out.append(' '); marks = 0 }
                listed == Becomes.NOTHING -> Unit
                Character.getType(cp).toByte().let { it == Character.CONTROL || it == Character.FORMAT } -> Unit
                isMark(cp) -> if (marks < MAX_MARKS_IN_A_ROW) { out.appendCodePoint(cp); marks++ }
                else -> { out.appendCodePoint(cp); marks = 0 }
            }
        }
        return out.trimEnd(' ').toString()
    }

    /**
     * The mail [template] to [to], from the instance named [instanceName] at [origin], whose contact (the address its
     * mails are sent from, [Mail.contactOf]) is [contact]. Every value passes [oneLine] first; a value of which nothing is
     * left is shown as its row's own fallback words (the template's words for a missing value; "andvari" for the
     * instance's name, as [Instance] names an instance without one; [Mail.NO_CONTACT]; "unknown" for an account ID), never
     * as nothing. The slots are then built per template ([slotsOf]); the plain-text part and the HTML part ([MailShell])
     * are both drawn from the same slots, so they say the same sentences in the same order.
     */
    fun render(template: String, to: String, instanceName: String, origin: String, contact: String, ctx: Mail.Ctx): OutgoingMail {
        require(template in ALL) { "unknown template" }
        val v = ctx.vars.mapValues { oneLine(it.value) }
        val name = oneLine(instanceName).ifEmpty { "andvari" }
        val site = oneLine(origin)
        val address = oneLine(to)
        val reach = oneLine(contact).ifEmpty { Mail.NO_CONTACT }
        val id = ctx.accountId?.let(::oneLine)?.ifEmpty { "unknown" }
        val time = oneLine(Mail.utc(ctx.at))
        val s = slotsOf(template, v, "$name ($site)", address, reach, time)
        // The sign-up code mail goes out before any account exists: it never carries an ID.
        val facts = s.facts + if (template != "signup_code" && carriesAccountId(template, v) && id != null) listOf(Fact("Your account ID", id, FactKind.ID)) else emptyList()
        val help = HELP_PAGE[template]?.let { "$HELP/$it/" }
        val host = site.removePrefix("https://").removePrefix("http://")

        val lines = ArrayList<String>()
        fun para(l: String) { lines += l; lines += "" }
        para("andvari · $host")
        lines += s.subject; para("=".repeat(s.subject.length))
        s.message.forEach(::para)
        s.code?.let { para("    $it") }
        s.codeLines.forEach(::para)
        s.mailbox?.let { (paragraph, value) -> para(paragraph); para("    $value") }
        if (facts.isNotEmpty()) { facts.forEach { lines += "${it.label}: ${it.value}" }; lines += "" }
        s.todo.forEach(::para)
        help?.let { para("Help: $it") }
        lines += "--"; lines += "$name · $site"; lines += MailShell.FOOTER
        val text = lines.joinToString("\n", postfix = "\n")

        val html = MailShell.fill(
            MailShell.SHELL,
            mapOf(
                "subject" to s.subject, "host" to host, "message" to s.message, "code" to listOfNotNull(s.code), "code_lines" to s.codeLines,
                "mailbox" to listOfNotNull(s.mailbox?.let { (paragraph, value) -> mapOf("paragraph" to paragraph, "value" to value) }),
                "facts" to if (facts.isEmpty()) emptyList() else listOf(
                    mapOf(
                        "rows" to facts.map {
                            mapOf("label" to it.label, "value" to it.value, "plain" to (it.kind == FactKind.PLAIN), "time" to (it.kind == FactKind.TIME), "id" to (it.kind == FactKind.ID))
                        },
                    ),
                ),
                "todo" to s.todo, "help" to listOfNotNull(help?.let { mapOf("href" to it, "shown" to it.removePrefix("https://")) }),
                "instance_name" to name, "origin" to site,
            ),
        )
        return OutgoingMail(template, to, s.subject, text, html)
    }

    /**
     * The slots of [template], in the approved design's order, with today's sentences and labels word for word. [v] are
     * the template's values, [inst] is "name (origin)", [to] the recipient, [contact] the instance's contact and [time]
     * the time of the event, every one of them already one line ([oneLine]). A value of [all] of which nothing is left is
     * read as missing, so its row shows the template's own words for a missing value; a device row given an empty value
     * says "unknown".
     */
    private fun slotsOf(template: String, all: Map<String, String>, inst: String, to: String, contact: String, time: String): Slots {
        val v = all.filterValues { it.isNotEmpty() }
        val at = Fact("Time", time, FactKind.TIME)
        val device = if ("device" in all) listOf(Fact("Device", v["device"] ?: "unknown")) else emptyList()
        val questions = Fact("Questions", contact)
        return when (template) {
            "signup_code" -> Slots(
                "Your andvari sign-up code", listOf("Your sign-up code for $inst is:"), code = all.getValue("code").ifEmpty { "?" },
                codeLines = listOf("It expires in 15 minutes.", IGNORE),
            )
            "signup_existing" -> Slots(
                "Someone tried to sign up with your address",
                listOf("You already have an account on $inst. If that was you, sign in instead. Nothing changed."), facts = listOf(at),
            )
            "new_device" -> Slots(
                "A new device was added to your andvari account", listOf("A new device was added to your account on $inst."),
                facts = device + Fact("How", v["how"] ?: "signed in with your master password") + at, todo = listOf(NEXT_STEP),
            )
            "password_changed" -> Slots(
                "Your andvari master password was changed", listOf("The master password of your account on $inst was changed."),
                facts = device + at, todo = listOf(NEXT_STEP),
            )
            // After a recovery the reason stands where the device would: a sentence of the message, and no device row.
            "two_step_off" -> Slots(
                "Two-step sign-in was turned off", listOf("Two-step sign-in was turned off for your account on $inst.") + listOfNotNull(v["why"]),
                facts = (if (v["why"] == null) device else emptyList()) + at, todo = listOf(NEXT_STEP),
            )
            "recovery_changed" -> Slots(
                "Your recovery settings changed",
                listOf("The recovery settings of your account on $inst changed from ${v["old"] ?: "?"} to ${v["new"] ?: "?"}.") + listOfNotNull(v["kit"]),
                facts = device + at, todo = listOf(NEXT_STEP),
            )
            "device_removed" -> Slots(
                "A device was removed from your account", listOf("A device was removed from your account on $inst."),
                facts = listOf(Fact("Removed", v["removed"] ?: "a device"), Fact("By", v["by"] ?: "you"), at), todo = listOf(NEXT_STEP),
            )
            "operator_escrow_read" -> Slots(
                "The operator downloaded your recovery copy", listOf("The operator of $inst downloaded your account's recovery copy."), facts = listOf(at),
                todo = listOf("This is the first step of restoring your account. If you didn't ask for help, contact $contact and consider turning operator recovery off."),
            )
            // With its mailbox value, the mail does not tell the reader to ignore it: the paragraph above the value says what
            // a person who did not ask should do (keep the value), so the code's lines end with "Nothing happens without
            // this code." and the paragraph and the value follow them.
            "recovery_request_code" -> Slots(
                "Your andvari account recovery code", listOf("Your recovery code for $inst is:"), code = all.getValue("code").ifEmpty { "?" },
                codeLines = listOf(
                    "It expires in 15 minutes. The operator can only help after you enter this code.",
                    if (v["mailboxValue"] != null) NOTHING_WITHOUT_THE_CODE else IGNORE,
                ),
                mailbox = v["mailboxValue"]?.let { MAILBOX_VALUE_PARAGRAPH to it },
            )
            "recovery_request_open" -> Slots(
                "Someone asked the operator to reset your account", listOf("Someone asked the operator of $inst to reset your account."),
                facts = listOf(at, Fact("Device", "${MailDevices.kind(v["platform"]).word} (as the request reported it)")),
                todo = listOf("It waits 7 days; any of your signed-in devices can cancel it. If this wasn't you, cancel it and change your email password."),
            )
            "recovery_request_cancelled" -> Slots(
                "The request to reset your account was cancelled", listOf("The request to reset your account on $inst was cancelled."), facts = device + at,
            )
            "recovery_request_private" -> Slots(
                "About your andvari recovery request",
                listOf("Someone asked the operator of $inst to reset your account. This account has no operator recovery. Use your recovery kit."),
                facts = listOf(at),
            )
            "recovery_applied" -> Slots(
                "Your master password was reset",
                listOf("The master password of your account on $inst was reset ${v["how"] ?: "with your recovery kit"}. Every device was signed out."),
                facts = device + at, todo = listOf("If this wasn't you, contact $contact at once."),
            )
            "account_disabled" -> Slots(
                "Your andvari account was disabled", listOf("Your account on $inst was disabled by its operator."),
                facts = listOf(Fact("Reason", v["reason"] ?: "other"), at, questions),
            )
            "account_enabled" -> Slots(
                "Your andvari account was re-enabled", listOf("Your account on $inst was re-enabled by its operator."), facts = listOf(at, questions),
            )
            "account_deleted" -> Slots(
                "Your andvari account was deleted",
                listOf("Your account $to on $inst was deleted.", "Its vaults and everything stored only in them are gone."), facts = listOf(at),
            )
            "account_deleted_by_operator" -> Slots(
                "Your andvari account was deleted by the operator",
                listOf(
                    "Your account $to on $inst was deleted by its operator.", "It had been disabled since ${v["disabledSince"] ?: "?"}.",
                    "Its vaults and everything stored only in them are gone.",
                ),
                facts = listOf(at, questions),
            )
            "require_link_cleared" -> Slots(
                "New-device protection was turned off",
                listOf("You recovered your account on $inst, so andvari turned off 'New devices must be linked'. Turn it on again in Settings if you want it."),
                facts = listOf(at),
            )
            else -> error("unreachable")
        }
    }

    fun escape(s: String): String = buildString(s.length) {
        for (ch in s) when (ch) {
            '<' -> append("&lt;"); '>' -> append("&gt;"); '&' -> append("&amp;"); '"' -> append("&quot;"); '\'' -> append("&#39;")
            else -> append(ch)
        }
    }
}
