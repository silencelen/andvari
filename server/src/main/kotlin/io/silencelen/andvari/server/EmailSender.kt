package io.silencelen.andvari.server

import jakarta.mail.Address
import jakarta.mail.Authenticator
import jakarta.mail.Message
import jakarta.mail.PasswordAuthentication
import jakarta.mail.Session
import jakarta.mail.Transport
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import org.slf4j.LoggerFactory
import java.util.Properties

/**
 * Strict single-address validation (breaker B1). The invite `email` is admin-typed free text that
 * can reach SMTP; a CR/LF/comma in it could inject headers (Bcc → a spam relay) under the household's
 * real SPF/DKIM domain. Reject anything that isn't ONE plain address. Applied at `createInvite` BEFORE
 * the address is ever stored, so a poisoned address can't be persisted even for a non-emailed invite.
 * Deliberately NARROW (not RFC-exhaustive) — for a header-injection guard, narrow beats permissive.
 */
object EmailAddress {
    private val RE = Regex("^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}$")
    fun isValid(email: String): Boolean {
        if (email.isEmpty() || email.length > 254) return false
        // kills CR, LF, NUL, tab, and every space/control — the header-injection primitives.
        if (email.any { it.isISOControl() || it.isWhitespace() }) return false
        return RE.matches(email)
    }
}

/**
 * cut 4 email-invite. Sends the enroll link to the invite's OWN email via SMTP submission (the M365
 * relay). Best-effort + off the request path (App.kt dispatches to Dispatchers.IO AFTER the tx
 * commits, so a slow/failed relay can never stall the SQLite writer or the HTTP response — breaker A3).
 */
interface EmailSender {
    /** `to` MUST be pre-validated (EmailAddress.isValid). Throws on failure — the caller swallows and
     *  logs an error CLASS only, never the address/link/exception message (breaker A4). */
    fun sendInvite(to: String, enrollLink: String)
}

class SmtpEmailSender(
    private val host: String,
    private val port: Int,
    private val user: String,
    private val pass: String,
    private val from: String,
) : EmailSender {
    private val log = LoggerFactory.getLogger("andvari.email")

    override fun sendInvite(to: String, enrollLink: String) {
        require(EmailAddress.isValid(to)) { "invalid recipient" } // caller pre-validates; defense in depth
        val props = Properties().apply {
            put("mail.smtp.host", host)
            put("mail.smtp.port", port.toString())
            put("mail.smtp.auth", "true")
            // A8: STARTTLS REQUIRED + cert-validated. No plaintext fallback (required=true), server
            // identity checked, and NO ssl.trust=* — a MITM on the CT122→relay hop cannot strip TLS
            // and harvest the M365 AUTH credential in cleartext.
            put("mail.smtp.starttls.enable", "true")
            put("mail.smtp.starttls.required", "true")
            put("mail.smtp.ssl.checkserveridentity", "true")
            // A3: bounded so a hung relay can't tie up the IO thread.
            put("mail.smtp.connectiontimeout", "10000")
            put("mail.smtp.timeout", "15000")
            put("mail.smtp.writetimeout", "15000") // bound a stalled DATA write so no IO thread parks

            // A4: mail.debug OFF — otherwise it dumps RCPT TO + DATA (recipient + link) to stdout→Loki.
            put("mail.debug", "false")
        }
        val session = Session.getInstance(props, object : Authenticator() {
            override fun getPasswordAuthentication() = PasswordAuthentication(user, pass)
        })
        // Explicit Address-typed vals so setFrom(Address) / setRecipient(RecipientType, Address)
        // resolve unambiguously (the jakarta String overloads otherwise tangle inside an apply block).
        // strict=true rejects a malformed recipient (B1 backstop); a SINGLE recipient (never a list)
        // closes the arbitrary-Bcc / extra-recipient vector.
        val fromAddr: Address = InternetAddress(from)
        val toAddr: Address = InternetAddress(to, true)
        val msg = MimeMessage(session)
        msg.setFrom(fromAddr)
        msg.setRecipient(Message.RecipientType.TO, toAddr)
        msg.subject = "You're invited to andvari"
        msg.setText(body(enrollLink), "utf-8")
        Transport.send(msg)
        log.info("invite email dispatched") // A4: no recipient, no link, no token
    }

    private fun body(enrollLink: String): String = """
        You've been invited to andvari, your household's password manager.

        Open this link on the same network as the app to set up your account:

        $enrollLink

        This link is a one-time key — it expires within the hour, and it can't be undone once used.
        You'll also need the printed recovery sheet, handed to you in person, to finish setting up.

        If you weren't expecting this, you can safely ignore it.
    """.trimIndent()
}
