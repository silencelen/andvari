package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import jakarta.mail.Session
import jakarta.mail.internet.InternetAddress
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.util.Properties
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Mail is plain text with an HTML alternative of the same content, never HTML only (spec 03 §14.5). */
class MailTransportTest {
    private val mail = MailTemplates.render(
        "new_device", "me@example.com", "Home", "https://vault.example", "support@example.com",
        Mail.Ctx("ab".repeat(16), 1_800_000_000_000, mapOf("device" to "<b>x</b> (linux)")),
    )

    private fun parts(msg: MimeMessage): List<Pair<String, String>> {
        assertTrue(msg.contentType.startsWith("multipart/alternative"), msg.contentType)
        val mp = msg.content as MimeMultipart
        return (0 until mp.count).map { i -> mp.getBodyPart(i).let { it.contentType.substringBefore(';').lowercase() to (it.content as String) } }
    }

    private fun tokenOk() = """{"access_token":"tok","token_type":"Bearer"}"""

    @Test
    fun mime_carriesTheTextFirst_thenTheSameContentAsHtml() {
        val p = parts(mimeOf(mail, InternetAddress("support@example.com", "andvari")))
        assertEquals(listOf("text/plain", "text/html"), p.map { it.first })
        assertEquals(mail.text, p[0].second)
        assertEquals(mail.html, p[1].second)
        assertTrue(!p[1].second.contains("<b>x</b>"), "dynamic strings are escaped in the HTML part")
    }

    @Test
    fun graph_sendsTheMimeMessage_withBothParts() {
        var sendBody: String? = null
        var sendType: String? = null
        var sendPath: String? = null
        val engine = MockEngine { req ->
            if (req.url.host == "login.microsoftonline.com") {
                respond(tokenOk(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
            } else {
                sendPath = req.url.encodedPath
                sendType = req.body.contentType?.toString()
                sendBody = (req.body as TextContent).text
                assertEquals("Bearer tok", req.headers[HttpHeaders.Authorization])
                respond("", HttpStatusCode.Accepted)
            }
        }
        val t = GraphTransport(HttpClient(engine), "tenant", "client", "secret", "support@example.com")
        assertTrue(t.send(mail) is SendResult.Ok)
        assertEquals("/v1.0/users/support@example.com/sendMail", sendPath)
        assertTrue(sendType!!.startsWith("text/plain"), sendType)
        val msg = MimeMessage(Session.getInstance(Properties()), java.util.Base64.getDecoder().decode(sendBody!!).inputStream())
        assertEquals(listOf("text/plain", "text/html"), parts(msg).map { it.first })
        assertEquals(mail.subject, msg.subject)
        assertEquals("me@example.com", msg.allRecipients.single().toString())
        val from = msg.from.single() as InternetAddress
        assertEquals("andvari", from.personal); assertEquals("support@example.com", from.address)
    }

    @Test
    fun graph_classifiesFailuresByStatus() {
        fun with(status: HttpStatusCode) = GraphTransport(
            HttpClient(
                MockEngine { req ->
                    if (req.url.host == "login.microsoftonline.com") respond(tokenOk(), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
                    else respond("", status)
                },
            ),
            "t", "c", "s", "support@example.com",
        )
        assertTrue(with(HttpStatusCode.BadRequest).send(mail) is SendResult.Permanent)
        assertTrue(with(HttpStatusCode.TooManyRequests).send(mail) is SendResult.Transient)
        assertTrue(with(HttpStatusCode.ServiceUnavailable).send(mail) is SendResult.Transient)
    }
}
