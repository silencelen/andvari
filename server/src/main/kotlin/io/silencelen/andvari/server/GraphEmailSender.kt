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
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.slf4j.LoggerFactory

/**
 * cut 4 email-invite via Microsoft Graph app-only `sendMail` — the durable M365 path (no SMTP AUTH,
 * no stored mailbox password). Client-credentials OAuth2 → `POST /users/{sender}/sendMail`, reusing
 * the server's existing Ktor HTTP client (no new dependency). Same `EmailSender` contract + hardening
 * as the SMTP sender: the recipient is pre-validated at `createInvite` (B1), the call runs off-thread
 * AFTER the tx commits (A3), and failures are logged class-only — HTTP status number, never a response
 * body (which could echo the client secret or the recipient/link — A4). TLS to Microsoft is validated
 * by the Ktor client's default trust store.
 */
class GraphEmailSender(
    private val http: HttpClient,
    private val tenantId: String,
    private val clientId: String,
    private val clientSecret: String,
    private val sender: String, // the from-mailbox UPN (e.g. no-reply@monahanhosting.com)
) : EmailSender {
    private val log = LoggerFactory.getLogger("andvari.email")

    override fun sendInvite(to: String, enrollLink: String) {
        require(EmailAddress.isValid(to)) { "invalid recipient" } // caller pre-validates; defense in depth
        runBlocking {
            withTimeout(20_000) { // bound a hung Graph call so no IO thread parks (A3)
                sendMail(fetchToken(), to, enrollLink)
            }
        }
        log.info("invite email dispatched (graph)") // A4: no recipient, no link, no token
    }

    private suspend fun fetchToken(): String {
        val resp = http.post("https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                Parameters.build {
                    append("client_id", clientId)
                    append("client_secret", clientSecret)
                    append("scope", "https://graph.microsoft.com/.default")
                    append("grant_type", "client_credentials")
                }.formUrlEncode(),
            )
        }
        // A4: on failure surface only the status code — the token error body can echo the secret.
        if (!resp.status.isSuccess()) error("token endpoint ${resp.status.value}")
        return Json.parseToJsonElement(resp.bodyAsText()).jsonObject["access_token"]?.jsonPrimitive?.content
            ?: error("token response had no access_token")
    }

    private suspend fun sendMail(token: String, to: String, enrollLink: String) {
        val payload = buildJsonObject {
            putJsonObject("message") {
                put("subject", InviteEmailBody.SUBJECT)
                putJsonObject("body") {
                    // Branded HTML (Graph sends a single body; email clients render the inline-styled
                    // treasury card). See InviteEmailBody — one source shared with the SMTP transport.
                    put("contentType", "HTML")
                    put("content", InviteEmailBody.html(enrollLink))
                }
                putJsonArray("toRecipients") {
                    addJsonObject { putJsonObject("emailAddress") { put("address", to) } }
                }
            }
            put("saveToSentItems", false)
        }
        val resp = http.post("https://graph.microsoft.com/v1.0/users/$sender/sendMail") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(payload.toString())
        }
        if (!resp.status.isSuccess()) error("graph sendMail ${resp.status.value}") // A4: status only
    }
}
