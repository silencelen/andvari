package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Spec 01 §5.5: `emailNorm` admits only `local@domain` with a dot-atom local part and a domain
 * under the origin host grammar, so mail display syntax cannot name the same mailbox under a new string.
 */
class EmailGrammarTest {
    /** Typed → normalised. The vector author copies these rows. */
    private val accepted = listOf(
        "user@example.com" to "user@example.com",
        "  User@Example.COM \t" to "user@example.com",
        "first.last@example.com" to "first.last@example.com",
        "a+tag@sub.example.co.uk" to "a+tag@sub.example.co.uk",
        "o'brien@example.com" to "o'brien@example.com",
        "x_y-z@ex-ample.com" to "x_y-z@ex-ample.com",
        "!#\$%&'*+/=?^_`{|}~-@example.com" to "!#\$%&'*+/=?^_`{|}~-@example.com",
        "a@xn--bcher-kva.example" to "a@xn--bcher-kva.example",
        "1@example.io" to "1@example.io",
        "a@b.co" to "a@b.co",
        "${"l".repeat(64)}@example.com" to "${"l".repeat(64)}@example.com",
        "user@123.example.com" to "user@123.example.com",
    )

    private val refused = listOf(
        "x<user@blocked.example>", "<user@blocked.example>", "user@blocked.example(x)", "(x)user@example.com",
        "\"quoted\"@example.com", "\"a b\"@example.com", ".user@example.com", "user.@example.com", "us..er@example.com",
        "user@localhost", "user@example", "user@[127.0.0.1]", "user@127.0.0.1", "user@example.123", "user@example.0x1f",
        "user@-example.com", "user@example-.com", "user@example..com", "user@.example.com", "user@example.com.",
        "user@example.com:8443", "user@exa_mple.com", "user@example.com/x", "${"l".repeat(65)}@example.com",
        "a@b@example.com", "user,other@example.com", "user;x@example.com", "user\\x@example.com", "user[x]@example.com",
        "user:x@example.com", "@example.com", "user@", "user@${"d".repeat(64)}.com", "us er@example.com", "user@exämple.com",
    )

    @Test
    fun theAddressRule() {
        val wrong = ArrayList<String>()
        for ((typed, norm) in accepted) if (Grammar.emailNorm(typed) != norm) wrong += "accept: <$typed> gave <${Grammar.emailNorm(typed)}>"
        for (typed in refused) if (Grammar.emailNorm(typed) != null) wrong += "refuse: <$typed> gave <${Grammar.emailNorm(typed)}>"
        assertEquals(emptyList(), wrong, wrong.joinToString("\n"))
    }

    @Test
    fun displaySyntaxNoLongerPassesTheBlocklist() = testApplication {
        val s = TestKit.services(TestKit.config(mode = "open", blocklist = setOf("blocked.example")))
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        suspend fun start(email: String) = c.call(HttpMethod.Post, "/api/v1/signup/start", """{"email":"${email.replace("\"", "\\\"")}","ageConfirmed":true}""")
        assertEquals("email_domain_blocked", start("user@blocked.example").errorCode())
        for (e in listOf("x<user@blocked.example>", "<user@blocked.example>", "user@blocked.example(x)")) {
            val r = start(e)
            assertEquals(400, r.status.value, "$e: ${r.bodyAsText()}"); assertEquals("invalid_email", r.errorCode(), e)
        }
    }
}
