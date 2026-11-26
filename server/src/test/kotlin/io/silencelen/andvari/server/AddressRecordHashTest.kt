package io.silencelen.andvari.server

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.slf4j.LoggerFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * What the server's records keep of an address a person typed is a hash keyed with a secret of the server's (decided on
 * 2026-11-17). Before, the audit rows of a sign-up's first steps carried the first characters of a plain SHA-256 of the
 * address, printed to the journal too, and the rows bound to an address (sign-up codes and tickets, an enrol link minted
 * for an address) kept the plain hash: whoever read them could confirm a guessed address, of people with no account too.
 * Each value still ties the rows of one address together, and two addresses still differ.
 */
class AddressRecordHashTest {
    private val post = HttpMethod.Post

    private fun start(email: String) = """{"email":"$email","ageConfirmed":true}"""

    /** [value] (a whole hash or a prefix of one) is no prefix of the plain SHA-256 of any of [emails]. */
    private fun assertNotPlain(value: String, emails: List<String>, what: String) {
        assertTrue(value.length >= 8, "$what: '$value'")
        for (e in emails) assertFalse(sha256Hex(e).startsWith(value), "$what for $e is (a prefix of) the plain hash")
    }

    private fun addrOf(meta: String?): String {
        assertTrue(meta != null && meta.startsWith("addr="), "meta: $meta")
        return meta.removePrefix("addr=")
    }

    @Test
    fun signUpsFirstSteps_auditRowsJournalLinesCodesAndTickets_keepAKeyedHash() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(TestKit.config(mode = "open"), clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val journal = LoggerFactory.getLogger("andvari.audit") as Logger
        val lines = ListAppender<ILoggingEvent>().also { it.start() }
        journal.addAppender(lines)
        val a = "first@example.com"
        val b = "second@example.com"
        val both = listOf(a, b)
        try {
            for ((email, ip) in listOf(a to "10.7.1.1", a to "10.7.1.2", b to "10.7.1.3")) {
                assertEquals(202, c.call(post, "/api/v1/signup/start", start(email), ip = ip).status.value)
            }
            for (email in listOf(a, a, b)) {
                assertEquals("bad_code", c.call(post, "/api/v1/signup/verify", """{"email":"$email","code":"000001"}""").errorCode())
            }
        } finally {
            journal.detachAppender(lines)
        }
        fun metas(type: String) = s.db.read { db -> db.queryAll("SELECT meta FROM audit WHERE type=? ORDER BY id", type) { it.getString(1) } }.map { addrOf(it) }
        for (type in listOf("signup_start", "signup_verify_fail")) {
            val (a1, a2, b1) = metas(type)
            for (v in listOf(a1, a2, b1)) assertNotPlain(v, both, "$type audit row")
            assertEquals(a1, a2, "$type: two rows of one address tie together")
            assertNotEquals(a1, b1, "$type: two addresses differ")
            // The journal's lines carry what the rows carry, and nothing of the plain hash.
            val logged = lines.list.map { WireJson.json.parseToJsonElement(it.formattedMessage).jsonObject }
                .filter { it["type"]?.jsonPrimitive?.content == type }
                .map { addrOf(it["meta"]?.jsonPrimitive?.content) }
            assertEquals(listOf(a1, a2, b1), logged, "$type: the journal's lines")
        }
        // The code rows: one per address, keyed, and tied to the audit rows of that address.
        fun codeHash(email: String) = s.db.read { db -> db.queryAll("SELECT emailHash FROM signup_codes") { it.getString(1) } }
            .filter { it.startsWith(metas("signup_start")[if (email == a) 0 else 2]) }
        val codeA = codeHash(a).single()
        val codeB = codeHash(b).single()
        assertEquals(2L, s.db.read { db -> db.count("SELECT COUNT(*) FROM signup_codes") })
        for (v in listOf(codeA, codeB)) assertNotPlain(v, both, "signup_codes.emailHash")
        assertNotEquals(codeA, codeB)
        // The tickets: the right code of each address mints one, bound to the code row's keyed hash.
        val mails = Flow.sink(s).filter { it.first == "signup_code" }
        for (email in both) {
            val code = Flow.codeIn(mails.last { it.second == email }.third)
            val v = c.call(post, "/api/v1/signup/verify", """{"email":"$email","code":"$code"}""")
            assertEquals(200, v.status.value, v.bodyAsText())
        }
        val tickets = s.db.read { db -> db.queryAll("SELECT emailHash FROM signup_tickets ORDER BY rowid") { it.getString(1) } }
        assertEquals(listOf(codeA, codeB), tickets)
    }

    @Test
    fun anEnrolLinkMintedForAnAddress_keepsAKeyedHash_andALinkMintedBefore_stillWorksForItsAddressOnly() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = "me@example.com"
        val you = "you@example.com"
        val auths = listOf(Flow.enrolAuth(s, bound = me), Flow.enrolAuth(s, bound = me), Flow.enrolAuth(s, bound = you))
        fun bound(id: String) = s.db.read { db -> db.queryOne("SELECT boundEmailHash FROM links WHERE linkId=?", id) { it.getString(1) }!! }
        val (m1, m2, y1) = auths.map { bound(it.linkId) }
        for (v in listOf(m1, m2, y1)) assertNotPlain(v, listOf(me, you), "links.boundEmailHash")
        assertEquals(m1, m2)
        assertNotEquals(m1, y1)
        // The keyed binding is the one register checks: the bound address registers, another is refused.
        assertEquals("email_mismatch", c.call(post, "/api/v1/auth/register", Me(you).register(s, auths[0])).errorCode())
        Flow.register(c, s, Me(me), auths[0])
        // A link minted before the keyed hash keeps the plain one: it still registers its address, and only that one.
        val before = Flow.enrolAuth(s, bound = you)
        s.db.tx { db -> db.exec("UPDATE links SET boundEmailHash=? WHERE linkId=?", sha256Hex(you), before.linkId) }
        assertEquals("email_mismatch", c.call(post, "/api/v1/auth/register", Me("third@example.com").register(s, before)).errorCode())
        Flow.register(c, s, Me(you), before)
    }
}
