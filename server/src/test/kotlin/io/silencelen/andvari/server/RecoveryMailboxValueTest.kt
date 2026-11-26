package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The way out through the mailbox (spec 03 §18.1, spec 05 R37; decided on 2026-11-17). Anyone who knows a person's
 * address can spend that address's five recovery requests of the day, and the person's own request then went nowhere.
 * Every code mail now carries a mailbox value; a request that names a value of its address, unused and unexpired, is
 * taken past the five, uses the value up, and draws on a ceiling of its own (five a day per address). A wrong, used,
 * expired or foreign value changes nothing, and the answer never tells.
 */
class RecoveryMailboxValueTest {
    private val post = HttpMethod.Post

    private class Fix(val c: HttpClient, val s: Services, val clock: MutableClock, val real: Me, val other: Me, val priv: Me, val op: Me, val ticking: Ticking)

    /** The server's clock: [base], moved on by [tick] milliseconds at every reading, as time passes while a request runs. */
    private class Ticking(val base: MutableClock) : Clock {
        @Volatile var tick = 0L
        override fun now(): Long = synchronized(this) { base.ms.also { base.ms += tick } }
    }

    private class Opened(val response: HttpResponse, val body: String, val requestId: String, val ip: String, val pollSecret: String)

    private fun app(block: suspend (Fix) -> Unit) = testApplication {
        val clock = MutableClock()
        val ticking = Ticking(clock)
        val key = TestKit.Identity().curvePub
        val s = TestKit.services(TestKit.config(recoveryKey = key), ticking)
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val real = Me("real@example.com")
        Flow.register(c, s, real, Flow.enrolAuth(s), "operator", Flow.escrow(real, sha256Hex(key)))
        val other = Me("other@example.com")
        Flow.register(c, s, other, Flow.enrolAuth(s), "operator", Flow.escrow(other, sha256Hex(key)))
        val priv = Flow.member(c, s, "private@example.com")
        Flow.sink(s)
        block(Fix(c, s, clock, real, other, priv, op, ticking))
    }

    /**
     * One request from a fresh caller address (the per-IP bucket is not what this test is about). [value] is put in the
     * body as a JSON string when given; [rawValue] is put in as it is (a number, a long string).
     */
    private suspend fun open(f: Fix, email: String, value: String? = null, rawValue: String? = null, expect: Int = 202): Opened {
        val poll = TestKit.crypto.randomBytes(32)
        val extra = when {
            rawValue != null -> ""","mailboxValue":$rawValue"""
            value != null -> ""","mailboxValue":"$value""""
            else -> ""
        }
        val body = """{"email":"$email","rPub":"${b32()}","pollHash":"${sha256Hex(poll)}","platform":"android"$extra}"""
        val ip = randomIp()
        val r = f.c.call(post, "/api/v1/recovery/requests", body, ip = ip)
        val text = r.bodyAsText()
        assertEquals(expect, r.status.value, text)
        val id = if (expect == 202) WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), text).requestId else ""
        return Opened(r, text, id, ip, Bytes.toB64(poll))
    }

    /** Status, headers (without the date) and body, with the request's own id masked: what the caller can compare. */
    private fun shape(o: Opened): String =
        "${o.response.status.value} ${o.response.headers.entries().filter { it.key != "Date" }.sortedBy { it.key }} ${o.body.replace(o.requestId, "<id>")}"

    private suspend fun poll(f: Fix, o: Opened): String {
        val r = f.c.call(post, "/api/v1/recovery/requests/${o.requestId}/poll", """{"pollSecret":"${o.pollSecret}"}""")
        return "${r.status.value} ${r.headers.entries().filter { it.key != "Date" }.sortedBy { it.key }} ${r.bodyAsText()}"
    }

    /** The code mails sent to [email] so far, oldest first. */
    private fun codeMails(f: Fix, email: String): List<String> =
        Flow.sink(f.s).filter { it.first == "recovery_request_code" && it.second == email }.map { it.third }

    private val valueLine = Regex("""^ {4}([A-Z2-9]{4} [A-Z2-9]{4} [A-Z2-9]{4} [A-Z2-9]{4})$""", RegexOption.MULTILINE)

    /** The mailbox value a code mail carries, as the mail shows it (four groups of four). */
    private fun valueIn(text: String): String = assertNotNull(valueLine.find(text), text).groupValues[1]

    private fun requestUser(f: Fix, o: Opened): String? =
        f.s.db.read { c -> c.queryOne("SELECT userId FROM recovery_requests WHERE requestId=?", o.requestId) { it.getString(1) } }

    private fun valuesOf(f: Fix, email: String): Long =
        f.s.db.read { c -> c.count("SELECT COUNT(*) FROM recovery_mailbox_values WHERE emailHash=?", f.s.config.addressHash(email)) }

    /** Five requests for [email], as a stranger would open them; returns the values their mails carried. */
    private suspend fun spendTheFive(f: Fix, email: String): List<String> {
        val before = codeMails(f, email).size
        repeat(5) { open(f, email) }
        val mails = codeMails(f, email)
        return mails.drop(before).map { valueIn(it) }
    }

    @Test
    fun theGap_fiveRequestsFromElsewhere_leaveThePersonsOwnNowhere_andAValueFromOneOfThoseMailsTakesIt() = app { f ->
        val values = spendTheFive(f, f.real.email)
        assertEquals(5, codeMails(f, f.real.email).size)
        assertEquals(5, values.toSet().size, "every mail carries a value of its own")
        // The person's own request, without a value: answered alike, and it goes nowhere.
        val nowhere = open(f, f.real.email)
        assertEquals(5, codeMails(f, f.real.email).size)
        assertEquals(null, requestUser(f, nowhere))
        // With a value from one of those mails (as the mail shows it, in lower case): taken, and its mail arrives.
        val mine = open(f, f.real.email, value = values[2].lowercase())
        val mails = codeMails(f, f.real.email)
        assertEquals(6, mails.size)
        assertEquals(f.real.userId, requestUser(f, mine))
        val v = f.c.call(post, "/api/v1/recovery/requests/${mine.requestId}/verify", """{"code":"${Flow.codeIn(mails.last())}"}""")
        assertEquals(200, v.status.value, v.bodyAsText())
        // Its mail carries a fresh value like any other.
        assertTrue(valueIn(mails.last()) !in values)
        assertEquals(shape(nowhere), shape(mine))
    }

    @Test
    fun anAddressReceivesAtMostFivePlusFiveRequestMailsWithinOneWindowOfEachCap_andAValueTheCeilingRefusedStillWorksInTheNext() = app { f ->
        val first = spendTheFive(f, f.real.email)
        val second = first.map { v ->
            open(f, f.real.email, value = v)
            valueIn(codeMails(f, f.real.email).last())
        }
        assertEquals(10, codeMails(f, f.real.email).size)
        // The eleventh, with a right value: the ceiling of values is spent, so nothing is sent and the value is kept.
        val eleventh = open(f, f.real.email, value = second[0])
        assertEquals(10, codeMails(f, f.real.email).size)
        assertEquals(null, requestUser(f, eleventh))
        assertEquals(5L, valuesOf(f, f.real.email))
        // The next day: five more, then that value takes one more.
        f.clock.advance(Clock.DAY_MS)
        spendTheFive(f, f.real.email)
        assertEquals(15, codeMails(f, f.real.email).size)
        open(f, f.real.email, value = second[0])
        assertEquals(16, codeMails(f, f.real.email).size)
    }

    @Test
    fun aValueIsUsedOnce() = app { f ->
        val values = spendTheFive(f, f.real.email)
        val taken = open(f, f.real.email, value = values[0])
        assertEquals(f.real.userId, requestUser(f, taken))
        assertEquals(6, codeMails(f, f.real.email).size)
        // 5 values were mailed, one was used, and the new mail's is stored.
        assertEquals(5L, valuesOf(f, f.real.email))
        val again = open(f, f.real.email, value = values[0])
        assertEquals(null, requestUser(f, again))
        assertEquals(6, codeMails(f, f.real.email).size)
        assertEquals(shape(taken), shape(again))
    }

    @Test
    fun aValueExpiresSevenDaysAfterItsMail_andTheJanitorForgetsIt() = app { f ->
        val day0 = spendTheFive(f, f.real.email)
        // Six days later it still works.
        f.clock.advance(6 * Clock.DAY_MS)
        spendTheFive(f, f.real.email)
        open(f, f.real.email, value = day0[0])
        assertEquals(11, codeMails(f, f.real.email).size)
        // Seven days after its mail it does nothing.
        f.clock.advance(Clock.DAY_MS)
        spendTheFive(f, f.real.email)
        val late = open(f, f.real.email, value = day0[1])
        assertEquals(null, requestUser(f, late))
        assertEquals(16, codeMails(f, f.real.email).size)
        // The janitor forgets the expired ones (the four left of day 0) and keeps the others.
        val before = valuesOf(f, f.real.email)
        f.s.janitor.sweep(f.clock.now())
        assertEquals(before - 4, valuesOf(f, f.real.email))
        assertEquals(0L, f.s.db.read { it.count("SELECT COUNT(*) FROM recovery_mailbox_values WHERE expiresAt<=?", f.clock.now()) })
    }

    @Test
    fun aValueOfAnotherAddress_changesNothing_andStaysItsOwnAddresss() = app { f ->
        val others = spendTheFive(f, f.other.email)
        spendTheFive(f, f.real.email)
        val foreign = open(f, f.real.email, value = others[0])
        assertEquals(null, requestUser(f, foreign))
        assertEquals(5, codeMails(f, f.real.email).size)
        // For its own address it still works.
        val own = open(f, f.other.email, value = others[0])
        assertEquals(f.other.userId, requestUser(f, own))
        assertEquals(6, codeMails(f, f.other.email).size)
    }

    /**
     * The answer and what it leaves: for a right value, a wrong one, one not of the value's form and none; for an address
     * with an account of each posture and one without; within the address's five, past them, and past the ceiling of
     * values. Every answer is byte for byte the same (the id aside), every poll is, every request writes one audit row
     * whose meta says only whether a value was given and whether it took the request, and only a request that mails a
     * code stores a value.
     */
    @Test
    fun theAnswer_thePoll_andTheRecords_neverTell() = app { f ->
        val shapes = LinkedHashMap<String, String>()
        val polls = LinkedHashMap<String, String>()
        val wrong = "ABCD EFGH JKLM NPQR"
        fun lastAuditId() = f.s.db.read { c -> c.queryOne("SELECT COALESCE(MAX(id),0) FROM audit") { it.getLong(1) }!! }
        fun records(after: Long) = f.s.db.read { c ->
            c.queryAll("SELECT type,userId,deviceId,ip,meta FROM audit WHERE id>? ORDER BY id", after) { r -> listOf(r.getString(1), r.getString(2), r.getString(3), r.getString(4), r.getString(5)) }
        }.filter { !it[0]!!.startsWith("email_") }
        suspend fun case(name: String, email: String, value: String?, named: String?, meta: String?) {
            val before = lastAuditId()
            val o = open(f, email, value = value)
            shapes[name] = shape(o)
            polls[name] = poll(f, o)
            assertEquals(listOf(listOf("recovery_request_create", named, null, o.ip, meta)), records(before), name)
        }
        val values = ArrayList<String>()
        // Within the five.
        for ((who, email) in listOf("real" to f.real.email, "unknown" to "nobody@example.com", "private" to f.priv.email)) {
            val named = if (who == "real") f.real.userId else null
            case("$who, within, none", email, null, named, null)
            case("$who, within, wrong", email, wrong, named, "mailbox=not_used")
            case("$who, within, not a value", email, "not a value", named, "mailbox=not_used")
        }
        values += codeMails(f, f.real.email).map { valueIn(it) }
        // A right value within the five is not needed: the request is an ordinary one, and the value is kept.
        case("real, within, right", f.real.email, values[0], f.real.userId, "mailbox=not_used")
        case("real, within, last", f.real.email, null, f.real.userId, null)
        assertEquals(5, codeMails(f, f.real.email).size)
        values.clear(); values += codeMails(f, f.real.email).map { valueIn(it) }
        // Past the five.
        repeat(5) { open(f, "nobody@example.com"); open(f, f.priv.email) }
        for ((who, email) in listOf("real" to f.real.email, "unknown" to "nobody@example.com", "private" to f.priv.email)) {
            case("$who, past, none", email, null, null, null)
            case("$who, past, wrong", email, wrong, null, "mailbox=not_used")
        }
        case("unknown, past, a value of another address", "nobody@example.com", values[0], null, "mailbox=not_used")
        for (i in 0 until 5) case("real, past, right $i", f.real.email, values[i], f.real.userId, "mailbox=used")
        // Past the ceiling of values: a right value (from the newest mail) is answered alike and takes nothing.
        case("real, past the ceiling, right", f.real.email, valueIn(codeMails(f, f.real.email).last()), null, "mailbox=not_used")
        assertEquals(1, shapes.values.toSet().size, shapes.entries.joinToString("\n"))
        assertEquals(1, polls.values.toSet().size, polls.entries.joinToString("\n"))
        assertTrue(""""state":"unverified"""" in polls.values.first())
        // Only a request that mails a code stores a value: ten mails, of which five values were used.
        assertEquals(10, codeMails(f, f.real.email).size)
        assertEquals(5L, valuesOf(f, f.real.email))
        assertEquals(0L, valuesOf(f, "nobody@example.com"))
        assertEquals(0L, valuesOf(f, f.priv.email))
        // The private-posture notice carries no value.
        val notices = Flow.sink(f.s).filter { it.first == "recovery_request_private" }
        assertTrue(notices.isNotEmpty() && notices.none { valueLine.containsMatchIn(it.third) })
        // A value that is not a string, or longer than 64 characters, is refused alike for every address, before any account work.
        val refusals = listOf(f.real.email, "nobody@example.com", f.priv.email).flatMap { email ->
            listOf(
                open(f, email, rawValue = "12345", expect = 400),
                open(f, email, rawValue = "\"${"A".repeat(65)}\"", expect = 400),
                open(f, email, rawValue = "{}", expect = 400),
            )
        }
        assertEquals(1, refusals.map { shape(it) }.toSet().size)
        assertTrue(""""error":"bad_mailbox_value"""" in refusals.first().body, refusals.first().body)
        // null is no value.
        case("real, past, null", f.real.email, null, null, null)
        val n = open(f, "nobody@example.com", rawValue = "null")
        assertEquals(shapes.values.first(), shape(n))
    }

    @Test
    fun anAddresssValuesAreForgotten_whenItsAccountIsDeleted() = app { f ->
        repeat(2) { open(f, f.real.email) }
        open(f, f.other.email)
        assertEquals(2L, valuesOf(f, f.real.email))
        val r = f.c.call(post, "/api/v1/account/delete", """{"confirmEmail":"${f.real.email}","currentAuthKey":"${f.real.authKey}","leaves":[]}""", f.real.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(0L, valuesOf(f, f.real.email))
        assertEquals(1L, valuesOf(f, f.other.email))
    }

    @Test
    fun anAddresssValuesAreForgotten_whenItsRecoveryCompletes() = app { f ->
        repeat(2) { open(f, f.real.email) }
        open(f, f.other.email)
        assertEquals(2L, valuesOf(f, f.real.email))
        val v = WireJson.json.decodeFromString(
            RecoveryVerifyResponse.serializer(),
            f.c.call(post, "/api/v1/recovery/self/verify", """{"email":"${f.real.email}","recoveryAuthKey":"${f.real.recoveryAuthKey}"}""").bodyAsText(),
        )
        val tail = """"newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA","newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"ios","name":"x","deviceSecret":"${b32()}"}"""
        val kc = f.c.call(post, "/api/v1/recovery/self/commit", """{"recoveryTicket":"${v.recoveryTicket}","newAuthKey":"${b32()}",$tail}""")
        assertEquals(200, kc.status.value, kc.bodyAsText())
        assertEquals(0L, valuesOf(f, f.real.email))
        assertEquals(1L, valuesOf(f, f.other.email))
    }

    @Test
    fun aValueIsSixteenSymbolsOfItsAlphabet_andIsTakenAsTyped() {
        val seen = HashSet<String>()
        repeat(200) {
            val v = Assisted.newMailboxValue()
            assertEquals(16, v.length)
            assertTrue(v.all { it in Assisted.MAILBOX_ALPHABET }, v)
            seen += v
            assertEquals(v, Assisted.mailboxValueOf(Assisted.mailboxDisplay(v).lowercase()))
            assertEquals(v, Assisted.mailboxValueOf(Assisted.mailboxDisplay(v).replace(' ', '-')))
        }
        assertEquals(200, seen.size)
        assertEquals(32, Assisted.MAILBOX_ALPHABET.toSet().size)
        assertEquals(null, Assisted.mailboxValueOf("ABCD EFGH JKLM NPQ"))
        assertEquals(null, Assisted.mailboxValueOf("ABCD EFGH JKLM NPQ0"))
        assertEquals(null, Assisted.mailboxValueOf("ABCD EFGH JKLM NPQRS"))
    }

    /**
     * A typed value is brought to its form in ASCII only: spaces, tabs and dashes go and a to z are raised. A full Unicode
     * case mapping turns characters from outside the alphabet into letters of it (the long s into S, the sharp s into SS,
     * the ligatures ff, fl and st into two letters each); none of them, nor a full-width letter, is a value's symbol.
     */
    @Test
    fun aTypedValueIsBroughtToItsFormInAsciiOnly() {
        assertEquals("STFFFLSS2345ABCD", Assisted.mailboxValueOf("st-ff fl\tss 2345-abcd"))
        for (typed in listOf(
            "ſ".repeat(16), // the long s
            "ß".repeat(8), // the sharp s
            "ﬀ".repeat(8), // ff
            "ﬂ".repeat(8), // fl
            "ﬆ".repeat(8), // st
            "Ａ".repeat(16), // a full-width A
            "ａ".repeat(16), // a full-width a
            "ſTFFFLSS2345ABCD",
            "ﬆFFFLSS2345ABCD",
            "STﬀﬂSS2345ABCD",
            "STFFFLß2345ABCD",
            "ＳTFFFLSS2345ABCD",
            "ı".repeat(16), // the dotless i, which a full mapping raises to I
        )) assertEquals(null, Assisted.mailboxValueOf(typed), typed)
    }

    @Test
    fun aRealValueWithOneLetterTypedAsALookAlikeFromOutsideAscii_changesNothing_andTheValueAsTypedInLowerCaseIsTaken() = app { f ->
        // A value of the address whose letters a full case mapping can reach from outside ASCII (S, F, L, T).
        val value = "STFFFLSS2345ABCD"
        storeValue(f, f.real.email, value)
        spendTheFive(f, f.real.email)
        val ceiling = "${Assisted.MAILBOX_BUCKET.name}:${Grammar.emailHash(f.real.email)}"
        val stored = valuesOf(f, f.real.email)
        val none = open(f, f.real.email, value = "ABCD EFGH JKLM NPQR")
        for (typed in listOf(
            "ſTFF FLSS 2345 ABCD",
            "ﬆFF FLSS 2345 ABCD",
            "STﬀﬂ SS23 45AB CD",
            "STFF FLß 2345 ABCD",
            "ＳTFF FLSS 2345 ABCD",
        )) {
            val o = open(f, f.real.email, value = typed)
            assertEquals(null, requestUser(f, o), typed)
            assertEquals(5, codeMails(f, f.real.email).size, typed)
            assertEquals(stored, valuesOf(f, f.real.email), typed)
            assertEquals(0, f.s.limiter.count(ceiling), typed)
            assertEquals(shape(none), shape(o), typed)
        }
        // The same value in lower case, with spaces and dashes: taken.
        val taken = open(f, f.real.email, value = "st-ff fl ss-2345 abcd")
        assertEquals(f.real.userId, requestUser(f, taken))
        assertEquals(6, codeMails(f, f.real.email).size)
        assertEquals(1, f.s.limiter.count(ceiling))
    }

    /**
     * Eight requests at once with the same right value, past the address's five: every answer is the same, one mail is
     * sent, one request is taken, and one unit of the value's ceiling is used.
     */
    @Test
    fun eightRequestsAtOnceWithTheSameRightValue_takeOneRequest_sendOneMail_andUseOneUnitOfTheCeiling() = app { f ->
        val values = spendTheFive(f, f.real.email)
        val ceiling = "${Assisted.MAILBOX_BUCKET.name}:${Grammar.emailHash(f.real.email)}"
        val stored = valuesOf(f, f.real.email)
        val all = coroutineScope { (1..8).map { async { open(f, f.real.email, value = values[0]) } }.awaitAll() }
        assertEquals(1, all.map { shape(it) }.toSet().size)
        assertEquals(6, codeMails(f, f.real.email).size)
        assertEquals(1, all.count { requestUser(f, it) == f.real.userId })
        assertEquals(7, all.count { requestUser(f, it) == null })
        assertEquals(1, f.s.limiter.count(ceiling))
        // The value was used, and the one mail's value was stored.
        assertEquals(stored, valuesOf(f, f.real.email))
    }

    private fun createMetas(f: Fix, after: Long): List<String?> = f.s.db.read { c ->
        c.queryAll("SELECT meta FROM audit WHERE id>? AND type='recovery_request_create' ORDER BY id", after) { it.getString(1) }
    }

    private fun lastAuditId(f: Fix): Long = f.s.db.read { c -> c.queryOne("SELECT COALESCE(MAX(id),0) FROM audit") { it.getLong(1) }!! }

    private fun storeValue(f: Fix, email: String, value: String) {
        val emailHash = f.s.config.addressHash(email)
        f.s.db.tx { c -> c.exec("INSERT INTO recovery_mailbox_values(valueHash,emailHash,expiresAt) VALUES(?,?,?)", Assisted.mailboxHash(f.s, emailHash, value), emailHash, f.clock.now() + Assisted.MAILBOX_TTL_MS) }
    }

    @Test
    fun anAddresssValuesAreForgotten_whenItsAccountSwitchesToThePrivatePosture() = app { f ->
        val values = spendTheFive(f, f.real.email)
        open(f, f.other.email)
        assertEquals(5L, valuesOf(f, f.real.email))
        val body = """{"posture":"private","currentAuthKey":"${f.real.authKey}","accountState":{"sealedState":"AAAA","baseSeq":0}}"""
        val r = f.c.call(HttpMethod.Put, "/api/v1/account/recovery", body, f.real.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(0L, valuesOf(f, f.real.email))
        assertEquals(1L, valuesOf(f, f.other.email))
        // A value from before the switch does nothing past the five.
        val ceiling = "${Assisted.MAILBOX_BUCKET.name}:${Grammar.emailHash(f.real.email)}"
        val before = lastAuditId(f)
        val o = open(f, f.real.email, value = values[0])
        assertEquals(null, requestUser(f, o))
        assertEquals(0, f.s.limiter.count(ceiling))
        assertEquals(listOf<String?>("mailbox=not_used"), createMetas(f, before))
    }

    /**
     * An address whose account is in the private posture and that still holds a value (one stored by a server of the
     * version before, which did not forget at the switch): past the five a request that names it never uses it, never
     * draws the value's ceiling, records `mailbox=not_used`, and sends nothing more than a request without it.
     */
    @Test
    fun aRequestForAnAddressInThePrivatePosture_neverUsesAValue_norDrawsItsCeiling() = app { f ->
        val value = "STFFFLSS2345ABCD"
        storeValue(f, f.priv.email, value)
        repeat(5) { open(f, f.priv.email) }
        val notices = { Flow.sink(f.s).count { it.first == "recovery_request_private" } }
        val noticesBefore = notices()
        val ceiling = "${Assisted.MAILBOX_BUCKET.name}:${Grammar.emailHash(f.priv.email)}"
        val before = lastAuditId(f)
        val none = open(f, f.priv.email)
        val o = open(f, f.priv.email, value = value)
        assertEquals(1L, valuesOf(f, f.priv.email))
        assertEquals(0, f.s.limiter.count(ceiling))
        assertEquals(listOf(null, "mailbox=not_used"), createMetas(f, before))
        assertEquals(noticesBefore, notices())
        assertEquals(null, requestUser(f, o))
        assertEquals(shape(none), shape(o))
    }

    @Test
    fun aPasswordChangeKeepsTheAddresssValues_andOneStillTakesARequestPastTheFive() = app { f ->
        val values = spendTheFive(f, f.real.email)
        val body = """{"currentAuthKey":"${f.real.authKey}","newAuthKey":"${b32()}","newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA"}"""
        val r = f.c.call(HttpMethod.Put, "/api/v1/account/password", body, f.real.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(5L, valuesOf(f, f.real.email))
        val o = open(f, f.real.email, value = values[1])
        assertEquals(f.real.userId, requestUser(f, o))
        assertEquals(6, codeMails(f, f.real.email).size)
    }

    @Test
    fun anAddresssValuesAreForgotten_whenTheOperatorDeletesItsAccount() = app { f ->
        repeat(2) { open(f, f.real.email) }
        open(f, f.other.email)
        assertEquals(2L, valuesOf(f, f.real.email))
        val d = f.c.call(post, "/api/v1/admin/accounts/${f.real.userId}/disable", """{"reason":"request","currentAuthKey":"${f.op.authKey}"}""", f.op.token)
        assertEquals(200, d.status.value, d.bodyAsText())
        f.clock.advance(31 * Clock.DAY_MS)
        val token = f.s.db.tx { c -> f.s.sessions.issue(c, f.op.userId, f.op.deviceId, "linux", passwordLogin = true).accessToken }
        val r = f.c.call(post, "/api/v1/admin/accounts/${f.real.userId}/delete", """{"currentAuthKey":"${f.op.authKey}"}""", token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(0L, valuesOf(f, f.real.email))
        assertEquals(1L, valuesOf(f, f.other.email))
    }

    /** One request with the value of the newest code mail not yet used; returns whether a mail was sent. */
    private suspend fun byValue(f: Fix, email: String, unused: ArrayDeque<String>): Boolean {
        val before = codeMails(f, email).size
        open(f, email, value = unused.removeFirst())
        val mails = codeMails(f, email)
        if (mails.size == before) return false
        unused.addLast(valueIn(mails.last()))
        return true
    }

    private suspend fun plain(f: Fix, email: String, unused: ArrayDeque<String>): Boolean {
        val before = codeMails(f, email).size
        open(f, email)
        val mails = codeMails(f, email)
        if (mails.size == before) return false
        unused.addLast(valueIn(mails.last()))
        return true
    }

    /**
     * The bound as it is (spec 03 §18.1): each cap counts in a window of 24 hours that starts at the first request it
     * counts, and the address's window and the value's window start independently. Within one window of each, never more
     * than five mails by plain requests and five by values; across the windows' edges, up to twenty inside 24 hours.
     * The sequence: one plain request at t0; at t0 + 24 h - 60 s four plain and five by value; at t0 + 24 h + 1 ms five
     * plain (a sixth by value sends nothing); at t0 + 48 h - 60 s five by value (a plain one sends nothing). Twenty mails,
     * nineteen of them inside the closed 24 hours from t0 + 24 h - 60 s.
     */
    @Test
    fun theBound_fivePlusFivePerWindowOfEachCap_andAcrossTheWindowsEdgesNineteenInside24HoursInTheCheckedSequence() = app { f ->
        val e = f.real.email
        val unused = ArrayDeque<String>()
        val t0 = f.clock.ms
        val sent = ArrayList<Long>()
        suspend fun plainAt(t: Long, n: Int, expectSent: Boolean) = repeat(n) { f.clock.ms = t; assertEquals(expectSent, plain(f, e, unused), "plain at ${t - t0}"); if (expectSent) sent += t }
        suspend fun valueAt(t: Long, n: Int, expectSent: Boolean) = repeat(n) { f.clock.ms = t; assertEquals(expectSent, byValue(f, e, unused), "by value at ${t - t0}"); if (expectSent) sent += t }
        val d = Clock.DAY_MS
        plainAt(t0, 1, true)
        plainAt(t0 + d - 60_000, 4, true)
        plainAt(t0 + d - 60_000, 1, false)
        valueAt(t0 + d - 60_000, 5, true)
        valueAt(t0 + d - 60_000, 1, false)
        plainAt(t0 + d + 1, 5, true)
        plainAt(t0 + d + 1, 1, false)
        valueAt(t0 + d + 1, 1, false)
        valueAt(t0 + 2 * d - 60_000, 5, true)
        plainAt(t0 + 2 * d - 60_000, 1, false)
        valueAt(t0 + 2 * d - 60_000, 1, false)
        assertEquals(20, sent.size)
        assertEquals(20, codeMails(f, e).size)
        val from = t0 + d - 60_000
        assertEquals(19, sent.count { it in from..from + d })
    }

    /**
     * The most the windows allow inside 24 hours: five plain and five by value at t0, five plain and five by value at
     * exactly t0 + 24 h, when both windows start again. Twenty mails inside the closed 24 hours, ten of them past ten
     * through requests that name values; a twenty-first, plain or by value, sends nothing.
     */
    @Test
    fun theBound_atMostTwentyRequestMailsInsideAClosed24Hours() = app { f ->
        val e = f.real.email
        val unused = ArrayDeque<String>()
        val t0 = f.clock.ms
        repeat(5) { assertTrue(plain(f, e, unused)) }
        repeat(5) { assertTrue(byValue(f, e, unused)) }
        assertEquals(false, plain(f, e, unused))
        assertEquals(false, byValue(f, e, unused))
        f.clock.ms = t0 + Clock.DAY_MS
        repeat(5) { assertTrue(plain(f, e, unused)) }
        repeat(5) { assertTrue(byValue(f, e, unused)) }
        assertEquals(false, plain(f, e, unused))
        assertEquals(false, byValue(f, e, unused))
        assertEquals(20, codeMails(f, e).size)
    }

    /**
     * The address's window and the code mails' window start at one reading of the clock, so they lapse together. The
     * clock moves on at every reading while the first window's five requests run; the request at exactly the end of the
     * address's window is inside a fresh window of the address, and its mail is sent, never dropped by a mail cap whose
     * window started a few milliseconds later.
     */
    @Test
    fun theAddresssWindowAndTheCodeMailsWindowLapseTogether_atTheWindowsEdge() = app { f ->
        val e = f.real.email
        f.ticking.tick = 1
        spendTheFive(f, e)
        f.ticking.tick = 0
        assertEquals(5, codeMails(f, e).size)
        val start = assertNotNull(f.s.limiter.windowStart("${Assisted.ADDRESS_BUCKET.name}:${Grammar.emailHash(e)}"))
        f.clock.ms = start + Clock.DAY_MS
        val dropped = { f.s.db.read { c -> c.count("SELECT COUNT(*) FROM audit WHERE type='email_dropped'") } }
        val droppedBefore = dropped()
        val o = open(f, e)
        assertEquals(f.real.userId, requestUser(f, o))
        assertEquals(6, codeMails(f, e).size)
        assertEquals(droppedBefore, dropped())
    }

    private fun requestHash(f: Fix, o: Opened): String =
        f.s.db.read { c -> c.queryOne("SELECT emailHash FROM recovery_requests WHERE requestId=?", o.requestId) { it.getString(1) }!! }

    /**
     * A request's row, real or decoy, and the mailbox values its mail carried keep the address's keyed hash (decided on
     * 2026-11-17). Before, a decoy kept the plain SHA-256 of an address that has no account for a day, so whoever read
     * the table could confirm a guessed address that someone had typed. The rows of one address still tie together.
     */
    @Test
    fun requestRowsRealAndDecoy_andTheirMailboxValues_keepTheAddressKeyed() = app { f ->
        val nobody = "nobody@example.com"
        val emails = listOf(f.real.email, nobody, f.other.email)
        val real = listOf(open(f, f.real.email), open(f, f.real.email)).map { requestHash(f, it) }
        val decoy = listOf(open(f, nobody), open(f, nobody)).map { requestHash(f, it) }
        val other = requestHash(f, open(f, f.other.email))
        for (v in real + decoy + other) for (e in emails) assertTrue(v != sha256Hex(e), "a request row keeps the plain hash of $e")
        assertEquals(real[0], real[1])
        assertEquals(decoy[0], decoy[1])
        assertEquals(3, setOf(real[0], decoy[0], other).size, "three addresses, three values")
        val values = f.s.db.read { c -> c.queryAll("SELECT emailHash FROM recovery_mailbox_values") { it.getString(1) } }
        assertEquals(listOf(real[0], real[0], other).sorted(), values.sorted(), "each real request's value, under its address's value; a decoy stores none")
    }

    /**
     * A value mailed before the keyed hash was stored with the plain hash of its address: it still takes a request past
     * the five until it expires, and goes with the address's other values when the account switches to the private
     * posture, so that an upgrade of the server takes no one's way out away.
     */
    @Test
    fun aValueStoredWithThePlainHashBefore_stillTakesTheRequest_andIsForgottenWithItsAddress() = app { f ->
        val plain = Grammar.emailHash(f.real.email)
        fun storeBefore(value: String) = f.s.db.tx { c ->
            c.exec("INSERT INTO recovery_mailbox_values(valueHash,emailHash,expiresAt) VALUES(?,?,?)", Assisted.mailboxHash(f.s, plain, value), plain, f.clock.now() + Assisted.MAILBOX_TTL_MS)
        }
        fun plainRows() = f.s.db.read { c -> c.count("SELECT COUNT(*) FROM recovery_mailbox_values WHERE emailHash=?", plain) }
        storeBefore("ABCDEFGHJKLMNPQR")
        storeBefore("STUVWXYZ23456789")
        spendTheFive(f, f.real.email)
        val taken = open(f, f.real.email, value = "ABCD EFGH JKLM NPQR")
        assertEquals(f.real.userId, requestUser(f, taken))
        assertEquals(1L, plainRows(), "the value used is gone, the other stays")
        val body = """{"posture":"private","currentAuthKey":"${f.real.authKey}","accountState":{"sealedState":"AAAA","baseSeq":0}}"""
        val r = f.c.call(HttpMethod.Put, "/api/v1/account/recovery", body, f.real.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        assertEquals(0L, plainRows())
        assertEquals(0L, valuesOf(f, f.real.email))
    }
}
