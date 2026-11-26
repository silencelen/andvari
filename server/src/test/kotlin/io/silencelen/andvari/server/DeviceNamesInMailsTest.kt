package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.RecoveryRequestCreated
import io.silencelen.andvari.core.model.wire.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A mail's rows about a device show the name the device gave itself (decided on 22 November 2026), in quotation marks,
 * cut to forty characters and marked as the device's own words ([MailDevices.name]). The name is chosen by whoever signs
 * in on the device, claims a device link or applies a recovery, so a mail shows only its letters and digits of any
 * alphabet, its spaces, apostrophes and hyphens: every other character becomes a space, and so do 26 letters that are
 * drawn like punctuation. A name can then hold no working web address, no working mail address, no line of its own and
 * no markup; a telephone number stays possible. These tests hold the
 * function to its rules, one name at a time, and then send every mail that has a row about a device through the server's
 * real routes with each hostile name on every device involved, reading both parts of each mail.
 *
 * Every character of a test's name that is not plain ASCII is written as its code point ([s]), so that no invisible or
 * direction-changing character stands in this file itself.
 */
class DeviceNamesInMailsTest {
    private val post = HttpMethod.Post
    private fun b32() = Bytes.toB64(TestKit.crypto.randomBytes(32))
    private fun id16() = Bytes.toB64(TestKit.crypto.randomBytes(16))
    private fun s(vararg cps: Int): String = cps.joinToString("") { String(Character.toChars(it)) }
    private fun json(x: String): String = JsonPrimitive(x).toString()
    private val kdf = """"newKdfSalt":"${Bytes.toB64(ByteArray(16) { 5 })}","newKdfParams":{"v":1,"alg":"argon2id13","ops":1,"memBytes":8388608},"newWrappedUvk":"AAAA""""

    /** A name shown whole, and a name shown cut, as the function gives them. */
    private fun whole(t: String) = "\"$t\" ${MailDevices.NAMED_ITSELF}"
    private fun cut(t: String) = "\"$t\" ${MailDevices.NAME_CUT}"

    /**
     * Five hostile names, each as the name a device holds and as the text of a link's claim: r1 a sentence with a link,
     * r2 two hundred spaces before a "Help:" line, r3 a hundred wide spaces before one, r4 Cyrillic letters that look like
     * Latin ones, r5 a name that fakes a kind of app.
     */
    private val r1 = "Pixel. Your account was closed. Sign in at https://evil.example/reset to reopen it" to "Ignore this. Call 555 0100 https://evil.example/r"
    private val r2 = ("Pixel" + " ".repeat(200) + "Help: https://evil.example/help/compromised/") to ("Pixel" + " ".repeat(20) + "Help: https://evil.example/h")
    private val r3 = ("Pixel" + s(0x3000).repeat(100) + "Help: https://evil.example/help/compromised/") to ("Pixel" + s(0x3000).repeat(10) + "Help: evil.example/h")
    private val lookAlike = s(0x430) + "ndv" + s(0x430) + "ri support"
    private val r4 = lookAlike to lookAlike
    private val r5 = "office laptop (windows)" to "office laptop (windows)"

    /** A name of 10,000 characters, as an older database or a restored file can hold one (the routes take 256). */
    private val long = ("Qzxv " + "Pixel ".repeat(1_665) + "Vkyp!").also { check(it.length == 10_000) }

    /** Names in four scripts, with their marks: Chinese, Arabic (two words), Devanagari with a nukta and a vowel sign. */
    private val scripts = s(0x5F20, 0x4F1F, 0x7684, 0x624B, 0x673A) + " " + s(0x647, 0x627, 0x62A, 0x641) + " " + s(0x623, 0x62D, 0x645, 0x62F) + " " +
        s(0x92B, 0x93C, 0x94B, 0x928)

    /** Each name a test gives the function, and what a mail shows of it (null: the row without a name). */
    private val table: List<Triple<String, String, String?>> = listOf(
        Triple("the owner's example: a name with a dot", "Jordan's Pixel 8.1", whole("Jordan's Pixel 8 1")),
        Triple("an emoji", "Jordan's Pixel " + s(0x1F525), whole("Jordan's Pixel")),
        Triple("an emoji of several joined", s(0x1F468, 0x200D, 0x1F469, 0x200D, 0x1F467) + " Phone", whole("Phone")),
        Triple("a web address", "https://evil.example/login", whole("https evil example login")),
        Triple("a mail address", "help@evil.example", whole("help evil example")),
        Triple("a telephone number, which stays", "+1 (555) 010-0199", whole("1 555 010-0199")),
        Triple("r1: a sentence with a link", r1.first, cut("Pixel Your account was closed Sign in at")),
        Triple("r1: its claim", r1.second, cut("Ignore this Call 555 0100 https evil exa")),
        Triple("r2: 200 spaces before Help:", r2.first, cut("Pixel Help https evil example help compr")),
        Triple("r2: its claim", r2.second, whole("Pixel Help https evil example h")),
        Triple("r3: 100 wide spaces before Help:", r3.first, cut("Pixel Help https evil example help compr")),
        Triple("r3: its claim", r3.second, whole("Pixel Help evil example h")),
        Triple("r4: look-alike letters, which are letters", r4.first, whole(lookAlike)),
        Triple("r5: a faked kind of app", r5.first, whole("office laptop windows")),
        Triple("200 spaces before a line that begins Help:", " ".repeat(200) + "\nHelp: https://evil.example/help/compromised/", whole("Help https evil example help compromised")),
        Triple("100 wide spaces before a line that begins Help:", s(0x3000).repeat(100) + "\nHelp: https://evil.example/help/compromised/", whole("Help https evil example help compromised")),
        Triple("a line break inside a name", "Jordan's\nHelp: https://evil.example/", whole("Jordan's Help https evil example")),
        Triple("every other kind of break", "a\r\nb" + s(0x2028) + "c" + s(0x2029) + "d" + s(0x85) + "e\tf" + s(0x0B) + "g", whole("a b c d e f g")),
        Triple("zero-width joiners and their kin", "Pi" + s(0x200D) + "xel" + s(0x200C) + "9" + s(0x200B) + "x" + s(0x2060) + "y" + s(0xFEFF) + "z", whole("Pi xel 9 x y z")),
        Triple("a right-to-left override", s(0x202E) + "gnp.exe Pixel", whole("gnp exe Pixel")),
        Triple("direction isolates and marks", "Pixel " + s(0x2067) + "abc" + s(0x2069, 0x200F, 0x061C), whole("Pixel abc")),
        Triple("a name of marks only", s(0x301, 0x302, 0x303, 0x304), null),
        Triple("one letter with 20 marks", "q" + s(0x301).repeat(20), whole("q" + s(0x301).repeat(3))),
        Triple("one letter with 20 marks, the first of which composes", "a" + s(0x301).repeat(20), whole(s(0xE1) + s(0x301).repeat(3))),
        Triple("64 bytes of letters of 4 bytes each", s(0x10400).repeat(16), whole(s(0x10400).repeat(16))),
        Triple("41 letters of 4 bytes each", s(0x10400).repeat(41), cut(s(0x10400).repeat(40))),
        Triple("the fortieth character inside a letter's marks", "a".repeat(39) + "q" + s(0x301, 0x302, 0x303) + "z", cut("a".repeat(39) + "q" + s(0x301, 0x302, 0x303))),
        Triple("forty characters exactly", "a".repeat(40), whole("a".repeat(40))),
        Triple("forty-one characters", "a".repeat(41), cut("a".repeat(40))),
        Triple("a space left at the end by the cut", "a".repeat(39) + " bbb", cut("a".repeat(39))),
        Triple("a quotation mark inside a name", "My \"work\" phone", whole("My 'work' phone")),
        Triple(
            "other quotation marks",
            s(0x201C) + "Jordan" + s(0x2019) + "s" + s(0x201D) + " " + s(0xAB) + "Pixel" + s(0xBB) + " " + s(0x300C) + "A" + s(0x300D) + " `b" + s(0xB4) + " " +
                s(0x2BB) + "c" + s(0x2BC) + " " + s(0xFF02) + "d" + s(0xFF07) + " " + s(0x2039) + "e" + s(0x203A),
            whole("'Jordan's' 'Pixel' 'A' 'b' 'c' 'd' 'e'"),
        ),
        Triple(
            "the rest of the quotation marks",
            s(0x201E) + "f" + s(0x201F) + " " + s(0x201A) + "g" + s(0x201B) + " " + s(0x300E) + "h" + s(0x300F) + " " + s(0x2B9) + "i" + s(0x2BA) + " " + s(0x2018) + "j" + s(0x2019),
            whole("'f' 'g' 'h' 'i' 'j'"),
        ),
        Triple("the hyphens, and dashes that are not", "Jean" + s(0x2010) + "Luc" + s(0x2011) + "X a" + s(0x2013) + "b" + s(0x2014) + "c" + s(0x2212) + "d", whole("Jean-Luc-X a b c d")),
        Triple("other kinds of space", "Jordan" + s(0xA0) + "Pixel" + s(0x2009) + "X" + s(0x3000) + "Y", whole("Jordan Pixel X Y")),
        Triple("a lone surrogate", "Pix" + s(0xD800) + "el", whole("Pix el")),
        Triple("letters that draw a blank", "Pixel" + s(0x3164, 0x3164) + "Help" + s(0x115F), whole("Pixel Help")),
        Triple("a variation selector after a letter, which draws nothing", "a" + s(0xFE0F) + "b", whole("ab")),
        Triple("an ideographic variation selector inside a word", s(0x845B, 0xE0100, 0x98FE), whole(s(0x845B, 0x98FE))),
        Triple("Mongolian free variation selectors inside a word", s(0x1820, 0x180B, 0x1821, 0x180C, 0x1822, 0x180D), whole(s(0x1820, 0x1821, 0x1822))),
        Triple("a combining grapheme joiner inside a word", "a" + s(0x34F) + "b", whole("ab")),
        Triple("the Khmer inherent vowels inside a word", s(0x1780, 0x17B4, 0x1781, 0x17B5), whole(s(0x1780, 0x1781))),
        Triple("a variation selector after a space", "a " + s(0xFE0F) + "b", whole("a b")),
        Triple("a mark after a variation selector composes with its letter", "a" + s(0xFE0F, 0x301) + "b", whole(s(0xE1) + "b")),
        Triple("a mark after a combining grapheme joiner composes with its letter", "e" + s(0x34F, 0x300), whole(s(0xE8))),
        Triple(
            "letters drawn like a colon, a slash and a full stop, making a Help line with an address",
            "Help" + s(0xA4FD) + " https" + s(0xA4FD, 0x141F, 0x141F) + "evil" + s(0xA4F8) + "example" + s(0x141F),
            whole("Help https evil example"),
        ),
        Triple("letters drawn like a colon, making a fake time", "Pixel 8 Time" + s(0xA4FD) + " 2026-11-22 10" + s(0xA4FD) + "00 UTC", whole("Pixel 8 Time 2026-11-22 10 00 UTC")),
        Triple("a name of look-alike letters and spaces only", s(0xA4F8, 0x20, 0x141F, 0x1C0, 0x20, 0x2D0, 0xA78F), null),
        Triple("a mark after a look-alike letter", "a" + s(0x1C0, 0x301) + "b", whole("a b")),
        Triple(
            "letters drawn like a slash or an apostrophe that stay",
            "a" + s(0x30CE) + "b" + s(0x4E3F) + "c" + s(0x7F4) + "d" + s(0x7F5) + "e" + s(0xA78C) + "f",
            whole("a" + s(0x30CE) + "b" + s(0x4E3F) + "c" + s(0x7F4) + "d" + s(0x7F5) + "e" + s(0xA78C) + "f"),
        ),
        Triple("digits that are not decimal digits", "Pixel " + s(0xB2) + " " + s(0x2167) + " " + s(0x663), whole("Pixel " + s(0x663))),
        Triple("markup", "<b>x</b> & \"q\"", whole("b x b 'q'")),
        Triple("a mark after a hyphen, and an enclosing mark", "a-" + s(0x301) + "b 1" + s(0x20E3), whole("a- b 1")),
        Triple("letters of other scripts, with their marks", scripts, whole(scripts)),
        Triple("a decomposed letter, composed", "Jose" + s(0x301), whole("Jos" + s(0xE9))),
        Triple("a name of 10,000 characters", long, cut("Qzxv Pixel Pixel Pixel Pixel Pixel Pixel")),
        Triple("an empty name", "", null),
        Triple("a name of spaces only", "   ", null),
        Triple("a name of blanks of every kind", s(0x3000, 0xA0) + "\t\n" + s(0x200B), null),
        Triple("a name of emoji only", s(0x1F525, 0x1F525), null),
        Triple("a name of punctuation only", "...", null),
        Triple("a name of one apostrophe", "'", null),
        Triple("a name of one hyphen", "-", null),
        Triple("a name of apostrophes, hyphens and spaces", "' - ''--  '", null),
        Triple("a name of apostrophes and hyphens between other characters", "!'-!" + s(0x2010) + "?" + s(0x201C), null),
        Triple("a name of which the cut leaves only hyphens", "-".repeat(50) + "abc", null),
        Triple("a letter with an apostrophe and a hyphen, which stays", "a-'", whole("a-'")),
    )

    /**
     * The function, name by name: what a mail shows of each. Every result is also one line as every value of a mail is
     * ([MailTemplates.oneLine] leaves it as it is), and holds between its quotation marks only letters, decimal digits,
     * combining marks after them, spaces, apostrophes and hyphens: no address, no line, no markup.
     */
    @Test
    fun whatAMailShowsOfAName_nameByName() {
        val wrong = ArrayList<String>()
        for ((what, stored, expected) in table) {
            val got = MailDevices.name(stored)
            if (got != expected) wrong += "$what: expected <$expected>, got <$got>"
        }
        assertTrue(wrong.isEmpty(), wrong.joinToString("\n"))
        assertNull(MailDevices.name(null))
        check(s(0x10400).repeat(16).toByteArray(Charsets.UTF_8).size == 64)
        for ((what, stored, _) in table) {
            val got = MailDevices.name(stored) ?: continue
            assertEquals(got, MailTemplates.oneLine(got), what)
            val inner = got.removePrefix("\"").substringBeforeLast("\" (")
            var i = 0
            while (i < inner.length) {
                val cp = inner.codePointAt(i)
                i += Character.charCount(cp)
                val t = Character.getType(cp).toByte()
                val ok = cp == 0x20 || cp == 0x27 || cp == 0x2D || t == Character.DECIMAL_DIGIT_NUMBER || t == Character.NON_SPACING_MARK ||
                    t == Character.COMBINING_SPACING_MARK || t in setOf(Character.UPPERCASE_LETTER, Character.LOWERCASE_LETTER, Character.TITLECASE_LETTER, Character.MODIFIER_LETTER, Character.OTHER_LETTER)
                assertTrue(ok, "$what: U+%04X in <$got>".format(cp))
            }
            for (no in listOf("://", "@", ".", "/", ":", "\n", "<", ">", "&", "\"")) assertFalse(no in inner, "$what: <$got> holds $no")
            assertFalse(inner.startsWith(" ") || inner.endsWith(" ") || "  " in inner, what)
        }
    }

    /**
     * The 26 letters that are drawn like a full stop, a colon, a slash or an apostrophe (decided on 22 November 2026):
     * the six tone letters of the Lisu alphabet, twelve small raised signs of the Canadian syllabics, the four click
     * letters, two letters drawn like a colon, one like a doubled apostrophe and one like a raised dot.
     */
    private val lookAlikes = (0xA4F8..0xA4FD) + (0x141E..0x1428) + listOf(0x18DF) + (0x1C0..0x1C3) + listOf(0x2D0, 0x2D1, 0x2EE, 0xA78F)

    /**
     * Each of the 26 becomes a space in a device's name: alone it leaves no name, and at the start, at the end and between
     * two letters it is a space, which the rule for spaces then joins with its neighbours or takes off the ends.
     */
    @Test
    fun eachLookAlikeLetter_becomesASpace() {
        assertEquals(26, lookAlikes.toSet().size)
        val wrong = ArrayList<String>()
        for (cp in lookAlikes) {
            val c = s(cp)
            val cases = listOf(c to null, (c + "ab") to whole("ab"), ("ab" + c) to whole("ab"), ("a" + c + "b") to whole("a b"), ("a " + c + " b") to whole("a b"))
            for ((stored, expected) in cases) {
                val got = MailDevices.name(stored)
                if (got != expected) wrong += "U+%04X: expected <$expected>, got <$got>".format(cp)
            }
        }
        assertTrue(wrong.isEmpty(), "${wrong.size} wrong:\n" + wrong.take(10).joinToString("\n"))
    }

    /** The two names drawn like a Help line with an address and like a time, on every road, in both parts of each mail. */
    @Test
    fun lookAlikeLetters_aHelpLineAndAFakeTime_onEveryRoad() {
        for (what in listOf("letters drawn like a colon, a slash and a full stop, making a Help line with an address", "letters drawn like a colon, making a fake time")) {
            val stored = table.first { it.first == what }.second
            onlyTheRowsGainTheName(stored, stored)
        }
    }

    /**
     * Over names generated with a fixed seed, from an alphabet of letters of three scripts, digits, a space, the apostrophe,
     * the hyphen, three combining marks, the first and last code point of each range of marks that draw nothing, the
     * Mongolian vowel separator and U+180F, three invisible format characters, a letter outside the first plane, the 26
     * look-alike letters and the five that stay: no name shown holds one of the 26, every name shown is in the composed
     * form (NFC), and the function gives the text it shows back unchanged.
     */
    @Test
    fun everyNameShownIsComposed_givesItselfBack_andHoldsNoLookAlike_overGeneratedNames() {
        val alphabet = listOf(
            'a'.code, 'e'.code, 'q'.code, 'Z'.code, 0x3B1, 0x430, 0x845B, 0x98FE, '1'.code, '9'.code, 0x20, 0x27, 0x2D,
            0x301, 0x300, 0x302,
            0x34F, 0x17B4, 0x17B5, 0x180B, 0x180D, 0xFE00, 0xFE0F, 0xE0100, 0xE01EF,
            0x180E, 0x180F, 0x200B, 0x202E, 0xFEFF, 0x10400,
            0x30CE, 0x4E3F, 0x7F4, 0x7F5, 0xA78C,
        ) + lookAlikes
        val banned = lookAlikes.toSet()
        val random = java.util.Random(20_261_122L)
        val count = 100_000
        val started = System.nanoTime()
        val wrong = ArrayList<String>()
        fun inner(shown: String) = shown.removePrefix("\"").substringBeforeLast("\" (")
        repeat(count) {
            val stored = s(*IntArray(1 + random.nextInt(60)) { alphabet[random.nextInt(alphabet.size)] })
            val got = MailDevices.name(stored) ?: return@repeat
            val text = inner(got)
            val again = MailDevices.name(text)?.let(::inner)
            if (!java.text.Normalizer.isNormalized(text, java.text.Normalizer.Form.NFC) || again != text || text.codePoints().anyMatch { it in banned }) {
                if (wrong.size < 5) wrong += stored.codePoints().toArray().joinToString(" ") { "U+%04X".format(it) } + " -> <$text> again <$again>"
                else wrong += ""
            }
        }
        println("Generated names: $count in ${(System.nanoTime() - started) / 1_000_000} ms; holding a look-alike, not composed or not given back: ${wrong.size}")
        assertTrue(wrong.isEmpty(), "${wrong.size} names, among them:\n" + wrong.take(5).joinToString("\n"))
    }

    /**
     * The kind of app is a word of the server's own: every value of the closed platform list has fixed words of its own,
     * and any other text the platform column could hold (a row of an older database, a restored file) gets the one
     * fallback, never itself. The name follows the kind; a device that was there before has the day and the time the
     * server added it, in UTC.
     */
    @Test
    fun everyKindOfAppHasTheServersOwnWords_andTheNameFollowsThem() {
        val all = io.silencelen.andvari.core.model.wire.WirePlatform.ALL
        for (p in all) assertTrue(MailDevices.kind(p) !== MailDevices.UNKNOWN, p)
        assertEquals(all.size, all.map { MailDevices.kind(it).word }.toSet().size)
        assertEquals(all.size, all.map { MailDevices.kind(it).app }.toSet().size)
        for (p in listOf("Android", "android ", "", "office laptop (windows)", "ios\nHelp: x", "web<b>", "linux" + s(0x200D), null)) {
            assertTrue(MailDevices.kind(p) === MailDevices.UNKNOWN, "$p")
        }
        val at = Instant.parse("2026-10-02T23:30:00Z").toEpochMilli()
        assertEquals("an app of unknown kind added on 2026-10-02 23:30 UTC, " + whole("office laptop"), MailDevices.words(MailDevice("office laptop (windows)", "office laptop", "password", at, isNew = false)))
        assertEquals("Unknown (as the device reported it), " + whole("evil example"), MailDevices.words(MailDevice("evil.example", "evil.example", "password", at, isNew = true)))
        assertEquals("the Android app added on 2026-10-02 23:30 UTC", MailDevices.words(MailDevice("android", s(0x1F525), "password", at, isNew = false)))
        assertEquals("Android (as the device reported it)", MailDevices.words(MailDevice("android", null, "password", at, isNew = true)))
    }

    /** One mail as the outbox holds it. */
    private class Sent(val template: String, val subject: String, val text: String, val html: String) {
        /** The value of the plain text's row [label], or null when the mail has no such row. */
        fun row(label: String): String? = text.lines().firstOrNull { it.startsWith("$label: ") }?.removePrefix("$label: ")

        /** The value of the HTML part's row [label] as it stands in the source, entities and all. */
        fun htmlSource(label: String): String? = html.indexOf("$label:&nbsp;</td>").takeIf { it >= 0 }?.let { i ->
            html.substring(i).substringAfter("</td>").substringAfter('>').substringBefore("</td>")
        }

        /** The value of the HTML part's row [label], as a reader sees it (its entities read). */
        fun htmlRow(label: String): String? = htmlSource(label)
            ?.replace("&lt;", "<")?.replace("&gt;", ">")?.replace("&quot;", "\"")?.replace("&#39;", "'")?.replace("&amp;", "&")
    }

    /** Every mail the instance queued, read from the outbox before the sender takes it. */
    private class Outbox(val s: Services) {
        val mails = ArrayList<Sent>()
        private val seen = HashSet<Long>()

        fun collect() {
            s.db.read { c ->
                c.queryAll("SELECT id,template,subject,text,html FROM mail_outbox ORDER BY id") { it.getLong(1) to Sent(it.getString(2), it.getString(3), it.getString(4), it.getString(5)) }
            }.forEach { (id, m) -> if (seen.add(id)) mails += m }
        }

        /** What the sender delivers ([Flow.sink]), after every queued mail was read here. */
        fun sink(): List<Triple<String, String, String>> { collect(); return Flow.sink(s) }
    }

    /** When the server added [deviceId], as a mail says it. */
    private fun addedOf(s: Services, deviceId: String): String =
        Mail.utc(s.db.read { c -> c.queryOne("SELECT createdAt FROM devices WHERE deviceId=?", deviceId) { it.getLong(1) } }!!)

    private fun fresh(s: Services, userId: String, deviceId: String): String =
        s.db.tx { c -> s.sessions.issue(c, userId, deviceId, "linux", passwordLogin = true).accessToken }

    private suspend fun signIn(c: HttpClient, me: Me, authKey: String, name: String, platform: String): SessionResponse {
        val r = c.call(post, "/api/v1/auth/login", """{"email":"${me.email}","authKey":"$authKey","device":{"platform":"$platform","name":${json(name)},"deviceSecret":"${b32()}"}}""")
        assertEquals(200, r.status.value, r.bodyAsText())
        return WireJson.json.decodeFromString(SessionResponse.serializer(), r.bodyAsText())
    }

    /** What one run of [road] sent, and when the server added each of its devices. */
    private class Road(val mails: List<Sent>, val first: String, val second: String, val linked: String, val recovered: String)

    /**
     * Every road that sends a mail about a device, with [name] as the name of every device involved: written on every
     * device row before each step, and sent in each request that names a device (a sign-in, a recovery's commit) where the
     * route takes it, else the plain name "Qzxv". A device link is claimed under [claimText], or "Qzxv" where it is not a
     * name a claim can carry (more than 64 bytes, a refused character).
     */
    private fun road(name: String, claimText: String): Road {
        var result: Road? = null
        testApplication {
            val clock = MutableClock()
            val key = TestKit.Identity().curvePub
            val s = TestKit.services(TestKit.config(recoveryKey = key), clock)
            application { andvariModule(s) }
            val c = client
            val op = Flow.finishSetup(c, s)
            val me = Me("me@example.com")
            Flow.register(c, s, me, Flow.enrolAuth(s), "operator", Flow.escrow(me, sha256Hex(key)))
            val box = Outbox(s)
            box.sink()
            box.mails.clear()
            val asked = if (Grammar.isText(name)) name else "Qzxv"
            fun nameEveryDevice() = s.db.tx { it.exec("UPDATE devices SET name=?", name) }
            val first = me.deviceId

            // A password sign-in on a new device, as a Mac.
            nameEveryDevice()
            val second = signIn(c, me, me.authKey, asked, "macos")

            // A device link claimed by a device that is not signed in, as Android; approved by the first device; picked up.
            nameEveryDevice()
            val linkId = id16()
            assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 3_600_000}}""", me.token).status.value)
            val proof = b32()
            val claimName = Grammar.nameOf(claimText) ?: Grammar.nameOf("Qzxv")!!
            val claim = """{"nPub":"${b32()}","name":"$claimName","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}"""
            assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/claim", claim).status.value)
            assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", me.token).status.value)
            assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
            assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", me.token).status.value)
            val pk = c.call(post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${me.authKey}","device":{"deviceSecret":"${b32()}"}}""")
            assertEquals(200, pk.status.value, pk.bodyAsText())
            val linked = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse.serializer(), pk.bodyAsText()).session.deviceId

            // The first device removes the linked one; the operator removes the Mac.
            nameEveryDevice()
            clock.advance(13_000)
            assertEquals(200, c.call(post, "/api/v1/account/devices/$linked/revoke", """{"currentAuthKey":"${me.authKey}"}""", fresh(s, me.userId, first)).status.value)
            nameEveryDevice()
            clock.advance(13_000)
            assertEquals(200, c.call(post, "/api/v1/admin/devices/${second.deviceId}/revoke", """{"currentAuthKey":"${op.authKey}"}""", fresh(s, op.userId, op.deviceId)).status.value)

            // A recovery request opened (as the browser extension) and cancelled by the first device.
            suspend fun openVerified(platform: String): Triple<String, String, String> {
                val poll = TestKit.crypto.randomBytes(32)
                val rPub = b32()
                val body = """{"email":"${me.email}","rPub":"$rPub","pollHash":"${sha256Hex(poll)}","platform":"$platform"}"""
                val reqId = WireJson.json.decodeFromString(RecoveryRequestCreated.serializer(), c.call(post, "/api/v1/recovery/requests", body).bodyAsText()).requestId
                val code = Flow.codeIn(box.sink().last { it.first == "recovery_request_code" }.third)
                assertEquals(200, c.call(post, "/api/v1/recovery/requests/$reqId/verify", """{"code":"$code"}""").status.value)
                return Triple(reqId, Bytes.toB64(poll), rPub)
            }
            nameEveryDevice()
            val (vetoed, _, _) = openVerified("extension")
            val veto = """{"statement":"${Bytes.toB64(me.identity.frame(10, """{"v":2,"purpose":"recovery-veto","requestId":"$vetoed","userId":"${me.userId}","issuedAt":1800000000000}"""))}"}"""
            assertEquals(200, c.call(post, "/api/v1/recovery/requests/$vetoed/veto", veto, fresh(s, me.userId, first)).status.value)

            // A recovery with the operator's help, committed by a new device that names itself (iPhone).
            nameEveryDevice()
            val (reqId, poll, rPub) = openVerified("android")
            clock.advance(Assisted.HOLD_MS)
            val commit = TestKit.crypto.randomBytes(32)
            val sealed = Bytes.toB64(TestKit.crypto.randomBytes(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(me.email)))
            val commitHash = io.silencelen.andvari.core.trust.AssistedRecovery.commitHash(TestKit.crypto, commit)
            val fulfil = c.call(post, "/api/v1/admin/recovery-requests/$reqId/fulfil", """{"sealed":"$sealed","requestKey":"$rPub","commitHash":"$commitHash","currentAuthKey":"${op.authKey}"}""", fresh(s, op.userId, op.deviceId))
            assertEquals(200, fulfil.status.value, fulfil.bodyAsText())
            val key1 = b32()
            val kitKey = b32()
            val assisted = c.call(
                post, "/api/v1/recovery/requests/$reqId/commit",
                """{"pollSecret":"$poll","commit":"${Bytes.toB64(commit)}","newAuthKey":"$key1",$kdf,"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"$kitKey"},"device":{"platform":"ios","name":${json(asked)},"deviceSecret":"${b32()}"}}""",
            )
            assertEquals(200, assisted.status.value, assisted.bodyAsText())
            val recovered = WireJson.json.decodeFromString(SessionResponse.serializer(), assisted.bodyAsText()).deviceId

            // The recovered device changes the recovery settings, the master password, and turns two-step sign-in off.
            nameEveryDevice()
            clock.advance(13_000)
            val posture = c.call(HttpMethod.Put, "/api/v1/account/recovery", """{"posture":"private","currentAuthKey":"$key1","accountState":{"sealedState":"AAAA","baseSeq":0}}""", fresh(s, me.userId, recovered))
            assertEquals(200, posture.status.value, posture.bodyAsText())
            nameEveryDevice()
            clock.advance(13_000)
            val key2 = b32()
            assertEquals(200, c.call(HttpMethod.Put, "/api/v1/account/password", """{"currentAuthKey":"$key1","newAuthKey":"$key2",$kdf}""", fresh(s, me.userId, recovered)).status.value)
            nameEveryDevice()
            val totp = "JBSWY3DPEHPK3PXP"
            s.db.tx { it.exec("UPDATE users SET totpSecret=?, totpEnrolledAt=1, totpLastStep=0 WHERE userId=?", totp, me.userId) }
            clock.advance(13_000)
            val off = c.call(post, "/api/v1/account/totp/disable", """{"code":"${Flow.totp(totp, clock.now())}","currentAuthKey":"$key2"}""", fresh(s, me.userId, recovered))
            assertEquals(200, off.status.value, off.bodyAsText())

            // A kit recovery by a new device that names itself (Windows), two-step sign-in and "New devices must be linked" on.
            nameEveryDevice()
            s.db.tx { it.exec("UPDATE users SET totpSecret=?, totpEnrolledAt=1, totpLastStep=0, requireLink=1 WHERE userId=?", totp, me.userId) }
            val v = WireJson.json.decodeFromString(
                RecoveryVerifyResponse.serializer(),
                c.call(post, "/api/v1/recovery/self/verify", """{"email":"${me.email}","recoveryAuthKey":"$kitKey"}""").bodyAsText(),
            )
            val kit = c.call(
                post, "/api/v1/recovery/self/commit",
                """{"recoveryTicket":"${v.recoveryTicket}","newAuthKey":"${b32()}",$kdf,"newMemberRecovery":{"recoveryWrappedUvk":"AAAA","recoveryAuthKey":"${b32()}"},"device":{"platform":"windows","name":${json(asked)},"deviceSecret":"${b32()}"}}""",
            )
            assertEquals(200, kit.status.value, kit.bodyAsText())
            box.sink()
            result = Road(box.mails.toList(), addedOf(s, first), addedOf(s, second.deviceId), addedOf(s, linked), addedOf(s, recovered))
        }
        return result!!
    }

    /** The same roads with a name of which a mail shows nothing: every row as it is without a name. */
    private val unnamed: Road get() = unnamedRoads ?: road("...", "...").also { unnamedRoads = it }

    /** The mails whose code and mailbox value are new on every road, so that two roads' copies of them differ anyway. */
    private val codeMails = setOf("signup_code", "recovery_request_code")

    private val labels = listOf("Device", "Removed", "By", "How")
    private fun masked(x: String) = x.replace(Regex("[0-9a-f]{32}"), "ACCOUNT-ID")

    /**
     * The roads with [name] (and a link claimed under [claimText]) against the same roads with no name: in both parts of
     * every mail the name adds only its own words at the end of a row about a device, as the function gives them, and
     * nothing else (no line, no tag, no entity, no other change); the subject holds no name. Returns the hostile run.
     */
    private fun onlyTheRowsGainTheName(name: String, claimText: String): Road {
        val named = road(name, claimText)
        val asked = if (Grammar.isText(name)) name else "Qzxv"
        val claimed = Grammar.nameOf(claimText)?.let { claimText } ?: "Qzxv"
        val shown = listOf(name, asked, claimed).mapNotNull { MailDevices.name(it) }.distinct().sortedByDescending { it.length }
        val bare = unnamed.mails
        assertEquals(bare.map { it.template }, named.mails.map { it.template })
        for (t in listOf("new_device", "device_removed", "recovery_request_open", "recovery_request_cancelled", "recovery_applied", "recovery_changed", "password_changed", "two_step_off", "require_link_cleared")) {
            assertTrue(t in named.mails.map { it.template }, "$t was sent")
        }
        var rowsWithAName = 0
        for ((m, b) in named.mails.zip(bare)) {
            val what = "${m.template} with <$name>"
            assertEquals(b.subject, m.subject, what)
            for (n in shown) assertFalse(n.removePrefix("\"").substringBeforeLast("\" (") in m.subject, "$what: the subject holds the name")
            assertEquals(b.text.lines().size, m.text.lines().size, "$what: the name made a line of its own:\n${m.text}")
            var text = m.text
            var html = m.html
            for (n in shown) {
                text = text.replace(", $n", "")
                html = html.replace(MailTemplates.escape(", $n"), "")
            }
            if (m.template !in codeMails) {
                assertEquals(masked(b.text), masked(text), "$what: the plain part differs outside its rows' names")
                assertEquals(masked(b.html), masked(html), "$what: the HTML part differs outside its rows' names")
            }
            for (label in labels) {
                val row = m.row(label) ?: continue
                val was = b.row(label)!!
                assertTrue(row == was || shown.any { row == "$was, $it" }, "$what: $label: $row")
                if (row != was) rowsWithAName++
                assertEquals(row, m.htmlRow(label), "$what: the row $label is the same in the HTML part")
                assertEquals(MailTemplates.escape(row), m.htmlSource(label), what)
                assertFalse('<' in m.htmlSource(label)!!, what)
            }
            assertTrue(m.text.lines().count { it.startsWith("Help:") } <= 1, what)
        }
        // What the table says a mail shows of the name: every row about a device that holds it shows it.
        val expected = table.first { it.second == name }.third
        assertEquals(expected, MailDevices.name(name), name)
        when {
            expected != null -> assertTrue(rowsWithAName >= 10, "rows that show a name: $rowsWithAName")
            shown.isEmpty() -> assertEquals(0, rowsWithAName)
        }
        return named
    }

    private fun rows(r: Road, t: String, label: String) = r.mails.filter { it.template == t }.mapNotNull { it.row(label) }

    /** The owner's example, on every road: every row about a device, word for word, and the apostrophe in the HTML source. */
    @Test
    fun theOwnersExample_everyRowWordForWord() {
        val r = onlyTheRowsGainTheName("Jordan's Pixel 8.1", "Jordan's Pixel 8.1")
        val j = "\"Jordan's Pixel 8 1\" " + MailDevices.NAMED_ITSELF
        assertEquals(listOf("Mac (as the device reported it), $j", "Android (as the device reported it), $j"), rows(r, "new_device", "Device"))
        assertEquals(listOf("signed in with your master password", "linked from the Linux app added on ${r.first}, $j"), rows(r, "new_device", "How"))
        assertEquals(listOf("the Android app added on ${r.linked}, $j", "the Mac app added on ${r.second}, $j"), rows(r, "device_removed", "Removed"))
        assertEquals(listOf("you, from the Linux app added on ${r.first}, $j", "the operator"), rows(r, "device_removed", "By"))
        assertEquals(listOf("Browser extension (as the request reported it)", "Android (as the request reported it)"), rows(r, "recovery_request_open", "Device"))
        assertEquals(listOf("the Linux app added on ${r.first}, $j"), rows(r, "recovery_request_cancelled", "Device"))
        assertEquals(listOf("iPhone or iPad (as the device reported it), $j", "Windows (as the device reported it), $j"), rows(r, "recovery_applied", "Device"))
        for (t in listOf("recovery_changed", "password_changed", "two_step_off")) assertEquals(listOf("the iPhone or iPad app added on ${r.recovered}, $j"), rows(r, t, "Device"), t)
        assertTrue(Regex("\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2} UTC").matches(r.first), r.first)
        val html = r.mails.first { it.template == "new_device" }.html
        assertTrue("Mac (as the device reported it), &quot;Jordan&#39;s Pixel 8 1&quot; ${MailTemplates.escape(MailDevices.NAMED_ITSELF)}</td>" in html, html)
    }

    /**
     * A link's claim whose stored name cannot be read (a row of an older or restored database: the claim route refuses
     * such a name) gives the new device the server's own fallback name; the new-device mail then shows the row without a
     * name, never the server's words marked as the device's own.
     */
    @Test
    fun aClaimNameThatCannotBeRead_givesTheRowWithoutAName() = testApplication {
        val clock = MutableClock()
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val box = Outbox(s)
        box.sink()
        box.mails.clear()
        val linkId = id16()
        assertEquals(201, c.call(post, "/api/v1/device-links", """{"linkId":"$linkId","expiresAt":${clock.now() + 3_600_000}}""", me.token).status.value)
        val proof = b32()
        val claim = """{"nPub":"${b32()}","name":"${Grammar.nameOf("Jordan's Pixel")!!}","platform":"android","commitN":"${"c".repeat(64)}","mac":"${b32()}"}"""
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/claim", claim).status.value)
        // The stored claim becomes one that no request could have sent: a NUL inside the name.
        val unreadable = Bytes.toB64(("Jordan" + 0.toChar() + "Pixel").toByteArray(Charsets.UTF_8))
        s.db.tx { it.exec("UPDATE device_links SET claimName=? WHERE linkId=?", unreadable, linkId) }
        assertNull(io.silencelen.andvari.core.trust.TrustGrammar.decodeName(unreadable))
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/nonce", """{"nonceE":"${b32()}","proofHash":"${sha256Hex(proof)}"}""", me.token).status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/reveal", """{"nonceN":"${b32()}","proof":"$proof"}""").status.value)
        assertEquals(200, c.call(post, "/api/v1/device-links/$linkId/approve", """{"outer":"QUFBQUFB","inner":"SU5ORVJJ","approveMac":"${b32()}"}""", me.token).status.value)
        val pk = c.call(post, "/api/v1/device-links/$linkId/pickup", """{"proof":"$proof","authKey":"${me.authKey}","device":{"deviceSecret":"${b32()}"}}""")
        assertEquals(200, pk.status.value, pk.bodyAsText())
        box.collect()
        val m = box.mails.single { it.template == "new_device" }
        assertEquals("Android (as the device reported it)", m.row("Device"), m.text)
        assertEquals("Android (as the device reported it)", m.htmlRow("Device"), m.html)
    }

    @Test fun r1_aSentenceWithALink() { onlyTheRowsGainTheName(r1.first, r1.second) }
    @Test fun r2_twoHundredSpacesBeforeHelp() { onlyTheRowsGainTheName(r2.first, r2.second) }
    @Test fun r3_aHundredWideSpacesBeforeHelp() { onlyTheRowsGainTheName(r3.first, r3.second) }
    @Test fun r4_lookAlikeLetters() { onlyTheRowsGainTheName(r4.first, r4.second) }
    @Test fun r5_aFakedKindOfApp() { onlyTheRowsGainTheName(r5.first, r5.second) }

    /** The owner's other examples and the names that only a database can hold, each on every road. */
    @Test
    fun everyOtherHostileName_onEveryRoad() {
        val onRoads = setOf(
            "an emoji", "an emoji of several joined", "a web address", "a mail address", "a telephone number, which stays",
            "200 spaces before a line that begins Help:", "100 wide spaces before a line that begins Help:", "a line break inside a name",
            "every other kind of break", "zero-width joiners and their kin", "a right-to-left override", "a name of marks only",
            "one letter with 20 marks", "64 bytes of letters of 4 bytes each", "the fortieth character inside a letter's marks",
            "a quotation mark inside a name", "an empty name", "a name of spaces only", "a name of 10,000 characters",
        )
        val chosen = table.filter { it.first in onRoads }
        assertEquals(onRoads.size, chosen.size)
        for ((_, stored, _) in chosen) onlyTheRowsGainTheName(stored, stored)
    }

    /**
     * Outside the rows about a device every mail is byte for byte what it was before names were shown: each of the 18
     * mails rendered with the rows' words as the server made them until 22 November 2026 (the kind and the day) and with
     * the words of today (the kind, the day and the time, and the name), compared with those rows' values left out.
     */
    @Test
    fun everyRowThatIsNotAboutADevice_isByteForByteWhatItWas() {
        val at = Instant.parse("2026-11-21T21:14:00Z").toEpochMilli()
        fun device(platform: String, name: String, day: String, isNew: Boolean = false) =
            MailDevices.words(MailDevice(platform, name, "password", Instant.parse("${day}T10:00:00Z").toEpochMilli(), isNew))
        val pixel = device("android", "Jordan's Pixel", "2026-10-02")
        val laptop = device("windows", "the office laptop", "2026-09-14")
        val added = device("android", "Jordan's Pixel", "2026-11-21", isNew = true)
        val oldPixel = "the Android app added on 2026-10-02 UTC"
        val oldLaptop = "the Windows app added on 2026-09-14 UTC"
        val oldAdded = "Android (as the device reported it)"
        fun values(p: String, l: String, a: String): Map<String, Map<String, String>> = mapOf(
            "signup_code" to mapOf("code" to "482 917"),
            "new_device" to mapOf("device" to a, "how" to "linked from $l"),
            "password_changed" to mapOf("device" to p), "two_step_off" to mapOf("device" to p),
            "recovery_changed" to mapOf("device" to p, "old" to "your kit only", "new" to "your kit and the operator", "kit" to "A new recovery kit was made."),
            "device_removed" to mapOf("removed" to l, "by" to "you, from $p"),
            "recovery_request_code" to mapOf("code" to "305 166", "mailboxValue" to "MBX-7Q2K-91ZD"),
            "recovery_request_open" to mapOf("platform" to "android"), "recovery_request_cancelled" to mapOf("device" to p),
            "recovery_applied" to mapOf("device" to a), "account_disabled" to mapOf("reason" to "request"),
            "account_deleted_by_operator" to mapOf("disabledSince" to "2026-10-30 09:02 UTC"),
        )
        val before = values(oldPixel, oldLaptop, oldAdded)
        val after = values(pixel, laptop, added)
        val rowValue = Regex("((?:Device|Removed|By|How):&nbsp;</td><td[^>]*>)[^<]*(</td>)")
        fun outside(text: String) = text.lines().joinToString("\n") { l -> labels.firstOrNull { l.startsWith("$it: ") }?.let { "$it:" } ?: l }
        var changed = 0
        for (t in MailTemplates.ALL) {
            fun render(v: Map<String, Map<String, String>>) = MailTemplates.render(
                t, "jordan@example.com", "andvari", "https://vault.andvaripass.com", "support@andvaripass.com",
                Mail.Ctx("9f3a21c788b04d12e5a7c0b9d4f2a618", at, v[t] ?: emptyMap()),
            )
            val was = render(before)
            val now = render(after)
            assertEquals(was.subject, now.subject, t)
            assertEquals(outside(was.text), outside(now.text), t)
            assertEquals(rowValue.replace(was.html, "$1$2"), rowValue.replace(now.html, "$1$2"), t)
            if (was.text != now.text) changed++
            assertEquals(was.text != now.text, was.html != now.html, t)
        }
        assertEquals(7, changed)
    }

    companion object {
        /** The roads with no name, run once for every test of the class. */
        private var unnamedRoads: Road? = null
    }
}
