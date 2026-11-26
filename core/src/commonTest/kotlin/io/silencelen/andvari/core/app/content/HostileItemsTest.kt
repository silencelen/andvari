package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.ItemDocShape
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PasswordHistoryEntry
import io.silencelen.andvari.core.client.VaultItem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Item documents the content did not write: a shared vault's co-member, or the server, may be hostile. What a list row
 * or a fill suggestion shows is one safe line; a fill reads a bounded number of addresses, the same in the app and in
 * the iPhone's snapshot; a history is read only as far as this app keeps one; a one-time code that is not one shows
 * nothing; and one rule says which saved address may be opened.
 */
class HostileItemsTest {
    private val personal = FakeVaultContent.PERSONAL_VAULT_ID

    private fun safe(s: String) = s.none { it.category == CharCategory.FORMAT || it.category == CharCategory.CONTROL || it == '\u2028' || it == '\u2029' }

    @Test
    fun aNameMadeToMislead_isOneSafeLine_inTheListAndEveryFillSuggestion_whileTheItemStaysAsWritten() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val name = "Bank\u202Emoc.evil\u202C\u0000\nsecond line\u2028\u200B\u2066x\u2069"
        val user = "me\u202E@evil\r\nadmin"
        val bank = c.seed(personal, ItemDoc(type = "login", name = name, login = LoginData(username = user, password = "pw", uris = listOf("https://bank\u202E.test/"))))
        val card = c.seed(personal, ItemDoc(type = "card", name = "Visa\u202E1234", card = io.silencelen.andvari.core.client.CardData(number = "4111111111111111")))
        val row = c.state.items.single { it.itemId == bank }
        assertEquals("Bankmoc.evil second line x", row.name)
        assertEquals("me@evil admin", row.username)
        assertTrue(safe(row.host!!), row.host)
        val suggestion = c.fillLogins(listOf("bank.test")).single { it.itemId == bank }
        assertEquals(row.name, suggestion.name)
        assertEquals(row.username, suggestion.username)
        assertTrue(suggestion.host == null || safe(suggestion.host!!))
        assertEquals("Visa1234", c.fillCards().single { it.itemId == card }.name)
        assertTrue(c.state.items.all { safe(it.name) })
        // What is handed out, edited and searched is the item as written.
        assertEquals(user, c.fillCredential(bank)!!.username)
        assertEquals(name, c.itemDetail(bank)!!.name)
        c.setQuery("second line")
        assertEquals(listOf(bank), c.state.items.map { it.itemId })
    }

    @Test
    fun aVeryLongName_isCut_inTheListAndTheFill() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val long = "a".repeat(5_000) + "😀".repeat(1_000)
        val id = c.seedLogin(personal, long, "u".repeat(100_000), "pw", "https://long.test")
        val row = c.state.items.single()
        assertEquals(ItemText.LABEL_MAX_CHARS + 1, row.name.length)
        assertTrue(row.name.endsWith("…"))
        assertEquals(ItemText.LABEL_MAX_CHARS + 1, row.username!!.length)
        assertEquals(row.name, c.fillLogins(emptyList()).single().name)
        assertEquals(long, c.itemDetail(id)!!.name)
        // A cut never splits a surrogate pair.
        val emoji = ItemText.label("😀".repeat(300))
        assertTrue(emoji.dropLast(1).chunked(2).all { it.length == 2 && it[0].isHighSurrogate() && it[1].isLowSurrogate() }, emoji)
        assertEquals("x", ItemText.label("\uDE00x\uD83D"), "a lone surrogate half is dropped")
    }

    @Test
    fun veryManyAddresses_aFillReadsTheFirstHundred_inTheAppAndTheSnapshotAlike() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val uris = (0 until 5_000).map { "https://h$it.test" }
        val many = c.seed(personal, ItemDoc(type = "login", name = "Many", login = LoginData(username = "u", password = "pw", uris = uris)))
        assertTrue(c.fillMatches(many, listOf("https://h99.test/")))
        assertFalse(c.fillMatches(many, listOf("https://h100.test/")), "past the first hundred an address is never matched")
        val offered = c.fillLogins(listOf("https://h4999.test/")).single()
        assertFalse(offered.matches)
        assertEquals(FillRules.MAX_FILL_ADDRESSES, offered.uris.size)
        // The snapshot keeps the same addresses, so the extension matches exactly as the app does.
        val item = VaultItem(many, personal, 1, 1, ItemDoc(type = "login", name = "Many", login = LoginData(username = "u", password = "pw", uris = uris)))
        val kept = assertNotNull(ContentFillSnapshot.fillable(item))
        assertEquals(uris.take(FillRules.MAX_FILL_ADDRESSES), kept.doc.login!!.uris)
    }

    @Test
    fun aLongHistory_isReadOnlyAsFarAsThisAppKeepsOne() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val history = (1..1_000).map { PasswordHistoryEntry("old-$it", it.toLong()) }
        val id = c.seed(personal, ItemDoc(type = "login", name = "Old", login = LoginData(password = "now", passwordHistory = history)))
        assertEquals((1_000 downTo 981).map { it.toLong() }, c.passwordHistory(id))
        assertEquals("old-1000", c.previousPassword(id, 0))
        assertEquals("old-981", c.previousPassword(id, ContentSaves.HISTORY_MAX - 1))
        assertNull(c.previousPassword(id, ContentSaves.HISTORY_MAX))
        assertEquals(ContentSaves.HISTORY_MAX, c.itemDetail(id)!!.previousPasswords, "the detail counts what can be read")
    }

    @Test
    fun aOneTimeCodeSecretThatIsNotOne_showsNoCode_andThrowsNothing() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val bad = listOf(
            "not-a-secret?", "!!!!", "0189", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=-30", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=99",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", "otpauth://totp/x?secret=", "A".repeat(200_000) + "!",
        )
        for (totp in bad) {
            val id = c.seed(personal, ItemDoc(type = "login", name = "T", login = LoginData(password = "pw", totp = totp)))
            assertNull(c.oneTimeCode(id), totp.take(60))
            val item = VaultItem(id, personal, 1, 1, ItemDoc(type = "login", name = "T", login = LoginData(password = "pw", totp = totp)))
            assertNotNull(ContentFillSnapshot.fillable(item), "the snapshot keeps it as written; its reader shows no code either")
        }
    }

    @Test
    fun anAddressWithASchemeTheAppsMustNeverOpen_isNotOpenable() {
        val refused = listOf(
            "javascript:alert(1)", "JavaScript:alert(1)", "data:text/html,<script>x</script>", "file:///etc/passwd", "intent://x#Intent;end",
            "androidapp://com.bank", "ftp://bank.test", "vbscript:x", "about:blank", "chrome://settings",
            "https://bank.test@evil.test/", "bank.test@evil.test","https://bank\u202E.test",
            "https://bank.test/\u0000", "https://bank .test", "", "   ", "https://", "//evil.test", "\\\\evil.test", "bank.test:443",
        )
        for (s in refused) assertNull(ItemText.openableAddress(s), s)
        assertEquals("https://bank.test/login?x=1#a", ItemText.openableAddress("https://bank.test/login?x=1#a"))
        assertEquals("http://router.lan", ItemText.openableAddress(" http://router.lan "))
        assertEquals("https://bank.test", ItemText.openableAddress("bank.test"))
        assertEquals("https://bank.test/a@b", ItemText.openableAddress("https://bank.test/a@b"), "an @ in the path names no user")
    }

    @Test
    fun aRepeatedKey_readsAsItsLastValue_andAWrongType_refusesTheDocument() {
        // The parser every path shares (ItemCodec.open) keeps the last of a repeated key, as JSON.parse does on web.
        val tree = Json.parseToJsonElement("""{"type":"note","name":"A","name":"B"}""")
        assertEquals("B", tree.jsonObject["name"]!!.jsonPrimitive.content)
        assertNull(ItemDocShape.problem(tree))
        // A field of the wrong type refuses the whole document: the item is kept unread, on every path at once.
        assertEquals("name", ItemDocShape.problem(Json.parseToJsonElement("""{"type":"note","name":7}""")))
        assertEquals("login.uris", ItemDocShape.problem(Json.parseToJsonElement("""{"type":"login","name":"A","login":{"uris":"https://x.test"}}""")))
        assertEquals("type", ItemDocShape.problem(Json.parseToJsonElement("""{"name":"A"}""")))
    }
}
