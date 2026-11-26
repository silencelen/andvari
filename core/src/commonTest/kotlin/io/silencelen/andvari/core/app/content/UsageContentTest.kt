package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.SecretField
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PasswordHistoryEntry
import io.silencelen.andvari.core.client.UsageRecorderCore
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Health's "last used" on the new session (spec 02 §8.2, design 2026-08-22): the content reads the usage ledger the
 * session gives it after the unlock's first completed sync, and again after each sync while Health is open. Before,
 * the content never read it, and every login said "Last used not recorded".
 */
class UsageContentTest {
    private class Ledger(var text: String?, var fails: Boolean = false) : UsageRecorderCore.Transport {
        var fetches = 0
        override suspend fun fetchSealed(): String? {
            fetches++
            if (fails) throw IllegalStateException("offline")
            return text?.let { "sealed" }
        }
        override fun open(sealed: String): ByteArray = text!!.encodeToByteArray()
        override fun seal(plain: ByteArray): String = error("the content never writes the ledger")
        override suspend fun put(sealed: String) = error("the content never writes the ledger")
    }

    private class Host(val r: ItemRig, val ledger: Ledger?) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun usageLedger(): UsageRecorderCore.Transport? = ledger
        val uses = ArrayList<Pair<String, Long>>()
        override fun recordUse(itemId: String, atMs: Long) {
            uses += itemId to atMs
        }
    }

    private fun dates(c: EngineVaultContent, name: String): String = c.state.health!!.staleness.single { it.name == name }.dates

    @Test
    fun lastUsed_isReadFromTheLedgerAfterASync_andAgainWhileHealthIsOpen() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.echo = true
        val ledger = Ledger(null)
        val c = EngineVaultContent(r.engine, r.crypto, Host(r, ledger))
        c.syncQuietly()
        c.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.test"), "", "", false), null)
        val bank = c.state.items.single().itemId
        c.openHealth()
        assertTrue(dates(c, "Bank").startsWith("Last used not recorded"), dates(c, "Bank"))

        ledger.text = "{\"$bank\":{\"lastUsedAt\":${r.now - 2 * 86_400_000L},\"useCount\":3}}"
        c.syncQuietly()
        assertTrue(dates(c, "Bank").startsWith("Last used 2 days ago"), dates(c, "Bank"))

        // A ledger that cannot be read leaves what was read; with Health closed, a sync does not fetch it again.
        ledger.fails = true
        c.syncQuietly()
        assertTrue(dates(c, "Bank").startsWith("Last used 2 days ago"), dates(c, "Bank"))
        c.closeHealth()
        val before = ledger.fetches
        c.syncQuietly()
        assertEquals(before, ledger.fetches)
        c.openHealth()
        assertTrue(dates(c, "Bank").startsWith("Last used 2 days ago"), "kept for the next open: ${dates(c, "Bank")}")
    }

    // ---- recording a use (spec 02 §8.2; the content records, the session sends) ----

    private val personal = FakeVaultContent.PERSONAL_VAULT_ID

    @Test
    fun aLoginReleasedToAFill_isOneUse_handedToTheSession() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.echo = true
        val host = Host(r, null)
        val c = EngineVaultContent(r.engine, r.crypto, host)
        c.syncQuietly()
        c.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.test"), "", "", false), null)
        val bank = c.state.items.single().itemId
        assertTrue(host.uses.isEmpty(), "a save is not a use")
        assertEquals("pw", c.fillCredential(bank)!!.password)
        assertEquals(listOf(bank to r.now), host.uses)
        // The same release a moment later is the same use; a minute on, it is another.
        c.fillCredential(bank)
        assertEquals(1, host.uses.size)
        r.now += ContentController.USE_WINDOW_MS
        c.fillCredential(bank)
        assertEquals(listOf(bank to r.now - ContentController.USE_WINDOW_MS, bank to r.now), host.uses)
    }

    @Test
    fun aCardReleasedToAFill_isOneUse_howeverManyFieldsItGives() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val card = c.seedCard(personal, "Visa", "4111111111111111", "07", "31")
        assertTrue(c.fillCards().single().hasNumber, "listing the cards releases nothing")
        assertTrue(c.recordedUses.isEmpty())
        assertEquals("4111111111111111", c.fillCardField(card, "number"))
        assertEquals("07", c.fillCardField(card, "expMonth"))
        assertEquals("31", c.fillCardField(card, "expYear"))
        assertEquals(listOf(card), c.recordedUses)
    }

    /**
     * The Android app's need: rows that must carry values before the person picks one
     * are read without recording a use, and only the row the person picked is recorded, once.
     */
    @Test
    fun rowsReadBeforeAPickRecordNothing_andOnlyThePickedRowIsOneUse() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val a = c.seedLogin(personal, "Own A", "a@example.com", "pass-a", "androidapp://com.example.app")
        val b = c.seedLogin(personal, "Own B", "b@example.com", "pass-b", "androidapp://com.example.app")
        val card = c.seedCard(personal, "Visa", "4111111111111111", "07", "31")
        val note = c.seedNote(personal, "Note", "text")
        assertEquals("pass-a", c.fillCredentialUnrecorded(a)!!.password)
        assertEquals("pass-b", c.fillCredentialUnrecorded(b)!!.password)
        assertEquals("4111111111111111", c.fillCardFieldUnrecorded(card, "number"))
        assertEquals("07", c.fillCardFieldUnrecorded(card, "expMonth"))
        assertTrue(c.recordedUses.isEmpty(), "rows offered with their values are not uses: ${c.recordedUses}")
        assertTrue(c.recordFillPicked(b))
        assertTrue(c.recordFillPicked(b), "the same pick a moment later is the same use")
        assertTrue(c.recordFillPicked(card))
        assertEquals(listOf(b, card), c.recordedUses)
        assertFalse(c.recordFillPicked(note), "a note is not a fill row")
        assertNull(c.fillCredentialUnrecorded(note))
        assertFalse(c.recordFillPicked("00000000-0000-4000-8000-00000000dead"), "not in the working set")
        assertEquals(listOf(b, card), c.recordedUses)
    }

    /**
     * A pick the platform reports at the next fill request (Android reads its fill history then) is recorded at the time
     * of the pick, as the ledger's `lastUsedAt` means (spec 02 §8.2), never at the later read; never after now; and one
     * use with a release of the same item within the window around it.
     */
    @Test
    fun aPickReportedLater_isRecordedAtTheTimeOfThePick() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val a = c.seedLogin(personal, "Own A", "a@example.com", "made-up-a", "androidapp://com.example.app")
        val b = c.seedLogin(personal, "Own B", "b@example.com", "made-up-b", "androidapp://com.example.app")
        val card = c.seedCard(personal, "Visa", "4111111111111111", "07", "31")
        val now = c.nowMs
        val pickedAt = now - 10 * 60_000L
        assertTrue(c.recordFillPickedAt(a, pickedAt))
        assertEquals(listOf(a), c.recordedUses)
        assertEquals(listOf(pickedAt), c.recordedUseTimes, "the time of the pick, not of the read")

        // The same item released again within the window around the pick is the same use.
        assertTrue(c.recordFillPickedAt(a, pickedAt + 30_000L))
        assertEquals(1, c.recordedUses.size)

        // A pick the platform dates after now is recorded as now; a time before 1970 records nothing.
        assertTrue(c.recordFillPickedAt(b, now + 3_600_000L))
        assertEquals(now, c.recordedUseTimes.last())
        assertFalse(c.recordFillPickedAt(card, -1L))
        assertEquals(listOf(a, b), c.recordedUses)

        // A use recorded now, after the earlier pick and outside its window, is a use of its own.
        assertEquals("made-up-a", c.fillCredential(a)!!.password)
        assertEquals(listOf(a, b, a), c.recordedUses)
        assertEquals(now, c.recordedUseTimes.last())
    }

    @Test
    fun aSecretRevealedOrCopied_isAUse_andHealthShowsItAtOnce() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val bank = c.seed(personal, ItemDoc(type = "login", name = "Bank", login = LoginData(username = "me", password = "pw", uris = listOf("https://bank.test"))))
        val vpn = c.seed(personal, ItemDoc(type = "login", name = "Vpn", login = LoginData(password = "now", passwordHistory = listOf(PasswordHistoryEntry("then", 10)))))
        val note = c.seedNote(personal, "Safe", "1234")
        val card = c.seedCard(personal, "Visa", "4111111111111111", "07", "31")
        c.openHealth()
        assertTrue(c.state.health!!.staleness.single { it.name == "Bank" }.dates.startsWith("Last used not recorded"))
        assertEquals("pw", c.revealSecret(bank, SecretField.PASSWORD))
        assertEquals("then", c.previousPassword(vpn, 0))
        assertEquals("1234", c.revealSecret(note, SecretField.NOTES))
        assertEquals("4111111111111111", c.revealSecret(card, SecretField.CARD_NUMBER))
        assertEquals(listOf(bank, vpn, note, card), c.recordedUses)
        // A copy right after the reveal is the same use.
        c.revealSecret(bank, SecretField.PASSWORD)
        assertEquals(4, c.recordedUses.size)
        c.closeHealth()
        c.openHealth()
        val bankDates = c.state.health!!.staleness.single { it.name == "Bank" }.dates
        assertFalse(bankDates.startsWith("Last used not recorded"), "a use not yet sent shows in Health: $bankDates")
    }

    @Test
    fun nothingIsRecorded_forARefusedFill_aRevealThatFoundNothing_aCode_orAfterALock() = runBlocking<Unit> {
        val c = FakeVaultContent()
        val frozen = "00000000-0000-4000-8000-00000000f0f0"
        c.addSharedVault(frozen, "Family", io.silencelen.andvari.core.client.items.VaultAccess.ROLE_WRITER, io.silencelen.andvari.core.client.items.VaultStanding.FROZEN)
        val cold = c.seedLogin(frozen, "Cold", "me", "pw", "https://cold.test")
        val note = c.seedNote(personal, "Empty", "")
        val login = c.seed(personal, ItemDoc(type = "login", name = "Bare", login = LoginData(username = "me", totp = "JBSWY3DPEHPK3PXP")))
        val card = c.seedCard(personal, "Visa", "", "07", "31")
        assertNull(c.fillCredential(cold), "a frozen vault's login is refused to a fill")
        assertNull(c.fillCardField(cold, "number"))
        assertNull(c.fillCredential(note), "a note is not a login")
        assertNull(c.fillCredential(card))
        assertNull(c.fillCardField(login, "number"), "a login is not a card")
        assertNull(c.fillCardField(card, "number"), "a card with no number gives none")
        assertNull(c.fillCredential("00000000-0000-4000-8000-00000000dead"), "an item that is gone")
        assertNull(c.revealSecret(note, SecretField.NOTES), "an empty secret")
        assertNull(c.revealSecret(login, SecretField.PASSWORD))
        assertNull(c.previousPassword(login, 0), "no earlier password")
        assertNull(c.revealSecret("00000000-0000-4000-8000-00000000dead", SecretField.PASSWORD))
        assertTrue(c.oneTimeCode(login) != null, "a code is shown, and refreshed every second: not a reveal")
        assertTrue(c.recordedUses.isEmpty(), "${c.recordedUses}")
        c.close()
        assertNull(c.revealSecret(login, SecretField.TOTP_SECRET))
        assertTrue(c.recordedUses.isEmpty())
    }

    @Test
    fun aSessionWithNoLedger_ranksNothingByUse() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.echo = true
        val c = EngineVaultContent(r.engine, r.crypto, Host(r, null))
        c.syncQuietly()
        c.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.test"), "", "", false), null)
        c.openHealth()
        assertTrue(dates(c, "Bank").startsWith("Last used not recorded"))
    }
}
