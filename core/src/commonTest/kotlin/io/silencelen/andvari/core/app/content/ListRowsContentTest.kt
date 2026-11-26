package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.client.CardData
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.TimeSource

/** What a row of the vault's list carries, and what building the list costs with 2,000 items. */
class ListRowsContentTest {
    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
    }

    /** 2,000 items over the real engine: 1,900 in the personal vault, 100 in a shared one. */
    private fun bigRig(): Pair<ItemRig, EngineVaultContent> {
        val r = ItemRig()
        r.openShared(role = "reader")
        val rows = (0 until 2000).map { i ->
            val d = if (i % 10 == 0) ItemDoc(type = "card", name = "Card $i", card = CardData(number = "4111111111111111"))
            else ItemDoc(type = "login", name = "Site $i", login = LoginData(username = "user$i", password = "pw", uris = listOf("https://s$i.test")))
            if (i < 1900) r.itemRow(r.id(), r.personal, r.personalKey, d, rev = 10L + i) else r.itemRow(r.id(), r.shared, r.sharedKey, d, rev = 10L + i)
        }
        r.server.queue.add(r.response(r.server.rev + 2100, items = rows))
        runBlocking { check(r.engine.sync() is ItemResult.Ok) }
        r.server.echo = true
        return r to EngineVaultContent(r.engine, r.crypto, TestHost(r))
    }

    /** Milliseconds for one state of the list (a query change rebuilds it), the median of [runs]. */
    private fun timeList(c: VaultContent, runs: Int = 9): Long {
        val times = (0 until runs).map { i ->
            val mark = TimeSource.Monotonic.markNow()
            c.setQuery(if (i % 2 == 0) "" else " ")
            check(c.state.items.size == 2000)
            mark.elapsedNow().inWholeMicroseconds
        }.sorted()
        return times[runs / 2] / 1000
    }

    private val personal = FakeVaultContent.PERSONAL_VAULT_ID
    private val family = "00000000-0000-4000-8000-0000000000aa"
    private val work = "00000000-0000-4000-8000-0000000000bb"

    private fun FakeVaultContent.row(name: String): ItemSummary = state.items.single { it.name == name }

    @Test
    fun aRowSaysItsVault_itsCard_itsLastChange_andWhetherItMayBeChanged() {
        val c = FakeVaultContent()
        c.addSharedVault(family, "Family", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
        c.addSharedVault(work, "Work", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        val bank = c.seedLogin(personal, "Bank", "ana", "made-up-1", "https://bank.test")
        val wifi = c.seedLogin(family, "Wifi", "home", "made-up-2", "")
        c.seedLogin(work, "Wiki", "ana", "made-up-3", "")
        // The stored brand is stale: the row's brand comes from the number.
        c.seed(personal, ItemDoc(type = "card", name = "Visa card", card = CardData(number = "4242 4242 4242 4242", brand = "amex")))
        c.seedCard(family, "Odd card", "9999123", "01", "2031")
        c.seed(personal, ItemDoc(type = "card", name = "Blank card", card = CardData()))
        c.seedNote(personal, "Note", "made-up text")

        c.row("Bank").let {
            assertEquals(personal, it.vaultId)
            assertEquals("Personal", it.vaultName)
            assertFalse(it.sharedVault)
            assertTrue(it.editable)
            assertNull(it.cardBrand)
            assertNull(it.cardLastFour)
        }
        c.row("Wifi").let {
            assertEquals(family, it.vaultId)
            assertEquals("Family", it.vaultName)
            assertTrue(it.sharedVault)
            assertFalse(it.editable, "a reader of a shared vault may not change its items")
            assertEquals(c.itemDetail(wifi)!!.editable, it.editable, "the row and the detail agree")
        }
        c.row("Wiki").let {
            assertTrue(it.sharedVault)
            assertTrue(it.editable, "a writer may")
        }
        c.row("Visa card").let {
            assertEquals("Visa", it.cardBrand)
            assertEquals("4242", it.cardLastFour)
        }
        c.row("Odd card").let {
            assertNull(it.cardBrand, "a brand not known")
            assertEquals("9123", it.cardLastFour)
        }
        c.row("Blank card").let {
            assertNull(it.cardBrand)
            assertNull(it.cardLastFour)
        }
        assertNull(c.row("Note").cardLastFour)

        // The last change orders "recently updated".
        c.setUpdatedAt(bank, c.nowMs + 5_000)
        c.setUpdatedAt(wifi, c.nowMs + 9_000)
        assertEquals(c.nowMs + 9_000, c.row("Wifi").updatedAt)
        assertEquals(listOf("Wifi", "Bank"), c.state.items.sortedByDescending { it.updatedAt }.take(2).map { it.name })

        // A server whose card chain forked is read only: no row offers Edit.
        c.stopServer()
        assertTrue(c.state.items.none { it.editable })
        assertEquals("Personal", c.row("Bank").vaultName, "the rest of the row stays")
    }

    @Test
    fun aHeldVaultsRows_carryItsName_andOfferNoEdit() {
        val c = FakeVaultContent()
        c.addSharedVault(work, "Work", VaultAccess.ROLE_WRITER, VaultStanding.VERIFIED)
        c.seedLogin(work, "Wiki", "ana", "made-up-3", "")
        c.holdVault(work, "removed", readable = true)
        val row = c.heldItems(work).single()
        assertEquals(work, row.vaultId)
        assertEquals("Work", row.vaultName)
        assertTrue(row.sharedVault)
        assertFalse(row.editable)
    }

    @Test
    fun overTheEngine_aRowSaysItsVault_itsCard_theServersLastWrite_andAReaderGetsNoEdit() {
        val r = ItemRig()
        val readOnly = r.id()
        val visa = r.id()
        r.openShared(
            role = "reader",
            items = listOf(r.itemRow(readOnly, r.shared, r.sharedKey, rev = 41)),
        )
        r.serve(r.itemRow(visa, r.personal, r.personalKey, ItemDoc(type = "card", name = "Visa card", card = CardData(number = "4000056655665556")), rev = 52))
        runBlocking { check(r.engine.sync() is ItemResult.Ok) }
        r.server.echo = true
        val c = EngineVaultContent(r.engine, r.crypto, TestHost(r))
        val shared = c.state.items.single { it.itemId == readOnly }
        assertEquals(r.shared, shared.vaultId)
        assertEquals("Family", shared.vaultName)
        assertTrue(shared.sharedVault)
        assertFalse(shared.editable)
        assertEquals(41L, shared.updatedAt, "the server's record of the last write")
        val card = c.state.items.single { it.itemId == visa }
        assertEquals("Personal", card.vaultName)
        assertFalse(card.sharedVault)
        assertTrue(card.editable)
        assertEquals("Visa", card.cardBrand)
        assertEquals("5556", card.cardLastFour)
        assertEquals(52L, card.updatedAt)
        assertEquals(c.itemDetail(visa)!!.updatedAt, card.updatedAt, "the row and the detail agree")
    }

    @Test
    fun theVaultsAreReadAFixedNumberOfTimesPerState_whateverTheListsLength() {
        fun readsPerState(items: Int): Int {
            val c = FakeVaultContent()
            c.addSharedVault(family, "Family", VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
            repeat(items) { i -> c.seed(if (i % 2 == 0) personal else family, ItemDoc(type = "login", name = "Site $i", login = LoginData(username = "u$i"))) }
            val before = c.vaultReads
            c.setQuery("site")
            check(c.state.items.size == items)
            return c.vaultReads - before
        }
        val small = readsPerState(2)
        assertEquals(small, readsPerState(2000), "no read of a vault per row")
        assertTrue(small <= 2, "one read for the list and the vault filter's choices; was $small")
    }

    @Test
    fun theListOf2000Items_isBuiltWithNoCallPerRow_andIsTimed() {
        val (r, c) = bigRig()
        val callsBefore = r.server.calls
        timeList(c, 3) // warm
        val ms = timeList(c)
        println("vault list, 2000 items over the engine: median $ms ms per state")
        kotlin.test.assertEquals(callsBefore, r.server.calls, "building the list reaches the server never")

        val f = FakeVaultContent()
        repeat(2000) { i -> f.seed(FakeVaultContent.PERSONAL_VAULT_ID, ItemDoc(type = "login", name = "Site $i", login = LoginData(username = "u$i"))) }
        timeList(f, 3)
        println("vault list, 2000 items over the fake: median ${timeList(f)} ms per state")
    }
}
