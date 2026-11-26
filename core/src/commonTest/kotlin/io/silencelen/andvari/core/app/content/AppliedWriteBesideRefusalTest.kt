package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A write the server applied answers as applied, always: never as failed because another queued change was refused for
 * good at the read that follows it. That other change is undone on this device and said by a notice of its own, which
 * names the item. Over the real item engine, on a durable queue: a change to "Door" in the shared vault waits from an
 * offline save, and the server then denies every change to that vault.
 */
class AppliedWriteBesideRefusalTest {
    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun login(name: String) = LoginInput(name, "me", "pw", listOf("https://example.com"), "", "", false)

    /** The notice of [count] refused changes in [vault], naming the item when it is one. */
    private fun refusedLine(count: Int, item: String?, vault: String): String = ContentCopy.writeDenied(count, item, vault)

    private class Setup(val r: ItemRig, val cache: DurableCache, val c: EngineVaultContent)

    /** "Door" saved into the shared vault while the server is unreachable: its change waits; then the vault is denied. */
    private fun doorWaits(): Setup = runBlocking {
        val cache = DurableCache()
        val r = ItemRig(cache)
        r.openShared()
        r.server.echo = true
        val c = EngineVaultContent(r.engine, r.crypto, TestHost(r))
        r.server.offline = true
        c.saveLogin(null, login("Door"), r.shared)
        assertTrue(cache.pending().any { it.vaultId == r.shared }, "Door's change waits")
        r.server.offline = false
        r.server.denyVaults += r.shared
        Setup(r, cache, c)
    }

    @Test
    fun aWriteTheServerApplied_answersAsSaved_whileAnotherChangeIsRefused() = runBlocking<Unit> {
        val s = doorWaits()
        val answer = s.c.saveLogin(null, login("Bank"), null)
        println("applied write beside a refusal: answer $answer, notices ${s.c.state.vaultNotices.map { it.text }}, error ${s.c.state.error}, notice ${s.c.state.notice}")
        assertEquals(ActionResult.Ok, answer, "Bank was stored by the server: it is said as saved")
        assertEquals(listOf("Bank"), s.c.state.items.map { it.name }, "Door's change is undone on this device")
        assertTrue(s.cache.pending().isEmpty())
        assertTrue(s.r.server.itemRows.values.any { !it.deleted && it.vaultId == s.r.personal }, "and Bank is on the server")
        val said = s.c.state.vaultNotices.single()
        assertEquals(refusedLine(1, "Door", "Family"), said.text, "the refused change is said, naming its item")
        assertTrue(said.warning)
        assertEquals(null, s.c.state.error, "nothing else reads as failed")
    }

    @Test
    fun aSyncWithNoWriteInHand_saysTheRefusedChangeByItsItem() = runBlocking<Unit> {
        val s = doorWaits()
        val answer = s.c.syncQuietly()
        println("sync with a refusal: answer $answer, notices ${s.c.state.vaultNotices.map { it.text }}, error ${s.c.state.error}")
        assertEquals(ActionResult.Failed(ContentCopy.denied(1)), answer, "the sync's own answer is as it was")
        assertTrue(s.c.state.items.isEmpty(), "Door's change is undone on this device")
        assertEquals(listOf(refusedLine(1, "Door", "Family")), s.c.state.vaultNotices.map { it.text })
    }

    @Test
    fun twoRefusedBesideAnAppliedWrite_areCountedInOneNotice() = runBlocking<Unit> {
        val s = doorWaits()
        s.r.server.offline = true
        s.c.saveLogin(null, login("Gate"), s.r.shared)
        s.r.server.offline = false
        val answer = s.c.saveLogin(null, login("Bank"), null)
        assertEquals(ActionResult.Ok, answer)
        assertEquals(listOf(refusedLine(2, null, "Family")), s.c.state.vaultNotices.map { it.text })
    }

    @Test
    fun aWriteWhoseOwnChangeIsRefused_answersAsRefused_asBefore() = runBlocking<Unit> {
        val s = doorWaits()
        val answer = s.c.saveLogin(null, login("Gate"), s.r.shared)
        println("own change refused beside another: answer $answer, notices ${s.c.state.vaultNotices.map { it.text }}")
        assertEquals(ActionResult.Failed(ContentCopy.denied(2)), answer, "Gate's own change was refused: said as refused, as before")
        assertTrue(s.c.state.items.isEmpty())
        assertEquals(listOf(refusedLine(1, "Door", "Family")), s.c.state.vaultNotices.map { it.text }, "Door, the other one, is said by name")
    }
}
