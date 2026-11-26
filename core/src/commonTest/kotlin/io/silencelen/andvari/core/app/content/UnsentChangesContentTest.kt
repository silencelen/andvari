package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.MutationOp
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * When the real item engine keeps a change to send, and when it refuses it (spec 03 §5: "Clients maintain a durable
 * outbound queue"; design §4.4: a copy the server signed out is kept, and what was not sent is sent at the next sign-in;
 * the rule of 2026-11-17: no copy is deleted over changes not sent without the person being told how many).
 *
 * A change is kept to be sent only where the queue outlives the session: the account's copy kept at rest (the server's
 * policy allows an offline copy and the platform consents: Android by default, the desktop with "keep me signed in").
 * There a save, an edit and a deletion with no answer are queued, shown at once and counted. Where the copy lives only in
 * memory each is refused with the offline line and nothing waits: the person keeps what they typed in the editor. A move
 * and a file's upload are never queued on either: a move is refused with the retry line (its plan kept, the item where it
 * was), a save with files with the offline line (the editor keeps the file; the save is kept until the editor closes).
 */
class UnsentChangesContentTest {
    private class Stores {
        val moves = InMemoryFillSnapshots()
        val keptSaves = InMemoryFillSnapshots()
        val files = InMemoryBlobs()
        val applied = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
        val fill = InMemoryFillSnapshots()
    }

    private fun unlock(r: ItemRig): OpenedAccount {
        val seed = ByteArray(32) { 4 }
        val identity = r.crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
        return OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = "https://vault.example.com"
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    private fun content(r: ItemRig, engine: ItemEngine = r.engine, s: Stores = Stores()): EngineVaultContent {
        r.server.echo = true
        r.server.journal = true
        return EngineVaultContent(engine, r.crypto, TestHost(r), ContentKeeping(unlock(r), s.moves, s.keptSaves, s.files, s.applied, s.queue, s.fill))
    }

    private fun login(name: String) = LoginInput(name, "me", "pw-$name", listOf("https://$name.test".lowercase()), "", "", false)

    private fun EngineVaultContent.idOf(name: String) = state.items.single { it.name == name }.itemId

    /** What the app interface counts at a sign-out from the item engine's cache: the queue, the refused rows waiting, the held vaults. */
    private fun unsent(cache: VaultCache) = cache.pending().size + cache.stagedDenied().size + cache.heldVaults().size

    /** Three logins made while the server answered, and the shared vault open: Bank to edit, Old to delete, Mail to move. */
    private suspend fun seeded(cache: VaultCache): Pair<ItemRig, EngineVaultContent> {
        val r = ItemRig(cache)
        r.openShared()
        val c = content(r)
        c.syncQuietly()
        for (n in listOf("Bank", "Old", "Mail")) assertEquals(ActionResult.Ok, c.saveLogin(null, login(n), null))
        assertEquals(0, unsent(cache))
        return r to c
    }

    /** The five acts while the server does not answer; answers what each act's result was, by act. */
    private suspend fun EngineVaultContent.everyAct(): Map<String, ActionResult> {
        val bank = idOf("Bank")
        val out = LinkedHashMap<String, ActionResult>()
        out["new"] = saveLogin(null, login("Train"), null)
        out["edit"] = saveLogin(bank, LoginInput("Bank", "me", "changed offline", listOf("https://bank.test"), "", "", false), null)
        out["delete"] = deleteItem(idOf("Old"))
        out["move"] = moveOrCopyItem(idOf("Mail"), "cccccccc-cccc-4ccc-8ccc-cccccccccccc", true)
        openAttachmentDraft(null)
        addAttachment("scan.pdf", "page one".encodeToByteArray())
        out["file"] = saveLogin(null, login("Passport"), null)
        return out
    }

    @Test
    fun noAnswerAtTheSave_onACopyKeptAtRest_queuesTheSaveTheEditAndTheDeletion_countsThem_andSendsThemWhenTheServerAnswers() = runBlocking<Unit> {
        val cache = DurableCache()
        val (r, c) = seeded(cache)
        val bank = c.idOf("Bank")
        val old = c.idOf("Old")
        val mail = c.idOf("Mail")
        r.server.offline = true

        val acts = c.everyAct()
        assertEquals(ActionResult.Ok, acts["new"])
        assertEquals(ActionResult.Ok, acts["edit"])
        assertEquals(ActionResult.Ok, acts["delete"])
        assertEquals(ContentCopy.SAVE_OFFLINE, c.state.notice, "the queued line, not 'saved'")
        assertEquals(ContentCopy.MOVE_RETRY, (acts["move"] as ActionResult.Failed).message)
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, (acts["file"] as ActionResult.Failed).message)

        // What the person has: the new item and the edit in the list at once, the deleted item gone, the moved one where it was.
        val names = c.state.items.map { it.name }.toSet()
        assertTrue("Train" in names && "Bank" in names && "Mail" in names && "Old" !in names && "Passport" !in names, "$names")
        assertEquals(r.personal, r.engine.item(mail)?.vaultId, "the move did not happen")
        assertEquals(3, unsent(cache), "the save, the edit and the deletion wait to be sent")
        val train = c.idOf("Train")
        assertEquals(setOf(train, bank, old), r.engine.waitingChanges(r.personal))
        assertEquals(1, c.keptSavesWaiting(), "the save with its file is kept while its editor is open")
        c.closeAttachmentDraft()
        assertEquals(0, c.keptSavesWaiting(), "closing the editor gives the save with files up: it was said as not saved")

        // The server answers again: what waited is sent, and nothing waits.
        r.server.offline = false
        val before = r.server.pushes.size
        assertEquals(ActionResult.Ok, c.syncQuietly())
        val sent = r.server.pushes.drop(before).flatten()
        assertEquals(setOf(train, bank, old), sent.map { it.itemId }.toSet())
        assertTrue(sent.single { it.itemId == old }.op == MutationOp.DELETE)
        assertEquals(0, unsent(cache))
        assertEquals(emptySet(), r.engine.waitingChanges(r.personal))
    }

    @Test
    fun noAnswerAtTheSave_onACopyInMemory_refusesTheSaveTheEditAndTheDeletion_andNothingWaits() = runBlocking<Unit> {
        val cache = InMemoryVaultCache()
        val (r, c) = seeded(cache)
        r.server.offline = true

        val acts = c.everyAct()
        for (act in listOf("new", "edit", "delete", "file")) {
            assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, assertIs<ActionResult.Failed>(acts[act], act).message, act)
        }
        assertEquals(ContentCopy.MOVE_RETRY, (acts["move"] as ActionResult.Failed).message)
        // What the person has: the list as it was (the editor still holds what they typed), and nothing to count.
        assertEquals(setOf("Bank", "Old", "Mail"), c.state.items.map { it.name }.toSet())
        assertEquals("pw-Bank", r.engine.item(c.idOf("Bank"))?.doc?.login?.password)
        assertEquals(0, unsent(cache))

        r.server.offline = false
        val before = r.server.pushes.size
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(before, r.server.pushes.size, "nothing that was refused is sent later")
    }

    @Test
    fun openedFromTheKeptCopyWithTheServerUnreachable_theSaveTheEditAndTheDeletionWait_andGoWhenItAnswers() = runBlocking<Unit> {
        val cache = DurableCache()
        val (r, first) = seeded(cache)
        first.close()
        // The app starts again from its kept copy and the server has not answered since.
        r.server.offline = true
        val engine = r.restarted()
        val c = content(r, engine)
        assertEquals(ContentCopy.SYNC_OFFLINE, (c.syncQuietly() as ActionResult.Failed).message)
        assertEquals(setOf("Bank", "Old", "Mail"), c.state.items.map { it.name }.toSet(), "the kept copy is shown")

        val acts = c.everyAct()
        assertEquals(ActionResult.Ok, acts["new"])
        assertEquals(ActionResult.Ok, acts["edit"])
        assertEquals(ActionResult.Ok, acts["delete"])
        assertEquals(ContentCopy.MOVE_RETRY, (acts["move"] as ActionResult.Failed).message)
        assertEquals(ContentCopy.SAVE_FAILED_OFFLINE, (acts["file"] as ActionResult.Failed).message)
        assertEquals(3, unsent(cache))

        r.server.offline = false
        assertEquals(ActionResult.Ok, c.syncQuietly())
        assertEquals(0, unsent(cache))
        assertTrue(r.server.itemRows.values.any { !it.deleted && it.itemId == c.idOf("Train") })
    }

    /**
     * The session's refresh fails: the push is answered `401` (the one refresh was refused, or got no answer). On a copy
     * kept at rest the change stays queued (design §4.4: the server's end keeps the copy, and what was not sent goes at
     * the next sign-in), and the sign-out counts it. On a copy in memory it is taken out with the refusal: it would
     * otherwise land later after the person was told it failed, or go at the lock the server's end brings, unsaid.
     */
    @Test
    fun aSessionTheServerEnded_keepsTheChangeOnACopyKeptAtRest_andTakesItOutOfACopyInMemory() = runBlocking<Unit> {
        for (durable in listOf(true, false)) {
            val cache: VaultCache = if (durable) DurableCache() else InMemoryVaultCache()
            val (r, c) = seeded(cache)
            r.server.refuseWith = 401 to "unauthorized"
            val saved = c.saveLogin(null, login("Train"), null)
            val deleted = c.deleteItem(c.idOf("Old"))
            if (durable) {
                // Kept, and said as kept: never "failed" (the rule of 2026-11-17).
                assertEquals(ActionResult.Ok, saved)
                assertEquals(ActionResult.Ok, deleted)
                assertEquals(ContentCopy.kept(io.silencelen.andvari.core.client.items.Written.KEPT_SESSION_ENDED), c.state.notice)
            } else {
                assertEquals(ContentCopy.SESSION_EXPIRED, assertIs<ActionResult.Failed>(saved, "durable=$durable").message)
                assertEquals(ContentCopy.SESSION_EXPIRED, assertIs<ActionResult.Failed>(deleted, "durable=$durable").message)
            }
            assertEquals(if (durable) 2 else 0, unsent(cache), "durable=$durable")

            // Signed in again: on the kept copy what waited is sent; from memory nothing was kept to send.
            r.server.refuseWith = null
            val before = r.server.pushes.size
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertEquals(if (durable) 2 else 0, r.server.pushes.drop(before).flatten().size, "durable=$durable")
            assertEquals(0, unsent(cache))
        }
    }

    /**
     * On a copy kept at rest, a save, an edit and a deletion the server refused for now (its session ended, too many
     * requests, a fault of its own) are kept and sent later, so each is said as kept, with a line of its own that says
     * when it goes, and never as failed; the item shows with its pending mark, as any queued change does.
     */
    @Test
    fun aRefusalForNow_onACopyKeptAtRest_isSaidAsKept_withALineForEachCase_andTheChangeShowsAsWaiting() = runBlocking<Unit> {
        val cases = listOf(
            Triple(401, "unauthorized", CopyKey.SAVE_KEPT_SESSION_ENDED),
            Triple(429, "rate_limited", CopyKey.SAVE_KEPT_TOO_MANY),
            Triple(503, "unavailable", CopyKey.SAVE_KEPT_SERVER_FAULT),
        )
        for ((status, code, key) in cases) {
            val cache = DurableCache()
            val (r, c) = seeded(cache)
            val bank = c.idOf("Bank")
            r.server.refuseWith = status to code
            for (act in listOf<suspend () -> ActionResult>(
                { c.saveLogin(null, login("Train"), null) },
                { c.saveLogin(bank, LoginInput("Bank", "me", "changed", listOf("https://bank.test"), "", "", false), null) },
                { c.deleteItem(c.idOf("Old")) },
            )) {
                assertEquals(ActionResult.Ok, act(), "$status")
                assertEquals(key.fill(emptyList()), c.state.notice, "$status")
                assertEquals(ContentNoticeKind.QUEUED, c.state.noticeKind, "$status")
            }
            assertEquals(3, unsent(cache), "$status")
            assertEquals(3, c.state.queued, "$status: as many items have a change waiting as for any queued change")
            assertTrue(c.state.items.single { it.name == "Train" }.pendingSync, "$status")
            assertEquals("changed", r.engine.item(bank)?.doc?.login?.password, "$status")

            r.server.refuseWith = null
            assertEquals(ActionResult.Ok, c.syncQuietly(), "$status")
            assertEquals(0, unsent(cache), "$status: sent when the server takes them again")
            assertTrue(r.server.itemRows.values.any { !it.deleted && it.itemId == c.idOf("Train") }, "$status")
        }
    }

    /** A rate limit or a server fault on the save's own push: the same as a session's end, on either copy. */
    @Test
    fun aRateLimitOrAServerFault_onACopyInMemory_refusesTheSave_andNothingLandsLaterUnseen() = runBlocking<Unit> {
        for (status in listOf(429, 503)) {
            val cache = InMemoryVaultCache()
            val (r, c) = seeded(cache)
            r.server.refuseWith = status to "transient_$status"
            assertIs<ActionResult.Failed>(c.saveLogin(null, login("Train"), null), "$status")
            assertEquals(0, unsent(cache), "$status")
            r.server.refuseWith = null
            val before = r.server.pushes.size
            assertEquals(ActionResult.Ok, c.syncQuietly())
            assertEquals(before, r.server.pushes.size, "$status: the refused save is not sent later")
            assertTrue(c.state.items.none { it.name == "Train" }, "$status")
        }
    }

    /**
     * An edit made over an earlier edit still waiting (carried into memory when the copy stopped being kept at rest):
     * when the new edit is refused, the earlier one is not taken down with it.
     */
    @Test
    fun aRefusedEditOnACopyInMemory_putsBackTheEarlierChangeStillWaiting() = runBlocking<Unit> {
        val durable = DurableCache()
        val r = ItemRig(durable)
        r.server.offline = true
        val train = r.engine.save(null, r.doc.copy(name = "Train")).let { (it as io.silencelen.andvari.core.client.items.ItemResult.Ok).value.itemId }
        // The copy moves to memory with its queue, as the app interface carries it when the consent is withdrawn.
        val memory = InMemoryVaultCache()
        val waiting = durable.pending()
        for (m in waiting) memory.enqueue(m)
        val engine = ItemEngine(r.server, r.keys, r.gate, memory, r.userId, r.crypto, { r.now })
        assertEquals("Train", engine.item(train)?.doc?.name)

        val refused = engine.save(train, r.doc.copy(name = "Train, edited"), vaultId = r.personal)
        assertIs<io.silencelen.andvari.core.client.items.ItemResult.Failed>(refused)
        assertEquals(waiting.map { it.mutationId }, memory.pending().map { it.mutationId }, "the earlier change still waits, as it was")
        assertEquals("Train", engine.item(train)?.doc?.name)

        r.server.offline = false
        assertIs<io.silencelen.andvari.core.client.items.ItemResult.Ok<*>>(engine.sync())
        assertNull(memory.pending().firstOrNull())
        assertEquals(setOf(train), r.server.applied())
    }
}
