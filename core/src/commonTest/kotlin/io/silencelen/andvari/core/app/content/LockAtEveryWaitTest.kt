package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AttachmentContent
import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.CardInput
import io.silencelen.andvari.core.app.ExportFile
import io.silencelen.andvari.core.app.ExportKind
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.InMemoryBlobs
import io.silencelen.andvari.core.app.InMemoryFillSnapshots
import io.silencelen.andvari.core.app.InMemorySaveQueue
import io.silencelen.andvari.core.app.LoginInput
import io.silencelen.andvari.core.app.NoteInput
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.client.items.DurableCache
import io.silencelen.andvari.core.client.items.ItemRig
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Every content intent overtaken by a lock, at each of its waits. The fake server holds the n-th
 * call an intent makes; the lock lands there as the app interface runs it (the content closes, then the item engine,
 * then the account's keys are wiped); the call is let go, and the intent must then:
 * - not throw to the screen;
 * - answer the lock: `NotDone(null)`, or null, or a file read with neither bytes nor an error. Never a refusal, so never
 *   "wrong password", "not ours" or "nothing there";
 * - delete or drop nothing on this device: every queued change at the lock is still queued or was sent, every item is
 *   still held or the server deleted it, and every kept record, set-aside file and capture is still there.
 *
 * It prints the table the report carries ("intent | wait | answer").
 */
class LockAtEveryWaitTest {
    private class Disk : KeptStorage {
        val records = HashMap<String, InMemoryFillSnapshots>()
        val blobSets = HashMap<String, InMemoryBlobs>()
        override fun record(name: String): FillSnapshotStore = records.getOrPut(name) { InMemoryFillSnapshots() }
        override fun blobs(name: String): BlobStore = blobSets.getOrPut(name) { InMemoryBlobs() }
        fun held(): Set<String> =
            records.filterValues { it.bytes != null }.keys + blobSets.flatMap { (n, b) -> b.ids().map { "$n/$it" } }
    }

    private class TestHost(val r: ItemRig) : ContentHost {
        override fun wallMs(): Long = r.now
        override fun attachmentLimits() = AttachmentRules.limits(null, null)
        override fun origin(): String = ORIGIN
        override fun userId(): String = r.userId
        override fun accountId(): String = "0123456789abcdef0123456789abcdef"
        override fun backupKdfParams(): KdfParams? = null
        override fun offlineCacheAllowed(): Boolean = true
    }

    /** One unlocked account with its content, over the real item engine and a fake server. */
    private inner class Ctx {
        val r = ItemRig(DurableCache())
        val disk = Disk()
        val queue = InMemorySaveQueue()
        val fill = InMemoryFillSnapshots()
        val stores = ContentStores(r.crypto, disk, queue, fill)
        val account: OpenedAccount = run {
            val seed = ByteArray(32) { 4 }
            val identity = r.crypto.boxKeypairFromSeed(seed)
            val genesis = VerifiedGenesis(GenesisFields(r.userId, Bytes.toB64(identity.publicKey), "instance", r.personal, 0), "00".repeat(32))
            OpenedAccount(r.userId, ByteArray(32) { 1 }, identity, r.crypto.signKeypairFromSeed(seed), genesis, r.personal, ByteArray(32) { 7 })
        }
        val c: EngineVaultContent = run {
            r.server.echo = true
            r.server.journal = true
            EngineVaultContent(r.engine, r.crypto, TestHost(r), stores.keeping(account, ORIGIN, offlineCacheAllowed = true))
        }

        fun lock() {
            c.close()
            r.engine.close()
            account.wipe()
        }

        suspend fun saved(name: String, withFile: Boolean = false): String {
            if (withFile) {
                c.openAttachmentDraft(null)
                check(c.addAttachment("a.txt", "file body".encodeToByteArray()) == ActionResult.Ok)
            }
            check(c.saveLogin(null, login(name), null) == ActionResult.Ok)
            return c.state.items.first { it.name == name }.itemId
        }

        /** Two copies of one login, as Health's duplicates list shows them: the cluster's signature. */
        suspend fun duplicates(): String {
            c.saveLogin(null, login("Dup", "https://dup.test"), null)
            c.saveLogin(null, login("Dup", "https://dup.test"), null)
            c.openHealth()
            return c.state.health!!.duplicates.first().signature
        }

        /** A capture of an extension, after the sync that publishes the key it is sealed to. */
        suspend fun capture(site: String, user: String, password: String) {
            c.syncQuietly()
            SaveQueue.enqueue(queue, r.crypto, site, user, password, r.now, "safari")
        }
    }

    private class Case(val name: String, val setup: suspend Ctx.() -> Any? = { null }, val call: suspend Ctx.(Any?) -> Any?)

    private fun login(name: String, uri: String = "https://example.com", password: String = "pw") = LoginInput(name, "me", password, listOf(uri), "", "", false)

    private val cases = listOf(
        Case("saveLogin, new") { c.saveLogin(null, login("New"), null) },
        Case("saveLogin, edit", { saved("Old") }) { c.saveLogin(it as String, login("Edited"), null) },
        Case("saveLogin, with a file") {
            c.openAttachmentDraft(null)
            c.addAttachment("b.txt", "body".encodeToByteArray())
            c.saveLogin(null, login("With file"), null)
        },
        Case("saveCard, new") { c.saveCard(null, CardInput("Visa", "A B", "4111111111111111", "07/31", "", "123", "", "", false), null) },
        Case("saveNote, new") { c.saveNote(null, NoteInput("Note", "text", false), null) },
        Case("deleteItem", { saved("Gone") }) { c.deleteItem(it as String) },
        Case("readAttachment", { saved("Has file", withFile = true) }) { id ->
            val item = c.itemDetail(id as String)!!
            c.readAttachment(id, item.attachments.single().id)
        },
        Case("openTrash", { c.deleteItem(saved("Binned")) }) { c.openTrash() },
        Case("restoreFromTrash", { saved("Binned").also { c.deleteItem(it); c.openTrash() } }) { c.restoreFromTrash(it as String) },
        Case("purgeFromTrash", { saved("Binned").also { c.deleteItem(it); c.openTrash() } }) { c.purgeFromTrash(it as String) },
        Case("openDeletedVaults") { c.openDeletedVaults() },
        Case("openItemHistory", { saved("V1").also { c.saveLogin(it, login("V2"), null) } }) { c.openItemHistory(it as String) },
        Case("restoreItemVersion", {
            saved("V1").also {
                c.saveLogin(it, login("V2"), null)
                c.openItemHistory(it)
            }
        }) { id -> c.restoreItemVersion(id as String, c.state.history!!.versions.first().rev) },
        Case("moveOrCopyItem, move", { r.openShared(); saved("Mover") }) { c.moveOrCopyItem(it as String, r.shared, true) },
        Case("moveOrCopyItem, copy", { r.openShared(); saved("Copier") }) { c.moveOrCopyItem(it as String, r.shared, false) },
        Case("saveVaultItemsToPersonal", { r.openShared(items = listOf(r.itemRow(r.id(), r.shared, r.sharedKey))); c.refresh() }) { c.saveVaultItemsToPersonal(r.shared) },
        Case("renameSharedVault", { r.openShared(role = "owner"); c.refresh() }) { c.renameSharedVault(r.shared, "Renamed") },
        Case("checkBreaches", { saved("Site").also { c.openHealth() } }) { c.checkBreaches() },
        Case("mergeDuplicates", { duplicates() }) { c.mergeDuplicates(it as String) },
        Case("keepDuplicate", { duplicates() }) { sig -> c.keepDuplicate(sig as String, c.state.items.first().itemId) },
        Case("markNotDuplicates", { duplicates() }) { c.markNotDuplicates(it as String) },
        Case("importCsv") { c.importCsv("name,url,username,password,note\nA,https://a.test,u,p,\n".encodeToByteArray()) },
        Case("confirmImport", { c.importCsv("name,url,username,password,note\nA,https://a.test,u,p,\nB,https://b.test,u,p,\n".encodeToByteArray()) }) { c.confirmImport() },
        Case("openExport", { saved("Exported") }) { c.openExport(ExportKind.BACKUP) },
        Case("backupFile", {
            saved("Backed up", withFile = true)
            c.openExport(ExportKind.BACKUP)
            c.setExportAttachments(true)
        }) { c.backupFile("correct horse battery staple", "correct horse battery staple") },
        Case("readSaveQueue", { capture("https://new.test", "me", "pw1") }) { c.readSaveQueue() },
        Case("confirmPendingSave", {
            // Held for the person's word while the personal vault could not be written, then it can again.
            capture("https://new.test", "me", "pw1")
            r.keys.put(r.personal, r.personalKey, standing = io.silencelen.andvari.core.client.items.VaultStanding.FROZEN)
            c.readSaveQueue()
            r.keys.put(r.personal, r.personalKey)
            c.state.pendingSaves.first().id
        }) { c.confirmPendingSave(it as String) },
        Case("discardPendingSave", {
            capture("https://new.test", "me", "pw1")
            r.keys.put(r.personal, r.personalKey, standing = io.silencelen.andvari.core.client.items.VaultStanding.FROZEN)
            c.readSaveQueue()
            r.keys.put(r.personal, r.personalKey)
            c.state.pendingSaves.first().id
        }) { c.discardPendingSave(it as String) },
        Case("dismissAppliedSaves", {
            capture("https://new.test", "me", "pw1")
            c.readSaveQueue()
        }) { c.dismissAppliedSaves() },
        Case("undoAppliedSave", {
            capture("https://new.test", "me", "pw1")
            c.readSaveQueue()
            c.state.appliedSaves.first().id
        }) { c.undoAppliedSave(it as String) },
        Case("undoAllAppliedSaves", {
            capture("https://new.test", "me", "pw1")
            c.readSaveQueue()
        }) { c.undoAllAppliedSaves() },
        Case("refresh", { saved("Item") }) { c.refresh() },
        Case("syncQuietly", { saved("Item") }) { c.syncQuietly() },
    )

    /** What the device holds at a moment: queued mutation ids, held item ids, kept records and files, captures, the snapshot. */
    private class Held(val pending: Set<String>, val items: Set<String>, val kept: Set<String>, val captures: Set<String>, val fill: Boolean)

    private fun Ctx.held() = Held(
        r.cache.pending().mapTo(HashSet()) { it.mutationId },
        r.cache.envelopes().filter { !it.deleted }.mapTo(HashSet()) { it.itemId },
        disk.held(), queue.entries().keys, fill.bytes != null,
    )

    private fun describe(a: Any?): String = when (a) {
        null -> "null"
        is ActionResult.NotDone -> "NotDone(${a.message})"
        is ActionResult.Failed -> "Failed(${a.message})"
        is ActionResult.Ok -> "Ok"
        is AttachmentContent -> "AttachmentContent(bytes=${a.bytes != null}, error=${a.error})"
        is ExportFile -> "ExportFile"
        else -> a.toString()
    }

    /** The lock's own answer: nothing done, nothing said, nothing handed out. */
    private fun isLockAnswer(a: Any?): Boolean = when (a) {
        null -> true
        is ActionResult.NotDone -> a.message == null
        is AttachmentContent -> a.bytes == null && a.error == null
        else -> false
    }

    @Test
    fun everyIntent_atEveryWait_answersTheLock_andDropsNothing() = runBlocking<Unit> {
        val table = ArrayList<String>()
        val problems = ArrayList<String>()
        for (case in cases) {
            var n = 1
            while (n <= 12) {
                val x = Ctx()
                val arg = try {
                    case.setup(x)
                } catch (t: Throwable) {
                    problems += "${case.name}: its setup failed: $t"
                    break
                }
                var calls = 0
                var route = ""
                val entered = CompletableDeferred<Unit>()
                val release = CompletableDeferred<Unit>()
                x.r.server.hold = { which ->
                    if (++calls == n) {
                        route = which
                        entered.complete(Unit)
                        release.await()
                    }
                }
                val run = async { runCatching { case.call(x, arg) } }
                // Bounded: an intent that throws inside a coroutine fails here, naming the wait.
                val reached = io.silencelen.andvari.core.app.waitFor("${case.name} to reach its server call $n or to answer") {
                    select { entered.onAwait { true }; run.onAwait { false } }
                }
                if (!reached) {
                    if (n == 1) table += "| ${case.name} | (no wait) | ${describe(run.await().getOrNull())} |"
                    break
                }
                val before = x.held()
                x.lock()
                release.complete(Unit)
                val outcome = io.silencelen.andvari.core.app.waitFor("${case.name} to answer after the lock at $route (call $n)") { run.await() }
                x.r.server.hold = null
                val answer = outcome.getOrNull()
                val wait = "$route (call $n)"
                table += "| ${case.name} | $wait | ${outcome.exceptionOrNull()?.let { "THROWS ${it::class.simpleName}" } ?: describe(answer)} |"
                outcome.exceptionOrNull()?.let { problems += "${case.name} at $wait threw $it" }
                if (outcome.isSuccess && !isLockAnswer(answer)) problems += "${case.name} at $wait answered ${describe(answer)}"
                val after = x.held()
                val sent = x.r.server.pushes.flatten().mapTo(HashSet()) { it.mutationId }
                val dropped = before.pending.filter { it !in after.pending && it !in sent }
                if (dropped.isNotEmpty()) problems += "${case.name} at $wait dropped queued changes $dropped"
                val gone = before.items.filter { it !in after.items && x.r.server.itemRows[it]?.deleted != true && it !in x.r.server.purged }
                if (gone.isNotEmpty()) problems += "${case.name} at $wait dropped items $gone"
                if (!after.kept.containsAll(before.kept)) problems += "${case.name} at $wait dropped kept records ${before.kept - after.kept}"
                if (!after.captures.containsAll(before.captures)) problems += "${case.name} at $wait dropped captures ${before.captures - after.captures}"
                if (before.fill && !after.fill) problems += "${case.name} at $wait deleted the fill snapshot"
                n++
            }
        }
        println("| Intent | Wait the lock landed in | Answer |\n|---|---|---|\n" + table.joinToString("\n"))
        if (problems.isNotEmpty()) fail(problems.joinToString("\n"))
    }

    /** The calls that never wait: after the lock they hand out nothing and write nothing. */
    @Test
    fun theFillCallsAndTheSnapshot_handOutNothingAfterTheLock() = runBlocking<Unit> {
        val x = Ctx()
        val id = x.saved("Fill me")
        x.c.saveCard(null, CardInput("Visa", "A B", "4111111111111111", "07/31", "", "123", "", "", false), null)
        val card = x.c.state.items.first { it.name == "Visa" }.itemId
        val snapshot = x.fill.bytes?.copyOf()
        x.lock()
        assertEquals(emptyList(), x.c.fillLogins(listOf("example.com")))
        assertEquals(null, x.c.fillCredential(id))
        assertEquals(emptyList(), x.c.fillCards())
        assertEquals(null, x.c.fillCardField(card, "number"))
        assertEquals(emptyList(), x.c.credentialIdentities())
        assertEquals(null, x.c.revealSecret(id, io.silencelen.andvari.core.app.SecretField.PASSWORD))
        assertEquals(null, x.c.oneTimeCode(id))
        x.c.reload()
        assertTrue(snapshot == null || snapshot.contentEquals(x.fill.bytes), "the snapshot is neither rewritten nor deleted by a lock")
    }

    private companion object {
        const val ORIGIN = "https://vault.example.com"
    }
}
