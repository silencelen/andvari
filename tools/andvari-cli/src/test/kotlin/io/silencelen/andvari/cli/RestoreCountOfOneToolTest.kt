package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The tool's lines of a count of one read in the singular, as the desktop app's do (decided on 23 November 2026): a vault
 * of one item, one item the account already holds, one item to restore, one item restored into one vault, one attached
 * file carried, one item the server refused. Counts of none and of more read as before.
 */
class RestoreCountOfOneToolTest {
    private val env = RestoreFiles.env
    private val crypto = createCryptoProvider()

    @Test fun aBackupOfOneItemWithOneFileIntoAnAccountHoldingOneReadsInTheSingular() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("one@example.org")
            w.run(me, "item", "put", "personal", stdin = CliRun.lines("""{"type":"login","name":"Mine","login":{"username":"u","password":"p"}}""")).ok()
            val k = crypto.randomBytes(32)
            val ref = AttachmentRef("44444444-4444-4444-8444-000000000001", "scan.pdf", 20, Bytes.toB64(k))
            val bank = RestoreFiles.login(1, RestoreFiles.PERSONAL, "Bank").let { it.copy(doc = it.doc.copy(attachments = listOf(ref))) }
            val payload = RestoreFiles.personalOnly(emptyList()).copy(
                items = listOf(bank),
                attachments = listOf(BackupAttachmentEntry(1, ref.id, bank.itemId, "scan.pdf", 20, Bytes.toB64(k))),
            )
            val backup = RestoreFiles.write(w.tmp, "one.andvari", RestoreFiles.bytes(payload, "eeeeeeee-eeee-4eee-8eee-eeeeeeeec201", listOf(Backup.AttachmentSection(k.copyOf()) { ByteArray(20) { 3 } })))

            val preview = w.run(me, "restore", "--backup", backup.path, "--dry-run", env = { env[it] }).ok()
            println("ONE|preview=${preview.trim().lines()}")
            val lines = preview.lines()
            assertTrue("  personal vault “Personal”: 1 item" in lines, preview)
            assertTrue(
                "  this account already holds 1 item that no restore of this file on this device stored; a restore adds the backup's items beside it and replaces nothing, so an item in both will be there twice" in lines,
                preview,
            )
            assertTrue("  to restore: 1 item" in lines, preview)

            val run = w.run(me, "restore", "--backup", backup.path, env = { env[it] }).ok()
            println("ONE|run=${run.trim().lines().takeLast(2)}")
            assertTrue("restored 1 item into 1 vault; 1 attachment carried" in run.lines(), run)
        }
    }

    @Test fun oneItemTheServerRefusedReadsInTheSingularAndTwoItemsStoredAsBefore() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("one-refused@example.org")
            w.run(w.op, "operator", "quota", "one-refused@example.org", "--items", "2").ok()
            val backup = RestoreFiles.write(w.tmp, "three.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail", "Shop")), "eeeeeeee-eeee-4eee-8eee-eeeeeeeec202"))
            // The server gives no usage figures: the restore starts, and the server refuses the item that does not fit.
            p.lie = mapOf(WireRoute.SYNC to { e -> JsonObject(e.jsonObject - "quota") })
            val run = w.run(me, "restore", "--backup", backup.path, env = { env[it] }, dial = p.address)
            println("ONE|refused=${run.out.trim().lines()}")
            assertEquals(1, run.code, run.out + run.err)
            val lines = run.out.lines()
            assertTrue("  personal vault “Personal”: 3 items" in lines, run.out)
            assertTrue("  not stored: 1 item the server refused" in lines, run.out)
            assertTrue("restored 2 items into 1 vault" in lines, run.out)
        } }
    }
}
