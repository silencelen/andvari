package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Files a restore refuses whole, before anything is shown or written: a file cut short at the edge of a part, a file
 * whose attached files no honest writer arranges so, a document nested past the reader's bound. And a part that only an
 * item of no listed vault names, which is never read.
 */
class RestoreWholeFileRulesTest {
    private val env = RestoreFiles.env
    private val crypto = createCryptoProvider()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val x = "44444444-4444-4444-8444-4444444444a1"
    private val y = "44444444-4444-4444-8444-4444444444a2"

    private fun restore(w: CliWorld, home: File, file: File, vararg more: String) =
        w.run(home, "restore", "--backup", file.path, *more, env = { env[it] })

    private fun records(home: File): List<String> = home.listFiles().orEmpty().map { it.name }.filter { it.startsWith("restore-") }

    private fun count(w: CliWorld, home: File) = w.run(home, "item", "list", "personal").ok().lines().count { it.isNotBlank() }

    /** Refused before the preview with [code], dry run and run alike; no record, nothing stored. */
    private fun refusedWhole(w: CliWorld, home: File, file: File, code: String, what: String) {
        for (more in listOf(arrayOf("--dry-run"), emptyArray())) {
            val run = restore(w, home, file, *more)
            assertEquals(1, run.code, "$what ${more.toList()}: ${run.out}${run.err}")
            assertTrue(run.err.contains("the backup does not open: $code"), "$what ${more.toList()}: ${run.err}")
            assertTrue(!run.out.contains("Backup made"), "$what: no preview was shown")
        }
        assertEquals(emptyList(), records(home), "$what: no record")
        assertEquals(0, count(w, home), "$what: nothing stored")
    }

    /** The offsets where the parts of [b] end: the header first, then each framed part (the last is the file's end). */
    private fun edges(b: ByteArray): List<Int> {
        fun le(at: Int, n: Int) = (0 until n).fold(0L) { acc, i -> acc or ((b[at + i].toLong() and 0xFF) shl (8 * i)) }
        var at = 12 + le(8, 4).toInt()
        val out = arrayListOf(at)
        while (at < b.size) {
            at += 8 + le(at, 8).toInt()
            out += at
        }
        return out
    }

    // ---- a file cut short at the edge of a part ----

    /** "Bank", "Mail" and "Shop" with one attached file each, sealed by the shared writer (`Backup.build`). */
    private fun threeWithFiles(): ByteArray {
        val sizes = listOf(30, 5_000, 12)
        val base = RestoreFiles.personalOnly(listOf("Bank", "Mail", "Shop"))
        val keys = sizes.map { crypto.randomBytes(32) }
        val ids = sizes.indices.map { "44444444-4444-4444-8444-00000000000${it + 1}" }
        val items = base.items.mapIndexed { i, item ->
            item.copy(doc = item.doc.copy(attachments = listOf(AttachmentRef(ids[i], "f$i.bin", sizes[i].toLong(), Bytes.toB64(crypto.randomBytes(32))))))
        }
        val entries = sizes.indices.map { BackupAttachmentEntry(it + 1, ids[it], RestoreFiles.itemId(it + 1), "f$it.bin", sizes[it].toLong(), Bytes.toB64(keys[it])) }
        val parts = sizes.indices.map { i -> Backup.AttachmentSection(keys[i].copyOf()) { ByteArray(sizes[i]) { b -> (b % 7).toByte() } } }
        return RestoreFiles.bytes(base.copy(items = items, attachments = entries), "eeeeeeee-eeee-4eee-8eee-eeeeeeeee101", parts)
    }

    @Test fun aBackupCutAtAnyEdgeBetweenTwoPartsIsRefusedWholeAsCutShort() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val whole = threeWithFiles()
            // After the header, after the items, after the first file, after the second file.
            val cuts = edges(whole).dropLast(1)
            assertEquals(4, cuts.size, "$cuts")
            for (cut in cuts) refusedWhole(w, me, RestoreFiles.write(w.tmp, "cut-$cut.andvari", whole.copyOf(cut)), Backup.ERR_TRUNCATED, "cut at $cut")
            // The whole file then restores whole, every file with its item.
            val done = Json.parseToJsonElement(restore(w, me, RestoreFiles.write(w.tmp, "whole.andvari", whole), "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(3, done.getValue("items").jsonPrimitive.int)
            assertEquals(3, done.getValue("attachmentsCarried").jsonPrimitive.int)
            assertEquals(3, count(w, me))
        }
    }

    // ---- attached files arranged as no honest writer arranges them ----

    /** [payload] sealed as written, each of [parts] (key, bytes) a part of its own, whatever its manifest says. */
    private fun sealed(payload: BackupPayload, parts: List<Pair<ByteArray, ByteArray>>, fileId: String): ByteArray {
        val out = ArrayList<ByteArray>()
        Backup.buildWithPayloadBytes(
            crypto, RestoreFiles.PASS, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray(),
            parts.map { (k, b) -> Backup.AttachmentSection(k.copyOf()) { b.copyOf() } }, null,
        ) { out += it.copyOf() }
        return out.fold(ByteArray(0)) { acc, b -> acc + b }
    }

    /** "Bank" naming the file [x] and "Mail" naming nothing, with the entries [entries] made by [entries] from fresh keys. */
    private fun bankAndMail(fileId: String, entries: (List<ByteArray>) -> List<BackupAttachmentEntry>): ByteArray {
        val keys = List(2) { crypto.randomBytes(32) }
        val base = RestoreFiles.personalOnly(listOf("Bank", "Mail"))
        val items = base.items.mapIndexed { i, it ->
            if (i == 0) it.copy(doc = it.doc.copy(attachments = listOf(AttachmentRef(x, "scan.pdf", 4, Bytes.toB64(crypto.randomBytes(32)))))) else it
        }
        val list = entries(keys)
        return sealed(base.copy(items = items, attachments = list), list.map { e -> keys[e.section - 1] to "SCAN".encodeToByteArray() }, fileId)
    }

    @Test fun anEntryUnderAnItemWhoseDocumentDoesNotNameItRefusesTheWholeFile() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            // Under "Mail", which names no file at all.
            val toMail = bankAndMail("eeeeeeee-eeee-4eee-8eee-eeeeeeeee102") { k ->
                listOf(BackupAttachmentEntry(1, x, RestoreFiles.itemId(1), "scan.pdf", 4, Bytes.toB64(k[0])), BackupAttachmentEntry(2, y, RestoreFiles.itemId(2), "other.pdf", 4, Bytes.toB64(k[1])))
            }
            refusedWhole(w, me, RestoreFiles.write(w.tmp, "to-mail.andvari", toMail), Backup.ERR_BAD_PAYLOAD, "an entry under Mail")
            // Under "Bank", whose document names x only.
            val toBank = bankAndMail("eeeeeeee-eeee-4eee-8eee-eeeeeeeee103") { k ->
                listOf(BackupAttachmentEntry(1, x, RestoreFiles.itemId(1), "scan.pdf", 4, Bytes.toB64(k[0])), BackupAttachmentEntry(2, y, RestoreFiles.itemId(1), "other.pdf", 4, Bytes.toB64(k[1])))
            }
            refusedWhole(w, me, RestoreFiles.write(w.tmp, "to-bank.andvari", toBank), Backup.ERR_BAD_PAYLOAD, "a second entry under Bank")
        }
    }

    @Test fun theSameEntryTwiceUnderOneItemRefusesTheWholeFile() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val twice = bankAndMail("eeeeeeee-eeee-4eee-8eee-eeeeeeeee104") { k ->
                listOf(BackupAttachmentEntry(1, x, RestoreFiles.itemId(1), "scan.pdf", 4, Bytes.toB64(k[0])), BackupAttachmentEntry(2, x, RestoreFiles.itemId(1), "scan.pdf", 4, Bytes.toB64(k[1])))
            }
            refusedWhole(w, me, RestoreFiles.write(w.tmp, "twice.andvari", twice), Backup.ERR_BAD_PAYLOAD, "the same entry twice")
        }
    }

    @Test fun anEntryWithAPartNumberBelowOneRefusesTheWholeFile() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            for ((n, section) in listOf(0, -1).withIndex()) {
                val key = crypto.randomBytes(32)
                val base = RestoreFiles.personalOnly(listOf("Bank", "Mail"))
                val items = base.items.mapIndexed { i, it ->
                    if (i == 0) it.copy(doc = it.doc.copy(attachments = listOf(AttachmentRef(x, "scan.pdf", 4, Bytes.toB64(crypto.randomBytes(32)))))) else it
                }
                // The file holds one part; its entry names part [section].
                val entry = BackupAttachmentEntry(section, x, RestoreFiles.itemId(1), "scan.pdf", 4, Bytes.toB64(key))
                val bytes = sealed(base.copy(items = items, attachments = listOf(entry)), listOf(key to "SCAN".encodeToByteArray()), "eeeeeeee-eeee-4eee-8eee-eeeeeeeee11$n")
                refusedWhole(w, me, RestoreFiles.write(w.tmp, "part-$n.andvari", bytes), Backup.ERR_BAD_PAYLOAD, "an entry naming part $section")
            }
        }
    }

    // ---- a document nested past the reader's bound ----

    /** The deepest nesting the shared reader takes (the payload's own object counted as one). */
    private val bound = Backup.MAX_PAYLOAD_DEPTH

    /** "Bank" and "Deep", where Deep's document holds arrays nested so that the payload's deepest point is [depth]. */
    private fun nested(depth: Int, fileId: String): ByteArray {
        val base = RestoreFiles.personalOnly(listOf("Bank", "Deep")).let { p -> p.copy(items = p.items.mapIndexed { i, it -> if (i == 1) it.copy(doc = it.doc.copy(notes = "MARK")) else it }) }
        // The payload's object, its items, the item, its document: four, then the arrays.
        val k = depth - 4
        val text = json.encodeToString(BackupPayload.serializer(), base).replace("\"notes\":\"MARK\"", "\"notes\":\"x\",\"deep\":" + "[".repeat(k) + "]".repeat(k))
        assertTrue(text.contains("[".repeat(k)))
        val out = ArrayList<ByteArray>()
        Backup.buildWithPayloadBytes(crypto, RestoreFiles.PASS, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), text.encodeToByteArray(), emptyList(), null) { out += it.copyOf() }
        return out.fold(ByteArray(0)) { acc, b -> acc + b }
    }

    @Test fun aDocumentNestedPastTheBoundIsRefusedOnTheDryRunAndTheRunAndOneAtTheBoundIsRead() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            refusedWhole(w, me, RestoreFiles.write(w.tmp, "deep-10000.andvari", nested(10_000, "eeeeeeee-eeee-4eee-8eee-eeeeeeeee105")), Backup.ERR_BAD_PAYLOAD, "nested 10 000 deep")
            refusedWhole(w, me, RestoreFiles.write(w.tmp, "deep-over.andvari", nested(bound + 1, "eeeeeeee-eeee-4eee-8eee-eeeeeeeee106")), Backup.ERR_BAD_PAYLOAD, "nested one past the bound")
            val at = RestoreFiles.write(w.tmp, "deep-at.andvari", nested(bound, "eeeeeeee-eeee-4eee-8eee-eeeeeeeee107"))
            assertEquals(0, restore(w, me, at, "--dry-run").code)
            val done = Json.parseToJsonElement(restore(w, me, at, "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(2, done.getValue("items").jsonPrimitive.int)
        }
    }

    // ---- a part only an item of no listed vault names is never read ----

    @Test fun aPartNamedOnlyByAnItemOfNoListedVaultIsNeverReadEvenUnderTheIdOfACarriedFile() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val good = crypto.randomBytes(32)
            val strayKey = crypto.randomBytes(32)
            val ref = { AttachmentRef(x, "scan.pdf", 4, Bytes.toB64(crypto.randomBytes(32))) }
            val base = RestoreFiles.personalOnly(listOf("Bank"))
            val bank = base.items.single().let { it.copy(doc = it.doc.copy(attachments = listOf(ref()))) }
            // "Stray" lies in a vault the file does not list and names the same file id; its entry comes first.
            val stray = RestoreFiles.login(2, "99999999-9999-4999-8999-999999999999", "Stray").let { it.copy(doc = it.doc.copy(attachments = listOf(ref()))) }
            val payload = base.copy(
                items = listOf(bank, stray),
                attachments = listOf(
                    BackupAttachmentEntry(1, x, RestoreFiles.itemId(2), "scan.pdf", 4, Bytes.toB64(strayKey)),
                    BackupAttachmentEntry(2, x, RestoreFiles.itemId(1), "scan.pdf", 4, Bytes.toB64(good)),
                ),
            )
            // Stray's part is sealed under another key than its entry gives: reading it would stop the restore.
            val file = RestoreFiles.write(w.tmp, "stray.andvari", sealed(payload, listOf(crypto.randomBytes(32) to "XXXX".encodeToByteArray(), good to "SCAN".encodeToByteArray()), "eeeeeeee-eeee-4eee-8eee-eeeeeeeee108"))
            val preview = Json.parseToJsonElement(restore(w, me, file, "--dry-run", "--json").ok()).jsonObject
            assertEquals(1, preview.getValue("attachments").jsonPrimitive.int, "only Bank's file is counted")
            val left = preview.getValue("leftOut").jsonObject
            assertEquals(1, left.getValue("itemsUnderNoVault").jsonPrimitive.int)
            assertEquals(1, left.getValue("filesUnderNoItem").jsonPrimitive.int)
            val done = Json.parseToJsonElement(restore(w, me, file, "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(1, done.getValue("items").jsonPrimitive.int)
            assertEquals(1, done.getValue("attachmentsCarried").jsonPrimitive.int)
            assertEquals(0, done.getValue("attachmentsStripped").jsonPrimitive.int)
        }
    }
}
