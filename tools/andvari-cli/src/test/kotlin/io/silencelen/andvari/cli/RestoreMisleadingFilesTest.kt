package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.RandomAccessFile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Files made to mislead a restore, one rule each: the file's id, the record that belongs to the file's bytes, the size
 * asked before the read, nothing the restore leaves out unsaid, and sections no item names left unread.
 */
class RestoreMisleadingFilesTest {
    private val env = RestoreFiles.env

    private fun restore(w: CliWorld, home: File, file: File, vararg more: String, pass: String = RestoreFiles.PASS) =
        w.run(home, "restore", "--backup", file.path, *more, env = { if (it == "ANDVARI_BACKUP_PASSPHRASE") pass else env[it] })

    private fun count(w: CliWorld, home: File) = w.run(home, "item", "list", "personal").ok().lines().count { it.isNotBlank() }

    /** Every path under [dir], relative. */
    private fun tree(dir: File): Set<String> = dir.walkTopDown().map { it.relativeTo(dir).path }.toSet()

    // ---- A1: the file's id ----

    @Test fun aFileWhoseIdIsNotALowerCaseUuidIsRefusedAndNothingAppearsInOrOutsideTheHome() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            count(w, me)
            val ids = listOf(
                "x/../../escaped", "..", "a\\b", "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE", "eeeeeeee" + Char(0) + "eeee", "a".repeat(4000),
                "/tmp/andvari-restore-escaped",
            )
            for ((i, id) in ids.withIndex()) {
                val file = RestoreFiles.write(w.tmp, "bad-$i.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank")), fileId = id))
                val before = tree(w.tmp)
                val run = restore(w, me, file)
                assertEquals(1, run.code, "$i: " + run.out + run.err)
                assertEquals(before, tree(w.tmp), "$i: nothing appeared in or beside the home")
                assertTrue(!File("/tmp/andvari-restore-escaped").exists() && File("/tmp").listFiles()!!.none { it.name.startsWith("andvari-restore-escaped") })
                assertEquals(0, count(w, me), "$i: nothing restored")
            }
        }
    }

    // ---- A2: the record belongs to the file's bytes ----

    private fun names(w: CliWorld, home: File) = w.run(home, "item", "list", "personal").ok().lines().filter { it.isNotBlank() }.map { it.substringAfter("  ") }.sorted()

    @Test fun twoFilesUnderOneIdEachRestoreWholeInEitherOrderAndNothingTwice() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val id = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee9"
            val a = RestoreFiles.write(w.tmp, "a.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail")), fileId = id))
            val b = RestoreFiles.write(w.tmp, "b.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Shop", "Cafe")), fileId = id))
            val c = RestoreFiles.write(w.tmp, "c.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Gym")), fileId = id, pass = "another pass phrase"))
            val files = listOf(a to RestoreFiles.PASS, b to RestoreFiles.PASS, c to "another pass phrase")
            val whole = mapOf(a to 2, b to 2, c to 1)
            fun restored(home: File, f: Pair<File, String>) =
                Json.parseToJsonElement(restore(w, home, f.first, "--json", pass = f.second).ok()).jsonObject.getValue("restored").jsonObject.getValue("items").jsonPrimitive.int
            for ((n, order) in listOf(files, files.reversed()).withIndex()) {
                val home = w.account("person$n@example.org")
                for (f in order) assertEquals(whole.getValue(f.first), restored(home, f), "${f.first.name} restores whole")
                for (f in order) assertEquals(0, restored(home, f), "${f.first.name} again: nothing twice")
                assertEquals(listOf("Bank", "Cafe", "Gym", "Mail", "Shop"), names(w, home))
            }
        }
    }

    // ---- A3: the size before the read ----

    @Test fun aFileOverTheCapIsRefusedUnread() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val big = File(w.tmp, "big.andvari")
            RandomAccessFile(big, "rw").use { it.setLength(Backup.MAX_FILE_BYTES + 1) }
            // What this process read, as the kernel counts it: a read of the file would add more than 256 MiB.
            fun read(): Long = File("/proc/self/io").readLines().first { it.startsWith("rchar:") }.substringAfter(':').trim().toLong()
            val before = read()
            val run = restore(w, me, big)
            val after = read()
            assertEquals(1, run.code, run.out + run.err)
            assertTrue(run.err.contains("the backup does not open: too_large"), run.err)
            assertTrue(after - before < 64L * 1024 * 1024, "the file was read: ${after - before} bytes")
        }
    }

    // ---- A4: nothing is skipped unsaid ----

    private val crypto = createCryptoProvider()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val p = RestoreFiles.PERSONAL

    private fun leftOut(doc: JsonObject): Map<String, Int> = doc.getValue("leftOut").jsonObject.mapValues { it.value.jsonPrimitive.int }.filterValues { it != 0 }

    private fun preview(w: CliWorld, home: File, file: File): JsonObject = Json.parseToJsonElement(restore(w, home, file, "--dry-run", "--json").ok()).jsonObject

    /** [payload] sealed as written, with [sections] as given whatever its manifest says. */
    private fun sealed(payload: BackupPayload, sections: List<Backup.AttachmentSection>, fileId: String = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee5"): ByteArray {
        val parts = ArrayList<ByteArray>()
        Backup.buildWithPayloadBytes(
            crypto, RestoreFiles.PASS, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray(), sections, null,
        ) { parts += it.copyOf() }
        return parts.fold(ByteArray(0)) { acc, p -> acc + p }
    }

    @Test fun aSecondVaultUnderAUsedIdIsShownOnceCountedOnceAndSaid() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            w.run(w.op, "operator", "quota", "me@example.org", "--items", "2").ok()
            val payload = BackupPayload(
                exportedAt = 1_760_000_000_000L, origin = "https://old.example",
                vaults = listOf(BackupVault(p, "personal", "Personal", "owner"), BackupVault(p, "personal", "Personal again", "owner")),
                items = listOf(RestoreFiles.login(1, p, "Bank"), RestoreFiles.login(2, p, "Mail")),
            )
            val file = RestoreFiles.write(w.tmp, "f.andvari", RestoreFiles.bytes(payload))
            val doc = preview(w, me, file)
            assertEquals(listOf("Personal" to 2), doc.getValue("vaults").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content to it.jsonObject.getValue("items").jsonPrimitive.int })
            assertEquals(mapOf("vaultsTwice" to 1), leftOut(doc))
            // The room check counts its items once: two items fit a limit of two.
            val done = Json.parseToJsonElement(restore(w, me, file, "--vaults", "all", "--json").ok()).jsonObject
            assertEquals(2, done.getValue("restored").jsonObject.getValue("items").jsonPrimitive.int)
            assertEquals(1, done.getValue("restored").jsonObject.getValue("vaults").jsonPrimitive.int)
            assertEquals(mapOf("vaultsTwice" to 1), leftOut(done.getValue("restored").jsonObject))
            assertEquals(listOf("Bank", "Mail"), names(w, me))
        }
    }

    @Test fun aSecondItemUnderAUsedIdIsLeftOutSaidAndNeverSentUnderTheFirstOnesId() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val payload = RestoreFiles.personalOnly(listOf("Bank", "Mail")).let { it.copy(items = it.items + RestoreFiles.login(1, p, "Bank twin")) }
            val file = RestoreFiles.write(w.tmp, "f.andvari", RestoreFiles.bytes(payload))
            val doc = preview(w, me, file)
            assertEquals(2, doc.getValue("vaults").jsonArray.single().jsonObject.getValue("items").jsonPrimitive.int)
            assertEquals(mapOf("itemsTwice" to 1), leftOut(doc))
            val done = Json.parseToJsonElement(restore(w, me, file, "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(2, done.getValue("items").jsonPrimitive.int, "the second is never counted as stored")
            assertEquals(mapOf("itemsTwice" to 1), leftOut(done))
            assertEquals(listOf("Bank", "Mail"), names(w, me))
        }
    }

    @Test fun anItemUnderAVaultTheFileDoesNotListIsLeftOutAndSaid() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val payload = RestoreFiles.personalOnly(listOf("Bank")).let { it.copy(items = it.items + RestoreFiles.login(2, "99999999-9999-4999-8999-999999999999", "Stray")) }
            val file = RestoreFiles.write(w.tmp, "f.andvari", RestoreFiles.bytes(payload))
            assertEquals(mapOf("itemsUnderNoVault" to 1), leftOut(preview(w, me, file)))
            val done = Json.parseToJsonElement(restore(w, me, file, "--vaults", "all", "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(mapOf("itemsUnderNoVault" to 1), leftOut(done))
            assertEquals(listOf("Bank"), names(w, me))
        }
    }

    /** "Bank" (item 1) with the file "scan.pdf" in section 1; [extra] entries and [sections] beyond it as the case needs. */
    private fun withFiles(extra: List<BackupAttachmentEntry>, sections: Int, refs: Map<Int, String> = emptyMap()): ByteArray {
        val key = crypto.randomBytes(32)
        val file = "the bytes of the scan".encodeToByteArray()
        val att = "44444444-4444-4444-8444-444444444441"
        val base = RestoreFiles.personalOnly(listOf("Bank", "Mail"))
        val items = base.items.mapIndexed { i, item ->
            val ids = listOfNotNull(if (i == 0) att else null, refs[i + 1])
            item.copy(doc = item.doc.copy(attachments = ids.map { AttachmentRef(it, if (it == att) "scan.pdf" else "other.pdf", file.size.toLong(), Bytes.toB64(crypto.randomBytes(32))) }))
        }
        val payload = base.copy(items = items, attachments = listOf(BackupAttachmentEntry(1, att, RestoreFiles.itemId(1), "scan.pdf", file.size.toLong(), Bytes.toB64(key))) + extra)
        val parts = List(sections) { i -> if (i == 0) Backup.AttachmentSection(key) { file.copyOf() } else Backup.AttachmentSection(crypto.randomBytes(32)) { "another file".encodeToByteArray() } }
        return sealed(payload, parts)
    }

    @Test fun anAttachedFileUnderAnItemTheFileDoesNotListIsLeftOutAndSaid() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val stray = BackupAttachmentEntry(2, "44444444-4444-4444-8444-444444444442", "22222222-2222-4222-8222-999999999999", "stray.pdf", 12, Bytes.toB64(crypto.randomBytes(32)))
            val file = RestoreFiles.write(w.tmp, "f.andvari", withFiles(listOf(stray), sections = 2))
            val doc = preview(w, me, file)
            assertEquals(mapOf("filesUnderNoItem" to 1), leftOut(doc))
            assertEquals(1, doc.getValue("attachments").jsonPrimitive.int)
            val done = Json.parseToJsonElement(restore(w, me, file, "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(mapOf("filesUnderNoItem" to 1), leftOut(done))
            assertEquals(1, done.getValue("attachmentsCarried").jsonPrimitive.int)
        }
    }

    @Test fun anAttachedFileWhoseSectionTheFileDoesNotHoldRefusesTheWholeFileAsCutShort() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val other = "44444444-4444-4444-8444-444444444442"
            val missing = BackupAttachmentEntry(5, other, RestoreFiles.itemId(2), "other.pdf", 12, Bytes.toB64(crypto.randomBytes(32)))
            // Mail names a file in section 5, which the file does not hold; the file holds a section 2 no entry names.
            val file = RestoreFiles.write(w.tmp, "f.andvari", withFiles(listOf(missing), sections = 2, refs = mapOf(2 to other)))
            for (more in listOf(arrayOf("--dry-run"), emptyArray())) {
                val run = restore(w, me, file, *more)
                assertEquals(1, run.code, run.out + run.err)
                assertTrue(run.err.contains("the backup does not open: truncated"), run.err)
            }
            assertEquals(0, count(w, me))
        }
    }

    // ---- A5: sections no item names are not read ----

    @Test fun aSectionNoItemNamesIsNotRead() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val bytes = withFiles(emptyList(), sections = 1)
            // A second section of bytes that are no sealed section at all: reading it would fail the restore.
            val junk = ByteArray(5_000) { 0x5A }
            val len = ByteArray(8) { i -> ((junk.size.toLong() ushr (8 * i)) and 0xFF).toByte() }
            val file = RestoreFiles.write(w.tmp, "f.andvari", bytes + len + junk)
            assertEquals(mapOf("sectionsUnnamed" to 1), leftOut(preview(w, me, file)))
            val done = Json.parseToJsonElement(restore(w, me, file, "--json").ok()).jsonObject.getValue("restored").jsonObject
            assertEquals(2, done.getValue("items").jsonPrimitive.int)
            assertEquals(1, done.getValue("attachmentsCarried").jsonPrimitive.int)
            assertEquals(mapOf("sectionsUnnamed" to 1), leftOut(done))
        }
    }
}
