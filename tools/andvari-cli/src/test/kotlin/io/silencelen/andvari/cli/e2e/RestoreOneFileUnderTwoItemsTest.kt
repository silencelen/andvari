package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Args
import io.silencelen.andvari.cli.CliError
import io.silencelen.andvari.cli.CliHome
import io.silencelen.andvari.cli.CliWorld
import io.silencelen.andvari.cli.Ctx
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.Restore
import io.silencelen.andvari.cli.RestoreFiles
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One attached file named by two items of a backup. An honest export writes an item and its conflict copy so (two
 * entries, two parts, one file id, one vault): each item gets the file under an upload of its own, and a second run
 * stores nothing. The same shape made to mislead touches nothing the account held, and one file id named in two vaults
 * is no honest file: it is refused whole.
 */
class RestoreOneFileUnderTwoItemsTest {
    private val crypto = createCryptoProvider()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val personal = RestoreFiles.PERSONAL
    private val x = "44444444-4444-4444-8444-4444444444b1"

    private fun item(n: Int, vault: String, name: String, vararg refs: AttachmentRef): BackupItem =
        RestoreFiles.login(n, vault, name).let { it.copy(doc = it.doc.copy(attachments = refs.toList())) }

    private fun ref(id: String, name: String, size: Long) = AttachmentRef(id, name, size, Bytes.toB64(crypto.randomBytes(32)))

    /** [payload] sealed with one part per entry, each (key, bytes) of [parts]. */
    private fun sealed(payload: BackupPayload, parts: List<Pair<ByteArray, String>>, fileId: String): ByteArray {
        val out = ArrayList<ByteArray>()
        Backup.buildWithPayloadBytes(
            crypto, RestoreFiles.PASS, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray(),
            parts.map { (k, b) -> Backup.AttachmentSection(k.copyOf()) { b.encodeToByteArray() } }, null,
        ) { out += it.copyOf() }
        return out.fold(ByteArray(0)) { acc, b -> acc + b }
    }

    /** The tool's restore of [file] into [session], keeping its record in [home]: what it printed. */
    private suspend fun TestServer.restore(home: File, file: File, session: AccountSession, vararg more: String): String {
        val buf = ByteArrayOutputStream()
        val env = mapOf("ANDVARI_BACKUP_PASSPHRASE" to RestoreFiles.PASS)
        val c = Ctx(Args(listOf("restore", "--backup", file.path) + more), CliHome(home), PrintStream(buf), { env[it] }, { null }, ::now)
        Restore(c, session).run()
        return buf.toString()
    }

    private suspend fun TestServer.alice(): AccountSession {
        Steps.registerThrough(device("operator"), origin, setupLink, "op@example.org")
        val h = Host(MemoryDeviceState(), MemoryDeviceState(), ::now, deviceName = "alice")
        Steps.registerThrough(h, origin, Steps.enrolLink(this), "alice@example.org", trustGate = true)
        val a = h.account(origin)!!
        a.synced()
        return a
    }

    private suspend fun bytesOf(a: AccountSession, r: AttachmentRef): String = when (val got = a.items.downloadAttachment(r)) {
        is ItemResult.Ok -> got.value.decodeToString()
        is ItemResult.Failed -> "not downloaded: ${got.why}"
    }

    @Test fun anItemAndItsConflictCopyNamingOneFileEachGetTheFileAndASecondRunStoresNothing() {
        TestServer().use { it.journey {
            val a = alice()
            val k1 = crypto.randomBytes(32)
            val k2 = crypto.randomBytes(32)
            // As the shared and the web writer make it: one entry and one part per (item, file), the same bytes twice.
            val payload = RestoreFiles.personalOnly(emptyList()).copy(
                items = listOf(item(1, personal, "Bank", ref(x, "scan.pdf", 9)), item(2, personal, "Bank (conflict copy)", ref(x, "scan.pdf", 9))),
                attachments = listOf(
                    BackupAttachmentEntry(1, x, RestoreFiles.itemId(1), "scan.pdf", 9, Bytes.toB64(k1)),
                    BackupAttachmentEntry(2, x, RestoreFiles.itemId(2), "scan.pdf", 9, Bytes.toB64(k2)),
                ),
            )
            val home = Files.createTempDirectory("andvari-restore").toFile()
            val file = File(home, "copy.andvari").also { f -> f.writeBytes(sealed(payload, listOf(k1 to "SCANBYTES", k2 to "SCANBYTES"), "eeeeeeee-eeee-4eee-8eee-eeeeeeeee201")) }
            val first = restore(home, file, a)
            assertTrue(first.contains("restored 2 items into 1 vault; 2 attachments carried"), first)
            assertTrue(!first.contains("run the same command again"), first)
            val second = restore(home, file, a)
            // Nothing is left: no run, and no vault counted as restored into (decided on 23 November 2026).
            assertTrue(second.contains("nothing of the chosen vaults was left to restore"), second)
            assertTrue(!second.contains("run the same command again"), second)
            a.sync()
            val held = a.items.items()
            assertEquals(listOf("Bank", "Bank (conflict copy)"), held.map { i -> i.doc.name }.sorted())
            for (i in held) assertEquals("SCANBYTES", bytesOf(a, i.doc.attachments.single()), i.doc.name)
            assertEquals(2, held.map { i -> i.doc.attachments.single().id }.toSet().size, "each item has an upload of its own")
        } }
    }

    @Test fun oneFileNamedUnderManyItemsIsCountedOncePerItemByThePreviewAndTheRoomCheck() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val size = 50_000
            val keys = List(5) { crypto.randomBytes(32) }
            val payload = RestoreFiles.personalOnly(emptyList()).copy(
                items = List(5) { n -> item(n + 1, personal, "Item $n", ref(x, "big.bin", size.toLong())) },
                attachments = List(5) { n -> BackupAttachmentEntry(n + 1, x, RestoreFiles.itemId(n + 1), "big.bin", size.toLong(), Bytes.toB64(keys[n])) },
            )
            val file = RestoreFiles.write(w.tmp, "many.andvari", sealed(payload, keys.map { k -> k to "b".repeat(size) }, "eeeeeeee-eeee-4eee-8eee-eeeeeeeee202"))
            fun run(vararg more: String) = w.run(me, "restore", "--backup", file.path, *more, env = { RestoreFiles.env[it] })
            val preview = Json.parseToJsonElement(run("--dry-run", "--json").ok()).jsonObject
            assertEquals(5, preview.getValue("attachments").jsonPrimitive.int, "one per item")
            // Room for the items and one copy of the file, not for five copies.
            w.run(w.op, "operator", "quota", "me@example.org", "--bytes", "120000").ok()
            val short = run()
            assertTrue(short.code != 0 && short.err.contains("account_short_of_space"), "the room check counted one copy only: ${short.out}${short.err}")
            assertEquals(0, items(w, me).size, "nothing written")
            w.run(w.op, "operator", "quota", "me@example.org", "--bytes", "10000000").ok()
            val done = run()
            assertTrue(done.ok().contains("restored 5 items into 1 vault; 5 attachments carried"), done.out)
            assertTrue(!done.out.contains("run the same command again"), done.out)
            val held = items(w, me)
            assertEquals(5, held.size)
            val ids = held.map { o -> o.getValue("doc").jsonObject.getValue("attachments").jsonArray.single().jsonObject.getValue("id").jsonPrimitive.content }
            assertEquals(5, ids.toSet().size, "each item has an upload of its own")
        }
    }

    private fun items(w: CliWorld, home: File) =
        Json.parseToJsonElement(w.run(home, "item", "list", "personal", "--json").ok()).jsonArray.map { it.jsonObject }

    @Test fun theMisleadingTwinTouchesNothingTheAccountHeldAndOneFileIdInTwoVaultsIsRefusedWhole() {
        TestServer().use { it.journey {
            val a = alice()
            val home = Files.createTempDirectory("andvari-restore").toFile()
            // What the account holds first: "Passport" with its file, from an honest backup.
            val z = "44444444-4444-4444-8444-4444444444bf"
            val kz = crypto.randomBytes(32)
            val first = RestoreFiles.personalOnly(emptyList()).copy(
                items = listOf(item(9, personal, "Passport", ref(z, "passport.jpg", 8))),
                attachments = listOf(BackupAttachmentEntry(1, z, RestoreFiles.itemId(9), "passport.jpg", 8, Bytes.toB64(kz))),
            )
            restore(home, File(home, "first.andvari").also { f -> f.writeBytes(sealed(first, listOf(kz to "ORIGINAL"), "eeeeeeee-eeee-4eee-8eee-eeeeeeeee203")) }, a)
            a.sync()
            val passport = a.items.items().single()
            val own = passport.doc.attachments.single().id

            // A file whose items name x in two vaults, the old file's id and the account's own file id.
            val family = RestoreFiles.FAMILY
            val keys = List(4) { crypto.randomBytes(32) }
            fun twin(withOtherVault: Boolean): BackupPayload {
                val items = listOf(
                    item(1, personal, "A", ref(x, "a.txt", 4)),
                    item(3, personal, "D names the old file's id", ref(z, "passport.jpg", 9)),
                    item(4, personal, "E names the account's own file id", ref(own, "passport.jpg", 10)),
                ) + (if (withOtherVault) listOf(item(2, family, "C in another vault", ref(x, "a.txt", 4))) else emptyList())
                val entries = listOf(
                    BackupAttachmentEntry(1, x, RestoreFiles.itemId(1), "a.txt", 4, Bytes.toB64(keys[0])),
                    BackupAttachmentEntry(2, z, RestoreFiles.itemId(3), "passport.jpg", 9, Bytes.toB64(keys[1])),
                    BackupAttachmentEntry(3, own, RestoreFiles.itemId(4), "passport.jpg", 10, Bytes.toB64(keys[2])),
                ) + (if (withOtherVault) listOf(BackupAttachmentEntry(4, x, RestoreFiles.itemId(2), "a.txt", 4, Bytes.toB64(keys[3]))) else emptyList())
                return BackupPayload(
                    exportedAt = 1L, origin = origin, userId = a.userId,
                    vaults = listOf(BackupVault(personal, "personal", "Personal", "owner"), BackupVault(family, "shared", "Family", "owner")),
                    items = items, attachments = entries,
                )
            }
            val bytes = listOf(keys[0] to "AAAA", keys[1] to "OVERWRITE", keys[2] to "OVERWRITE2", keys[3] to "EVIL")
            val twoVaults = File(home, "twin-two-vaults.andvari").also { f -> f.writeBytes(sealed(twin(true), bytes, "eeeeeeee-eeee-4eee-8eee-eeeeeeeee204")) }
            val refused = try { restore(home, twoVaults, a, "--vaults", "all"); null } catch (e: CliError) { e }
            assertTrue(refused?.message.orEmpty().contains("the backup does not open: ${Backup.ERR_BAD_PAYLOAD}"), "${refused?.message}")
            a.sync()
            assertEquals(listOf(passport.itemId), a.items.items().map { i -> i.itemId }, "nothing written")

            val oneVault = File(home, "twin-one-vault.andvari").also { f -> f.writeBytes(sealed(twin(false), bytes.take(3), "eeeeeeee-eeee-4eee-8eee-eeeeeeeee205")) }
            val out = restore(home, oneVault, a)
            assertTrue(out.contains("restored 3 items"), out)
            a.sync()
            val now = a.items.items()
            val still = now.single { i -> i.itemId == passport.itemId }
            assertEquals(passport.doc, still.doc, "what the account held is unchanged")
            assertEquals("ORIGINAL", bytesOf(a, still.doc.attachments.single()))
            val added = now.filter { i -> i.itemId != passport.itemId }
            assertTrue(added.flatMap { i -> i.doc.attachments }.none { r -> r.id == z || r.id == own || r.id == x }, "every carried file has a fresh id")
            assertTrue(now.flatMap { i -> i.doc.attachments }.none { r -> bytesOf(a, r) == "EVIL" }, "the twin's bytes landed somewhere")
        } }
    }
}
