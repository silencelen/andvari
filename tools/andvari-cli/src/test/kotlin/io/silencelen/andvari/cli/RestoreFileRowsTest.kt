package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A backup file made by someone else to mislead the person who restores it, one row at a time, for each row the product
 * has a rule for; and the 0.30.0 web app's file into an account without room for it.
 */
class RestoreFileRowsTest {
    private val env = RestoreFiles.env
    private val crypto = createCryptoProvider()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private fun restore(w: CliWorld, home: File, file: File, vararg more: String) =
        w.run(home, "restore", "--backup", file.path, *more, env = { env[it] })

    private fun items(w: CliWorld, home: File, vault: String = "personal"): List<JsonObject> =
        Json.parseToJsonElement(w.run(home, "item", "list", vault, "--json").ok()).jsonArray.map { it.jsonObject }

    private fun vaults(w: CliWorld, home: File): List<JsonObject> = Json.parseToJsonElement(w.run(home, "vault", "list", "--json").ok()).jsonArray.map { it.jsonObject }

    private fun name(o: JsonObject) = o.getValue("doc").jsonObject.getValue("name").jsonPrimitive.content

    /** One personal login "Bank" with a file "scan.pdf" whose manifest entry [entry] makes as the row needs. */
    private fun withFile(entry: (BackupAttachmentEntry) -> BackupAttachmentEntry, sectionCount: Int = 1): ByteArray {
        val file = "the bytes of the scan".encodeToByteArray()
        val key = crypto.randomBytes(32)
        val attId = "44444444-4444-4444-8444-444444444441"
        val honest = BackupAttachmentEntry(1, attId, RestoreFiles.itemId(1), "scan.pdf", file.size.toLong(), Bytes.toB64(key))
        val payload = RestoreFiles.personalOnly(listOf("Bank", "Mail")).let { p ->
            p.copy(
                items = listOf(p.items[0].copy(doc = p.items[0].doc.copy(attachments = listOf(AttachmentRef(attId, "scan.pdf", file.size.toLong(), Bytes.toB64(crypto.randomBytes(32)))))), p.items[1]),
                attachments = listOf(entry(honest)),
            )
        }
        val parts = ArrayList<ByteArray>()
        // Written as the payload says, even where its manifest does not match the sections (the shared build would refuse).
        Backup.buildWithPayloadBytes(
            crypto, RestoreFiles.PASS, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee7", crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray(), List(sectionCount) { Backup.AttachmentSection(key) { file.copyOf() } }, null,
        ) { parts += it.copyOf() }
        return parts.fold(ByteArray(0)) { acc, p -> acc + p }
    }

    @Test fun anItemOrVaultCarryingTheIdOfOneTheAccountHoldsReplacesNothingAndWritesIntoNothing() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            restore(w, me, RestoreFiles.write(w.tmp, "first.andvari", RestoreFiles.bytes(RestoreFiles.threeVaults())), "--vaults", "all").ok()
            val mine = items(w, me)
            val personalId = vaults(w, me).single { it.getValue("kind").jsonPrimitive.content == "personal" }.getValue("vaultId").jsonPrimitive.content
            val familyId = vaults(w, me).single { it.getValue("name").jsonPrimitive.content == "Family" }.getValue("vaultId").jsonPrimitive.content
            val familyItems = items(w, me, familyId)

            // A second file names the account's own vaults and items by their ids, with other contents.
            val hostile = BackupPayload(
                exportedAt = 1_760_000_000_000L, origin = "https://old.example",
                vaults = listOf(BackupVault(personalId, "personal", "Personal", "owner"), BackupVault(familyId, "shared", "Family", "owner")),
                items = mine.mapIndexed { i, o -> BackupItem(o.getValue("itemId").jsonPrimitive.content, personalId, 1, 0L, ItemDoc("login", "Evil $i", login = LoginData("evil", "evil"))) } +
                    familyItems.mapIndexed { i, o -> BackupItem(o.getValue("itemId").jsonPrimitive.content, familyId, 1, 0L, ItemDoc("login", "Evil shared $i", login = LoginData("evil", "evil"))) },
            )
            restore(w, me, RestoreFiles.write(w.tmp, "second.andvari", RestoreFiles.bytes(hostile, fileId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee2")), "--vaults", "all").ok()

            val after = items(w, me)
            for (o in mine) assertEquals(o, after.single { it.getValue("itemId") == o.getValue("itemId") }, "the account's item is as it was")
            assertEquals(4, after.size, "the file's items are added under new ids")
            assertEquals(familyItems, items(w, me, familyId), "the account's shared vault is as it was")
            assertEquals(2, vaults(w, me).count { it.getValue("name").jsonPrimitive.content == "Family" }, "a new vault, beside it")
        }
    }

    @Test fun anAttachedFileWhoseEntryPointsAtAnotherItemRefusesTheWholeFile() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            // The entry lies under Mail, whose document names no file: no andvari writer makes that.
            val file = RestoreFiles.write(w.tmp, "f.andvari", withFile({ it.copy(itemId = RestoreFiles.itemId(2)) }))
            val run = restore(w, me, file)
            assertEquals(1, run.code, run.out + run.err)
            assertTrue(run.err.contains("the backup does not open: bad_payload"), run.err)
            assertEquals(0, items(w, me).size)
        }
    }

    @Test fun anAttachedFileThatIsNotTheSizeItsEntryNamesStopsTheRestoreAndNothingOfItIsUploaded() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val run = restore(w, me, RestoreFiles.write(w.tmp, "f.andvari", withFile({ it.copy(size = 3) })))
            assertEquals(1, run.code, run.out + run.err)
            assertTrue(run.err.contains("attachment “scan.pdf” is not the size the file names: nothing uploaded"), run.err)
            assertEquals(0, items(w, me).size)
        }
    }

    @Test fun anAttachedFileWhoseSectionIsNotInTheFileRefusesTheWholeFileAsCutShort() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val run = restore(w, me, RestoreFiles.write(w.tmp, "f.andvari", withFile({ it.copy(section = 5) })))
            assertEquals(1, run.code, run.out + run.err)
            assertTrue(run.err.contains("the backup does not open: truncated"), run.err)
            assertEquals(0, items(w, me).size)
        }
    }

    @Test fun anItemUnderAVaultTheFileDoesNotListIsNeitherCountedNorSent() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val p = RestoreFiles.personalOnly(listOf("Bank", "Mail"))
            val stray = p.copy(items = p.items + RestoreFiles.login(3, "99999999-9999-4999-8999-999999999999", "Stray"))
            val file = RestoreFiles.write(w.tmp, "f.andvari", RestoreFiles.bytes(stray))
            val preview = Json.parseToJsonElement(restore(w, me, file, "--dry-run", "--json").ok()).jsonObject
            assertEquals(listOf(2), preview.getValue("vaults").jsonArray.map { it.jsonObject.getValue("items").jsonPrimitive.int })
            restore(w, me, file, "--vaults", "all").ok()
            assertEquals(listOf("Bank", "Mail"), items(w, me).map(::name).sorted())
        }
    }

    @Test fun namesWithControlCharactersDirectionMarksAndEscapeSequencesAreShownAsTextNeverActedOn() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val p = RestoreFiles.threeVaults()
            val evil = "Fam\u001B[2J\u001B]52;c;aGk=\u0007ily\u202Eexe.pdf\u2028"
            val file = RestoreFiles.write(w.tmp, "f.andvari", RestoreFiles.bytes(p.copy(vaults = p.vaults.map { if (it.name == "Family") it.copy(name = evil) else it })))
            for (args in listOf(arrayOf("--dry-run"), arrayOf("--dry-run", "--json"))) {
                val run = restore(w, me, file, *args)
                val shown = run.ok() + run.err
                for (raw in listOf('\u001B', '\u0007', '\u202E', '\u2028')) assertFalse(shown.contains(raw), "a raw U+%04X reached the terminal".format(raw.code))
            }
            assertTrue(restore(w, me, file, "--dry-run").ok().contains("Fam\\u{001B}[2J"))
        }
    }

    @Test fun aFileWhoseHeaderAsksMoreThanTheCeilingsIsRefusedBeforeAnyKeyIsDerived() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            for ((ops, mem) in listOf(1L to 512L * 1024 * 1024, 17L to 8L * 1024 * 1024)) {
                val header = """{"format":"andvari-backup","v":1,"fileId":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","kdfSalt":"AAAAAAAAAAAAAAAAAAAAAA","kdfParams":{"v":1,"alg":"argon2id13","opsLimit":$ops,"memBytes":$mem}}""".encodeToByteArray()
                val out = ByteArrayOutputStream()
                out.write(Backup.MAGIC)
                out.write(byteArrayOf(header.size.toByte(), (header.size shr 8).toByte(), 0, 0))
                out.write(header)
                out.write(ByteArray(8))
                val started = System.nanoTime()
                val run = restore(w, me, RestoreFiles.write(w.tmp, "costly.andvari", out.toByteArray()))
                assertEquals(1, run.code, run.out + run.err)
                assertTrue(run.err.contains("the backup does not open: unsupported_kdf"), run.err)
                assertTrue(System.nanoTime() - started < 30_000_000_000L)
            }
            assertEquals(0, items(w, me).size)
        }
    }

    @Test fun theOldWebFileIntoAnAccountWithoutRoomWritesNothing() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            w.run(w.op, "operator", "quota", "me@example.org", "--items", "3").ok()
            val old = RestoreFiles.write(w.tmp, "old.andvari", RestoreFileRowsTest::class.java.getResourceAsStream("/old-backups/backup-0.30.0-web.andvari")!!.readBytes())
            val run = w.run(me, "restore", "--backup", old.path, "--vaults", "all", env = { if (it == "ANDVARI_BACKUP_PASSPHRASE") "old backup pass phrase 0.30" else env[it] })
            assertEquals(EXIT_SHORT_OF_SPACE, run.code, run.out + run.err)
            assertTrue(run.err.contains("items: 0 used of 3; it would add 7, 4 too many"), run.err)
            assertEquals(0, items(w, me).size)
            assertEquals(listOf("personal"), vaults(w, me).map { it.getValue("kind").jsonPrimitive.content })
        }
    }
}
