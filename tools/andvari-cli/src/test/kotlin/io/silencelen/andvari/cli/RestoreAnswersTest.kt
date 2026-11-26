package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The three answers of 22 November 2026 on restoring a backup: shared vaults are offered apart and restored only when
 * chosen; an account that already holds items is told how many; the same file chosen again says what was restored and
 * when, and offers only the rest. And what the restore keeps on this device holds no item, no name and no open key.
 */
class RestoreAnswersTest {
    private val env = RestoreFiles.env

    private fun preview(w: CliWorld, home: File, backup: File): JsonObject =
        Json.parseToJsonElement(w.run(home, "restore", "--backup", backup.path, "--dry-run", "--json", env = { env[it] }).ok()).jsonObject

    private fun vaults(doc: JsonObject): Map<String, JsonObject> = doc.getValue("vaults").jsonArray.associate { it.jsonObject.getValue("name").jsonPrimitive.content to it.jsonObject }

    private fun sharedNames(w: CliWorld, home: File): Set<String> =
        Json.parseToJsonElement(w.run(home, "vault", "list", "--json").ok()).jsonArray.map { it.jsonObject }
            .filter { it.getValue("kind").jsonPrimitive.content != "personal" }.map { it.getValue("name").jsonPrimitive.content }.toSet()

    private fun count(w: CliWorld, home: File, vault: String = "personal") = w.run(home, "item", "list", vault).ok().lines().count { it.isNotBlank() }

    @Test fun eachSharedVaultIsOfferedApartAndOnlyTheChosenOnesAreRestored() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(RestoreFiles.threeVaults()))

            val before = vaults(preview(w, me, backup))
            for (name in listOf("Personal", "Family", "Work")) assertTrue(before.getValue(name).getValue("offered").jsonPrimitive.boolean, name)
            // Offered, not ticked: only the personal vault is chosen unless a shared one is named.
            assertEquals(listOf(true, false, false), listOf("Personal", "Family", "Work").map { before.getValue(it).getValue("chosen").jsonPrimitive.boolean })

            w.run(me, "restore", "--backup", backup.path, "--vaults", "personal,${RestoreFiles.FAMILY}", env = { env[it] }).ok()
            assertEquals(setOf("Family"), sharedNames(w, me))
            assertEquals(2, count(w, me))
            val after = vaults(preview(w, me, backup))
            assertEquals(listOf(false, false, true), listOf("Personal", "Family", "Work").map { after.getValue(it).getValue("offered").jsonPrimitive.boolean })
        }
    }

    @Test fun thePreviewCountsTheItemsTheAccountAlreadyHoldsAndTheRestoreStillAddsBesideThem() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            for (n in listOf("Mine", "Also mine")) w.run(me, "item", "put", "personal", stdin = CliRun.lines("""{"type":"login","name":"$n","login":{"username":"u","password":"p"}}""")).ok()
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail"))))

            assertEquals(2, preview(w, me, backup).getValue("accountItems").jsonPrimitive.int)
            val text = w.run(me, "restore", "--backup", backup.path, "--dry-run", env = { env[it] }).ok()
            assertTrue(text.contains("this account already holds 2 items"), text)

            assertTrue(w.run(me, "restore", "--backup", backup.path, env = { env[it] }).ok().contains("restored 2 items"))
            assertEquals(4, count(w, me), "added beside them, nothing replaced")
        }
    }

    @Test fun theSameFileChosenAgainSaysWhatWasRestoredAndWhenAndOffersOnlyTheRest() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(RestoreFiles.threeVaults()))

            val at = s.now()
            w.run(me, "restore", "--backup", backup.path, env = { env[it] }).ok()
            val second = vaults(preview(w, me, backup))
            val personal = second.getValue("Personal")
            assertFalse(personal.getValue("offered").jsonPrimitive.boolean)
            assertTrue(personal.getValue("restoredAt").jsonPrimitive.long >= at, "$personal")
            for (name in listOf("Family", "Work")) {
                assertTrue(second.getValue(name).getValue("offered").jsonPrimitive.boolean, name)
                assertEquals(JsonNull, second.getValue(name).getValue("restoredAt"))
            }
            val text = w.run(me, "restore", "--backup", backup.path, "--dry-run", env = { env[it] }).ok().lines()
            assertTrue(text.single { it.contains("“Personal”") }.contains("restored into this account on"), text.joinToString("\n"))

            // The vault left unticked the first time is restored now; the personal vault is not stored again.
            w.run(me, "restore", "--backup", backup.path, "--vaults", "all", env = { env[it] }).ok()
            assertEquals(2, count(w, me))
            assertEquals(setOf("Family", "Work"), sharedNames(w, me))
            assertTrue(vaults(preview(w, me, backup)).values.none { it.getValue("offered").jsonPrimitive.boolean })
        }
    }

    @Test fun theRecordOnThisDeviceHoldsNoItemNoNameAndNoKeyThatOpensWithoutTheAccount() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val crypto = io.silencelen.andvari.core.crypto.createCryptoProvider()
            val oldKey = crypto.randomBytes(32)
            val sectionKey = crypto.randomBytes(32)
            val file = "the scanned passport".encodeToByteArray()
            val attId = "44444444-4444-4444-8444-444444444441"
            val payload = RestoreFiles.threeVaults().let { p ->
                p.copy(
                    items = p.items + BackupItem(
                        RestoreFiles.itemId(9), RestoreFiles.PERSONAL, 1, 1_760_000_000_000L,
                        ItemDoc("login", "Passport office", notes = "my private note", login = LoginData("passport-user", "passport-password"), attachments = listOf(AttachmentRef(attId, "passport.pdf", file.size.toLong(), Bytes.toB64(oldKey)))),
                    ),
                    attachments = listOf(BackupAttachmentEntry(1, attId, RestoreFiles.itemId(9), "passport.pdf", file.size.toLong(), Bytes.toB64(sectionKey))),
                )
            }
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(payload, sections = listOf(Backup.AttachmentSection(sectionKey) { file.copyOf() })))
            w.run(me, "restore", "--backup", backup.path, "--vaults", "all", env = { env[it] }).ok()

            val record = me.listFiles()!!.single { it.name.startsWith("restore-") }.readBytes()
            val text = record.decodeToString()
            val names = payload.vaults.map(BackupVault::name) + payload.items.map { it.doc.name } + "passport.pdf"
            val secrets = payload.items.flatMap { listOfNotNull(it.doc.notes, it.doc.login?.username, it.doc.login?.password) } + file.decodeToString()
            for (word in names + secrets) assertFalse(text.contains(word), "the record holds “$word”")
            // No key of the file, and not the fresh key the restored item now carries, except sealed to the account.
            val fresh = Json.parseToJsonElement(w.run(me, "item", "list", "personal", "--json").ok()).jsonArray.map { it.jsonObject.getValue("doc").jsonObject }
                .single { it.getValue("name").jsonPrimitive.content == "Passport office" }.getValue("attachments").jsonArray.single().jsonObject.getValue("fileKey").jsonPrimitive.content
            for (key in listOf(Bytes.toB64(oldKey), Bytes.toB64(sectionKey), fresh)) assertFalse(text.contains(key), "the record holds a key in the open")
            for (key in listOf(oldKey, sectionKey, Bytes.fromB64(fresh))) assertFalse(containsBytes(record, key), "the record holds a key's bytes")
            // The record keeps one upload per item and attached file: here one item with one file.
            val sealed = Json.parseToJsonElement(text).jsonObject.getValue("files").jsonObject.values.single().jsonObject.values.single().jsonObject.getValue("sealedKey").jsonPrimitive.content
            assertNotEquals(fresh, sealed)
            assertFalse(containsBytes(Bytes.fromB64(sealed), Bytes.fromB64(fresh)), "the sealed key is not the key itself")
        }
    }

    private fun containsBytes(hay: ByteArray, needle: ByteArray): Boolean =
        (0..hay.size - needle.size).any { i -> needle.indices.all { hay[i + it] == needle[it] } }
}
