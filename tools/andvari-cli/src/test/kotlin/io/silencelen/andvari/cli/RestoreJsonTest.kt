package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** `restore --json`: standard output carries one document (the preview and what was restored), every other line standard error. */
class RestoreJsonTest {
    private val env = mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD, "ANDVARI_BACKUP_PASSPHRASE" to "backup pass phrase")

    private fun backupOf(names: List<String>): ByteArray {
        val crypto = createCryptoProvider()
        val pv = "11111111-1111-4111-8111-111111111111"
        val payload = BackupPayload(
            exportedAt = 1_760_000_000_000L, origin = "https://old.example",
            vaults = listOf(BackupVault(pv, "personal", "Personal", "owner")),
            items = names.mapIndexed { i, n -> BackupItem("22222222-2222-4222-8222-00000000000$i", pv, 1, 1_760_000_000_000L, ItemDoc("login", n, login = LoginData("u$i", "p$i"))) },
        )
        val parts = ArrayList<ByteArray>()
        Backup.build(crypto, "backup pass phrase", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload, emptyList(), null) { parts += it }
        return parts.fold(ByteArray(0)) { acc, p -> acc + p }
    }

    @Test fun aRestoreWithJsonPrintsOneDocumentAndNothingElseOnStandardOutput() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val backup = File(w.tmp, "old.andvari").also { it.writeBytes(backupOf(listOf("Bank", "Mail"))) }

            val dry = w.run(me, "restore", "--backup", backup.path, "--dry-run", "--json", env = { env[it] })
            val preview = Json.parseToJsonElement(dry.ok()).jsonObject
            assertEquals(JsonNull, preview["restored"])
            assertEquals(2, preview.getValue("vaults").jsonArray.single().jsonObject.getValue("items").jsonPrimitive.int)
            assertTrue(dry.err.contains("Backup made") && dry.err.contains("personal vault"), dry.err)

            val run = w.run(me, "restore", "--backup", backup.path, "--json", env = { env[it] })
            val doc = Json.parseToJsonElement(run.ok()).jsonObject
            val restored = doc.getValue("restored").jsonObject
            assertEquals(2, restored.getValue("items").jsonPrimitive.int)
            assertEquals(0, restored.getValue("refused").jsonPrimitive.int)
            assertEquals("https://old.example", doc.getValue("origin").jsonPrimitive.content)
            assertTrue(run.err.contains("Backup made"), run.err)
            assertEquals(2, w.run(me, "item", "list", "personal").ok().lines().count { it.isNotBlank() })
        }
    }
}
