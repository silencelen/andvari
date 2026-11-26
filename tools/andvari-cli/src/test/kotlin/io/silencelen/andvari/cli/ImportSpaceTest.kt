package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec 03 §14.4 at the command line: before `restore` writes anything, a fresh sync
 * and the shared check. Short: nothing starts, and the tool says which limit and by how much, with its own exit code,
 * message key and, with `--json`, a document. Unknown (no figures from the server): the restore starts and the server
 * decides. The account's own meters (`account quota`) and each account's in the operator's listing.
 */
class ImportSpaceTest {
    private val pass = mapOf("ANDVARI_PASSWORD" to io.silencelen.andvari.cli.e2e.Steps.PASSWORD, "ANDVARI_BACKUP_PASSPHRASE" to "backup pass phrase")

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

    @Test fun anImportTheAccountHasNoRoomForDoesNotStartAndSaysWhichLimitAndByHowMuch() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            fun count(home: File) = w.run(home, "item", "list", "personal").ok().lines().count { it.isNotBlank() }
            w.run(me, "item", "put", "personal", stdin = CliRun.lines("""{"type":"login","name":"Mine","login":{"username":"u","password":"p"}}""")).ok()
            w.run(w.op, "operator", "quota", "me@example.org", "--items", "3").ok()
            val backup = File(w.tmp, "old.andvari").also { it.writeBytes(backupOf(listOf("Bank", "Mail", "Shop"))) }

            // Short by one item: nothing starts.
            val short = w.run(me, "restore", "--backup", backup.path, env = { pass[it] })
            assertEquals(EXIT_SHORT_OF_SPACE, short.code, short.out + short.err)
            assertTrue(short.err.contains("[$KEY_SHORT_OF_SPACE]") && short.err.contains("items: 1 used of 3; it would add 3, 1 too many"), short.err)
            assertTrue(short.err.contains("operator quota"), short.err)
            assertEquals(1, count(me), "nothing was written")
            val doc = Json.parseToJsonElement(w.run(me, "restore", "--backup", backup.path, "--json", env = { pass[it] }).also { assertEquals(EXIT_SHORT_OF_SPACE, it.code) }.out.lines().last { it.startsWith("{") }).jsonObject
            assertEquals(KEY_SHORT_OF_SPACE, doc.getValue("error").jsonPrimitive.content)
            val f = doc.getValue("short").jsonArray.single().jsonObject
            assertEquals(listOf("items", "1", "3", "3", "1"), listOf("quota", "used", "limit", "adds", "by").map { f.getValue(it).jsonPrimitive.content })
            assertEquals(1, count(me))

            // The account's own view and the operator's listing show the meters.
            assertTrue(w.run(me, "account", "quota").ok().contains("items: 1 used of 3"))
            val own = Json.parseToJsonElement(w.run(me, "account", "quota", "--json").ok()).jsonObject.getValue("quota").jsonObject
            assertEquals(1L to 3L, own.getValue("items").jsonObject.let { it.getValue("used").jsonPrimitive.long to it.getValue("limit").jsonPrimitive.long })
            assertTrue(w.run(w.op, "operator", "accounts").ok().lines().first { it.contains(" me@example.org ") }.contains("items 1/3"))

            // Room: the restore runs.
            w.run(w.op, "operator", "quota", "me@example.org", "--items", "100").ok()
            assertTrue(w.run(me, "restore", "--backup", backup.path, env = { pass[it] }).ok().contains("restored 3 items"))
            assertEquals(4, count(me))

            // Unknown: a server that gives no figures. The restore starts, and the server decides what fits.
            val bob = w.account("bob@example.org")
            w.run(w.op, "operator", "quota", "bob@example.org", "--items", "2").ok()
            p.lie = mapOf(WireRoute.SYNC to { e -> JsonObject(e.jsonObject - "quota") })
            val unknown = w.run(bob, "restore", "--backup", backup.path, env = { pass[it] }, dial = p.address)
            assertTrue(unknown.err.contains("the restore starts and the server decides"), unknown.err)
            assertTrue(w.run(bob, "account", "quota", dial = p.address).ok().contains("unknown"))
            p.lie = emptyMap()
            val stored = count(bob)
            assertTrue(stored <= 2, "the server took what fits and no more: $stored")
        } }
    }
}
