package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
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
 * An item the server refuses during a restore is kept by its name and tried again. Before, the tool counted it, acked its
 * batch and forgot it: a second run said "restored 0 items" and the item was never stored.
 */
class RestoreRefusedKeptTest {
    private fun restored(r: CliRun) = Json.parseToJsonElement(r.ok()).jsonObject.getValue("restored").jsonObject

    @Test fun anItemTheServerRefusesIsKeptByItsNameAndTriedAgainByTheNextRestore() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            fun names(home: File) = w.run(home, "item", "list", "personal").ok().lines().filter { it.isNotBlank() }.map { it.substringAfter("  ") }
            w.run(w.op, "operator", "quota", "me@example.org", "--items", "2").ok()
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail", "Shop"))))

            // The server gives no usage figures: the restore starts, and the server refuses the item that does not fit.
            p.lie = mapOf(WireRoute.SYNC to { e -> JsonObject(e.jsonObject - "quota") })
            val first = w.run(me, "restore", "--backup", backup.path, "--json", env = { RestoreFiles.env[it] }, dial = p.address)
            // A run that ends with an item the server refused ends with status 1 (decided on 23 November 2026).
            assertEquals(1, first.code, first.out + first.err)
            val one = Json.parseToJsonElement(first.out).jsonObject.getValue("restored").jsonObject
            assertEquals(2, one.getValue("items").jsonPrimitive.int)
            assertEquals(1, one.getValue("refused").jsonPrimitive.int)
            assertEquals(listOf("Shop"), one.getValue("refusedItems").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })
            assertTrue(first.err.contains("Shop"), first.err)
            p.lie = emptyMap()
            assertEquals(listOf("Bank", "Mail"), names(me).sorted())

            // The next preview names it.
            val preview = Json.parseToJsonElement(w.run(me, "restore", "--backup", backup.path, "--dry-run", "--json", env = { RestoreFiles.env[it] }).ok()).jsonObject
            assertEquals(listOf("Shop"), preview.getValue("refusedBefore").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })
            // In the words decided on 25 November 2026, with "chosen" where the desktop says "ticked"; the server's reason
            // follows the name.
            val said = w.run(me, "restore", "--backup", backup.path, "--dry-run", env = { RestoreFiles.env[it] }).ok().lines()
                .single { it.startsWith("  Refused by the server in an earlier restore: ") }
            assertTrue(said.startsWith("  Refused by the server in an earlier restore: “Shop”"), said)
            assertTrue(said.endsWith(". Where their vault can be chosen, the restore tries them again."), said)

            // With room, the next restore tries it again under the same id: stored once.
            w.run(w.op, "operator", "quota", "me@example.org", "--items", "100").ok()
            val again = restored(w.run(me, "restore", "--backup", backup.path, "--json", env = { RestoreFiles.env[it] }))
            assertEquals(1, again.getValue("items").jsonPrimitive.int)
            assertEquals(0, again.getValue("refused").jsonPrimitive.int)
            assertEquals(listOf("Bank", "Mail", "Shop"), names(me).sorted())

            // Once more: nothing is left to try, and nothing is stored twice.
            assertEquals(0, restored(w.run(me, "restore", "--backup", backup.path, "--json", env = { RestoreFiles.env[it] })).getValue("items").jsonPrimitive.int)
            assertEquals(3, names(me).size)
        } }
    }
}
