package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The tool tells its caller the truth by its status (decided on 23 November 2026): a run that ends with an item the
 * server refused ends with 1, its printed lines as they were; a `--vaults` id the file does not hold is a wrong argument,
 * 2, said before anything of the restore is sent, written or printed.
 */
class RestoreStatusToolTest {
    private val env = RestoreFiles.env

    private fun items(w: CliWorld, home: File) = w.run(home, "item", "list", "personal").ok().lines().count { it.isNotBlank() }

    @Test fun aRunWithAnItemTheServerRefusedEndsWithStatusOneAndItsLinesAsTheyWere() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("refused@example.org")
            w.run(w.op, "operator", "quota", "refused@example.org", "--items", "2").ok()
            val backup = RestoreFiles.write(w.tmp, "three.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail", "Shop")), "eeeeeeee-eeee-4eee-8eee-eeeeeeeec101"))
            // The server gives no usage figures: the restore starts, and the server refuses the item that does not fit.
            p.lie = mapOf(WireRoute.SYNC to { e -> JsonObject(e.jsonObject - "quota") })
            val run = w.run(me, "restore", "--backup", backup.path, env = { env[it] }, dial = p.address)
            println("STATUS|refused: code=${run.code} out=${run.out.trim().lines().takeLast(2)}")
            assertEquals(1, run.code, run.out + run.err)
            assertTrue("restored 2 items into 1 vault" in run.out.lines(), run.out)
            assertTrue(run.out.contains("not stored, kept to try again (run the same command again): “Shop”"), run.out)
            assertFalse(run.err.contains("andvari-cli:"), "no line is added: ${run.err}")
            // With --json: the same status, the document as it was.
            val again = w.run(me, "restore", "--backup", backup.path, "--json", env = { env[it] }, dial = p.address)
            assertEquals(1, again.code, again.out + again.err)
            val restored = Json.parseToJsonElement(again.out).jsonObject.getValue("restored").jsonObject
            assertEquals(1, restored.getValue("refused").jsonPrimitive.int)
            p.lie = emptyMap()
            // With room, the item is stored: status 0.
            w.run(w.op, "operator", "quota", "refused@example.org", "--items", "100").ok()
            w.run(me, "restore", "--backup", backup.path, env = { env[it] }).ok()
            assertEquals(3, items(w, me))
        } }
    }

    @Test fun aVaultsIdTheFileDoesNotHoldIsAWrongArgumentAndNothingOfTheRestoreHappens() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("typo@example.org")
            val backup = RestoreFiles.write(w.tmp, "three.andvari", RestoreFiles.bytes(RestoreFiles.threeVaults(), "eeeeeeee-eeee-4eee-8eee-eeeeeeeec102"))
            val run = w.run(me, "restore", "--backup", backup.path, "--vaults", "personal,nope,${RestoreFiles.FAMILY},also", env = { env[it] })
            println("STATUS|typo: code=${run.code} out=${run.out.trim().lines()} err=${run.err.trim().lines()}")
            assertEquals(2, run.code, run.out + run.err)
            assertTrue(run.err.contains("“nope”, “also”"), run.err)
            assertFalse(run.out.contains("Backup made") || run.err.contains("Backup made"), "nothing of the preview is printed")
            assertFalse(run.out.contains("nothing of the chosen vaults"), run.out)
            assertFalse(me.listFiles()!!.any { it.name.startsWith("restore-") }, "no record is written")
            assertEquals(0, items(w, me), "nothing is sent")
            // An id of the file, "personal" and "all" are all taken.
            w.run(me, "restore", "--backup", backup.path, "--vaults", "personal,${RestoreFiles.FAMILY},all", "--dry-run", env = { env[it] }).ok()
        }
    }
}
