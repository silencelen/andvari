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
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A restore's plan is kept in this device's home between runs, so that a rerun resumes from the first batch the server
 * did not acknowledge. That plan belongs to the account it restores into: the same backup restored on the same device into
 * another account (a sign-out, then a sign-in as someone else) stores every item there. Before, the second account's run
 * found the first account's plan, skipped every batch as already stored, and stored nothing, while saying it was done.
 * Signing out, for its part, keeps the plan: what a restore has not sent yet is never deleted by it.
 */
class RestorePlanOwnerTest {
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

    private fun restored(r: CliRun): Int = Json.parseToJsonElement(r.ok()).jsonObject.getValue("restored").jsonObject.getValue("items").jsonPrimitive.int

    @Test fun theSameBackupRestoredIntoAnotherAccountOnThisDeviceStoresEveryItemThere() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            w.account("other@example.org")
            val backup = File(w.tmp, "old.andvari").also { it.writeBytes(backupOf(listOf("Bank", "Mail"))) }

            assertEquals(2, restored(w.run(me, "restore", "--backup", backup.path, "--json", env = { env[it] })))
            assertEquals(2, w.run(me, "item", "list", "personal").ok().lines().count { it.isNotBlank() })

            // Signed out, the plan stays; then the other account signs in on this same device.
            w.run(me, "sign-out").ok()
            assertTrue(me.listFiles()!!.any { it.name.startsWith("restore-") }, "signing out kept the restore's plan")
            w.run(me, "sign-in", "--email", "other@example.org", "--trust-card", w.card0).ok()

            assertEquals(2, restored(w.run(me, "restore", "--backup", backup.path, "--json", env = { env[it] })), "every item, into this account")
            assertEquals(2, w.run(me, "item", "list", "personal").ok().lines().count { it.isNotBlank() })
            // And run again for the same account, its own plan says it is done: nothing is stored twice.
            assertEquals(0, restored(w.run(me, "restore", "--backup", backup.path, "--json", env = { env[it] })))
            assertEquals(2, w.run(me, "item", "list", "personal").ok().lines().count { it.isNotBlank() })
        }
    }

    /**
     * The tool keeps no changes between runs (its item cache lives in memory): a change the server did not get is said as
     * not stored, never as queued, so a later sign-out or forget-server has nothing unsent to delete.
     */
    @Test fun aChangeTheServerDidNotGetIsSaidAsNotStored_andNothingOfItIsKept() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            p.cut = setOf(io.silencelen.andvari.core.model.wire.WireRoute.PUSH)
            val r = w.run(me, "item", "put", "personal", dial = p.address,
                stdin = CliRun.lines("""{"type":"login","name":"GitHub","login":{"username":"me","password":"pw"}}"""))
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("not stored"), r.err)
            assertTrue(!r.out.contains("stored ") && !r.out.contains("queued"), r.out)
            p.cut = emptySet()
            assertEquals(0, w.run(me, "item", "list", "personal").ok().lines().count { it.isNotBlank() }, "nothing of it kept, nothing sent later")
        } }
    }
}
