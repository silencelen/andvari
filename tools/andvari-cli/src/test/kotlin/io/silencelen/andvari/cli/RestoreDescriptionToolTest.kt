package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The tool prints its preview and its end from the shared restore's one description (decided on 23 November 2026): what
 * is left of each vault, the items beside which a restore adds, and at the end only what the server kept in this run.
 */
class RestoreDescriptionToolTest {
    private val env = RestoreFiles.env
    private val crypto = createCryptoProvider()

    private fun sharedNames(w: CliWorld, home: File): Set<String> =
        Json.parseToJsonElement(w.run(home, "vault", "list", "--json").ok()).jsonArray.map { it.jsonObject }
            .filter { it.getValue("kind").jsonPrimitive.content != "personal" }.map { it.getValue("name").jsonPrimitive.content }.toSet()

    private fun ref(n: Int, name: String) = AttachmentRef("44444444-4444-4444-8444-%012d".format(n), name, 20, Bytes.toB64(crypto.randomBytes(32)))

    @Test fun aDocumentThatNamesOneFileTwiceCountsNoFileWhenTheServerRefusesItsItem() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("dup@example.org")
            val x = ref(1, "twice.bin")
            val k = crypto.randomBytes(32)
            val items = listOf(RestoreFiles.login(1, RestoreFiles.PERSONAL, "Dup").let { it.copy(doc = it.doc.copy(attachments = listOf(x, x))) }, RestoreFiles.login(2, RestoreFiles.PERSONAL, "Plain"))
            val entries = listOf(BackupAttachmentEntry(1, x.id, RestoreFiles.itemId(1), "twice.bin", 20, Bytes.toB64(k)))
            val bytes = RestoreFiles.bytes(RestoreFiles.personalOnly(emptyList()).copy(items = items, attachments = entries), "eeeeeeee-eeee-4eee-8eee-eeeeeeeed001", listOf(Backup.AttachmentSection(k.copyOf()) { ByteArray(20) { 3 } }))
            val f = RestoreFiles.write(w.tmp, "dup.andvari", bytes)
            val run = w.run(me, "restore", "--backup", f.path, env = { env[it] })
            println("TOOL|dup: code=${run.code} out=${run.out.trim().lines().takeLast(3)} err=${run.err.trim()}")
            assertTrue(run.out.contains("“Dup”"), "the server refused Dup, listed by name: ${run.out}")
            assertFalse(run.out.contains("carried"), "no file is in the account: ${run.out}")
        }
    }

    @Test fun aRunOfOneSharedVaultAloneReportsNoFileOfThePersonalVaultAndARunThatStoredNothingReportsNone() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("alone@example.org")
            val payload = RestoreFiles.threeVaults().let { p ->
                p.copy(items = p.items.map { if (it.itemId == RestoreFiles.itemId(1)) it.copy(doc = it.doc.copy(attachments = listOf(ref(2, "left.pdf")))) else it })
            }
            val f = RestoreFiles.write(w.tmp, "three.andvari", RestoreFiles.bytes(payload, "eeeeeeee-eeee-4eee-8eee-eeeeeeeed002"))
            val first = w.run(me, "restore", "--backup", f.path, env = { env[it] }).ok()
            assertTrue(first.contains("1 attachment not in the file"), first)
            val family = w.run(me, "restore", "--backup", f.path, "--vaults", RestoreFiles.FAMILY, env = { env[it] }).ok()
            val again = w.run(me, "restore", "--backup", f.path, "--vaults", "personal,${RestoreFiles.FAMILY}", env = { env[it] }).ok()
            println("TOOL|alone: first=${first.trim().lines().last()} family=${family.trim().lines().last()} again=${again.trim().lines().last()}")
            assertTrue(family.contains("restored 2 items"), family)
            assertFalse(family.contains("not in the file"), "Family alone took no file off: $family")
            assertTrue(again.contains("nothing of the chosen vaults was left to restore"), again)
            assertFalse(again.contains("not in the file"), "a run that stored nothing and ended no vault: $again")
        }
    }

    @Test fun aVaultOfTheFileWithNoItemIsNotMadeAlsoUnderVaultsAll() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("empty@example.org")
            val payload = RestoreFiles.personalOnly(listOf("Bank")).let { it.copy(vaults = it.vaults + BackupVault("33333333-3333-4333-8333-3333333333e0", "shared", "Empty", "owner")) }
            val f = RestoreFiles.write(w.tmp, "empty.andvari", RestoreFiles.bytes(payload, "eeeeeeee-eeee-4eee-8eee-eeeeeeeed003"))
            val run = w.run(me, "restore", "--backup", f.path, "--vaults", "all", env = { env[it] })
            println("TOOL|empty vault: code=${run.code} out=${run.out.trim().lines()} err=${run.err.trim()} shared=${sharedNames(w, me)}")
            assertEquals(0, run.code, run.err)
            assertEquals(emptySet(), sharedNames(w, me), "no vault is made for a vault of the file with no item")
        }
    }

    @Test fun theSameFileASecondTimeSaysNothingOfItemsThatWouldBeThereTwice() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("twice@example.org")
            val f = RestoreFiles.write(w.tmp, "two.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail")), "eeeeeeee-eeee-4eee-8eee-eeeeeeeed004"))
            w.run(me, "restore", "--backup", f.path, env = { env[it] }).ok()
            val preview = w.run(me, "restore", "--backup", f.path, "--dry-run", env = { env[it] }).ok()
            println("TOOL|second preview=${preview.trim().lines()}")
            assertFalse(preview.contains("already holds"), "the account holds only this file's own items: $preview")
            assertFalse(preview.contains("there twice"), preview)
        }
    }
}
