package io.silencelen.andvari.cli.e2e

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.Send
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.HttpMethod
import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Args
import io.silencelen.andvari.cli.CliError
import io.silencelen.andvari.cli.CliHome
import io.silencelen.andvari.cli.Ctx
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.Restore
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec 07 §3, a resumable restore: the id of each vault the restore recreates is chosen once, kept in the plan before
 * the first create, and passed on every retry. A create the server applied but whose answer was lost, followed by a
 * restart, is re-posted under the same id on the rerun: one vault, its key adopted through the owner wrap. The file's
 * attachments are re-encrypted under fresh keys and uploaded before their items, in the first run and after the restart.
 */
class RestoreResumeTest {
    private val logPost = Regex("^/api/v1/vaults/[^/]+/log$")

    @Test fun aRestoreInterruptedAfterItsFirstCreateAndRunAgainCreatesNoSecondVault() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            // Alice's device loses the answer to the next vault-log post it sends: the server applied it, she never knows.
            val loseNext = AtomicBoolean(false)
            val logPosts = AtomicInteger()
            val http = HttpClient(Java) {
                install(HttpTimeout) { requestTimeoutMillis = 60_000 }
                expectSuccess = false
                install(createClientPlugin("lose") {
                    on(Send) { req ->
                        val call = proceed(req)
                        if (req.method == HttpMethod.Post && logPost.matches(req.url.build().encodedPath)) {
                            logPosts.incrementAndGet()
                            if (loseNext.compareAndSet(true, false)) throw java.io.IOException("the answer was lost")
                        }
                        call
                    }
                })
            }
            val state = MemoryDeviceState()
            val secure = MemoryDeviceState()
            val ah = Host(state, secure, ::now, http = http, deviceName = "alice")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val a = ah.account(s.origin)!!
            a.synced()

            val home = Files.createTempDirectory("andvari-restore").toFile()
            val backup = File(home, "old.andvari").also { it.writeBytes(backupWithASharedVault()) }
            suspend fun restore(session: AccountSession): String {
                val buf = ByteArrayOutputStream()
                val env = mapOf("ANDVARI_BACKUP_PASSPHRASE" to "backup pass phrase")
                val c = Ctx(Args(listOf("restore", "--backup", backup.path, "--vaults", "all")), CliHome(home), PrintStream(buf), { env[it] }, { null }, ::now)
                Restore(c, session).run()
                return buf.toString()
            }

            loseNext.set(true)
            val stopped = try { restore(a); null } catch (e: CliError) { e } ?: throw AssertionError("the first run should stop at the lost answer")
            assertTrue(stopped.message.orEmpty().contains("run the same command again"), "${stopped.message}")
            assertEquals(1, logPosts.get(), "the genesis reached the server once")
            val plan = Json.parseToJsonElement(home.listFiles()!!.single { it.name.startsWith("restore-") }.readText()).jsonObject
            val chosen = plan["chosenIds"]!!.jsonObject[SHARED]!!.jsonPrimitive.content

            // A restart: a new host over the same device state; nothing of the first run is in memory.
            val again = Host(state, secure, ::now, http = http, deviceName = "alice")
            again.adopt(ah.session(s.origin)!!)
            val a2 = again.account(s.origin)!!
            val out = restore(a2)
            // The personal vault's batch was acknowledged in the first run; the shared vault's two items go in now, with
            // Router's attachment; NAS's is not in the file.
            // The run is for the shared vault only: the personal vault has nothing left (decided on 23 November 2026).
            assertTrue(out.contains("restored 2 items into 1 vault; 1 attachment carried; 1 attachment not in the file"), out)

            val shared = a2.vaultIds().filter { it != a2.personalVaultId }
            assertEquals(listOf(chosen), shared, "one recreated vault, under the id the plan chose")
            assertIs<VaultLogStatus.Verified>(a2.logs.status(chosen))
            assertEquals(setOf("Router", "NAS"), a2.items(chosen).map { it.doc["name"]!!.jsonPrimitive.content }.toSet())
            assertEquals(setOf("Bank"), a2.items(a2.personalVaultId!!).map { it.doc["name"]!!.jsonPrimitive.content }.toSet())
            // Spec 07 §3: the attachments the file carries are re-encrypted, uploaded and open again; NAS's is stripped.
            a2.assertCarried(a2.personalVaultId!!, "Bank", 0)
            a2.assertCarried(chosen, "Router", 1)
            assertEquals(emptyList(), a2.items.items().single { it.doc.name == "NAS" }.doc.attachments)

            // A third run finds everything acknowledged.
            assertTrue(restore(a2).contains("nothing of the chosen vaults was left to restore"))
            assertEquals(listOf(chosen), a2.vaultIds().filter { it != a2.personalVaultId })
            home.deleteRecursively()
        } }
    }

    /**
     * Personal "Bank" and shared "Router" each carry an attachment the file holds (sections 1 and 2); shared "NAS"
     * names one the file does not hold (over the cap at export), which the restore strips and names.
     */
    private fun backupWithASharedVault(): ByteArray {
        val crypto = io.silencelen.andvari.core.crypto.createCryptoProvider()
        val keys = listOf(crypto.randomBytes(32), crypto.randomBytes(32))
        val refs = listOf(
            AttachmentRef(OLD_ATT[0], "bank.pdf", FILES[0].size.toLong(), Bytes.toB64(keys[0])),
            AttachmentRef(OLD_ATT[1], "router.txt", FILES[1].size.toLong(), Bytes.toB64(keys[1])),
            AttachmentRef(OLD_ATT[2], "nas.iso", 9_000_000L, Bytes.toB64(crypto.randomBytes(32))),
        )
        fun item(n: Int, vault: String, name: String, ref: AttachmentRef) =
            BackupItem(itemId(n), vault, 1, 1_760_000_000_000L, ItemDoc("login", name, login = LoginData("u$n", "p$n"), attachments = listOf(ref)))
        val payload = BackupPayload(
            exportedAt = 1_760_000_000_000L, origin = "https://old.example",
            vaults = listOf(BackupVault(PERSONAL, "personal", "Personal", "owner"), BackupVault(SHARED, "shared", "Home", "owner")),
            items = listOf(item(1, PERSONAL, "Bank", refs[0]), item(2, SHARED, "Router", refs[1]), item(3, SHARED, "NAS", refs[2])),
            attachments = listOf(
                BackupAttachmentEntry(1, OLD_ATT[0], itemId(1), "bank.pdf", FILES[0].size.toLong(), Bytes.toB64(keys[0])),
                BackupAttachmentEntry(2, OLD_ATT[1], itemId(2), "router.txt", FILES[1].size.toLong(), Bytes.toB64(keys[1])),
            ),
        )
        val sections = listOf(Backup.AttachmentSection(keys[0]) { FILES[0].copyOf() }, Backup.AttachmentSection(keys[1]) { FILES[1].copyOf() })
        val parts = ArrayList<ByteArray>()
        Backup.build(crypto, "backup pass phrase", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee1", crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload, sections, null) { parts += it }
        return parts.fold(ByteArray(0)) { acc, p -> acc + p }
    }

    /** [name]'s one attachment in [vaultId] after the restore: a fresh id and key, and the file's bytes when downloaded. */
    private suspend fun AccountSession.assertCarried(vaultId: String, name: String, n: Int) {
        val item = items.items().single { it.vaultId == vaultId && it.doc.name == name }
        val ref = item.doc.attachments.single()
        assertNotEquals(OLD_ATT[n], ref.id, "a fresh attachment id")
        val got = when (val r = items.downloadAttachment(ref)) {
            is ItemResult.Ok -> r.value
            is ItemResult.Failed -> throw AssertionError("download of $name's attachment: ${r.why}")
        }
        assertContentEquals(FILES[n], got, "$name's attachment opens to the file's bytes")
    }

    companion object {
        val OLD_ATT = listOf("44444444-4444-4444-8444-444444444441", "44444444-4444-4444-8444-444444444442", "44444444-4444-4444-8444-444444444443")
        val FILES = listOf(ByteArray(70_000) { (it % 251).toByte() }, "router admin: 192.168.1.1".encodeToByteArray())
        fun itemId(n: Int) = "22222222-2222-4222-8222-00000000000$n"
        const val PERSONAL = "11111111-1111-4111-8111-111111111111"
        const val SHARED = "33333333-3333-4333-8333-333333333333"
    }
}
