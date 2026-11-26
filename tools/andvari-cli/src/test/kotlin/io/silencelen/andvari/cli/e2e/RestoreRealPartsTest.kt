package io.silencelen.andvari.cli.e2e

import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.Send
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.HttpMethod
import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.OwnerOnlyFile
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.restore.BackupRestore
import io.silencelen.andvari.core.client.restore.RestoreFile
import io.silencelen.andvari.core.client.restore.RestoreHost
import io.silencelen.andvari.core.client.restore.RestoreOpening
import io.silencelen.andvari.core.client.restore.RestoreRecords
import io.silencelen.andvari.core.client.restore.RestoreResult
import io.silencelen.andvari.core.client.restore.RestoreStop
import java.io.File
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The shared restore over the real parts: the test world's server, real accounts, and the backup the web app of 0.30.0
 * wrote (`old-backups/`, with its passphrase). It opens, its preview says what was put in, it restores whole into a fresh
 * account item for item and file for file, and a restore stopped half-way and chosen again stores nothing twice.
 */
class RestoreRealPartsTest {
    private val pass = "old backup pass phrase 0.30"
    private val old: ByteArray = RestoreRealPartsTest::class.java.getResourceAsStream("/old-backups/backup-0.30.0-web.andvari")!!.readBytes()
    private val personal = "11111111-1111-4111-8111-111111111111"
    private val family = "33333333-3333-4333-8333-333333333331"
    private val work = "33333333-3333-4333-8333-333333333332"
    private val push = Regex("^/api/v1/sync/push$")

    /** The account of [session] as the shared restore asks for it, its record kept as files of [dir]. */
    private fun host(session: AccountSession, dir: File, now: () -> Long) = object : RestoreHost {
        override val crypto get() = session.host.crypto
        override val origin get() = session.origin
        override val userId get() = session.userId
        override val account get() = session.held.session.account
        override val items get() = session.items
        override val logs get() = session.logs
        override val records = object : RestoreRecords {
            private fun f(name: String) = File(dir, "$name.json")
            override fun read(name: String) = f(name).takeIf { it.isFile }?.readText()
            override fun replace(name: String, text: String) = OwnerOnlyFile(f(name)).replace(text)
            // Only a record from before records named their account is removed, and these tests write none.
            override fun remove(name: String) = throw AssertionError("no older record to remove: $name")
        }
        override suspend fun sync() {
            session.sync()
        }
        override fun now() = now()
    }

    /** The old file, opened for a restore with its passphrase. */
    private fun opened(a: AccountSession): RestoreFile = assertIs<RestoreOpening.Opened>(BackupRestore.open(a.host.crypto, pass, old)).file

    /** A document as compared: its attachments apart (they get fresh ids and keys) and the log head a writer adds. */
    private fun bare(d: ItemDoc) = d.copy(attachments = emptyList(), extras = d.extras - "logHead")

    @Test fun theOldWebFileOpensAndRestoresWholeIntoAFreshAccountItemForItemAndFileForFile() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            val ah = Host(MemoryDeviceState(), MemoryDeviceState(), ::now, deviceName = "alice")
            Steps.registerThrough(ah, s.origin, Steps.enrolLink(s), "alice@example.org", trustGate = true)
            val a = ah.account(s.origin)!!
            a.synced()
            val dir = Files.createTempDirectory("andvari-restore").toFile()
            val restore = BackupRestore(host(a, dir, ::now))
            val file = opened(a)

            val preview = restore.preview(file)
            assertEquals(1_763_000_000_000L, preview.exportedAt)
            assertEquals("https://vault.example.org", preview.origin)
            assertEquals(listOf("Personal" to 3, "Family" to 2, "Work" to 2), preview.vaults.map { it.name to it.items })
            assertEquals(listOf(true, true, false), preview.vaults.map { it.owned })
            assertTrue(preview.vaults.all { it.offered })
            assertEquals(2, preview.attachments)
            assertEquals(70_036L, preview.attachmentBytes)
            assertEquals(listOf("tax-archive.zip"), preview.attachmentsOverCap)
            assertEquals(listOf("scan.pdf"), preview.attachmentFetchFailed)
            assertEquals(1, preview.undecryptable)
            assertEquals(0, preview.accountItems)
            assertEquals(emptyList(), preview.refused)

            val done = assertIs<RestoreResult.Done>(restore.restore(file, setOf(personal, family, work)))
            assertEquals(7, done.stored)
            assertEquals(2, done.carried)
            assertEquals(2, done.stripped, "the files over the cap and not fetched are not in the file")
            assertEquals(emptyList(), done.refused)

            a.sync()
            val names = a.items.vaults().associate { it.vaultId to it.name }
            val shared = a.vaultIds().filter { it != a.personalVaultId }
            assertEquals(setOf("Family", "Work"), shared.map { names[it] }.toSet())
            assertTrue(shared.none { it == family || it == work }, "new vaults, under new ids")
            val restored = a.items.items()
            assertEquals(7, restored.size)
            for (item in file.opened.payload.items) {
                val vaultName = file.opened.payload.vaults.single { it.vaultId == item.vaultId }.name
                val got = restored.single { it.doc.name == item.doc.name }
                assertNotEquals(item.itemId, got.itemId)
                assertEquals(if (item.vaultId == personal) a.personalVaultId else shared.single { names[it] == vaultName }, got.vaultId)
                assertEquals(bare(item.doc), bare(got.doc), item.doc.name)
            }
            // The two files the file carries, byte for byte under fresh ids and keys; the two it does not carry, stripped.
            for (entry in file.opened.payload.attachments) {
                val ref = restored.single { it.doc.name == file.opened.payload.items.single { i -> i.itemId == entry.itemId }.doc.name }.doc.attachments.single()
                assertNotEquals(entry.attachmentId, ref.id)
                assertEquals(entry.name to entry.size, ref.name to ref.size)
                val bytes = when (val r = a.items.downloadAttachment(ref)) {
                    is ItemResult.Ok -> r.value
                    is ItemResult.Failed -> throw AssertionError("download of ${ref.name}: ${r.why}")
                }
                assertContentEquals(file.opened.readAttachment(entry), bytes)
            }
            assertTrue(restored.single { it.doc.name == "Router" }.doc.attachments.isEmpty())
            assertTrue(restored.single { it.doc.name == "Jira" }.doc.attachments.isEmpty())

            // The next preview of the same file: every vault restored, and when.
            val again = restore.preview(file)
            assertTrue(again.vaults.none { it.offered })
            assertEquals(7, again.accountItems)
        } }
    }

    @Test fun aRestoreStoppedHalfWayAndChosenAgainStoresNothingTwice() {
        TestServer().use { it.journey { val s = this
            Steps.registerThrough(s.device("operator"), s.origin, s.setupLink, "op@example.org")
            // The answer to the first push is lost: the server stored the batch, the device never knows.
            val loseNext = AtomicBoolean(false)
            val http = HttpClient(Java) {
                install(HttpTimeout) { requestTimeoutMillis = 60_000 }
                expectSuccess = false
                install(createClientPlugin("lose") {
                    on(Send) { req ->
                        val call = proceed(req)
                        if (req.method == HttpMethod.Post && push.matches(req.url.build().encodedPath) && loseNext.compareAndSet(true, false)) {
                            throw java.io.IOException("the answer was lost")
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
            val dir = Files.createTempDirectory("andvari-restore").toFile()

            loseNext.set(true)
            val first = BackupRestore(host(a, dir, ::now)).restore(opened(a), setOf(personal, family, work))
            val stop = assertIs<RestoreResult.Stopped>(first).stop
            assertIs<RestoreStop.BatchRefused>(stop)

            // A restart: a new host over the same device state, the same record; nothing of the first run in memory.
            val again = Host(state, secure, ::now, http = http, deviceName = "alice")
            again.adopt(ah.session(s.origin)!!)
            val a2 = again.account(s.origin)!!
            val second = BackupRestore(host(a2, dir, ::now)).restore(opened(a2), setOf(personal, family, work))
            assertIs<RestoreResult.Done>(second)
            a2.sync()
            val items = a2.items.items()
            assertEquals(7, items.size, items.map { it.doc.name }.toString())
            assertEquals(7, items.map { it.doc.name }.toSet().size, "no item twice")
            assertEquals(2, a2.vaultIds().count { it != a2.personalVaultId }, "no vault twice")
            assertEquals(2, items.sumOf { it.doc.attachments.size })
        } }
    }
}
