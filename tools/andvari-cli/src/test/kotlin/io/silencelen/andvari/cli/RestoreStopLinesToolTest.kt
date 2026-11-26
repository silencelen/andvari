package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * The tool's two lines for a restore that stopped at a batch of items or at an attached file (decided on 25 November
 * 2026): each says that its batch or file is not confirmed as stored in the account, which is true whether or not
 * anything reached the server; what was seen follows the colon, and the line still ends by saying how to resume.
 */
class RestoreStopLinesToolTest {
    private val env = RestoreFiles.env

    private fun count(w: CliWorld, home: java.io.File) = w.run(home, "item", "list", "personal").ok().lines().count { it.isNotBlank() }

    @Test fun aBatchThatNeverReachedTheServerIsNotConfirmedAsStored() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail"))))
            // Every push is cut before the server gets it: nothing of the batch reaches the server.
            p.cut = setOf(WireRoute.PUSH)
            val run = w.run(me, "restore", "--backup", backup.path, env = { env[it] }, dial = p.address)
            p.cut = emptySet()
            println("STOPLINE|batch code=${run.code} err=${run.err.trim()}")
            assertNotEquals(0, run.code, run.out + run.err)
            val said = run.err.lines().single { "batch 1 of “Personal”" in it }
            assertTrue("batch 1 of “Personal” is not confirmed as stored in the account: " in said, said)
            assertTrue(said.endsWith(" (run the same command again to resume)"), said)
            assertEquals(0, count(w, me), "nothing reached the server")
        } }
    }

    @Test fun anAttachedFileTheServerTookWhoseAnswerWasLostIsNotConfirmedAsStored() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val crypto = io.silencelen.andvari.core.crypto.createCryptoProvider()
            val sectionKey = crypto.randomBytes(32)
            val file = "the scanned passport".encodeToByteArray()
            val attId = "44444444-4444-4444-8444-444444444441"
            val payload = RestoreFiles.personalOnly(listOf("Bank")).let { b ->
                b.copy(
                    items = b.items + BackupItem(
                        RestoreFiles.itemId(9), RestoreFiles.PERSONAL, 1, 1_760_000_000_000L,
                        ItemDoc("login", "Passport office", login = LoginData("passport-user", "passport-password"), attachments = listOf(AttachmentRef(attId, "passport.pdf", file.size.toLong(), Bytes.toB64(crypto.randomBytes(32))))),
                    ),
                    attachments = listOf(BackupAttachmentEntry(1, attId, RestoreFiles.itemId(9), "passport.pdf", file.size.toLong(), Bytes.toB64(sectionKey))),
                )
            }
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(payload, sections = listOf(Backup.AttachmentSection(sectionKey) { file.copyOf() })))
            // The upload reaches the server and is stored; its answer never comes back.
            val taken = java.util.concurrent.atomic.AtomicInteger()
            p.answer = mapOf(
                WireRoute.ATTACHMENT_UPLOAD to { _, forward ->
                    val (status, _) = forward()
                    if (status == 200) taken.incrementAndGet()
                    throw java.io.IOException("the answer is lost on its way back")
                },
            )
            val run = w.run(me, "restore", "--backup", backup.path, env = { env[it] }, dial = p.address)
            p.answer = emptyMap()
            println("STOPLINE|file code=${run.code} taken=${taken.get()} err=${run.err.trim()}")
            assertNotEquals(0, run.code, run.out + run.err)
            assertTrue(taken.get() > 0, "the server stored the upload")
            val said = run.err.lines().single { "attachment “passport.pdf”" in it }
            assertTrue("attachment “passport.pdf” is not confirmed as stored in the account: " in said, said)
            assertTrue(said.endsWith(" (run the same command again to resume)"), said)
        } }
    }
}
