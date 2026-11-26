package io.silencelen.andvari.cli.e2e

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Args
import io.silencelen.andvari.cli.CliError
import io.silencelen.andvari.cli.CliHome
import io.silencelen.andvari.cli.Ctx
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.Restore
import io.silencelen.andvari.cli.RestoreFiles
import io.silencelen.andvari.core.client.MemoryDeviceState
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the account holds changed between the tool's preview and its run (another program on this device finished the
 * same restore meanwhile, its record now beside this run's): nothing is sent, and the tool says so without naming a
 * cause it cannot know.
 */
class RestoreChangedToolTest {
    /** Standard output that calls [at] once, when [text] has been printed. */
    private class Watched(private val text: String, private val at: () -> Unit) : ByteArrayOutputStream() {
        private var done = false

        @Synchronized
        override fun write(b: ByteArray, off: Int, len: Int) {
            super.write(b, off, len)
            if (!done && toString().contains(text)) {
                done = true
                at()
            }
        }

        @Synchronized
        override fun write(b: Int) {
            super.write(b)
            if (!done && toString().contains(text)) {
                done = true
                at()
            }
        }
    }

    private suspend fun TestServer.alice(): AccountSession {
        Steps.registerThrough(device("operator"), origin, setupLink, "op@example.org")
        val h = Host(MemoryDeviceState(), MemoryDeviceState(), ::now, deviceName = "alice")
        Steps.registerThrough(h, origin, Steps.enrolLink(this), "alice@example.org", trustGate = true)
        val a = h.account(origin)!!
        a.synced()
        return a
    }

    @Test fun anAccountChangedBetweenThePreviewAndTheRunSendsNothingAndSaysSo() {
        TestServer().use { it.journey {
            val a = alice()
            val env = mapOf("ANDVARI_BACKUP_PASSPHRASE" to RestoreFiles.PASS)
            val first = Files.createTempDirectory("andvari-restore-changed").toFile()
            val second = Files.createTempDirectory("andvari-restore-changed").toFile()
            val file = File(first, "three.andvari").also { f -> f.writeBytes(RestoreFiles.bytes(RestoreFiles.personalOnly(listOf("Bank", "Mail", "Shop")), "eeeeeeee-eeee-4eee-8eee-eeeeeeeec001")) }
            // The first program restores the file whole, keeping its record in its own home.
            Restore(Ctx(Args(listOf("restore", "--backup", file.path)), CliHome(first), PrintStream(ByteArrayOutputStream()), { env[it] }, { null }, ::now), a).run()
            a.sync()
            val held = a.items.items().size
            assertEquals(3, held)
            // The second has no record: its preview offers the three. Once it has printed what it will restore, the first
            // program's record arrives beside it, as a second program finishing the same restore leaves it.
            val record = assertNotNull(first.listFiles()!!.singleOrNull { it.name.startsWith("restore-") })
            val out = Watched("  to restore: 3 items") { record.copyTo(File(second, record.name)) }
            val c = Ctx(Args(listOf("restore", "--backup", file.path)), CliHome(second), PrintStream(out, true), { env[it] }, { null }, ::now)
            val e = try { Restore(c, a).run(); null } catch (e: CliError) { e }
            val said = assertNotNull(e, "the run stops: ${out}").message.orEmpty()
            println("CHANGED|out=${out.toString().trim().lines()} said=$said")
            assertTrue(said.contains("changed after the preview was made") && said.contains("nothing was sent"), said)
            assertFalse(said.contains("sync"), "no cause it cannot know: $said")
            a.sync()
            assertEquals(held, a.items.items().size, "nothing was sent")
        } }
    }
}
