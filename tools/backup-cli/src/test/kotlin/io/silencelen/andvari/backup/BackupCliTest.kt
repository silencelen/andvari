package io.silencelen.andvari.backup

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupException
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Drives [BackupInspect] against real containers built by the :core reference impl
 * (TestBackups) — verify pass/fail with the spec 07 §2.2 error codes, dump redaction,
 * extract round-trip + overwrite refusal, and the offline classpath guarantee.
 */
class BackupCliTest {
    private val crypto = TestBackups.crypto

    // ---- verify ----

    @Test
    fun verify_goodFile_passesAndCounts() {
        val sample = TestBackups.buildSample("verify pass phrase")
        val report = BackupInspect.verify(crypto, sample.passphrase, sample.file)
        assertTrue(report.pass)
        assertEquals(null, report.framingMismatch)
        assertEquals(
            listOf("Personal (personal, owner)" to 2, "Family (shared, writer)" to 1),
            report.itemsPerVault,
        )
        assertEquals(2, report.checks.size)
        assertTrue(report.checks.all { it.pass }, report.checks.toString())
        assertEquals("GitHub", report.checks[0].itemName)
        assertEquals("Wifi", report.checks[1].itemName)
        // Skips recorded by the exporting client surface in the payload for the summary.
        assertEquals(listOf("tax-archive.zip"), report.opened.payload.skipped.attachmentsOverCap)
    }

    @Test
    fun verify_wrongPassphrase_isCombinedSpecCode() {
        val sample = TestBackups.buildSample("the right passphrase")
        val e = assertFailsWith<BackupException> { BackupInspect.verify(crypto, "the wrong passphrase", sample.file) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    @Test
    fun verify_tamperedPayloadByte_isCombinedSpecCode() {
        val sample = TestBackups.buildSample("tamper payload phrase")
        val tampered = sample.file.copyOf()
        val i = TestBackups.section0DataOffset(tampered) + 16 // inside the section-0 envelope
        tampered[i] = (tampered[i].toInt() xor 1).toByte()
        val e = assertFailsWith<BackupException> { BackupInspect.verify(crypto, sample.passphrase, tampered) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    @Test
    fun verify_tamperedAttachmentByte_failsThatCheckNotTheOpen() {
        val sample = TestBackups.buildSample("tamper attachment phrase")
        val tampered = sample.file.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 1).toByte() // last attachment section
        val report = BackupInspect.verify(crypto, sample.passphrase, tampered)
        assertFalse(report.pass)
        assertTrue(report.checks[0].pass, "untouched section must still verify")
        assertFalse(report.checks[1].pass)
        assertTrue(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT in report.checks[1].detail)
    }

    @Test
    fun verify_truncatedFile_isTruncated() {
        val sample = TestBackups.buildSample("truncate phrase")
        val truncated = sample.file.copyOfRange(0, sample.file.size - 10)
        val e = assertFailsWith<BackupException> { BackupInspect.verify(crypto, sample.passphrase, truncated) }
        assertEquals(Backup.ERR_TRUNCATED, e.code)
    }

    // ---- dump redaction ----

    @Test
    fun dump_redactsSecretsByDefault() {
        val sample = TestBackups.buildSample("dump redaction phrase")
        val opened = Backup.open(crypto, sample.passphrase, sample.file)
        val redacted = BackupInspect.dumpJson(opened.payload, secrets = false)

        assertTrue(Redact.MASK in redacted)
        assertFalse("hunter2" in redacted, "live password must be masked")
        assertFalse("oldhunter1" in redacted, "passwordHistory password must be masked")
        assertFalse("JBSWY3DPEHPK3PXP" in redacted, "totp seed must be masked")
        for (entry in opened.payload.attachments) {
            assertFalse(entry.fileKey in redacted, "manifest fileKey must be masked")
        }
        // Non-secrets survive; a null password stays null (not masked into looking present).
        assertTrue("jacob" in redacted)
        assertTrue("router-config.txt" in redacted)
        assertTrue("\"password\": null" in redacted)
    }

    @Test
    fun dump_secretsFlag_printsRaw() {
        val sample = TestBackups.buildSample("dump secrets phrase")
        val opened = Backup.open(crypto, sample.passphrase, sample.file)
        val raw = BackupInspect.dumpJson(opened.payload, secrets = true)

        assertTrue("hunter2" in raw)
        assertTrue("oldhunter1" in raw)
        assertTrue("JBSWY3DPEHPK3PXP" in raw)
        for (entry in opened.payload.attachments) assertTrue(entry.fileKey in raw)
        assertFalse(Redact.MASK in raw)
    }

    // ---- extract ----

    @Test
    fun extract_roundTrip_thenRefusesOverwrite() {
        val sample = TestBackups.buildSample("extract phrase")
        val opened = Backup.open(crypto, sample.passphrase, sample.file)
        val outDir = createTempDirectory("backup-cli-extract").toFile()
        try {
            val written = BackupInspect.extract(opened, outDir)
            assertEquals(2, written.size)
            assertEquals("GitHub-router-config.txt", written[0].file.name)
            assertEquals("Wifi-scan.pdf", written[1].file.name)
            assertContentEquals(TestBackups.attachmentA, written[0].file.readBytes())
            assertContentEquals(TestBackups.attachmentB, written[1].file.readBytes())

            // Second run refuses BEFORE writing anything — bytes stay exactly as written.
            val e = assertFailsWith<IllegalStateException> { BackupInspect.extract(opened, outDir) }
            assertTrue("refusing to overwrite" in (e.message ?: ""), e.message ?: "")
            assertContentEquals(TestBackups.attachmentA, written[0].file.readBytes())
            assertContentEquals(TestBackups.attachmentB, written[1].file.readBytes())
        } finally {
            outDir.deleteRecursively()
        }
    }

    @Test
    fun extract_sanitizesPathSeparators() {
        val sample = TestBackups.buildSample(
            "extract sanitize phrase",
            itemNames = mapOf(TestBackups.GITHUB_ITEM to "evil/item"),
            attachmentNames = "..\\..\\pwn.bin" to "sub/dir/scan.pdf",
        )
        val opened = Backup.open(crypto, sample.passphrase, sample.file)
        val outDir = createTempDirectory("backup-cli-sanitize").toFile()
        try {
            val written = BackupInspect.extract(opened, outDir)
            assertEquals("evil_item-.._.._pwn.bin", written[0].file.name)
            assertEquals("Wifi-sub_dir_scan.pdf", written[1].file.name)
            for (w in written) {
                assertEquals(outDir.canonicalFile, w.file.canonicalFile.parentFile, "must not escape outDir")
                assertTrue(w.file.isFile)
            }
        } finally {
            outDir.deleteRecursively()
        }
    }

    @Test
    fun extract_refusesCollidingNamesUpFront() {
        val sample = TestBackups.buildSample(
            "extract collide phrase",
            // Both manifest entries end up as "Same-a.bin".
            itemNames = mapOf(TestBackups.GITHUB_ITEM to "Same", TestBackups.WIFI_ITEM to "Same"),
            attachmentNames = "a.bin" to "a.bin",
        )
        val opened = Backup.open(crypto, sample.passphrase, sample.file)
        val outDir = createTempDirectory("backup-cli-collide").toFile()
        try {
            val e = assertFailsWith<IllegalStateException> { BackupInspect.extract(opened, outDir) }
            assertTrue("same output name" in (e.message ?: ""), e.message ?: "")
            assertEquals(0, outDir.listFiles()!!.size, "refusal must happen before any write")
        } finally {
            outDir.deleteRecursively()
        }
    }

    // ---- offline guarantee ----

    @Test
    fun noNetworkClassesOnClasspath() {
        // The offline guarantee (spec 07 §3 — same discipline as recovery-cli): no HTTP
        // client must be reachable.
        for (cls in listOf(
            "io.ktor.client.HttpClient",
            "java.net.http.HttpClient",
            "okhttp3.OkHttpClient",
        )) {
            // java.net.http is in the JDK, so only assert the 3rd-party HTTP stacks are absent.
            if (cls.startsWith("java.")) continue
            val present = runCatching { Class.forName(cls) }.isSuccess
            assertTrue(!present, "$cls must NOT be on the backup-cli classpath (offline tool)")
        }
    }
}
