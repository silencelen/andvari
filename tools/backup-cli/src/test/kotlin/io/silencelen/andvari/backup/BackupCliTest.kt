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

    /**
     * H83 at the CLI level. `verify`'s contract is that per-attachment failures are "collected,
     * never fatal" — the whole point of the command in a recovery is to name EVERY attachment
     * that will not restore, in one pass, before the operator makes a decision. A manifest
     * `fileKey` that is not base64url used to throw a bare CryptoException from `Bytes.fromB64`
     * one frame OUTSIDE the per-entry `catch (BackupException)`, so the first bad entry aborted
     * the entire verify with `error: invalid base64url` and the operator learned nothing about
     * the rest of the file. :core now translates that decode into the combined per-entry code;
     * this pins the behaviour the CLI actually exposes, which is what the operator sees.
     */
    @Test
    fun verify_manifestFileKeyNotBase64url_isACollectedFailRow() {
        val sample = TestBackups.buildWithBadManifestFileKey("bad manifest key phrase")
        // Must NOT throw: a per-entry problem is a FAIL row, not an aborted command.
        val report = BackupInspect.verify(crypto, sample.passphrase, sample.file)
        assertFalse(report.pass, "a manifest key that cannot decode must fail the file")
        assertEquals(1, report.checks.size)
        assertFalse(report.checks[0].pass)
        // The row carries the spec error code, not a raw base64 complaint — and it names the item,
        // so the operator can tell which attachment is lost.
        assertTrue(
            report.checks[0].detail.startsWith(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT),
            "detail should lead with the spec code, was: ${report.checks[0].detail}",
        )
        assertEquals("GitHub", report.checks[0].itemName)
        // Everything else about the file is still readable — that is what makes this a per-entry
        // verdict and not a corrupt container, and it is what Main.kt's summary reports around it.
        assertEquals(listOf("Personal (personal, owner)" to 2, "Family (shared, writer)" to 1), report.itemsPerVault)
        assertEquals(null, report.framingMismatch)
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
    fun redact_masksCardPanCvvAndNoteBodies() {
        // Regression: the old SECRET_KEYS omitted number/securityCode/notes, silently leaking full
        // card PAN + CVV and secure-note bodies from the "safe to share" default dump.
        val obj = Redact.tree(
            kotlinx.serialization.json.Json.parseToJsonElement(
                """{"number":"4111111111111111","securityCode":"987","notes":"wifi pw hunter2","password":"pw","name":"Visa"}""",
            ),
        ) as kotlinx.serialization.json.JsonObject
        assertEquals(Redact.MASK, (obj["number"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals(Redact.MASK, (obj["securityCode"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals(Redact.MASK, (obj["notes"] as kotlinx.serialization.json.JsonPrimitive).content)
        assertEquals("Visa", (obj["name"] as kotlinx.serialization.json.JsonPrimitive).content) // non-secret preserved
    }

    @Test
    fun secretsDescription_enumeratesFullMaskedSet() {
        // CR-16 / PT-M6 residual: the `--secrets` help text (Main.kt usage) and the runtime
        // WARNING banner (Main.kt dump) both interpolate Redact.secretsDescription, so this pins
        // that the operator-facing text names card PAN, CVV and note bodies — not just the old
        // password/TOTP/fileKey — and is derived from SECRET_KEYS so it can't drift again.
        val d = Redact.secretsDescription
        for (term in listOf("password", "TOTP seed", "fileKey", "card number", "security code", "note body")) {
            assertTrue(term in d, "secrets description must name '$term' — got: $d")
        }
        // The description must cover every masked key (the Redact init-block coverage invariant).
        assertEquals(Redact.SECRET_KEYS.size, 6, "SECRET_KEYS changed — update SECRET_LABELS to match")
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

    /**
     * Security review 2026-10 (A13, q45): "never overwrites" holds on a case-insensitive filesystem (macOS APFS by
     * default, Windows) too. Names that differ only by case, or by a trailing dot/space Windows drops, are ONE file
     * there, so they are refused up front like an exact collision; so is an existing file under another case.
     */
    @Test
    fun extract_refusesNamesThatCollideOnACaseInsensitiveFilesystem() {
        for ((names, atts) in listOf(
            ("Same" to "same") to ("a.bin" to "A.BIN"),
            ("Same" to "Same") to ("a.bin" to "a.bin. "),
        )) {
            val sample = TestBackups.buildSample(
                "extract fold phrase",
                itemNames = mapOf(TestBackups.GITHUB_ITEM to names.first, TestBackups.WIFI_ITEM to names.second),
                attachmentNames = atts,
            )
            val opened = Backup.open(crypto, sample.passphrase, sample.file)
            val outDir = createTempDirectory("backup-cli-fold").toFile()
            try {
                val e = assertFailsWith<IllegalStateException>("$names/$atts") { BackupInspect.extract(opened, outDir) }
                assertTrue("same output name" in (e.message ?: ""), e.message ?: "")
                assertEquals(0, outDir.listFiles()!!.size, "refusal must happen before any write")
            } finally {
                outDir.deleteRecursively()
            }
        }
        // An existing file that differs only by case is the same file there: refused, and left untouched.
        val sample = TestBackups.buildSample("extract fold existing phrase")
        val opened = Backup.open(crypto, sample.passphrase, sample.file)
        val outDir = createTempDirectory("backup-cli-fold-existing").toFile()
        try {
            val existing = java.io.File(outDir, "GITHUB-ROUTER-CONFIG.TXT").apply { writeText("mine") }
            val e = assertFailsWith<IllegalStateException> { BackupInspect.extract(opened, outDir) }
            assertTrue("refusing to overwrite" in (e.message ?: ""), e.message ?: "")
            assertEquals("mine", existing.readText())
            assertEquals(1, outDir.listFiles()!!.size)
        } finally {
            outDir.deleteRecursively()
        }
    }

    // ---- offline guarantee ----

    // ---- A14 (F12): verify prints co-member-authored strings, so it escapes their controls ----

    @Test
    fun verify_rendersHostileNamesAsVisibleEscapes() {
        // A co-member of the shared vault names things with terminal escapes: erase-line + cursor-up
        // to overwrite the FAIL rows, an OSC 52 clipboard write, and the one-byte C1 CSI.
        val sample = TestBackups.buildSample(
            "hostile names phrase",
            itemNames = mapOf(TestBackups.GITHUB_ITEM to "Bank\u001B[2K\u001B[1A"),
            attachmentNames = "scan\u001B]52;c;cHduZWQ=\u0007.pdf" to "a\tb\nVERIFY PASS",
            edit = { p ->
                p.copy(
                    origin = "https://x.example\u009B2J",
                    userId = "aaaa\u001Bc",
                    vaults = p.vaults.map { if (it.type == "shared") it.copy(name = "Family\u001B[8m") else it },
                    skipped = p.skipped.copy(
                        undecryptable = p.skipped.undecryptable.map { it.copy(itemId = it.itemId + "\u0085") },
                        attachmentsOverCap = listOf("big\u007F.zip"),
                        attachmentFetchFailed = listOf("gone\u001B[0m.bin"),
                    ),
                )
            },
        )
        val report = BackupInspect.verify(crypto, sample.passphrase, sample.file)
        val out = BackupInspect.renderVerify("backup.andvari", report)

        val controls = out.filter { it != '\n' && io.silencelen.andvari.core.client.TerminalText.isControl(it) }
        assertEquals("", controls, "no control character from the payload reaches the terminal")
        for (visible in listOf(
            "Bank\\u001B[2K\\u001B[1A", "scan\\u001B]52;c;cHduZWQ=\\u0007.pdf", "a\\u0009b\\u000AVERIFY PASS",
            "https://x.example\\u009B2J", "aaaa\\u001Bc", "Family\\u001B[8m (shared, writer)",
            "\\u0085", "big\\u007F.zip", "gone\\u001B[0m.bin",
        )) {
            assertTrue(visible in out, "missing visible escape $visible in:\n$out")
        }
        // A name cannot forge a line of its own: the only line breaks are the renderer's.
        assertFalse(out.lines().any { it.startsWith("VERIFY PASS") }, out)
    }

    @Test
    fun verify_exceptionDetailIsEscapedToo() {
        assertEquals("error: bad \\u001B[31mthing", BackupInspect.errorLine(null, "bad \u001B[31mthing"))
        assertEquals("error [backup_truncated]: cut \\u009B", BackupInspect.errorLine("backup_truncated", "cut \u009B"))
    }

    @Test
    fun sanitizeFileName_sharesTheControlClass_C1Included() {
        assertEquals("a_b_c_d", BackupInspect.sanitizeFileName("a\u009Bb\u0085c\u001Bd"))
    }

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
