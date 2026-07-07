package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** spec 07 — pure reference tests for the CSV export writer and the `.andvari` backup
 *  container (vector byte-pinning lives in jvmTest/ExportVectorsTest). */
class ExportTest {
    private val crypto = createCryptoProvider()
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /** Minimum-cost KDF — these tests exercise the container, not argon2id. */
    private val fast = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024)

    private fun login(
        name: String,
        username: String? = null,
        password: String? = null,
        uris: List<String> = emptyList(),
        totp: String? = null,
        notes: String? = null,
        attachments: List<AttachmentRef> = emptyList(),
    ) = ItemDoc(type = "login", name = name, notes = notes, login = LoginData(username, password, uris, totp), attachments = attachments)

    private fun collect(block: ((ByteArray) -> Unit) -> Unit): ByteArray {
        val parts = ArrayList<ByteArray>()
        block { parts.add(it) }
        val out = ByteArray(parts.sumOf { it.size })
        var o = 0
        for (p in parts) { p.copyInto(out, o); o += p.size }
        return out
    }

    // ---- CSV writer ----

    @Test
    fun csv_emptyList_isHeaderOnly() {
        assertEquals("name,url,username,password,note,totp\r\n", ExportCsv.write(emptyList()))
    }

    @Test
    fun csv_basicRow_columnMapping() {
        val csv = ExportCsv.write(listOf(login("GitHub", "jacob", "hunter2", listOf("https://gh.test"), "otpauth://totp/x?secret=AAAA", "a note")))
        assertEquals("name,url,username,password,note,totp\r\nGitHub,https://gh.test,jacob,hunter2,a note,otpauth://totp/x?secret=AAAA\r\n", csv)
    }

    @Test
    fun csv_quoting_iff_needed_and_doubleQuoteEscape() {
        val csv = ExportCsv.write(
            listOf(
                login("Acme, Inc", "user\"name", "p,w\"1", listOf("https://a.test")),
                // Formula-injection characters are verbatim, never mangled/quoted (spec 07 §1).
                login("=cmd()", "=SUM(A1)", "+plus-@at", listOf("https://f.test"), notes = " not trimmed "),
            ),
        )
        val lines = csv.split("\r\n")
        assertEquals("\"Acme, Inc\",https://a.test,\"user\"\"name\",\"p,w\"\"1\",,", lines[1])
        assertEquals("=cmd(),https://f.test,=SUM(A1),+plus-@at, not trimmed ,", lines[2])
    }

    @Test
    fun csv_normalizesCrlfAndLoneCrToLf() {
        val csv = ExportCsv.write(listOf(login("M", "u", "p\rq", listOf("https://m.test"), notes = "l1\r\nl2\rl3\nl4")))
        assertEquals("name,url,username,password,note,totp\r\nM,https://m.test,u,\"p\nq\",\"l1\nl2\nl3\nl4\",\r\n", csv)
    }

    @Test
    fun csv_skipsNoteItems_writesEmptyUserPassRows_dropsUriTail() {
        val csv = ExportCsv.write(
            listOf(
                ItemDoc(type = "note", name = "Never exported", notes = "secret"),
                login("EmptyBoth", "", "", listOf("https://w.test")),
                login("TwoUris", "u", "p", listOf("https://first.test", "https://dropped.test")),
            ),
        )
        assertEquals(
            "name,url,username,password,note,totp\r\n" +
                "EmptyBoth,https://w.test,,,,\r\n" +
                "TwoUris,https://first.test,u,p,,\r\n",
            csv,
        )
    }

    @Test
    fun csv_preservesCallerOrder_deterministically() {
        val docs = listOf(login("b"), login("a"), login("c"))
        val first = ExportCsv.write(docs)
        assertEquals(first, ExportCsv.write(docs))
        assertEquals(listOf("name,url,username,password,note,totp", "b,,,,,", "a,,,,,", "c,,,,,", ""), first.split("\r\n"))
    }

    @Test
    fun csv_warnings_enumerateByName() {
        val ref = AttachmentRef(id = "x", name = "scan.pdf", size = 1, fileKey = "a2V5")
        val w = ExportCsv.warnings(
            listOf(
                ItemDoc(type = "note", name = "A note"),
                ItemDoc(type = "note", name = "Note with file", attachments = listOf(ref)),
                login("Login with file", "u", "p", attachments = listOf(ref)),
                login("Two uris", "u", "p", uris = listOf("a.test", "b.test")),
                login("Empty both"),
                login("Fine", "u", "p", uris = listOf("c.test")),
            ),
        )
        assertEquals(listOf("A note", "Note with file"), w.noteItems)
        assertEquals(listOf("Note with file", "Login with file"), w.withAttachments)
        assertEquals(listOf("Two uris"), w.extraUris)
        assertEquals(listOf("Empty both"), w.emptyUsernameAndPassword)
    }

    // ---- AD ----

    @Test
    fun adExport_shape() {
        assertContentEquals("andvari/v1|export|1|abc-123".encodeToByteArray(), Ad.export(1, "abc-123"))
    }

    // ---- container: build/open round trips ----

    private fun samplePayload(): BackupPayload {
        val vaultId = "11111111-1111-4111-8111-111111111111"
        return BackupPayload(
            exportedAt = 1751850000000,
            origin = "https://andvari.test",
            userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            identityFingerprint = "0123456789abcdef",
            vaults = listOf(BackupVault(vaultId, "personal", "Personal", "owner")),
            items = listOf(
                BackupItem("22222222-2222-4222-8222-222222222222", vaultId, 1, 1751840000000, login("GitHub", "jacob", "hunter2", listOf("https://gh.test"))),
                BackupItem("33333333-3333-4333-8333-333333333333", vaultId, 1, 1751841000000, ItemDoc(type = "note", name = "Wifi", notes = "closet")),
            ),
            skipped = BackupSkipped(undecryptable = listOf(BackupSkippedItem("44444444-4444-4444-8444-444444444444", vaultId, 2))),
        )
    }

    private fun buildSample(passphrase: String, payload: BackupPayload = samplePayload(), attachments: List<Backup.AttachmentSection> = emptyList()): Pair<String, ByteArray> {
        val fileId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        val file = collect { sink ->
            Backup.build(crypto, passphrase, fileId, crypto.randomBytes(16), fast, payload, attachments, null, sink)
        }
        return fileId to file
    }

    @Test
    fun container_roundTrip_itemsOnly() {
        val payload = samplePayload()
        val (fileId, file) = buildSample("round trip passphrase", payload)
        val opened = Backup.open(crypto, "round trip passphrase", file)
        assertEquals(Backup.FORMAT, opened.header.format)
        assertEquals(1, opened.header.v)
        assertEquals(fileId, opened.header.fileId)
        assertEquals("argon2id13", opened.header.kdfParams.alg)
        assertEquals(fast.ops, opened.header.kdfParams.opsLimit)
        assertEquals(payload, opened.payload)
        assertEquals(0, opened.attachmentSectionCount)
    }

    @Test
    fun container_wrongPassphrase_isCombinedError() {
        val (_, file) = buildSample("the right passphrase")
        val e = assertFailsWith<BackupException> { Backup.open(crypto, "the wrong passphrase", file) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    @Test
    fun container_tamperedCiphertext_isCombinedError() {
        val (_, file) = buildSample("tamper passphrase")
        val tampered = file.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        val e = assertFailsWith<BackupException> { Backup.open(crypto, "tamper passphrase", tampered) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    @Test
    fun container_fileIdSwapInHeader_failsAdBinding() {
        val (fileId, file) = buildSample("ad binding passphrase")
        val headerLen = ((file[8].toInt() and 0xFF)) or ((file[9].toInt() and 0xFF) shl 8) or ((file[10].toInt() and 0xFF) shl 16) or ((file[11].toInt() and 0xFF) shl 24)
        val headerStr = file.copyOfRange(12, 12 + headerLen).decodeToString()
        val swapped = headerStr.replace(fileId, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeef").encodeToByteArray()
        assertEquals(headerLen, swapped.size)
        val forged = file.copyOf().also { swapped.copyInto(it, 12) }
        val e = assertFailsWith<BackupException> { Backup.open(crypto, "ad binding passphrase", forged) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    /** Pins that ItemDoc's ExtrasOverlaySerializer operates INSIDE the backup payload:
     *  unknown fields at all 4 doc levels survive build→open (spec 02 §3 via 07 §2.4). */
    @Test
    fun container_preservesUnknownDocFields_atAllFourLevels() {
        val doc = json.decodeFromString(
            ItemDoc.serializer(),
            """{"type":"login","name":"Everything","x-top":"keep","login":{"username":"u","password":"p","x-l":{"deep":true},"passwordHistory":[{"password":"old","retiredAt":1690000000000,"x-h":7}]},"attachments":[{"id":"55555555-5555-4555-8555-555555555555","name":"a.bin","size":1,"fileKey":"a2V5","x-a":false}]}""",
        )
        val payload = samplePayload().copy(items = listOf(BackupItem("66666666-6666-4666-8666-666666666666", "11111111-1111-4111-8111-111111111111", 1, 0, doc)))
        val (_, file) = buildSample("extras passphrase", payload)
        val opened = Backup.open(crypto, "extras passphrase", file)
        val out = opened.payload.items.single().doc
        assertEquals(JsonPrimitive("keep"), out.extras["x-top"])
        assertEquals(buildJsonObject { put("deep", true) }, out.login?.extras?.get("x-l"))
        assertEquals(JsonPrimitive(7), out.login?.passwordHistory?.single()?.extras?.get("x-h"))
        assertEquals(JsonPrimitive(false), out.attachments.single().extras["x-a"])
        assertEquals("p", out.login?.password)
    }

    // ---- container: attachment sections ----

    @Test
    fun container_attachmentSections_roundTrip() {
        val plainA = ByteArray(100) { (it * 3).toByte() }
        val plainB = ByteArray(Attachments.CHUNK + 123) { (it * 7 + 1).toByte() } // multi-chunk
        val keyA = crypto.randomBytes(32)
        val keyB = crypto.randomBytes(32)
        val payload = samplePayload().copy(
            attachments = listOf(
                BackupAttachmentEntry(1, "aaaa1111-0000-4000-8000-000000000001", "22222222-2222-4222-8222-222222222222", "a.bin", plainA.size.toLong(), Bytes.toB64(keyA)),
                BackupAttachmentEntry(2, "aaaa1111-0000-4000-8000-000000000002", "22222222-2222-4222-8222-222222222222", "b.bin", plainB.size.toLong(), Bytes.toB64(keyB)),
            ),
        )
        // build() zeroes the supplied plaintext buffers — hand it copies.
        val sections = listOf(
            Backup.AttachmentSection(keyA) { plainA.copyOf() },
            Backup.AttachmentSection(keyB) { plainB.copyOf() },
        )
        val (_, file) = buildSample("attachment passphrase", payload, sections)
        val opened = Backup.open(crypto, "attachment passphrase", file)
        assertEquals(2, opened.attachmentSectionCount)
        assertContentEquals(plainA, opened.readAttachment(opened.payload.attachments[0]))
        assertContentEquals(plainB, opened.readAttachmentSection(2, keyB))
        // Wrong fileKey on a valid section is the combined error.
        val e = assertFailsWith<BackupException> { opened.readAttachmentSection(1, keyB) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    @Test
    fun container_build_rejectsManifestSectionMismatch() {
        val payload = samplePayload().copy(
            attachments = listOf(BackupAttachmentEntry(1, "a", "i", "n", 1, Bytes.toB64(crypto.randomBytes(32)))),
        )
        assertFailsWith<IllegalArgumentException> {
            collect { sink -> Backup.build(crypto, "x", "f", crypto.randomBytes(16), fast, payload, emptyList(), null, sink) }
        }
    }

    /** A stream truncated INSIDE valid section framing (missing FINAL chunk) must fail
     *  hard at read time (spec 02 §6 discipline carried into §2.5 sections). */
    @Test
    fun container_attachmentStreamTruncation_failsHard() {
        val passphrase = "stream truncation passphrase"
        val fileId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
        val salt = crypto.randomBytes(16)
        val payloadUtf8 = json.encodeToString(BackupPayload.serializer(), BackupPayload(exportedAt = 0)).encodeToByteArray()
        val exportKey = Hkdf.sha256(crypto, Keys.masterKey(crypto, passphrase, salt, fast), ByteArray(0), "andvari/v1/export".encodeToByteArray(), 32)
        val section0 = Envelope.seal(crypto, exportKey, payloadUtf8, Ad.export(1, fileId))
        val fileKey = crypto.randomBytes(32)
        val enc = Attachments.encrypt(crypto, fileKey, ByteArray(Attachments.CHUNK + 50) { 9 }) // 2 chunks
        val truncatedStream = enc.header + enc.ciphertext.copyOfRange(0, Attachments.CIPHER_CHUNK) // FINAL dropped
        val file = rawContainer(headerJson(fileId, Bytes.toB64(salt)), listOf(section0, truncatedStream))
        val opened = Backup.open(crypto, passphrase, file) // framing + section 0 are intact
        val e = assertFailsWith<BackupException> { opened.readAttachmentSection(1, fileKey) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, e.code)
    }

    // ---- container: §2.2 validation ladder ----

    private fun u32le(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())
    private fun u64le(v: Long) = ByteArray(8) { i -> ((v ushr (8 * i)) and 0xFF).toByte() }

    private fun rawContainer(headerJson: String, sections: List<ByteArray>): ByteArray {
        var out = "ANDVBK01".encodeToByteArray() + u32le(headerJson.encodeToByteArray().size) + headerJson.encodeToByteArray()
        for (s in sections) out = out + u64le(s.size.toLong()) + s
        return out
    }

    private fun headerJson(
        fileId: String = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        saltB64: String = Bytes.toB64(ByteArray(16) { it.toByte() }),
        format: String = "andvari-backup",
        v: Int = 1,
        kdfV: Int = 1,
        alg: String = "argon2id13",
        opsLimit: Long = 1,
        memBytes: Long = 8 * 1024 * 1024,
    ): String = """{"format":"$format","v":$v,"fileId":"$fileId","kdfSalt":"$saltB64","kdfParams":{"v":$kdfV,"alg":"$alg","opsLimit":$opsLimit,"memBytes":$memBytes}}"""

    private fun assertRejects(code: String, file: ByteArray, passphrase: String = "ladder passphrase") {
        val e = assertFailsWith<BackupException> { Backup.open(crypto, passphrase, file) }
        assertEquals(code, e.code)
    }

    @Test
    fun ladder_magic() {
        assertRejects(Backup.ERR_UNKNOWN_FORMAT, byteArrayOf(1, 2, 3)) // shorter than magic
        assertRejects(Backup.ERR_UNKNOWN_FORMAT, rawContainer(headerJson(), listOf(ByteArray(4))).also { it[0] = 'X'.code.toByte() })
    }

    @Test
    fun ladder_header() {
        assertRejects(Backup.ERR_TRUNCATED, "ANDVBK01".encodeToByteArray() + byteArrayOf(9, 0)) // ends inside headerLen
        assertRejects(Backup.ERR_TOO_LARGE, "ANDVBK01".encodeToByteArray() + u32le(64 * 1024 + 1)) // headerLen over cap
        assertRejects(Backup.ERR_TRUNCATED, "ANDVBK01".encodeToByteArray() + u32le(100) + ByteArray(10)) // ends inside header
        assertRejects(Backup.ERR_UNKNOWN_FORMAT, rawContainer("this is not json", listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNKNOWN_FORMAT, rawContainer("""{"v":1}""", listOf(ByteArray(4)))) // required fields missing
    }

    @Test
    fun ladder_formatAndVersion() {
        assertRejects(Backup.ERR_UNKNOWN_FORMAT, rawContainer(headerJson(format = "andvari-backup-vNext"), listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNKNOWN_VERSION, rawContainer(headerJson(v = 2), listOf(ByteArray(4))))
    }

    @Test
    fun ladder_kdf() {
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(alg = "scrypt"), listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(kdfV = 2), listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(memBytes = 256L * 1024 * 1024 + 1), listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(opsLimit = 17), listOf(ByteArray(4))))
        // Below libsodium's own minima — argon2id cannot run these (not a policy floor).
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(opsLimit = 0), listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(memBytes = 4096), listOf(ByteArray(4))))
        assertRejects(Backup.ERR_UNSUPPORTED_KDF, rawContainer(headerJson(saltB64 = Bytes.toB64(ByteArray(8))), listOf(ByteArray(4))))
    }

    @Test
    fun ladder_sectionFraming() {
        assertRejects(Backup.ERR_TRUNCATED, rawContainer(headerJson(), emptyList())) // section 0 missing
        assertRejects(Backup.ERR_TRUNCATED, rawContainer(headerJson(), emptyList()) + byteArrayOf(1, 2, 3)) // ends inside a length
        assertRejects(Backup.ERR_TRUNCATED, rawContainer(headerJson(), emptyList()) + u64le(100) + ByteArray(10)) // section past EOF
        assertRejects(Backup.ERR_TRUNCATED, rawContainer(headerJson(), emptyList()) + u64le(Long.MIN_VALUE) + ByteArray(10)) // u64 high bit
        // A large POSITIVE length (Long.MAX_VALUE) must also reject: off+8+len used to overflow
        // Long to a negative sum that slipped past the guard, then len.toInt() truncated to garbage.
        assertRejects(Backup.ERR_TRUNCATED, rawContainer(headerJson(), emptyList()) + u64le(Long.MAX_VALUE) + ByteArray(10))
    }

    @Test
    fun open_missingAttachmentSection_rejects() {
        val (_, file) = buildSample("no sections passphrase")
        val opened = Backup.open(crypto, "no sections passphrase", file)
        val e = assertFailsWith<BackupException> { opened.readAttachmentSection(1, crypto.randomBytes(32)) }
        assertEquals(Backup.ERR_TRUNCATED, e.code)
        assertTrue("no such attachment section" in (e.message ?: ""))
    }
}
