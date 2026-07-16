package io.silencelen.andvari.backup

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupSkippedItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.PasswordHistoryEntry
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider

/**
 * Builds REAL `.andvari` containers through the :core reference impl for the CLI tests
 * and the jar-smoke sample generator ([main] in SampleGen.kt). FAST-class kdf params
 * (the vector-gen pattern) — these exercise the container and the CLI, never argon2id
 * at production cost.
 */
object TestBackups {
    val crypto = createCryptoProvider()
    val fast = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024)

    const val PERSONAL_VAULT = "11111111-1111-4111-8111-111111111111"
    const val FAMILY_VAULT = "77777777-7777-4777-8777-777777777777"
    const val GITHUB_ITEM = "22222222-2222-4222-8222-222222222222"
    const val WIFI_ITEM = "33333333-3333-4333-8333-333333333333"
    const val ROUTER_ITEM = "88888888-8888-4888-8888-888888888888"

    /** Known plaintexts for the two embedded attachments (B spans multiple secretstream chunks). */
    val attachmentA = ByteArray(4096) { (it * 31 + 7).toByte() }
    val attachmentB = ByteArray(Attachments.CHUNK + 123) { (it * 13 + 1).toByte() }

    class Sample(
        val file: ByteArray,
        val fileId: String,
        val passphrase: String,
        val payload: BackupPayload,
        val attachmentKeys: List<ByteArray>,
    )

    fun samplePayload(
        attachmentEntries: List<BackupAttachmentEntry>,
        itemNames: Map<String, String> = emptyMap(),
    ): BackupPayload {
        fun name(id: String, default: String) = itemNames[id] ?: default
        return BackupPayload(
            exportedAt = 1751850000000,
            origin = "https://andvari.example.net",
            userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            identityFingerprint = "0123456789abcdef",
            vaults = listOf(
                BackupVault(PERSONAL_VAULT, "personal", "Personal", "owner"),
                BackupVault(FAMILY_VAULT, "shared", "Family", "writer"),
            ),
            items = listOf(
                BackupItem(
                    GITHUB_ITEM, PERSONAL_VAULT, 1, 1751840000000,
                    ItemDoc(
                        type = "login", name = name(GITHUB_ITEM, "GitHub"),
                        login = LoginData(
                            username = "jacob", password = "hunter2",
                            uris = listOf("https://github.com"),
                            totp = "otpauth://totp/gh?secret=JBSWY3DPEHPK3PXP",
                            passwordHistory = listOf(PasswordHistoryEntry("oldhunter1", 1690000000000)),
                        ),
                    ),
                ),
                BackupItem(
                    WIFI_ITEM, PERSONAL_VAULT, 1, 1751841000000,
                    ItemDoc(type = "note", name = name(WIFI_ITEM, "Wifi"), notes = "router is in the closet"),
                ),
                BackupItem(
                    ROUTER_ITEM, FAMILY_VAULT, 1, 1751842000000,
                    // password = null on purpose: dump must keep it null, not mask it.
                    ItemDoc(type = "login", name = name(ROUTER_ITEM, "Router admin"), login = LoginData(username = "admin", password = null)),
                ),
            ),
            attachments = attachmentEntries,
            skipped = BackupSkipped(
                undecryptable = listOf(BackupSkippedItem("44444444-4444-4444-8444-444444444444", PERSONAL_VAULT, 2)),
                attachmentsOverCap = listOf("tax-archive.zip"),
            ),
        )
    }

    /** Two vaults, three items, two embedded attachments, recorded skips — the everything sample. */
    fun buildSample(passphrase: String, itemNames: Map<String, String> = emptyMap(), attachmentNames: Pair<String, String> = "router-config.txt" to "scan.pdf"): Sample {
        val keyA = crypto.randomBytes(32)
        val keyB = crypto.randomBytes(32)
        val payload = samplePayload(
            listOf(
                BackupAttachmentEntry(1, "aaaa1111-0000-4000-8000-000000000001", GITHUB_ITEM, attachmentNames.first, attachmentA.size.toLong(), Bytes.toB64(keyA)),
                BackupAttachmentEntry(2, "aaaa1111-0000-4000-8000-000000000002", WIFI_ITEM, attachmentNames.second, attachmentB.size.toLong(), Bytes.toB64(keyB)),
            ),
            itemNames,
        )
        val fileId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        val parts = ArrayList<ByteArray>()
        Backup.build(
            crypto, passphrase, fileId, crypto.randomBytes(16), fast, payload,
            // build() zeroes the supplied plaintext buffers — hand it copies.
            listOf(
                Backup.AttachmentSection(keyA) { attachmentA.copyOf() },
                Backup.AttachmentSection(keyB) { attachmentB.copyOf() },
            ),
            null,
        ) { parts.add(it) }
        val file = ByteArray(parts.sumOf { it.size })
        var off = 0
        for (p in parts) {
            p.copyInto(file, off)
            off += p.size
        }
        return Sample(file, fileId, passphrase, payload, listOf(keyA, keyB))
    }

    /** Offset of the first byte of section 0's envelope (magic + headerLen + header + u64 length). */
    fun section0DataOffset(file: ByteArray): Int {
        val headerLen = (file[8].toInt() and 0xFF) or ((file[9].toInt() and 0xFF) shl 8) or
            ((file[10].toInt() and 0xFF) shl 16) or ((file[11].toInt() and 0xFF) shl 24)
        return 12 + headerLen + 8
    }
}
