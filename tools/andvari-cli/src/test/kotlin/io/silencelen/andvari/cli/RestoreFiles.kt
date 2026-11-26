package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File

/** Backup files for the restore's tests, made by the shared code's own `Backup.build`. */
object RestoreFiles {
    const val PASS = "backup pass phrase"
    const val PERSONAL = "11111111-1111-4111-8111-111111111111"
    const val FAMILY = "33333333-3333-4333-8333-333333333331"
    const val WORK = "33333333-3333-4333-8333-333333333332"
    val env = mapOf("ANDVARI_PASSWORD" to io.silencelen.andvari.cli.e2e.Steps.PASSWORD, "ANDVARI_BACKUP_PASSPHRASE" to PASS)

    fun itemId(n: Int) = "22222222-2222-4222-8222-%012d".format(n)

    fun login(n: Int, vault: String, name: String) = BackupItem(itemId(n), vault, 1, 1_760_000_000_000L, ItemDoc("login", name, login = LoginData("user$n", "secret-password-$n")))

    /** [payload] as a file under [PASS]; [fileId] tells files apart (each file has a record of its own). */
    fun bytes(payload: BackupPayload, fileId: String = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", sections: List<Backup.AttachmentSection> = emptyList(), pass: String = PASS): ByteArray {
        val crypto = createCryptoProvider()
        val parts = ArrayList<ByteArray>()
        Backup.build(crypto, pass, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), payload, sections, null) { parts += it.copyOf() }
        return parts.fold(ByteArray(0)) { acc, p -> acc + p }
    }

    /** A personal vault ("Bank", "Mail"), the shared vault "Family" the person owned ("Router", "Wifi") and "Work" they were a writer of ("Jira", "Wiki"). */
    fun threeVaults(): BackupPayload = BackupPayload(
        exportedAt = 1_760_000_000_000L, origin = "https://old.example",
        vaults = listOf(BackupVault(PERSONAL, "personal", "Personal", "owner"), BackupVault(FAMILY, "shared", "Family", "owner"), BackupVault(WORK, "shared", "Work", "writer")),
        items = listOf(login(1, PERSONAL, "Bank"), login(2, PERSONAL, "Mail"), login(3, FAMILY, "Router"), login(4, FAMILY, "Wifi"), login(5, WORK, "Jira"), login(6, WORK, "Wiki")),
    )

    fun personalOnly(names: List<String>): BackupPayload = BackupPayload(
        exportedAt = 1_760_000_000_000L, origin = "https://old.example",
        vaults = listOf(BackupVault(PERSONAL, "personal", "Personal", "owner")),
        items = names.mapIndexed { i, n -> login(i + 1, PERSONAL, n) },
    )

    fun write(dir: File, name: String, bytes: ByteArray): File = File(dir, name).also { it.writeBytes(bytes) }
}
