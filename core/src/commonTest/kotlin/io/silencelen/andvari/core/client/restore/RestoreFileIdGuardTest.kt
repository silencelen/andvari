package io.silencelen.andvari.core.client.restore

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * A restore opens only a file whose id is a lower-case UUID, the one form every andvari writer makes. The ids here are
 * all made of the characters a record's name may hold, so nothing but the id rule itself refuses them: a host would make
 * a record of each, and the restore would go on.
 */
class RestoreFileIdGuardTest {
    private val crypto = createCryptoProvider()
    private val pass = "id pass phrase"

    private fun file(fileId: String): ByteArray {
        val out = ArrayList<ByteArray>()
        Backup.build(crypto, pass, fileId, crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8 * 1024 * 1024), BackupPayload(exportedAt = 1L)) { out += it.copyOf() }
        val all = ByteArray(out.sumOf { it.size })
        var at = 0
        for (b in out) {
            b.copyInto(all, at)
            at += b.size
        }
        return all
    }

    @Test fun anIdARecordNameCouldHoldButThatIsNoLowerCaseUuidIsRefused() {
        val ids = listOf(
            "abc",
            "0-0-0-0-0",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee",
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee-1",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "gggggggg-gggg-4ggg-8ggg-gggggggggggg",
            "-eeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        )
        for (id in ids) {
            assertTrue(BackupRestore.safeRecordName("restore-$id-0123456789abcdef-0123456789abcdef0123456789abcdef"), id)
            assertIs<RestoreOpening.IdRefused>(BackupRestore.open(crypto, pass, file(id)), id)
        }
        assertIs<RestoreOpening.Opened>(BackupRestore.open(crypto, pass, file("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")))
    }
}
