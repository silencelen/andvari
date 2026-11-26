package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * On the old account line, a refusal because the account was wiped (a lock on another thread
 * between the caller's liveness check and the open) passes through the handlers that read kept records, and nothing is
 * removed or rewritten because of it (spec 01 §8 rule 5). Before, each swallowed the refusal and treated the record as
 * one this version cannot read: the kept moves were deleted and counted dropped, the kept saves with files deleted and
 * counted unreadable. The wipe here lands before the open, which is what the other thread's lock does at the worst
 * moment.
 */
class OldLineLockPassesThroughTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))

    private fun wipedAccount(): Account =
        Account.enroll("inv", "w@example.com", "w", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey,
            Escrow.fingerprint(crypto, recovery.publicKey), "dev", crypto).account.also { it.wipe() }

    /** A file of app-private storage, in memory, that counts its deletes. */
    private class File(var bytes: ByteArray?) : FillSnapshotStore {
        var deletes = 0
        override fun write(bytes: ByteArray): Boolean { this.bytes = bytes.copyOf(); return true }
        override fun read(): ByteArray? = bytes?.copyOf()
        override fun delete() { deletes++; bytes = null }
    }

    private val record = ByteArray(96) { (it * 7 + 3).toByte() }

    @Test fun theKeptMovesAreNotDeletedBecauseTheVaultLocked() {
        val file = File(record.copyOf())
        var dropped = 0
        val wiped = wipedAccount()
        val store = VaultMoves.Store.Sealed(file, { dropped += it }) { wiped }
        assertFailsWith<AccountWipedException> { store.load() }
        assertEquals(0, file.deletes, "the record stays")
        assertContentEquals(record, file.bytes)
        assertEquals(0, dropped, "nothing is counted dropped")
    }

    @Test fun theKeptSavesWithFilesAreNotDeletedBecauseTheVaultLocked() {
        val file = File(record.copyOf())
        val saves = PendingSaves(file, InMemoryBlobs()) { true }
        assertFailsWith<AccountWipedException> { saves.unlocked(wipedAccount()) }
        assertEquals(0, file.deletes, "the record stays")
        assertContentEquals(record, file.bytes)
    }
}
