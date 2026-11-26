package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.app.content.ContentFillSnapshot
import io.silencelen.andvari.core.app.content.FillSnapshotOpener
import io.silencelen.andvari.core.app.content.FillSnapshotRead
import io.silencelen.andvari.core.app.content.FillSnapshotVault
import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.GenesisFields
import io.silencelen.andvari.core.trust.VerifiedGenesis
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame

/**
 * The opener that holds only the account's id and vault key ([VaultKeyReader]), for the iPhone's AutoFill extension: it
 * opens exactly what [OpenedAccount.sealUnderVaultKey] sealed for the same account and purpose, nothing else, and nothing
 * at all once wiped.
 */
class VaultKeyReaderTest {
    private val crypto = createCryptoProvider()
    private val uvk = ByteArray(32) { 1 }

    private fun account(userId: String = "u1", key: ByteArray = uvk, seedByte: Byte = 4): OpenedAccount {
        val seed = ByteArray(32) { seedByte }
        val identity = crypto.boxKeypairFromSeed(seed)
        val genesis = VerifiedGenesis(GenesisFields(userId, Bytes.toB64(identity.publicKey), "instance", "v-personal", 0), "00".repeat(32))
        return OpenedAccount(userId, key.copyOf(), identity, crypto.signKeypairFromSeed(seed), genesis, null, null)
    }

    private val snapshot = """{"logins":[{"host":"bank.example","user":"p"}]}""".encodeToByteArray()

    @Test fun aSealMadeByTheAccountOpens_andTheCallersKeyCanBeWipedAtOnce() {
        val sealed = account().sealUnderVaultKey(crypto, "fill-snapshot", snapshot)
        val mine = uvk.copyOf()
        val reader = VaultKeyReader("u1", mine)
        mine.fill(0)
        assertContentEquals(snapshot, reader.openUnderVaultKey(crypto, "fill-snapshot", sealed), "the key is copied")
        assertEquals("u1", reader.userId)
    }

    @Test fun anotherAccountPurposeOrKey_orADamagedSeal_answersNull() {
        val sealed = account().sealUnderVaultKey(crypto, "fill-snapshot", snapshot)
        val reader = VaultKeyReader("u1", uvk)
        assertNull(VaultKeyReader("u2", uvk).openUnderVaultKey(crypto, "fill-snapshot", sealed), "another account, same key")
        assertNull(reader.openUnderVaultKey(crypto, "kept-saves", sealed), "another purpose")
        assertNull(reader.openUnderVaultKey(crypto, "fill-snapshot", account().sealUnderVaultKey(crypto, "kept-saves", snapshot)), "a seal for another purpose, asked for as this one")
        assertNull(VaultKeyReader("u1", ByteArray(32) { 2 }).openUnderVaultKey(crypto, "fill-snapshot", sealed), "another key")
        assertNull(reader.openUnderVaultKey(crypto, "fill-snapshot", account(userId = "u2").sealUnderVaultKey(crypto, "fill-snapshot", snapshot)), "another account's seal")
        for (i in sealed.indices step 7) {
            val damaged = sealed.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
            assertNull(reader.openUnderVaultKey(crypto, "fill-snapshot", damaged), "damaged at $i")
        }
        assertNull(reader.openUnderVaultKey(crypto, "fill-snapshot", sealed.copyOf(sealed.size - 1)), "truncated")
        assertNull(reader.openUnderVaultKey(crypto, "fill-snapshot", ByteArray(3)), "not a seal")
        // The UVK itself is never the key: an envelope under the raw UVK with the very AD does not open.
        assertNull(reader.openUnderVaultKey(crypto, "fill-snapshot", Envelope.seal(crypto, uvk, snapshot, "andvari/v2|vault-key-seal|u1|fill-snapshot".encodeToByteArray())))
        for (bad in listOf("", "Fill", "fill|snapshot", "-x", "x".repeat(65))) assertNull(reader.openUnderVaultKey(crypto, bad, sealed), bad)
        // The identity key plays no part: the account with another identity but the same UVK reads the reader's input.
        assertContentEquals(snapshot, account(seedByte = 9).openUnderVaultKey(crypto, "fill-snapshot", sealed))
    }

    @Test fun afterTheWipe_itThrowsAsAWipedAccountDoes() {
        val sealed = account().sealUnderVaultKey(crypto, "fill-snapshot", snapshot)
        val reader = VaultKeyReader("u1", uvk)
        reader.wipe()
        assertFailsWith<AccountWipedException> { reader.openUnderVaultKey(crypto, "fill-snapshot", sealed) }
        assertFailsWith<AccountWipedException> { reader.openUnderVaultKey(crypto, "not|a purpose", sealed) }
        reader.wipe()
        assertContentEquals(ByteArray(32) { 1 }, uvk, "the caller's array is its own")
    }

    @Test fun aReaderIsBuiltOnlyFromAnAccountIdAndAWholeKey() {
        assertFailsWith<IllegalArgumentException> { VaultKeyReader("", uvk) }
        assertFailsWith<IllegalArgumentException> { VaultKeyReader("u1", ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { VaultKeyReader("u1", ByteArray(0)) }
    }

    /**
     * The content tests' `FillSnapshotTest.uvkOnly` helper, verbatim but for the rig: the reference the reader replaces.
     * Over every input that test gives it (the account's key or another, the account or another, the right purpose or
     * another, a damaged seal, an unsealed body) the reader answers exactly what the helper answers.
     */
    private fun referenceOpener(key: ByteArray, userId: String) = FillSnapshotOpener { purpose, bytes ->
        val k = Hkdf.sha256(crypto, key, ByteArray(0), "${OpenedAccount.VAULT_KEY_SEAL_INFO}$purpose".encodeToByteArray(), 32)
        try {
            runCatching { Envelope.open(crypto, k, bytes, "andvari/v2|vault-key-seal|$userId|$purpose".encodeToByteArray()) }.getOrNull()
        } finally {
            k.fill(0)
        }
    }

    private fun readerOpener(key: ByteArray, userId: String): FillSnapshotOpener {
        val reader = VaultKeyReader(userId, key)
        return FillSnapshotOpener { purpose, bytes -> reader.openUnderVaultKey(crypto, purpose, bytes) }
    }

    @Test fun itAnswersExactlyWhatTheReferenceOpenerAnswers_andOpensARealFillSnapshot() {
        val origin = "https://andvari.example.com"
        val plain = ContentFillSnapshot(origin = origin, userId = "u1", items = emptyList(), writtenAtMs = 1).encode()
        val sealed = account().sealUnderVaultKey(crypto, ContentFillSnapshot.PURPOSE, plain)
        val other = account().sealUnderVaultKey(crypto, "kept-saves", plain)
        val damaged = sealed.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        for (key in listOf(uvk, ByteArray(32) { 2 })) for (user in listOf("u1", "u2")) for (purpose in listOf(ContentFillSnapshot.PURPOSE, "kept-saves")) {
            for (bytes in listOf(sealed, other, damaged, plain)) {
                val want = referenceOpener(key, user).openUnderVaultKey(purpose, bytes)
                val got = readerOpener(key, user).openUnderVaultKey(purpose, bytes)
                if (want == null) assertNull(got, "$user/$purpose") else assertContentEquals(want, got, "$user/$purpose")
            }
        }
        assertIs<FillSnapshotRead.Opened>(FillSnapshotVault.readBytes(crypto, sealed, origin, "u1", readerOpener(uvk, "u1"))).vault.close()
        assertSame(FillSnapshotRead.Unreadable, FillSnapshotVault.readBytes(crypto, sealed, origin, "u2", readerOpener(uvk, "u2")))
        assertSame(FillSnapshotRead.Unreadable, FillSnapshotVault.readBytes(crypto, other, origin, "u1", readerOpener(uvk, "u1")))
        val wiped = VaultKeyReader("u1", uvk).also { it.wipe() }
        assertSame(FillSnapshotRead.Unreadable, FillSnapshotVault.readBytes(crypto, sealed, origin, "u1") { p, b -> wiped.openUnderVaultKey(crypto, p, b) })
    }
}
