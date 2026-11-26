package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.RegisterRequest
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The old account line takes no key or seed of zeros out of anything (spec 01, "Keys in memory and the lock", rule 4),
 * and says each where it is taken out as what it is there: the account's key unwrapped with the password and the
 * identity seed opened under the account's key are damaged keys; the account's key a quick unlock is handed, or the
 * one a member's recovery copy opens to, does not open; an attachment's file key (any writer of a shared vault chooses
 * it) is a damaged item; a backup's file key is a damaged backup. Before, each was taken, and the next open, signature
 * or derivation under it was refused by the key floor as though the account were locked (or, for a file, decrypted
 * under it).
 */
class AccountZeroKeyTakeOutTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "made-up test password 24"

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String, provider: CryptoProvider = crypto): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", provider)
        val keys = AccountKeys(
            kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
            encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
            escrowFingerprint = reg.escrow!!.fingerprint,
        )
        return Enrolled(reg, account, keys)
    }

    /**
     * The test plays a party that holds the key [key] (the password's wrap key, the account's key, a recovery secret's
     * wrap key): an envelope under it whose plaintext is 32 zero bytes, built at the provider because the shared envelope
     * refuses to wrap a wiped key. The only function here that puts zeros through the provider.
     */
    private fun wrapOfZeros(key: ByteArray, ad: ByteArray): String {
        val nonce = crypto.randomBytes(Envelope.NONCE_BYTES)
        val ct = crypto.aeadEncrypt(key, nonce, ByteArray(32), ad)
        return Bytes.toB64(byteArrayOf(Envelope.VERSION, Envelope.ALG_XCHACHA20POLY1305_IETF) + nonce + ct)
    }

    private fun passwordWrapKey(keys: AccountKeys): ByteArray {
        val mk = Keys.masterKey(crypto, password, Bytes.fromB64(keys.kdfSalt), keys.kdfParams)
        return try { Keys.wrapKey(crypto, mk) } finally { mk.fill(0) }
    }

    // Building each hostile input below wraps 32 zero bytes at the provider, which the zero-key tripwire counts:
    // [wrapOfZeros] is the one place it lists as expected for this class. The account's own opens happen outside it and
    // record nothing. Each of the three fails on the code before the check (the floor's "locked" at the next open, or no
    // refusal).

    @Test fun aPasswordThatOpensAWrapOfZerosMeetsDamagedKeysNeverALock() {
        val e = enroll("zero-uvk@example.com")
        val wk = passwordWrapKey(e.keys)
        val hostile = e.keys.copy(wrappedUvk = wrapOfZeros(wk, Ad.uvk(e.reg.userId)))
        wk.fill(0)
        assertFailsWith<VaultKeyDamagedException> { Account.unlock(e.reg.userId, password, hostile, crypto) }
        // The honest wrap still opens with the same password.
        Account.unlock(e.reg.userId, password, e.keys, crypto).wipe()
    }

    @Test fun anIdentitySeedOfZerosUnderTheAccountsKeyIsDamagedKeysOnEveryUnlock() {
        val e = enroll("zero-seed@example.com")
        val uvk = e.account.uvkCopyForPlatformWrap()
        val hostile = e.keys.copy(encryptedIdentitySeed = wrapOfZeros(uvk, Ad.idkey(e.reg.userId)))
        assertFailsWith<VaultKeyDamagedException> { Account.unlockWithUvk(e.reg.userId, uvk.copyOf(), hostile, crypto) }
        assertFailsWith<VaultKeyDamagedException> { Account.unlock(e.reg.userId, password, hostile, crypto) }
        Account.unlockWithUvk(e.reg.userId, uvk, e.keys, crypto).wipe()
    }

    @Test fun aRecoveryCopyThatOpensToZerosRecoversNothing() {
        val e = enroll("zero-recovery@example.com")
        val secret = crypto.randomBytes(32)
        val wk = MemberRecovery.wrapKey(crypto, secret)
        val verify = RecoveryVerifyResponse(e.reg.userId, "ticket", wrapOfZeros(wk, Ad.recovery(e.reg.userId)), e.keys.encryptedIdentitySeed, e.keys.identityPub)
        wk.fill(0)
        val failed = assertFailsWith<CryptoException> { Account.recover(secret, verify, "a new master password 24", kdf, crypto) }
        assertTrue("all-zero" in failed.message.orEmpty(), "refused where the key is taken out: ${failed.message}")
    }

    /** No hostile input is built (a key of zeros is only handed over): on. On the code before, the floor's "locked". */
    @Test fun aQuickUnlockHandedAKeyOfZerosIsAnInvalidSecretNeverALock() {
        val e = enroll("zero-quick@example.com")
        val failed = assertFailsWith<CryptoException> { Account.unlockWithUvk(e.reg.userId, ByteArray(32), e.keys, crypto) }
        assertTrue("all-zero" in failed.message.orEmpty(), failed.message)
        // The real key still opens; one with a single non-zero byte is simply not this account's.
        val uvk = e.account.uvkCopyForPlatformWrap()
        Account.unlockWithUvk(e.reg.userId, uvk, e.keys, crypto).wipe()
        val near = ByteArray(32).also { it[31] = 1 }
        val other = assertFailsWith<CryptoException> { Account.unlockWithUvk(e.reg.userId, near, e.keys, crypto) }
        assertTrue("all-zero" !in other.message.orEmpty())
    }

    /** Counts every file decryption made through it. */
    private class Counting(val inner: CryptoProvider) : CryptoProvider by inner {
        var fileOpens = 0
        override fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray> {
            fileOpens++
            return inner.secretstreamDecrypt(key, header, chunks)
        }
    }

    private fun serving(body: ByteArray, account: Account): SyncEngine {
        val engine = MockEngine { _ -> respond(ByteReadChannel(body), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/octet-stream")) }
        return SyncEngine(AndvariApi("http://fake", HttpClient(engine), Tokens("a", "r")), account, InMemoryVaultCache())
    }

    /**
     * Spec 02 §6: a file key is a per-file random 32-byte key inside the item's ciphertext, so a writer of a shared vault
     * chooses it. One of zeros is refused as a damaged item, before anything is decrypted under it. No hostile input goes
     * through the provider (the key is only text in the reference): on.
     */
    @Test fun anAttachmentWhoseFileKeyIsZerosIsADamagedItemAndIsNeverDecrypted() = runBlocking<Unit> {
        val counting = Counting(crypto)
        val e = enroll("zero-file@example.com", counting)
        val plain = ByteArray(300) { it.toByte() }
        val key = crypto.randomBytes(32)
        val enc = Attachments.encrypt(crypto, key, plain.copyOf())
        val body = enc.header + enc.ciphertext
        val zeroRef = AttachmentRef(id = "att-1", name = "scan.pdf", size = plain.size.toLong(), fileKey = Bytes.toB64(ByteArray(32)))
        val failed = assertFailsWith<CryptoException> { serving(body, e.account).downloadAttachment(zeroRef) }
        assertTrue("all-zero" in failed.message.orEmpty(), failed.message)
        assertEquals(0, counting.fileOpens, "nothing was decrypted under a key of zeros")
        // The same file under its real key opens.
        val ref = zeroRef.copy(fileKey = Bytes.toB64(key))
        assertContentEquals(plain, serving(body, e.account).downloadAttachment(ref))
        assertEquals(1, counting.fileOpens)
        e.account.wipe()
    }

    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    /**
     * Spec 07 §2.4: the manifest's file keys are fresh random keys for the backup's own sections. A key of zeros, given
     * to the section reader or named by the manifest, is a damaged backup with the section's own code, never decrypted
     * under. On (the zeros are only a key handed over and manifest text).
     */
    @Test fun aBackupSectionReadUnderAFileKeyOfZerosIsADamagedBackup() {
        val key = crypto.randomBytes(32)
        val plain = ByteArray(64) { 9 }
        val passphrase = "zero file key passphrase"
        val payload = BackupPayload(
            exportedAt = 1L, userId = "11111111-1111-4111-8111-111111111111",
            attachments = listOf(BackupAttachmentEntry(1, "aaaa1111-0000-4000-8000-000000000001", "22222222-2222-4222-8222-222222222222", "a.bin", plain.size.toLong(), Bytes.toB64(ByteArray(32)))),
        )
        val bytes = ArrayList<Byte>()
        Backup.buildWithPayloadBytes(
            crypto, passphrase, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", crypto.randomBytes(16), KdfParams(ops = 1, memBytes = 8192),
            json.encodeToString(BackupPayload.serializer(), payload).encodeToByteArray(), listOf(Backup.AttachmentSection(key) { plain.copyOf() }), null,
        ) { chunk -> chunk.forEach { bytes += it } }
        val opened = Backup.open(crypto, passphrase, bytes.toByteArray())
        val bySection = assertFailsWith<BackupException> { opened.readAttachmentSection(1, ByteArray(32)) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, bySection.code)
        assertTrue("all-zero" in bySection.message.orEmpty(), bySection.message)
        val byManifest = assertFailsWith<BackupException> { opened.readAttachment(opened.payload.attachments.single()) }
        assertEquals(Backup.ERR_WRONG_PASSPHRASE_OR_CORRUPT, byManifest.code)
        assertTrue("all-zero" in byManifest.message.orEmpty(), byManifest.message)
        assertContentEquals(plain, opened.readAttachmentSection(1, key))
    }
}
