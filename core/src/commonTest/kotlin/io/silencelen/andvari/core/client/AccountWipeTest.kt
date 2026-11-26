package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Survey gap 7: [Account.wipe] zeroes the keys an account holds (a lock no longer leaves them to the collector),
 * and a wiped account seals, signs and copies out nothing, so an operation still running when its session ended
 * cannot produce anything from a zeroed key.
 */
class AccountWipeTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)

    private fun enroll(): EnrollResult =
        Account.enroll("inv", "w@example.com", "w", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fingerprint, "dev", crypto)

    private fun keysOf(e: EnrollResult) = AccountKeys(
        kdfSalt = e.request.kdfSalt, kdfParams = e.request.kdfParams, wrappedUvk = e.request.wrappedUvk,
        encryptedIdentitySeed = e.request.encryptedIdentitySeed, identityPub = e.request.identityPub,
        escrowFingerprint = e.request.escrow!!.fingerprint,
    )

    private fun ByteArray.isZero() = all { it == 0.toByte() }

    @Test
    fun aWipeZeroesTheUvkTheAccountTookInPlace() {
        val e = enroll()
        val uvk = e.account.uvkCopyForPlatformWrap()
        val before = uvk.copyOf()
        val account = Account.unlockWithUvk(e.request.userId, uvk, keysOf(e), crypto) // the account takes this array
        assertFalse(account.isWiped)
        account.wipe()
        assertTrue(account.isWiped)
        assertTrue(uvk.isZero(), "the UVK is zeroed where it lives, not left to the collector")
        assertFalse(before.isZero(), "a copy taken before the wipe was the caller's")
        account.wipe() // idempotent
        assertTrue(account.isWiped)
    }

    @Test
    fun aWipedAccountSealsSignsAndCopiesNothing() {
        val a = enroll().account
        val vaultId = a.personalVaultId
        val doc = ItemDoc(type = "login", name = "x")
        a.encryptItem(vaultId, "item-1", doc) // it seals while live
        val member = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        a.wipe()
        val refused = listOf<Pair<String, () -> Any>>(
            "the UVK copy for a platform wrap" to { a.uvkCopyForPlatformWrap() },
            "an item seal" to { a.encryptItem(vaultId, "item-2", doc) },
            "the usage ledger seal" to { a.sealUsage(byteArrayOf(1, 2, 3)) },
            "the account-state seal" to { a.sealAccountState(AccountStateDoc(userId = a.userId, seq = 1)) },
            "a new shared vault's wrap" to { a.buildCreateSharedVault("shared") },
            "a member's key seal" to { a.wrapVkForMember(member, vaultId) },
            "a lifecycle key" to { a.lifecycleKeyFor(vaultId) },
            "an owner wrap" to { a.buildOwnerWrap(vaultId) },
            "a personal wrap" to { a.buildPersonalWrap(vaultId) },
            "a rename" to { a.buildRenameMeta(vaultId, "", "renamed") },
            "a recovery piece over the UVK" to { a.setupMemberRecovery("auth") },
            "an escrow re-seal of the UVK" to { a.resealEscrowFor(Bytes.toB64(recovery.publicKey), fingerprint) },
        )
        for ((what, call) in refused) {
            assertFailsWith<AccountWipedException>(what) { call() }
        }
    }

    /**
     * The old account line (what the iPhone app and the released apps run on) also refuses every use
     * that only READS a key once wiped. Before, each of these ran under the zeros: an open failed as damaged data (a grant
     * row marked unreadable, the personal vault UNREADABLE, a name or ledger read as missing), the password proof said
     * "wrong password", and a held key's tag was the tag of zeros. Each is built while live and asked after the wipe; the
     * account's own state is unchanged by the refused call.
     */
    @Test
    fun aWipedAccountOpensComparesAndTagsNothing() {
        val e = enroll()
        val a = e.account
        val personal = a.personalVaultId
        val shared = a.buildCreateSharedVault("shared")
        val grant = io.silencelen.andvari.core.model.WireGrant(shared.vaultId, a.userId, "owner", shared.request.wrappedVk, 1)
        val accountState = a.sealAccountState(AccountStateDoc(userId = a.userId, seq = 1))
        val usage = a.sealUsage(byteArrayOf(1, 2, 3))
        val wrap = a.buildPersonalWrap(personal)
        val keys = keysOf(e)
        val status = a.personalStatus
        a.wipe()
        val refused = listOf<Pair<String, () -> Any?>>(
            "a grant row" to { a.addGrant(grant) },
            "a held vault's name from its row" to { a.peekVaultName(grant, shared.request.metaBlob) },
            "a vault's name" to { a.decryptVaultName(shared.vaultId, shared.request.metaBlob) },
            "a vault's meta" to { a.decryptVaultMeta(shared.vaultId, shared.request.metaBlob) },
            "the account state" to { a.openAccountState(accountState) },
            "the usage ledger" to { a.openUsage(usage) },
            "the personal wrap" to { a.applyPersonalWrap(wrap) },
            "a cached personal wrap" to { a.applyCachedPersonalWrap(wrap) },
            "a personal-vault change held" to { a.holdPersonalChange(wrap) },
            "a designated personal wrap" to { a.installDesignatedPersonalWrap(wrap) },
            "the password proof" to { a.verifyPassword("pw", keys) },
            "the reauthentication key" to { a.reauthAuthKey("pw", keys) },
            "a held key's tag" to { a.legacyKeyTag(shared.vaultId) },
        )
        for ((what, call) in refused) {
            assertFailsWith<AccountWipedException>(what) { call() }
        }
        assertEquals(status, a.personalStatus, "a refused wrap changed nothing")
        assertFalse(a.keyUnreadable(shared.vaultId), "a refused row is not marked unreadable")
    }

    @Test
    fun aPasswordUnlockWhoseAccountDoesNotOpenZeroesWhatItOpened() {
        // Review 3: the opened UVK is the call's until an account takes it; here none does (an identity mismatch).
        val e = enroll()
        val opened = mutableListOf<ByteArray>()
        val spy = object : io.silencelen.andvari.core.crypto.CryptoProvider by crypto {
            override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray =
                crypto.aeadDecrypt(key, nonce, ciphertext, ad).also { opened += it }
        }
        val stranger = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        val keys = keysOf(e).copy(identityPub = Bytes.toB64(stranger))
        assertFailsWith<io.silencelen.andvari.core.crypto.CryptoException> { Account.unlock(e.request.userId, "pw", keys, spy) }
        assertTrue(opened.size >= 2, "the UVK and the identity seed were opened")
        assertTrue(opened.all { it.isZero() }, "and both are zeroed")
    }

    @Test
    fun theRefusalIsNotReadAsAWrongPassword() {
        // The save ladders read a CryptoException as "wrong master password"; a session that ended is not that.
        val e: Throwable = AccountWipedException()
        assertFalse(e is io.silencelen.andvari.core.crypto.CryptoException)
        assertTrue(e is IllegalStateException)
    }
}
