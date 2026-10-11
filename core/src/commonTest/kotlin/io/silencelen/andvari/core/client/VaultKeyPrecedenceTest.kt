package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Canonical-key precedence (security review 2026-10, root cause A, §3.1). The sync server is
 * hostile: it can attach any blob to any grant row. A `sealedVk` is `crypto_box_seal` to our
 * PUBLIC identity key, so the server can mint one around a key it chose. A `wrappedVk` opens only
 * under our own UVK, so it is the only evidence of which key is really ours.
 *
 * Before this row, `addGrant` opened the seal whenever one was present, even on a row that also
 * carried our own wrap, so a server that added a forged seal to the owner's shared-vault row had
 * the client adopt the server's key on the next cold start (every new write then sealed under a
 * key the server holds). These cases pin the rule: the UVK wrap wins, a different seal is an
 * anomaly, and a damaged wrap never falls back to a seal.
 */
class VaultKeyPrecedenceTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id
    private val password = "correct horse battery staple"

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint,
            ),
        )
    }

    private fun freshDevice(e: Enrolled) = Account.unlock(e.reg.userId, password, e.keys, crypto)

    /** What the hostile server mints: a well-formed v1 seal to the victim's public key around a VK it chose. */
    private fun forgedSeal(victim: Enrolled, vaultId: String, serverVk: ByteArray): String =
        Bytes.toB64(SharedGrant.seal(crypto, victim.account.identityPub, vaultId, serverVk))

    /** Flip one ciphertext byte: still a well-formed envelope, but its AEAD tag no longer verifies. */
    private fun tamper(b64: String): String {
        val raw = Bytes.fromB64(b64)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
        return Bytes.toB64(raw)
    }

    @Test
    fun aForgedSealOnTheOwnersOwnRowNeverDisplacesTheUvkWrappedKey() {
        val owner = enroll("owner@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val serverVk = crypto.randomBytes(32)

        // THE EXPLOIT (review A-1/A-4): the owner's own row, our wrap intact, plus a seal the server minted.
        val row = WireGrant(
            vaultId = shared.vaultId, userId = owner.reg.userId, role = "owner",
            wrappedVk = shared.request.wrappedVk, rev = 2,
            sealedVk = forgedSeal(owner, shared.vaultId, serverVk),
        )
        val device = freshDevice(owner) // a cold start: nothing held, the row decides
        device.addGrant(row)

        assertTrue(device.hasVault(shared.vaultId))
        // The held key is OUR key: the genuine metaBlob (sealed under the real VK) still opens.
        assertEquals("Household", device.decryptVaultName(shared.vaultId, shared.request.metaBlob))
        // And a new write is NOT sealed under the server's key.
        val itemId = device.newItemId()
        val upload = device.encryptItem(shared.vaultId, itemId, ItemDoc(type = "login", name = "x"))
        assertTrue(
            runCatching { Envelope.openB64(crypto, serverVk, upload.blob, Ad.item(shared.vaultId, itemId, upload.formatVersion)) }.isFailure,
            "new writes must never be sealed under a server-chosen key",
        )
        // The swap is surfaced, not swallowed.
        assertTrue(device.vkMismatch(shared.vaultId), "a seal that opens to a different VK is a 'vault key mismatch' anomaly")
        // Provenance: a row that carries ANY seal is a shared vault, never a personal candidate (H64).
        assertTrue(device.keyArrivedByMemberGrant(shared.vaultId))
    }

    @Test
    fun aForgedSealOnThePersonalRowIsRefusedAndTheVaultStaysPersonal() {
        val victim = enroll("personal@example.com")
        val pv = victim.reg.personalVault.vaultId
        val row = WireGrant(
            vaultId = pv, userId = victim.reg.userId, role = "owner", wrappedVk = victim.reg.personalVault.wrappedVk,
            rev = 1, sealedVk = forgedSeal(victim, pv, crypto.randomBytes(32)),
        )
        val device = freshDevice(victim)
        device.addGrant(row)
        assertTrue(device.decryptVaultName(pv, victim.reg.personalVault.metaBlob) != null, "the genuine personal VK is held")
        assertTrue(device.vkMismatch(pv))
    }

    @Test
    fun aMatchingSealIsSilentAndAnUnopenableSealIsIgnored() {
        val owner = enroll("quiet@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        // The enrolling Account holds the genuine VK, so its self-seal is the honest "same key" seal.
        val sameSeal = owner.account.wrapVkForMember(owner.account.identityPub, shared.vaultId)

        val matching = freshDevice(owner)
        matching.addGrant(
            WireGrant(shared.vaultId, owner.reg.userId, "owner", shared.request.wrappedVk, 2, sameSeal),
        )
        assertTrue(matching.hasVault(shared.vaultId))
        assertFalse(matching.vkMismatch(shared.vaultId), "the same VK in both forms is the honest post-transfer row")

        // A seal for a DIFFERENT identity (an honest post-transfer row can retain one) does not open: ignored.
        val stranger = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val foreign = Bytes.toB64(SharedGrant.seal(crypto, stranger.publicKey, shared.vaultId, crypto.randomBytes(32)))
        val ignoring = freshDevice(owner)
        ignoring.addGrant(WireGrant(shared.vaultId, owner.reg.userId, "owner", shared.request.wrappedVk, 2, foreign))
        assertEquals("Household", ignoring.decryptVaultName(shared.vaultId, shared.request.metaBlob))
        assertFalse(ignoring.vkMismatch(shared.vaultId))
    }

    @Test
    fun aDamagedWrapNeverFallsBackToASeal() {
        val owner = enroll("damaged@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val serverVk = crypto.randomBytes(32)
        val row = WireGrant(
            shared.vaultId, owner.reg.userId, "owner",
            wrappedVk = tamper(shared.request.wrappedVk), rev = 2,
            sealedVk = forgedSeal(owner, shared.vaultId, serverVk),
        )
        val device = freshDevice(owner)
        assertFailsWith<VaultGrantKeyUnreadableException> { device.addGrant(row) }
        assertFalse(device.hasVault(shared.vaultId), "a damaged wrap must not fall back to a (server-mintable) seal")
        assertTrue(device.keyUnreadable(shared.vaultId), "the vault shows as 'key unreadable — tell your admin'")

        // A structurally broken wrap (not even base64url) is the same terminal state.
        val device2 = freshDevice(owner)
        assertFailsWith<VaultGrantKeyUnreadableException> {
            device2.addGrant(row.copy(wrappedVk = "!!not-base64!!"))
        }
        assertFalse(device2.hasVault(shared.vaultId))
    }

    @Test
    fun peekVaultNameFollowsTheSamePrecedence() {
        val owner = enroll("peek@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val serverVk = crypto.randomBytes(32)
        val serverMeta = Envelope.sealB64(crypto, serverVk, """{"name":"Server's choice"}""".encodeToByteArray(), Ad.vaultMeta(shared.vaultId))
        val row = WireGrant(shared.vaultId, owner.reg.userId, "owner", shared.request.wrappedVk, 2, forgedSeal(owner, shared.vaultId, serverVk))
        val device = freshDevice(owner)

        assertEquals("Household", device.peekVaultName(row, shared.request.metaBlob))
        assertNull(device.peekVaultName(row, serverMeta), "a blob under the server's key must not open through the seal")
        assertNull(device.peekVaultName(row.copy(wrappedVk = tamper(row.wrappedVk)), serverMeta), "no seal fallback on a damaged wrap")
        assertFalse(device.hasVault(shared.vaultId), "peek never admits the key")
    }

    @Test
    fun memberSelfWrapRoundTripsAndASecondDeviceReadsTheKeyFromTheWrap() {
        val owner = enroll("sw-owner@example.com")
        val member = enroll("sw-member@example.com")
        val shared = owner.account.buildCreateSharedVault("Household")
        val seal = owner.account.wrapVkForMember(member.account.identityPub, shared.vaultId)
        val memberRow = WireGrant(shared.vaultId, member.reg.userId, "writer", "", 4, seal)

        val first = freshDevice(member)
        first.addGrant(memberRow)
        assertTrue(first.needsSelfWrap(memberRow), "a key adopted from a seal with no wrap on the row needs a self-wrap")
        // A6: but a v1-seal key is never wrapped until this device vouches for it (§8.2 freeze or the human's Accept).
        assertFalse(first.selfWrapAuthorized(shared.vaultId))
        assertFailsWith<VaultKeyNotVerifiedException> { first.buildSelfWrap(shared.vaultId) }
        first.authorizeLegacyKey(shared.vaultId)
        val selfWrap = first.buildSelfWrap(shared.vaultId)
        assertFalse(first.needsSelfWrap(memberRow.copy(wrappedVk = selfWrap)), "once the wrap is on the row it is not posted again")

        // The second device: the server now serves the self-wrap, and the seal is ABSENT.
        val second = freshDevice(member)
        val wrappedOnly = memberRow.copy(wrappedVk = selfWrap, sealedVk = null, rev = 5)
        second.addGrant(wrappedOnly)
        assertEquals("Household", second.decryptVaultName(shared.vaultId, shared.request.metaBlob))
        assertFalse(second.needsSelfWrap(wrappedOnly))
        // H64 still holds without the seal: a non-owner row is a shared vault. Since root cause A §4 (A5)
        // "personal" comes only from the personal wrap, so nothing here can make it personal.
        assertTrue(second.keyArrivedByMemberGrant(shared.vaultId))
        assertEquals("", second.personalVaultId)

        // And the seal is no longer load-bearing: with both present, a swapped seal changes nothing.
        val third = freshDevice(member)
        third.addGrant(memberRow.copy(wrappedVk = selfWrap, sealedVk = forgedSeal(member, shared.vaultId, crypto.randomBytes(32))))
        assertEquals("Household", third.decryptVaultName(shared.vaultId, shared.request.metaBlob))
        assertTrue(third.vkMismatch(shared.vaultId))

        // Another member's wrap is not ours: it fails its AEAD under our UVK, so it is unreadable, not a fallback.
        val other = enroll("sw-other@example.com")
        val otherDevice = freshDevice(other)
        val otherSeal = owner.account.wrapVkForMember(other.account.identityPub, shared.vaultId)
        assertFailsWith<VaultGrantKeyUnreadableException> {
            otherDevice.addGrant(WireGrant(shared.vaultId, other.reg.userId, "writer", selfWrap, 6, otherSeal))
        }
    }
}
