package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The old account line's signed grant (spec 01, "Keys in memory and the lock"): a grant made and signed by a pinned
 * owner that carries a vault key of 32 zero bytes is refused as a bad key (`bad_vk`), never adopted. Before, it was
 * adopted, and every later open under it was refused by the key floor as though the account were locked: a refusal made
 * from data. Every other key still opens, among them keys with a single non-zero byte at either end.
 */
class SignedGrantZeroKeyTest {
    private val crypto = createCryptoProvider()
    private val ownerSeed = ByteArray(32) { (it + 1).toByte() }
    private val memberSeed = ByteArray(32) { (it + 101).toByte() }
    private val ownerId = "11111111-1111-4111-8111-111111111111"
    private val memberId = "22222222-2222-4222-8222-222222222222"
    private val vaultId = "33333333-3333-4333-8333-333333333333"

    /**
     * The owner's side: a grant of [vk] to the member, signed and sealed as a pinned owner makes one, whatever key it
     * carries. Sealing a frame whose `vk` is 32 zero bytes is what the zero-key tripwire counts at the provider, and this
     * function is the one place it lists as expected for this class. The member's open happens outside it, in
     * [grantFor], so a line from the code under test still fails the run.
     */
    private fun sealedByTheOwner(memberPublicKey: ByteArray, vk: ByteArray): ByteArray {
        val signer = crypto.signKeypairFromSeed(ownerSeed)
        val frame = SignedGrant.buildFrame(crypto, signer, Statement.VaultGrant(
            from = ownerId, to = memberId, toKey = memberPublicKey, vaultId = vaultId,
            grantId = ByteArray(16) { it.toByte() }, issuedAt = 1_791_590_400_000L, vk = vk,
        ))
        return SignedGrant.seal(crypto, memberPublicKey, frame)
    }

    private fun grantFor(vk: ByteArray): GrantOutcome {
        val ownerPub = crypto.boxKeypairFromSeed(ownerSeed).publicKey
        val me = crypto.boxKeypairFromSeed(memberSeed)
        val sealed = sealedByTheOwner(me.publicKey, vk)
        return SignedGrant.open(crypto, memberId, me.publicKey, me.privateKey, vaultId, sealed,
            pinFor = { uid -> if (uid == ownerId) GrantPin(ownerPub, current = true) else null }, heldVk = null)
    }

    /** Fails on the code before the check: the key was adopted. The member's own open records nothing at the tripwire. */
    @Test fun aSignedGrantFromAPinnedOwnerCarryingAZeroVaultKeyIsRefusedAsABadKey() {
        val outcome = assertIs<GrantOutcome.Refused>(grantFor(ByteArray(32)))
        assertEquals(GrantVerdict.BAD_VK, outcome.verdict)
    }

    @Test fun everyNonZeroVaultKeyStillOpens() {
        val keys = listOf(
            ByteArray(32).also { it[0] = 1 },
            ByteArray(32).also { it[31] = 1 },
            ByteArray(32) { 0xFF.toByte() },
            crypto.randomBytes(32).also { it[0] = (it[0].toInt() or 1).toByte() },
        )
        for (vk in keys) {
            val adopted = assertIs<GrantOutcome.Adopted>(grantFor(vk), Bytes.toB64(vk))
            assertContentEquals(vk, adopted.vk)
            assertEquals(ownerId, adopted.from)
        }
    }
}
