package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import kotlin.test.assertIs

/** An account for tests: a fixed identity seed, its joint Ed25519 key and its X25519 identity key. */
internal class Party(crypto: CryptoProvider, val userId: String, seedByte: Int) {
    val seed: ByteArray = ByteArray(32) { (seedByte * 7 + it).toByte() }
    val sign: KeyPairBytes = crypto.signKeypairFromSeed(seed)
    val box: KeyPairBytes = crypto.boxKeypairFromSeed(seed)

    /** The identity key as `b64_32` text. */
    val key: String = Bytes.toB64(box.publicKey)
}

internal object Ids {
    const val ALICE = "11111111-1111-4111-8111-111111111111"
    const val BOB = "22222222-2222-4222-8222-222222222222"
    const val CAROL = "33333333-3333-4333-8333-333333333333"
    const val DAVE = "44444444-4444-4444-8444-444444444444"
    const val VAULT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    const val OTHER_VAULT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    const val INSTANCE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    const val OTHER_INSTANCE = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    const val T0 = 1_763_164_800_000L

    /** A 16-byte id as `b64_16` text, distinct per [n]. */
    fun id16(n: Int): String = Bytes.toB64(ByteArray(16) { (n * 16 + it).toByte() })
}

/**
 * Builds a real log for tests, one signed and VERIFIED entry at a time: every frame goes through
 * [VaultLog.signChecked], so a test can only extend a chain the verifier accepts.
 */
internal class LogBuilder(private val crypto: CryptoProvider, val vaultId: String = Ids.VAULT) {
    var state: VaultState? = null
        private set
    val frames = ArrayList<ByteArray>()
    var clock: Long = Ids.T0

    /** The key every vault in these tests uses. */
    val vk: ByteArray = ByteArray(32) { (0x40 + it).toByte() }

    fun genesis(owner: Party): VaultLogStep =
        commit(owner, LogEntry.Genesis(vaultId, owner.userId, clock, owner.key, VaultLog.vkCommit(crypto, vk, vaultId)))

    fun append(by: Party, make: (LogPosition) -> LogEntry): VaultLogStep {
        clock += 1_000
        return commit(by, make(VaultLog.position(state!!, clock)))
    }

    fun add(owner: Party, member: Party, grantId: String, role: MemberRole = MemberRole.WRITER): VaultLogStep =
        append(owner) { LogEntry.Add(vaultId, it.seq, it.prev, owner.userId, it.at, member.userId, member.key, role, grantId) }

    fun remove(owner: Party, member: Party): VaultLogStep =
        append(owner) { LogEntry.Remove(vaultId, it.seq, it.prev, owner.userId, it.at, member.userId) }

    fun leave(member: Party): VaultLogStep =
        append(member) { LogEntry.Leave(vaultId, it.seq, it.prev, member.userId, it.at) }

    /** The owner offers ownership to [to], who accepts: two entries. */
    fun transfer(owner: Party, to: Party, offerId: String) {
        append(owner) { LogEntry.Offer(vaultId, it.seq, it.prev, owner.userId, it.at, to.userId, to.key, offerId, it.at + 60_000) }
        append(to) { LogEntry.Accept(vaultId, it.seq, it.prev, to.userId, it.at, offerId) }
    }

    private fun commit(by: Party, entry: LogEntry): VaultLogStep {
        val signed = assertIs<Checked.Ok<SignedLogEntry>>(VaultLog.signChecked(crypto, by.sign, state, entry), "the builder signs only what verifies").value
        frames += signed.frame
        state = signed.step.state
        return signed.step
    }
}
