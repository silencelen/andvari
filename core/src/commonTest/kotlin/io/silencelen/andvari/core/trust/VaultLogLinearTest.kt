package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.TimeSource

/**
 * A replay costs one step per entry. It used to copy
 * the member map and the list of adds for every entry, so a log of n adds cost n squared: 8,000 adds
 * took seconds, and the list of adds never shrank, so add and leave cycles grew every member's stored
 * state for good.
 *
 * The signature check is stubbed out for this class ONLY, and the map from a signer key to its X25519
 * image is computed once per key and remembered. Both cost the same for every entry, so they add
 * nothing to the question asked here (how the cost grows with the log) and would drown the answer;
 * every other check, the hashing and the state transitions are the real ones. Nothing here asserts
 * seconds: two sizes are compared.
 */
class VaultLogLinearTest {
    private val real = createCryptoProvider()
    private val crypto = object : CryptoProvider by real {
        private val images = HashMap<String, ByteArray>()

        override fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean = true

        override fun ed25519PkToCurve25519(ed25519PublicKey: ByteArray): ByteArray =
            images.getOrPut(Bytes.toHexLower(ed25519PublicKey)) { real.ed25519PkToCurve25519(ed25519PublicKey) }.copyOf()
    }
    private val owner = Party(real, Ids.ALICE, 1)

    private fun uuid(n: Int): String = "00000000-0000-4000-8000-" + n.toString(16).padStart(12, '0')

    private fun replay(frames: List<ByteArray>, from: VaultState? = null): VaultLogReplay =
        VaultLog.replay(crypto, Ids.VAULT, frames, from, KnownHashes.NONE_HELD)

    private fun verify(prior: VaultState?, frame: ByteArray) = VaultLog.verify(crypto, Ids.VAULT, prior, frame, KnownHashes.NONE_HELD)

    /** A log under one key pair: every entry carries that signer, and each member is given that same key, so a `leave` binds too. */
    private inner class Log {
        val frames = ArrayList<ByteArray>()
        private var prev = TrustGrammar.ZERO_HASH

        init {
            push("genesis", mapOf("actor" to Ids.ALICE, "ownerKey" to owner.key, "vkCommit" to "ab".repeat(32)))
        }

        private fun push(kind: String, fields: Map<String, String>) {
            val head = mapOf("vaultId" to Ids.VAULT, "seq" to frames.size.toString(), "prev" to prev, "kind" to kind, "at" to Ids.T0.toString())
            val statement = StatementCodec.encode(TrustPurpose.VAULT_LOG, head + fields, kind)
            val frame = SignedFrame.MAGIC + byteArrayOf(0x03) + owner.sign.publicKey + ByteArray(64) + statement
            frames += frame
            prev = SignedFrame.hash(real, frame)
        }

        fun add(member: String): Log = apply {
            push("add", mapOf("actor" to Ids.ALICE, "member" to member, "memberKey" to owner.key, "role" to "reader", "grantId" to Ids.id16(1)))
        }

        fun leave(member: String): Log = apply { push("leave", mapOf("actor" to member)) }

        fun remove(member: String): Log = apply { push("remove", mapOf("actor" to Ids.ALICE, "member" to member)) }
    }

    /** The fastest of [runs] replays of [frames], in nanoseconds; each must verify every frame. */
    private fun replayNanos(frames: List<ByteArray>, runs: Int): Long {
        var best = Long.MAX_VALUE
        repeat(runs) {
            val mark = TimeSource.Monotonic.markNow()
            val result = replay(frames)
            best = minOf(best, mark.elapsedNow().inWholeNanoseconds)
            assertNull(result.verdict)
            assertEquals(frames.size, result.accepted)
        }
        return best
    }

    @Test
    fun twentyThousandEntries_replayInTimeThatGrowsWithTheLog_notWithItsSquare() {
        val small = Log().also { for (i in 1..2_000) it.add(uuid(i)) }
        val big = Log().also { for (i in 1..20_000) it.add(uuid(i)) }
        replayNanos(small.frames, 3) // warm up
        replayNanos(big.frames, 1)
        val smallNs = replayNanos(small.frames, 5)
        val bigNs = replayNanos(big.frames, 3)
        // Ten times the entries: about ten times the work when a replay is linear, about a hundred when
        // every entry copies the state. The bound sits between the two with room on each side.
        assertTrue(bigNs < 30 * smallNs, "2,000 entries in ${smallNs / 1_000} us, 20,000 in ${bigNs / 1_000} us")

        val state = assertNotNull(replay(big.frames).state)
        assertEquals(20_001, state.members.size)
        assertEquals(20_000L, state.latestAdd(uuid(20_000))?.seq)
    }

    @Test
    fun addAndLeaveCycles_doNotGrowTheState() {
        val log = Log()
        val member = uuid(1)
        repeat(2_000) { log.add(member).leave(member) }
        log.add(member).add(uuid(2)).remove(uuid(2))
        val state = assertNotNull(replay(log.frames).state)
        assertEquals(4_003L, state.head.seq)
        assertEquals(setOf(member, uuid(2)), state.latestAdds.keys)
        assertEquals(4_001L, state.latestAdd(member)?.seq, "the latest add, not the first")
        assertEquals(4_001L, state.members.getValue(member).addSeq)
        assertEquals(4_002L, state.latestAdd(uuid(2))?.seq, "kept for an account that was removed: its grant answers `removed`")
        assertEquals(setOf(Ids.ALICE, member), state.members.keys)
        val stored = state.encode()
        assertTrue(stored.length < 2_000, "the stored state does not grow with the log: ${stored.length} characters")
        assertEquals(state, VaultState.decode(stored))
    }

    @Test
    fun aReplayAndEntryByEntryVerification_reachTheSameState_andARefusedFrameChangesNothing() {
        val log = Log()
        for (i in 1..40) {
            log.add(uuid(i))
            if (i % 3 == 0) log.remove(uuid(i))
            if (i % 5 == 0 && (i - 1) % 3 != 0) log.leave(uuid(i - 1)) // a member that is still one
        }
        var state: VaultState? = null
        for (frame in log.frames) state = assertIs<Checked.Ok<VaultLogStep>>(verify(state, frame)).value.state
        val whole = replay(log.frames)
        assertEquals(state, whole.state)
        assertEquals(state?.encode()?.let { VaultState.decode(it) }, whole.state)

        // The same frames with one that does not belong: the state is the one after the last good entry,
        // and it is the state a replay of only the good entries gives.
        val cut = 25
        val broken = log.frames.take(cut) + listOf(log.frames[cut + 1]) + log.frames.drop(cut + 1)
        val partial = replay(broken)
        assertEquals(cut, partial.accepted)
        assertEquals(VaultLogVerdict.BAD_SEQ, partial.verdict)
        assertEquals(replay(log.frames.take(cut)).state, partial.state)

        // Replaying on from a state leaves that state as it was.
        val from = assertNotNull(replay(log.frames.take(cut)).state)
        val before = from.encode()
        assertEquals(whole.state, replay(log.frames.drop(cut), from).state)
        assertEquals(before, from.encode())
        // A single verified step does not touch the state it was judged against either.
        assertIs<Checked.Ok<VaultLogStep>>(verify(from, log.frames[cut]))
        assertEquals(before, from.encode())
        // Nothing applied: the very state that was given comes back.
        assertSame(from, replay(listOf(log.frames[0]), from).state)
    }
}
