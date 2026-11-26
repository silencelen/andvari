package io.silencelen.andvari.core.client.session

/**
 * A [PlatformKeyWrap] for tests: a key per slot in memory, "sealing" by XOR with it and binding the AAD. Each prompt
 * is counted in [prompts], and [next] scripts what the next prompt answers.
 */
class TestKeyWrap : PlatformKeyWrap {
    enum class Next { OK, CANCEL, REFUSE, INVALIDATED, FAIL }

    var biometric = true
    var next = Next.OK
    var prompts = 0
    val keys = HashMap<String, ByteArray>()
    private val aads = HashMap<String, String>()
    val destroyed = ArrayList<String>()

    override fun strongBiometric(): Boolean = biometric

    /** When set, the next consent prompt stays up until it completes: what a test does while the prompt is on screen. */
    var promptUp: kotlinx.coroutines.CompletableDeferred<Unit>? = null

    /** When true, the next prepared seal fails (the authorisation lapsed, or the key was invalidated during the prompt). */
    var sealFails = false

    /** Every secret a seal was lent, as the very array: a test checks none was zeroed or kept past the use. */
    val lent = ArrayList<ByteArray>()
    var prepared = 0
    var discarded = 0

    private var made = 0

    override suspend fun prepare(slot: String, aad: ByteArray): KeyWrapPrepare {
        prompts++
        val n = next.also { next = Next.OK }
        // A fresh key for the slot first (replacing any it had), then the prompt, as the platforms do.
        val key = ByteArray(32) { (it * 31 + slot.length + 7 + made).toByte() }
        made++
        keys[slot] = key
        aads[slot] = aad.decodeToString()
        promptUp?.let { up -> promptUp = null; up.await() }
        return when (n) {
            Next.CANCEL -> KeyWrapPrepare.Cancelled
            Next.FAIL, Next.REFUSE, Next.INVALIDATED -> KeyWrapPrepare.Failed
            Next.OK -> {
                prepared++
                val fails = sealFails.also { sealFails = false }
                KeyWrapPrepare.Prepared(object : KeyWrapPrepared {
                    private var used = false

                    override fun seal(secret: ByteArray): ByteArray? {
                        if (used) return null
                        used = true
                        lent += secret
                        if (fails) return null
                        return ByteArray(secret.size) { (secret[it].toInt() xor key[it % key.size].toInt()).toByte() }
                    }

                    override fun discard() {
                        if (!used) discarded++
                        used = true
                    }
                })
            }
        }
    }

    /** When set, the next opening prompt stays up until it completes: what a test does while that prompt is on screen. */
    var openUp: kotlinx.coroutines.CompletableDeferred<Unit>? = null

    /** Every secret an opening released, as the very array handed over: a test checks the receiver wiped it. */
    val released = ArrayList<ByteArray>()

    /** What each confirmation prompt ([openToConfirm]) was asked to say. */
    val reasons = ArrayList<String?>()

    /** How many prompts were confirmation prompts rather than unlocks. */
    var confirmPrompts = 0

    override suspend fun open(slot: String, sealed: ByteArray, aad: ByteArray): KeyWrapOpen {
        prompts++
        val n = next.also { next = Next.OK }
        openUp?.let { up -> openUp = null; up.await() }
        return when (n) {
            Next.CANCEL -> KeyWrapOpen.Cancelled
            Next.REFUSE, Next.FAIL -> KeyWrapOpen.Refused
            Next.INVALIDATED -> KeyWrapOpen.Invalidated
            Next.OK -> {
                val key = keys[slot] ?: return KeyWrapOpen.Invalidated
                if (aads[slot] != aad.decodeToString() || key.size != sealed.size) return KeyWrapOpen.Invalidated
                val secret = ByteArray(sealed.size) { (sealed[it].toInt() xor key[it % key.size].toInt()).toByte() }
                released += secret
                KeyWrapOpen.Opened(secret)
            }
        }
    }

    override suspend fun openToConfirm(slot: String, sealed: ByteArray, aad: ByteArray, reason: String?): KeyWrapOpen {
        confirmPrompts++
        reasons += reason
        return open(slot, sealed, aad)
    }

    /** Seal [secret] under [slot]'s current key as [prepare]'s sealer would: a test's own record, for a key of its choosing. */
    fun sealWith(slot: String, secret: ByteArray): ByteArray {
        val key = keys.getValue(slot)
        return ByteArray(secret.size) { (secret[it].toInt() xor key[it % key.size].toInt()).toByte() }
    }

    override fun destroy(slot: String) {
        keys.remove(slot)
        aads.remove(slot)
        destroyed += slot
    }
}

/** [Clocks] a test moves by hand. */
class TestClocks(var wall: Long = 1_794_744_000_000L, var mono: Long = 5_000_000L, var boot: String? = "boot-1") : Clocks {
    override fun wallMs(): Long = wall
    override fun monotonicMs(): Long = mono
    override fun bootId(): String? = boot

    fun advance(ms: Long) {
        wall += ms
        mono += ms
    }
}
