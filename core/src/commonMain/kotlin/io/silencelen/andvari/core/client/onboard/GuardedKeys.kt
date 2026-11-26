package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.crypto.KeyPairBytes
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlin.concurrent.Volatile

/**
 * The one guard over an opened account's keys (spec 01 §8: keys live in memory only
 * and end with the session). Every use of a key takes the guard, checks the keys are not wiped, uses the key and lets
 * go, as the released `Account.withKeys` does; [wipe] takes the guard too. So a use already running when the lock comes
 * finishes on whole keys, none starts after it, and none ever sees a half-wiped key.
 *
 * A use is a plain block, never a suspending one: the compiler refuses a wait inside it, so no key is read on one side
 * of a wait and used on the other. Code that built something from a key and then waits (for an answer, a mutex, a
 * network call) asks [check] after the wait, before it sends what it built.
 *
 * Whatever else is unwrapped from the account's keys (a shared vault's key) is registered with [whenWiped], so it is
 * wiped with them under the same guard.
 */
class KeyGuard internal constructor() {
    private val lock = SynchronizedObject()

    @Volatile
    private var wiped = false
    private val hooks = ArrayList<() -> Unit>()

    /** How many uses are running; only the thread that holds the lock can be inside one. Read and written under it. */
    private var depth = 0

    /** A wipe asked from inside a use on this thread: its zeroing waits for the outermost use's end. */
    private var zeroWhenUseEnds = false

    /** Whether the keys are wiped: nothing more is sealed, wrapped, signed or derived with them. */
    val isWiped: Boolean get() = wiped

    /** Runs [block] with the keys held against [wipe]; refuses with [AccountWipedException] once they are wiped. */
    internal fun <T> use(block: () -> T): T = synchronized(lock) {
        if (wiped) throw AccountWipedException()
        depth++
        try {
            block()
        } finally {
            depth--
            if (depth == 0 && zeroWhenUseEnds) {
                zeroWhenUseEnds = false
                runHooks()
            }
        }
    }

    /**
     * [block] under the guard's lock without the wiped check: for bookkeeping of what the guard's hooks zero (the log
     * engine's key maps), so it never runs beside a wipe. It must not use a key.
     */
    internal fun <T> locked(block: () -> T): T = synchronized(lock) { block() }

    /**
     * Refuses with [AccountWipedException] once the keys are wiped: what a caller asks after every wait, before it sends
     * anything built from the keys.
     */
    internal fun check() {
        if (wiped) throw AccountWipedException()
    }

    /** Runs [hook] at [wipe], under the guard (at once if the keys are wiped already). [hook] only zeroes and drops. */
    internal fun whenWiped(hook: () -> Unit) {
        synchronized(lock) {
            if (wiped) hook() else hooks += hook
        }
    }

    /**
     * Zero every key under this guard. Idempotent. Every hook runs even when one throws; the first failure is thrown
     * after all ran. The lock is re-entrant, so a wipe reached from inside a use on the same thread
     * would zero the key under that use (P1): there the keys read as wiped at once (no new use starts, [check] refuses)
     * and are zeroed when the outermost running use ends, so that use finishes on whole keys.
     */
    internal fun wipe() {
        synchronized(lock) {
            if (wiped) return
            wiped = true
            if (depth > 0) zeroWhenUseEnds = true else runHooks()
        }
    }

    /** Under the lock: every hook, whatever one throws; the first failure after all ran, the others suppressed in it. */
    private fun runHooks() {
        var failure: Throwable? = null
        for (h in hooks) {
            try {
                h()
            } catch (t: Throwable) {
                if (failure == null) failure = t else failure.addSuppressed(t)
            }
        }
        hooks.clear()
        failure?.let { throw it }
    }
}

/**
 * One of an account's secret keys (the UVK, the personal vault's key), reachable only inside [use], under its account's
 * [KeyGuard], and zeroed when the guard wipes. No code outside the account holds the array itself.
 */
class GuardedKey internal constructor(private val key: ByteArray, internal val guard: KeyGuard) {
    init {
        guard.whenWiped { key.fill(0) }
    }

    /**
     * [block] with the key, under the guard; [AccountWipedException] once wiped. [block] keeps no reference to it, and
     * answers what it built from the key, never the key. Where the test machinery is on, an answer that is the array, a
     * copy of it or its text form is refused with [KeyEscapeException] ([KeyEscape]); a shipped build hands back what
     * the block answered.
     */
    internal fun <T> use(block: (ByteArray) -> T): T = guard.use { KeyEscape.refuse(block(key), key) }

    companion object {
        /**
         * A key that belongs to no opened account (a test's own, or a flow's own before any account exists), under a
         * guard of its own.
         */
        internal fun loose(key: ByteArray): GuardedKey = GuardedKey(key, KeyGuard())
    }
}

/**
 * One of an account's key pairs (identity, signing): the public half readable at any time, the private half only inside
 * [use], under its account's [KeyGuard], and zeroed when the guard wipes.
 */
class GuardedKeyPair internal constructor(private val pair: KeyPairBytes, internal val guard: KeyGuard) {
    init {
        guard.whenWiped { pair.privateKey.fill(0) }
    }

    /** The public key: not secret, readable after the wipe too. */
    val publicKey: ByteArray get() = pair.publicKey

    /**
     * [block] with the pair, under the guard; [AccountWipedException] once wiped. [block] keeps no reference to it; where
     * the test machinery is on, an answer that is the pair, its private key (or the seed half), a copy or the text of
     * one is refused ([KeyEscapeException]), and a shipped build hands back what the block answered. The public key
     * may leave.
     */
    internal fun <T> use(block: (KeyPairBytes) -> T): T = guard.use { KeyEscape.refuse(block(pair), pair.privateKey, pair) }

    companion object {
        /** A pair that belongs to no opened account (a test's own), under a guard of its own. */
        internal fun loose(pair: KeyPairBytes): GuardedKeyPair = GuardedKeyPair(pair, KeyGuard())
    }
}

/**
 * A guarded use answered the key itself: a key that leaves its guard outlives the lock that
 * zeroes the original, and a copy is not zero, so neither the floor nor the tripwire would ever see it. Raised only
 * where the test machinery is on ([KeyEscape]), never in a shipped build. A programming mistake, never a lock:
 * deliberately not a [io.silencelen.andvari.core.crypto.KeysGoneException].
 */
class KeyEscapeException internal constructor(what: String) :
    IllegalStateException("a guarded use answered $what: a key leaves its guard only as what was built from it (a seal, a signature, a derived key), never as itself, a copy or its text")

/**
 * The run-time half of the fence, a DEVELOPMENT check: every guarded lend ([GuardedKey.use],
 * [GuardedKeyPair.use], the vault-key lend `withKey`) passes its block's answer through [refuse] before the guard lets
 * go. Where the test machinery is on, refused: the key's array; an array equal to it (or, for a 64-byte Ed25519 secret,
 * to its seed half); a pair holding it; a list of its bytes; its base64url, base64 or hex text, as a string or as ASCII
 * bytes; and any of those one level inside a [Pair], a [Triple], a collection or an array. A refused copy is zeroed
 * before the throw.
 *
 * It runs only where the test seam is present ([io.silencelen.andvari.core.crypto.lendCheckSwitch]: every module's tests
 * on the JVM and Android), never in a shipped build: there a lend's answer is handed back as
 * the block answered it, never compared with the key, zeroed or refused, because data can equal a key (every member of
 * a shared vault knows its key, so its owner can name the vault with the key's text, and a writer can store an item or
 * a file equal to it), and refusing data stops the app of everyone who reads it. It is a net for programming slips,
 * kept beside the tripwire and the source check, not a proof: a key stashed in a variable outside the block, or inside
 * an object of the block's own making, is not an answer it can see (the source check in `AccountKeyFenceTest` looks
 * for the first; nothing catches the second).
 */
internal object KeyEscape {
    /** The test seam's switch, found at the first lend; null in a shipped build. */
    private val switch: (() -> Boolean)? = io.silencelen.andvari.core.crypto.lendCheckSwitch()

    /** Whether a lend's answer is inspected now: never in a shipped build; in tests, unless a test asked for "as shipped". */
    val checking: Boolean get() = switch?.invoke() == true

    fun <T> refuse(answer: T, key: ByteArray, pair: KeyPairBytes? = null): T {
        if (!checking) return answer
        val what = escaped(answer, key, pair, nested = false) ?: return answer
        if (answer is ByteArray && answer !== key) answer.fill(0)
        throw KeyEscapeException(what)
    }

    private fun escaped(a: Any?, key: ByteArray, pair: KeyPairBytes?, nested: Boolean): String? = when (a) {
        null, is Unit, is Boolean, is Number -> null
        is ByteArray -> when {
            a === key -> "the key's own array"
            sameBytes(a, key, 0, key.size) -> "a copy of the key"
            key.size == 64 && sameBytes(a, key, 0, 32) -> "a copy of the key's seed"
            isTextOf(a.size, { a[it].toInt() and 0xff }, key) -> "the key's text, as bytes"
            else -> null
        }
        is String -> if (isTextOf(a.length, { a[it].code }, key)) "the key as text" else null
        is KeyPairBytes -> if (a === pair || a.privateKey === key || sameBytes(a.privateKey, key, 0, key.size)) "the key pair" else null
        is Pair<*, *> -> if (nested) null else escaped(a.first, key, pair, true) ?: escaped(a.second, key, pair, true)
        is Triple<*, *, *> -> if (nested) null else escaped(a.first, key, pair, true) ?: escaped(a.second, key, pair, true) ?: escaped(a.third, key, pair, true)
        is Collection<*> -> when {
            a.size == key.size && a.all { it is Byte } && sameList(a, key) -> "a list of the key's bytes"
            nested -> null
            else -> a.firstNotNullOfOrNull { escaped(it, key, pair, true) }
        }
        is Array<*> -> if (nested) null else a.firstNotNullOfOrNull { escaped(it, key, pair, true) }
        else -> null
    }

    /** True when [a] is exactly [key]'s bytes `[from, to)`. Reads every byte (no early exit). */
    private fun sameBytes(a: ByteArray, key: ByteArray, from: Int, to: Int): Boolean {
        if (a.size != to - from) return false
        var acc = 0
        for (i in a.indices) acc = acc or (a[i].toInt() xor key[from + i].toInt())
        return acc == 0
    }

    /** [a] (all bytes, as many as [key]) is [key]'s bytes in order. Reads every element (no early exit). */
    private fun sameList(a: Collection<*>, key: ByteArray): Boolean {
        var acc = 0
        var i = 0
        for (b in a) acc = acc or ((b as Byte).toInt() xor key[i++].toInt())
        return acc == 0
    }

    /**
     * Whether the [length] characters [ch] gives are the hex (either case), base64url or base64 (padded or not) text of
     * [key], or of a 64-byte secret's seed half. The text is decoded into a scratch array of the
     * key's length, compared with the key without an early exit, and the scratch is zeroed: no text form of the key is
     * ever built.
     */
    private fun isTextOf(length: Int, ch: (Int) -> Int, key: ByteArray): Boolean =
        textOf(length, ch, key, key.size) or (key.size == 64 && textOf(length, ch, key, 32))

    private fun textOf(length: Int, ch: (Int) -> Int, key: ByteArray, n: Int): Boolean {
        val unpadded = (n * 4 + 2) / 3
        val padded = (n + 2) / 3 * 4
        if (length != n * 2 && length != unpadded && length != padded) return false
        val scratch = ByteArray(n)
        try {
            val decoded = if (length == n * 2) hex(ch, scratch) else base64(length, ch, scratch, unpadded)
            return decoded && sameBytes(scratch, key, 0, n)
        } finally {
            scratch.fill(0)
        }
    }

    private fun hexDigit(c: Int): Int = when (c) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'a'.code..'f'.code -> c - 'a'.code + 10
        in 'A'.code..'F'.code -> c - 'A'.code + 10
        else -> -1
    }

    private fun hex(ch: (Int) -> Int, out: ByteArray): Boolean {
        var bad = false
        for (i in out.indices) {
            val hi = hexDigit(ch(2 * i))
            val lo = hexDigit(ch(2 * i + 1))
            bad = bad or (hi < 0) or (lo < 0)
            out[i] = ((hi shl 4) or lo).toByte()
        }
        return !bad
    }

    private fun base64Digit(c: Int): Int = when (c) {
        in 'A'.code..'Z'.code -> c - 'A'.code
        in 'a'.code..'z'.code -> c - 'a'.code + 26
        in '0'.code..'9'.code -> c - '0'.code + 52
        '+'.code, '-'.code -> 62
        '/'.code, '_'.code -> 63
        else -> -1
    }

    /** Either alphabet; the first [digits] characters are digits and anything after them is `=` padding. */
    private fun base64(length: Int, ch: (Int) -> Int, out: ByteArray, digits: Int): Boolean {
        var bad = false
        for (i in digits until length) bad = bad or (ch(i) != '='.code)
        var bits = 0
        var held = 0
        var o = 0
        for (i in 0 until digits) {
            val d = base64Digit(ch(i))
            bad = bad or (d < 0)
            bits = (bits shl 6) or (d and 63)
            held += 6
            if (held >= 8 && o < out.size) {
                held -= 8
                out[o++] = (bits shr held).toByte()
                bits = bits and ((1 shl held) - 1)
            }
        }
        return !bad && o == out.size
    }
}
