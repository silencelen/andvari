package io.silencelen.andvari.core.crypto

/**
 * The keys an operation was given are gone: a lock or the end of the session zero-filled them (spec 01 §8: keys live in
 * memory only and end with the session). The operation did nothing and must end as "locked", never as anything else.
 *
 * Deliberately NOT a [CryptoException]: a [CryptoException] from an open reads as "wrong password", "not ours" or
 * "damaged" to its callers, and a lock is none of those. A
 * handler that tells a lock apart catches this type; the account's own refusal after a wipe
 * ([io.silencelen.andvari.core.client.AccountWipedException]) is one of it.
 */
open class KeysGoneException(message: String = "the account's keys are gone: the vault locked or the session ended") : IllegalStateException(message)

/**
 * [block]'s answer, or null when it failed for any reason but a lock: the shape of a
 * `runCatching { … }.getOrNull()` around work that reads a key, with [KeysGoneException] passed through, so a handler
 * whose failure branch removes, rewrites or counts something never does it because the vault locked (spec 01 §8 rule 5).
 */
internal inline fun <T> orNullUnlessLocked(block: () -> T): T? = try {
    block()
} catch (e: KeysGoneException) {
    throw e
} catch (e: Throwable) {
    null
}

/**
 * The test machinery's switch over the check of a lend's answer (spec 01 §8 rule 1): asked once,
 * at the first lend. Null in a shipped build, which carries no test seam: then no lend's answer is ever compared with
 * the key, zeroed or refused, because there the check cannot tell a programming slip from data that equals a key (a
 * vault's name, an item or a file another member chose), and refusing data is an attack on the person using it. Where
 * the test suites' tripwire is on the class path (every module's tests, `ZeroKeyWatch` on the JVM and Android), the
 * answer is the tripwire's word, asked at each lend: "checked" unless a test asked for "as shipped".
 */
internal expect fun lendCheckSwitch(): (() -> Boolean)?

/**
 * The last line of defence of the shared crypto path: no legitimate key is all zeros, so a seal, wrap,
 * signature, derivation or open under one, or a wrap of one, is refused with [KeysGoneException] before the platform's
 * provider is called. A zero-filled key is what a lock leaves behind in an array something still holds; whatever was
 * about to be built from it must not exist, let alone be sent.
 */
internal object KeyFloor {
    /**
     * Told of every refusal before the throw, when a test run's tripwire is on the class path (`ZeroKeyWatch`); null in
     * a release. A refusal is the floor catching what the guard should have stopped, so a test suite treats one it did
     * not ask for as a finding, even when a handler swallows the exception.
     */
    @kotlin.concurrent.Volatile
    var onRefusal: ((String) -> Unit)? = null

    private fun refuse(what: String): Nothing {
        onRefusal?.invoke(what)
        throw KeysGoneException()
    }

    /** True when [b] is non-empty and every byte is zero. Reads every byte (no early exit). */
    fun allZero(b: ByteArray): Boolean {
        if (b.isEmpty()) return false
        var acc = 0
        for (x in b) acc = acc or x.toInt()
        return acc == 0
    }

    /** Refuses [key] (a symmetric key, an HKDF input key, an Ed25519 or X25519 secret) when it is all zeros. */
    fun requireKey(key: ByteArray) {
        if (allZero(key)) refuse("an all-zero key")
    }

    /**
     * Refuses an Ed25519 secret (libsodium's 64 bytes: seed ‖ public) whose seed half is all zeros: what a wipe leaves,
     * since a wipe zeroes the whole array.
     */
    fun requireSigningKey(secret: ByteArray) {
        // The seed half is read in place: a copy of it would be the account's identity seed, outliving the lock.
        if (allZero(secret) || (secret.size == 64 && allZeroUpTo(secret, 32))) refuse("a signing key with an all-zero seed")
    }

    /** True when [b]'s first [n] bytes are all zero, read in place. Reads every one of them (no early exit). */
    private fun allZeroUpTo(b: ByteArray, n: Int): Boolean {
        var acc = 0
        for (i in 0 until n) acc = acc or b[i].toInt()
        return acc == 0
    }

    /**
     * Refuses a plaintext that is a wiped key: exactly 32 or 64 bytes, all zero (a UVK, a vault key, a seed or a signing
     * secret after a wipe). No item, document or record this app seals is 32 or 64 zero bytes.
     */
    fun requireNotWipedKey(plaintext: ByteArray) {
        if ((plaintext.size == 32 || plaintext.size == 64) && allZero(plaintext)) refuse("a wrap of an all-zero key")
    }
}
