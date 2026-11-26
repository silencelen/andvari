package io.silencelen.andvari.tripwire

import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.SecretStreamResult
import io.silencelen.andvari.core.crypto.ZeroKeyWatch
import java.io.File

/**
 * The test suites' tripwire for keys used after a lock. A lock zero-fills the
 * account's keys; whatever still held one of those arrays and sealed, opened, signed, derived or MACed with it did so
 * under zeros. The shared code refuses that ([io.silencelen.andvari.core.crypto.KeysGoneException], the floor); this
 * records what reaches the platform's provider anyway, by any path, and every refusal of the floor, so a refusal a
 * handler swallows still leaves a line.
 *
 * Test machinery only: it lives in `core/src/jvmTripwire`, which each watched module adds to its TEST source set (core's
 * `jvmTest`, the hostile-server bench, the command-line and recovery tools, the desktop app, the Android app's unit
 * tests), and is found through `META-INF/services` by the shipped seam ([ZeroKeyWatch]). Nothing that ships carries
 * either. It records only when the system property [PROPERTY] names a file, which `gradle/zero-key-tripwire.gradle.kts`
 * sets on each watched test task; that task fails at its end when the file holds an unexpected line.
 *
 * Counted at the provider: an AEAD seal or open, a secretstream seal or open, a sealed-box open, under an all-zero key;
 * a key pair from an all-zero seed; an Ed25519 signature with an all-zero seed; an HMAC under an all-zero key (except
 * HKDF's own all-zero default salt) or over a wiped key (a derivation from zero input, whatever the salt); an AEAD seal
 * or a sealed box whose plaintext is a wiped key (32 or 64 zero bytes) or a frame holding one (a secret JSON field, such
 * as a grant's `vk`, that is 32 or 64 zero bytes in base64url).
 *
 * Expected lines: a test whose job is to show the floor refusing, or the tripwire counting, zeros. A line is expected
 * when a frame of its stack belongs to one of [EXPECTED]; it is written with the prefix `expected ` and does not fail
 * the task. Every other line fails it.
 */
class ZeroKeyTripwire : ZeroKeyWatch {
    private val record: File? = System.getProperty(PROPERTY)?.takeIf { it.isNotBlank() }?.let(::File)

    /** Creates the record (empty), so the task can tell "on and clean" from "never reached". */
    override fun watch(provider: CryptoProvider): CryptoProvider = record?.let {
        it.parentFile?.mkdirs()
        it.createNewFile()
        Recording(provider, it)
    } ?: provider

    override fun refused(what: String) {
        record?.let { write(it, "the floor refused $what") }
    }

    /** Lends are checked in every test, whether or not this run records, unless one asked for [asShipped]. */
    override fun checksLends(): Boolean = !lendsAsShipped

    /** The decorator, public so a test can wrap its own provider with its own record. */
    class Recording(private val inner: CryptoProvider, private val record: File) : CryptoProvider by inner {
        private fun trip(what: String) = write(record, what)

        override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray {
            if (key.size == 32 && allZero(key)) trip("a seal under an all-zero key")
            if (wipedKey(plaintext)) trip("a wrap of an all-zero key")
            else zeroKeyField(plaintext)?.let { trip("a seal of a frame holding an all-zero key (\"$it\")") }
            return inner.aeadEncrypt(key, nonce, plaintext, ad)
        }

        override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray {
            if (allZero(key)) trip("an open under an all-zero key")
            return inner.aeadDecrypt(key, nonce, ciphertext, ad)
        }

        override fun secretstreamEncrypt(key: ByteArray, chunks: List<ByteArray>): SecretStreamResult {
            if (allZero(key)) trip("a file sealed under an all-zero key")
            return inner.secretstreamEncrypt(key, chunks)
        }

        override fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray> {
            if (allZero(key)) trip("a file opened under an all-zero key")
            return inner.secretstreamDecrypt(key, header, chunks)
        }

        override fun sealTo(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray {
            if (wipedKey(plaintext)) trip("a wrap of an all-zero key")
            else zeroKeyField(plaintext)?.let { trip("a sealed box of a frame holding an all-zero key (\"$it\")") }
            return inner.sealTo(recipientPublicKey, plaintext)
        }

        override fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray {
            if (allZero(privateKey)) trip("a sealed box opened with an all-zero private key")
            return inner.sealOpen(publicKey, privateKey, sealed)
        }

        override fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes {
            if (allZero(seed)) trip("an X25519 key pair from an all-zero seed")
            return inner.boxKeypairFromSeed(seed)
        }

        override fun signKeypairFromSeed(seed: ByteArray): KeyPairBytes {
            if (allZero(seed)) trip("an Ed25519 key pair from an all-zero seed")
            return inner.signKeypairFromSeed(seed)
        }

        override fun signDetached(secretKey: ByteArray, message: ByteArray): ByteArray {
            // Only a secret of the right length signs at all; a malformed one is the provider's refusal, not a signature.
            if (secretKey.size == 64 && allZero(secretKey.copyOfRange(0, 32))) trip("a signature with an all-zero key")
            return inner.signDetached(secretKey, message)
        }

        override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
            mac(key, data)
            return inner.hmacSha256(key, data)
        }

        override fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray {
            mac(key, data)
            return inner.hmacSha512(key, data)
        }

        private fun mac(key: ByteArray, data: ByteArray) {
            if (wipedKey(data)) trip("a derivation from an all-zero input")
            // HKDF's extract step keys its HMAC with RFC 5869's default salt, HashLen zeros: that is no wiped key.
            else if (allZero(key) && !fromHkdfExtract()) trip("a MAC under an all-zero key")
        }
    }

    companion object {
        /** The system property that turns the tripwire on: the path of the file it records into. */
        const val PROPERTY = "andvari.test.zeroKeyTripwire"

        /**
         * The one switch between "checked" and "as shipped" for a guarded lend's answer (spec
         * 01 §8 rule 1). False, the default in every test: the guard refuses an answer that is the key, a copy or its
         * text ([io.silencelen.andvari.core.client.onboard.KeyEscapeException]), the net against programming slips.
         * True: lends run as a shipped build runs them, which has no tripwire and so never inspects an answer. Only test
         * code can reach it (this class is never shipped); set it through [asShipped], which puts it back.
         */
        @Volatile
        @JvmStatic
        var lendsAsShipped: Boolean = false

        /** [block] with lends as shipped ([lendsAsShipped]), then the switch as it was. A suspending caller may wait inside. */
        inline fun <T> asShipped(block: () -> T): T {
            val was = lendsAsShipped
            lendsAsShipped = true
            try {
                return block()
            } finally {
                lendsAsShipped = was
            }
        }

        /**
         * The tests whose job is to make the floor refuse, or the tripwire count, zeros (simple class names; a nested or
         * lambda class of one counts as it). Each is named for what it shows; adding one here is a reviewed decision.
         */
        val EXPECTED: Set<String> = setOf(
            "KeyFloorTest", // the floor's own refusals
            "ZeroKeyTripwireTest", // the tripwire's own counts
            "CanonAndLengthGuardsTest", // the provider's own input guards, fed keys of zeros on purpose
            "SignedStatementVectorTest.primitives_failClosedOnBadInput", // a primitive fed a seed of zeros on purpose
            // keyfloor.json's must-refuse rows: the three all-zero inputs that links.json, devicelink.json and vaultlog.json
            // carried until 2026-11-16 (their places there now hold near-zero inputs, so those suites refuse nothing).
            "KeyFloorVectorTest.refuse_everyAllZeroInputIsRefusedAtItsOperation",
            "NearZeroVectorRowsTest.allZerosStaysRefused", // the same three derivations, asserted refused without a file

            // The probe's detector: whether a pushed item opens under a vault key of zeros, at the provider.
            "EngineKeysAfterLockTest.opensUnderZeros",
            // A hostile server's wrap of 32 zero bytes under a password it chose, built at the
            // provider on purpose: what a wiped UVK looks like, so a lock during the proof can be shown never to prove it.
            "AccountProofLockTest.aChosenPasswordIsNeverReadAsRightAcrossALock",
            // A hostile party's own sealing of a frame that holds an all-zero key, so that the reader can be shown to refuse
            // it where the key is taken out. Each entry is the one function that seals; the reading under test is outside it,
            // so a line from shipped code in these tests is still unexpected.
            "SignedGrantZeroKeyTest.sealedByTheOwner", // a pinned owner's signed grant whose vault key is zeros
            "ZeroKeyInRecoveryTest.sealedByTheRecoveryKey", // a recovery answer whose account key is zeros
            "SharedGrantZeroKeyTest.sealOfZeros", // a first-form grant seal, which a server can make, whose vault key is zeros
            "AccountZeroVaultKeyTest.v1SealOfZeros", // the same seal, served to the old account line
            "AccountZeroVaultKeyTest.wrapOfZeros", // a vault key of zeros wrapped under the account's own key
            // The old account line's unlocks: an account key, an identity seed or a recovery copy that opens to zeros.
            "AccountZeroKeyTakeOutTest.wrapOfZeros",
            "AccountOpenZeroPersonalWrapTest.wrapOfZeros", // the new line's personal vault wrap opening to zeros
        )

        private val LOCK = Any()

        internal fun allZero(b: ByteArray): Boolean {
            if (b.isEmpty()) return false
            var acc = 0
            for (x in b) acc = acc or x.toInt()
            return acc == 0
        }

        internal fun wipedKey(b: ByteArray) = (b.size == 32 || b.size == 64) && allZero(b)

        private val zeroKeyText = Regex(""""(\w*(?:[vV]k|[sS]eed|[sS]ecret|[pP]riv|[pP]rivateKey))"\s*:\s*"(?:A{43}=?|A{86}(?:==)?)"""")

        /**
         * The name of a secret field of a frame (JSON: `vk`, `uvk`, a name ending in `Vk`, `Seed`, `Secret`, `Priv` or
         * `PrivateKey`) whose string is 32 or 64 zero bytes in base64url (padded or not), or null. A key travels in a frame
         * as base64url only (spec 00); hex is for hashes and fingerprints, and a public key of zeros is a test's fixture,
         * not a wiped secret.
         */
        internal fun zeroKeyField(b: ByteArray): String? {
            if (b.size < 45 || b.size > 1 shl 20) return null
            return zeroKeyText.find(b.decodeToString())?.groupValues?.get(1)
        }

        private fun simple(f: StackTraceElement) = f.className.substringAfterLast('.').substringBefore('$')

        private fun frames() = Throwable().stackTrace.asSequence()
            .filter { !it.className.startsWith(ZeroKeyTripwire::class.java.name) && !it.className.startsWith("io.silencelen.andvari.core.crypto.ZeroKeyWatch") }

        /** The HMAC's caller, past any provider that wraps this one (a test's spy delegates under the same name). */
        private fun fromHkdfExtract(): Boolean =
            frames().firstOrNull { !it.methodName.startsWith("hmacSha") }?.className == "io.silencelen.andvari.core.crypto.Hkdf"

        private fun write(record: File, what: String) {
            val stack = frames().toList()
            val expected = stack.any { f -> simple(f) in EXPECTED || "${simple(f)}.${f.methodName}" in EXPECTED }
            val test = stack.lastOrNull { simple(it).endsWith("Test") }?.let { "${simple(it)}.${it.methodName}" } ?: "no test frame"
            val where = stack.take(14).joinToString(" < ") { "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}" }
            synchronized(LOCK) { record.appendText("${if (expected) "expected " else ""}$what in $test at $where\n") }
        }
    }
}
