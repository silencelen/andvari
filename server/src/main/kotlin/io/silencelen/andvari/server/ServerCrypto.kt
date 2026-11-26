package io.silencelen.andvari.server

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.interfaces.PwHash
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider

/**
 * Server-only crypto. The vault crypto is all client-side; the server just needs:
 *  - a slow hash over the received authKey (so a DB leak ≠ login replay, spec 01 §3)
 *  - opaque token generation + hashing
 *  - deterministic fake prelogin salts (anti-enumeration, spec 01 §3)
 */
object ServerCrypto {
    private val ls = LazySodiumJava(SodiumJava())
    private val crypto = createCryptoProvider()

    /**
     * At most this many Argon2id hashes or verifies run at once, server-wide. Each takes 64 MiB of
     * native memory (MEMLIMIT_INTERACTIVE) and a core for a few hundred milliseconds, so four bound the memory
     * at 256 MiB whatever arrives, and keep a small host's cores busy without queueing every other request
     * behind them; more would not finish sooner on the two to four cores a self-hosted box has.
     */
    const val ARGON2_PERMITS = 4

    private val argon2 = java.util.concurrent.Semaphore(ARGON2_PERMITS, true)
    private val inFlight = java.util.concurrent.atomic.AtomicInteger()

    /** Tests only: Argon2 operations run so far, and the most that ever ran at once. */
    internal val argon2Calls = java.util.concurrent.atomic.AtomicLong()
    internal val argon2MaxInFlight = java.util.concurrent.atomic.AtomicInteger()

    private inline fun <T> argon2Work(block: () -> T): T {
        argon2.acquireUninterruptibly()
        try {
            argon2Calls.incrementAndGet()
            val n = inFlight.incrementAndGet()
            argon2MaxInFlight.accumulateAndGet(n, ::maxOf)
            try {
                return block()
            } finally {
                inFlight.decrementAndGet()
            }
        } finally {
            argon2.release()
        }
    }

    /** Store side of the login verifier: argon2id string over the (already KDF-derived) authKey. */
    fun hashVerifier(authKeyB64: String): String = argon2Work {
        ls.cryptoPwHashStr(authKeyB64, PwHash.OPSLIMIT_INTERACTIVE, PwHash.MEMLIMIT_INTERACTIVE)
            ?: error("cryptoPwHashStr failed")
    }

    fun verify(storedVerifier: String, authKeyB64: String): Boolean = argon2Work {
        ls.cryptoPwHashStrVerify(storedVerifier, authKeyB64)
    }

    /**
     * A fixed valid argon2id string so a `/recovery/self/verify` for an unknown email OR a known
     * email with no member_recovery row spends the SAME argon2id CPU as a real verify (anti-enum,
     * design §F.5). Mirrors Service.DUMMY_VERIFIER on the login path (Service.kt:1050). Computed
     * once, after `ls`/`crypto` are initialized above.
     */
    val DUMMY_RECOVERY_VERIFIER: String = hashVerifier("andvari-dummy-recovery-authkey")

    fun newToken(): String = Bytes.toB64(crypto.randomBytes(32))

    fun sha256(data: ByteArray): ByteArray = crypto.sha256(data)

    fun hashToken(token: String): String = Bytes.toB64(crypto.sha256(token.encodeToByteArray()))

    /** Deterministic 16-byte fake salt for unknown emails (looks real, leaks nothing). */
    fun fakeSalt(enumSecret: ByteArray, email: String): ByteArray =
        crypto.hmacSha256(enumSecret, email.lowercase().encodeToByteArray()).copyOf(16)

    /** The label of the key every address hash in the server's records is made with ([addressHash]). */
    private val ADDRESS_RECORD_LABEL = "andvari/v2|address-record-key".encodeToByteArray()

    /**
     * The hash of an address a person typed ([emailNorm]) as the server's records keep it: in the audit rows and the
     * journal lines of a sign-up's first steps, and in every stored row that is bound to an address (sign-up codes and
     * tickets, recovery requests real and decoy, mailbox values, an enrol link minted for an address).
     * `hexLower(HMAC-SHA-256(K, "andvari/v2|address|" + emailNorm))`, where K is `HMAC-SHA-256(enumSecret,
     * "andvari/v2|address-record-key")`: a key of its own, derived from the instance's enumeration secret under a label of
     * its own, so that it shares nothing with the fake salts the same secret makes, which are served to anyone. The same
     * address gives the same hash, so rows still tie together; without the secret, a guessed address confirms nothing.
     * A row written under an earlier secret (a restore beside a new secret, or a changed one) no longer ties to new rows.
     */
    fun addressHash(enumSecret: ByteArray, emailNorm: String): String {
        val key = crypto.hmacSha256(enumSecret, ADDRESS_RECORD_LABEL)
        try {
            return Bytes.toHexLower(crypto.hmacSha256(key, "andvari/v2|address|$emailNorm".encodeToByteArray()))
        } finally {
            key.fill(0)
        }
    }
}
