package io.silencelen.andvari.core.trust

/**
 * What a pure verifier of this package returns (design 2026-11-15 §18.2, the crypto and statement verifiers): either the checked
 * value, or exactly one NAMED verdict.
 *
 * The rules every verifier in `core/trust` keeps:
 * - **Pure.** No I/O, no network, no storage, no global state. The same bytes give the same answer on
 *   every device and on the server, which runs this same code (§3.7 step 7, T-R2).
 * - **Clock-free.** No verifier reads a clock. Where a rule of the design needs "now" (a link's
 *   `expiresAt`, §6.8), the caller passes it in; the vault log takes no time at all (§3.3, T2-R-a).
 * - **Total.** Untrusted input never throws: every rejection is a [Refused] carrying one verdict of the
 *   verifier's own enum, whose `code` is the design's name for it. There is no free-text failure.
 *   An `IllegalArgumentException` from this package always means the CALLER broke a builder's contract
 *   (it asked to sign a value outside the grammar), never that a received value was bad.
 * - **First failure decides.** Each verifier documents its check order; the verdict is the first check
 *   that fails, so two implementations agree on every rejection, not only on accept or refuse.
 */
sealed class Checked<out T, out V> {
    /** Every check passed. [value] is the verified result. */
    class Ok<out T>(val value: T) : Checked<T, Nothing>()

    /** The first failing check, as a named verdict. Nothing else about the input may be used. */
    class Refused<out V>(val verdict: V) : Checked<Nothing, V>()

    val isOk: Boolean get() = this is Ok

    /** The verified value, or null when refused. */
    fun valueOrNull(): T? = (this as? Ok<T>)?.value

    /** The verdict, or null when every check passed. */
    fun verdictOrNull(): V? = (this as? Refused<V>)?.verdict
}
