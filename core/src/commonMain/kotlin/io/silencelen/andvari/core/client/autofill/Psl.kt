package io.silencelen.andvari.core.client.autofill

/**
 * Registrable-domain (eTLD+1) resolution against the vendored PSL snapshot
 * (design docs/design/2026-07-10-etld1-psl-matching.md, spec 02 §3.1).
 *
 * Three-state result (amendment A1 — a nullable String cannot express the bare-suffix
 * tightening, and exact-rule membership misses all wildcard-derived suffixes):
 *  - [Registrable]  — the host's registrable domain is positively known.
 *  - [PublicSuffix] — the host IS a public suffix (exact, wildcard-derived, or
 *                     exception-derived alike): `github.io`, `co.uk`, `b.kawasaki.jp`,
 *                     `us-east-1.compute.amazonaws.com`.
 *  - [Unknown]      — no EXPLICIT rule matched (the PSL's implicit `*` fallback is
 *                     deliberately NOT applied — fail-safe A3/R-OLD), or the input is
 *                     non-ASCII / an IP literal / unparseable. Matching degrades to the
 *                     pre-eTLD+1 rules for Unknown, so `nas.local`-style intranet hosts
 *                     keep today's behavior bit-for-bit.
 */
sealed interface PslResult {
    data class Registrable(val domain: String) : PslResult
    data object PublicSuffix : PslResult
    data object Unknown : PslResult
}

object Psl {
    // Rule sets parsed once from the generated snapshot. Wildcard rules are stored as their
    // base (`*.kawasaki.jp` → `kawasaki.jp`), exceptions minus the `!`.
    private val exact: Set<String> by lazy { sets.first }
    private val wildcards: Set<String> by lazy { sets.second }
    private val exceptions: Set<String> by lazy { sets.third }

    private val sets: Triple<Set<String>, Set<String>, Set<String>> by lazy {
        val e = HashSet<String>()
        val w = HashSet<String>()
        val x = HashSet<String>()
        for (rule in PslData.joined.splitToSequence('\n')) {
            when {
                rule.isEmpty() -> {}
                rule.startsWith("!") -> x.add(rule.substring(1))
                rule.startsWith("*.") -> w.add(rule.substring(2))
                else -> e.add(rule)
            }
        }
        Triple(e, w, x)
    }

    /**
     * Resolve a NORMALIZED host (lowercase, no port/userinfo/trailing dot — the caller runs
     * [UriMatch.normalizeHost] first; this only self-guards).
     *
     * Walk (amendment A2, normative): candidate suffixes longest-first; at each candidate
     * test exception → exact → wildcard; an exception sets `suffixLen = candidateLabels − 1`
     * and STOPS (never overridden by the sibling wildcard that always co-exists); exact or
     * wildcard sets `suffixLen = candidateLabels` and stops. Longest-first + stop-on-first
     * makes the longest rule win by construction.
     */
    fun resolve(host: String): PslResult {
        // Self-guard (security review 2026-10): no DNS name exceeds 253 octets ([UriMatch.normalizeHost]
        // already refuses one); without it a planted many-label host made this walk O(labels²).
        if (host.isEmpty() || host.length > UriMatch.MAX_HOST_OCTETS || host.any { it.code >= 128 } || host.contains(':')) return PslResult.Unknown
        val labels = host.split('.')
        if (labels.any { it.isEmpty() }) return PslResult.Unknown
        if (labels.size == 4 && labels.all { l -> l.all { it.isDigit() } }) return PslResult.Unknown // IPv4
        // Each candidate suffix is a substring of `host` from a label's start offset — no per-step join.
        val starts = IntArray(labels.size)
        for (i in 1 until labels.size) starts[i] = starts[i - 1] + labels[i - 1].length + 1
        fun suffixFrom(i: Int) = host.substring(starts[i])
        var suffixLen = 0
        for (i in labels.indices) {
            val cand = suffixFrom(i)
            if (cand in exceptions) {
                suffixLen = (labels.size - i) - 1
                break
            }
            if (cand in exact) {
                suffixLen = labels.size - i
                break
            }
            if (labels.size - i >= 2 && suffixFrom(i + 1) in wildcards) {
                suffixLen = labels.size - i
                break
            }
        }
        return when {
            suffixLen == 0 -> PslResult.Unknown
            suffixLen >= labels.size -> PslResult.PublicSuffix
            else -> PslResult.Registrable(suffixFrom(labels.size - suffixLen - 1))
        }
    }
}
