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
        if (host.isEmpty() || host.any { it.code >= 128 } || host.contains(':')) return PslResult.Unknown
        val labels = host.split('.')
        if (labels.any { it.isEmpty() }) return PslResult.Unknown
        if (labels.size == 4 && labels.all { l -> l.all { it.isDigit() } }) return PslResult.Unknown // IPv4
        var suffixLen = 0
        for (i in labels.indices) {
            val cand = labels.subList(i, labels.size).joinToString(".")
            if (cand in exceptions) {
                suffixLen = (labels.size - i) - 1
                break
            }
            if (cand in exact) {
                suffixLen = labels.size - i
                break
            }
            if (labels.size - i >= 2 && labels.subList(i + 1, labels.size).joinToString(".") in wildcards) {
                suffixLen = labels.size - i
                break
            }
        }
        return when {
            suffixLen == 0 -> PslResult.Unknown
            suffixLen >= labels.size -> PslResult.PublicSuffix
            else -> PslResult.Registrable(labels.subList(labels.size - suffixLen - 1, labels.size).joinToString("."))
        }
    }
}
