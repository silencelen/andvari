package io.silencelen.andvari.app.autofill

/**
 * DNS length limits for a host-app-supplied `webDomain` (security review 2026-10, wave-6 LOW).
 *
 * Any app sets its own `ViewNode.webDomain`, and the autofill diagnostics normalised it through
 * `UriMatch.normalizeHost` → IDNA → punycode for every field of every fill request, before any
 * trust check. Punycode encoding is quadratic in a label's code points, so one ~65k-code-point label
 * pinned the fill thread for seconds. No real host can exceed 253 characters in total or 63 in a
 * label, so checking the raw length first loses nothing and runs in time linear in the input.
 * Measured on the raw string (UTF-16 units, an upper bound on code points): a non-ASCII label that
 * passes here is at most 63 code points, which punycode handles trivially.
 */
object HostCap {
    const val MAX_HOST = 253
    const val MAX_LABEL = 63

    fun withinDnsLimits(raw: String): Boolean {
        if (raw.length > MAX_HOST) return false
        var label = 0
        for (c in raw) {
            if (c == '.') label = 0 else if (++label > MAX_LABEL) return false
        }
        return true
    }
}
