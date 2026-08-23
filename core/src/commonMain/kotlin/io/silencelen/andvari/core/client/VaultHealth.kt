package io.silencelen.andvari.core.client

/**
 * Vault-wide password health rows — strength, reuse and TOTP presence per login. The Kotlin twin
 * of `healthRows` in `web/src/ui/Health.tsx` (ported by
 * `docs/design/2026-08-23-android-vault-health.md`).
 *
 * Pure, like [Staleness] and [Duplicates]: a fresh item list in, fresh rows out, so a client's
 * view recomputes exactly when its items change and can never freeze on a stale snapshot. (That
 * is not hypothetical — bug-web--1 was precisely this view memoizing on an identity-stable
 * dependency and freezing for a whole mount while live syncs applied underneath it.)
 *
 * Strength comes from [Strength.estimateStrength], which is ALREADY the twin of web's
 * `strength.ts` — no second scoring implementation exists or should.
 *
 * BREACH COUNTS ARE DELIBERATELY ABSENT from this type. They are fetched on demand
 * ([Strength.breachCount]), cost a network round trip, and — per CR-08 / WC-13 §E.4 — may be
 * cached only in memory, per-account, and dropped at the sign-out choke point. Threading them
 * through a pure derivation would invite exactly the at-rest cache that audit removed once.
 */
object VaultHealth {

    data class HealthRow(
        val itemId: String,
        val name: String,
        /** The plaintext password — the caller's lookup key for a breach scan, never persisted. */
        val password: String,
        /** [Strength.estimateStrength]: 0..4, pattern-aware. */
        val strength: Int,
        /** How many OTHER items share this exact password (0 = not reused). */
        val reused: Int,
        val hasTotp: Boolean,
    )

    /**
     * Derive the health rows. Only logins WITH a password qualify: a note has nothing to score,
     * and a password-less login is not a weak password — it is an absence, and scoring it would
     * report a defect the vault does not have.
     */
    fun healthRows(items: List<VaultItem>): List<HealthRow> {
        val logins = items.filter { it.doc.type == "login" && !it.doc.login?.password.isNullOrEmpty() }
        val byPassword = HashMap<String, Int>()
        for (it in logins) {
            val pw = it.doc.login!!.password!!
            byPassword[pw] = (byPassword[pw] ?: 0) + 1
        }
        return logins.map { it ->
            val pw = it.doc.login!!.password!!
            HealthRow(
                itemId = it.itemId,
                name = it.doc.name.ifEmpty { "(untitled)" },
                password = pw,
                strength = Strength.estimateStrength(pw),
                reused = (byPassword[pw] ?: 1) - 1,
                hasTotp = !it.doc.login?.totp.isNullOrEmpty(),
            )
        }
    }

    data class HealthSummary(val logins: Int, val weak: Int, val reused: Int)

    /** Tile counts, derived from the SAME rows the list shows so a tile can never disagree with
     *  it. "Weak" is score <= 1 ("very weak" / "weak"), matching Health.tsx. */
    fun summarize(rows: List<HealthRow>): HealthSummary = HealthSummary(
        logins = rows.size,
        weak = rows.count { it.strength <= 1 },
        reused = rows.count { it.reused > 0 },
    )
}
