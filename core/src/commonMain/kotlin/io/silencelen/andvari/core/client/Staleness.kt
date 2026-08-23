package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * Vault-health STALENESS — which logins are oldest, least recently used, and least recently
 * confirmed to still work. The Kotlin twin of `web/src/ui/staleness.ts`
 * (design `docs/design/2026-08-22-login-health-staleness-verification.md`, ported to the native
 * clients by `docs/design/2026-08-23-android-vault-health.md`).
 *
 * Pure and UI-free, the [VaultListView] / [Duplicates] idiom, so `StalenessTest` pins every
 * decision below without a render. The screens render and write; nothing is decided there.
 *
 * TWO SIGNALS, DELIBERATELY DIFFERENT IN KIND — the whole design turns on not conflating them:
 *
 *  - [VaultItem.updatedAt] is the SERVER clock (spec 02 §1), trustworthy for ordering, and means
 *    "last CHANGED" — nothing more. It bumps on a rename, a note tweak, a `dupeAck` write, a
 *    conflict materialization; a bulk import restamps an entire vault. It is therefore NEVER
 *    presented as "password age", and it never decides staleness alone. (`login.passwordHistory`
 *    cannot rescue this: spec 02 §3 reserves it with exactly one writer, so an absent history
 *    means nothing at all.)
 *  - [ItemDoc.check] is the CLIENT clock and means "a human confirmed this" (spec 02 §3).
 *    Advisory only — a future `at` is clamped, never trusted, because in a shared vault it can
 *    come from another member's skewed (or hostile) device.
 *
 * Usage is INJECTED, not read here ([StalenessOptions.lastUsedAt]). Usage lives in the sealed
 * per-user ledger (spec 02 §8.2) that this module deliberately knows nothing about, so the
 * ranking is identical whether or not a ledger is present on this install.
 */
object Staleness {

    /** Verdicts that mean "this login needs attention NOW" — the actionable half of the
     *  vocabulary. An UNRECOGNIZED result is deliberately NOT failing: spec 02 §3 makes the
     *  vocabulary open, and a future client's verdict must degrade to "checked, verdict
     *  unknown", never to a red row. */
    private val FAILING: Set<String> = setOf("bad", "gone", "blocked")

    fun isFailing(result: String?): Boolean = result != null && result in FAILING

    const val DAY_MS: Long = 86_400_000L
    private const val SIX_MONTHS_MS: Long = 182L * DAY_MS
    private const val YEAR_MS: Long = 365L * DAY_MS

    /** The snooze the "couldn't complete" verdict offers (design §4). One knob, named. */
    const val SNOOZE_MS: Long = 30L * DAY_MS

    /**
     * Scanning buckets. Declared in PRIORITY ORDER — [rankOf] depends on it.
     *
     * [wire] is the cross-implementation name, identical to web's `StaleBucket` union
     * (`web/src/ui/staleness.ts`). It exists so the shared vectors in
     * `spec/test-vectors/vaulthealth.json` can be graded against BOTH engines from one file;
     * it is not a display string and must never be shown to a user.
     */
    enum class StaleBucket(val wire: String) {
        FAILING("failing"),
        NEVER("never"),
        OVER_YEAR("over-year"),
        SIX_TO_TWELVE("six-to-twelve"),
        RECENT("recent"),
    }

    private fun rankOf(b: StaleBucket): Int = b.ordinal

    data class StalenessRow(
        val itemId: String,
        val vaultId: String,
        val name: String,
        val username: String,
        /** First saved WEB uri, verbatim — the "open site" target. Same rule and same reason as
         *  [Duplicates]: only a web uri is navigable (an `androidapp://` entry is not). */
        val firstUri: String? = null,
        /** Server clock. "Last changed", never "password age" — see the class KDoc. */
        val updatedAt: Long,
        /** From the injected ledger; null = no record, which is NOT "never used". */
        val lastUsedAt: Long? = null,
        val check: ItemCheck? = null,
        /** [ItemCheck.at] clamped to `now` — the skew guard. Null when never checked. */
        val checkedAt: Long? = null,
        val bucket: StaleBucket,
        /** Under an unexpired [ItemCheck.until]. Filtered from the default view, never deleted. */
        val snoozed: Boolean,
    )

    data class StalenessOptions(
        /** Injected ledger lookup (spec 02 §8.2). Omit entirely on an install with no ledger. */
        val lastUsedAt: ((String) -> Long?)? = null,
        /** Injected clock so the tests are not wall-clock dependent. */
        val now: Long,
        /** Include snoozed rows (the "show snoozed" toggle). */
        val includeSnoozed: Boolean = false,
    )

    private fun bucketFor(checkedAt: Long?, result: String?, age: Long): StaleBucket = when {
        isFailing(result) -> StaleBucket.FAILING
        checkedAt == null -> StaleBucket.NEVER
        age > YEAR_MS -> StaleBucket.OVER_YEAR
        age > SIX_MONTHS_MS -> StaleBucket.SIX_TO_TWELVE
        else -> StaleBucket.RECENT
    }

    /**
     * The staleness table, ordered worst-first. The ordering is EXPLAINABLE BY CONSTRUCTION
     * rather than a weighted score: a score would be unarguable-with and would quietly encode
     * judgements the user never agreed to. Three tiers, each with its own honest tie-break:
     *
     *   1. failing verdicts   — most RECENT first (a fresh failure is the most actionable thing)
     *   2. never checked      — oldest `updatedAt` first (the only age signal such a row has)
     *   3. everything checked — oldest `checkedAt` first (longest since a human confirmed it)
     *
     * Name is the final tie-break throughout, so equal stamps keep a stable alphabetical order
     * (the [VaultListView] "recent" rule).
     *
     * **Name comparison note:** web uses `localeCompare`, this uses code-unit order. They agree
     * on ASCII, which is what the shared vectors cover. The divergence is confined to the FINAL
     * tie-break between rows whose timestamps are already equal, so it is cosmetic ordering and
     * never changes which rows are surfaced or how they are bucketed.
     */
    fun stalenessRows(items: List<VaultItem>, opts: StalenessOptions): List<StalenessRow> {
        val now = opts.now
        val rows = ArrayList<StalenessRow>()

        for (it in items) {
            if (it.doc.type != "login") continue // notes and cards have no login to verify
            val check = it.doc.check
            // Skew clamp (spec 02 §3): a client-clock `at` from the future is displayed and
            // ordered as "just now" rather than allowed to sort above every genuine entry.
            val checkedAt = check?.let { c -> minOf(c.at, now) }
            val age = if (checkedAt == null) 0L else maxOf(0L, now - checkedAt)
            val snoozed = check?.until != null && check.until > now
            if (snoozed && !opts.includeSnoozed) continue

            rows.add(
                StalenessRow(
                    itemId = it.itemId,
                    vaultId = it.vaultId,
                    name = it.doc.name.ifEmpty { "(untitled)" },
                    username = it.doc.login?.username ?: "",
                    firstUri = (it.doc.login?.uris ?: emptyList())
                        .firstOrNull { u -> UriMatch.parseSavedUri(u) is SavedUri.Web },
                    updatedAt = it.updatedAt,
                    lastUsedAt = opts.lastUsedAt?.invoke(it.itemId),
                    check = check,
                    checkedAt = checkedAt,
                    bucket = bucketFor(checkedAt, check?.result, age),
                    snoozed = snoozed,
                ),
            )
        }

        return rows.sortedWith { a, b ->
            val ra = rankOf(a.bucket)
            val rb = rankOf(b.bucket)
            if (ra != rb) return@sortedWith ra - rb
            when (a.bucket) {
                // A fresh failure is the most actionable thing on this screen: newest first.
                StaleBucket.FAILING -> compareLongsThenName(b.checkedAt ?: 0L, a.checkedAt ?: 0L, a.name, b.name)
                // The only age signal a never-checked row has.
                StaleBucket.NEVER -> compareLongsThenName(a.updatedAt, b.updatedAt, a.name, b.name)
                // Longest since a human confirmed it.
                else -> compareLongsThenName(a.checkedAt ?: 0L, b.checkedAt ?: 0L, a.name, b.name)
            }
        }
    }

    private fun compareLongsThenName(x: Long, y: Long, aName: String, bName: String): Int =
        if (x != y) x.compareTo(y) else aName.compareTo(bName)

    data class StalenessSummary(val unchecked: Int, val failing: Int)

    /** Counts for the health tiles. Derived from the SAME rows the table shows, so a tile can
     *  never disagree with the list under it. */
    fun stalenessSummary(rows: List<StalenessRow>): StalenessSummary = StalenessSummary(
        unchecked = rows.count { it.bucket == StaleBucket.NEVER },
        failing = rows.count { it.bucket == StaleBucket.FAILING },
    )

    data class CheckPlan(
        /** The single item write to hand to the save path. ONE write per verdict — spec 02 §7
         *  caps `item_versions` at 10 per item, so a chatty writer here would evict real edit
         *  history (the F63 backstop) permanently. */
        val write: PlannedWrite? = null,
        /** Shown verbatim when the verdict cannot be recorded. The [Duplicates] refusal idiom. */
        val refusal: String? = null,
    )

    data class PlannedWrite(val itemId: String, val doc: ItemDoc)

    // Refusal copy, verbatim from staleness.ts — these are user-facing strings and the twin
    // must not paraphrase them.
    private const val REFUSAL_VANISHED =
        "That item changed under you — the list refreshes on its own; try again."
    private const val REFUSAL_NOT_LOGIN = "Only logins can be checked."
    private const val REFUSAL_READER =
        "This login is in a vault you can only view — ask the vault's owner to record a check."

    /**
     * Compose the doc for one recorded verdict. Pure: composed HERE so the tests pin exactly
     * what ships, and so the screens only render and save.
     *
     * A SKIPPED item never reaches this function — skipping writes nothing at all, by design.
     *
     * [ItemCheck.okAt] carries forward (spec 02 §3): an `ok` verdict stamps it to now, any other
     * verdict copies the prior value unchanged, so "last worked in March, failed in August"
     * survives in one small object without an array.
     */
    fun planCheck(
        items: List<VaultItem>,
        itemId: String,
        result: String,
        now: Long,
        roleFor: (String) -> String?,
        snoozeMs: Long? = null,
    ): CheckPlan {
        // The list refreshes itself on every applied sync, so a vanished item is a race.
        val item = items.firstOrNull { it.itemId == itemId } ?: return CheckPlan(refusal = REFUSAL_VANISHED)
        if (item.doc.type != "login") return CheckPlan(refusal = REFUSAL_NOT_LOGIN)
        // A reader's write would be refused by the server anyway (spec 02 §4: roles are
        // server-enforced). Refuse it HERE, with the reason, rather than letting it fail.
        if (roleFor(item.vaultId) == "reader") return CheckPlan(refusal = REFUSAL_READER)

        val prior = item.doc.check
        val okAt = if (result == "ok") now else prior?.okAt
        val check = ItemCheck(
            at = now,
            result = result,
            okAt = okAt,
            until = snoozeMs?.let { now + it },
        )
        return CheckPlan(write = PlannedWrite(itemId, item.doc.copy(check = check)))
    }

    /** Clear a snooze so the item returns to the list immediately ("unsnooze"). Keeps the
     *  verdict — only the horizon goes — because the verdict is still the last true thing a
     *  human observed. */
    fun planUnsnooze(
        items: List<VaultItem>,
        itemId: String,
        roleFor: (String) -> String?,
    ): CheckPlan {
        val item = items.firstOrNull { it.itemId == itemId } ?: return CheckPlan(refusal = REFUSAL_VANISHED)
        if (roleFor(item.vaultId) == "reader") return CheckPlan(refusal = REFUSAL_READER)
        val check = item.doc.check ?: return CheckPlan()
        if (check.until == null) return CheckPlan() // nothing to do, and nothing worth a write
        return CheckPlan(write = PlannedWrite(itemId, item.doc.copy(check = check.copy(until = null))))
    }
}
