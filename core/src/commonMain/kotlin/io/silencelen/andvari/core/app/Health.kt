package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Duplicates
import io.silencelen.andvari.core.client.Staleness
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.UsageLedger
import io.silencelen.andvari.core.client.VaultHealth
import io.silencelen.andvari.core.client.VaultItem

/**
 * Vault health while its screen is open ([SessionController.openHealth]), the Android app's health screen (design
 * 2026-08-23): weak and reused passwords, known breaches, duplicate copies, and how long since a person confirmed each
 * login still works. Every ranking, cluster, survivor and refusal is core's ([VaultHealth], [Duplicates], [Staleness]),
 * the modules the web and Android clients use; this only carries them to the screen.
 */
data class HealthView(
    val tiles: HealthTilesView,
    /** Logins with a password: the most breached first, then by name. */
    val passwords: List<HealthPasswordView>,
    /** Copies of the same account still to sort out. */
    val duplicates: List<DuplicateClusterView>,
    /** Copies marked "not duplicates": they stay quiet until one of them changes, and can be put back. */
    val notDuplicates: List<DuplicateClusterView>,
    /** Logins by how long since a person confirmed each still works, worst first. */
    val staleness: List<StalenessView>,
    /** Logins snoozed for now are listed too. */
    val showSnoozed: Boolean,
    /** The list is empty only because every login is snoozed. */
    val allSnoozed: Boolean,
    /** A breach scan is running: ranges done, of how many. */
    val scan: ScanProgressView?,
    /** A breach scan has run this session (another one is a rescan). */
    val scanned: Boolean,
    /** The outcome of the last action here, or why it was refused, in a sentence. */
    val message: String?,
    /** A login just marked as gone, offered for the trash. */
    val offerDelete: HealthOfferView?,
    /** A login just marked as refusing its password, offered to open or to give a new password. */
    val offerBad: HealthOfferView?,
    /** The check run, while it is on: the login it stands on. */
    val run: CheckRunView?,
)

/** The counts at the top, from the same rows the lists show. */
data class HealthTilesView(
    val logins: Int,
    val weak: Int,
    val reused: Int,
    /** Logins found in known breaches; null until a scan has a verdict for this vault. */
    val breached: Int?,
    /** What the Breached count can't say by itself ("run a scan", "incomplete"); null otherwise. */
    val breachedHint: String?,
    val duplicates: Int,
    val unchecked: Int,
    val failing: Int,
)

data class HealthPasswordView(
    val itemId: String,
    val name: String,
    /** Core's estimate, in words ("very weak" to "strong"). */
    val strength: String,
    /** Very weak or weak. */
    val weak: Boolean,
    /** How many other logins have this exact password. */
    val reused: Int,
    val hasTotp: Boolean,
    /** Known breaches of this password; null without a verdict (never scanned, its range failed, or it changed since). */
    val breaches: Long?,
)

data class DuplicateClusterView(
    /** The cluster's identity as constituted: its sorted member ids. */
    val signature: String,
    /** The sites the copies share. */
    val sites: String,
    /** The same password on every copy; otherwise one of them is out of date. */
    val exact: Boolean,
    /** Newest first. */
    val members: List<DuplicateMemberView>,
    /** An exact cluster that can be merged here: what the merge does, for its confirmation. Null otherwise. */
    val mergeConfirm: String?,
    /** Why an exact cluster can't be merged here; null when it can, or for copies with different passwords. */
    val mergeRefusal: String?,
)

data class DuplicateMemberView(
    val itemId: String,
    val name: String,
    val username: String,
    /** The vault the copy is in: whether removing it touches anyone else. */
    val vaultName: String,
    /** Copies with different passwords: what keeping this one does, for its confirmation. Null otherwise. */
    val keepConfirm: String?,
    /** Copies with different passwords: why this one can't be kept here, said at the first tap. Null otherwise. */
    val keepRefusal: String?,
)

data class StalenessView(
    val itemId: String,
    val name: String,
    val username: String,
    /** Where it stands, in words ("never checked", "last check failed: wrong password"). */
    val state: String,
    /** Its last check failed. */
    val failing: Boolean,
    /** When it was last used (as this account's devices recorded it) and last changed. */
    val dates: String,
    val snoozed: Boolean,
    val neverChecked: Boolean,
)

data class CheckRunView(
    val itemId: String,
    val name: String,
    val username: String,
    /** The saved site to sign in at; null when the login has none. */
    val site: String?,
    val hasPassword: Boolean,
    /** 1-based. */
    val position: Int,
    val total: Int,
)

data class HealthOfferView(val itemId: String, val name: String)

data class ScanProgressView(val done: Int, val total: Int)

/**
 * What the health screen holds while it is open, besides the vault itself. The breach verdicts are the controller's:
 * they outlive the screen, not the session.
 */
internal class HealthSession {
    var showSnoozed = false
    var message: String? = null
    var offerDelete: String? = null
    var offerBad: String? = null

    /** The check run: the logins it goes through, by id (the list re-sorts as verdicts land), and where it is. */
    var queue: List<String> = emptyList()
    var index = 0
    val running: Boolean get() = queue.isNotEmpty()

    var scan: ScanProgressView? = null

    /** The usage record, read once when the screen opens; empty when there is none (which ranks nothing differently). */
    var usage: Map<String, UsageLedger.Entry> = emptyMap()
}

/** The last breach scan of this session: verdicts by item, never by password, and the item revision each is about. */
internal class BreachVerdicts(val byItem: Map<String, Long>, val revs: Map<String, Long>, val incomplete: Boolean) {
    /** The verdicts that still hold: an item changed since the scan, or with a change still to sync, has none. */
    fun fresh(items: List<VaultItem>, pending: Set<String>): Map<String, Long> {
        val live = items.associate { it.itemId to it.rev }
        return byItem.filterKeys { id -> id !in pending && revs[id] != null && revs[id] == live[id] }
    }
}

/** The health screen from the vault's items and what the screen holds. Pure: the controller does the writing. */
internal fun healthView(
    h: HealthSession,
    items: List<VaultItem>,
    pending: Set<String>,
    breaches: BreachVerdicts?,
    roleFor: (String) -> String?,
    vaultName: (String) -> String,
    now: Long,
): HealthView {
    val rows = VaultHealth.healthRows(items)
    val summary = VaultHealth.summarize(rows)
    val fresh = breaches?.fresh(items, pending)
    val retired = breaches != null && fresh != null && breaches.byItem.keys.any { it !in fresh }
    val passwords = rows.sortedWith(compareByDescending<VaultHealth.HealthRow> { fresh?.get(it.itemId) ?: 0L }.thenBy { it.name })
        .map { r ->
            HealthPasswordView(
                itemId = r.itemId, name = r.name, strength = Strength.label(r.strength), weak = r.strength <= 1, reused = r.reused,
                hasTotp = r.hasTotp, breaches = fresh?.get(r.itemId),
            )
        }
    val breached = fresh?.let { m -> rows.count { (m[it.itemId] ?: 0L) > 0L } }

    val clusters = Duplicates.duplicateClusters(items, roleFor)
    val byId = items.associateBy { it.itemId }
    fun clusterView(c: Duplicates.DuplicateCluster): DuplicateClusterView {
        val ids = c.members.map { it.itemId }
        val merge = c.merge
        return DuplicateClusterView(
            signature = c.signature,
            sites = c.sites.joinToString(", "),
            exact = c.kind == Duplicates.Kind.EXACT,
            members = c.members.map { m ->
                val differs = c.kind == Duplicates.Kind.DIFFERS && !c.dismissed
                val others = c.members.filter { it.itemId != m.itemId }
                DuplicateMemberView(
                    itemId = m.itemId, name = m.name, username = m.username, vaultName = vaultName(m.vaultId),
                    keepConfirm = if (differs) HealthCopy.keepConfirm(m.name, vaultName(m.vaultId), others.size, others.map { vaultName(it.vaultId) }) else null,
                    // Asked with no clock: the preview never writes.
                    keepRefusal = if (differs) Duplicates.planKeep(items, ids, m.itemId, roleFor, 0).keepRefusal else null,
                )
            },
            mergeConfirm = merge?.let { p ->
                val survivor = byId[p.survivorId]
                HealthCopy.mergeConfirm(
                    survivor?.doc?.name?.ifEmpty { null } ?: HealthCopy.THIS_COPY, vaultName(survivor?.vaultId ?: ""), p.loserIds.size,
                    p.loserIds.mapNotNull { byId[it]?.vaultId }.map(vaultName),
                )
            },
            mergeRefusal = if (c.kind == Duplicates.Kind.EXACT) c.mergeRefusal else null,
        )
    }
    val open = clusters.filter { !it.dismissed }.map(::clusterView)
    val quiet = clusters.filter { it.dismissed }.map(::clusterView)

    val lastUsed = { id: String -> h.usage[id]?.lastUsedAt }
    val staleRows = Staleness.stalenessRows(items, Staleness.StalenessOptions(lastUsedAt = lastUsed, now = now, includeSnoozed = h.showSnoozed))
    // The tiles count snoozed-excluded rows whatever the toggle shows: it reveals rows, it never changes a count.
    val staleSummary = Staleness.stalenessSummary(
        if (h.showSnoozed) Staleness.stalenessRows(items, Staleness.StalenessOptions(lastUsedAt = lastUsed, now = now)) else staleRows,
    )
    val allSnoozed = staleRows.isEmpty() && !h.showSnoozed &&
        Staleness.stalenessRows(items, Staleness.StalenessOptions(lastUsedAt = lastUsed, now = now, includeSnoozed = true)).isNotEmpty()

    return HealthView(
        tiles = HealthTilesView(
            logins = summary.logins, weak = summary.weak, reused = summary.reused, breached = breached,
            breachedHint = when {
                breached == null -> HealthCopy.RUN_A_SCAN
                breaches?.incomplete == true || retired -> HealthCopy.INCOMPLETE
                else -> null
            },
            duplicates = open.size, unchecked = staleSummary.unchecked, failing = staleSummary.failing,
        ),
        passwords = passwords,
        duplicates = open,
        notDuplicates = quiet,
        staleness = staleRows.map { r ->
            StalenessView(
                itemId = r.itemId, name = r.name, username = r.username, state = HealthCopy.state(r),
                failing = r.bucket == Staleness.StaleBucket.FAILING,
                dates = "Last used " + (r.lastUsedAt?.let { HealthCopy.ago(it, now) } ?: "not recorded") + " · last changed " + HealthCopy.ago(r.updatedAt, now),
                snoozed = r.snoozed, neverChecked = r.bucket == Staleness.StaleBucket.NEVER,
            )
        },
        showSnoozed = h.showSnoozed,
        allSnoozed = allSnoozed,
        scan = h.scan,
        scanned = breaches != null,
        message = h.message,
        offerDelete = h.offerDelete?.let { id -> byId[id]?.let { HealthOfferView(id, it.doc.name.ifEmpty { HealthCopy.UNTITLED }) } },
        offerBad = h.offerBad?.let { id -> byId[id]?.let { HealthOfferView(id, it.doc.name.ifEmpty { HealthCopy.UNTITLED }) } },
        run = runView(h, items, now),
    )
}

/** The login the check run stands on, looked up fresh (snoozed included: a verdict made during the run can snooze it). */
private fun runView(h: HealthSession, items: List<VaultItem>, now: Long): CheckRunView? {
    if (!h.running) return null
    val id = h.queue.getOrNull(h.index) ?: return null
    val row = Staleness.stalenessRows(items, Staleness.StalenessOptions(now = now, includeSnoozed = true)).firstOrNull { it.itemId == id } ?: return null
    val password = items.firstOrNull { it.itemId == id }?.doc?.login?.password
    return CheckRunView(
        itemId = id, name = row.name, username = row.username, site = row.firstUri, hasPassword = !password.isNullOrEmpty(),
        position = h.index + 1, total = h.queue.size,
    )
}

/** What the health screen says (the Android app's sentences, in this app's words). */
internal object HealthCopy {
    const val UNTITLED = "(untitled)"
    const val THIS_COPY = "this copy"
    const val RUN_A_SCAN = "run a scan"
    const val INCOMPLETE = "incomplete"
    const val SCAN_FAILED = "The breach check couldn't reach the service, so nothing was checked. Try again later."
    const val SCAN_INCOMPLETE = "The breach check is incomplete: some passwords couldn't be checked and show no verdict. Check again to cover them."
    const val RUN_FINISHED = "Done: every login in the run has been looked at."
    const val BACK_ON_THE_LIST = "Back on the list."
    const val NOT_DUPLICATES = "Marked as not duplicates: these copies stay quiet unless one of them changes."
    const val NOT_EVERY_COPY = "Couldn't update every copy, so the group may come back until a try gets through. Try again."
    const val MERGE_DIDNT_FINISH = "The merge didn't finish: the kept copy is saved, and any copy already removed is in the trash. Check the group and try again."
    const val KEEP_DIDNT_FINISH = "That didn't finish: the kept copy is saved, and any copy already removed is in the trash. Check the group and try again."
    const val GROUP_CHANGED = "A copy changed under you. The list has been refreshed; try again."
    const val TRASHED = "Moved to the trash. It can be restored from there for 30 days."
    const val CHOOSE_RESULT = "Choose what happened when you signed in."

    /** What a person can say after signing in themselves: it worked, it refused the password, the account is gone, or
     *  they couldn't finish (which also snoozes the login for 30 days). */
    val CHECK_RESULTS = setOf("ok", "bad", "gone", "blocked")

    fun scanDone(breached: Int): String =
        "Breach check finished: " + (if (breached == 1) "1 login was" else "$breached logins were") + " found in known breaches."

    fun mergeConfirm(survivor: String, survivorVault: String, losers: Int, loserVaults: List<String>): String =
        "Keep “$survivor” in “$survivorVault” and move the other " + (if (losers == 1) "copy" else "$losers copies") +
            ", in “" + loserVaults.distinct().joinToString("”, “") + "”, to the trash, where they stay 30 days. The saved sites of every copy are kept."

    fun keepConfirm(keep: String, keepVault: String, others: Int, otherVaults: List<String>): String =
        "“$keep” stays in “$keepVault”. The other " + (if (others == 1) "copy" else "$others copies") + ", in “" +
            otherVaults.distinct().joinToString("”, “") + "”, go" + (if (others == 1) "es" else "") +
            " to the trash for 30 days, and " + (if (others == 1) "its password stays" else "their passwords stay") + " in the kept login's password history."

    fun merged(losers: Int): String =
        "Merged: " + (if (losers == 1) "the other copy is" else "the other $losers copies are") + " in the trash for 30 days."

    fun kept(losers: Int): String =
        "Kept one copy: " + (if (losers == 1) "the other is" else "the other $losers are") +
            " in the trash for 30 days, and " + (if (losers == 1) "its password is" else "their passwords are") + " in the kept login's password history."

    /** Where a login stands, in words; the wire names of core's buckets are never shown. */
    fun state(r: Staleness.StalenessRow): String = when (r.bucket) {
        Staleness.StaleBucket.FAILING -> when (r.check?.result) {
            "bad" -> "Last check failed: wrong password"
            "gone" -> "Last check failed: the account is gone"
            "blocked" -> "Last check couldn't be finished"
            else -> "Last check failed"
        }
        Staleness.StaleBucket.NEVER -> "Never checked"
        Staleness.StaleBucket.OVER_YEAR -> "Not checked in over a year"
        Staleness.StaleBucket.SIX_TO_TWELVE -> "Not checked in 6 to 12 months"
        Staleness.StaleBucket.RECENT -> if (r.check?.result == "ok") "Checked recently: it worked" else "Checked recently"
    } + (if (r.snoozed) " · snoozed" else "")

    /** A day count in words, as the Android app says it. */
    fun ago(at: Long, now: Long): String {
        val days = ((now - at) / Staleness.DAY_MS).coerceAtLeast(0)
        return when {
            days == 0L -> "today"
            days == 1L -> "yesterday"
            days < 60L -> "$days days ago"
            days < 730L -> "${days / 30} months ago"
            else -> "${days / 365} years ago"
        }
    }
}
