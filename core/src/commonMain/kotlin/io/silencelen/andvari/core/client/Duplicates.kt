package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.autofill.Psl
import io.silencelen.andvari.core.client.autofill.PslResult
import io.silencelen.andvari.core.client.autofill.SavedUri
import io.silencelen.andvari.core.client.autofill.UriMatch

/**
 * Duplicate-entry detection + the guided-merge plan — the Kotlin twin of
 * `web/src/ui/duplicates.ts` (owner-requested 2026-08-12; ported to the native clients by
 * `docs/design/2026-08-23-android-vault-health.md`).
 *
 * Two ways the vault legitimately grows duplicates, both by DESIGN elsewhere: the extension's
 * locked-at-capture save records a recoverable NEW item rather than risking the 2b clobber, and
 * importers mint renamed copies rather than corrupting an uncertain match. This module is the
 * other half of those bargains: find the copies and offer the safe consolidation.
 *
 * Pure and exposed for pinning (the [Staleness] idiom): clustering, survivor choice and the
 * merge plan are all decided HERE; the screens only render and write.
 *
 * Clustering: LOGIN items group when they share a SITE key (the registrable domain of any saved
 * web uri — the same eTLD+1 authority autofill matching uses; a host the PSL can't resolve
 * keys as the normalized host itself, and `androidapp://` uris key as the package) AND the same
 * normalized username (trim + lowercase — display keeps the exact strings). Transitive: an item
 * saved for both example.com and example.co.uk bridges its two site-mates into one cluster.
 * Items with NO resolvable site key never cluster — without a site, equal credentials could
 * still be different accounts.
 *
 * [Kind.EXACT] = every member's password is byte-identical (the mergeable tier). [Kind.DIFFERS]
 * = same site + username but diverging passwords: one of them is stale. Members are newest-first
 * so the UI can say which. Never auto-merged — only the human knows which password the site
 * accepts.
 *
 * VAULTS (audit F03). Clustering deliberately spans vaults — the app MINTS cross-vault twins by
 * design — so hiding them would hide the duplicates a household is most likely to have. But a
 * merge across a sharing boundary deletes the OTHER members' copy: report the cluster, refuse
 * the merge. A view-only (reader) vault refuses too: neither the survivor's save nor a loser's
 * remove would be allowed, and a half-completed merge is the worst outcome of all.
 */
object Duplicates {

    enum class Kind { EXACT, DIFFERS }

    data class DuplicateMember(
        val itemId: String,
        val vaultId: String,
        val name: String,
        /** Exact stored username (clustering normalizes; display must not). */
        val username: String,
        val updatedAt: Long,
        val hasTotp: Boolean,
        /** The member's first saved WEB uri, verbatim — the "open site" affordance for the
         *  differs resolution flow: the only honest password test is the human logging in; the
         *  client must never probe a site with candidate credentials itself. */
        val firstUri: String? = null,
    )

    /** The ready-to-write consolidation for an ELIGIBLE exact cluster: save [doc] over the
     *  survivor, then remove the losers (they land in Deleted items — the 30-day Trash — so a
     *  wrong merge is recoverable). [doc] is composed HERE so the tests pin what ships. */
    data class MergePlan(
        val survivorId: String,
        val loserIds: List<String>,
        val doc: ItemDoc,
    )

    data class DuplicateCluster(
        /** Display: the site keys the members share (union, sorted). */
        val sites: List<String>,
        /** Members newest-first — for DIFFERS, the first is the copy most likely current. */
        val members: List<DuplicateMember>,
        val kind: Kind,
        /** Exact clusters: the plan, or (exclusively) the human-readable refusal. */
        val merge: MergePlan? = null,
        val mergeRefusal: String? = null,
        /** Identity of the cluster AS CONSTITUTED — the dismissal token. */
        val signature: String,
        /** Every member carries this signature as its `dupeAck`: the user said "not duplicates". */
        val dismissed: Boolean,
    )

    // Refusal copy, verbatim from duplicates.ts — user-facing strings; the twin must not
    // paraphrase them.
    private const val REFUSAL_CROSS_VAULT = "These copies are in different vaults — merge by hand."
    private const val REFUSAL_READER =
        "These copies are in a vault you can only view — ask the vault's owner to merge them."
    private const val REFUSAL_TOTP = "The copies carry different one-time codes — merge by hand."
    private const val REFUSAL_NOTES = "The copies carry different notes — merge by hand."
    private const val REFUSAL_ATTACHMENTS_MANY = "More than one copy has attachments — merge by hand."
    private const val REFUSAL_SPLIT = "The copies each hold data the others lack — merge by hand."
    private const val REFUSAL_STALE = "A copy changed under you — the list refreshes on its own; try again."
    private const val REFUSAL_KEEP_ATTACHMENTS = "A copy being removed has attachments — merge by hand."
    private const val REFUSAL_DISMISS_READER =
        "These copies are in a vault you can only view — ask the vault's owner."

    /** The dismissal token: the cluster's sorted member ids. Any membership change — a new copy
     *  minted, one merged away — changes the signature, so an old acknowledgment stops matching
     *  and the cluster resurfaces. Joined with "|": itemIds are server-assigned identifiers, so
     *  the delimiter has no forgery surface (unlike the username NUL below). */
    fun clusterSignature(memberIds: List<String>): String = memberIds.sorted().joinToString("|")

    /** Site keys for one login item (exposed for the tests). */
    fun siteKeysOf(doc: ItemDoc): Set<String> {
        val out = LinkedHashSet<String>()
        for (raw in doc.login?.uris ?: emptyList()) {
            when (val saved = UriMatch.parseSavedUri(raw)) {
                null -> continue
                is SavedUri.AndroidApp -> out.add("app:${saved.pkg}")
                is SavedUri.Web -> {
                    val r = Psl.resolve(saved.host)
                    out.add(if (r is PslResult.Registrable) r.domain else saved.host)
                }
            }
        }
        return out
    }

    private fun normUser(doc: ItemDoc): String = (doc.login?.username ?: "").trim().lowercase()

    /**
     * Survivor + plan for an EXACT cluster, or the refusal. Fail-closed: the survivor must carry
     * every distinct piece of member data (the one one-time code, the one notes text, and the
     * attachments if any single member holds them) — data split across copies, or diverging
     * values, refuses rather than quietly dropping anything. Losers' uris are unioned onto the
     * survivor (raw-string dedupe, survivor's order first) and `favorite` survives if ANY copy
     * had it. Everything else (passwordHistory, unknown extras-overlay fields) stays the
     * survivor's own — the losers go to the Trash intact, not into oblivion.
     */
    private fun planMerge(members: List<VaultItem>, roleFor: (String) -> String?): Pair<MergePlan?, String?> {
        // audit F03, first: a cluster that spans vaults is REPORT-ONLY. Merging one would delete
        // a copy out of a shared vault — from every other member's devices, with the household
        // never told — for a "duplicate" whose whole point is that it lives in two places.
        if (members.map { it.vaultId }.toSet().size > 1) return null to REFUSAL_CROSS_VAULT
        // audit F03: a reader can be neither survivor (the save is denied) nor loser (the remove
        // is denied and the merge half-completes). The cluster shares ONE vault by the check
        // above, so this refuses the WHOLE merge rather than a subset — the filter is what
        // guarantees no reader-held item can reach `loserIds`.
        val writable = members.filter { roleFor(it.vaultId) != "reader" }
        if (writable.size < members.size || writable.size < 2) return null to REFUSAL_READER

        val docs = members.map { it.doc }
        val totps = docs.map { it.login?.totp ?: "" }.filter { it.isNotEmpty() }.distinct()
        if (totps.size > 1) return null to REFUSAL_TOTP
        val notes = docs.map { (it.notes ?: "").trim() }.filter { it.isNotEmpty() }.distinct()
        if (notes.size > 1) return null to REFUSAL_NOTES
        val withAttachments = members.filter { it.doc.attachments.isNotEmpty() }
        if (withAttachments.size > 1) return null to REFUSAL_ATTACHMENTS_MANY

        // Candidates: newest-first members that carry every distinct datum found above.
        val sorted = members.sortedByDescending { it.updatedAt }
        val candidates = sorted.filter { m ->
            if (totps.size == 1 && (m.doc.login?.totp ?: "") != totps[0]) return@filter false
            if (notes.size == 1 && (m.doc.notes ?: "").trim() != notes[0]) return@filter false
            if (withAttachments.size == 1 && m.itemId != withAttachments[0].itemId) return@filter false
            true
        }
        val survivor = candidates.firstOrNull() ?: return null to REFUSAL_SPLIT

        val losers = sorted.filter { it.itemId != survivor.itemId }
        val uris = unionUris(survivor.doc, losers)
        val favorite = docs.any { it.favorite }
        var doc = survivor.doc.copy(login = (survivor.doc.login ?: LoginData()).copy(uris = uris))
        if (favorite) doc = doc.copy(favorite = true)
        return MergePlan(survivor.itemId, losers.map { it.itemId }, doc) to null
    }

    /** Losers' uris onto the survivor: raw-string dedupe, the survivor's own order first, then
     *  the others' in the order given (newest-first at both call sites) — planMerge's original
     *  rule, shared with [planKeep] so the two consolidations can never drift. */
    private fun unionUris(survivorDoc: ItemDoc, others: List<VaultItem>): List<String> {
        val uris = ArrayList(survivorDoc.login?.uris ?: emptyList())
        val seen = HashSet(uris)
        for (m in others) {
            for (u in m.doc.login?.uris ?: emptyList()) {
                if (seen.add(u)) uris.add(u)
            }
        }
        return uris
    }

    data class KeepPlan(val keep: MergePlan? = null, val keepRefusal: String? = null)

    /**
     * "Keep this one" for a DIFFERS cluster: the human tested which password the site currently
     * accepts and picked the survivor; retire the rest. Same fail-closed shape as [planMerge] —
     * cross-vault and view-only clusters refuse, and data only a loser holds (a diverging
     * one-time code, diverging notes, any attachments) refuses rather than quietly riding into
     * the Trash's 30-day window.
     *
     * The losers' PASSWORDS are the deliberate exception — they are what this flow exists to not
     * lose: every distinct one is appended to the survivor's `passwordHistory` at the caller's
     * [retiredAt] clock (passed in — this module stays pure), so even a wrong pick outlives the
     * Trash purge. **This is `passwordHistory`'s first and only writer** (spec 02 §3).
     *
     * Docs are looked up FRESH from [items] by id — a rendered cluster snapshot must never write
     * stale docs.
     */
    fun planKeep(
        items: List<VaultItem>,
        memberIds: List<String>,
        keepId: String,
        roleFor: (String) -> String?,
        retiredAt: Long,
    ): KeepPlan {
        val members = memberIds.mapNotNull { id -> items.firstOrNull { it.itemId == id } }
        val survivor = members.firstOrNull { it.itemId == keepId }
        if (members.size != memberIds.size || members.size < 2 || survivor == null) {
            return KeepPlan(keepRefusal = REFUSAL_STALE)
        }
        if (members.map { it.vaultId }.toSet().size > 1) return KeepPlan(keepRefusal = REFUSAL_CROSS_VAULT)
        if (members.any { roleFor(it.vaultId) == "reader" }) return KeepPlan(keepRefusal = REFUSAL_READER)

        val losers = members.filter { it.itemId != keepId }.sortedByDescending { it.updatedAt }
        val sTotp = survivor.doc.login?.totp ?: ""
        if (losers.any { (it.doc.login?.totp ?: "").isNotEmpty() && (it.doc.login?.totp ?: "") != sTotp }) {
            return KeepPlan(keepRefusal = REFUSAL_TOTP)
        }
        val sNotes = (survivor.doc.notes ?: "").trim()
        if (losers.any { val n = (it.doc.notes ?: "").trim(); n.isNotEmpty() && n != sNotes }) {
            return KeepPlan(keepRefusal = REFUSAL_NOTES)
        }
        if (losers.any { it.doc.attachments.isNotEmpty() }) return KeepPlan(keepRefusal = REFUSAL_KEEP_ATTACHMENTS)

        val have = HashSet<String>()
        have.add(survivor.doc.login?.password ?: "")
        (survivor.doc.login?.passwordHistory ?: emptyList()).forEach { have.add(it.password) }
        val retired = ArrayList<PasswordHistoryEntry>()
        for (m in losers) {
            val pw = m.doc.login?.password ?: ""
            if (pw.isNotEmpty() && have.add(pw)) retired.add(PasswordHistoryEntry(password = pw, retiredAt = retiredAt))
        }
        var doc = survivor.doc.copy(
            login = (survivor.doc.login ?: LoginData()).copy(
                uris = unionUris(survivor.doc, losers),
                passwordHistory = (survivor.doc.login?.passwordHistory ?: emptyList()) + retired,
            ),
        )
        if (members.any { it.doc.favorite }) doc = doc.copy(favorite = true)
        return KeepPlan(keep = MergePlan(keepId, losers.map { it.itemId }, doc))
    }

    data class DismissPlan(
        val writes: List<Staleness.PlannedWrite>? = null,
        val dismissRefusal: String? = null,
    )

    /** "Not duplicates — keep both": stamp every member with the cluster's signature. A write
     *  per member — so a view-only vault refuses — but a CROSS-vault cluster is fine: unlike a
     *  merge, nothing is removed from anywhere, which makes this the quiet ending for the
     *  deliberate cross-vault twins [planMerge] refuses to touch. An empty [signature] clears
     *  the acknowledgment (un-dismiss) by dropping the key, never writing it blank. Fresh-doc
     *  lookup by id, as in [planKeep]. */
    fun planDismiss(
        items: List<VaultItem>,
        memberIds: List<String>,
        signature: String,
        roleFor: (String) -> String?,
    ): DismissPlan {
        val members = memberIds.mapNotNull { id -> items.firstOrNull { it.itemId == id } }
        if (members.size != memberIds.size) return DismissPlan(dismissRefusal = REFUSAL_STALE)
        if (members.any { roleFor(it.vaultId) == "reader" }) return DismissPlan(dismissRefusal = REFUSAL_DISMISS_READER)
        return DismissPlan(
            writes = members.map { m ->
                Staleness.PlannedWrite(m.itemId, m.doc.copy(dupeAck = signature.ifEmpty { null }))
            },
        )
    }

    fun duplicateClusters(items: List<VaultItem>, roleFor: (String) -> String?): List<DuplicateCluster> {
        val logins = items
            .filter { it.doc.type == "login" }
            .map { Entry(it, siteKeysOf(it.doc), normUser(it.doc)) }
            .filter { it.sites.isNotEmpty() }

        // Union-find over shared (site, username) keys — transitive by design (see class KDoc).
        val parent = HashMap<Int, Int>()
        fun find(i: Int): Int {
            var r = i
            while (parent[r] != r) r = parent[r]!!
            parent[i] = r
            return r
        }
        fun union(a: Int, b: Int) { parent[find(a)] = find(b) }
        logins.indices.forEach { parent[it] = it }
        val byKey = HashMap<String, Int>()
        logins.forEachIndexed { i, m ->
            for (site in m.sites) {
                // A NUL separator so a username containing the delimiter cannot forge a
                // different item's key. Written as the ESCAPE, never a literal 0x00: a raw NUL
                // makes git treat the whole file as binary, and a security-relevant module
                // nobody can diff or blame is a worse problem than the one it solves.
                val key = "$site\u0000${m.user}"
                val first = byKey[key]
                if (first == null) byKey[key] = i else union(i, first)
            }
        }

        val groups = LinkedHashMap<Int, MutableList<Entry>>()
        logins.forEachIndexed { i, m -> groups.getOrPut(find(i)) { ArrayList() }.add(m) }

        val clusters = ArrayList<DuplicateCluster>()
        for (members in groups.values) {
            if (members.size < 2) continue
            val sorted = members.sortedByDescending { it.it.updatedAt }
            val passwords = sorted.map { it.it.doc.login?.password ?: "" }.toSet()
            val kind = if (passwords.size == 1) Kind.EXACT else Kind.DIFFERS
            val signature = clusterSignature(members.map { it.it.itemId })
            val planned = if (kind == Kind.EXACT) planMerge(members.map { it.it }, roleFor) else null to null
            clusters.add(
                DuplicateCluster(
                    sites = members.flatMap { it.sites }.distinct().sorted(),
                    members = sorted.map { e ->
                        DuplicateMember(
                            itemId = e.it.itemId,
                            vaultId = e.it.vaultId,
                            name = e.it.doc.name.ifEmpty { "(untitled)" },
                            username = e.it.doc.login?.username ?: "",
                            updatedAt = e.it.updatedAt,
                            hasTotp = !e.it.doc.login?.totp.isNullOrEmpty(),
                            firstUri = (e.it.doc.login?.uris ?: emptyList())
                                .firstOrNull { u -> UriMatch.parseSavedUri(u) is SavedUri.Web },
                        )
                    },
                    kind = kind,
                    merge = planned.first,
                    mergeRefusal = planned.second,
                    signature = signature,
                    // Dismissed only while EVERY member acknowledges exactly this constitution
                    // of the cluster — one new/changed member id breaks the match and it
                    // resurfaces.
                    dismissed = members.all { it.it.doc.dupeAck == signature },
                ),
            )
        }
        // Exact (mergeable) clusters first, then by site for a stable render.
        return clusters.sortedWith { a, b ->
            if (a.kind == b.kind) (a.sites.firstOrNull() ?: "").compareTo(b.sites.firstOrNull() ?: "")
            else if (a.kind == Kind.EXACT) -1 else 1
        }
    }

    private data class Entry(val it: VaultItem, val sites: Set<String>, val user: String)
}
