package io.silencelen.andvari.core.client

/**
 * Pure planning helpers for the spec 07 export flows (Backup + CSV) — the ONE copy both
 * JVM natives compile (F82: the per-app "identical twins" had already drifted; android
 * grew [BackupRequest] in B8, desktop didn't). Deliberately thin over Export.kt, which
 * is platform-free and takes already-ordered docs / already-fetched plaintexts —
 * ordering, vault enumeration and the §2.5 attachment cap live HERE. Reads go through
 * [SyncEngine]'s read-only surface ([SyncEngine.envelopes]/[SyncEngine.vaultRows]),
 * never a carried reference to the engine's private cache (a close-ordering hazard).
 * Web's plan.ts stays its own copy — inherent to the non-KMP stack.
 */

/** One vault line in the export preflight (name decrypted client-side, never sent anywhere). */
data class ExportVault(
    val vaultId: String,
    val type: String, // "personal" | "shared"
    val name: String,
    val role: String,
    val itemCount: Int,
)

/** Preflight for "Back up vault…" (spec 07 §2). [offlineNote] non-null when the
 *  pre-export sync failed and the snapshot is "vault as of last sync". */
data class BackupPreflight(
    val vaults: List<ExportVault>,
    val offlineNote: String?,
)

/** Preflight for "Export for another password manager…" (spec 07 §1). */
data class CsvPreflight(
    val warnings: ExportCsv.Warnings,
    val loginCount: Int,
    val offlineNote: String?,
)

/**
 * A confirmed backup preflight, pending its destination pick. Held in the app's state
 * holder (Android: the ViewModel, NOT Compose `remember`) so a configuration change —
 * Fold unfold / rotation / split-screen resize — while the system picker is foreground
 * doesn't drop it and silently no-op the launcher result (leaving an empty file).
 * Holding the passphrase there is acceptable: the vault is unlocked, so its keys are
 * already in process memory; it is never written to SavedState/disk.
 */
data class BackupRequest(
    val vaults: Set<String>,
    val includeAttachments: Boolean,
    val passphrase: String,
)

/** Post-backup summary for the success dialog (named skips per spec — never counts only). */
data class BackupResult(
    val items: Int,
    val vaults: Int,
    val attachments: Int,
    val attachmentsOverCap: List<String>,
    val attachmentFetchFailed: List<String>,
)

data class PlannedAttachment(val item: VaultItem, val ref: AttachmentRef)

/** §2.5 attachment plan: what fits under the 64 MiB total-plaintext cap, plus the
 *  names of whatever does not (skipped BY NAME, spec 07 §2.5). */
data class AttachmentPlan(
    val included: List<PlannedAttachment>,
    val totalBytes: Long,
    val overCap: List<String>,
)

object ExportPlanner {
    /**
     * The pinned "vault order" (spec 07 §1/§2.4 determinism): the personal vault first,
     * then shared vaults by decrypted name (case-insensitive) then vaultId. Only vaults
     * whose VK is held are listed — those are the ones export can include at all.
     */
    fun vaultLines(engine: SyncEngine, account: Account): List<ExportVault> {
        val counts = engine.items().groupingBy { it.vaultId }.eachCount()
        val known = engine.vaultRows().filter { account.hasVault(it.vaultId) }.map { v ->
            ExportVault(
                vaultId = v.vaultId,
                type = v.type,
                name = account.decryptVaultName(v.vaultId, v.metaBlob) ?: v.vaultId.take(8),
                role = account.roleFor(v.vaultId) ?: if (v.vaultId == account.personalVaultId) "owner" else "member",
                itemCount = counts[v.vaultId] ?: 0,
            )
        }
        // Defensive: a decrypted item whose vault row hasn't landed yet still exports.
        val missing = counts.keys.filter { id -> known.none { it.vaultId == id } }.map { id ->
            ExportVault(
                vaultId = id,
                type = if (id == account.personalVaultId) "personal" else "shared",
                name = id.take(8),
                role = account.roleFor(id) ?: "member",
                itemCount = counts[id] ?: 0,
            )
        }
        return (known + missing).sortedWith(
            compareBy({ it.vaultId != account.personalVaultId }, { it.name.lowercase() }, { it.vaultId }),
        )
    }

    /** Items in export order (spec 07 §1): [vaultOrder] position, then updatedAt, then
     *  itemId as the final deterministic tiebreak. Vaults not in [vaultOrder] are excluded. */
    fun orderedItems(engine: SyncEngine, vaultOrder: List<String>): List<VaultItem> {
        val pos = vaultOrder.withIndex().associate { (i, id) -> id to i }
        return engine.items()
            .filter { it.vaultId in pos }
            .sortedWith(compareBy({ pos[it.vaultId] }, { it.updatedAt }, { it.itemId }))
    }

    /** Greedy §2.5 plan over [items] (already in export order): every attachment that
     *  would push the total embedded plaintext past 64 MiB is skipped by name. */
    fun planAttachments(items: List<VaultItem>): AttachmentPlan {
        val included = ArrayList<PlannedAttachment>()
        val overCap = ArrayList<String>()
        var total = 0L
        for (item in items) for (ref in item.doc.attachments) {
            if (total + ref.size > Backup.MAX_TOTAL_ATTACHMENT_PLAINTEXT) {
                overCap.add(ref.name)
            } else {
                included.add(PlannedAttachment(item, ref))
                total += ref.size
            }
        }
        return AttachmentPlan(included, total, overCap)
    }

    /**
     * §2.4 skipped.undecryptable: persisted envelopes with no decrypted twin — a missing
     * VK or a newer formatVersion (spec 02 §3 fail-closed); the cache keeps the envelope
     * and hydrate() retries, which is exactly the surface export enumerates from.
     */
    fun undecryptable(engine: SyncEngine): List<BackupSkippedItem> =
        engine.envelopes()
            .filter { !it.deleted && engine.item(it.itemId) == null }
            .map { BackupSkippedItem(it.itemId, it.vaultId, it.formatVersion) }
}
