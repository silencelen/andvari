package io.silencelen.andvari.core.client

/**
 * The vault list's sort + facet transform, shared by the native clients — the Kotlin twin of
 * web/src/ui/listview.ts (owner dev-note 2026-08-18): facets subset, then sort. "name"
 * preserves the engine's alphabetical order (SyncEngine.items() already sorts by name — a
 * re-sort here would shadow that contract); "recent" is updatedAt desc, stable so equal
 * stamps keep the alphabetical order. "all" is the sentinel for both facets. Pure and
 * Compose-free, so VaultListViewTest pins it from commonTest without any UI runtime.
 */
object VaultListView {
    fun apply(items: List<VaultItem>, sort: String, type: String, vaultId: String): List<VaultItem> {
        var out = items
        if (type != "all") out = out.filter { it.doc.type == type }
        if (vaultId != "all") out = out.filter { it.vaultId == vaultId }
        if (sort == "recent") out = out.sortedByDescending { it.updatedAt }
        return out
    }
}
