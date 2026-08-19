package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/**
 * Owner dev-note 2026-08-18: the vault list's sort + facet transform (web's listview.test.ts
 * twin) — facets subset without re-ordering, "name" never re-sorts (the engine's alphabetical
 * order is the contract), "recent" is updatedAt desc with the incoming order as the stable
 * tiebreak. Pure core object shared by Android and desktop, so plain kotlin.test in
 * commonTest (the CardDisplayTest idiom).
 */
class VaultListViewTest {

    private fun item(id: String, type: String, updatedAt: Long, vaultId: String = "v1") = VaultItem(
        itemId = id,
        vaultId = vaultId,
        rev = 1,
        updatedAt = updatedAt,
        doc = if (type == "login") ItemDoc(type = type, name = id, login = LoginData(username = "u", password = "p"))
        else ItemDoc(type = type, name = id, notes = "n"),
    )

    // Alphabetical by construction — the SyncEngine.items() contract this transform leans on.
    private val items = listOf(
        item("alpha", "login", 300),
        item("bravo", "note", 100, "v2"),
        item("carol", "card", 300),
        item("delta", "login", 200, "v2"),
    )

    @Test
    fun defaultViewPassesTheSameListThrough() {
        assertSame(items, VaultListView.apply(items, "name", "all", "all"))
    }

    @Test
    fun typeFacetSubsetsWithoutReordering() {
        assertEquals(listOf("alpha", "delta"), VaultListView.apply(items, "name", "login", "all").map { it.itemId })
    }

    @Test
    fun vaultFacetComposesWithTheTypeFacet() {
        assertEquals(listOf("bravo", "delta"), VaultListView.apply(items, "name", "all", "v2").map { it.itemId })
        assertEquals(listOf("delta"), VaultListView.apply(items, "name", "login", "v2").map { it.itemId })
    }

    @Test
    fun recentIsUpdatedAtDescWithTheIncomingOrderAsStableTiebreak() {
        assertEquals(listOf("alpha", "carol", "delta", "bravo"), VaultListView.apply(items, "recent", "all", "all").map { it.itemId })
    }
}
