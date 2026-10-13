package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.VaultInfo
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A, branch A5c (API review LOW item 7): the Settings "Personal vault"
 * card used to pick `choices.firstOrNull { it.type == "personal" }`. Core derives `VaultInfo.type` from the
 * wrap-decided `Account.personalVaultId` (SyncEngine.vaultInfos, A5), so the label was already not the
 * server's — but the card has the wrap-decided id itself, and a display that follows the id cannot regress if
 * `type` ever becomes a copied label again. Web reads `personalVaultId` the same way.
 */
class PersonalVaultCardTest {

    private val source = File("src/main/kotlin/io/silencelen/andvari/app/HouseholdScreen.kt").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    @Test
    fun theCardFollowsTheWrapDecidedPersonalVaultIdNotTheTypeLabel() {
        // A hand-built list whose `type` label disagrees with the id: the card must side with the id.
        val choices = listOf(
            VaultInfo("v-family", "personal", "Family", "owner"),
            VaultInfo("v-mine", "shared", "Mine", "owner"),
        )
        assertEquals("v-mine", personalVaultCardCurrent(choices, "v-mine")?.vaultId)
        assertNull(personalVaultCardCurrent(choices, ""), "no confirmed personal vault ⇒ 'isn't confirmed yet', whatever a label says")
        assertNull(personalVaultCardCurrent(choices, "v-elsewhere"), "a personal vault not among the choices is not shown as one of them")
    }

    @Test
    fun theCardReadsTheIdThroughTheHelper() {
        assertTrue(source.contains("personalVaultCardCurrent(choices, vm.personalVaultId())"), "PersonalVaultCard must select by the wrap-decided id")
        assertFalse(source.contains("choices.firstOrNull { it.type == \"personal\" }"), "…never by the type label")
    }
}
