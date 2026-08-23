package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.VaultHealth.healthRows
import io.silencelen.andvari.core.client.VaultHealth.summarize
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The Kotlin twin of the PURE half of `web/src/ui/health-rows.test.ts` (design 2026-08-23 §10).
 *
 * The web file's remaining blocks grep `Health.tsx` / `Vault.tsx` for memo dependency lists and
 * rendering obligations — React wiring pins with no Kotlin analogue. The Android screen's
 * equivalent obligations belong to its own tests, not here.
 */
class VaultHealthTest {
    private fun login(
        itemId: String,
        password: String,
        totp: String? = null,
        name: String = itemId,
    ): VaultItem = VaultItem(
        itemId = itemId,
        vaultId = "v1",
        rev = 1,
        updatedAt = 0,
        doc = ItemDoc(
            type = "login",
            name = name,
            login = LoginData(username = "u", password = password, totp = totp),
        ),
    )

    @Test
    fun keepsOnlyLoginsWithPasswords_andFlagsReuseAcrossTheRest() {
        val items = listOf(
            login("a", "correct horse battery staple"),
            login("b", "hunter2"),
            login("c", "hunter2", totp = "otpauth://totp/x?secret=GEZDGNBV"),
            login("d", ""), // password-less login — not a health row
            VaultItem("n", "v1", 1, 0, ItemDoc(type = "note", name = "note", notes = "x")),
        )
        val rows = healthRows(items)
        assertEquals(listOf("a", "b", "c"), rows.map { it.itemId })
        assertEquals(0, rows.first { it.itemId == "a" }.reused)
        assertEquals(1, rows.first { it.itemId == "b" }.reused) // one OTHER item shares it
        assertTrue(rows.first { it.itemId == "c" }.hasTotp)
        assertEquals(false, rows.first { it.itemId == "b" }.hasTotp)
    }

    @Test
    fun aChangedPasswordLandsInTheNextDerivation() {
        val before = healthRows(listOf(login("a", "hunter2")))
        val after = healthRows(listOf(login("a", "correct horse battery staple")))
        assertTrue(after.first { it.itemId == "a" }.strength > before.first { it.itemId == "a" }.strength)
    }

    @Test
    fun anUntitledLoginStillGetsADisplayName() {
        assertEquals("(untitled)", healthRows(listOf(login("a", "pw", name = "")))[0].name)
    }

    @Test
    fun summaryCountsComeFromTheSameRowsTheListShows() {
        val rows = healthRows(
            listOf(
                login("weak1", "aaa"),
                login("weak2", "aaa"),
                login("strong", "correct horse battery staple"),
            ),
        )
        // "aaa" is shared by two items, so both count as reused; both are also weak.
        assertEquals(VaultHealth.HealthSummary(logins = 3, weak = 2, reused = 2), summarize(rows))
    }
}
