package io.silencelen.andvari.desktop.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * "Also used by …" under a login whose password other logins share, on the vault list and on the Health page: the line
 * for one where one other login shares it, the line for several otherwise, with the count.
 */
class ReusedCountTest {
    @Test
    fun oneOtherLoginHasTheLineForOneAndTwoHaveTheLineForSeveral() {
        val one = reusedLine(1) as UiText.Ph
        assertEquals(Placeholder.HEALTH_REUSED_ONE, one.placeholder)
        assertEquals(emptyList(), one.args)
        val two = reusedLine(2) as UiText.Ph
        assertEquals(Placeholder.HEALTH_REUSED, two.placeholder)
        assertEquals(listOf("2"), two.args)
        println("REUSED|1|${one.shown()}|2|${two.shown()}")
    }

    @Test
    fun bothPlacesThatSayItChooseByTheCount() {
        val items = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultItemsScreens.kt").readText()
        val health = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultHealthScreens.kt").readText()
        assertTrue(items.contains("Say(reusedLine(h.reused)"))
        assertTrue(health.contains("reusedLine(p.reused).shown().takeIf { p.reused > 0 }"))
        for (src in listOf(items, health)) assertTrue(!src.contains("Placeholder.HEALTH_REUSED,"), "no place forms the line for several by itself")
    }
}
