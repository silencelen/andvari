package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.SpaceVerdict
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared code says about the account's space, on the screens: the import's own line when it does not fit, the
 * line for a copy that goes on on stated sizes, and Settings' four meters. Against the fake's switches.
 */
class SpaceAndStorageTest {
    private val csv = "name,url,username,password,note\nGH,https://gh.test,jordan,pw,hi\nNT,https://n.test,ana,pw2,\n".encodeToByteArray()

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun anImportThatDoesNotFitSaysSoUnderItsPlan() = runBlocking<Unit> {
        val c = FakeVaultContent()
        c.setRoomLeft(1L shl 40, 0, 0)
        assertEquals(ActionResult.Ok, c.importCsv(csv.copyOf()))
        val space = assertNotNull(c.state.space)
        assertEquals(SpaceVerdict.NOT_ENOUGH, space.verdict)
        assertEquals(UiText.of(assertNotNull(space.line)).shown(), assertNotNull(importSpaceLine(c.state)).shown())
        assertNull(declaredSpaceLine(c.state), "not the stated-sizes line")
        assertTrue("importSpaceLine(state)" in src("VaultTransferScreens.kt"))
    }

    @Test
    fun anImportThatFitsOrAnUnknownSpaceSaysNothing() = runBlocking<Unit> {
        val roomy = FakeVaultContent()
        roomy.setRoomLeft(1L shl 40, 100, 5)
        roomy.importCsv(csv.copyOf())
        assertNull(importSpaceLine(roomy.state))
        val unknown = FakeVaultContent()
        unknown.importCsv(csv.copyOf())
        assertNull(unknown.state.space)
        assertNull(importSpaceLine(unknown.state))
        assertNull(declaredSpaceLine(unknown.state))
    }

    @Test
    fun settingsShowsTheFourMetersOrNothing() {
        val none = FakeVaultContent()
        assertNull(none.state.storage, "an older server gives none: Settings shows nothing")
        val c = FakeVaultContent()
        c.setRoomLeft(5000, 90, 2)
        val rows = storageRows(assertNotNull(c.state.storage))
        assertEquals(
            listOf(Placeholder.STORAGE_BYTES, Placeholder.STORAGE_ITEMS, Placeholder.STORAGE_SHARED_VAULTS, Placeholder.STORAGE_LINKS),
            rows.map { it.first },
        )
        assertEquals(listOf(1000L to 6000L, 10L to 100L, 1L to 3L, 2L to 20L), rows.map { it.second.used to it.second.limit })
        assertEquals(sizeText(6000), meterText(Placeholder.STORAGE_BYTES, 6000))
        assertEquals("100", meterText(Placeholder.STORAGE_ITEMS, 100))
        val settings = src("SettingsScreens.kt")
        assertTrue(settings.indexOf("StorageSection(model)") > settings.indexOf("VaultBackupSection(model)"))
        assertTrue("declaredSpaceLine(state)" in src("VaultItemsScreens.kt"))
    }
}
