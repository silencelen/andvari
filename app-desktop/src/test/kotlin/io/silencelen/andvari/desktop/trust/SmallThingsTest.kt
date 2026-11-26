package io.silencelen.andvari.desktop.trust

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Small things found on the desktop's screens, each pinned. */
class SmallThingsTest {
    @Test
    fun theKeptSignInThatCannotBeOpenedNoLongerNamesTheKeyStoreAsTheOnlyReason() {
        // A key store that does not answer, an unwrapped file this computer does not accept, another account's seal.
        val gloss = Placeholder.KEPT_UNOPENABLE.gloss
        assertFalse(gloss.contains("key store"), gloss)
        assertTrue(gloss.contains("sign in again") && gloss.contains("not deleted"), gloss)
    }

    @Test
    fun aFreshImportOffersImportNotTryAgain() {
        val api = io.silencelen.andvari.core.app.fake.FakeScenes.desktopAt(io.silencelen.andvari.core.app.fake.FakeScene.LOCKED)
        val m = TrustModel(api, kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined), { 0L })
        m.run({ unlock(kotlin.test.assertNotNull(snapshot.locked), io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        val c = kotlin.test.assertNotNull(m.content.value)
        kotlinx.coroutines.runBlocking { c.importCsv("name,url,username,password\nA,https://a.example,me,pw\n".toByteArray()) }
        val v = kotlin.test.assertNotNull(c.state.csvImport)
        assertTrue(v.retryable && v.error == null, "core marks a fresh import retryable")
        kotlin.test.assertEquals(Placeholder.IMPORT_CONFIRM, importButton(v), "but nothing has failed: the button imports")
    }

    @Test
    fun assistedRecoveryWithNoKeyStoreSaysItsRequestIsKeptForThisRunOnly() {
        val root = Files.createTempDirectory("l7-9-requests").toFile()
        try {
            val none = DesktopHome(File(root, "none"), NoKeyStore, log = {}, keyStorePause = {})
            val noStore = HomeSignInKeeping(none)
            assertFalse(noStore.assistRequestThisRunOnly, "nothing asked, nothing held yet")
            none.requestFile.replace("""{"request":"waiting"}""")
            assertTrue(noStore.assistRequestThisRunOnly, "no key store: the request is held in memory only")
            assertFalse(File(none.dir, "assist-requests.json").exists(), "and never written unwrapped")

            val kept = DesktopHome(File(root, "kept"), TestKeyStore(), log = {}, keyStorePause = {})
            kept.requestFile.replace("""{"request":"waiting"}""")
            assertFalse(HomeSignInKeeping(kept).assistRequestThisRunOnly, "a key store wraps it: it outlives the run")
        } finally {
            root.deleteRecursively()
        }
        val screen = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/LinkAndRecoveryScreens.kt").readText()
            .substringAfter("internal fun OperatorHelpScreen(").substringBefore("\n}\n")
        assertTrue(screen.contains("if (model.assistRequestThisRunOnly()) Say(UiText.ph(Placeholder.ASSIST_REQUEST_THIS_RUN_ONLY))"))
    }
}
