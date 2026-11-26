package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.ItemFailure
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A write whose screen left while it was on the wire arrives as the vault's
 * notice, and the next vault screen shows it, whichever screen that is (before, only the item list showed the notice,
 * so a refusal left behind by the editor was not said on the item's detail, the trash or the history).
 */
class LeftBehindNoticeTest {
    @Test
    fun aDeniedDeleteWhoseScreenLeftIsTheNoticeAboveEveryVaultScreen() = runBlocking<Unit> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        m.onSnapshot(api.snapshot)
        val fake = assertNotNull(api.fakeContent)
        val c = assertNotNull(m.content.value)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Mail", "ada", "pw-1", "https://mail.example")
        c.refresh()
        c.dismissNotice()

        // Attended, the screen says the refusal itself and the notice stays empty.
        fake.failNextWith(ItemFailure.Refused("forbidden", 403))
        val said = assertIs<ActionResult.Failed>(c.deleteItem(id)).message
        assertNull(c.state.notice, "attended: the screen that asked says it")

        // The screen left (its job is cancelled) while the delete was on the wire: the answer is the notice.
        fake.failNextWith(ItemFailure.Refused("forbidden", 403))
        val left = launch(start = CoroutineStart.UNDISPATCHED) {
            coroutineContext[Job]!!.cancel()
            c.deleteItem(id)
        }
        left.join()
        assertEquals(said, c.state.notice, "the denied delete is said at the next screen")

        // Every vault screen shows it: the notice is drawn above the screen switch, not inside the list.
        val section = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultItemsScreens.kt").readText()
            .substringAfter("internal fun VaultItemsSection(").substringBefore("\n}\n")
        assertTrue(section.indexOf("VaultNotice(c, state)") in 0 until section.indexOf("when {"))
        val list = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultItemsScreens.kt").readText()
            .substringAfter("private fun VaultItemsList(").substringBefore("\n}\n")
        assertTrue(!list.contains("state.notice"), "said once, not twice on the list")
    }
}
