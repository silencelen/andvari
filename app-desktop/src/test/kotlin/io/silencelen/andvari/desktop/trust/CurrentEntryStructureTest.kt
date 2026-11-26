package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The lock screen, the first window and the entry screens take the current desktop app's structure (decided on
 * 2026-11-16): its brand head, its sign-in margin, its error bar with "dismiss", the wait named under a sign-in; the
 * Sharing cards' rows carry their letter; a section that opens on request has its title and a button, as a section.
 */
class CurrentEntryStructureTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")

    @Test
    fun theBrandHeadAndTheMarginAreTheCurrentApps() {
        val ui = src("TrustUi.kt")
        assertTrue(body(ui, "internal fun Sigil(").contains("Text(BRAND_LINE"))
        assertTrue(BRAND_LINE == "the keeper of the hoard", "carried over word for word")
        assertTrue(body(ui, "internal fun AuthColumn(").contains(".padding(28.dp)"))
        for ((file, head) in listOf("EntryScreens.kt" to "internal fun FirstRunScreen(", "AccountScreens.kt" to "internal fun LockScreen(")) {
            assertTrue(body(src(file), head).contains("Sigil()"), head)
        }
        // The sign-in screens open under the same head, centred; the lock screen centres what it names.
        assertTrue(body(src("AccountEntryScreens.kt"), "internal fun SignInScreen(").contains("BrandHead()"))
        assertTrue(body(src("EntryScreens.kt"), "internal fun SignInChoiceScreen(").contains("WindowHead(UiText.of(CopyKey.FIRST_SIGN_IN))"))
        val lock = body(src("AccountScreens.kt"), "internal fun LockScreen(")
        assertTrue(lock.contains("LockNameLine(locked)") && !lock.contains("InstanceName("))
        assertTrue(body(src("AccountScreens.kt"), "private fun LockNameLine(").contains("textAlign = TextAlign.Center"))
    }

    @Test
    fun whatWasSaidIsTheErrorBarAndDismissPutsItAway() {
        val ui = src("TrustUi.kt")
        val said = body(ui, "internal fun SaidHere(")
        assertTrue(said.contains("ErrorBar(said.text) { model.clearSaid() }"))
        val bar = body(ui, "internal fun ErrorBar(")
        assertTrue(bar.contains("containerColor = MaterialTheme.colorScheme.errorContainer") && bar.contains("onErrorContainer"))
        assertTrue(bar.contains("LiveRegionMode.Assertive") && bar.contains("Placeholder.DISMISS"))
        assertFalse(bar.contains("border"), "no bar at the card's edge")

        val api = FakeScenes.desktopAt(FakeScene.SIGN_IN)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        m.say(UiText.ph(Placeholder.PASSWORDS_DIFFER))
        assertNotNull(m.saidOn(api.snapshot))
        m.clearSaid()
        assertNull(m.saidOn(api.snapshot), "dismissed")
    }

    @Test
    fun theSignInNamesTheWaitInASlotAndTheLockKeepsItsOwn() {
        val signIn = body(src("AccountEntryScreens.kt"), "internal fun SignInScreen(")
        assertTrue(signIn.contains("FixedSlot(BUSY_LINE_SLOT) { if (s.busy) Quiet(UiText.ph(Placeholder.CHECKING_PASSWORD)) }"))
        assertTrue(signIn.indexOf("Placeholder.SIGN_IN_BUTTON") < signIn.indexOf("BUSY_LINE_SLOT"), "under the button")
        val lock = body(src("AccountScreens.kt"), "internal fun LockScreen(")
        assertTrue(lock.contains("if (s.busy) Quiet(UiText.ph(Placeholder.UNLOCKING))"))
        // Sign out stays a quiet text button below everything, behind its question, as in the current app.
        assertTrue(lock.indexOf("SignOutButton(model, s)") > lock.indexOf("UNLOCK_SAID_SLOT"))
    }

    @Test
    fun theSharingCardsRowsCarryTheirLetterAndAClosedSectionIsDrawnAsASection() {
        assertTrue(body(src("VaultScreens.kt"), "internal fun SharedVaultsSection(").contains("LetterHead(vaultRowName(v),"))
        assertTrue(body(src("PeopleScreens.kt"), "internal fun PeopleSection(").contains("LetterHead(c.label, contactLine(c))"))
        val closed = body(src("TrustUi.kt"), "internal fun ClosedSection(")
        assertTrue(closed.contains("SectionTitle(title)") && closed.contains("Second("))
        val opens = mapOf(
            "PeopleScreens.kt" to "ClosedSection(Placeholder.PEOPLE,",
            "LinksScreens.kt" to "ClosedSection(Placeholder.LINKS,",
            "SettingsScreens.kt" to "ClosedSection(Placeholder.DEVICES,",
        )
        for ((file, call) in opens) assertTrue(src(file).contains(call), call)
        assertTrue(src("SettingsScreens.kt").contains("ClosedSection(Placeholder.RECOVERY_SETTINGS,"))
        assertTrue(body(src("SettingsScreens.kt"), "internal fun TwoStepSection(").contains("Second(UiText.ph(Placeholder.TWO_STEP_OPEN)"))
    }

    @Test
    fun theFirstWindowTheSignInAndTheLockDrawAtTheNarrowestAndAWideWindow() {
        for (scene in listOf(FakeScene.FIRST_RUN, FakeScene.SIGN_IN, FakeScene.LOCKED)) {
            val api = FakeScenes.desktopAt(scene)
            val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
            m.onSnapshot(api.snapshot)
            val s = api.snapshot
            if (scene == FakeScene.SIGN_IN) assertIs<EntryScreen.SignIn>(s.entry)
            m.say(UiText.ph(Placeholder.PASSWORDS_DIFFER))
            for (width in listOf(480, 1000)) {
                val image = ImageComposeScene(width, 720, Density(1f)) {
                    MaterialTheme {
                        val locked = s.locked
                        val entry = s.entry
                        when {
                            locked != null -> LockScreen(m, s, locked)
                            entry != null -> EntryScreens(m, s, entry)
                        }
                    }
                }
                try {
                    image.render()
                } finally {
                    image.close()
                }
            }
        }
    }
}
