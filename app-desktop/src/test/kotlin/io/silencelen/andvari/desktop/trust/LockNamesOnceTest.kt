package io.silencelen.andvari.desktop.trust

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The lock screen names who is locked and on which server once, in the current app's quiet address line (§4.4); the
 * password sign-in names the same way with no empty title space; the moment the vault opens is named; an open list of
 * people with nobody in it says so; an answer on a page of its own stands over the foot of the window, not above its
 * cards.
 */
class LockNamesOnceTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()
    private fun body(text: String, head: String) = text.substringAfter(head).substringBefore("\n}\n")
    /** How often [part] stands as a whole word in [text] (the name "andvari" inside the origin's host does not count). */
    private fun count(text: String, part: String) = Regex("(?<![\\w.])" + Regex.escape(part) + "(?![\\w.])").findAll(text).count()

    private fun model(scene: FakeScene) = FakeScenes.desktopAt(scene).let { api ->
        api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L }).also { it.onSnapshot(api.snapshot) }
    }

    @Test
    fun theLockScreenNamesTheServersNameAndItsAddressEachOnce() {
        val (api, _) = model(FakeScene.LOCKED)
        val locked = assertNotNull(api.snapshot.locked)
        val instance = locked.prompt.instance
        assertTrue(instance.name.isNotEmpty() && instance.origin.isNotEmpty())
        val shown = lockNameLines(locked).joinToString("\n") { it.shown() }
        assertEquals(1, count(shown, instance.name), shown)
        assertEquals(1, count(shown, instance.origin), shown)
        assertEquals(1, count(shown, assertNotNull(locked.prompt.email)), shown)
        // The design's own words (§4.4), whole.
        assertEquals(CopyKey.MASTER_PASSWORD_FOR.english.replace("{0}", locked.prompt.email!!).replace("{1}", instance.name).replace("{2}", instance.origin), lockNameLines(locked).first().shown())

        // Nothing else on the screen names them: no instance block, no large title, the field's label says what to type.
        val lock = body(src("AccountScreens.kt"), "internal fun LockScreen(")
        assertFalse(lock.contains("InstanceName(") || lock.contains("lockTitle(") || lock.contains("titleLarge"), lock)
        assertTrue(lock.indexOf("LockNameLine(locked)") in 0 until lock.indexOf("SecretField(UiText.ph(Placeholder.PASSWORD_FIELD)"))
        val line = body(src("AccountScreens.kt"), "private fun LockNameLine(")
        assertTrue(line.contains("onSurfaceVariant") && line.contains("bodyLarge") && line.contains("monospacedOrigin("), "the current app's quiet address line")
    }

    @Test
    fun theOriginInTheLineIsMonospacedAndTheWordsAreUnchanged() {
        val styled = monospacedOrigin("Master password for a@b.example on Home (https://home.example)", "https://home.example")
        assertEquals("Master password for a@b.example on Home (https://home.example)", styled.text)
        val span = styled.spanStyles.single()
        assertEquals("https://home.example", styled.text.substring(span.start, span.end))
        assertTrue(monospacedOrigin("no origin here", "https://x.example").spanStyles.isEmpty())
    }

    @Test
    fun thePasswordSignInNamesTheServerUntilAnAddressIsTypedThenTheAccountOnIt() {
        val (api, _) = model(FakeScene.SIGN_IN)
        val screen = assertIs<EntryScreen.SignIn>(api.snapshot.entry)
        assertNull(signInTitle(screen, ""))
        val typed = assertNotNull(signInTitle(screen, "bo@example.com")).shown()
        val instance = screen.prompt.instance
        assertEquals(1, count(typed, instance.name), typed)
        assertEquals(1, count(typed, instance.origin), typed)
        val signIn = body(src("AccountEntryScreens.kt"), "internal fun SignInScreen(")
        assertFalse(signIn.contains("InstanceName(") || signIn.contains("Title("), "named once, with no large title slot")
        val naming = body(src("AccountEntryScreens.kt"), "private fun SignInNaming(")
        assertTrue(naming.contains("if (line == null)") && naming.contains("instance.origin"), "the server named while nothing is typed")
        assertEquals(52, SIGN_IN_TITLE_SLOT.value.toInt(), "two quiet lines, not three of the title")
    }

    @Test
    fun theMomentTheVaultOpensIsNamedAndDraws() {
        val section = body(src("VaultItemsScreens.kt"), "internal fun VaultItemsSection(")
        val nullBranch = section.substringAfter("val c = content ?: return").substringBefore("val state by")
        assertTrue(nullBranch.contains("header()") && nullBranch.contains("VaultOpening()"))
        assertTrue(body(src("VaultItemsScreens.kt"), "internal fun VaultOpening(").contains("Placeholder.VAULT_OPENING"))
        val scene = ImageComposeScene(480, 400, Density(1f)) { MaterialTheme { Column { VaultOpening() } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    @Test
    fun anOpenListOfPeopleWithNobodyInItSaysSo() {
        val (api, m) = model(FakeScene.CONTACTS)
        for (c in assertNotNull(api.snapshot.account?.contacts).contacts) m.run({ contacts.removeContact(c) })
        val account = assertNotNull(api.snapshot.account)
        assertTrue(assertNotNull(account.contacts).contacts.isEmpty())
        val people = body(src("PeopleScreens.kt"), "internal fun PeopleSection(")
        assertTrue(people.contains("if (screen.contacts.isEmpty()) Say(UiText.ph(Placeholder.PEOPLE_NONE)"))
        assertTrue(people.indexOf("Placeholder.PEOPLE_NONE") < people.indexOf("Placeholder.CLOSE"))
        val scene = ImageComposeScene(480, 600, Density(1f)) { MaterialTheme { Column { PeopleSection(m, api.snapshot, account) } } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
    }

    @Test
    fun anAnswerOnAPageOfItsOwnStandsAtTheFootOfTheWindowNotAboveTheCards() {
        val pages = body(src("AccountScreens.kt"), "private fun SignedInPages(")
        val own = pages.substringAfter("else -> Box(Modifier.fillMaxSize()) {")
        assertTrue(own.contains("AttentionArea(model, s, account, page, fork, go, saidInPlace = false)"))
        assertTrue(own.contains("Column(Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(horizontal = 16.dp)) { SaidHere(model, s) }"))
        assertTrue(own.indexOf("PageColumn {") < own.indexOf("SaidHere(model, s)"), "drawn over the page, after it")
        // The vault page keeps it in its attention area, above the list, as the current app's vault window does.
        assertTrue(body(src("AccountScreens.kt"), "private fun AttentionArea(").contains("if (saidInPlace) SaidHere(model, s)"))
    }
}
