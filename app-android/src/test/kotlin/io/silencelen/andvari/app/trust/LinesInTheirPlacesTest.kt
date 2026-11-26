package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Each approved line stands where its label on the wording page puts it, and nowhere else: the line that says a
 * master password change was made, the name field's label and the line under it, and each state of "New devices must
 * be linked" under the setting's own name and explanation. Each test walks the fake to the state and names the line
 * by its key, so another state's line standing there turns it red.
 */
class LinesInTheirPlacesTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun afterAPasswordChangeTheFirstLineSaysTheChangeWasMade() {
        val (api, m) = at(FakeScene.VAULTS)
        m.runIn(PASSWORD_CHANGE_SECTION, { settings.changeMasterPassword(FakeScenes.PASSWORD, "a much longer master password, 2026!") }, { passwordChangeWords(it, 0) })
        assertNull(m.saidIn(api.snapshot, PASSWORD_CHANGE_SECTION), "done: nothing in place but the lines below")
        val lines = passwordChangedLines(assertNotNull(api.snapshot.account))
        assertEquals(
            listOf(Placeholder.PASSWORD_CHANGED, Placeholder.PASSWORD_CHANGED_THIS_PHONE, Placeholder.PASSWORD_CHANGED_NO_KIT),
            lines.take(3).map { assertIs<UiText.Ph>(it).placeholder },
            "done with the other devices, then this phone, then the kit: the approved lines' order",
        )
        // The test is about this sentence: the change itself is said first, before the other devices.
        assertEquals(
            "Your master password is changed. Your other devices were signed out. They need the new master password to sign in again.",
            Placeholder.PASSWORD_CHANGED.words,
        )
        // The section shows exactly these lines once the change is done.
        val section = src("SettingsScreens.kt").substringAfter("internal fun ChangePasswordSection(").substringBefore("\n}\n")
        assertTrue("passwordChangedLines(account)" in section)
    }

    @Test
    fun theNameFieldIsLabelledYourNameAndTheLineUnderItSaysWhoSeesIt() {
        val (api, _) = at(FakeScene.CREATE_ACCOUNT)
        assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        val form = src("AccountEntryScreens.kt").substringAfter("internal fun CreateAccountScreen(").substringBefore("\n}\n")
        val field = form.indexOf("Field(UiText.ph(Placeholder.DISPLAY_NAME_FIELD), name) { name = it }")
        assertTrue(field > 0, "the label is the field's own key")
        val under = form.indexOf("Quiet(UiText.ph(Placeholder.DISPLAY_NAME_UNDER))")
        assertTrue(under > field && form.substring(field, under).count { it == '\n' } == 1, "the line under the field follows it at once")
        assertEquals("Your name", Placeholder.DISPLAY_NAME_FIELD.words)
        assertEquals("People you connect with see this name.", Placeholder.DISPLAY_NAME_UNDER.words)
    }

    @Test
    fun eachStateOfNewDevicesMustBeLinkedHasItsOwnLineUnderTheSettingsNameAndWhatItDoes() {
        val (api, m) = at(FakeScene.VAULTS)
        m.run({ devices.openDevices() })
        fun screen() = assertNotNull(assertNotNull(api.snapshot.account).devices)
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_UNKNOWN, requireLinkState(screen()), "the server does not say")
        m.run({ devices.setRequireLink(true, FakeScenes.PASSWORD) })
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_IS_ON, requireLinkState(screen()))
        m.run({ devices.setRequireLink(false, FakeScenes.PASSWORD) })
        assertEquals(Placeholder.DEVICE_REQUIRE_LINK_IS_OFF, requireLinkState(screen()))
        // The three states are three lines, none of them the explanation.
        val states = listOf(Placeholder.DEVICE_REQUIRE_LINK_UNKNOWN, Placeholder.DEVICE_REQUIRE_LINK_IS_ON, Placeholder.DEVICE_REQUIRE_LINK_IS_OFF)
        assertEquals(3, states.map { UiText.ph(it).shown() }.toSet().size)
        assertTrue(states.none { UiText.ph(it).shown() == UiText.ph(Placeholder.DEVICE_REQUIRE_LINK_BODY).shown() })
        assertEquals("It's on.", Placeholder.DEVICE_REQUIRE_LINK_IS_ON.words)
        assertEquals("It's off.", Placeholder.DEVICE_REQUIRE_LINK_IS_OFF.words)
        // On the screen: the name, what it does, then the state, then the buttons.
        val view = src("DevicesScreens.kt").substringAfter("internal fun DevicesSection(").substringBefore("internal fun DeviceLinkHostView(")
        val order = listOf(
            "Say(Placeholder.DEVICE_REQUIRE_LINK_TITLE",
            "Quiet(UiText.ph(Placeholder.DEVICE_REQUIRE_LINK_BODY))",
            "Quiet(UiText.ph(requireLinkState(screen)))",
            "for (next in requireLinkChoices(screen))",
        ).map { view.indexOf(it) }
        assertTrue(order.all { it > 0 } && order == order.sorted(), "title, body, state, buttons: $order")
    }
}
