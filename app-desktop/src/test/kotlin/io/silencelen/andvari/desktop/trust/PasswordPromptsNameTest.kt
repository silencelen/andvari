package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Design point 6 (§4.4): every prompt that asks for the master password names the account, the instance and its
 * origin: two-step, devices, recovery, account deletion, approving a device link, and both recovery prompts.
 */
class PasswordPromptsNameTest {
    private fun src(name: String): String =
        listOf(File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name"), File("app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/trust/$name"))
            .first { it.isFile }.readText()

    @Test
    fun theLineNamesTheAccountTheInstanceAndItsOrigin() {
        val s = FakeScenes.desktopAt(FakeScene.DEVICES).snapshot
        val email = assertNotNull(s.account?.email)
        val label = assertNotNull(s.instance?.label)
        val line = assertNotNull(masterPasswordFor(s)).shown()
        assertTrue(email in line, line)
        assertTrue(label.name in line, line)
        assertTrue(label.origin in line, line)
    }

    @Test
    fun noSignedInPromptAsksForThePasswordBare() {
        val settings = src("SettingsScreens.kt")
        val people = src("PeopleScreens.kt")
        // Change master password names itself in its own line (with the two new-password fields below it).
        val bare = Regex("""SecretField\(UiText\.ph\(Placeholder\.PASSWORD_FIELD\)""")
        assertEquals(1, bare.findAll(settings).count(), "only Change master password's own, which names the account above it")
        assertTrue(settings.substringAfter("fun ChangePasswordSection(").substringBefore("SecretField(").contains("CopyKey.MASTER_PASSWORD_FOR"))
        assertFalse(bare.containsMatchIn(people))
        // Two-step (turning it on; turning it off or a new key), a new kit after a move, deletion, devices, a device
        // link's approval, recovery, operator recovery.
        assertEquals(8, Regex("""MasterPasswordField\(s, """).findAll(settings).count())
        // The recovery key changed, and keeping operator recovery.
        assertEquals(2, Regex("""MasterPasswordField\(s, """).findAll(people).count())
    }
}
