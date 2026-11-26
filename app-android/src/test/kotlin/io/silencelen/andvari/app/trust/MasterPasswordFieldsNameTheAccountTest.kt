package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §4.4: every master-password field names the account, the server's name and its
 * address. This walks every screen of the new path that holds a master-password field and fails if one does not show
 * the three: the signed-in screens through [MasterPasswordField], the signed-out ones through their own titles.
 */
class MasterPasswordFieldsNameTheAccountTest {
    private val dir = File("src/main/kotlin/io/silencelen/andvari/app/trust")

    /** Each top-level function of the new path's screens, by name, with its body. */
    private fun functions(): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val start = Regex("""(?m)^(?:internal |private )?fun (?:<[^>]+> )?(\w+)\(""")
        for (f in dir.listFiles().orEmpty().filter { it.name.endsWith(".kt") }.sortedBy { it.name }) {
            val text = f.readText()
            val heads = start.findAll(text).toList()
            for ((i, m) in heads.withIndex()) {
                val end = if (i + 1 < heads.size) heads[i + 1].range.first else text.length
                out[f.name + ":" + m.groupValues[1]] = text.substring(m.range.first, end)
            }
        }
        return out
    }

    /** How each signed-out screen names the account and the server above its field. */
    private val entryTitles = mapOf(
        "AccountScreens.kt:LockScreen" to "PasswordStepTitle(lockTitle(locked), locked.prompt.instance)",
        "AccountEntryScreens.kt:SignInScreen" to "Title(signInTitle(screen, email))",
        "LinkAndRecoveryScreens.kt:LinkDevicePasswordScreen" to "PasswordStepTitle(screen.prompt.title?.let { UiText.of(it) }, screen.prompt.instance)",
        "KitScreens.kt:KitNotMade" to "fillCopy(CopyKey.MASTER_PASSWORD_FOR, kit.email, kit.instance.name, kit.instance.origin)",
    )

    @Test
    fun everyScreenWithAMasterPasswordFieldNamesTheAccountTheServerAndItsAddress() {
        val withField = functions().filterValues { it.contains("Placeholder.PASSWORD_FIELD") || it.contains("MasterPasswordField(s, ") }
        val screens = withField.keys - "TrustUi.kt:MasterPasswordField"
        // The screens the rule names are among them.
        for (expected in listOf(
            "DevicesScreens.kt:DevicesSection", "DevicesScreens.kt:DeviceLinkHostView", "RecoverySettingsScreens.kt:OperatorRecoveryWarningView",
            "SettingsScreens.kt:ChangePasswordSection", "SettingsScreens.kt:DeleteAccountSection", "SettingsScreens.kt:TwoStepSection",
        )) assertTrue(expected in screens, "$expected holds a master-password field: $screens")
        for ((name, body) in withField) {
            if (name == "TrustUi.kt:MasterPasswordField") continue
            val title = entryTitles[name]
            if (title != null) {
                assertTrue(body.contains(title), "$name names the account and the server in its title")
            } else {
                assertTrue(body.contains("MasterPasswordField(s, "), "$name shows its field through MasterPasswordField")
                assertTrue(!body.contains("SecretField(UiText.ph(Placeholder.PASSWORD_FIELD)"), "$name has no bare master-password field")
            }
        }
        val field = functions().getValue("TrustUi.kt:MasterPasswordField")
        assertTrue(field.contains("masterPasswordLine(s.account?.email, s.instance?.label)?.let { Say(it"))
    }

    @Test
    fun theLineHoldsTheAccountTheServersNameAndItsAddress() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val account = assertNotNull(api.snapshot.account)
        val label = assertNotNull(api.snapshot.instance).label
        val line = assertNotNull(masterPasswordLine(account.email, label)).shown()
        assertEquals("Master password for ${account.email} on ${label.name} (${label.origin})", line)
        assertTrue(label.origin.isNotEmpty())
        assertNull(masterPasswordLine(null, label))
        assertNull(masterPasswordLine(account.email, null))

        val locked = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val title = lockTitle(assertNotNull(locked.snapshot.locked)).shown()
        val l = assertNotNull(locked.snapshot.locked).prompt
        assertTrue(title.contains(assertNotNull(l.email)) && title.contains(l.instance.name) && title.contains(l.instance.origin), title)
    }
}
