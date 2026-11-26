package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** A member's role changes only from its question (the web's walk of 2026-11-16): one tap on the switch signs nothing. */
class RoleChangeConfirmTest {
    @Test
    fun theSwitchOnlyAsksAndTheConfirmSignsTheRole() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.MEMBERS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }, { false }, {})
        val me = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        val bo = me.contacts.first { it.label == "Bo" }
        val boInFake = me.vaults.first { it.name == "Family" }.members.first { it.userId == bo.userId }
        assertEquals(RoleInVault.WRITER, boInFake.role)
        val row = assertNotNull(assertNotNull(api.snapshot.account).members).members.first { it.userId == bo.userId }

        val (ask, allows) = roleChangeQuestion(row, MemberRole.READER)
        // The question is named by its key; it names the person, and the role as every screen names it.
        assertEquals(Placeholder.ROLE_CHANGE_ASK, (ask as UiText.Ph).placeholder)
        assertEquals(listOf(personLine(row.who).shown(), roleWord(RoleInVault.READER)), ask.args)
        assertEquals(roleWord(RoleInVault.WRITER), roleWord(MemberRole.WRITER))
        val screens = File("src/main/kotlin/io/silencelen/andvari/app/trust").listFiles()!!.filter { it.extension == "kt" }.joinToString("") { it.readText() }
        assertTrue(".literal" !in screens && "role.name.lowercase()" !in screens && "role?.name?.lowercase()" !in screens, "no screen names a role by the records' word")
        assertEquals(Placeholder.ROLE_READER_ALLOWS, (allows as UiText.Ph).placeholder)
        assertEquals(Placeholder.ROLE_WRITER_ALLOWS, (roleChangeQuestion(row, MemberRole.WRITER).second as UiText.Ph).placeholder)

        confirmRoleChange(m, row, MemberRole.READER)
        assertEquals(RoleInVault.READER, boInFake.role, "said: ${m.said.value?.text?.shown()}")

        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultScreens.kt").readText()
        assertTrue(src.contains("Quieter(UiText.ph(Placeholder.LINK_ROLE_SWITCH), enabled = !s.busy && m.role != RoleInVault.OWNER) { changingRole = m to next }"))
        assertEquals(1, Regex("vaults\\.changeRole\\(").findAll(src).count(), "the confirm is the one place a role is signed")
        assertTrue(src.substringAfter("internal fun confirmRoleChange(").substringBefore("\n\n").contains("vaults.changeRole(member, next)"))
    }
}
