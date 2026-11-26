package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.PasswordChangeResult
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the shared code gained, on this app's screens.
 */
class SharedCodeGainsTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun theKeysAwaitingTheOwnersWordsShowAsPlaceholdersWhereTheyAreNamed() {
        for (key in listOf(CopyKey.DEVICES_REVOKE_DOES_NOT_WIPE, CopyKey.SIGN_UP_CODE_LINE, CopyKey.KIT_RECOVER_SETS_PASSWORD)) {
            val shown = assertIs<UiText.Ph>(UiText.of(key), key.name)
            assertEquals(Placeholder.AWAITING_OWNER, shown.placeholder)
            assertFalse(shown.shown().contains("⟦⟦"), "one pair of marks")
        }
        // A line made from such a key is a placeholder too (CopyLine cannot be built outside core: read the rule).
        assertTrue(src("UiText.kt").contains("line.key.awaitingOwner -> Ph(Placeholder.AWAITING_OWNER, listOf(unbracket(line.english)))"))
        // A key with words is still plain.
        assertIs<UiText.Plain>(UiText.of(CopyKey.ALREADY_SIGNED_IN_THERE))
        // Where they show: always on Devices, above the sign-up code field, under the kit recovery's title.
        assertTrue(src("DevicesScreens.kt").contains("Quiet(UiText.of(screen.revokeLine))"))
        val code = src("AccountEntryScreens.kt").substringAfter("internal fun SignUpCodeScreen(").substringBefore("\n}\n")
        assertTrue(code.indexOf("Quiet(UiText.of(screen.codeLine))") in 0 until code.indexOf("Field(UiText.ph(Placeholder.CODE_FIELD)"))
        val kit = src("LinkAndRecoveryScreens.kt").substringAfter("internal fun KitRecoverScreen(").substringBefore("\n}\n")
        assertTrue(kit.indexOf("Quiet(UiText.of(screen.setsPasswordLine))") > kit.indexOf("Title(UiText.of(screen.title))"))
    }

    @Test
    fun theAlreadySignedInRefusalIsSaidInTheOwnersWordsAndDismissed() {
        val shell = src("AccountScreens.kt").substringAfter("private fun AccountLines(").substringBefore("\n}\n")
        assertTrue(shell.contains("account.inviteNotUsed?.let { line ->"))
        assertTrue(shell.contains("Say(UiText.of(line))"))
        assertTrue(shell.contains("model.act { links.dismissOpened() }"))
        // Not said twice: the refusal's own line gives way to it.
        assertTrue(src("TrustModel.kt").contains("if (r == InviteResult.NOT_USABLE_SIGNED_IN && api.snapshot.account?.inviteNotUsed != null) note(place, r, null) else note(place, r)"))
        assertTrue(UiText.of(CopyKey.ALREADY_SIGNED_IN_THERE).shown().contains("You're already signed in there."), "the owner's words, plain")
    }

    @Test
    fun aPasswordChangeThisPhonesCopyCouldNotFollowSaysSoAndNeverOffersTryAgain() {
        val words = passwordChangeWords(PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE, 0)
        assertEquals(Placeholder.PASSWORD_CHANGED_PREVIOUS_OPENS_HERE, assertIs<UiText.Ph>(words).placeholder)
        assertFalse(words!!.shown().contains("try again"))
        val section = src("SettingsScreens.kt")
        assertTrue(section.contains("if (result.done || result == PasswordChangeResult.WEAK_PASSWORD || result == PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE) {"), "the typed passwords go: the new one is in force")
        assertTrue(src("AccountScreens.kt").contains("if (locked.previousPasswordOpensCopy) Say(UiText.ph(Placeholder.LOCK_PREVIOUS_PASSWORD_OPENS)"))
    }

    @Test
    fun theOwnershipOfferAndTheTypedKitsGateUseTheApprovedWords() {
        assertEquals(Approved.OWNERSHIP_OFFER_BODY, assertIs<UiText.Plain>(ownershipOfferBody()).text)
        // The typed kit's gate: the screen shows core's prompt as it is (its title, lines and "It's the same").
        val gate = src("EntryScreens.kt")
        assertTrue(gate.contains("prompt.confirmLabel?.let { UiText.of(it) }"))
    }

    @Test
    fun eachStageOfAnOperatorHelpRequestHasItsOwnLineAndAnEndedOneOffersNoRetry() {
        val lines = OperatorHelpStage.entries.map { operatorHelpStageLine(it).shown() }
        assertEquals(lines.size, lines.toSet().size, "one line per stage")
        assertEquals(setOf(OperatorHelpStage.VETOED, OperatorHelpStage.EXPIRED, OperatorHelpStage.DID_NOT_CHECK_OUT), OperatorHelpStage.entries.filter { operatorHelpEnded(it) }.toSet())
        val screen = src("LinkAndRecoveryScreens.kt").substringAfter("internal fun OperatorHelpScreen(").substringBefore("\n}\n")
        assertTrue(screen.contains("} else if (!operatorHelpEnded(screen.stage)) {"))
        assertTrue(screen.contains("entry.abandonOperatorHelp(screen)"), "Start over stays")
    }

    @Test
    fun namesShowAsOneSafeLineAndEveryOpenedAddressGoesThroughTheSharedRule() {
        assertEquals("Bank  ·  me", nameLine("Ba\u202Enk", "me\u200B"))
        assertFalse(nameLine("a\nb", "").contains("\n"))
        for (bad in listOf("javascript:alert(1)", "intent://x#Intent;end", "file:///etc/passwd", "https://bank.example@evil.example", "data:text/html,x", "bank.example\\evil")) {
            assertNull(webAddress(bad), bad)
        }
        assertEquals("https://bank.example", webAddress("bank.example"))
        assertTrue(src("VaultHealthScreens.kt").contains("return ItemText.openableAddress(site)"))
    }
}
