package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The owner's approved wording of 2026-11-15, applied exactly where the desktop held placeholders. */
class ApprovedCopyTest {
    /**
     * The approved wording file, as the run names it in the system property `andvari.approvedWordingFile` (the desktop's
     * test task sets it from the environment variable `ANDVARI_APPROVED_WORDING_FILE`). Without it, or where the file it
     * names is missing, the check against the file is left out.
     */
    private val approvedFile: File? = System.getProperty("andvari.approvedWordingFile")?.takeIf { it.isNotBlank() }?.let(::File)

    private fun source(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    /** Every string the desktop carries is the approved one, character for character (checked where the run names the file). */
    @Test
    fun everyCarriedStringIsTheApprovedOneExactly() {
        if (approvedFile == null || !approvedFile.exists()) return
        val entries = Json.parseToJsonElement(approvedFile.readText()).jsonArray.map { it.jsonObject }
        assertEquals(28, entries.size)
        val approved = HashMap<String, String>()
        for (e in entries) {
            val key = e.getValue("key").jsonPrimitive.content
            e["title"]?.takeIf { it !is JsonNull }?.let { approved["$key.title"] = it.jsonPrimitive.content }
            e["body"]?.takeIf { it !is JsonNull }?.let { approved["$key.body"] = it.jsonPrimitive.content }
            (e["buttons"] as? JsonArray)?.forEachIndexed { i, b -> approved["$key.button$i"] = b.jsonPrimitive.content }
        }
        for ((id, words) in ApprovedCopy.text) assertEquals(approved[id], words, id)
    }

    @Test
    fun coresReservedKeysShowTheApprovedWords() {
        assertEquals("Create an account here", UiText.of(CopyKey.SERVER_CREATE_ACCOUNT).shown())
        assertEquals("Sign in", UiText.of(CopyKey.SERVER_SIGN_IN).shown())
        assertFalse(UiText.of(CopyKey.SERVER_INVITATION_ONLY).isPlaceholder)
        assertFalse(UiText.of(CopyKey.SERVER_NOT_TAKING_ACCOUNTS).isPlaceholder)
        val api = FakeScenes.desktopAt(FakeScene.LINK_REQUIRED)
        val screen = assertIs<EntryScreen.LinkRequired>(api.snapshot.entry)
        assertEquals("This device needs to be linked", UiText.of(screen.title).shown())
        val body = UiText.of(screen.body)
        assertFalse(body.isPlaceholder)
        assertTrue(body.shown().startsWith(screen.body.values[0] + " on " + screen.body.values[1] + " (" + screen.body.values[2] + ") has “New devices must be linked” turned on"))
    }

    @Test
    fun theFirstScreenSaysClosedThenFullThenInvitationOnly() {
        for ((mode, button, line) in listOf(
            Triple(JoinMode.INVITATION_ONLY, "Sign-up is invitation-only right now", "If someone sent you an invitation link, use Paste an invite link."),
            Triple(JoinMode.CLOSED, "Sign-up is closed right now", "You can still sign in to an account you already have."),
        )) {
            val api = io.silencelen.andvari.core.app.fake.FakeDesktopAppApi(null)
            api.script.publicInstance.mode = mode
            api.start()
            val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
            assertTrue(first.offersPublicInstance)
            assertEquals(mode, first.signup.mode, "the fake reports the mode at start")
            val choice = firstRunChoices(first)[1]
            assertFalse(choice.enabled)
            assertEquals(button, choice.label.shown())
            assertEquals(line, assertNotNull(choice.line).shown())
        }
        val entry = source("EntryScreens.kt").substringAfter("internal fun firstRunChoices(").substringBefore("\n}\n")
        assertTrue(entry.indexOf("JoinMode.CLOSED ->") < entry.indexOf("signup.full ->") && entry.indexOf("signup.full ->") < entry.indexOf("JoinMode.INVITATION_ONLY ->"))
    }

    @Test
    fun theSmallerSentencesAreTheApprovedOnes() {
        assertEquals(ApprovedCopy.text["RECOVERY_CHECK_STOPPED.body"], firstRunNotice(FirstRunNotice.RECOVERY_STOPPED).shown())
        assertEquals("andvari sent your change but got no answer from this server, so it can't tell yet whether it went through. It will keep sending the same change until the server confirms it. You don't need to do it again.", UiText.forResult(VaultActionResult.SENT_PENDING, 0)?.shown())
        assertEquals("waiting for the server", ApprovedCopy.line("VAULT_CHANGE_WAITING.body", 1))
        assertEquals("Read this to Ada.", ApprovedCopy.line("COMPARE_READ_AND_TYPE.body", 0, "Ada"))
        assertEquals("Ask Ada to read the code on their device, then type it here.", ApprovedCopy.line("COMPARE_READ_AND_TYPE.body", 1, "Ada"))
        assertEquals("Make Ada the owner of “Trips”?", ApprovedCopy.words("OWNERSHIP_OFFER.title", "Ada", "Trips"))
        assertEquals("Ask Ada to take over", ApprovedCopy.words("OWNERSHIP_OFFER.button0", "Ada"))
        assertTrue(ApprovedCopy.line("CARD_RECORD_DAMAGED.body", 0, "https://x.example").contains("the identity of https://x.example is damaged"))
        // Where each one stands.
        val vaults = source("VaultScreens.kt")
        assertTrue(vaults.contains("VaultLogState.FROZEN -> UiText.approved(\"VAULT_HISTORY_FORKED.body\")"))
        assertTrue(vaults.contains("VaultLogState.KEY_MISSING -> UiText.approved(\"VAULT_KEY_MISSING.body\")"))
        assertTrue(vaults.contains("UiText.approved(\"INCOMING_CONFIRM_FIRST.body\", it.label)"))
        // The vault's name goes in as a slot: where it is not known, the plain words stand there unquoted (SmallFaultsTest).
        assertTrue(vaults.contains("title = { Say(UiText.Plain(ApprovedCopy.wordsWith(\"OWNERSHIP_OFFER.title\", said(who), name))) }"), "an ownership offer asks first")
        assertTrue(vaults.contains("Quiet(UiText.approved(\"MEMBERS_MAY_BE_INCOMPLETE_WHY.body\"))"))
        val people = source("PeopleScreens.kt")
        assertTrue(people.contains("UiText.approved(\"PERSON_FROM_OTHER_DEVICE_HINT.body\")") && people.contains("UiText.approved(\"PEOPLE_NOT_REVIEWED.button0\")"))
        val check = source("LinkAndRecoveryScreens.kt").substringAfter("internal fun CheckAccountScreen(").substringBefore("\n}\n")
        for (n in 0..2) assertTrue(check.contains("RECOVERY_CHECK_ACCOUNT.button$n"))
        val entry = source("EntryScreens.kt")
        for (id in listOf("CARD_NOT_VERIFIED.body", "CARD_MOVE_NOT_FOLLOWED.body", "GATE_TITLE_KIND_CHANGE.button0", "GATE_TITLE_KIND_CHANGE.button1", "CARD_OTHER_ADDRESS.body", "CARD_RECORD_DAMAGED.title")) {
            assertTrue(entry.contains("\"$id\""), id)
        }
    }

    // ---- the old data (approved entry 6, and the rule decided for the old data) ----

    @Test
    fun oldDataIsToldOnceThenStaysASettingsLineUntilItIsGone() {
        val api = FakeScenes.desktopAt(FakeScene.OLD_DATA_LEFT)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "the first screen, usable: nothing is blocked")
        val old = assertNotNull(api.snapshot.oldData)
        assertEquals(OldDataShown.NOTICE, oldDataShown(old))
        api.acknowledgeOldData(old)
        val after = assertNotNull(api.snapshot.oldData)
        assertEquals(OldDataShown.SETTINGS_LINE, oldDataShown(after), "not again after Continue")
        assertFalse(api.retryOldDataRemoval(after), "still there")
        assertEquals(OldDataShown.SETTINGS_LINE, oldDataShown(api.snapshot.oldData))
        api.script.oldStoresThatStay -= PreCutoverStore.OFFLINE_CACHE
        assertTrue(api.retryOldDataRemoval(assertNotNull(api.snapshot.oldData)))
        assertEquals(OldDataShown.NOTHING, oldDataShown(api.snapshot.oldData), "the line goes with the data")
    }

    @Test
    fun noSignedOutScreenIsBlockedAndTheOldDataIsNeverRead() {
        val app = source("TrustApp.kt")
        assertFalse(app.contains("OldDataBlocking"), "no blocking screen")
        assertFalse(source("UiText.kt").contains("OLD_DATA_BLOCKS"))
        val notice = app.substringAfter("private fun OldDataNotice(").substringBefore("\n}\n")
        assertTrue(notice.contains("OLD_DATA_NOT_REMOVED.button0") && notice.contains("acknowledgeOldData"))
        assertTrue(source("AccountScreens.kt").contains("OldDataSettingsLine(model, s)"))
        // The wipe deletes named files and reads nothing of them; the one file it reads is prefs.json, to keep the theme.
        val wipe = source("DesktopStores.kt").substringAfter("class DesktopOldStores(").substringBefore("\n}\n")
        val reads = Regex("readText\\(|readBytes\\(|inputStream\\(|bufferedReader\\(").findAll(wipe).count()
        assertEquals(1, reads)
        assertTrue(wipe.substringAfter("private fun cutDownPrefs(").contains("f.readText()"))
    }
}
