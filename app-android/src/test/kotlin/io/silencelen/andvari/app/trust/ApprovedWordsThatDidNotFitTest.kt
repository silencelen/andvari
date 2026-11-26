package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The approved wordings that did not fit. The screen's own parts are made here: the
 * question before an ownership offer (entry 26) and the comparison field labelled by its approved line (entry 21).
 * The already-signed-in refusal (entry 7) waits on the shared code.
 */
class ApprovedWordsThatDidNotFitTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun theOwnershipOfferIsAskedFirstInTheApprovedWords() {
        assertEquals("Make {0} the owner of “{1}”?", Approved.OWNERSHIP_OFFER_TITLE)
        assertEquals("Ask {0} to take over", Approved.OWNERSHIP_OFFER_ASK)
        assertEquals(
            "Nothing changes until they accept in their app. They have 14 days, and you can cancel until then. Afterwards they manage the vault's members, and only they can rename it, hand it over or delete it. You stay in it as a writer.",
            Approved.OWNERSHIP_OFFER_BODY,
        )
        val q = ownershipOfferQuestion("Bo", "Trips")
        assertEquals("Make Bo the owner of “Trips”?", q.title.shown())
        assertEquals("Ask Bo to take over", q.ask.shown())
        // Core's offer lasts 14 days now (OwnershipOffer.DAYS), so the approved body is shown as it is.
        assertEquals(14, io.silencelen.andvari.core.app.OwnershipOffer.DAYS)
        assertEquals(Approved.OWNERSHIP_OFFER_BODY, assertIs<UiText.Plain>(q.body).text)
        assertFalse(Placeholder.entries.any { it.name == "OWNERSHIP_OFFER_BODY" }, "the placeholder is gone")

        val members = src("VaultScreens.kt").substringAfter("private fun MembersView(").substringBefore("\n}\n")
        // The row's button only opens the question; the one offer is the question's confirm, and Cancel sends nothing.
        assertTrue(members.contains("enabled = !s.busy && m.role != RoleInVault.OWNER) { offering = m }"))
        assertEquals(1, Regex("""vaults\.offerOwnership\(""").findAll(src("VaultScreens.kt")).count())
        assertTrue(members.contains("confirmButton = { androidx.compose.material3.TextButton(onClick = { offering = null; model.run({ vaults.offerOwnership(m) }) }) { Say(q.ask) } }"))
        assertTrue(members.contains("dismissButton = { androidx.compose.material3.TextButton(onClick = { offering = null }) { Say(CopyKey.CANCEL) } }"))
    }

    @Test
    fun theComparisonFieldIsLabelledByItsApprovedLine() {
        val view = src("PeopleScreens.kt").substringAfter("internal fun CompareView(").substringBefore("internal fun ownCodeTypedBack")
        assertTrue(view.contains("val typeTheirs = UiText.approved(Approved.COMPARE_TYPE_THEIRS, c.label)"))
        assertTrue(view.contains("Say(typeTheirs)"))
        assertTrue(view.contains("LineLabelledField(typeTheirs, theirs, KeyboardType.NumberPassword, mono = true)"))
        assertFalse(src("UiText.kt").contains("COMPARE_THEIR_CODE"), "the placeholder label is gone")
        val field = src("TrustUi.kt").substringAfter("internal fun LineLabelledField(").substringBefore("\n}\n")
        assertTrue(field.contains("semantics { contentDescription = name }"), "a screen reader names the field by the line")
        assertFalse(field.contains("label ="), "no floating label")
    }
}
