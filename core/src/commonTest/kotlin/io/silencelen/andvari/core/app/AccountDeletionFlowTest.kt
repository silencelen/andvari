package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.ReauthFailedException
import io.silencelen.andvari.core.model.AccountDeleteBlocker
import io.silencelen.andvari.core.model.AccountDeletePreview
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The steps of deleting an account that the iOS, Android and desktop apps share (spec 03 §13): what is checked before
 * anything is sent, the preview in words, and each app's own name for itself. The request itself, its outcomes and the
 * wipe after it run in SessionControllerTest (the iOS controller), against a server stand-in.
 */
class AccountDeletionFlowTest {
    private val phone = AccountDeletionFlow(DeletionCopy.PHONE)
    private val personal = "00000000-0000-4000-8000-0000000000a1"
    private val mine = "00000000-0000-4000-8000-0000000000a2"
    private val shared = "00000000-0000-4000-8000-0000000000a3"

    @Test
    fun nothingIsSentUntilTheAddressThePasswordAndTheCodeAreThere() {
        assertEquals(DeletionCopy.PHONE.EMAIL_MISMATCH, phone.refusal("someone@example.com", "ann@example.com", "pw", "", totpRequired = false))
        assertEquals(DeletionCopy.PHONE.PASSWORD_REQUIRED, phone.refusal(" ANN@example.com ", "ann@example.com", "", "", totpRequired = false))
        assertEquals(DeletionCopy.PHONE.CODE_REQUIRED, phone.refusal("ann@example.com", "ann@example.com", "pw", " - ", totpRequired = true))
        assertNull(phone.refusal("ann@example.com", "ann@example.com", "pw", "", totpRequired = false), "no code when the account has none")
        assertNull(phone.refusal("ann@example.com", "Ann@Example.com", "pw", "123 456", totpRequired = true))
    }

    @Test
    fun thePreviewNamesWhatGoesWhatIsLeftAndWhatStandsInTheWay() {
        val names = mapOf(mine to "Garden", shared to "Family")
        val p = AccountDeletePreview(
            blockers = listOf(AccountDeleteBlocker("shared_vault", shared, 2), AccountDeleteBlocker("a_kind_from_a_later_server")),
            deletedVaults = listOf(personal, mine, "00000000-0000-4000-8000-0000000000a9"),
            leftVaults = listOf(shared),
            totpRequired = true,
        )
        val view = phone.previewView(p, personal, names::get)
        assertTrue(view.deleted.any { it.startsWith("Your Personal vault, the vault only you use, “Garden” and 1 other vault only you hold") }, view.deleted.toString())
        assertEquals(listOf("You'll leave “Family”. What you saved there stays for the people who still use it."), view.left)
        assertEquals(DeletionCopy.PHONE.blocker("shared_vault", "Family", 2), view.blockers[0])
        assertEquals(DeletionCopy.PHONE.blocker("a_kind_from_a_later_server", null, 0), view.blockers[1], "a kind this version does not know is listed")
        assertTrue(view.totpRequired)
        // A refusal's blockers show in place of the preview's.
        assertEquals(listOf(DeletionCopy.PHONE.blocker("last_admin", null, 3)), phone.previewView(p, personal, names::get, listOf(AccountDeleteBlocker("last_admin", null, 3))).blockers)
        val many = AccountDeletePreview(blockers = List(AccountDeletionFlow.LISTED + 5) { AccountDeleteBlocker("shared_vault", null, 1) }, deletedVaults = emptyList(), leftVaults = emptyList(), totpRequired = false)
        assertEquals(AccountDeletionFlow.LISTED, phone.previewView(many, personal, names::get).blockers.size)
    }

    @Test
    fun eachAppNamesItselfAndTheWebsWordsStayTheSame() {
        assertEquals("The account ann@example.com was deleted, with everything this phone kept for it.", DeletionCopy.PHONE.deleted("ann@example.com"))
        assertEquals("The account ann@example.com was deleted, with everything this computer kept for it.", DeletionCopy.COMPUTER.deleted("ann@example.com"))
        assertTrue(DeletionCopy.IPHONE.CREDENTIAL_CHANGED.contains("this iPhone was signed out"))
        assertTrue(DeletionCopy.COMPUTER.FORGOTTEN.startsWith("This computer forgot the account."), DeletionCopy.COMPUTER.FORGOTTEN)
        assertTrue(DeletionCopy.PHONE.MOST_LIKELY_DELETED.contains("You can make this phone forget the account"))
        assertEquals("Type ann@example.com to confirm. Your master password is checked on this computer before anything is sent.", DeletionCopy.COMPUTER.confirmFooter("ann@example.com"))
        // After an unknown outcome a later session end leaves the account's fate open, and offers no forgetting (spec 03 §13).
        assertFalse(DeletionCopy.PHONE.SESSION_ENDED_OUTCOME_UNKNOWN.contains("forget"))
    }

    @Test
    fun anAnswerThatSaysNothingIsNeitherDeletedNorRefused() {
        val copy = DeletionCopy.COMPUTER
        assertTrue(copy.outcomeUnknown(ApiException(502, "http_502", "bad gateway")))
        assertTrue(copy.outcomeUnknown(ApiException(500, "internal", "no")))
        assertTrue(copy.outcomeUnknown(kotlinx.io.IOException("no answer")))
        assertFalse(copy.outcomeUnknown(ApiException(400, "bad_totp_code", "no")))
        assertFalse(copy.outcomeUnknown(ReauthFailedException()))
        // A refused session after an unknown outcome no longer says "nothing was deleted".
        val flow = AccountDeletionFlow(copy)
        assertEquals(copy.SESSION_ENDED, flow.refusedMessage(ApiException(401, "unauthorized", "no"), afterUnknown = false))
        assertEquals(copy.SESSION_ENDED_OUTCOME_UNKNOWN, flow.refusedMessage(ApiException(401, "unauthorized", "no"), afterUnknown = true))
        assertEquals(copy.CREDENTIAL_CHANGED, flow.refusedMessage(ApiException(401, "credential_changed", "no"), afterUnknown = true))
        assertEquals(copy.SESSION_ENDED_OUTCOME_UNKNOWN, flow.checkMessage(DeletionCheck.SessionEnded))
        assertEquals(copy.OUTCOME_UNKNOWN, flow.checkMessage(DeletionCheck.Unreachable))
    }
}
