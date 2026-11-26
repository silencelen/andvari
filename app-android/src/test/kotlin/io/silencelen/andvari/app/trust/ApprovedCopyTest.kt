package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.FirstRunNotice
import io.silencelen.andvari.core.app.JoinMode
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.fake.FakeAppApi
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
import kotlin.test.assertTrue

/**
 * The owner's approved words for the 28 entries of the copy page of 2026-11-15, where this app shows them: pinned word
 * for word (they are his, so a change here is a change he did not approve), and where they replaced a placeholder, the
 * placeholder is gone.
 */
class ApprovedCopyTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
    }

    private fun firstRunWith(mode: JoinMode, full: Boolean = false): EntryScreen.FirstRun {
        val api = FakeAppApi(AppPlatform.ANDROID, null)
        api.script.publicInstance.mode = mode
        api.script.publicInstance.full = full
        api.start()
        return assertIs(api.snapshot.entry)
    }

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun theApprovedWordsAreTheOwnersWordForWord() {
        assertEquals("Sign-up is invitation-only right now", Approved.FIRST_SIGNUP_INVITATION_ONLY)
        assertEquals("If someone sent you an invitation link, use {0}.", Approved.FIRST_SIGNUP_INVITATION_ONLY_LINE)
        assertEquals("Sign-up is closed right now", Approved.FIRST_SIGNUP_CLOSED)
        assertEquals("You can still sign in to an account you already have.", Approved.FIRST_SIGNUP_CLOSED_LINE)
        assertEquals("Some old andvari data is still on this device", Approved.OLD_DATA_NOT_REMOVED_TITLE)
        assertEquals(
            "andvari couldn't remove data that an earlier version left on this device. This version never opens it. andvari will try again each time it starts.",
            Approved.OLD_DATA_NOT_REMOVED_BODY,
        )
        assertEquals("This address doesn't match the server's identity card", Approved.CARD_OTHER_ADDRESS_TITLE)
        assertEquals("This server says it changed", Approved.GATE_TITLE_KIND_CHANGE)
        assertEquals(
            "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened.",
            Approved.CARD_NOT_VERIFIED,
        )
        assertEquals("andvari can't read its record of this server", Approved.CARD_RECORD_DAMAGED_TITLE)
        assertEquals("andvari didn't follow this move", Approved.CARD_MOVE_NOT_FOLLOWED_TITLE)
        assertEquals("Is this your account?", Approved.RECOVERY_CHECK_ACCOUNT_TITLE)
        assertEquals(CopyKey.RECOVERY_CHECK_ACCOUNT_ID.english + ".", Approved.RECOVERY_CHECK_ACCOUNT_BODY, "the design's sentence with its full stop")
        assertEquals("It's different", Approved.RECOVERY_CHECK_ACCOUNT_DIFFERENT)
        assertEquals(
            "andvari stopped. No password was set and nothing was changed. Tell the operator that the account they restored wasn't yours.",
            Approved.RECOVERY_CHECK_STOPPED,
        )
        assertEquals("If you don't recognise them, choose Don't use.", Approved.PERSON_FROM_OTHER_DEVICE_HINT)
        assertEquals("Don't use", Approved.PERSON_DONT_USE)
        assertEquals("Review the list", Approved.PEOPLE_REVIEW_THE_LIST)
        assertEquals("{0} wants to share a vault with you. Confirm them on this device first.", Approved.INCOMING_CONFIRM_FIRST)
        assertEquals("Read this to {0}.", Approved.COMPARE_READ_THIS)
        assertEquals("Ask {0} to read the code on their device, then type it here.", Approved.COMPARE_TYPE_THEIRS)
        assertEquals("A shared vault andvari can't open", Approved.VAULT_KEY_MISSING_TITLE)
        assertEquals("waiting for the server", Approved.VAULT_CHANGE_WAITING_MARK)
        assertEquals("You asked {0} to take over “{1}”. They can accept until {2}.", Approved.OWNERSHIP_OFFER_NOTE)
        assertEquals(2, Approved.CARD_RECORD_DAMAGED_BODY.split('\n').size, "two paragraphs")
    }

    @Test
    fun theSharedCodesApprovedWordsAreTheOnesTheAppShowedBefore() {
        // The shared code now carries entries 3, 4, 5, 14, 27 and 28, and the app dropped its own copy of them.
        // These are the words the app's own map showed, letter for letter: the move changed none of them.
        val before = mapOf(
            CopyKey.SERVER_CREATE_ACCOUNT to "Create an account here",
            CopyKey.SERVER_SIGN_IN to "Sign in",
            CopyKey.SERVER_INVITATION_ONLY to "This server is invitation-only. To create an account, ask someone who uses it for an invitation link.",
            CopyKey.SERVER_NOT_TAKING_ACCOUNTS to "This server isn't taking new accounts right now.",
            CopyKey.LINK_REQUIRED_TITLE to "This device needs to be linked",
            CopyKey.LINK_REQUIRED_BODY to
                "{0} on {1} ({2}) has “New devices must be linked” turned on, and this device is new to it. Your master password was right. Link this device from one you already use. If you have none, recover the account with your recovery kit, which sets a new master password and turns this setting off.",
            CopyKey.OWNER_OUT_OF_SPACE_YOURS to "This wasn't saved. You own this vault: remove items or attachments you no longer need, or ask the operator for more space.",
            CopyKey.OWNER_OUT_OF_SPACE_THEIRS to "This wasn't saved. Ask the vault's owner to free up space.",
        )
        for ((key, words) in before) {
            assertFalse(key.reserved, "$key")
            assertFalse(key.awaitingOwner, "$key")
            assertEquals(words, UiText.of(key).shown(), "$key")
        }
        assertTrue(CopyKey.entries.none { it.reserved }, "no key is reserved any more: ${CopyKey.entries.filter { it.reserved }}")
        assertFalse(src("UiText.kt").contains("val reserved"), "the app's own map is gone")
        assertEquals(
            "This server is invitation-only. To create an account, ask someone who uses it for an invitation link.",
            UiText.of(assertIs<EntryScreen.Server>(at(FakeScene.SERVER_INVITATION_ONLY).first.snapshot.entry).notTaking!!).shown(),
        )
        assertEquals("This server isn't taking new accounts right now.", UiText.of(CopyKey.SERVER_NOT_TAKING_ACCOUNTS).shown())
    }

    @Test
    fun theFirstScreenSaysClosedThenFullThenInvitationOnly() {
        val invitation = firstRunChoices(firstRunWith(JoinMode.INVITATION_ONLY))[1]
        assertEquals("Sign-up is invitation-only right now", invitation.label.shown())
        assertFalse(invitation.enabled)
        assertEquals("If someone sent you an invitation link, use ${CopyKey.FIRST_SCAN_INVITE.english}.", invitation.line?.shown())

        val closed = firstRunChoices(firstRunWith(JoinMode.CLOSED, full = true))[1]
        assertEquals("Sign-up is closed right now", closed.label.shown(), "closed comes before full")
        assertFalse(closed.enabled)
        assertEquals("You can still sign in to an account you already have.", closed.line?.shown())

        val full = firstRunChoices(firstRunWith(JoinMode.INVITATION_ONLY, full = true))[1]
        assertEquals(CopyKey.FIRST_SIGNUP_FULL.english, full.label.shown(), "full comes before invitation-only")
        assertEquals(CopyKey.FIRST_CREATE_ACCOUNT_LINE.english, full.line?.shown())
    }

    @Test
    fun theStoppedRecoveryNoticeAndTheAccountCheckSayTheApprovedWords() {
        val (api, _) = at(FakeScene.FIRST_RUN_RECOVERY_STOPPED)
        assertEquals(FirstRunNotice.RECOVERY_STOPPED, assertIs<EntryScreen.FirstRun>(api.snapshot.entry).notice)
        val first = src("EntryScreens.kt")
        assertTrue(first.contains("FirstRunNotice.RECOVERY_STOPPED -> UiText.Plain(Approved.RECOVERY_CHECK_STOPPED)"))
        val check = src("LinkAndRecoveryScreens.kt").substringAfter("fun CheckAccountScreen(").substringBefore("\n}\n")
        assertTrue(check.indexOf("Approved.RECOVERY_CHECK_ACCOUNT_TITLE") in 0 until check.indexOf("screen.accountId"), "the title above the ID")
        // Below the ID, first, the line that names the kit (design §9.3 step 4); the older email-only body is not shown.
        assertTrue(check.indexOf("checkAccountLines(screen)") > check.indexOf("screen.accountId"), "the kit's line below it")
        assertTrue("Approved.RECOVERY_CHECK_ACCOUNT_BODY" !in check, "the email-only sentence is not shown first, or at all")
        assertTrue(check.contains("Approved.RECOVERY_CHECK_ACCOUNT_DIFFERENT") && check.contains("rejectRecoveredAccount"))
        assertTrue(check.contains("Approved.RECOVERY_CHECK_ACCOUNT_NOT_NOW") && check.contains("recoveredAccountNotNow"))
    }

    @Test
    fun theAddressMismatchNamesBothAddressesInTheApprovedSentence() {
        val (api, _) = at(FakeScene.ADDRESS_MISMATCH)
        val screen = assertIs<EntryScreen.AddressMismatch>(api.snapshot.entry)
        val line = addressMismatchLine(screen)
        assertFalse(line.isPlaceholder)
        assertEquals(
            "The server at ${screen.dialed} showed an identity card made for a different address, ${screen.cardNames}. andvari didn't connect, and nothing of yours " +
                "was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server.",
            line.shown(),
        )
    }

    @Test
    fun theCardStatesSayTheApprovedWords() {
        val card = src("EntryScreens.kt").substringAfter("fun InstanceCard(").substringBefore("\n}\n")
        assertTrue(card.contains("is InstanceCardState.Damaged -> {\n            CardRecordDamaged(instance.label.origin)"))
        assertTrue(card.contains("is InstanceCardState.NotVerified -> Say(UiText.Plain(Approved.CARD_NOT_VERIFIED))"))
        assertTrue(card.contains("Approved.CARD_MOVE_NOT_FOLLOWED_BODY, card.toOrigin"))
        assertTrue(src("AccountScreens.kt").contains("CardRecordDamaged(instance.label.origin)"), "the lock screen says the same")
        assertEquals(
            "The record this device keeps of the identity of https://a.example is damaged, or comes from a newer version of andvari.",
            UiText.approved(Approved.CARD_RECORD_DAMAGED_BODY, "https://a.example").shown().substringBefore(" Without"),
        )
    }

    @Test
    fun oldDataSaysTheApprovedTitleBodyAndButtons() {
        val notice = src("TrustApp.kt").substringAfter("fun OldDataNotice(").substringBefore("\n}\n")
        for (k in listOf("OLD_DATA_NOT_REMOVED_TITLE", "OLD_DATA_NOT_REMOVED_BODY", "OLD_DATA_NOT_REMOVED_TRY_AGAIN", "OLD_DATA_NOT_REMOVED_CONTINUE")) {
            assertTrue(notice.contains("Approved.$k"), k)
        }
        assertTrue(notice.contains("Approved.OLD_DATA_NOT_REMOVED_CONTINUE)) { model.api.acknowledgeOldData(notice) }"))
        val settings = src("AccountScreens.kt").substringAfter("s.oldData?.let").substringBefore("Gap()")
        assertTrue(settings.contains("Approved.OLD_DATA_NOT_REMOVED_TITLE") && settings.contains("Approved.OLD_DATA_NOT_REMOVED_TRY_AGAIN"))
    }

    @Test
    fun sharedVaultRowsSayTheApprovedWords() {
        val (api, _) = at(FakeScene.VAULT_STATES)
        val vaults = assertNotNull(api.snapshot.account).vaults
        val frozen = vaults.first { it.log == VaultLogState.FROZEN }
        assertEquals(Approved.VAULT_HISTORY_FORKED, logStateLine(frozen)?.shown())
        val missing = vaults.first { it.log == VaultLogState.KEY_MISSING }
        assertEquals(Approved.VAULT_KEY_MISSING, logStateLine(missing)?.shown())
        if (missing.name == null) assertEquals("A shared vault andvari can't open", vaultRowName(missing))
        vaults.firstOrNull { it.log == VaultLogState.CONFIRM_FIRST }?.let { row ->
            assertEquals("${row.sharedBy?.serverName.orEmpty()} wants to share a vault with you. Confirm them on this device first.", logStateLine(row)?.shown())
        }
        val family = vaults.first { it.ownerOutOfSpace }
        val expected = if (family.role == RoleInVault.OWNER) CopyKey.OWNER_OUT_OF_SPACE_YOURS.english else CopyKey.OWNER_OUT_OF_SPACE_THEIRS.english
        assertEquals(expected, outOfSpaceLine(family)?.shown())
        val list = src("VaultScreens.kt")
        // The mark only where the shared code draws no waiting change of its own: that one is said by its own lines.
        assertTrue(list.contains("if (v.changeWaiting && v.waiting == null) Quiet(UiText.Plain(Approved.VAULT_CHANGE_WAITING_MARK))"))
        assertTrue(list.contains("Quiet(UiText.of(CopyKey.OWNER_OUT_OF_SPACE))\n        outOfSpaceLine(v)?.let { Quiet(it) }"), "under the design's sentence")
        assertEquals(
            "andvari sent your change but got no answer from this server, so it can't tell yet whether it went through. It will keep sending the same change " +
                "until the server confirms it. You don't need to do it again.",
            UiText.forResult(VaultActionResult.SENT_PENDING, 0)?.shown(),
        )
    }

    @Test
    fun theMembersListSaysWhyItMayBeIncomplete() {
        val members = src("VaultScreens.kt").substringAfter("fun MembersView(").substringBefore("\n}\n")
        val heading = members.indexOf("CopyKey.MEMBERS_MAY_BE_INCOMPLETE.english")
        val why = members.indexOf("Approved.MEMBERS_MAY_BE_INCOMPLETE_WHY")
        assertTrue(heading in 0 until members.indexOf("for (m in screen.members)"), "in brackets after the heading")
        assertTrue(why > members.indexOf("for (m in screen.members)"), "the line under the list")
        assertEquals(
            "An item in this vault mentions history the server hasn't shown, so there may be members this device can't see.",
            Approved.MEMBERS_MAY_BE_INCOMPLETE_WHY,
        )
    }

    @Test
    fun peopleSayTheApprovedWords() {
        val prompts = src("PeopleScreens.kt")
        val newPerson = prompts.substringAfter("is AccountPrompt.NewPerson -> {").substringBefore("is AccountPrompt.PeopleList")
        assertTrue(newPerson.indexOf("Approved.PERSON_FROM_OTHER_DEVICE_HINT") < newPerson.indexOf("Approved.PERSON_USE_ON_THIS_DEVICE"))
        assertTrue(newPerson.contains("Approved.PERSON_DONT_USE), enabled = !s.busy) { model.act { contacts.dontUseOnThisDevice(p) } }"))
        assertTrue(prompts.contains("Say(UiText.Plain(Approved.PEOPLE_NOT_REVIEWED))"))
        assertTrue(prompts.contains("Approved.PEOPLE_REVIEW_THE_LIST), enabled = !s.busy) { model.act { contacts.reviewPeople(screen) } }"))
        val (api, _) = at(FakeScene.COMPARE_READY)
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(assertNotNull(api.snapshot.account).comparing)
        assertEquals("Read this to ${ready.label}.", UiText.approved(Approved.COMPARE_READ_THIS, ready.label).shown())
        assertTrue(prompts.contains("Say(UiText.approved(Approved.COMPARE_READ_THIS, c.label))"))
        // The line is held once and also labels the field (ApprovedWordsThatDidNotFitTest).
        assertTrue(prompts.contains("val typeTheirs = UiText.approved(Approved.COMPARE_TYPE_THEIRS, c.label)") && prompts.contains("Say(typeTheirs)"))
    }

    @Test
    fun theOfferNoteIsTheOwnersOnly() {
        assertEquals(
            "You asked Bo to take over “Trips”. They can accept until 1 Dec 2026.",
            UiText.approved(Approved.OWNERSHIP_OFFER_NOTE, "Bo", "Trips", "1 Dec 2026").shown(),
        )
        val fn = src("VaultScreens.kt").substringAfter("internal fun offerLine(").substringBefore("\n\n")
        // The person offered first, then the owner: only the owner who made the offer reads the owner's note.
        assertTrue(fn.indexOf("offer.toMe -> UiText.ph(Placeholder.VAULT_OFFER_TO_YOU)") in 0 until fn.indexOf("row.role == RoleInVault.OWNER ->"))
        assertTrue(fn.contains("else -> UiText.ph(Placeholder.VAULT_OFFER"), "any other member sees the line that names the person offered")
    }

    @Test
    fun fillingIsOnePassAndLeavesUnknownSlots() {
        assertEquals("a {0} b", fillTemplate("{0} {1}", listOf("a {0}", "b")))
        assertEquals("x {1}", fillTemplate("{0} {1}", listOf("x")))
    }
}
