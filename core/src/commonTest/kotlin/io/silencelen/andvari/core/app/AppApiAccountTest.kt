package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeContact
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeVault
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The signed-in half of IF-3, walked through the fake: contacts and codes, links, the vault log's actions and
 * states, incoming vaults, the card, deletion, recovery, devices and the master password.
 */
class AppApiAccountTest {
    private fun signedIn(): FakeAppApi = FakeScenes.at(FakeScene.VAULTS)

    /** The account the fake is signed in to, as the world holds it. */
    private fun FakeAppApi.me(): FakeAccount =
        assertNotNull(scriptServer(assertNotNull(snapshot.instance).label.origin).accounts[account.email])

    private fun FakeAppApi.person(label: String): FakeContact = me().contacts.first { it.label == label }

    private fun FakeAppApi.held(name: String): FakeVault = me().vaults.first { it.name == name }

    private fun FakeAppApi.members(name: String): MembersScreen {
        assertEquals(VaultActionResult.DONE, await { vaults.openMembers(vault(name)) })
        return assertNotNull(account.members)
    }

    private fun MembersScreen.row(label: String): MemberRow = members.first {
        val who = it.who
        (who is PersonName.Contact && who.label == label) || (who is PersonName.Unverified && who.serverName?.contains(label) == true)
    }

    // ---- §6.9, §8.5, §6.11: contacts and codes ----

    @Test
    fun aHandoverToTheSignedInAccountSignsAPhoneOutWithTheNotice() {
        val app = signedIn()
        app.script.handoverMadeThisAccountTheOperator()
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertEquals(FirstRunNotice.OPERATOR_NEEDS_COMPUTER, app.on<EntryScreen.FirstRun>().notice)
        assertNull(app.snapshot.account)
        // The owner's decision of 2026-11-16, on the fake: the account is held on the first screen until the person removes it.
        val held = assertNotNull(app.on<EntryScreen.FirstRun>().heldAsOperator)
        assertEquals(CopyKey.OPERATOR_HELD_ON_PHONE, held.line.key)
        assertEquals(CopyKey.OPERATOR_HELD_REMOVE_UNKNOWN, held.removeLine.key)
        app.entry.dismissNotice(app.on())
        assertNotNull(app.on<EntryScreen.FirstRun>().heldAsOperator, "not taken away with the notice")
        assertEquals(PlainResult.DONE, await { app.entry.removeHeldOperatorAccount(held) })
        assertNull(app.on<EntryScreen.FirstRun>().heldAsOperator)
        assertNull(app.script.heldAsOperator)
    }

    @Test
    fun contactsAreListedAndRemovedAndALabelFollowsItsKey() {
        val app = signedIn()
        assertNull(app.account.contacts, "a screen is null until it is opened")
        val bo = app.contact("Bo")
        assertTrue(bo.compared && bo.currentHere)
        val cy = app.contact("Cy")
        assertFalse(cy.compared)
        assertTrue(cy.currentHere)
        assertIs<PersonName.Contact>(app.members("Family").row("Bo").who)

        assertEquals(PlainResult.DONE, await { app.contacts.removeContact(bo) })
        assertEquals(listOf("Cy"), assertNotNull(app.account.contacts).contacts.map { it.label })
        assertEquals(PlainResult.STALE, await { app.contacts.removeContact(bo) })
        // The vault is untouched, and its member is no longer someone this account vouches for (T-R5).
        val unverified = assertNotNull(app.account.members).members.map { it.who }.filterIsInstance<PersonName.Unverified>()
        assertEquals(2, unverified.size)
        assertEquals("unverified member (as the server names them)", CopyKey.MEMBER_UNVERIFIED.english)
        app.contacts.closeContacts()
        assertNull(app.account.contacts)
    }

    @Test
    fun aContactMadeOnAnotherDeviceCountsHereAfterOneTap() {
        val app = signedIn()
        val dee = assertNotNull(app.script.otherDeviceAddsContact("Dee", "iPad"))
        val prompt = app.prompt<AccountPrompt.NewPerson>()
        assertEquals("New person from your iPad: Dee — Use on this device?", prompt.line.english)
        val row = app.contact("Dee")
        assertFalse(row.currentHere)
        assertEquals("confirm on this device", CopyKey.CONFIRM_ON_THIS_DEVICE.english)
        // Until then they cannot be given a vault from here, and a vault they share waits.
        assertEquals(VaultActionResult.NOT_A_CONTACT_HERE, await { app.vaults.addMember(app.members("Family"), row, MemberRole.READER) })
        val waiting = assertNotNull(app.script.contactSharesVault(dee, "Recipes"))
        assertFalse(app.hasPrompt<AccountPrompt.IncomingVault>())
        val listed = app.account.vaults.first { it.vaultId == waiting.vaultId }
        assertEquals(VaultLogState.CONFIRM_FIRST, listed.log)
        assertNull(listed.name, "nothing is decrypted, so there is no name to show")
        assertEquals("Dee", listed.sharedBy?.serverName)

        assertEquals(PlainResult.DONE, await { app.contacts.useOnThisDevice(prompt) })
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>())
        assertTrue(app.contact("Dee").currentHere)
        assertEquals(PlainResult.STALE, await { app.contacts.useOnThisDevice(prompt) })
    }

    @Test
    fun aPasswordOnlyDeviceShowsThePeopleListOnceAndUsesOnlyTheTickedOnes() {
        val app = FakeScenes.at(FakeScene.PEOPLE_LIST)
        val list = app.prompt<AccountPrompt.PeopleList>()
        assertEquals(listOf("Bo", "Cy"), list.people.map { it.label })
        assertTrue(list.people.none { it.currentHere })
        assertEquals(CopyKey.PEOPLE_BODY, list.body)
        assertEquals(CopyKey.PEOPLE_BODY_OPERATOR, AccountPrompt.PeopleList(emptyList(), operatorClause = true).body)
        assertTrue(CopyKey.PEOPLE_BODY_OPERATOR.english.contains(", or the operator, because you chose operator recovery."))
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>(), "the list stands in for the one-tap prompts")

        // "Later" changes nothing, and the list is put away: it does not come back by itself at the next unlock.
        app.contacts.peopleLater(list)
        assertFalse(app.hasPrompt<AccountPrompt.PeopleList>())
        app.script.lock()
        app.script.unlock()
        assertFalse(app.hasPrompt<AccountPrompt.PeopleList>())
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>(), "nor do one-tap prompts stand in for it")
        // The list of contacts says so, and brings it back when asked.
        assertEquals(PlainResult.DONE, await { app.contacts.openContacts() })
        val notReviewed = assertNotNull(app.account.contacts)
        assertTrue(notReviewed.peopleNotReviewed)
        app.contacts.reviewPeople(notReviewed)
        assertFalse(assertNotNull(app.account.contacts).peopleNotReviewed)
        val again = app.prompt<AccountPrompt.PeopleList>()

        val bo = again.people.first { it.label == "Bo" }
        assertEquals(PlainResult.DONE, await { app.contacts.usePeople(again, listOf(bo.userId, "someone-not-listed")) })
        assertFalse(app.hasPrompt<AccountPrompt.PeopleList>())
        assertTrue(app.contact("Bo").currentHere)
        assertFalse(app.contact("Cy").currentHere, "an unticked person stays out")
        // Unticking was the answer: no prompt asks about Cy again, at this unlock or a later one.
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>())
        app.script.lock()
        app.script.unlock()
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>())
        assertFalse(app.hasPrompt<AccountPrompt.PeopleList>())
        // The list of contacts is where Cy can still be confirmed, when the person is sure.
        assertEquals(PlainResult.DONE, await { app.contacts.confirmOnThisDevice(app.contact("Cy")) })
        assertTrue(app.contact("Cy").currentHere)
    }

    @Test
    fun aNewPersonCanBeRefusedOnThisDeviceAndConfirmedLaterFromTheList() {
        val app = signedIn()
        assertNotNull(app.script.otherDeviceAddsContact("Dee", "iPad"))
        val prompt = app.prompt<AccountPrompt.NewPerson>()
        assertEquals("iPad", prompt.madeOn)
        // "Don't use": the contact stays in the account, is not used here, and the prompt does not return.
        app.contacts.dontUseOnThisDevice(prompt)
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>())
        app.script.lock()
        app.script.unlock()
        assertFalse(app.hasPrompt<AccountPrompt.NewPerson>())
        val row = app.contact("Dee")
        assertFalse(row.currentHere)
        assertEquals("iPad", row.madeOn)
        assertEquals(PlainResult.DONE, await { app.contacts.confirmOnThisDevice(row) })
        assertTrue(app.contact("Dee").currentHere)

        // A device the account's list cannot name is "another of your devices", never an id.
        assertNotNull(app.script.unnamedDeviceAddsContact("Mal"))
        val unnamed = app.prompt<AccountPrompt.NewPerson>()
        assertEquals("", unnamed.madeOn)
        assertEquals("New person from another of your devices: Mal — Use on this device?", unnamed.line.english)
    }

    @Test
    fun aVaultFromAContactNotConfirmedHereWaitsForTheConfirmationAndAStrangersForAConnection() {
        val app = signedIn()
        val dee = assertNotNull(app.script.otherDeviceAddsContact("Dee", "iPad"))
        val waiting = assertNotNull(app.script.contactSharesVault(dee, "Recipes"))
        val stranger = assertNotNull(app.script.strangerSharesVault("Mallory"))
        val confirmFirst = app.account.vaults.first { it.vaultId == waiting.vaultId }
        val connectFirst = app.account.vaults.first { it.vaultId == stranger.vaultId }
        // Two situations, two states: a contact that only waits for this device, and no connection at all.
        assertEquals(VaultLogState.CONFIRM_FIRST, confirmFirst.log)
        assertEquals("Dee", confirmFirst.senderToConfirm?.label)
        assertNull(confirmFirst.connectFirstLine)
        assertEquals(VaultLogState.CONNECT_FIRST, connectFirst.log)
        assertNull(connectFirst.senderToConfirm)
        assertEquals("Mallory wants to share a vault with you. Connect with them first.", connectFirst.connectFirstLine?.english)
        assertNull(confirmFirst.name)
        assertNull(confirmFirst.owner, "no log verified yet, so nothing is known of the vault but who the server says sent it")

        // Confirming the sender on this device is the way on: the vault then asks, as any incoming vault does.
        assertEquals(PlainResult.DONE, await { app.contacts.confirmOnThisDevice(assertNotNull(confirmFirst.senderToConfirm)) })
        assertEquals("Recipes", app.prompt<AccountPrompt.IncomingVault>().vaultName)
        assertTrue(app.account.vaults.none { it.vaultId == waiting.vaultId })
        assertEquals(VaultLogState.CONNECT_FIRST, app.account.vaults.first { it.vaultId == stranger.vaultId }.log)
    }

    @Test
    fun aCodeExistsOnlyAfterTheRevealAndOnlyTypingItMarksAContactCompared() {
        val app = FakeScenes.at(FakeScene.COMPARE_WAITING)
        val waiting = assertIs<CompareScreen.Waiting>(app.account.comparing)
        assertEquals("Eve", waiting.label)

        app.script.revealArrives(app.person("Eve"))
        val ready = assertIs<CompareScreen.Ready>(app.account.comparing)
        assertEquals(6, ready.code.length)
        assertFalse(ready.replacesKey)

        // A failed comparison changes nothing.
        val wrong = await { app.contacts.submitComparison(ready, "000000") }
        assertEquals(ComparisonResult.MISMATCH, wrong)
        assertEquals("The codes don't match. Don't share anything with this person until you've talked.", wrong.sentence?.english)
        assertSame(ready, app.account.comparing)
        assertFalse(app.contact("Eve").compared)

        // Each side has its own code (§6.11): typing back the one on this screen, with no one reading anything, fails.
        assertEquals(ComparisonResult.MISMATCH, await { app.contacts.submitComparison(ready, ready.code) })
        assertFalse(app.contact("Eve").compared)
        val theirs = assertNotNull(app.script.codeTheyReadOut(ready.userId))
        assertNotEquals(ready.code, theirs)

        // The person types the digits the other one read out from their own screen.
        assertEquals(ComparisonResult.DONE, await { app.contacts.submitComparison(ready, theirs) })
        assertIs<CompareScreen.Matched>(app.account.comparing)
        assertTrue(app.contact("Eve").compared)
        assertEquals(ComparisonResult.STALE, await { app.contacts.submitComparison(ready, theirs) })
        app.contacts.closeCompare()
        assertNull(app.account.comparing)

        // A second, different nonce: the link failed, and no code is shown at all.
        val failed = FakeScenes.at(FakeScene.COMPARE_LINK_FAILED)
        assertIs<CompareScreen.LinkFailed>(failed.account.comparing)
        val racing = FakeScenes.at(FakeScene.COMPARE_READY)
        val shown = assertIs<CompareScreen.Ready>(racing.account.comparing)
        racing.person("Cy").linkFailed = true
        assertEquals(ComparisonResult.LINK_FAILED, await { racing.contacts.submitComparison(shown, racing.script.codeTheyReadOut(shown.userId)!!) })
        assertIs<CompareScreen.LinkFailed>(racing.account.comparing)
        assertFalse(racing.contact("Cy").compared)
    }

    @Test
    fun aContactsNewKeyIsAcceptedOnlyByAMatchedCode() {
        val app = signedIn()
        app.script.contactKeyChanges(app.person("Bo"))
        val prompt = app.prompt<AccountPrompt.KeyChanged>()
        assertEquals(
            "Bo's key is different from the one you connected with before. They may have reinstalled or made a new account. Compare codes to accept the new key.",
            prompt.line.english,
        )
        assertEquals(PlainResult.DONE, await { app.contacts.openCompareForNewKey(prompt) })
        val ready = assertIs<CompareScreen.Ready>(app.account.comparing)
        assertTrue(ready.replacesKey)
        assertEquals(ComparisonResult.MISMATCH, await { app.contacts.submitComparison(ready, "111111") })
        assertTrue(app.hasPrompt<AccountPrompt.KeyChanged>(), "the old key stays pinned")
        assertEquals(ComparisonResult.MISMATCH, await { app.contacts.submitComparison(ready, ready.code) }, "this side's own code is not the other's")
        assertEquals(ComparisonResult.DONE, await { app.contacts.submitComparison(ready, app.script.codeTheyReadOut(ready.userId)!!) })
        assertFalse(app.hasPrompt<AccountPrompt.KeyChanged>())
    }

    // ---- §6: links ----

    @Test
    fun aLinkWithSharesGivesThemOutOnlyAfterTheCodesOrBehindTheWarning() {
        val app = signedIn()
        val family = app.vault("Family")
        assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(listOf(ShareChoice(family.vaultId, MemberRole.WRITER)), LinkLifetimes.IN_PERSON_MINUTES) })
        val link = assertNotNull(app.account.links).links.single()
        assertEquals(OwnLinkKind.CONNECT, link.kind)
        assertEquals(family.vaultId, link.shares.single().vaultId)

        // The link itself is read on request; the countdown runs from what the server answered, on the fake's clock.
        assertTrue(assertNotNull(app.links.linkToShare(link)).startsWith("https://andvaripass.com/l#v2."))
        assertEquals(15 * MINUTE, app.links.linkTimeLeftMs(link))
        app.script.advance(5 * MINUTE)
        assertEquals(10 * MINUTE, app.links.linkTimeLeftMs(link))

        val fay = assertNotNull(app.script.someoneAnswers(link, "Fay"))
        assertTrue(assertNotNull(app.account.links).links.isEmpty())
        assertNull(app.links.linkToShare(link), "an answered link has no secret left to show")
        assertFalse(app.contact("Fay").compared)
        val waiting = assertNotNull(app.account.links).waitingShares.single()
        assertEquals("Share Family with Fay once you've compared codes", waiting.line.english)
        assertTrue(app.members("Family").members.none { (it.who as? PersonName.Contact)?.label == "Fay" }, "nothing was shared by the answer alone")

        // By hand, only behind the warning, and only this vault for this person.
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, await { app.links.releaseShare(waiting) })
        val warning = assertNotNull(app.account.shareWarning)
        assertEquals("Family", warning.vaultName)
        assertEquals("Fay", warning.label)
        assertEquals("You haven't compared codes with this person. Anyone who saw the link first could be on the other end.", CopyKey.UNCOMPARED_WARNING.english)
        app.vaults.cancelUncomparedShare(warning)
        assertNull(app.account.shareWarning)
        assertEquals(VaultActionResult.STALE, await { app.vaults.confirmUncomparedShare(warning) })
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, await { app.links.releaseShare(waiting) })
        assertEquals(VaultActionResult.DONE, await { app.vaults.confirmUncomparedShare(assertNotNull(app.account.shareWarning)) })
        assertEquals(RoleInVault.WRITER, assertNotNull(app.account.members).row("Fay").role)
        assertTrue(assertNotNull(app.account.links).waitingShares.isEmpty())

        // Or by the codes: a match releases what the link carried.
        assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(listOf(ShareChoice(family.vaultId, MemberRole.READER)), 60) })
        val gil = assertNotNull(app.script.someoneAnswers(assertNotNull(app.account.links).links.single(), "Gil"))
        assertEquals(PlainResult.DONE, await { app.contacts.openCompare(app.contact("Gil")) })
        assertEquals(ComparisonResult.DONE, await { app.contacts.submitComparison(assertIs(app.account.comparing), gil.theirCode) })
        assertEquals(RoleInVault.READER, assertNotNull(app.account.members).row("Gil").role)
        assertNotSame(fay, gil)
    }

    @Test
    fun aRevokedOrExpiredLinkIsGoneAndALateAnswerIsIgnored() {
        val app = signedIn()
        assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(emptyList(), 60) })
        val revoked = assertNotNull(app.account.links).links.single()
        assertEquals(PlainResult.DONE, await { app.links.revokeLink(revoked) })
        assertTrue(assertNotNull(app.account.links).links.isEmpty())
        assertNull(app.script.someoneAnswers(revoked, "Late"), "whatever the server says (T-R3)")
        assertEquals(PlainResult.STALE, await { app.links.revokeLink(revoked) })

        assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(emptyList(), LinkLifetimes.SHORTEST_MINUTES) })
        val short = assertNotNull(app.account.links).links.single()
        app.script.advance(6 * MINUTE)
        assertTrue(assertNotNull(app.account.links).links.isEmpty())
        assertEquals(0L, app.links.linkTimeLeftMs(short))
        assertNull(app.links.linkToShare(short))
        assertNull(app.script.someoneAnswers(short, "Late"))
        assertEquals(2, assertNotNull(app.account.contacts ?: app.contact("Bo").let { app.account.contacts }).contacts.size)
        app.links.closeLinks()
        assertNull(app.account.links)
    }

    @Test
    fun linkCreationHasItsLimits() {
        val app = signedIn()
        assertEquals(LinkCreateResult.BAD_LIFETIME, await { app.links.createConnectLink(emptyList(), 4) })
        assertEquals(LinkCreateResult.BAD_LIFETIME, await { app.links.createConnectLink(emptyList(), LinkLifetimes.CONNECT_LONGEST_MINUTES + 1) })
        // A share is the person choosing a vault they own for whoever answers.
        assertEquals(LinkCreateResult.NOT_ALLOWED, await { app.links.createConnectLink(listOf(ShareChoice(app.vault("Work").vaultId, MemberRole.READER)), 60) })
        // On a public instance only the operator makes register links.
        assertEquals(PlainResult.DONE, await { app.links.openLinks() })
        assertFalse(assertNotNull(app.account.links).invitationsAllowed)
        assertEquals(LinkCreateResult.NOT_ALLOWED, await { app.links.createInvitation(60) })
        repeat(20) { assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(emptyList(), 60) }) }
        assertEquals(LinkCreateResult.TOO_MANY_OPEN_LINKS, await { app.links.createConnectLink(emptyList(), 60) })

        // On a family's server any member may send an invitation instead.
        val family = FakeScenes.at(FakeScene.RECOVERY)
        assertEquals(LinkCreateResult.DONE, await { family.links.createInvitation(60) })
        val links = assertNotNull(family.account.links)
        assertTrue(links.invitationsAllowed)
        assertEquals(OwnLinkKind.INVITATION, links.links.single().kind)
        assertEquals("Send an invitation instead", CopyKey.SEND_INVITATION_INSTEAD.english)
        assertEquals(LinkCreateResult.BAD_LIFETIME, await { family.links.createInvitation(LinkLifetimes.INVITATION_LONGEST_MINUTES + 1) })
    }

    /** The fake keeps the engine's rule: an account with no name kept on this device names itself before any link. */
    @Test
    fun anAccountWithNoNameKeptHereAsksForItBeforeAnyLink() {
        val app = FakeScenes.at(FakeScene.OPENED_CONNECT)
        val prompt = assertIs<OpenedInvite.Connect>(app.account.opened)
        assertNotNull(app.links.ownName(), "a seeded account goes by a name here")
        assertNotNull(app.session).account.nameHere = null
        assertNull(app.links.ownName())
        assertEquals(ConnectResult.NAME_NEEDED, await { app.links.connect(prompt) })
        assertTrue(app.account.opened === prompt, "the question stays")
        assertTrue(app.me().contacts.none { it.label == "Eve" }, "nothing was answered")
        assertEquals(LinkCreateResult.NAME_NEEDED, await { app.links.createConnectLink(emptyList(), 60) })
        assertEquals(OwnNameResult.NOT_A_NAME, app.links.setOwnName(" padded "))
        assertEquals(OwnNameResult.DONE, app.links.setOwnName("Me here"))
        assertEquals("Me here", app.links.ownName())
        assertEquals(ConnectResult.DONE, await { app.links.connect(prompt) })
        assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(emptyList(), 60) })
    }

    @Test
    fun anInviteOpenedWhileSignedInAsksBeforeAnythingIsSent() {
        val app = FakeScenes.at(FakeScene.OPENED_CONNECT)
        val script = app.script
        val prompt = assertIs<OpenedInvite.Connect>(app.account.opened)
        assertEquals("Connect with Eve (as they call themselves)?", prompt.question.english)
        assertTrue(app.me().contacts.none { it.label == "Eve" }, "nothing is pinned or sent before the person confirms")
        assertEquals(ConnectResult.DONE, await { app.links.connect(prompt) })
        // The answered invite names the contact it made, so the codes can follow at once (in person, §6.7).
        val connected = assertIs<OpenedInvite.Connected>(app.account.opened)
        assertEquals("Eve", connected.contact.label)
        assertFalse(connected.contact.compared)
        assertTrue(connected.contact.currentHere)
        assertEquals(PlainResult.DONE, await { app.contacts.openCompare(connected.contact) })
        assertIs<CompareScreen.Waiting>(app.account.comparing)
        app.contacts.closeCompare()
        app.links.dismissOpened()
        assertNull(app.account.opened)
        assertFalse(app.contact("Eve").compared)
        assertEquals(ConnectResult.STALE, await { app.links.connect(prompt) })

        // Only an invite is acted on here too.
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, await { app.links.openInvite(script.deviceLinkFrom(app.me(), "MacBook"), PayloadSource.SCANNED) })
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, await { app.links.openInvite(script.kitOf(app.me()), PayloadSource.PASTED) })
        assertEquals(InviteResult.NOT_USABLE_SIGNED_IN, await { app.links.openInvite(script.invitation(script.publicInstance, "Bo"), PayloadSource.PASTED) })
        val here = assertNotNull(app.snapshot.instance).label
        val notUsed = assertNotNull(app.account.inviteNotUsed, "the approved sentence, filled")
        assertEquals(CopyKey.ALREADY_SIGNED_IN_THERE, notUsed.key)
        assertEquals(listOf(here.name, here.origin), notUsed.values)
        assertEquals(InviteResult.NOT_USABLE_SIGNED_IN, await { app.links.openInvite(script.enrolLink(script.publicInstance, null), PayloadSource.PASTED) })
        assertEquals(CopyKey.ALREADY_SIGNED_IN_THERE_ENROL, assertNotNull(app.account.inviteNotUsed).key, "an enrol link leaves out the last sentence")
        assertTrue(!CopyKey.ALREADY_SIGNED_IN_THERE_ENROL.english.contains("Connect with someone"))
        app.links.dismissOpened()
        assertNull(app.account.inviteNotUsed)
        assertEquals(LinkCreateResult.DONE, await { app.links.createConnectLink(emptyList(), 60) })
        val own = assertNotNull(app.links.linkToShare(assertNotNull(app.account.links).links.single()))
        assertEquals(InviteResult.OWN_LINK, await { app.links.openInvite(own, PayloadSource.PASTED) })
        assertNull(app.account.opened)

        // T12: whoever read the link first answered it; the real recipient sees that.
        val raced = script.connectInvite(script.publicInstance, "Hal")
        assertEquals(InviteResult.DONE, await { app.openAppLink(raced) })
        script.useUp(raced)
        assertEquals(ConnectResult.ALREADY_USED, await { app.links.connect(assertIs(app.account.opened)) })
        app.links.dismissOpened()
        assertNull(app.account.opened)
    }

    @Test
    fun anInviteUnderANewKeyOfAContactReplacesNothingByItself() {
        val app = FakeScenes.at(FakeScene.OPENED_KEY_CHANGED)
        val changed = assertIs<OpenedInvite.KeyChanged>(app.account.opened)
        assertTrue(changed.line.english.startsWith("Bo's key is different from the one you connected with before."))
        app.links.acknowledgeKeyChange(changed)
        assertEquals(ConnectResult.DONE, await { app.links.connect(assertIs(app.account.opened)) })
        // Bo is still the one contact, compared under the old key; the new one waits for a matched code.
        assertEquals(1, app.me().contacts.count { it.label == "Bo" })
        assertTrue(app.contact("Bo").compared)
        assertTrue(app.hasPrompt<AccountPrompt.KeyChanged>())
    }

    @Test
    fun anInviteForAnotherInstanceIsADeadEndThatOffersToSwitch() {
        val app = FakeScenes.at(FakeScene.OPENED_OTHER_INSTANCE)
        val other = assertIs<OpenedInvite.OtherInstance>(app.account.opened)
        assertEquals(
            "This invite is for Family (https://vault.family.example). You're signed in to andvari. Connecting means using an account on that other server.",
            other.line.english,
        )
        assertEquals("Switch to Family", other.switchLabel.english)
        assertEquals(ServerResult.DONE, await { app.links.switchInstance(other) })

        // Signed out of the first instance, and on with the invite at its own: here, a server that takes no sign-ups.
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertNull(app.snapshot.account)
        val dead = app.on<EntryScreen.NotTakingAccounts>()
        assertEquals("Family", dead.instance.name)
        // Signing in to an account there shows the Trust Gate first: a link offer is not a password pin.
        assertEquals(ServerResult.DONE, await { app.entry.signInWhereInvited(dead) })
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, app.on<EntryScreen.TrustGate>().prompt.wording)

        // The first instance's namespace stayed: its pin still lets this device sign in there without a gate.
        app.entry.startOver()
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.choosePublicInstance(app.on()) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertTrue(app.contact("Bo").currentHere, "and the contacts that counted on this device still do")
    }

    // ---- §3: the vault log's actions and states ----

    /** The desktop's first run, on the fake as on the engine: a compared contact added as a reader is listed at once, as a reader. */
    @Test
    fun aMemberAddedAsAReaderIsShownAtOnceAsAReader() {
        val app = signedIn()
        assertEquals(VaultActionResult.DONE, await { app.vaults.createVault("Trips") })
        val bo = app.contact("Bo")
        assertTrue(bo.compared)
        val screen = app.members("Trips")
        assertEquals(VaultActionResult.DONE, await { app.vaults.addMember(screen, bo, MemberRole.READER) })
        assertEquals(RoleInVault.READER, assertNotNull(app.account.members, "the screen stays open").row("Bo").role, "listed without reopening")
        app.vaults.closeMembers()
        assertEquals(RoleInVault.READER, app.members("Trips").row("Bo").role, "and the same reopened")
    }

    @Test
    fun theOwnerSignsEveryMembershipChange() {
        val app = signedIn()
        assertEquals(VaultActionResult.DONE, await { app.vaults.createVault("Trips") })
        val trips = app.vault("Trips")
        assertEquals(RoleInVault.OWNER, trips.role)
        assertEquals(VaultLogState.VERIFIED, trips.log)
        assertTrue(trips.writable)

        var screen = app.members("Family")
        assertTrue(screen.canManage)
        assertFalse(screen.mayBeIncomplete)
        assertEquals(listOf(RoleInVault.OWNER, RoleInVault.WRITER, RoleInVault.READER), screen.members.map { it.role })
        assertIs<PersonName.You>(screen.members.first().who)

        // add: a compared contact at once, an uncompared one only behind the warning.
        val cy = app.contact("Cy")
        assertEquals(VaultActionResult.NEEDS_UNCOMPARED_WARNING, await { app.vaults.addMember(screen, cy, MemberRole.READER) })
        assertTrue(assertNotNull(app.account.members).members.none { (it.who as? PersonName.Contact)?.label == "Cy" })
        assertEquals(VaultActionResult.DONE, await { app.vaults.confirmUncomparedShare(assertNotNull(app.account.shareWarning)) })
        screen = assertNotNull(app.account.members)
        assertEquals(RoleInVault.READER, screen.row("Cy").role)
        assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.addMember(screen, app.contact("Bo"), MemberRole.READER) }, "already a member")

        // role, remove
        assertEquals(VaultActionResult.DONE, await { app.vaults.changeRole(screen.row("Bo"), MemberRole.READER) })
        assertEquals(RoleInVault.READER, assertNotNull(app.account.members).row("Bo").role)
        assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.removeMember(screen.members.first()) }, "the owner is not removed")
        assertEquals(VaultActionResult.DONE, await { app.vaults.removeMember(screen.row("Dan")) })
        assertEquals(3, assertNotNull(app.account.members).members.size)
        assertTrue(CopyKey.REMOVE_MEMBER_WARNING.english.endsWith("To be sure, move everything to a new vault."))

        // offer, cancel
        assertEquals(VaultActionResult.DONE, await { app.vaults.offerOwnership(screen.row("Bo")) })
        val offer = assertNotNull(app.vault("Family").offer)
        assertFalse(offer.toMe)
        assertEquals("Bo", assertIs<PersonName.Contact>(offer.to).label)
        assertEquals(app.script.nowMs + 14 * DAY, offer.expiresAtMs)
        assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.offerOwnership(screen.row("Cy")) }, "one offer at a time")
        assertEquals(VaultActionResult.DONE, await { app.vaults.cancelOffer(app.vault("Family")) })
        assertNull(app.vault("Family").offer)

        // Only the owner: in a vault this account is a writer of, every owner action is refused.
        val work = app.members("Work")
        assertFalse(work.canManage)
        assertEquals(VaultActionResult.NOT_OWNER, await { app.vaults.changeRole(work.members.first { it.who is PersonName.You }, MemberRole.READER) })
        assertEquals(VaultActionResult.NOT_OWNER, await { app.vaults.deleteVault(app.vault("Work")) })
        app.vaults.closeMembers()
        assertNull(app.account.members)
    }

    @Test
    fun ownershipMovesOnlyByAnOfferTheOtherPersonAccepts() {
        val app = signedIn()
        app.script.ownerOffersOwnership(app.held("Work"), 3)
        val offered = assertNotNull(app.vault("Work").offer)
        assertTrue(offered.toMe)
        assertEquals(VaultActionResult.DONE, await { app.vaults.acceptOwnership(app.vault("Work")) })
        assertEquals(RoleInVault.OWNER, app.vault("Work").role)
        assertEquals(RoleInVault.WRITER, app.members("Work").row("Bo").role, "the old owner is a writer now")

        // Declining is the same entry the owner's withdrawal is: a cancel.
        val declining = signedIn()
        declining.script.ownerOffersOwnership(declining.held("Work"), 3)
        assertEquals(VaultActionResult.DONE, await { declining.vaults.cancelOffer(declining.vault("Work")) })
        assertNull(declining.vault("Work").offer)
        assertEquals(VaultActionResult.NOT_ALLOWED, await { declining.vaults.acceptOwnership(declining.vault("Work")) })

        val late = signedIn()
        late.script.ownerOffersOwnership(late.held("Work"), 0)
        assertEquals(VaultActionResult.OFFER_EXPIRED, await { late.vaults.acceptOwnership(late.vault("Work")) })
        val lapsed = signedIn()
        lapsed.script.ownerOffersOwnership(lapsed.held("Work"), 3)
        lapsed.script.advance(4 * DAY)
        assertNull(lapsed.vault("Work").offer, "an offer past its expiry is cleared")
    }

    @Test
    fun aDeletedVaultCanBeRestoredInItsGraceAndIsDeletedForGoodOnlyOnceTheLogSaysSo() {
        val app = signedIn()
        assertEquals(VaultActionResult.DONE, await { app.vaults.deleteVault(app.vault("Family")) })
        val deleted = app.vault("Family")
        assertEquals(app.script.nowMs + 7 * DAY, deleted.purgeAtMs)
        assertFalse(deleted.writable)
        assertEquals(VaultLogState.VERIFIED, deleted.log)
        assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.deleteVault(deleted) })
        assertEquals(VaultActionResult.DONE, await { app.vaults.restoreVault(deleted) })
        assertEquals(0L, app.vault("Family").purgeAtMs)
        assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.restoreVault(app.vault("Family")) })

        assertEquals(VaultActionResult.DONE, await { app.vaults.deleteVault(app.vault("Family")) })
        app.script.advance(8 * DAY)
        val purged = app.vault("Family")
        assertEquals(VaultLogState.PURGED, purged.log)
        assertEquals("deleted for good", purged.log.sentence?.english)
        // The device's copy is held for thirty days, never dropped on the server's word; items can still be copied out.
        assertEquals(app.script.nowMs + 30 * DAY, purged.heldUntilMs)
        assertTrue(purged.canSaveElsewhere && purged.canRemoveFromDevice && !purged.writable)
        assertEquals(VaultActionResult.DONE, await { app.vaults.saveItemsElsewhere(purged, null) })
        app.vaults.removeFromThisDevice(purged)
        assertTrue(app.account.vaults.none { it.name == "Family" })
    }

    @Test
    fun aMemberLeavesAndKeepsACopyForAWhile() {
        val app = signedIn()
        assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.leaveVault(app.vault("Family")) }, "an owner hands over or deletes")
        assertEquals(VaultActionResult.DONE, await { app.vaults.leaveVault(app.vault("Work")) })
        val left = app.vault("Work")
        assertEquals(VaultLogState.REMOVED, left.log)
        assertNull(left.role)
        assertFalse(left.removedByOwner)
        assertEquals(app.script.nowMs + 30 * DAY, left.heldUntilMs)
        assertTrue(left.canSaveElsewhere && left.canRemoveFromDevice)
    }

    @Test
    fun aVaultWhoseHistoryDoesNotCheckOutIsReadOnlyWithItsWaysOut() {
        val app = signedIn()
        app.held("Family").log = VaultLogState.FROZEN
        app.held("Work").log = VaultLogState.FAILED
        app.script.changed()
        val frozen = app.vault("Family")
        assertFalse(frozen.writable)
        assertTrue(frozen.canSaveElsewhere && frozen.canRemoveFromDevice)
        assertEquals("This shared vault's history doesn't check out — the server may be misbehaving.", app.vault("Work").log.sentence?.english)

        // Every entry but a leave is refused, and so is every write under the vault's key.
        val screen = app.members("Family")
        assertFalse(screen.canManage)
        assertEquals(VaultActionResult.READ_ONLY, await { app.vaults.addMember(screen, app.contact("Bo"), MemberRole.READER) })
        assertEquals(VaultActionResult.READ_ONLY, await { app.vaults.removeMember(screen.row("Dan")) })
        assertEquals(VaultActionResult.READ_ONLY, await { app.vaults.deleteVault(frozen) })
        assertEquals(VaultActionResult.READ_ONLY, await { app.vaults.saveItemsElsewhere(app.vault("Work"), frozen.vaultId) }, "nothing is copied in")
        // Copying out stays allowed: it writes only under the destination's key (T2-R-k).
        assertEquals(VaultActionResult.DONE, await { app.vaults.saveItemsElsewhere(frozen, null) })
        assertEquals("Items in this vault may have been changed by someone the server let in. Check what you copy.", CopyKey.CHECK_WHAT_YOU_COPY.english)
        assertEquals(VaultActionResult.DONE, await { app.vaults.leaveVault(app.vault("Work")) })
        app.vaults.removeFromThisDevice(frozen)
        assertTrue(app.account.vaults.none { it.name == "Family" })
        // A local act: the world still holds the vault.
        assertNotNull(app.held("Family"))
    }

    @Test
    fun everyVaultStateIsShownWithWhatItAllows() {
        val app = FakeScenes.at(FakeScene.VAULT_STATES)
        val byState = app.account.vaults.associateBy { it.log }
        assertEquals(VaultLogState.entries.toSet(), byState.keys)

        assertEquals("The server is showing an older version of this vault's history.", VaultLogState.WITHHELD.sentence?.english)
        assertEquals("key doesn't match this vault's history — the server may be misbehaving", VaultLogState.KEY_REFUSED.sentence?.english)
        for (state in listOf(VaultLogState.FAILED, VaultLogState.WITHHELD, VaultLogState.FROZEN)) {
            val row = assertNotNull(byState[state])
            assertTrue(!row.writable && row.canSaveElsewhere && row.canRemoveFromDevice, state.name)
        }
        // A key that was refused, or none: nothing is decrypted, so there is no name and nothing to copy.
        for (state in listOf(VaultLogState.KEY_REFUSED, VaultLogState.KEY_MISSING, VaultLogState.CONNECT_FIRST, VaultLogState.NOT_CHECKED_YET)) {
            val row = assertNotNull(byState[state])
            assertNull(row.name, state.name)
            assertTrue(!row.writable && !row.canSaveElsewhere, state.name)
            assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.openMembers(row) })
            assertEquals(VaultActionResult.NOT_ALLOWED, await { app.vaults.saveItemsElsewhere(row, null) })
        }
        val stranger = assertNotNull(byState[VaultLogState.CONNECT_FIRST])
        assertEquals("Mallory", stranger.sharedBy?.serverName)
        assertEquals("Mallory wants to share a vault with you. Connect with them first.", stranger.connectFirstLine?.english)
        assertTrue(assertNotNull(byState[VaultLogState.REMOVED]).removedByOwner)

        val family = app.vault("Family")
        assertTrue(family.historyHint)
        assertEquals("An item mentions history the server hasn't shown", CopyKey.VAULT_HISTORY_HINT.english)
        assertTrue(family.ownerOutOfSpace)
        // Approved entries 27 and 28: the line under it says whose space it is, from the row's verified role.
        val whose = if (family.role == io.silencelen.andvari.core.app.RoleInVault.OWNER) CopyKey.OWNER_OUT_OF_SPACE_YOURS else CopyKey.OWNER_OUT_OF_SPACE_THEIRS
        assertEquals(whose, family.outOfSpaceLine?.key)
        assertEquals(
            if (whose == CopyKey.OWNER_OUT_OF_SPACE_YOURS) "This wasn't saved. You own this vault: remove items or attachments you no longer need, or ask the operator for more space."
            else "This wasn't saved. Ask the vault's owner to free up space.",
            family.outOfSpaceLine?.english,
        )
        assertEquals(null, app.vault("Work").outOfSpaceLine, "a vault with space says nothing")
        val full = await { app.vaults.saveItemsElsewhere(app.vault("Work"), family.vaultId) }
        assertEquals(VaultActionResult.OUT_OF_SPACE, full)
        assertEquals("This vault's owner is out of space on this server.", full.sentence?.english)
    }

    @Test
    fun theServersRefusalsOfAnEntryAreEachTheirOwnAnswer() {
        val app = signedIn()
        app.script.noSpaceForVaults = true
        assertEquals(VaultActionResult.OUT_OF_SPACE, await { app.vaults.createVault("More") })
        app.script.noSpaceForVaults = false
        app.script.clockAhead = true
        val ahead = await { app.vaults.createVault("More") }
        assertEquals(VaultActionResult.CLOCK_AHEAD, ahead)
        assertEquals("Your device's clock is ahead. Set the correct time and try again.", ahead.sentence?.english)
        assertEquals(VaultActionResult.CLOCK_AHEAD, await { app.vaults.leaveVault(app.vault("Work")) })
        app.script.clockAhead = false
        // Signed and not acknowledged: the same bytes are sent again; the entry is never signed twice.
        app.script.appendGetsNoAnswer = true
        assertEquals(VaultActionResult.SENT_PENDING, await { app.vaults.deleteVault(app.vault("Family")) })
        app.script.failNext(Trouble.UNREACHABLE)
        assertEquals(VaultActionResult.UNREACHABLE, await { app.vaults.createVault("More") })
        app.scriptServer(app.snapshot.instance!!.label.origin).reachable = false
        assertEquals(VaultActionResult.UNREACHABLE, await { app.vaults.createVault("More") })
    }

    // ---- §3.6: incoming vaults ----

    @Test
    fun anIncomingVaultIsNeverAdoptedUnaskedAndAnAnswerIsBoundToItsAdd() {
        val app = FakeScenes.at(FakeScene.PROMPTS)
        val first = app.prompt<AccountPrompt.IncomingVault>()
        assertEquals("Bo wants to share “Holiday” with you", first.line.english)
        assertTrue(app.account.vaults.none { it.name == "Holiday" }, "not a vault of this account until it is accepted")

        // Decline: hidden, and a leave is signed so the owner sees it.
        assertEquals(VaultActionResult.DONE, await { app.vaults.declineIncoming(first) })
        assertFalse(app.hasPrompt<AccountPrompt.IncomingVault>())
        assertTrue(app.account.vaults.none { it.name == "Holiday" })

        // The owner adds the account again: the earlier answer was to another `add`, so the person is asked again (FS-R6).
        app.script.ownerAddsAgain(app.held("Holiday"))
        val second = app.prompt<AccountPrompt.IncomingVault>()
        assertNotSame(first, second)
        assertEquals(VaultActionResult.STALE, await { app.vaults.acceptIncoming(first) }, "the old prompt answers nothing")
        assertEquals(VaultActionResult.STALE, await { app.vaults.declineIncoming(first) })
        assertEquals(VaultActionResult.DONE, await { app.vaults.acceptIncoming(second) })
        assertEquals(VaultLogState.VERIFIED, app.vault("Holiday").log)
        assertFalse(app.hasPrompt<AccountPrompt.IncomingVault>())
    }

    // ---- §3.9, §3.11, §3.13: member lists and moving everything ----

    @Test
    fun theMemberListSaysWhatItCannotVouchFor() {
        val app = FakeScenes.at(FakeScene.MEMBERS_MAY_BE_INCOMPLETE)
        val screen = assertNotNull(app.account.members)
        assertTrue(screen.mayBeIncomplete)
        assertEquals("may be incomplete", CopyKey.MEMBERS_MAY_BE_INCOMPLETE.english)

        // A member whose account the operator deleted stays in the history until the owner removes them.
        val gone = screen.members.first { it.deletedByOperator }
        assertIs<PersonName.Unverified>(gone.who)
        assertEquals("someone the server calls Dan's account was deleted by the server's operator.", gone.deletedLine?.english)
        assertNull(screen.row("Bo").deletedLine)
        assertEquals("Remove from the list", CopyKey.REMOVE_FROM_THE_LIST.english)
        assertEquals(VaultActionResult.DONE, await { app.vaults.removeMember(gone) })
        assertTrue(assertNotNull(app.account.members).members.none { it.deletedByOperator })
        assertFalse(FakeScenes.at(FakeScene.MEMBERS).account.members!!.mayBeIncomplete)
    }

    @Test
    fun movingEverythingKeepsTheMembersOfAVaultInGoodStanding(): Unit = runBlocking {
        val app = FakeScenes.at(FakeScene.MOVE_EVERYTHING)
        val screen = assertNotNull(app.account.moving)
        assertFalse(screen.sourceStays)
        assertFalse(screen.shortOfSpace)
        assertFalse(screen.ticksOffered, "no tick boxes on a vault in good standing")
        assertEquals(CopyKey.MOVE_ONLY_LIVE_ITEMS, screen.whatMoves)
        val bo = screen.members.first { (it.who as? PersonName.Contact)?.label == "Bo" }
        val dan = screen.members.first { it.who is PersonName.Unverified }
        assertTrue(bo.ticked && bo.canBeAdded)
        // Someone this account is not connected with cannot be given the new vault's key: named before the start.
        assertFalse(dan.ticked || dan.canBeAdded)
        assertEquals(io.silencelen.andvari.core.app.MoveKept.MEMBER_CANNOT_BE_ADDED, screen.oldVaultKept)
        app.vaults.tickMember(screen, bo, false)
        assertTrue(assertNotNull(app.account.moving).members.first { it.userId == bo.userId }.ticked, "ticks change nothing here")

        // From Dan's remove dialog instead: Dan is removed on the old log first, so everyone left can be added.
        app.vaults.closeMoveEverything()
        assertEquals(VaultActionResult.DONE, app.vaults.openMembers(app.vault("Family")))
        val danRow = assertNotNull(app.account.members).members.first { it.userId == dan.userId }
        assertEquals(VaultActionResult.DONE, app.vaults.openMoveEverythingRemoving(danRow))
        val removing = assertNotNull(app.account.moving)
        assertEquals(dan.userId, removing.removing?.userId)
        assertTrue(removing.members.none { it.userId == dan.userId })
        assertNull(removing.oldVaultKept)

        app.script.holdNext()
        val move = async { app.vaults.moveEverything(assertNotNull(app.account.moving), "Family 2") }
        yield()
        assertTrue(assertNotNull(app.account.moving).running)
        app.script.releaseHold()
        assertEquals(VaultActionResult.DONE, move.await())
        assertNull(app.account.moving)
        assertEquals(VaultActionResult.DONE, app.vaults.openMembers(app.vault("Family 2")))
        assertEquals(listOf(RoleInVault.OWNER, RoleInVault.WRITER), assertNotNull(app.account.members).members.map { it.role })
        assertTrue(app.vault("Family").purgeAtMs > 0L, "the old vault is deleted once its items are out")

        val short = FakeScenes.at(FakeScene.VAULTS)
        short.script.noSpaceForVaults = true
        assertEquals(VaultActionResult.DONE, short.vaults.openMoveEverything(short.vault("Family")))
        assertTrue(assertNotNull(short.account.moving).shortOfSpace)
        assertEquals(VaultActionResult.OUT_OF_SPACE, short.vaults.moveEverything(assertNotNull(short.account.moving), "Family 2"))
        val stopped = assertNotNull(assertNotNull(short.account.moving).stopped, "a stop says where")
        // The check for space runs before anything is signed or sent, as the engine's: no vault is made, nothing copied.
        assertEquals(io.silencelen.andvari.core.app.MoveStage.CREATE_VAULT, stopped.stage)
        assertEquals("Family 2", stopped.toVaultName)
        assertEquals(0, stopped.copied)
        assertEquals(0, short.account.vaults.count { it.name == "Family 2" })
        short.vaults.closeMoveEverything()
        assertNull(short.account.moving)
        // The unfinished move is on the vault's row and offered on the first screen, as the engine does.
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_UNFINISHED, short.vault("Family").unfinishedMove?.key)
        val offer = short.account.unfinishedMoves.single()
        assertFalse(offer.deleteWaiting)
        assertEquals("Family", offer.vault.name)
        // Opened again, it carries on into the same new vault.
        short.script.noSpaceForVaults = false
        assertEquals(VaultActionResult.DONE, short.vaults.openMoveEverything(offer.vault))
        assertEquals(VaultActionResult.DONE, short.vaults.moveEverything(assertNotNull(short.account.moving), "ignored"))
        assertEquals(1, short.account.vaults.count { it.name == "Family 2" })
        assertEquals(emptyList(), short.account.unfinishedMoves)
        assertFalse(short.vault("Work").canMoveEverything, "the row says it is not offered")
        assertEquals(VaultActionResult.NOT_OWNER, short.vaults.openMoveEverything(short.vault("Work")))
        assertTrue(short.vault("Family 2").canMoveEverything)
    }

    /** The fake as the engine: a request marked "This was me" leaves the alert and is still listed in Settings. */
    @Test fun aRequestMarkedAsMineLeavesTheAlertAndStaysInSettings() = runBlocking<Unit> {
        val app = FakeScenes.at(FakeScene.VAULTS)
        val request = assertNotNull(app.script.someoneAsksOperator(io.silencelen.andvari.core.app.AppPlatform.ANDROID))
        val alert = app.account.prompts.filterIsInstance<io.silencelen.andvari.core.app.AccountPrompt.RecoveryRequest>().single()
        app.recovery.recoveryRequestWasMe(alert)
        assertTrue(app.account.prompts.none { it is io.silencelen.andvari.core.app.AccountPrompt.RecoveryRequest })
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, app.recovery.openRecovery())
        assertEquals(listOf(request.requestId), assertNotNull(app.account.recovery).requests.map { it.requestId })
    }

    /** The fake as the engine: while a move's deletion waits, every other change to the old vault is refused with one result. */
    @Test fun theFakeRefusesEveryOtherChangeWhileAMovesDeletionWaits() = runBlocking<Unit> {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.moveDeleteUnanswered = true
        // From the remove dialog of the member who cannot be added here, so that the old vault is to be deleted.
        assertEquals(VaultActionResult.DONE, app.vaults.openMoveEverything(app.vault("Family")))
        val cannot = assertNotNull(app.account.moving).members.first { !it.canBeAdded }.userId
        app.vaults.closeMoveEverything()
        assertEquals(VaultActionResult.DONE, app.vaults.openMembers(app.vault("Family")))
        assertEquals(VaultActionResult.DONE, app.vaults.openMoveEverythingRemoving(assertNotNull(app.account.members).members.first { it.userId == cannot }))
        app.vaults.closeMembers()
        assertEquals(VaultActionResult.SENT_PENDING, app.vaults.moveEverything(assertNotNull(app.account.moving), "Family 2"))
        app.vaults.closeMoveEverything()
        val old = app.vault("Family")
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_DELETE_WAITING, old.unfinishedMove?.key)
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.renameVault(old, "Again"))
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.deleteVault(old))
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.cancelOffer(old))
        assertEquals(VaultActionResult.DONE, app.vaults.openMembers(old))
        val member = assertNotNull(app.account.members).members.first { it.role != RoleInVault.OWNER }
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.changeRole(member, io.silencelen.andvari.core.trust.MemberRole.READER))
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.removeMember(member))
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.offerOwnership(member))
        assertEquals(VaultActionResult.MOVE_DELETE_WAITING, app.vaults.openMoveEverythingRemoving(member))
        app.vaults.closeMembers()
        assertFalse(app.vault("Family").writable)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_WAITING_READ_ONLY, app.vault("Family").readOnlyLine?.key)
        // The server stores the deletion later, outside the move: the notice, the copy, the dismiss.
        val other = FakeScenes.at(FakeScene.VAULTS)
        other.script.moveDeleteUnanswered = true
        assertEquals(VaultActionResult.DONE, other.vaults.openMembers(other.vault("Family")))
        assertEquals(VaultActionResult.DONE, other.vaults.openMoveEverythingRemoving(assertNotNull(other.account.members).members.first { it.userId == cannot }))
        other.vaults.closeMembers()
        assertEquals(VaultActionResult.SENT_PENDING, other.vaults.moveEverything(assertNotNull(other.account.moving), "Family 2"))
        assertTrue(other.script.serverStoresMoveDeleteLater(added = 2, changed = 1))
        val notice = other.account.movesStoredOutside.single()
        assertEquals(2, notice.added)
        assertEquals(1, notice.changed)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.MOVE_STORED_OUTSIDE, notice.line.key)
        assertEquals(emptyList(), other.account.unfinishedMoves)
        assertEquals(VaultActionResult.DONE, other.vaults.bringLateIntoMove(notice))
        assertEquals("3", other.account.movesStoredOutside.single().copiedLine?.values?.first())
        assertFalse(other.account.movesStoredOutside.single().canCopy)
        other.vaults.dismissMoveStored(other.account.movesStoredOutside.single())
        assertEquals(emptyList(), other.account.movesStoredOutside)

        // The move's own run finishes it.
        app.script.moveDeleteUnanswered = false
        assertEquals(VaultActionResult.DONE, app.vaults.openMoveEverything(app.vault("Family")))
        assertEquals(VaultActionResult.DONE, app.vaults.moveEverything(assertNotNull(app.account.moving), "ignored"))
        assertTrue(app.vault("Family").purgeAtMs > 0L)
    }

    @Test
    fun movingEverythingOutOfAFrozenVaultTicksNobodyAndSignsNothingOnItsLog() {
        val app = FakeScenes.at(FakeScene.MOVE_EVERYTHING_FROZEN)
        val screen = assertNotNull(app.account.moving)
        assertTrue(screen.sourceStays)
        // FS-R3: the last verified list may predate a removal this device never saw.
        assertTrue(screen.members.none { it.ticked })
        val bo = screen.members.first { (it.who as? PersonName.Contact)?.label == "Bo" }
        app.vaults.tickMember(screen, bo, true)
        val ticked = assertNotNull(app.account.moving)
        assertEquals(listOf(bo.userId), ticked.members.filter { it.ticked }.map { it.userId })
        assertEquals(VaultActionResult.STALE, await { app.vaults.moveEverything(screen, "Out") }, "the screen as it was is not the one on show")
        assertEquals(VaultActionResult.DONE, await { app.vaults.moveEverything(ticked, "Out") })

        val old = app.vault("Family")
        assertEquals(VaultLogState.FROZEN, old.log)
        assertEquals(0L, old.purgeAtMs, "nothing was signed on the frozen log")
        assertEquals(2, app.members("Out").members.size)
    }

    // ---- §4.4: the instance card ----

    @Test
    fun aWithheldCardStopsNothingAndAForkStopsEverythingUntilTheServerIsForgotten() {
        val withheld = FakeScenes.at(FakeScene.CARD_WITHHELD)
        assertIs<InstanceCardState.Withheld>(withheld.snapshot.instance?.card)
        assertEquals("This server is showing an older version of its identity card", CopyKey.CARD_WITHHELD.english)
        assertEquals(VaultActionResult.DONE, await { withheld.vaults.createVault("Still works") })
        withheld.script.cardOk()
        assertIs<InstanceCardState.Ok>(withheld.snapshot.instance?.card)
        assertIs<InstanceCardState.NotVerified>(FakeScenes.at(FakeScene.CARD_NOT_VERIFIED).snapshot.instance?.card)

        val stopped = FakeScenes.at(FakeScene.CARD_STOPPED)
        assertIs<InstanceCardState.Stopped>(stopped.snapshot.instance?.card)
        // No sync, no writes: every intent of the account fails, whatever it is.
        assertEquals(VaultActionResult.FAILED, await { stopped.vaults.createVault("No") })
        assertEquals(PlainResult.FAILED, await { stopped.contacts.openContacts() })
        assertEquals("Forget this server", CopyKey.FORGET_THIS_SERVER.english)
        // A fork stops traffic, not reading: the vault stays open from this device's copy, read-only, and says so.
        assertEquals(AppPhase.UNLOCKED, stopped.snapshot.phase)
        assertTrue(stopped.account.serverStopped)
        assertTrue(stopped.account.vaults.isNotEmpty() && stopped.account.vaults.none { it.writable })
        stopped.script.lock()
        assertEquals(VaultUnlockResult.DONE, await { stopped.unlock(assertNotNull(stopped.snapshot.locked), PW) })
        assertTrue(stopped.account.serverStopped)
        val instance = assertNotNull(stopped.snapshot.instance)
        assertEquals(PlainResult.DONE, await { stopped.instance.forgetServer(instance) })
        assertEquals(AppPhase.ENTRY, stopped.snapshot.phase)
        assertNull(stopped.snapshot.instance)
        stopped.on<EntryScreen.FirstRun>()
        assertEquals(PlainResult.STALE, await { stopped.instance.forgetServer(instance) })
    }

    @Test
    fun aSignedMoveIsFollowedByOneTapAndAKindChangeOnlyThroughTheGate() {
        val moved = FakeScenes.at(FakeScene.CARD_MOVED)
        val card = assertIs<InstanceCardState.Moved>(moved.snapshot.instance?.card)
        assertEquals("Family (https://vault.family.example) moved to https://vault.newhome.example, signed by its operator", card.line.english)
        assertEquals(FAMILY, moved.snapshot.instance?.label?.origin, "not followed until the person says so")
        assertEquals(MoveResult.DONE, await { moved.instance.followMove(card) })
        assertEquals("https://vault.newhome.example", moved.snapshot.instance?.label?.origin)
        assertIs<InstanceCardState.Ok>(moved.snapshot.instance?.card)
        assertEquals(MoveResult.STALE, await { moved.instance.followMove(card) })
        assertEquals(VaultActionResult.DONE, await { moved.vaults.createVault("After the move") })

        val changed = FakeScenes.at(FakeScene.CARD_KIND_CHANGED)
        val kind = assertIs<InstanceCardState.KindChanged>(changed.snapshot.instance?.card)
        assertEquals(TrustGateWording.KIND_CHANGE, kind.gate.wording)
        assertEquals(ServerKind.PUBLIC_SERVER, kind.gate.claimedKind)
        assertEquals(
            "Family (https://vault.family.example) now says it is a public server. This changes who can be offered operator recovery. Continue only if you expected this.",
            kind.gate.lines.single().english,
        )
        assertNull(kind.gate.title)
        // Until the person confirms, the old kind and its recovery rules stay in force.
        assertEquals(ServerKind.PRIVATE_SERVER, changed.snapshot.instance?.label?.kind)
        assertEquals(PlainResult.DONE, await { changed.recovery.openRecovery() })
        assertNotNull(assertNotNull(changed.account.recovery).question)
        assertEquals(PlainResult.DONE, await { changed.instance.acceptKindChange(kind) })
        assertEquals(ServerKind.PUBLIC_SERVER, changed.snapshot.instance?.label?.kind)
        assertNull(assertNotNull(changed.account.recovery).question, "a public instance offers no operator recovery")
    }

    @Test
    fun aMoveToAnAddressThisDeviceAlreadyPinsIsNotFollowed() {
        // §4.4: a move never replaces a pin that exists for the new origin (`pin_conflict`).
        val app = FakeScenes.at(FakeScene.CARD_MOVED)
        val card = assertIs<InstanceCardState.Moved>(app.snapshot.instance?.card)
        app.script.thisDevicePins(app.script.addServer("https://vault.newhome.example", "Somebody else's", ServerKind.PRIVATE_SERVER))
        assertEquals(MoveResult.ALREADY_PINNED_THERE, await { app.instance.followMove(card) })
        assertEquals(FAMILY, app.snapshot.instance?.label?.origin, "nothing moved")
        // The prompt stays, and now says why: the way on is to forget one of the two servers.
        val stays = assertIs<InstanceCardState.Moved>(app.snapshot.instance?.card)
        assertEquals(card.toOrigin, stays.toOrigin)
        assertTrue(stays.alreadyPinnedThere)
        assertEquals("Somebody else's", app.scriptServer("https://vault.newhome.example").name)
    }

    @Test
    fun aForkIsKeptWithThePinUntilTheServerIsForgotten() {
        val app = FakeScenes.at(FakeScene.CARD_STOPPED)
        val server = app.script.publicInstance
        // The server serves the old chain again: the fork this device saw is not forgotten for that (§4.4).
        server.identityChanged = false
        app.script.changed()
        assertIs<InstanceCardState.Stopped>(app.snapshot.instance?.card)
        assertEquals(VaultActionResult.FAILED, await { app.vaults.createVault("No") })
        app.script.lock()
        app.script.unlock()
        assertIs<InstanceCardState.Stopped>(app.snapshot.instance?.card)
        app.script.cardOk()
        assertIs<InstanceCardState.Stopped>(app.snapshot.instance?.card, "no later check lifts it either")

        assertEquals(PlainResult.DONE, await { app.instance.forgetServer(assertNotNull(app.snapshot.instance)) })
        app.on<EntryScreen.FirstRun>()
        // Forgotten, the server can be used again from the start.
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.choosePublicInstance(app.on()) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertIs<InstanceCardState.Ok>(app.snapshot.instance?.card)
    }

    @Test
    fun aDamagedPinRecordBlocksTheServerUntilItIsForgotten() {
        val app = FakeScenes.at(FakeScene.CARD_DAMAGED)
        val instance = assertNotNull(app.snapshot.instance)
        assertIs<InstanceCardState.Damaged>(instance.card)
        // There is no readable card to take a name from: the origin alone.
        assertEquals("", instance.label.name)
        assertEquals("https://vault.andvaripass.com", instance.label.origin)
        // It is never read as "no pin": everything is refused, signed in ...
        assertEquals(VaultActionResult.FAILED, await { app.vaults.createVault("No") })
        assertEquals(PlainResult.FAILED, await { app.contacts.openContacts() })
        // Unlike a fork, a damaged record blocks the unlock too: there is no pin to open the account against.
        app.script.lock()
        val locked = assertNotNull(app.snapshot.locked)
        assertEquals("", locked.prompt.instance.name)
        assertEquals(VaultUnlockResult.SERVER_BLOCKED, await { app.unlock(locked, PW) })
        assertEquals(AppPhase.LOCKED, app.snapshot.phase)
        assertIs<InstanceCardState.Damaged>(app.snapshot.instance?.card)

        // ... and signed out, where no Trust Gate opens for it either.
        app.script.sessionEndedByServer()
        // Signed out by the server, the account stays on its lock screen (design §4.4); the person signs in again from there.
        val byServer = assertNotNull(app.snapshot.locked)
        assertTrue(byServer.signedOutByServer)
        app.signInAgain(byServer)
        assertEquals(FirstRunNotice.SIGNED_OUT_BY_SERVER, app.on<EntryScreen.FirstRun>().notice)
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.IDENTITY_CONFLICT, await { app.entry.choosePublicInstance(app.on()) })
        val blocked = app.on<EntryScreen.ServerChanged>()
        assertIs<InstanceCardState.Damaged>(blocked.instance.card)
        assertSame(blocked.instance, app.snapshot.instance)

        assertEquals(PlainResult.DONE, await { app.instance.forgetServer(blocked.instance) })
        assertNull(app.snapshot.instance)
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.choosePublicInstance(app.on()) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertIs<InstanceCardState.Ok>(app.snapshot.instance?.card)
    }

    @Test
    fun aStoreBuildFollowsNeitherAMoveNorAKindChangeOfTheBakedInstance() {
        val app = FakeScenes.at(FakeScene.CARD_UPDATE_ANDVARI)
        val moved = assertIs<InstanceCardState.UpdateAndvari>(app.snapshot.instance?.card)
        assertEquals("This server says it moved. Update andvari.", moved.sentence.english)
        assertEquals("https://vault.andvaripass.com", app.snapshot.instance?.label?.origin)
        app.script.cardKindChanged()
        val changed = assertIs<InstanceCardState.UpdateAndvari>(app.snapshot.instance?.card)
        assertEquals("This server says it changed. Update andvari.", changed.sentence.english)
        assertEquals(ServerKind.PUBLIC_SERVER, app.snapshot.instance?.label?.kind)
    }

    // ---- §3.11: deleting the account ----

    @Test
    fun deletingTheAccountShowsWhatGoesAndRetriesWhenAVaultsHistoryMoved(): Unit = runBlocking {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.me().vaults.removeAll { it.role == RoleInVault.OWNER }
        // The screen opens at once; its plan arrives with the server's answer.
        app.script.holdNext()
        val opening = async { app.settings.openDeletion() }
        yield()
        assertNull(assertNotNull(app.account.deletion).plan)
        app.script.releaseHold()
        assertEquals(PlainResult.DONE, opening.await())

        val screen = assertNotNull(app.account.deletion)
        val plan = assertNotNull(screen.plan)
        assertEquals(ADA, screen.email)
        assertEquals(listOf("Personal"), plan.deletedVaults)
        assertEquals(listOf("Work"), plan.leftVaults, "one leave is signed for each")
        assertTrue(plan.canProceed)
        assertFalse(plan.codeNeeded)

        assertEquals(DeletionResult.EMAIL_MISMATCH, app.settings.deleteAccount(screen, "bo@example.com", PW, null))
        assertEquals(DeletionResult.WRONG_PASSWORD, app.settings.deleteAccount(screen, ADA, "wrong", null))
        app.script.deletionFarFutureHead = true
        val future = app.settings.deleteAccount(screen, ADA, PW, null)
        assertEquals(DeletionResult.FAR_FUTURE, future)
        assertEquals("One of your shared vaults reports a time far in the future. Try again later.", future.sentence?.english)
        app.script.deletionFarFutureHead = false
        app.script.clockAhead = true
        assertEquals(DeletionResult.CLOCK_AHEAD, app.settings.deleteAccount(screen, ADA, PW, null))
        app.script.clockAhead = false

        // The heads keep moving: three tries, then the person is told; nothing was deleted.
        app.script.deletionStaleRounds = 5
        assertEquals(DeletionResult.STILL_CHANGING, app.settings.deleteAccount(assertNotNull(app.account.deletion), ADA, PW, null))
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        app.script.deletionStaleRounds = 0

        // One stale round: the app fetches the heads again and retries by itself.
        app.script.deletionStaleRounds = 1
        var sawRetry = false
        val watching = app.observe { if (it.account?.deletion?.retrying == true) sawRetry = true }
        assertEquals(DeletionResult.DONE, app.settings.deleteAccount(assertNotNull(app.account.deletion), " ADA@example.com ", PW, null))
        watching.close()
        assertTrue(sawRetry)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        // The first screen says it once, beside (not as) a FirstRunNotice; dismissing takes it away.
        val first = app.on<EntryScreen.FirstRun>()
        assertNull(first.notice)
        val said = assertNotNull(first.accountDeleted)
        assertEquals(ADA, said.email)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN, said.line.key)
        assertEquals(listOf(ADA, said.instance.name, said.instance.origin), said.line.values)
        // As the engine: the server is forgotten with the account (its pin goes too).
        assertFalse(app.pins.containsKey(said.instance.origin))
        app.entry.dismissNotice(first)
        assertNull(app.on<EntryScreen.FirstRun>().accountDeleted)
        assertNull(app.script.publicInstance.accounts[ADA])
    }

    @Test
    fun aDeletionIsBlockedByWhatStandsInItsWayAndNeedsTheCodeOfTwoStepSignIn() {
        val app = FakeScenes.at(FakeScene.DELETION_BLOCKED)
        val screen = assertNotNull(app.account.deletion)
        val plan = assertNotNull(screen.plan)
        assertFalse(plan.canProceed)
        val owned = plan.blockers.first { it.kind == DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS }
        assertEquals("Family", owned.vaultName)
        assertEquals(2, owned.others)
        // A blocker this build does not know is shown as one it cannot explain, and never passed.
        assertNotNull(plan.blockers.firstOrNull { it.kind == DeletionBlockerKind.NOT_KNOWN })
        assertEquals(DeletionResult.BLOCKED, await { app.settings.deleteAccount(screen, ADA, PW, null) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        app.settings.closeDeletion()
        assertNull(app.account.deletion)

        val twoStep = FakeScenes.at(FakeScene.DELETION)
        twoStep.me().twoStepCode = "654321"
        twoStep.script.changed()
        val asked = assertNotNull(twoStep.account.deletion)
        assertTrue(assertNotNull(asked.plan).codeNeeded)
        assertEquals(DeletionResult.CODE_NEEDED, await { twoStep.settings.deleteAccount(asked, ADA, PW, null) })
        // The code is checked before the password, so the route is no password oracle.
        assertEquals(DeletionResult.WRONG_CODE, await { twoStep.settings.deleteAccount(asked, ADA, "wrong", "000000") })
        assertEquals(DeletionResult.DONE, await { twoStep.settings.deleteAccount(asked, ADA, PW, "654321") })
    }

    @Test
    fun aDeletionWithoutAnAnswerIsNeitherDoneNorFailedUntilItIsChecked() {
        val still = FakeScenes.at(FakeScene.DELETION_OUTCOME_UNKNOWN)
        val unknown = assertNotNull(still.account.deletion)
        assertTrue(unknown.outcomeUnknown)
        assertEquals(AppPhase.UNLOCKED, still.snapshot.phase)
        assertEquals(PlainResult.DONE, await { still.settings.checkDeletion(unknown) })
        assertFalse(assertNotNull(still.account.deletion).outcomeUnknown, "the account still exists")

        val gone = FakeScenes.at(FakeScene.DELETION)
        gone.script.deletionAnswerLost = true
        gone.script.deletionHappenedAnyway = true
        assertEquals(DeletionResult.OUTCOME_UNKNOWN, await { gone.settings.deleteAccount(assertNotNull(gone.account.deletion), ADA, PW, null) })
        assertEquals(PlainResult.STALE, await { gone.settings.checkDeletion(assertNotNull(gone.account.deletion)) })
        // As the engine: the check's `401` cannot be told from another end of the session, so nothing says "deleted".
        assertEquals(AppPhase.LOCKED, gone.snapshot.phase)
        assertTrue(assertNotNull(gone.snapshot.locked).signedOutByServer)

        // As the engine: the offer to forget the account here, only on the person's confirmation; the server stays.
        val offer = assertNotNull(gone.forgetAfterUnknownDeletionCheck())
        assertSame(offer, gone.forgetAfterUnknownDeletionCheck())
        assertEquals(ADA, offer.email)
        assertEquals(PlainResult.DONE, await { gone.forgetAfterUnknownDeletion(offer) })
        assertEquals(AppPhase.ENTRY, gone.snapshot.phase)
        assertNull(gone.forgetAfterUnknownDeletionCheck())
        assertTrue(gone.pins.containsKey(offer.instance.origin))
        assertEquals(PlainResult.STALE, await { gone.forgetAfterUnknownDeletion(offer) })
    }

    // ---- §4.5, §7.7, §9.3, §10: recovery ----

    @Test
    fun operatorRecoveryIsTurnedOnOnlyThroughItsWarningAndWithTheMasterPassword() {
        val app = FakeScenes.at(FakeScene.RECOVERY)
        var screen = assertNotNull(app.account.recovery)
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, screen.whoCanRecover)
        assertNotNull(screen.question)
        assertNull(screen.warning)

        assertEquals("This deletes the operator's recovery copy from the server. It cannot undo a copy the operator may already have made.", CopyKey.RECOVERY_TURN_OFF_NOTE.english)
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, await { app.recovery.turnOffOperatorRecovery(screen, "wrong") })
        assertEquals(RecoveryChangeResult.DONE, await { app.recovery.turnOffOperatorRecovery(screen, PW) })
        screen = assertNotNull(app.account.recovery)
        assertEquals(WhoCanRecover.ONLY_ME, screen.whoCanRecover)

        app.recovery.reviewOperatorRecovery(screen)
        val warning = assertNotNull(assertNotNull(app.account.recovery).warning)
        assertFalse(warning.unsignedChange)
        // The checkbox and the password are both part of the consent.
        assertEquals(RecoveryChangeResult.NOT_TICKED, await { app.recovery.turnOnOperatorRecovery(warning, understood = false, password = PW) })
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, await { app.recovery.turnOnOperatorRecovery(warning, understood = true, password = "wrong") })
        assertEquals(WhoCanRecover.ONLY_ME, assertNotNull(app.account.recovery).whoCanRecover)
        assertEquals(RecoveryChangeResult.DONE, await { app.recovery.turnOnOperatorRecovery(warning, understood = true, password = PW) })
        screen = assertNotNull(app.account.recovery)
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, screen.whoCanRecover)
        assertNull(screen.warning)
        assertEquals(RecoveryChangeResult.STALE, await { app.recovery.turnOnOperatorRecovery(warning, understood = true, password = PW) })

        app.recovery.reviewOperatorRecovery(screen)
        app.recovery.keepRecoveryPrivate(assertNotNull(assertNotNull(app.account.recovery).warning))
        assertNull(assertNotNull(app.account.recovery).warning)
        app.recovery.closeRecovery()
        assertNull(app.account.recovery)

        // A public instance offers no choice at all, so there is no warning to reach the operator posture through.
        val public = signedIn()
        assertEquals(PlainResult.DONE, await { public.recovery.openRecovery() })
        val none = assertNotNull(public.account.recovery)
        assertNull(none.question)
        public.recovery.reviewOperatorRecovery(none)
        assertNull(assertNotNull(public.account.recovery).warning)
    }

    @Test
    fun aRecoveryKeyThatChangedUnsignedIsSaidAtFirstConsentToo() {
        val app = FakeScenes.at(FakeScene.RECOVERY_WARNING_IN_SETTINGS)
        val screen = assertNotNull(app.account.recovery)
        // FS-R2, FC-2: the chain is walked from card 0, so a later opt-in sees the takeover warning as well.
        assertTrue(assertNotNull(screen.question).unsignedChange)
        val warning = assertNotNull(screen.warning)
        assertTrue(warning.unsignedChange)
        assertEquals("The recovery key for Family (https://vault.family.example) changed without the old key's signature.", warning.takeoverTitle?.english)
        assertTrue(CopyKey.RECOVERY_KEY_CHANGED_BODY.english.endsWith("Keep operator recovery only if the operator has told you why it changed."))
        assertEquals(WhoCanRecover.ONLY_ME, screen.whoCanRecover)
    }

    @Test
    fun aNewKitIsMadeWithTheMasterPasswordAndConfirmedLikeAnyOther() {
        val app = signedIn()
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, await { app.recovery.makeKit("wrong") })
        assertNull(app.account.kit)
        val before = app.me().kitSerial
        assertEquals(RecoveryChangeResult.DONE, await { app.recovery.makeKit(PW) })
        val kit = assertNotNull(app.account.kit)
        assertEquals(KitReason.MADE_IN_SETTINGS, kit.reason)
        assertEquals(KitStep.REVEAL, kit.step)
        assertEquals(before + 1, app.me().kitSerial, "the old kit stopped working when the new one was committed")
        app.saveKit()
        assertNull(app.account.kit)
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
    }

    @Test
    fun aRequestToResetTheAccountCanBeCancelledFromAnySignedInDevice() {
        val app = FakeScenes.at(FakeScene.PROMPTS)
        val prompt = app.prompt<AccountPrompt.RecoveryRequest>()
        assertEquals("Someone asked the operator to reset your account. If this wasn't you, cancel it.", CopyKey.RECOVERY_REQUEST_ALERT.english)
        val request = prompt.requests.single()
        assertEquals(OperatorHelpStage.HOLDING, request.stage)
        assertEquals(AppPlatform.ANDROID, request.reportedPlatform)
        assertEquals(app.script.nowMs + 7 * DAY, request.holdEndsAtMs)
        assertEquals(PlainResult.DONE, await { app.recovery.openRecovery() })
        assertEquals(listOf(request.requestId), assertNotNull(app.account.recovery).requests.map { it.requestId })

        // The hold passes: the request waits for the operator, and can still be cancelled.
        app.script.advance(7 * DAY)
        assertEquals(OperatorHelpStage.AWAITING_OPERATOR, app.prompt<AccountPrompt.RecoveryRequest>().requests.single().stage)
        assertEquals(PlainResult.DONE, await { app.recovery.cancelRecoveryRequest(request) })
        assertFalse(app.hasPrompt<AccountPrompt.RecoveryRequest>())
        assertTrue(assertNotNull(app.account.recovery).requests.isEmpty())
        assertEquals(PlainResult.STALE, await { app.recovery.cancelRecoveryRequest(request) })
    }

    @Test
    fun anUnsignedChangeOfTheRecoveryKeyAsksAndDefaultsToTurningItOff() {
        val app = FakeScenes.at(FakeScene.PROMPT_RECOVERY_KEY_CHANGED)
        val prompt = app.prompt<AccountPrompt.RecoveryKeyChanged>()
        assertEquals("The recovery key for Family (https://vault.family.example) changed without the old key's signature.", prompt.title.english)
        assertEquals(CopyKey.RECOVERY_KEY_CHANGED_BODY, prompt.body)
        assertEquals("Turn off operator recovery", CopyKey.RECOVERY_KEY_CHANGED_TURN_OFF.english)

        // "Later" changes nothing and seals nothing; the prompt returns at the next unlock.
        app.recovery.recoveryKeyChangedLater(prompt)
        assertFalse(app.hasPrompt<AccountPrompt.RecoveryKeyChanged>())
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, app.me().whoCanRecover)
        app.script.lock()
        app.script.unlock()
        val again = app.prompt<AccountPrompt.RecoveryKeyChanged>()
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, await { app.recovery.answerRecoveryKeyChanged(again, keep = false, password = "wrong") })
        assertEquals(RecoveryChangeResult.DONE, await { app.recovery.answerRecoveryKeyChanged(again, keep = false, password = PW) })
        assertEquals(WhoCanRecover.ONLY_ME, app.me().whoCanRecover)
        assertFalse(app.hasPrompt<AccountPrompt.RecoveryKeyChanged>())

        val keeping = FakeScenes.at(FakeScene.PROMPT_RECOVERY_KEY_CHANGED)
        assertEquals(RecoveryChangeResult.DONE, await { keeping.recovery.answerRecoveryKeyChanged(keeping.prompt(), keep = true, password = PW) })
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, keeping.me().whoCanRecover)
        assertFalse(keeping.hasPrompt<AccountPrompt.RecoveryKeyChanged>())
    }

    @Test
    fun aDeviceWithoutItsOwnRecordOfTheRecoveryChoiceAsksBeforeItSealsAnything() {
        val app = FakeScenes.at(FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY)
        val prompt = app.prompt<AccountPrompt.KeepOperatorRecovery>()
        assertEquals("Your account lets the operator of Family (https://vault.family.example) restore it. Keep that?", prompt.question.english)
        assertEquals("Not now", CopyKey.KEEP_OPERATOR_NOT_NOW.english)

        // "Not now", the default: nothing is sealed, and it asks again at the next unlock.
        app.recovery.keepOperatorRecoveryNotNow(prompt)
        assertFalse(app.hasPrompt<AccountPrompt.KeepOperatorRecovery>())
        app.script.lock()
        app.script.unlock()
        val again = app.prompt<AccountPrompt.KeepOperatorRecovery>()
        assertEquals(RecoveryChangeResult.WRONG_PASSWORD, await { app.recovery.answerKeepOperatorRecovery(again, keep = true, password = "wrong") })
        assertEquals(RecoveryChangeResult.DONE, await { app.recovery.answerKeepOperatorRecovery(again, keep = true, password = PW) })
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, app.me().whoCanRecover)
        // The choice was made here now: the device holds its own record of it and does not ask again.
        app.script.lock()
        app.script.unlock()
        assertFalse(app.hasPrompt<AccountPrompt.KeepOperatorRecovery>())

        val off = FakeScenes.at(FakeScene.PROMPT_KEEP_OPERATOR_RECOVERY)
        assertEquals(RecoveryChangeResult.DONE, await { off.recovery.answerKeepOperatorRecovery(off.prompt(), keep = false, password = PW) })
        assertEquals(WhoCanRecover.ONLY_ME, off.me().whoCanRecover)
    }

    // ---- §8: devices ----

    @Test
    fun devicesAreListedAndRevokedWithTheMasterPassword() {
        val app = FakeScenes.at(FakeScene.DEVICES)
        var screen = assertNotNull(app.account.devices)
        assertTrue(screen.requireLink)
        val here = screen.devices.first()
        assertTrue(here.current)
        assertEquals(HowDeviceJoined.REGISTERED, here.how)
        val mac = screen.devices.first { it.name == "MacBook" }
        assertEquals(HowDeviceJoined.LINKED, mac.how)
        assertEquals("iPhone", mac.linkedFrom)
        assertEquals(AppPlatform.MACOS, mac.platform)
        assertFalse(screen.devices.first { it.name == "Old phone" }.live)

        // A wrong password is its own answer on every re-authenticated action, never an expired session (S3-K1).
        assertEquals(ProofResult.WRONG_PASSWORD, await { app.devices.revokeDevice(mac, "wrong") })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(ProofResult.NOT_POSSIBLE, await { app.devices.revokeDevice(here, PW) }, "a device does not revoke itself")
        assertEquals(ProofResult.DONE, await { app.devices.revokeDevice(mac, PW) })
        screen = assertNotNull(app.account.devices)
        // As the server: a revoked device stays on the list, not live.
        val revoked = screen.devices.single { it.name == "MacBook" }
        assertFalse(revoked.live)
        // A revoked device is no longer one the account knows (FC-8).
        assertFalse(mac.deviceId in app.me().knownDevices)
        assertEquals(ProofResult.DONE, await { app.devices.revokeDevice(revoked, PW) }, "the server answers a second revoke as the first")
        assertFalse(assertNotNull(app.account.devices).devices.single { it.name == "MacBook" }.live)

        assertEquals(ProofResult.WRONG_PASSWORD, await { app.devices.setRequireLink(false, "wrong") })
        assertEquals(ProofResult.DONE, await { app.devices.setRequireLink(false, PW) })
        assertFalse(assertNotNull(app.account.devices).requireLink)
        app.devices.closeDevices()
        assertNull(app.account.devices)
    }

    /** As on the engine: the server serves no read of "New devices must be linked", so only what this device set is known. */
    @Test
    fun requireLinkIsNotKnownUntilThisDeviceSetsIt() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.me().requireLink = true
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        val screen = assertNotNull(app.account.devices)
        assertFalse(screen.requireLinkKnown, "the server's value is not readable")
        assertFalse(screen.requireLink)
        assertEquals(ProofResult.DONE, await { app.devices.setRequireLink(false, PW) })
        val set = assertNotNull(app.account.devices)
        assertTrue(set.requireLinkKnown)
        assertFalse(set.requireLink)
        assertFalse(app.me().requireLink)
    }

    @Test
    fun theExistingDeviceTakesTheNewDevicesDigitsTypedAndNeverShowsACode() {
        val app = signedIn()
        assertEquals(PlainResult.DONE, await { app.devices.startDeviceLink() })
        val shown = assertIs<DeviceLinkHost.Shown>(app.account.deviceLink)
        assertEquals(
            "On the new device, open andvari → Sign in → Link from your other device and scan this. It links to andvari (https://vault.andvaripass.com).",
            shown.line.english,
        )
        assertTrue(assertNotNull(app.devices.deviceLinkToShow(shown)).startsWith("https://andvaripass.com/d#v2."))
        // The countdown runs from what the server answered, on a clock the person cannot set.
        assertEquals(5 * MINUTE, app.devices.deviceLinkTimeLeftMs())
        app.script.advance(MINUTE)
        assertEquals(4 * MINUTE, app.devices.deviceLinkTimeLeftMs())

        app.script.joiningDeviceClaims("Pixel 9", AppPlatform.ANDROID)
        val claimed = assertIs<DeviceLinkHost.Claimed>(app.account.deviceLink)
        assertEquals("Pixel 9", claimed.deviceName)
        assertNull(app.devices.deviceLinkToShow(shown), "a claimed link is not shown again")

        // Only the new device's reveal, checked against its commitment, makes the digits askable.
        app.script.joiningDeviceReveals(matches = true)
        val digits = assertIs<DeviceLinkHost.TypeDigits>(app.account.deviceLink)
        assertEquals("Add Pixel 9 (android)? Type the six digits shown on the new device", digits.line.english)
        assertEquals(DigitsResult.DONE, await { app.devices.submitDeviceDigits(digits, app.script.joiningDeviceCode) })

        val approvable = assertIs<DeviceLinkHost.Approvable>(app.account.deviceLink)
        assertTrue(approvable.biometricsOffered)
        app.script.biometricsCancelled = true
        assertEquals(ProofResult.CANCELLED, await { app.devices.approveWithBiometrics(approvable, null) })
        assertSame(approvable, app.account.deviceLink, "a cancelled prompt leaves the link as it is")
        app.script.biometricsRefused = true
        assertEquals(ProofResult.BIOMETRICS_NOT_USED, await { app.devices.approveWithBiometrics(approvable, null) })
        assertEquals(ProofResult.WRONG_PASSWORD, await { app.devices.approveWithPassword(approvable, "wrong") })
        assertSame(approvable, app.account.deviceLink)
        assertEquals(ProofResult.DONE, await { app.devices.approveWithPassword(approvable, PW) })
        assertEquals("Pixel 9", assertIs<DeviceLinkHost.Approved>(app.account.deviceLink).deviceName)
        // No device exists until the new one proved the master password.
        assertTrue(app.me().devices.none { it.name == "Pixel 9" })

        // The existing device's part ends at the approval: it is told nothing when the new one picks up.
        val approved = app.account.deviceLink
        app.script.joiningDevicePicksUp()
        assertSame(approved, app.account.deviceLink)
        app.devices.dismissDeviceLink()
        assertNull(app.account.deviceLink)
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        val added = assertNotNull(app.account.devices).devices.first { it.name == "Pixel 9" }
        assertEquals(HowDeviceJoined.LINKED, added.how)
        assertEquals("iPhone", added.linkedFrom)
        app.devices.dismissDeviceLink()
        assertNull(app.account.deviceLink)

        val quick = FakeScenes.at(FakeScene.HOST_LINK_APPROVABLE)
        assertEquals(ProofResult.DONE, await { quick.devices.approveWithBiometrics(assertIs(quick.account.deviceLink), "Approve the new device") })
        assertIs<DeviceLinkHost.Approved>(quick.account.deviceLink)
    }

    /** §8.2 step 6 in the fake, as the engine: only a confirmed check approves; anything else approves nothing. */
    @Test
    fun aNewDeviceIsApprovedByTheFingerprintOrFaceCheckOnlyWhenItConfirms() {
        // Switched off by the check (the device's biometrics changed): the password is asked, and quick unlock is off.
        val changed = FakeScenes.at(FakeScene.HOST_LINK_APPROVABLE)
        val first = assertIs<DeviceLinkHost.Approvable>(changed.account.deviceLink)
        assertTrue(first.biometricsOffered)
        changed.script.biometricsChanged = true
        assertEquals(ProofResult.BIOMETRICS_NOT_USED, await { changed.devices.approveWithBiometrics(first, null) })
        val after = assertIs<DeviceLinkHost.Approvable>(changed.account.deviceLink, "the link waits")
        assertFalse(after.biometricsOffered, "quick unlock is off now")
        assertEquals(ProofResult.BIOMETRICS_NOT_USED, await { changed.devices.approveWithBiometrics(after, null) })
        assertEquals(ProofResult.DONE, await { changed.devices.approveWithPassword(after, PW) })

        // Not on at all: the password.
        val off = FakeScenes.at(FakeScene.HOST_LINK_APPROVABLE)
        off.script.quickUnlock = false
        assertEquals(ProofResult.BIOMETRICS_NOT_USED, await { off.devices.approveWithBiometrics(assertIs(off.account.deviceLink), null) })

        // Overtaken by a lock: nothing approved, and the vault is locked.
        val locked = FakeScenes.at(FakeScene.HOST_LINK_APPROVABLE)
        locked.script.lockDuringPresence = true
        assertEquals(ProofResult.STALE, await { locked.devices.approveWithBiometrics(assertIs(locked.account.deviceLink), null) })
        assertEquals(AppPhase.LOCKED, locked.snapshot.phase)
        assertNull(locked.snapshot.account)
    }

    @Test
    fun aDeviceLinkEndsOnAWrongCodeACancelANewerLinkOrTheClock() {
        val wrong = FakeScenes.at(FakeScene.HOST_LINK_TYPE_DIGITS)
        val typed = await { wrong.devices.submitDeviceDigits(assertIs(wrong.account.deviceLink), "000000") }
        assertEquals(DigitsResult.MISMATCH, typed)
        val ended = assertIs<DeviceLinkHost.Ended>(wrong.account.deviceLink)
        assertEquals(DeviceLinkHostEnd.CODE_MISMATCH, ended.outcome)
        assertEquals("Linking was cancelled", ended.outcome.sentence?.english)
        assertEquals(0L, wrong.devices.deviceLinkTimeLeftMs())

        val cancelled = FakeScenes.at(FakeScene.HOST_LINK_CLAIMED)
        assertEquals(PlainResult.DONE, await { cancelled.devices.cancelDeviceLink() })
        assertEquals(DeviceLinkHostEnd.CANCELLED, assertIs<DeviceLinkHost.Ended>(cancelled.account.deviceLink).outcome)
        assertEquals(PlainResult.STALE, await { cancelled.devices.cancelDeviceLink() })

        // Another device of the account made a newer link: this one is cancelled, in whatever state it was (S3-C3).
        val replaced = FakeScenes.at(FakeScene.HOST_LINK_CANCELLED)
        assertEquals(DeviceLinkHostEnd.CANCELLED, assertIs<DeviceLinkHost.Ended>(replaced.account.deviceLink).outcome)
        val approved = FakeScenes.at(FakeScene.HOST_LINK_APPROVED)
        approved.script.newerLinkMadeElsewhere()
        assertEquals(DeviceLinkHostEnd.CANCELLED, assertIs<DeviceLinkHost.Ended>(approved.account.deviceLink).outcome)
        approved.script.joiningDevicePicksUp()
        assertTrue(approved.me().devices.none { it.name == "Pixel 9" }, "a cancelled link adds nobody")

        // Making a newer link on this device replaces the one on show.
        val again = FakeScenes.at(FakeScene.HOST_LINK_SHOWN)
        val first = assertIs<DeviceLinkHost.Shown>(again.account.deviceLink)
        val firstLink = again.devices.deviceLinkToShow(first)
        assertEquals(PlainResult.DONE, await { again.devices.startDeviceLink() })
        val second = assertIs<DeviceLinkHost.Shown>(again.account.deviceLink)
        assertFalse(firstLink == again.devices.deviceLinkToShow(second))

        val slow = FakeScenes.at(FakeScene.HOST_LINK_SHOWN)
        slow.script.advance(6 * MINUTE)
        assertEquals(DeviceLinkHostEnd.EXPIRED, assertIs<DeviceLinkHost.Ended>(slow.account.deviceLink).outcome)

        val forged = FakeScenes.at(FakeScene.HOST_LINK_CLAIMED)
        forged.script.joiningDeviceReveals(matches = false)
        assertEquals(DeviceLinkHostEnd.DID_NOT_CHECK_OUT, assertIs<DeviceLinkHost.Ended>(forged.account.deviceLink).outcome)
    }

    // ---- the master password ----

    @Test
    fun changingTheMasterPasswordNeedsTheCurrentOneAndEndsTheOtherSessions() {
        val app = signedIn()
        assertEquals(PasswordChangeResult.WRONG_PASSWORD, await { app.settings.changeMasterPassword("wrong", "another master password") })
        assertEquals(PasswordChangeResult.WEAK_PASSWORD, await { app.settings.changeMasterPassword(PW, "short") })
        assertEquals(PasswordChangeResult.DONE, await { app.settings.changeMasterPassword(PW, "another master password") })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "this session stays")
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        assertTrue(assertNotNull(app.account.devices).devices.filter { !it.current }.none { it.live })
        assertEquals(ProofResult.WRONG_PASSWORD, await { app.devices.setRequireLink(true, PW) })
        assertEquals(ProofResult.DONE, await { app.devices.setRequireLink(true, "another master password") })
    }

    @Test
    fun aCopyThatCouldNotFollowTheNewPasswordIsSaidToOpenWithThePreviousOne() {
        val app = signedIn()
        app.script.deviceCannotFollowPassword = true
        assertEquals(PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE, await { app.settings.changeMasterPassword(PW, "another master password") })
        assertFalse(PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE.done)
        assertEquals(ProofResult.DONE, await { app.devices.setRequireLink(true, "another master password") }, "the server takes the new one")
        app.lock()
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.previousPasswordOpensCopy)
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, await { app.unlock(locked, "another master password") })
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(PasswordChangeResult.DONE, await { app.settings.changeMasterPassword("another master password", "a third master password") })
        app.lock()
        assertFalse(assertNotNull(app.snapshot.locked).previousPasswordOpensCopy)
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), "a third master password") })
    }

    @Test
    fun aSessionTheServerEndedLeavesTheAccountSignedOutByTheServerWithItsCopy() {
        val app = signedIn()
        app.script.sessionEndedByServer()
        // Design §4.4: the account stays, on its lock screen, as signed out by the server.
        assertEquals(AppPhase.LOCKED, app.snapshot.phase)
        assertNull(app.snapshot.account)
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.signedOutByServer)
        assertFalse(locked.quickUnlock)
        assertEquals(PlainResult.STALE, await { app.contacts.openContacts() })
        // The password opens the copy read-only.
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(locked, PW) })
        assertTrue(app.account.serverStopped)
        assertTrue(app.account.signedOutByServer, "the account's snapshot carries it too, as on the engine")
        app.lock()
        app.signInAgain(app.snapshot.locked!!)
        assertEquals(FirstRunNotice.SIGNED_OUT_BY_SERVER, app.on<EntryScreen.FirstRun>().notice)
    }

    /** As the engine (option A): another account is refused with its own answer until the kept one is signed out. */
    @Test
    fun anotherAccountIsRefusedWhileAServerEndedOneIsKeptUntilItIsSignedOut() {
        val app = signedIn()
        val bea = app.script.publicInstance.addAccount("bea@example.com", PW)
        app.script.sessionEndedByServer()
        assertNull(app.snapshot.keptSignedOut, "only the journey names it")
        app.signInAgain(app.snapshot.locked!!)
        assertEquals(ADA, assertNotNull(app.snapshot.keptSignedOut).email)
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.choosePublicInstance(app.on()) })
        assertEquals(SignInAnswer.ANOTHER_ACCOUNT_KEPT, await { app.entry.submitSignIn(app.on(), bea.email, PW) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertNotNull(app.snapshot.keptSignedOut, "the kept account stays as it was")

        // Its copy was open before the server ended the session: what waits in it cannot be counted now, so the
        // sign-out needs the person's second confirmation of the check (rule of 2026-11-17).
        val check = assertNotNull(app.signOutCheck())
        assertNull(check.unsentChanges)
        assertEquals(PlainResult.UNSENT_NOT_CONFIRMED, await { app.signOut() })
        assertNotNull(app.snapshot.keptSignedOut)
        assertEquals(PlainResult.DONE, await { app.signOutConfirmed(check) })
        assertNull(app.snapshot.keptSignedOut)
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.choosePublicInstance(app.on()) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on(), bea.email, PW) })
    }
}
