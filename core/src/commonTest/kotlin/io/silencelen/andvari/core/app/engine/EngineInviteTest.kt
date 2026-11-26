package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AddressMismatchFor
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.RegistrationVia
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkPerson
import io.silencelen.andvari.core.client.link.LinkServer
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Invites opened signed out on the engine (§6.7, §6.8): the link engine's recipient checks, and registration by link. */
class EngineInviteTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "11111111-1111-4111-8111-111111111111"

    private class World(val server: LinkServer, val alice: LinkPerson, val state: MemoryDeviceState, val app: EngineAppApi, val probe: LockProbe)

    private suspend fun world(): World {
        val server = LinkServer(crypto)
        val a = LinkPerson(crypto, server, 1, alice, "Alice").start()
        val state = MemoryDeviceState()
        var self: EngineAppApi? = null
        // The link server knows a caller by its account: the app's own, once it has one.
        val asApp = object : io.silencelen.andvari.core.client.net.WireClient {
            override val origin: String = server.instance.origin
            override suspend fun <T> call(route: io.silencelen.andvari.core.model.wire.WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T) =
                server.client(self?.keeper?.session?.userId).call(route, pathParams, query, bodyJson, authenticated, decode)
        }
        // Transparent until a probe holds a route.
        val probe = LockProbe(asApp)
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to probe)), state, MemoryDeviceState(), crypto,
                { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return World(server, a, state, app, probe)
    }

    /**
     * From the join screen of a connect link: sign-up by email, then the kit. The vault opens. [nameGone]: the name kept
     * at the registration is gone before the vault opens, so the account opens as one made on another device would.
     */
    private suspend fun World.joinAndSignUp(nameGone: Boolean = false) {
        val a = app
        assertEquals(ServerResult.DONE, a.entry.joinFromInvite(a.at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "bob@example.com", true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Bob", strong, true)))
        if (nameGone) a.rememberName(server.instance.origin, a.keeper.session!!.userId, "")
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Test fun aConnectLinkThatLedToANewAccountIsAnsweredOnceTheVaultOpens() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        val row = w.server.rows.values.single()
        assertEquals("answered", row.state, "the connection was answered")
        assertEquals(a.keeper.session!!.userId, row.answerer)
        assertTrue(a.snapshot.account!!.prompts.isEmpty())
        assertNull(a.connectAfterEntry)
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin), "the pin the account stands on stays")
    }

    /** §6.9, §6.11: the contact the connection made is listed, compared with the code the other side reads, and removed. */
    @Test fun theContactAConnectMadeIsComparedByTheCodeTheOtherSideReads() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        val bob = a.keeper.session!!.userId
        assertNull(a.snapshot.account!!.contacts, "closed until opened")
        // Alice's device processes the answer and posts its reveal.
        w.alice.flows.processAnswers()
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single()
        assertEquals(alice, row.userId)
        assertEquals("Alice", row.label)
        assertTrue(!row.compared)
        assertTrue(row.currentHere, "this device answered the link")
        assertTrue(a.snapshot.account!!.prompts.isEmpty(), "a contact this device made raises no prompt")
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openCompare(row))
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(a.snapshot.account!!.comparing)
        assertEquals("Alice", ready.label)
        val theirs = assertNotNull(w.alice.flows.code(bob), "the code Alice's screen shows")
        if (theirs != ready.code) {
            assertEquals(io.silencelen.andvari.core.app.ComparisonResult.MISMATCH, a.contacts.submitComparison(ready, ready.code), "this side's own code is a wrong entry")
            assertTrue(a.snapshot.account!!.comparing === ready, "a wrong entry changes nothing")
        }
        assertEquals(io.silencelen.andvari.core.app.ComparisonResult.DONE, a.contacts.submitComparison(ready, theirs.substring(0, 3) + " " + theirs.substring(3)))
        assertIs<io.silencelen.andvari.core.app.CompareScreen.Matched>(a.snapshot.account!!.comparing)
        assertTrue(a.snapshot.account!!.contacts!!.contacts.single().compared)
        a.contacts.closeCompare()
        assertNull(a.snapshot.account!!.comparing)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.removeContact(a.snapshot.account!!.contacts!!.contacts.single()))
        assertTrue(a.snapshot.account!!.contacts!!.contacts.isEmpty())
        a.lock()
        assertNull(a.snapshot.account)
    }

    /**
     * §6.11 on the side that answered a connect link: the creator's reveal is fetched only by opening the comparison, so
     * the row offers it before the reveal arrived. Before, the row offered it only once the codes were ready, which they
     * never became on this side: the answerer could never compare. Until the reveal is posted the comparison shows no code.
     */
    @Test fun theAnswerersRowOffersTheComparisonThatFetchesTheReveal() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single()
        assertTrue(!row.codesReady, "the reveal has not been fetched")
        assertTrue(row.canCompare, "the comparison is offered all the same")
        // Not posted yet: the comparison waits and shows no code.
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openCompare(row))
        assertIs<io.silencelen.andvari.core.app.CompareScreen.Waiting>(a.snapshot.account!!.comparing)
        a.contacts.closeCompare()
        // Alice's device processes the answer and posts its reveal; opening the comparison again fetches it.
        w.alice.flows.processAnswers()
        val again = a.snapshot.account!!.contacts!!.contacts.single()
        assertTrue(again.canCompare)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openCompare(again))
        val ready = assertIs<io.silencelen.andvari.core.app.CompareScreen.Ready>(a.snapshot.account!!.comparing)
        assertEquals(6, ready.code.length)
        assertTrue(a.snapshot.account!!.contacts!!.contacts.single().codesReady)
    }

    /** §6.7, §6.8 creator side: a link made here, answered by Alice, shows its contact; another is revoked. */
    @Test fun aLinkMadeHereIsAnsweredAndAnotherRevoked() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        // The server serves the creator's key with the link (it took it at Bob's registration).
        val bobOpen = a.keeper.established!!
        w.server.keys[bobOpen.userId] = io.silencelen.andvari.core.crypto.Bytes.toB64(bobOpen.account.identity.publicKey)
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.BAD_LIFETIME, a.links.createConnectLink(emptyList(), 1))
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE, a.links.createConnectLink(emptyList(), 15))
        val screen = assertNotNull(a.snapshot.account!!.links, "making a link opens the links screen")
        val own = screen.links.single()
        assertEquals(io.silencelen.andvari.core.app.OwnLinkKind.CONNECT, own.kind)
        val url = assertNotNull(a.links.linkToShare(own))
        assertTrue(a.links.linkTimeLeftMs(own) in 1..15 * 60_000L)
        // Alice opens it on her device and connects.
        val step = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Confirm>(
            w.alice.flows.open(url, io.silencelen.andvari.core.client.pin.GateEntry.SCAN_INVITE))
        assertEquals("Bob", step.offer.creatorName)
        assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Answered>(w.alice.flows.confirm(step))
        a.linksFlow.processAnswers()
        val links = a.snapshot.account!!.links!!
        assertTrue(links.links.isEmpty(), "an answered link is no longer open")
        val answered = links.answered.single()
        assertEquals(alice, answered.contact.userId)
        assertNull(a.links.linkToShare(own))
        // A second link, revoked: an answer later is ignored, and its secret is gone.
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE, a.links.createConnectLink(emptyList(), 60))
        val second = a.snapshot.account!!.links!!.links.single()
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.links.revokeLink(second))
        assertTrue(a.snapshot.account!!.links!!.links.isEmpty())
        assertNull(a.links.linkToShare(second))
        assertEquals(0L, a.links.linkTimeLeftMs(second))
        a.links.closeLinks()
        assertNull(a.snapshot.account!!.links)
    }

    /**
     * Links: a lock while a new link's POST is on its way. The link engine's
     * record write after the answer is refused under the wiped key; the intent answers STALE (it used to throw the
     * guard's KeysGoneException at the screen), nothing is sent after the lock, and after the next unlock a link is made.
     */
    @Test fun aLinkCreationALockOvertakesAnswersStaleSendsNothingAfterTheLockAndTheAppStaysUsable() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        val p = w.probe
        var result: io.silencelen.andvari.core.app.LinkCreateResult? = null
        with(p) {
            lockDuring(io.silencelen.andvari.core.model.wire.WireRoute.LINK_CREATE, { a.lock() }) { result = a.links.createConnectLink(emptyList(), 15) }
        }
        assertEquals(emptyList(), p.crashes.map { it.toString() }, "the intent answers, it does not crash")
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.STALE, result)
        assertEquals(emptyList(), p.sentAfterLock(), "nothing is sent after the lock")
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE, a.links.createConnectLink(emptyList(), 15))
    }

    /**
     * Contacts: a lock while removing a contact waits on the account state.
     * The account-state write is refused under the wiped key: STALE, nothing sent after the lock, the contact still
     * there, and after the next unlock it is removed as usual.
     */
    @Test fun aContactRemovalALockOvertakesAnswersStaleSendsNothingAfterTheLockAndTheAppStaysUsable() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        w.alice.flows.processAnswers()
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single()
        val p = w.probe
        var result: io.silencelen.andvari.core.app.PlainResult? = null
        with(p) {
            lockDuring(io.silencelen.andvari.core.model.wire.WireRoute.ACCOUNT_STATE_GET, { a.lock() }) { result = a.contacts.removeContact(row) }
        }
        assertEquals(emptyList(), p.crashes.map { it.toString() }, "the intent answers, it does not crash")
        assertEquals(io.silencelen.andvari.core.app.PlainResult.STALE, result)
        assertEquals(emptyList(), p.sentAfterLock(), "nothing is sent after the lock")
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val again = a.snapshot.account!!.contacts!!.contacts.single()
        assertEquals(alice, again.userId, "the contact is still there")
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.removeContact(again))
        assertTrue(a.snapshot.account!!.contacts!!.contacts.isEmpty())
    }

    /** §6.8 recipient side, signed in: a connect link to this account's own server asks, then answers. */
    @Test fun aConnectLinkOpenedSignedInAsksAndConnects() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        assertEquals(InviteResult.NOT_AN_INVITE, a.links.openInvite("hello", PayloadSource.PASTED))
        assertEquals(InviteResult.DONE, a.links.openInvite(w.link("connect"), PayloadSource.SCANNED))
        val ask = assertIs<io.silencelen.andvari.core.app.OpenedInvite.Connect>(a.snapshot.account!!.opened)
        assertEquals("Alice", ask.from)
        assertEquals(w.server.instance.origin, ask.instance.origin)
        val before = w.server.rows.values.count { it.state == "answered" }
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.DONE, a.links.connect(ask))
        assertEquals(before + 1, w.server.rows.values.count { it.state == "answered" })
        val connected = assertIs<io.silencelen.andvari.core.app.OpenedInvite.Connected>(a.snapshot.account!!.opened)
        assertEquals(alice, connected.contact.userId)
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.STALE, a.links.connect(ask))
        a.links.dismissOpened()
        assertNull(a.snapshot.account!!.opened)
        // A register link to the server this account is on cannot be used signed in.
        assertEquals(InviteResult.NOT_USABLE_SIGNED_IN, a.links.openInvite(w.link("register"), PayloadSource.SCANNED))
        assertNull(a.snapshot.account!!.opened)
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin))
        // The approved sentence (entry 7), filled by core with this instance's pinned name and address.
        val line = assertNotNull(a.snapshot.account!!.inviteNotUsed)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ALREADY_SIGNED_IN_THERE, line.key)
        val label = assertNotNull(a.snapshot.instance?.label)
        assertEquals(listOf(label.name, label.origin), line.values)
        assertTrue(line.english.startsWith("This link creates a new account on ${label.name} (${label.origin}). You're already signed in there."))
        a.links.dismissOpened()
        assertNull(a.snapshot.account!!.inviteNotUsed, "put away")
        // Opening another link clears it too.
        assertEquals(InviteResult.NOT_USABLE_SIGNED_IN, a.links.openInvite(w.link("register"), PayloadSource.SCANNED))
        assertNotNull(a.snapshot.account!!.inviteNotUsed)
        assertEquals(InviteResult.NOT_AN_INVITE, a.links.openInvite("not a link", PayloadSource.PASTED))
        assertNull(a.snapshot.account!!.inviteNotUsed)
    }

    /**
     * §6.3, §6.7: a link carries the name its account goes by, and the server serves no account its own name. An account
     * opened on a device that keeps no name for it (made on another device) used to have "Connect" end the opened link
     * with nothing sent and only "failed" said, and every link it made refused the same way: now each asks for the name
     * first, keeps what it holds, and goes on once the person chose one, which this device then keeps.
     */
    @Test fun anAccountWithNoNameKeptHereAsksForItBeforeAnyLinkAndSendsNothingUntilThen() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        val origin = w.server.instance.origin
        val bob = a.keeper.established!!
        w.server.keys[bob.userId] = io.silencelen.andvari.core.crypto.Bytes.toB64(bob.account.identity.publicKey)
        // As on a second device: no name kept here for this account.
        a.rememberName(origin, bob.userId, "")
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
        assertNull(a.links.ownName())

        // Making a link: refused before anything is written or sent.
        val rows = w.server.rows.size
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.NAME_NEEDED, a.links.createConnectLink(emptyList(), 60))
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.NAME_NEEDED, a.links.createInvitation(60))
        assertEquals(rows, w.server.rows.size, "no link was made")
        assertTrue(a.links.let { it.openLinks(); a.snapshot.account!!.links!!.links.isEmpty() }, "no record was kept")

        // Answering a link: the question stays, and nothing is answered.
        assertEquals(InviteResult.DONE, a.links.openInvite(w.link("connect"), PayloadSource.PASTED))
        val ask = assertIs<io.silencelen.andvari.core.app.OpenedInvite.Connect>(a.snapshot.account!!.opened)
        val answered = w.server.rows.values.count { it.state == "answered" }
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.NAME_NEEDED, a.links.connect(ask))
        assertTrue(a.snapshot.account!!.opened === ask, "the question stays")
        assertEquals(answered, w.server.rows.values.count { it.state == "answered" })

        // A name a link cannot carry is not kept.
        for (bad in listOf("", " Bob", "Bob ", "Bo" + Char(0x200B) + "b", "Bo\tb", "x".repeat(65))) {
            assertEquals(io.silencelen.andvari.core.app.OwnNameResult.NOT_A_NAME, a.links.setOwnName(bad), "\"$bad\"")
        }
        assertNull(a.links.ownName())
        assertEquals(io.silencelen.andvari.core.app.OwnNameResult.DONE, a.links.setOwnName("Bob B"))
        assertEquals("Bob B", a.links.ownName())

        // Then "Connect" goes on with the same question, and a link made here carries the name.
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.DONE, a.links.connect(ask))
        assertEquals(answered + 1, w.server.rows.values.count { it.state == "answered" })
        assertEquals(io.silencelen.andvari.core.app.LinkCreateResult.DONE, a.links.createConnectLink(emptyList(), 60))
        val url = assertNotNull(a.links.linkToShare(a.snapshot.account!!.links!!.links.single()))
        val step = assertIs<io.silencelen.andvari.core.client.link.RecipientStep.Confirm>(
            w.alice.flows.open(url, io.silencelen.andvari.core.client.pin.GateEntry.PASTE_INVITE))
        assertEquals("Bob B", step.offer.creatorName)

        // This device keeps it, across a lock.
        a.lock()
        assertNull(a.links.ownName(), "nothing is read while locked")
        assertEquals(io.silencelen.andvari.core.app.OwnNameResult.STALE, a.links.setOwnName("Other"))
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
        assertEquals("Bob B", a.links.ownName())
    }

    /** The connection a connect link opened signed out still owes, for an account with no name kept here: retried once one is chosen. */
    @Test fun aConnectionOwedToAnAccountWithNoNameHereWaitsForTheNameAndIsThenAnswered() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp(nameGone = true)
        assertEquals("open", w.server.rows.values.single().state, "nothing was answered")
        val owed = assertIs<io.silencelen.andvari.core.app.AccountPrompt.ConnectionNotMade>(a.snapshot.account!!.prompts.single())
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.NAME_NEEDED, owed.why)
        assertTrue(owed.canRetry, "it waits for the name")
        assertNotNull(a.connectAfterEntry, "the answer is still held")
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.NAME_NEEDED, a.links.retryConnection(owed))
        assertEquals(io.silencelen.andvari.core.app.OwnNameResult.DONE, a.links.setOwnName("Bob"))
        val again = assertIs<io.silencelen.andvari.core.app.AccountPrompt.ConnectionNotMade>(a.snapshot.account!!.prompts.single())
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.DONE, a.links.retryConnection(again))
        assertEquals("answered", w.server.rows.values.single().state)
        assertTrue(a.snapshot.account!!.prompts.isEmpty())
        assertNull(a.connectAfterEntry)
    }

    /** §6.9: a contact another device made asks once; "not here" is kept on this device, and the list can still confirm it. */
    @Test fun aContactMadeOnAnotherDeviceAsksToBeUsedHere() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.joinAndSignUp()
        // Another device of the account wrote a contact this device never answered or processed a link for.
        val carol = "33333333-3333-4333-8333-333333333333"
        val key = io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 5 })
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (carol to io.silencelen.andvari.core.client.state.ContactRecord(
                carol, key, io.silencelen.andvari.core.trust.TrustGrammar.encodeName("Carol")!!, verifiedAt = w.server.instance.now, compared = false,
                madeOn = "44444444-4444-4444-8444-444444444444")))
        }
        a.publish()
        val asked = assertIs<io.silencelen.andvari.core.app.AccountPrompt.NewPerson>(a.snapshot.account!!.prompts.single())
        assertEquals(carol, asked.userId)
        assertEquals("Carol", asked.label)
        a.contacts.dontUseOnThisDevice(asked)
        assertTrue(a.snapshot.account!!.prompts.isEmpty())
        // Not at the next unlock either: the answer is this device's own record.
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertTrue(a.snapshot.account!!.prompts.isEmpty())
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.openContacts())
        val row = a.snapshot.account!!.contacts!!.contacts.single { it.userId == carol }
        assertTrue(!row.currentHere)
        assertEquals(io.silencelen.andvari.core.app.PlainResult.DONE, a.contacts.confirmOnThisDevice(row))
        assertTrue(a.snapshot.account!!.contacts!!.contacts.single { it.userId == carol }.currentHere)
    }

    @Test fun aConnectionAnsweredFirstBySomeoneElseIsSaidAndGivingItUpKeepsThePin() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        // Someone else answers the link while the person signs up.
        w.server.rows.values.single().state = "answered"
        w.joinAndSignUp()
        val prompt = assertIs<io.silencelen.andvari.core.app.AccountPrompt.ConnectionNotMade>(a.snapshot.account!!.prompts.single())
        assertEquals("Alice", prompt.from)
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.ALREADY_USED, prompt.why)
        assertTrue(!prompt.canRetry)
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.STALE, a.links.retryConnection(prompt))
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin), "a spent link leaves the account's pin")
        a.links.dropConnection(prompt)
        assertTrue(a.snapshot.account!!.prompts.isEmpty())
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin))
    }

    @Test fun anAnswerWithNoReplyIsRetriedFromThePromptAndFindsItLanded() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        // The server takes the answer, but its reply is lost on the way back.
        w.server.loseReply += io.silencelen.andvari.core.model.wire.WireRoute.LINK_ANSWER
        w.joinAndSignUp()
        val prompt = assertIs<io.silencelen.andvari.core.app.AccountPrompt.ConnectionNotMade>(a.snapshot.account!!.prompts.single())
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.UNREACHABLE, prompt.why)
        assertTrue(prompt.canRetry)
        assertNotNull(a.connectAfterEntry, "the step is held for the retry")
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.UNREACHABLE, a.links.retryConnection(prompt))
        assertTrue(a.snapshot.account!!.prompts.single() === prompt, "the prompt stays as it was")
        w.server.loseReply.clear()
        assertEquals(io.silencelen.andvari.core.app.ConnectResult.DONE, a.links.retryConnection(prompt))
        assertTrue(a.snapshot.account!!.prompts.isEmpty())
        assertNull(a.connectAfterEntry)
    }

    @Test fun signingOutWithAConnectionStillOwedKeepsThePinAndForgetsTheLink() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.server.loseReply += io.silencelen.andvari.core.model.wire.WireRoute.LINK_ANSWER
        w.joinAndSignUp()
        assertNotNull(a.connectAfterEntry)
        a.signOut()
        assertNull(a.connectAfterEntry)
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin), "pins outlive a sign-out")
    }

    /**
     * The link engine settles the flow once the account stands on its pin (LinkFlows.settle): ending it later through
     * the engine itself, with no guard of the app's own in between, keeps the pin and leaves no flow.
     */
    @Test fun aHeldConnectionIsSettledSoEndingItInTheEngineKeepsThePin() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        w.server.loseReply += io.silencelen.andvari.core.model.wire.WireRoute.LINK_ANSWER
        w.joinAndSignUp()
        val held = assertNotNull(a.connectAfterEntry)
        assertEquals(1, a.entryLinks.openFlows(), "only the settled flow is held")
        a.entryLinks.dismiss(held)
        assertEquals(0, a.entryLinks.openFlows())
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin), "the engine keeps the pin of a settled flow")
    }

    private suspend fun World.link(kind: String): String =
        assertIs<CreateOutcome.Created>(alice.flows.create(kind, 60 * 60 * 1000L, emptyList())).link.url

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun EngineAppApi.scan(url: String): InviteResult {
        entry.openInviteEntry(at())
        return entry.submitInvite(at(), url, PayloadSource.SCANNED)
    }

    @Test fun anInvitationLinkRegistersAnAccountAndOpensTheVaultAfterTheKit() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("register")))
        val form = a.at<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.INVITATION_LINK, form.via)
        assertEquals("Alice", form.invitedBy)
        assertEquals(w.server.instance.origin, form.instance.origin)
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(form, NewAccountInput("bob@example.com", "Bob", strong, true)))
        assertEquals("answered", w.server.rows.values.single().state, "the registration answered the link")
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin), "the pin the account stands on stays")
        assertEquals(0, a.entryLinks.openFlows(), "the registration ended the link's flow")
    }

    @Test fun aConnectLinkWithoutAnAccountOffersASignUpAndGivingUpDropsThePinItMade() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(InviteResult.DONE, a.scan(w.link("connect")))
        val join = a.at<EntryScreen.JoinInvite>()
        assertEquals("Alice", join.from)
        assertIs<PinState.Pinned>(a.trust.pinState(w.server.instance.origin))
        assertEquals(ServerResult.DONE, a.entry.joinFromInvite(join))
        assertEquals("Alice", a.at<EntryScreen.SignUpEmail>().connectWith)
        a.entry.startOver()
        a.at<EntryScreen.FirstRun>()
        assertEquals(PinState.None, a.trust.pinState(w.server.instance.origin), "a link given up leaves no pin")
    }

    @Test fun anExpiredOrUsedLinkIsSaidAsSuchAndStartsNothing() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        val url = w.link("register")
        w.server.instance.now += 2 * 60 * 60 * 1000L
        assertEquals(InviteResult.EXPIRED, a.scan(url))
        a.at<EntryScreen.InviteEntry>()
        assertEquals(PinState.None, a.trust.pinState(w.server.instance.origin))
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, a.entry.submitInvite(a.at(), "andvari-kit:2:nothing", PayloadSource.PASTED))
        assertEquals(InviteResult.NOT_AN_INVITE, a.entry.submitInvite(a.at(), "hello", PayloadSource.PASTED))
    }

    @Test fun aServerServingAnotherAddresssCardShowsBothAddresses() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        val url = w.link("register")
        // The link's server now serves a genuine card made for another address (cards are public).
        val other = FakeInstance(crypto, origin = "https://other.example")
        w.server.instance.cards[0] = other.cards[0]
        assertEquals(InviteResult.OTHER_ADDRESS, a.scan(url))
        val shown = a.at<EntryScreen.AddressMismatch>()
        assertEquals(AddressMismatchFor.INVITE, shown.opening)
        assertEquals(w.server.instance.origin, shown.dialed)
        assertEquals("https://other.example", shown.cardNames)
        assertEquals(PinState.None, a.trust.pinState(w.server.instance.origin), "nothing pinned")
        assertTrue(a.entry.back())
        a.at<EntryScreen.InviteEntry>()
        assertNull(a.snapshot.account)
    }
}
