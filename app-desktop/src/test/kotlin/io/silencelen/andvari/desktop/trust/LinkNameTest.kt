package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
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
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A computer that signs in to an account made on another device keeps no name for its links, and the server serves none:
 * every link road stops there with nothing sent. The desktop asks for the name in a window of its own before Connect,
 * before making a connect link or an invitation, and before trying again a connection a sign-in still owes; keeps it;
 * then goes on with what the person was doing. Lines are named by their keys, so these hold whatever their words are.
 */
class LinkNameTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** This account as the fake's servers keep it. */
    private fun me(api: FakeDesktopAppApi): FakeAccount {
        val origin = assertNotNull(api.snapshot.instance).label.origin
        return assertNotNull(assertNotNull(api.script.server(origin)).accounts[assertNotNull(api.snapshot.account).email])
    }

    /** As on a computer that signed in to an account made elsewhere: no name kept here. */
    private fun madeElsewhere(api: FakeDesktopAppApi) {
        me(api).nameHere = null
        assertNull(api.links.ownName())
    }

    private fun shown(key: CopyKey) = UiText.of(key).shown()

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/$name").readText()

    @Test
    fun connectWithNoNameKeptAsksForItFirstThenConnects() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        madeElsewhere(api)
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        val ask = m.linkName
        ask.go(NamedLinkAct.Connect(opened))
        assertIs<NamedLinkAct.Connect>(ask.waiting, "the window asks for the name")
        assertSame(opened, assertNotNull(api.snapshot.account).opened, "nothing was answered; the question stays")
        assertNull(m.saidOn(api.snapshot), "nothing is said on the page: the window says it")

        // A name a link cannot carry is said in the window, which stays.
        for (bad in listOf("", " padded ", "tab\there")) {
            ask.keep(bad)
            assertEquals(shown(CopyKey.LINK_NAME_NOT_A_NAME), assertNotNull(ask.said).shown(), bad)
            assertIs<NamedLinkAct.Connect>(ask.waiting)
            assertNull(api.links.ownName())
            assertSame(opened, assertNotNull(api.snapshot.account).opened)
        }

        ask.keep("Ada at home")
        assertNull(ask.waiting, "the window goes")
        assertNull(ask.said)
        assertEquals("Ada at home", api.links.ownName())
        assertIs<OpenedInvite.Connected>(assertNotNull(api.snapshot.account).opened, "and Connect went on by itself")
    }

    @Test
    fun aNameKeptHereConnectsAtOnceWithNoWindow() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        assertNotNull(api.links.ownName())
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        m.linkName.go(NamedLinkAct.Connect(opened))
        assertNull(m.linkName.waiting)
        assertIs<OpenedInvite.Connected>(assertNotNull(api.snapshot.account).opened)
    }

    @Test
    fun aCallThatAnswersThatANameIsNeededOpensTheWindowRatherThanSayingItOnThePage() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        api.script.forceNext(ConnectResult.NAME_NEEDED)
        m.linkName.go(NamedLinkAct.Connect(opened))
        assertIs<NamedLinkAct.Connect>(m.linkName.waiting)
        assertNull(m.saidOn(api.snapshot))
        m.linkName.keep("Ada")
        assertNull(m.linkName.waiting)
        assertIs<OpenedInvite.Connected>(assertNotNull(api.snapshot.account).opened)
    }

    @Test
    fun cancelKeepsNothingSendsNothingAndLeavesTheQuestion() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        madeElsewhere(api)
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        m.linkName.go(NamedLinkAct.Connect(opened))
        m.linkName.cancel()
        assertNull(m.linkName.waiting)
        assertNull(api.links.ownName())
        assertSame(opened, assertNotNull(api.snapshot.account).opened)
    }

    @Test
    fun makingAConnectLinkAsksForTheNameThenMakesItAndClearsTheTicks() {
        val (api, m) = at(FakeScene.LINKS)
        madeElsewhere(api)
        val before = assertNotNull(assertNotNull(api.snapshot.account).links).links.size
        val answers = mutableListOf<LinkCreateResult>()
        m.linkName.go(NamedLinkAct.CreateLink(emptyList(), LinkLifetimes.IN_PERSON_MINUTES) { answers += it })
        assertIs<NamedLinkAct.CreateLink>(m.linkName.waiting)
        assertEquals(before, assertNotNull(assertNotNull(api.snapshot.account).links).links.size, "no link was made")
        assertEquals(emptyList(), answers)
        m.linkName.keep("Ada")
        assertNull(m.linkName.waiting)
        assertEquals(before + 1, assertNotNull(assertNotNull(api.snapshot.account).links).links.size)
        assertEquals(listOf(LinkCreateResult.DONE), answers)
    }

    @Test
    fun makingAnInvitationAsksForTheNameThenMakesIt() {
        val (api, m) = at(FakeScene.OPERATOR_CONSOLE)
        madeElsewhere(api)
        m.run({ links.openLinks() })
        val before = assertNotNull(assertNotNull(api.snapshot.account).links).links.size
        m.linkName.go(NamedLinkAct.Invitation(LinkLifetimes.IN_PERSON_MINUTES))
        assertIs<NamedLinkAct.Invitation>(m.linkName.waiting)
        assertEquals(before, assertNotNull(assertNotNull(api.snapshot.account).links).links.size)
        m.linkName.keep("Operator")
        assertNull(m.linkName.waiting)
        assertNull(m.saidOn(api.snapshot), "made")
        assertEquals(before + 1, assertNotNull(assertNotNull(api.snapshot.account).links).links.size)
    }

    @Test
    fun theConnectionASignInStillOwesWaitsForTheNameThenIsAnswered() {
        val (api, m) = at(FakeScene.PROMPT_CONNECTION_NOT_MADE)
        madeElsewhere(api)
        val p = assertIs<AccountPrompt.ConnectionNotMade>(assertNotNull(api.snapshot.account).prompts.single { it is AccountPrompt.ConnectionNotMade })
        m.linkName.go(NamedLinkAct.Retry(p))
        assertIs<NamedLinkAct.Retry>(m.linkName.waiting)
        assertTrue(assertNotNull(api.snapshot.account).prompts.any { it is AccountPrompt.ConnectionNotMade }, "still owed")
        m.linkName.keep("Ada")
        assertNull(m.linkName.waiting)
        assertFalse(assertNotNull(api.snapshot.account).prompts.any { it is AccountPrompt.ConnectionNotMade }, "answered")
    }

    @Test
    fun aLockPutsTheWindowAway() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        madeElsewhere(api)
        m.linkName.go(NamedLinkAct.Connect(assertIs(assertNotNull(api.snapshot.account).opened)))
        assertNotNull(m.linkName.waiting)
        api.lock()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.linkName.waiting, "the next unlock does not open it again")
    }

    /**
     * Found in the run against a real server: on the side that answered the link, the codes are ready only once the
     * creator's reveal has arrived, and the shared code fetches it only when the comparison is opened, so "Compare codes"
     * offered on ready codes alone was never offered there. It is offered for an uncompared person used here, and opens
     * the comparison (waiting for the code until the reveal comes). Once connected, the opened link's way out is Close.
     */
    @Test
    fun afterConnectTheAnswerersSideIsOfferedTheComparisonAndTheWayOutCloses() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        assertEquals(UiText.of(CopyKey.CANCEL).shown(), openedWayOut(opened).shown())
        m.linkName.go(NamedLinkAct.Connect(opened))
        val connected = assertIs<OpenedInvite.Connected>(assertNotNull(api.snapshot.account).opened)
        assertEquals(UiText.ph(Placeholder.CLOSE).shown(), openedWayOut(connected).shown())
        m.run({ contacts.openContacts() })
        // As the engine marks the answerer's row (the fake's connect does not yet): the creator's reveal waits to be fetched.
        val contact = api.script.publicInstance.accounts.values.flatMap { it.contacts }.first { it.userId == connected.contact.userId }
        contact.revealWaiting = true
        api.script.changed()
        val row = assertNotNull(api.snapshot.account?.contacts).contacts.single { it.userId == connected.contact.userId }
        assertFalse(row.codesReady, "the creator's code has not arrived")
        assertFalse(row.compared)
        assertTrue(row.canCompare && offersCompare(row), "Compare codes is offered all the same")
        m.run({ contacts.openCompare(row) })
        assertNotNull(assertNotNull(api.snapshot.account).comparing, "the comparison opens")
        assertTrue(src("PeopleScreens.kt").contains("if (offersCompare(c)) Second(UiText.of(CopyKey.COMPARE_CODES)"))
    }

    /**
     * The check of 2026-11-17 (property 5): the comparison is offered only where the shared code's [ContactRow.canCompare]
     * says so. A person used here whose link failed (a second, different reveal) cannot compare, and is not offered it;
     * the desktop's own rule offered it to every person used here.
     */
    @Test
    fun theComparisonIsOfferedOnlyWhereTheSharedCodeSaysItCanBeOpened() {
        val (api, m) = at(FakeScene.CONTACTS)
        m.run({ contacts.openContacts() })
        val rows = assertNotNull(api.snapshot.account?.contacts).contacts
        for (r in rows) assertEquals(!r.compared && r.canCompare, offersCompare(r), r.label)
        val open = rows.first { !it.compared && it.currentHere }
        val contact = api.script.publicInstance.accounts.values.flatMap { it.contacts }.first { it.userId == open.userId }
        api.script.linkFails(contact)
        val failed = assertNotNull(api.snapshot.account?.contacts).contacts.single { it.userId == open.userId }
        assertTrue(failed.currentHere && !failed.compared && !failed.canCompare)
        assertFalse(offersCompare(failed), "a failed link offers no comparison")
    }

    @Test
    fun everyLinkRoadGoesThroughTheNameAndTheWindowIsDrawnOverThePages() {
        val links = src("LinksScreens.kt")
        assertTrue(links.contains("model.linkName.go(NamedLinkAct.Connect(opened))"))
        assertTrue(links.contains("model.linkName.go(NamedLinkAct.CreateLink(choices, mins)"))
        assertTrue(links.contains("model.linkName.go(NamedLinkAct.Invitation(LinkLifetimes.IN_PERSON_MINUTES))"))
        assertFalse(links.contains("links.connect(") || links.contains("links.createConnectLink(") || links.contains("links.createInvitation("), "no road around the name")
        val people = src("PeopleScreens.kt")
        assertTrue(people.contains("model.linkName.go(NamedLinkAct.Retry(p))"))
        assertFalse(people.contains("links.retryConnection("))
        assertTrue(src("AccountScreens.kt").substringAfter("internal fun AccountShell(").substringBefore("\n}\n").contains("LinkNameWindow(model, s)"))

        // The window draws, with the field and a refused name's sentence.
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        madeElsewhere(api)
        m.linkName.go(NamedLinkAct.Connect(assertIs(assertNotNull(api.snapshot.account).opened)))
        m.linkName.keep("")
        val s = api.snapshot
        val image = ImageComposeScene(640, 480, Density(1f)) { MaterialTheme { Surface { LinkNameWindow(m, s) } } }
        try {
            image.render()
        } finally {
            image.close()
        }
    }
}
