package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.LinksApi
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnLinkKind
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * On a phone signed in to an account made on another device, the phone does not know the name the account goes by in
 * its links, and the server serves none (§6.7). Before anything is made or sent, the app asks for it, once, never
 * invents one, keeps a refused name's text with its sentence, and then goes on with what the person was doing: making
 * a connect link, making an invitation, "Connect" on a pasted link, and the answer a sign-in still owes.
 */
class LinkNameAskTest {
    private fun at(scene: FakeScene, api: (FakeAppApi) -> AppApi = { it }): Pair<FakeAppApi, TrustModel> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api(fake), CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(fake.snapshot)
        return fake to m
    }

    /** As on a second device: this phone keeps no name for the signed-in account. */
    private fun madeElsewhere(api: FakeAppApi): FakeAccount {
        val origin = assertNotNull(api.snapshot.instance).label.origin
        val me = assertNotNull(api.script.server(origin)).accounts.values.single { it.email.equals(FakeScenes.EMAIL, ignoreCase = true) }
        me.nameHere = null
        assertNull(api.links.ownName())
        return me
    }

    private fun ownLinks(api: FakeAppApi) = assertNotNull(assertNotNull(api.snapshot.account).links).links

    @Test
    fun makingAConnectLinkAsksForTheNameKeepsARefusedOneAndThenMakesTheLink() {
        val (api, m) = at(FakeScene.VAULTS)
        madeElsewhere(api)
        m.run({ links.openLinks() })
        var cleared = false
        m.linkAct(TrustModel.LinkAct.MakeConnectLink(emptyList(), 60)) { cleared = it.done }
        val ask = assertNotNull(m.nameAsk.value, "the question for the name")
        assertIs<TrustModel.LinkAct.MakeConnectLink>(ask.act)
        assertNull(ask.refused)
        assertTrue(ownLinks(api).isEmpty(), "nothing was made")
        assertNull(m.saidOn(api.snapshot), "no refusal under the top: the question says it")

        // A name a link cannot carry: the question stays, with its sentence; nothing was kept.
        m.giveOwnName(" Ada ")
        assertEquals(CopyKey.LINK_NAME_NOT_A_NAME, assertNotNull(m.nameAsk.value).refused)
        assertEquals(" Ada ", assertNotNull(m.nameAsk.value).typed, "what was typed is kept")
        assertNull(api.links.ownName())
        assertTrue(ownLinks(api).isEmpty())

        // The name as typed: kept, and the link is made with what the person chose.
        m.giveOwnName("Ada L")
        assertNull(m.nameAsk.value)
        assertEquals("Ada L", api.links.ownName())
        assertEquals(OwnLinkKind.CONNECT, ownLinks(api).single().kind)
        assertTrue(cleared, "what the screen does after the link was made ran once it was made")

        // Asked once: the next link goes straight on.
        m.linkAct(TrustModel.LinkAct.MakeConnectLink(emptyList(), 60))
        assertNull(m.nameAsk.value)
        assertEquals(2, ownLinks(api).size)
    }

    @Test
    fun makingAnInvitationAsksForTheNameFirstThenMakesTheInvitation() {
        // A family's server, where any member may send an invitation.
        val (api, m) = at(FakeScene.RECOVERY)
        madeElsewhere(api)
        m.run({ links.openLinks() })
        assertTrue(assertNotNull(assertNotNull(api.snapshot.account).links).invitationsAllowed)
        m.linkAct(TrustModel.LinkAct.MakeInvitation(LinkLifetimes.IN_PERSON_MINUTES))
        assertIs<TrustModel.LinkAct.MakeInvitation>(assertNotNull(m.nameAsk.value).act)
        assertTrue(ownLinks(api).isEmpty())
        m.giveOwnName("Ada")
        assertNull(m.nameAsk.value)
        assertEquals(OwnLinkKind.INVITATION, ownLinks(api).single().kind)
    }

    /** A phone whose shared code says it has a name, but whose call still answers NAME_NEEDED (nothing sent). */
    private class NameNotReallyKept(val fake: FakeAppApi) : AppApi by fake {
        override val links: LinksApi = object : LinksApi by fake.links {
            override fun ownName(): String? = fake.links.ownName() ?: "stale"
        }
    }

    @Test
    fun connectOnAPastedLinkAsksForTheNameWhenTheCallAnswersNameNeededThenConnectsTheSameLink() {
        val (api, m) = at(FakeScene.OPENED_CONNECT) { NameNotReallyKept(it) }
        val me = madeElsewhere(api)
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        val contacts = me.contacts.size
        m.linkAct(TrustModel.LinkAct.Connect(opened))
        val ask = assertNotNull(m.nameAsk.value, "NAME_NEEDED opens the question")
        assertSame(opened, assertIs<TrustModel.LinkAct.Connect>(ask.act).opened, "for the same opened link")
        assertSame(opened, assertNotNull(api.snapshot.account).opened, "the question \"Connect with …?\" stays")
        assertNull(m.saidOn(api.snapshot), "NAME_NEEDED is not said as a refusal")
        assertEquals(contacts, me.contacts.size, "nothing was answered")

        m.giveOwnName("Ada")
        assertNull(m.nameAsk.value)
        assertIs<OpenedInvite.Connected>(assertNotNull(api.snapshot.account).opened, "Connect went on with the same link")
        assertEquals(contacts + 1, me.contacts.size)
    }

    @Test
    fun connectOnAPastedLinkAsksBeforeCallingWhenThisPhoneKeepsNoName() {
        val (api, m) = at(FakeScene.OPENED_CONNECT)
        madeElsewhere(api)
        val opened = assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account).opened)
        m.linkAct(TrustModel.LinkAct.Connect(opened))
        assertNotNull(m.nameAsk.value)
        // Cancel: nothing kept, nothing sent, the question for the link stays where it was.
        m.dropNameAsk()
        assertNull(m.nameAsk.value)
        assertNull(api.links.ownName())
        assertSame(opened, assertNotNull(api.snapshot.account).opened)
        // Putting the opened link away closes a question that was for it.
        m.linkAct(TrustModel.LinkAct.Connect(opened))
        m.act { links.dismissOpened() }
        m.onSnapshot(api.snapshot)
        assertNull(m.nameAsk.value)
    }

    @Test
    fun theConnectionASignInStillOwesIsSentOnceTheNameIsGiven() {
        // An account made to connect with Bo, whose answer did not go out; on this phone no name is kept for it.
        val (api, m) = at(FakeScene.PROMPT_CONNECTION_NOT_MADE)
        val me = madeElsewhere(api)
        val owed =assertNotNull(assertNotNull(api.snapshot.account).prompts.filterIsInstance<AccountPrompt.ConnectionNotMade>().singleOrNull())
        assertTrue(owed.canRetry)
        m.linkAct(TrustModel.LinkAct.RetryConnection(owed))
        assertIs<TrustModel.LinkAct.RetryConnection>(assertNotNull(m.nameAsk.value).act)
        assertTrue(me.contacts.none { it.label == "Bo" }, "nothing was sent")

        m.giveOwnName("Ada")
        assertNull(m.nameAsk.value)
        assertTrue(assertNotNull(api.snapshot.account).prompts.none { it is AccountPrompt.ConnectionNotMade }, "the owed answer went")
        assertTrue(me.contacts.any { it.label == "Bo" })
        assertNull(m.said.value?.result?.takeIf { it != ConnectResult.DONE }, "nothing refused")
    }

    @Test
    fun aLockWhileTheQuestionIsOpenClosesItAndKeepsNothing() {
        val (api, m) = at(FakeScene.VAULTS)
        madeElsewhere(api)
        m.linkAct(TrustModel.LinkAct.MakeConnectLink(emptyList(), 60))
        assertNotNull(m.nameAsk.value)
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.nameAsk.value)
        m.giveOwnName("Ada")
        assertNull(m.nameAsk.value, "an answer after the lock does nothing")
    }

    @Test
    fun everyButtonThatSendsTheNameGoesThroughTheQuestionAndTheFieldStartsEmpty() {
        fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()
        val links = src("LinksScreens.kt")
        assertTrue("model.linkAct(TrustModel.LinkAct.MakeConnectLink(choices, mins))" in links)
        assertTrue("model.linkAct(TrustModel.LinkAct.MakeInvitation(LinkLifetimes.IN_PERSON_MINUTES))" in links)
        assertTrue("model.linkAct(TrustModel.LinkAct.Connect(opened))" in links)
        assertTrue("model.linkAct(TrustModel.LinkAct.RetryConnection(p))" in src("PeopleScreens.kt"))
        for (call in listOf("links.createConnectLink(", "links.createInvitation(", "links.connect(", "links.retryConnection(")) {
            val screens = File("src/main/kotlin/io/silencelen/andvari/app/trust").listFiles()!!.filter { it.name != "TrustModel.kt" }
            assertTrue(screens.none { call in it.readText() }, "$call only through the question for the name")
        }
        val dialog = links.substringAfter("internal fun LinkNameDialog(").substringBefore("\n}\n")
        assertTrue("var name by remember { mutableStateOf(open.typed) }" in dialog, "the app never fills a name in")
        val made = Regex("\\bNameAsk\\([^)]*after[^)]*\\)").findAll(src("TrustModel.kt")).map { it.value }.toList()
        assertTrue(made.size >= 3 && made.all { it.endsWith(", null)") || it.endsWith("LINK_NAME_NOT_A_NAME, name)") }, "typed is only ever what the person typed: $made")
        assertTrue("model.giveOwnName(name)" in dialog, "the name as typed, not trimmed")
        assertTrue("Say(CopyKey.LINK_NAME_NEEDED)" in dialog)
        assertTrue("open.refused?.let" in dialog)
        assertTrue("LinkNameDialog(model, s)" in src("TrustApp.kt"))
        // LinkCreateResult.NAME_NEEDED carries the question's sentence: the screen asks rather than refuses.
        assertEquals(CopyKey.LINK_NAME_NEEDED, LinkCreateResult.NAME_NEEDED.sentence)
    }
}
