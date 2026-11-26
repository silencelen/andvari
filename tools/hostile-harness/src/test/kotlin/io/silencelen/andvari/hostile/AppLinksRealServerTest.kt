package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.ContactRow
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.OwnNameResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ShareChoice
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.CreatorStep
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.MemberRole
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.http.Url
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §6.7, §6.8 and §6.10, the links of the app interface, against the REAL server, with the app interface on both
 * sides (the desktop app's engine, driven as the desktop drives it): one account makes a link, the other pastes it while
 * signed in ([io.silencelen.andvari.core.app.LinksApi.openInvite]) and answers "Connect"
 * ([io.silencelen.andvari.core.app.LinksApi.connect]). Until these, the flows were run only against stand-ins of the
 * server, which never asked what a real account signed in on a second device lacks: the name its links carry. The
 * server serves no account its own name, so a device that did not make the account keeps none, and the link engine
 * signs nothing without one (it ended the flow, with nothing sent, and "Connect" said only that it failed). Every
 * account here is made with the command-line tool and then signed in on a desktop, as on a person's second device.
 */
class AppLinksRealServerTest {
    private val crypto = createCryptoProvider()

    private fun World.desktop(tag: String, http: HttpClient = server.httpFor(proxy.dial(tag))): EngineDesktopAppApi {
        val state = MemoryDeviceState()
        val engine = AppEngine(AppPlatform.LINUX, "Desk $tag", dialingTransport(state, http, AppPlatform.LINUX), state, MemoryDeviceState(),
            crypto, server::now, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.IO)
        return EngineDesktopAppApi(engine).also { it.start() }
    }

    /** A device's network that reaches two servers, each origin through its own world's proxy as [tag] (and nothing else). */
    private fun twoServers(tag: String, a: World, b: World): HttpClient {
        val routes = listOf(Url(a.origin) to Url(a.proxy.dial(tag)), Url(b.origin) to Url(b.proxy.dial(tag)))
        return HttpClient(Java) {
            install(HttpTimeout) { requestTimeoutMillis = 60_000; connectTimeoutMillis = 10_000 }
            expectSuccess = false
            install(createClientPlugin("two servers") {
                onRequest { req, _ ->
                    val port = req.url.port.takeIf { it != 0 } ?: req.url.protocol.defaultPort
                    val to = routes.firstOrNull { (o, _) -> req.url.host == o.host && port == o.port && req.url.protocol == o.protocol }?.second
                        ?: error("refusing to dial ${req.url.host}: this test reaches only its two servers")
                    req.url.protocol = to.protocol
                    req.url.host = to.host
                    req.url.port = to.port
                }
            })
        }
    }

    private inline fun <reified T : EntryScreen> EngineDesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** The person types the server's address, confirms its Trust Gate and signs in with the password: the vault opens. */
    private suspend fun World.signedInDesktop(tag: String, email: String, http: HttpClient = server.httpFor(proxy.dial(tag))): EngineDesktopAppApi {
        val app = desktop(tag, http)
        app.entry.openOwnServer(app.at())
        assertEquals(ServerResult.DONE, app.entry.submitServerAddress(app.at(), origin))
        assertEquals(ServerResult.DONE, app.entry.confirmTrustGate(app.at()))
        assertEquals(ServerResult.DONE, app.entry.signInHere(app.at()))
        assertEquals(SignInAnswer.DONE, app.entry.submitSignIn(app.at(), email, Steps.PASSWORD))
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "the vault opens")
        return app
    }

    private fun EngineDesktopAppApi.account() = assertNotNull(snapshot.account, "the vault is open")

    /** [app] makes a connect link with [shares] attached, naming itself [name] first, and answers the link's address. */
    private suspend fun World.connectLinkOf(app: EngineDesktopAppApi, name: String, shares: List<ShareChoice> = emptyList()): String {
        assertEquals(PlainResult.DONE, app.links.openLinks())
        val mark = proxy.mark()
        // An account signed in on a second device: its name is asked for before any link is made, with nothing sent.
        assertNull(app.links.ownName(), "this device keeps no name for an account made elsewhere")
        assertEquals(LinkCreateResult.NAME_NEEDED, app.links.createConnectLink(shares, 60))
        assertEquals(emptyList(), proxy.requests(WireRoute.LINK_CREATE, since = mark), "nothing was made")
        assertEquals(OwnNameResult.DONE, app.links.setOwnName(name))
        assertEquals(LinkCreateResult.DONE, app.links.createConnectLink(shares, 60), "the link is made: ${proxy.tail()}")
        val row = assertNotNull(app.account().links?.links?.singleOrNull(), "the links screen lists it")
        return assertNotNull(app.links.linkToShare(row))
    }

    /**
     * [ada] pastes [url] and answers "Connect": first without a name (refused, nothing sent, the question kept), then
     * with one. Answers the contact the answer made on her side.
     */
    private suspend fun World.connects(ada: EngineDesktopAppApi, url: String, name: String): ContactRow {
        assertEquals(InviteResult.DONE, ada.links.openInvite(url, PayloadSource.PASTED), "the pasted link opens: ${proxy.tail()}")
        val opened = assertIs<OpenedInvite.Connect>(ada.account().opened, "\"Connect with …?\"")
        val mark = proxy.mark()
        assertEquals(ConnectResult.NAME_NEEDED, ada.links.connect(opened), "the answer needs this account's name")
        assertEquals(emptyList(), proxy.requests(tag = "ada", since = mark).map { it.route }, "nothing was sent")
        assertTrue(ada.account().opened === opened, "the question stays")
        assertEquals(OwnNameResult.DONE, ada.links.setOwnName(name))
        assertEquals(ConnectResult.DONE, ada.links.connect(opened), "Connect answers: ${proxy.tail()}")
        assertTrue(proxy.requests(WireRoute.LINK_ANSWER, "ada", mark).isNotEmpty(), "the answer reached the server")
        return assertIs<OpenedInvite.Connected>(ada.account().opened, "the contact it made is shown").contact
    }

    /** The creator reads the answers; both screens then show their codes and each person types the other's. */
    private suspend fun World.compared(bo: EngineDesktopAppApi, ada: EngineDesktopAppApi, adaSide: ContactRow, from: String, to: String) {
        assertEquals(PlainResult.DONE, bo.links.openLinks())
        val answered = assertNotNull(bo.account().links?.answered?.singleOrNull(), "the creator processed the answer: ${proxy.tail()}")
        assertEquals(to, answered.contact.label, "the creator sees the name the answer carried")
        assertEquals(from, adaSide.label, "the answerer sees the name the offer carried")
        assertEquals(PlainResult.DONE, bo.contacts.openCompare(answered.contact))
        assertEquals(PlainResult.DONE, ada.contacts.openCompare(adaSide))
        val boScreen = assertIs<CompareScreen.Ready>(bo.account().comparing, "the creator's code")
        val adaScreen = assertIs<CompareScreen.Ready>(ada.account().comparing, "the answerer's code, once the reveal arrived: ${proxy.tail()}")
        assertEquals(ComparisonResult.DONE, bo.contacts.submitComparison(boScreen, adaScreen.code))
        assertEquals(ComparisonResult.DONE, ada.contacts.submitComparison(adaScreen, boScreen.code))
    }

    @Test fun aConnectLinkPastedWhileSignedInAsksForTheNameThenConnectsBothAccounts() = world {
        operator()
        member("alice")
        member("bob")
        val ada = signedInDesktop("ada", "alice@example.org")
        val bo = signedInDesktop("bo", "bob@example.org")
        val url = connectLinkOf(bo, "Bo")
        val adaSide = connects(ada, url, "Ada")
        compared(bo, ada, adaSide, from = "Bo", to = "Ada")
        assertTrue(ada.contacts.let { it.openContacts(); ada.account().contacts!!.contacts.single().compared }, "compared on her side")
    }

    @Test fun aConnectLinkWithAVaultAttachedSharesItOnceTheCreatorsCodesMatched() = world {
        operator()
        member("alice")
        member("bob")
        val ada = signedInDesktop("ada", "alice@example.org")
        val bo = signedInDesktop("bo", "bob@example.org")
        assertEquals(VaultActionResult.DONE, bo.vaults.createVault("Trips"), "the vault is made: ${proxy.tail()}")
        // Its row comes with the pull the creation starts; this waits for one.
        bo.content!!.refresh()
        val trips = assertNotNull(bo.account().vaults.singleOrNull { it.name == "Trips" },
            "the creator's shared vault: ${bo.account().vaults.map { "${it.vaultId} ${it.name} ${it.role} ${it.log}" }}")
        val url = connectLinkOf(bo, "Bo", listOf(ShareChoice(trips.vaultId, MemberRole.READER)))
        val adaSide = connects(ada, url, "Ada")
        compared(bo, ada, adaSide, from = "Bo", to = "Ada")
        // The creator's matched entry released the share through the vault's log (§6.10): the answerer is offered it.
        assertEquals(emptyList(), bo.account().links?.waitingShares.orEmpty(), "nothing waits on the creator's side")
        ada.content!!.refresh()
        val incoming = assertNotNull(ada.account().prompts.filterIsInstance<AccountPrompt.IncomingVault>().singleOrNull(), "the vault is offered: ${ada.account().prompts}")
        assertEquals("Trips", incoming.vaultName)
        assertEquals("Bo", incoming.from)
        assertEquals(VaultActionResult.DONE, ada.vaults.acceptIncoming(incoming))
        assertNotNull(ada.account().vaults.singleOrNull { it.vaultId == trips.vaultId && it.name == "Trips" }, "she holds it")
    }

    @Test fun anInvitationForAnotherServerSwitchesThereAndMakesTheAccountItInvitesTo() = world {
        operator()
        member("alice")
        // The invitation is made on another server, by its operator (with the command-line tool).
        val there = another()
        val theirOp = there.operator()
        val ada = signedInDesktop("ada", "alice@example.org", twoServers("ada", this, there))
        val invitation = assertIs<CreateOutcome.Created>(theirOp.links.create("register", 3_600_000L, emptyList()), "the invitation").link.url
        assertEquals(InviteResult.DONE, ada.links.openInvite(invitation, PayloadSource.PASTED), "the pasted invitation opens: ${proxy.tail()}")
        val opened = assertIs<OpenedInvite.OtherInstance>(ada.account().opened, "the invitation is for another server")
        assertEquals(there.origin, opened.inviteInstance.origin)
        assertEquals(origin, opened.signedInTo.origin)
        // Nothing waits to be sent, so the switch needs no second confirmation; it signs out here.
        assertEquals(ServerResult.DONE, ada.links.switchInstance(opened), "the switch: ${proxy.tail()}")
        assertEquals(AppPhase.ENTRY, ada.snapshot.phase)
        val form = ada.at<EntryScreen.CreateAccount>()
        assertEquals(there.origin, form.instance.origin, "the form is for the invitation's server")
        assertEquals(CreateAccountResult.DONE, ada.entry.createAccount(form, NewAccountInput("ada@example.net", "Ada", Steps.PASSWORD, ageConfirmed = true)),
            "the account is made there: ${there.proxy.tail()}")
        // The invitation pins the two accounts to each other inside the registration (§6.7).
        assertIs<CreatorStep.Processed>(theirOp.links.processAnswers().single(), "the inviting operator gets the answer")
    }
}
