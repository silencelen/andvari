package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CompareScreen
import io.silencelen.andvari.core.app.ComparisonResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.LinkCreateResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.LinkPerson
import io.silencelen.andvari.core.client.link.LinkServer
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * §6.8 step 6 from the creator's side: a contact answers a link this device made under another key than the pinned one.
 * The old key stays pinned and nothing is shared; [AccountPrompt.KeyChanged] stays until this device's own matched
 * comparison accepts the new key, across a lock too; a wrong code changes nothing. Before, the engine raised no prompt
 * at all: the change showed only on the links screen while it was open, and was gone at the next opening.
 */
class EngineKeyChangeCreatorTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "11111111-1111-4111-8111-111111111111"

    private class World(val server: LinkServer, val alice: LinkPerson, val app: EngineAppApi)

    private suspend fun world(): World {
        val server = LinkServer(crypto)
        val a = LinkPerson(crypto, server, 1, alice, "Alice").start()
        var self: EngineAppApi? = null
        val asApp = object : WireClient {
            override val origin: String = server.instance.origin
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T) =
                server.client(self?.keeper?.session?.userId).call(route, pathParams, query, bodyJson, authenticated, decode)
        }
        val app = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.instance.origin to asApp)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            self = it
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        return World(server, a, app)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** Bob signs up through Alice's connect link: Alice is his contact, under her first key. */
    private suspend fun World.bobThroughAlicesLink() {
        val a = app
        a.entry.openInviteEntry(a.at())
        val url = assertIs<CreateOutcome.Created>(alice.flows.create("connect", 60 * 60 * 1000L, emptyList())).link.url
        assertEquals(InviteResult.DONE, a.entry.submitInvite(a.at(), url, PayloadSource.SCANNED))
        assertEquals(ServerResult.DONE, a.entry.joinFromInvite(a.at()))
        assertEquals(io.silencelen.andvari.core.app.SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "bob@example.com", true))
        assertEquals(io.silencelen.andvari.core.app.CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Bob", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        alice.flows.processAnswers()
        // The server serves Bob's key with the links he makes.
        val bob = a.keeper.established!!
        server.keys[bob.userId] = Bytes.toB64(bob.account.identity.publicKey)
    }

    /** Bob makes a connect link; "Alice", under a new key, answers it. Her flow, for the code she will read out. */
    private suspend fun World.aliceAnswersUnderANewKey(): Pair<LinkPerson, RecipientStep.Answered> {
        // Later than the first link's records (the link engine reads a contact's latest one).
        server.instance.now += 60_000L
        assertEquals(LinkCreateResult.DONE, app.links.createConnectLink(emptyList(), 60))
        val url = assertNotNull(app.links.linkToShare(app.snapshot.account!!.links!!.links.single()))
        val newAlice = LinkPerson(crypto, server, 9, alice.userId, "Alice").start()
        val step = assertIs<RecipientStep.Confirm>(newAlice.flows.open(url, GateEntry.SCAN_INVITE))
        val answered = assertIs<RecipientStep.Answered>(newAlice.flows.confirm(step))
        app.linksFlow.processAnswers()
        return newAlice to answered
    }

    private fun EngineAppApi.pinnedKeyOf(userId: String): String = vault!!.store.local().contacts.getValue(userId).identityPub

    @Test fun anAnswerUnderAnotherKeyRaisesThePromptUntilAMatchedComparisonAcceptsTheKey() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        w.bobThroughAlicesLink()
        val oldKey = a.pinnedKeyOf(alice)
        assertTrue(a.snapshot.account!!.prompts.none { it is AccountPrompt.KeyChanged })

        val (newAlice, answered) = w.aliceAnswersUnderANewKey()
        val prompt = assertIs<AccountPrompt.KeyChanged>(a.snapshot.account!!.prompts.single { it is AccountPrompt.KeyChanged })
        assertEquals(alice, prompt.userId)
        assertEquals("Alice", prompt.label)
        assertEquals(CopyKey.CONTACT_KEY_CHANGED, prompt.line.key)
        assertTrue(a.snapshot.account!!.links!!.answered.single().keyChanged)
        assertEquals(oldKey, a.pinnedKeyOf(alice), "nothing is replaced by the answer itself")
        a.links.closeLinks()
        a.publish()
        assertSame(prompt, a.snapshot.account!!.prompts.single { it is AccountPrompt.KeyChanged }, "the same prompt while it waits")

        // Kept across a lock: the next opening reads it again from the link engine's record.
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val again = assertIs<AccountPrompt.KeyChanged>(a.snapshot.account!!.prompts.single { it is AccountPrompt.KeyChanged })
        assertEquals(alice, again.userId)

        // The comparison: a wrong code changes nothing; her code accepts the new key, and the prompt goes.
        assertEquals(PlainResult.DONE, a.contacts.openCompareForNewKey(again))
        val ready = assertIs<CompareScreen.Ready>(a.snapshot.account!!.comparing)
        assertTrue(ready.replacesKey)
        newAlice.flows.awaitReveal(answered)
        val theirs = assertNotNull(newAlice.flows.code(a.keeper.session!!.userId), "the code her screen shows")
        val wrong = (theirs.toInt() + 1).mod(1_000_000).toString().padStart(6, '0')
        assertEquals(ComparisonResult.MISMATCH, a.contacts.submitComparison(ready, wrong))
        assertEquals(oldKey, a.pinnedKeyOf(alice), "a wrong code replaces nothing")
        assertTrue(a.snapshot.account!!.prompts.any { it is AccountPrompt.KeyChanged }, "the prompt stays")
        assertEquals(ComparisonResult.DONE, a.contacts.submitComparison(assertIs(a.snapshot.account!!.comparing), theirs))
        assertNotEquals(oldKey, a.pinnedKeyOf(alice), "the matched comparison accepted the new key")
        assertTrue(a.snapshot.account!!.prompts.none { it is AccountPrompt.KeyChanged }, "the prompt is gone")
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertTrue(a.snapshot.account!!.prompts.none { it is AccountPrompt.KeyChanged }, "and does not come back")
    }

    /** The fake's switch: a contact answers a link under a new key, the prompt shows, and a matched comparison ends it. */
    @Test fun theFakesKeyChangeFromTheCreatorsSideIsInStep() = runBlocking<Unit> {
        val app = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        val contact = assertNotNull(app.script.unnamedDeviceAddsContact("Dana"))
        assertEquals(LinkCreateResult.DONE, app.links.createConnectLink(emptyList(), 60))
        val link = app.snapshot.account!!.links!!.links.single()
        assertTrue(app.script.contactAnswersUnderNewKey(link, contact))
        val prompt = assertIs<AccountPrompt.KeyChanged>(app.snapshot.account!!.prompts.single { it is AccountPrompt.KeyChanged })
        assertEquals("Dana", prompt.label)
        assertTrue(app.snapshot.account!!.links!!.answered.single().keyChanged)
    }
}
