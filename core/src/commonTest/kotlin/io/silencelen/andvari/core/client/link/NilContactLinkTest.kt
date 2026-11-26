package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A user id of all zeros is never an account, so it is never pinned as a contact. A server can register an account under
 * that id; its links and its answers are then signed properly by that account's own key, and only the id is wrong. Before,
 * such a link opened to the confirmation and its creator was pinned, and such an answer was pinned by the link's creator.
 */
class NilContactLinkTest {
    private val crypto = createCryptoProvider()
    private val nilId = "00000000-0000-0000-0000-000000000000"
    private val alice = "11111111-1111-4111-8111-111111111111"
    private val bob = "22222222-2222-4222-8222-222222222222"
    private val hour = 3_600_000L

    @Test fun aLinkWhoseCreatorHasTheNilUserIdIsABadLinkAndPinsNothing() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val nil = LinkPerson(crypto, server, 3, nilId, "Nil").start()
        val b = LinkPerson(crypto, server, 2, bob, "Bob").start()
        val link = assertIs<CreateOutcome.Created>(nil.flows.create("connect", hour, emptyList())).link
        assertEquals(RecipientStep.Stopped(LinkStop.BAD_LINK), b.flows.open(link.url, GateEntry.SCAN_INVITE))
        assertTrue(b.store.doc.contacts.isEmpty(), "nothing pinned")
        assertNull(b.flows.code(nilId))
        // No answer was sent: the creator has nothing to process.
        assertTrue(nil.flows.processAnswers().isEmpty())
    }

    @Test fun anAnswerSignedByTheNilUserIdIsIgnoredAndNothingIsPinned() = runBlocking<Unit> {
        val server = LinkServer(crypto)
        val a = LinkPerson(crypto, server, 1, alice, "Alice").start()
        val nil = LinkPerson(crypto, server, 3, nilId, "Nil").start()
        val link = assertIs<CreateOutcome.Created>(a.flows.create("connect", hour, emptyList())).link
        val confirm = assertIs<RecipientStep.Confirm>(nil.flows.open(link.url, GateEntry.SCAN_INVITE))
        assertIs<RecipientStep.Answered>(nil.flows.confirm(confirm))
        assertEquals(listOf<CreatorStep>(CreatorStep.Ignored(link.linkId, WireLinkFlows.NIL_ANSWERER)), a.flows.processAnswers())
        assertTrue(a.store.doc.contacts.isEmpty(), "nothing pinned")
        assertNull(a.flows.code(nilId))
        assertTrue(a.releases.isEmpty())
        assertTrue(a.flows.createdLinks().isEmpty(), "the link's record is dropped")
        // The answer was acknowledged: it is not served again.
        assertTrue(a.flows.processAnswers().isEmpty())
    }
}
