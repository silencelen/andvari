package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** The fake plays the engine's answerer side of a link (§6.11): "Compare codes" is offered before the reveal was fetched. */
class FakeAnswererCompareTest {
    @Test
    fun theAnswerersRowOffersTheComparisonThatFetchesTheReveal() {
        val app = FakeScenes.at(FakeScene.CONTACTS)
        val cy = app.session!!.account.contacts.single { it.label == "Cy" }
        cy.codesReady = false
        cy.revealWaiting = true
        app.publish()
        val row = app.snapshot.account!!.contacts!!.contacts.single { it.label == "Cy" }
        assertTrue(!row.codesReady && row.canCompare, "offered before the reveal was fetched")

        assertEquals(PlainResult.DONE, await { app.contacts.openCompare(row) })
        assertIs<CompareScreen.Waiting>(app.snapshot.account!!.comparing, "not posted yet: no code")
        app.contacts.closeCompare()

        cy.revealPosted = true
        val again = app.snapshot.account!!.contacts!!.contacts.single { it.label == "Cy" }
        assertEquals(PlainResult.DONE, await { app.contacts.openCompare(again) })
        assertEquals("271828", assertIs<CompareScreen.Ready>(app.snapshot.account!!.comparing).code)
        assertTrue(app.snapshot.account!!.contacts!!.contacts.single { it.label == "Cy" }.codesReady)
    }
}
