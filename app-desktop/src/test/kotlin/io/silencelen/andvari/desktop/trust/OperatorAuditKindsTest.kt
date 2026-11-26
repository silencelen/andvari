package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.model.wire.AdminStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The console's filter for the audit's kinds (spec 03 §7.3): the list the server serves in its status when it carries
 * one, an unknown kind shown as served and never dropped, a kind seen in a row kept beside it; without the field, the
 * kinds seen in rows, as before.
 */
class OperatorAuditKindsTest {
    private val served = listOf("operator_disable", "operator_enable", "zz_new_kind_this_app_has_no_words_for")

    @Test
    fun theServedListIsTheFiltersChoicesInItsOrderWithEveryKindSeenKept() {
        val choices = OperatorModel.auditKindChoices(served, listOf("operator_enable", "row_only_kind"))
        assertEquals(served + "row_only_kind", choices, "served first as served; a kind seen in a row but not served is kept after them")
        assertTrue("zz_new_kind_this_app_has_no_words_for" in choices, "an unknown kind is never dropped")
        assertEquals(listOf("b", "a"), OperatorModel.auditKindChoices(listOf("b", "a", "b"), emptyList()), "served order, each once")
        assertEquals(emptyList(), OperatorModel.auditKindChoices(emptyList(), emptyList()), "an empty list served is an empty list")
    }

    @Test
    fun withoutTheFieldTheKindsSeenInRowsAreTheChoicesSorted() {
        assertEquals(listOf("a", "b"), OperatorModel.auditKindChoices(null, listOf("b", "a", "b")))
        assertEquals(emptyList(), OperatorModel.auditKindChoices(null, emptyList()))
    }

    @Test
    fun theStatusFieldDecodesAsTheSharedCodeReadsItAndAMalformedOneIsNoField() {
        val json = Json { ignoreUnknownKeys = true }
        fun status(kinds: String?) = json.decodeFromString(
            AdminStatus.serializer(),
            """{"serverVersion":"1","serverTime":0,"userCount":0,"itemCount":0,"attachmentCount":0,"attachmentBytes":0,"dbBytes":0,""" +
                """"totpEnrolledCount":0,"downloadsManifest":false,"emailConfigured":false,"instanceKind":"private",""" +
                """"signup":{"mode":"closed","cap":0,"active":0,"full":false},"mail":{"stalled":false}""" +
                (if (kinds == null) "" else ""","auditKinds":$kinds""") + "}",
        )
        assertEquals(served, OperatorModel.auditKindChoices(status("""["operator_disable","operator_enable","zz_new_kind_this_app_has_no_words_for"]""").auditKinds, emptyList()))
        assertNull(status(null).auditKinds)
        assertNull(status("""[1,2]""").auditKinds, "not a list of strings: no field, so the console falls back")
        assertEquals(listOf("seen"), OperatorModel.auditKindChoices(status("\"x\"").auditKinds, listOf("seen")))
    }

    @Test
    fun theConsoleFollowsTheStatusAtEachReadAndBehavesAsBeforeWithoutIt() {
        val api = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        val op = m.operator
        op.open()
        assertNull(assertNotNull(api.operatorApi.console).status?.auditKinds, "the test double serves no list")
        assertEquals(emptyList(), op.auditTypes.value)
        val bo = assertNotNull(api.operatorApi.console).accounts.first { it.email == "bo@family.example" }.userId
        op.disable(bo, DisableWhy.ABUSE, FakeScenes.PASSWORD)
        op.loadAudit(0L, null, null)
        assertEquals(listOf("operator_disable"), op.auditTypes.value, "the kinds seen in rows, as before")
        op.refresh()
        assertEquals(listOf("operator_disable"), op.auditTypes.value, "a read again keeps them")

        val model = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/OperatorModel.kt").readText()
        val follow = model.substringAfter("private fun followAuditKinds()").substringBefore("\n    }\n")
        assertTrue(follow.contains("auditKindChoices(api.operatorApi.console?.status?.auditKinds, auditSeen)"))
        for (call in listOf("fun open(): Job?", "fun refresh(): Job?", "fun loadAudit(")) {
            assertTrue(model.substringAfter(call).substringBefore("\n    }\n").contains("followAuditKinds()"), call)
        }
    }
}
