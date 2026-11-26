package io.silencelen.andvari.core.model.wire

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * What the server added to its answers on 2026-11-16, as the shared code reads it: the account state's counter on every
 * sync answer (spec 03 §4, `accountStateSeq`) and the audit's kinds on the operator's status (spec 03 §7.3,
 * `auditKinds`). Both are additive: absent is "not served" (an older server), and a value that cannot be one is read as
 * absent, never as a failure of the answer that carries it.
 */
class ServedAdditionsTest {
    private val sync = """{"rev":7,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[],"removedGrantsInfo":[],"linkAnswers":0,"recoveryRequests":0"""

    private fun syncWith(field: String?): SyncResponse =
        WireJson.json.decodeFromString(SyncResponse.serializer(), sync + (field?.let { ",\"accountStateSeq\":$it" } ?: "") + "}")

    @Test fun theAccountStatesCounterIsReadFromEverySyncAnswerAndAnythingButAWholeNumberIsNotServed() {
        assertEquals(0L, syncWith("0").accountStateSeq)
        assertEquals(41L, syncWith("41").accountStateSeq)
        assertEquals(Long.MAX_VALUE, syncWith(Long.MAX_VALUE.toString()).accountStateSeq)
        assertNull(syncWith(null).accountStateSeq, "an older server")
        for (bad in listOf("\"41\"", "-1", "1.5", "4.1e1", "null", "true", "{}", "[1]", "99999999999999999999")) {
            val r = syncWith(bad)
            assertNull(r.accountStateSeq, bad)
            assertEquals(7L, r.rev, "the rest of the answer is read: $bad")
        }
    }

    private val honest = AdminStatus("1.0.0", 1, 2, 3, 4, 5, 6, 7, true, true, InstanceKind.PRIVATE, AdminSignupStatus(SignupMode.OPEN, 200, 3, false), AdminMailStatus(false))

    private fun statusWith(kinds: String?): AdminStatus {
        val base = WireJson.json.encodeToJsonElement(AdminStatus.serializer(), honest).jsonObject.filterKeys { it != "auditKinds" }
        val obj: Map<String, JsonElement> = if (kinds == null) base else base + ("auditKinds" to Json.parseToJsonElement(kinds))
        return WireJson.json.decodeFromString(AdminStatus.serializer(), JsonObject(obj).toString())
    }

    @Test fun theAuditsKindsAreReadFromTheOperatorsStatusAndAnythingButAListOfStringsIsNotServed() {
        assertEquals(listOf("login", "login_fail", "recovery_request_commit_mismatch"), statusWith("""["login","login_fail","recovery_request_commit_mismatch"]""").auditKinds)
        assertEquals(emptyList(), statusWith("[]").auditKinds)
        assertNull(statusWith(null).auditKinds, "an older server")
        for (bad in listOf("""["login",1]""", """[null]""", """[["login"]]""", "\"login\"", "{}", "3", "null")) {
            val s = statusWith(bad)
            assertNull(s.auditKinds, bad)
            assertEquals(2L, s.userCount, "the rest of the status is read: $bad")
        }
        // A kind the console has no words for is kept as served.
        assertEquals(listOf("a_kind_from_a_newer_server"), statusWith("""["a_kind_from_a_newer_server"]""").auditKinds)
    }
}
