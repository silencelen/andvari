package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The audit's kinds, served (spec 03 §7.3): `GET /admin/status` carries `auditKinds`, every kind of audit row the server
 * can write, and this test reads the server's own source to prove the list is exactly that: no kind written is missing,
 * and none is listed that nothing writes.
 *
 * What the source scan counts as a write: every call of the audit's writers (`audit.on`, `audit.denied`,
 * `audit.pseudonymOn`) with a literal kind, or with `if (…) "a" else "b"`; and the kinds handed to the three helpers
 * that pass a kind on to a writer (`reauth`'s `auditType` and its default, `passwordGate`'s `failAudit`, and
 * `OperatorRules.target`'s `deniedType`). A writer called with any other expression fails the test, so a new way of
 * passing a kind cannot slip past it unseen.
 */
class AuditKindsTest {
    private fun sources(): List<File> {
        val dir = listOf(File("src/main/kotlin"), File("server/src/main/kotlin")).first { it.isDirectory }
        return dir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList().also { assertTrue(it.size > 20) }
    }

    private val kind = "\"([a-z][a-z0-9_]*)\""

    /** Every kind the server's source can write, and every writer call whose kind the scan cannot read. */
    private fun written(): Pair<Set<String>, List<String>> {
        val kinds = sortedSetOf<String>()
        val unread = ArrayList<String>()
        // The variables the three helpers below pass on, and Audit's own parameter.
        val forwarded = setOf("auditType", "failAudit", "it", "type")
        val writer = Regex("""audit\.(on|denied|pseudonymOn)\(\s*\w+\s*,\s*([^,]+),""")
        for (f in sources()) {
            val text = f.readText()
            for (m in writer.findAll(text)) {
                val arg = m.groupValues[2].trim()
                val literal = Regex("^$kind$").find(arg)
                val ifElse = Regex("""^if \([^"]*\) $kind else $kind$""").find(arg)
                when {
                    literal != null -> kinds += literal.groupValues[1]
                    ifElse != null -> { kinds += ifElse.groupValues[1]; kinds += ifElse.groupValues[2] }
                    arg in forwarded -> {}
                    else -> unread += "${f.name}: $arg"
                }
            }
            // reauth(…, "kind") and its default.
            Regex("""\breauth\([^()\n]*(?:\([^()\n]*\)[^()\n]*)*,\s*$kind""").findAll(text).forEach { kinds += it.groupValues[1] }
            Regex("""auditType: String = $kind""").findAll(text).forEach { kinds += it.groupValues[1] }
            // passwordGate(s, email, authKey, totp, ip, "kind").
            Regex("""\bpasswordGate\([^\n]*,\s*$kind\)""").findAll(text).forEach { kinds += it.groupValues[1] }
            // OperatorRules.target(s, c, id, op, ip, "kind" | null, …).
            Regex("""\btarget\(s, c, [^\n]*?, ip, $kind""").findAll(text).forEach { kinds += it.groupValues[1] }
            // The audit table is written by Audit alone.
            if (f.name != "Audit.kt") assertTrue("INSERT INTO audit" !in text, "${f.name} writes the audit table itself")
        }
        return kinds to unread
    }

    @Test
    fun theServedList_isExactlyEveryKindTheServerWrites() {
        val (kinds, unread) = written()
        if (unread.isNotEmpty()) fail("audit writes whose kind the scan cannot read (teach the scan, then list the kinds): $unread")
        assertTrue(kinds.size > 60, "the scan found the writes: $kinds")
        val listed = AuditKinds.ALL
        assertEquals(listed.sorted(), listed, "sorted")
        assertEquals(listed.toSet().size, listed.size, "no kind twice")
        assertEquals(emptySet(), kinds - listed.toSet(), "written but not served")
        assertEquals(emptySet(), listed.toSet() - kinds, "served but written by nothing")
        // Every kind an account deletion keeps or scopes to a vault is one the server writes.
        assertEquals(emptySet(), AccountDeletion.RETAINED_AUDIT_TYPES + AccountDeletion.VAULT_SCOPED_AUDIT_TYPES - listed.toSet())
    }

    /** The scan itself: each form it reads, and a writer it cannot read. */
    @Test
    fun theScan_readsEachFormOfWrite() {
        assertTrue("reauth_fail" in written().first, "reauth's default")
        assertTrue("totp_setup_reauth_fail" in written().first, "a kind handed to reauth")
        assertTrue("device_link_pickup_denied" in written().first, "a kind handed to passwordGate")
        assertTrue("operator_delete_denied" in written().first, "a kind handed to target")
        assertTrue("recovery_self_confirm_unbound" in written().first && "totp_enroll" in written().first, "if … else")
        assertTrue("email_sent" in written().first, "a writer outside the routes")
    }

    @Test
    fun theStatus_servesTheKinds_toTheOperatorOnly() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        val op = Flow.finishSetup(c, s)
        val me = Flow.member(c, s, "me@example.com")
        val r = c.call(HttpMethod.Get, "/api/v1/admin/status", token = op.token)
        assertEquals(200, r.status.value, r.bodyAsText())
        val served = WireJson.json.parseToJsonElement(r.bodyAsText()).jsonObject["auditKinds"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertEquals(AuditKinds.ALL, served)
        // Additive: the answer still decodes as the status it was.
        assertEquals(2L, WireJson.json.decodeFromString(AdminStatus.serializer(), r.bodyAsText()).userCount)
        assertEquals("not_operator", c.call(HttpMethod.Get, "/api/v1/admin/status", token = me.token).errorCode())
        assertEquals(401, c.call(HttpMethod.Get, "/api/v1/admin/status").status.value)
    }
}
