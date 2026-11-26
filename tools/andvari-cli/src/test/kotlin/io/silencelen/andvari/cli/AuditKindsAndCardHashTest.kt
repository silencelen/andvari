package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * `operator audit --type` against the kinds the server's status names (spec 03 §7.3), and the line of `card show` that the
 * offline recovery tool sends an operator to for the hash of the server's first card.
 */
class AuditKindsAndCardHashTest {
    private val newKind = "kind_this_tool_never_saw"

    @Test fun aKindTheStatusDoesNotNameIsRefusedBeforeAskingAndAnUnknownKindItNamesIsShownAsServed() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                fun audit(vararg args: String) = w.run(w.op, "operator", "audit", *args, dial = p.address)
                val statusKinds = Json.parseToJsonElement(w.run(w.op, "operator", "status", "--json").ok())
                    .jsonObject.getValue("auditKinds").jsonArray.map { it.jsonPrimitive.content }
                assertTrue(statusKinds.isNotEmpty(), "the real server names its kinds")

                // A kind the server does not write: refused, with the kinds it does write, and the audit list is never asked.
                var mark = p.seen.size
                val refused = audit("--type", "no_such_kind")
                assertEquals(2, refused.code, refused.out + refused.err)
                assertTrue(refused.err.contains(fill(AUDIT_KIND_NOT_KEPT, s.origin, "no_such_kind", "")) && refused.err.contains(statusKinds.first()), refused.err)
                assertTrue(p.seen.drop(mark).none { it.contains("/admin/audit") }, p.seen.drop(mark).toString())

                // A kind this tool has no words for, named by the status and served in the rows: asked for and shown as served.
                p.lie = mapOf(
                    WireRoute.ADMIN_STATUS to { e -> JsonObject(e.jsonObject + ("auditKinds" to JsonArray((statusKinds + newKind).map(::JsonPrimitive)))) },
                    // The real server has no rows of that kind: the page is the proxy's, two rows of it.
                    WireRoute.ADMIN_AUDIT to { _ ->
                        JsonArray((2L downTo 1L).map { id ->
                            JsonObject(mapOf("id" to JsonPrimitive(id), "at" to JsonPrimitive(1_700_000_000_000 + id), "type" to JsonPrimitive(newKind)))
                        })
                    },
                )
                mark = p.seen.size
                val shown = audit("--type", newKind)
                assertEquals(0, shown.code, shown.out + shown.err)
                assertTrue(p.seen.drop(mark).any { it.contains("/admin/audit") && it.contains("type=$newKind") }, p.seen.drop(mark).toString())
                val lines = shown.out.lines().filter { it.isNotBlank() }
                assertTrue(lines.isNotEmpty() && lines.all { it.contains("  $newKind  ") }, shown.out)
                val doc = Json.parseToJsonElement(audit("--type", newKind, "--json").ok()).jsonObject
                assertTrue(doc.getValue("rows").jsonArray.all { it.jsonObject.getValue("type").jsonPrimitive.content == newKind }, doc.toString())

                // A status that names no kinds (an older server): the type is asked for as given, as before.
                p.lie = mapOf(WireRoute.ADMIN_STATUS to { e -> JsonObject(e.jsonObject - "auditKinds") })
                mark = p.seen.size
                audit("--type", "no_such_kind")
                assertTrue(p.seen.drop(mark).any { it.contains("/admin/audit") && it.contains("type=no_such_kind") }, p.seen.drop(mark).toString())
            }
        }
    }

    @Test fun cardShowPrintsTheLineCard0HashThatTheRecoveryToolsRefusalNames() {
        TestServer().use { s ->
            val w = CliWorld(s)
            // The refusal reads: "`andvari-cli card show` (the line card0Hash)". Plain: a line `card0Hash:` and the 64 hex.
            val plain = w.run(w.op, "card", "show").ok()
            val line = plain.lines().filter { it.startsWith("card0Hash:") }
            assertEquals(1, line.size, plain)
            val hash = Regex("^card0Hash:\\s+([0-9a-f]{64})$").find(line.single())?.groupValues?.get(1)
            // The hash of the server's first card: a new device's Trust Gate takes it as --trust-card.
            assertEquals(w.card0, hash)
            w.account("someone@example.org")
            // --json: the same value under the key card0Hash.
            val doc = Json.parseToJsonElement(w.run(w.op, "card", "show", "--json").ok()).jsonObject
            assertEquals(hash, doc.getValue("card0Hash").jsonPrimitive.content)
            assertFalse(plain.contains("card0_hash"), plain)
        }
    }
}
