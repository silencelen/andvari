package io.silencelen.andvari.core.client

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Consumes spec/test-vectors/import-foreign.json (guided importers, 0.8.0) — the SAME
 * file the web twin checks — pinning the three new adapters (A1-A6), detection order
 * (A3), the shared TOTP normalize (A5) and the vault-aware plan rules (F75/A7/A9).
 * import.json stays byte-frozen and is consumed by ImportVectorsTest unchanged.
 */
class ImportForeignVectorsTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "import-foreign.json").readText()).jsonObject

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.sOrNull(k: String) = this[k].let { if (it == null || it is JsonNull) null else it.jsonPrimitive.content }
    private fun JsonObject.i(k: String) = getValue(k).jsonPrimitive.int
    private fun JsonObject.b(k: String) = getValue(k).jsonPrimitive.content.toBoolean()
    private fun JsonObject.arr(k: String) = getValue(k).jsonArray.map { it.jsonObject }
    private fun JsonObject.strings(k: String) = getValue(k).jsonArray.map { it.jsonPrimitive.content }

    private fun projections(el: JsonObject?): CsvImport.ImportProjections {
        if (el == null) return CsvImport.ImportProjections()
        return CsvImport.ImportProjections(
            logins = el.arr("logins").map {
                CsvImport.LoginProjection(
                    name = it.s("name"),
                    uris = it.strings("uris"),
                    username = it.s("username"),
                    password = it.s("password"),
                    totp = it.sOrNull("totp"),
                )
            },
            notes = el.arr("notes").map { CsvImport.NoteProjection(it.s("name"), it.s("notes")) },
            names = el.strings("names"),
        )
    }

    @Test
    fun cases() {
        for (case in v.arr("cases")) {
            val label = case.s("name")
            val parsed = CsvImport.parse(case.s("csv").encodeToByteArray())
            val expect = case.getValue("expect").jsonObject
            assertEquals(expect.s("format"), parsed.format.wire, "$label format")

            val existing = case.getValue("existing").let { if (it is JsonNull) null else it.jsonObject }
            var seq = 0
            val plan = CsvImport.plan(parsed, projections(existing)) { "id-${seq++}" }

            val expItems = expect.arr("items")
            assertEquals(expItems.size, plan.items.size, "$label item count")
            expItems.forEachIndexed { idx, ei ->
                val doc = plan.items[idx].doc
                assertEquals(ei.s("type"), doc.type, "$label item$idx type")
                assertEquals(ei.s("name"), doc.name, "$label item$idx name")
                assertEquals(ei.sOrNull("notes"), doc.notes, "$label item$idx notes")
                assertEquals(ei.b("favorite"), doc.favorite, "$label item$idx favorite")
                val el = ei.getValue("login").let { if (it is JsonNull) null else it.jsonObject }
                if (el == null) {
                    assertEquals(null, doc.login, "$label item$idx login")
                } else {
                    assertEquals(el.s("username"), doc.login?.username, "$label item$idx user")
                    assertEquals(el.s("password"), doc.login?.password, "$label item$idx pass")
                    assertEquals(el.strings("uris"), doc.login?.uris, "$label item$idx uris")
                    assertEquals(el.sOrNull("totp"), doc.login?.totp, "$label item$idx totp")
                }
            }

            val er = expect.getValue("report").jsonObject
            val rep = plan.report
            assertEquals(er.i("imported"), rep.imported, "$label imported")
            assertEquals(er.i("skippedEmpty"), rep.skippedEmpty, "$label skippedEmpty")
            assertEquals(er.i("collapsed"), rep.collapsed, "$label collapsed")
            assertEquals(er.strings("flagged"), rep.flagged, "$label flagged")
            assertEquals(er.strings("alreadyInVault"), rep.alreadyInVault, "$label alreadyInVault")
            assertEquals(er.strings("passwordDiffers"), rep.passwordDiffers, "$label passwordDiffers")
            assertEquals(er.strings("totpDiffers"), rep.totpDiffers, "$label totpDiffers")
            assertEquals(er.strings("archivedSkipped"), rep.archivedSkipped, "$label archivedSkipped")
            assertEquals(er.strings("unknownTypeSkipped"), rep.unknownTypeSkipped, "$label unknownTypeSkipped")
            assertEquals(er.strings("totpUnsupported"), rep.totpUnsupported, "$label totpUnsupported")
            assertEquals(er.strings("noteItems"), rep.noteItems, "$label noteItems")
            val expErrors = er.arr("errors")
            assertEquals(expErrors.size, rep.errors.size, "$label error count")
            expErrors.forEachIndexed { idx, ee ->
                assertEquals(ee.i("line"), rep.errors[idx].line, "$label error$idx line")
                assertEquals(ee.s("code"), rep.errors[idx].code, "$label error$idx code")
            }
        }
    }

    @Test
    fun rejects() {
        for (r in v.arr("reject")) {
            val e = assertFailsWith<CsvImport.ImportException>(r.s("name")) {
                CsvImport.parse(r.s("csv").encodeToByteArray())
            }
            assertEquals(r.s("error"), e.code, r.s("name"))
        }
    }
}
