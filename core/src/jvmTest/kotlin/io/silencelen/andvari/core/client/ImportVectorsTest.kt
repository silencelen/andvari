package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Consumes spec/test-vectors/import.json — the SAME file the web twin
 * (web/src/import/csv.test.ts) checks — so both impls parse browser CSVs identically.
 */
class ImportVectorsTest {
    private val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
    private val v: JsonObject = Json.parseToJsonElement(File(dir, "import.json").readText()).jsonObject

    private fun JsonObject.s(k: String) = getValue(k).jsonPrimitive.content
    private fun JsonObject.i(k: String) = getValue(k).jsonPrimitive.int
    private fun JsonObject.arr(k: String) = getValue(k).jsonArray.map { it.jsonObject }

    @Test
    fun files() {
        var seq = 0
        for (case in v.arr("files")) {
            val label = case.s("name")
            val parsed = CsvImport.parse(Bytes.fromB64(case.s("contentB64")))
            val expect = case.getValue("expect").jsonObject
            assertEquals(expect.s("format"), parsed.format.name.lowercase(), "$label format")

            val expRows = expect.arr("rows")
            assertEquals(expRows.size, parsed.rows.size, "$label row count")
            expRows.forEachIndexed { idx, er ->
                val r = parsed.rows[idx]
                assertEquals(er.s("name"), r.name, "$label row$idx name")
                assertEquals(er.s("url"), r.url, "$label row$idx url")
                assertEquals(er.s("username"), r.username, "$label row$idx user")
                assertEquals(er.s("password"), r.password, "$label row$idx pass")
                assertEquals(er.s("notes"), r.notes, "$label row$idx notes")
                if ("timePasswordChangedMs" in er) assertEquals(er.getValue("timePasswordChangedMs").jsonPrimitive.long, r.timePasswordChangedMs)
            }

            val expErrors = expect.arr("errors")
            assertEquals(expErrors.size, parsed.errors.size, "$label error count")
            expErrors.forEachIndexed { idx, ee ->
                assertEquals(ee.i("line"), parsed.errors[idx].line, "$label error$idx line")
                assertEquals(ee.s("code"), parsed.errors[idx].code, "$label error$idx code")
            }

            seq = 0
            val plan = CsvImport.plan(parsed) { "id-${seq++}" }
            val expDocs = expect.arr("docs")
            assertEquals(expDocs.size, plan.items.size, "$label doc count")
            expDocs.forEachIndexed { idx, ed ->
                val doc = plan.items[idx].doc
                assertEquals(ed.s("name"), doc.name, "$label doc$idx name")
                assertEquals(ed.s("username"), doc.login?.username ?: "", "$label doc$idx user")
                assertEquals(ed.s("password"), doc.login?.password ?: "", "$label doc$idx pass")
                assertEquals(ed.s("uri"), doc.login?.uris?.firstOrNull() ?: "", "$label doc$idx uri")
                assertEquals(ed.s("notes"), doc.notes ?: "", "$label doc$idx notes")
            }
            val expReport = expect.getValue("report").jsonObject
            assertEquals(expReport.i("imported"), plan.report.imported, "$label imported")
            assertEquals(expReport.i("skippedEmpty"), plan.report.skippedEmpty, "$label skippedEmpty")
            assertEquals(expReport.i("collapsed"), plan.report.collapsed, "$label collapsed")
            val expFlagged = expReport.getValue("flagged").jsonArray.map { it.jsonPrimitive.content }
            assertEquals(expFlagged, plan.report.flagged, "$label flagged")
        }
    }

    @Test
    fun rejects() {
        for (r in v.arr("reject")) {
            val reason = r.s("reason")
            val bytes = if ("contentB64" in r) {
                Bytes.fromB64(r.s("contentB64"))
            } else {
                val c = r.getValue("construct").jsonObject
                buildString {
                    append(c.s("header")).append('\n')
                    repeat(c.i("count")) { append(c.s("row")).append('\n') }
                }.encodeToByteArray()
            }
            val e = assertFailsWith<CsvImport.ImportException>(r.s("name")) { CsvImport.parse(bytes) }
            assertEquals(reason, e.code, r.s("name"))
        }
    }
}
