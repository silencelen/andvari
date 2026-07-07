package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Hand-written spec-06 intent tests — independent of the vector file (so the reference
 * impl is not self-certifying). Runs under :core:jvmTest (commonTest folds into jvm).
 */
class CsvImportTest {
    private var seq = 0
    private fun plan(csv: String): CsvImport.ImportPlan {
        seq = 0
        return CsvImport.plan(CsvImport.parse(csv.encodeToByteArray())) { "id-${seq++}" }
    }

    @Test fun chromeBasic_mapsFields() {
        val p = plan("name,url,username,password,note\nGH,https://gh.test,jacob,pw,hi\n")
        assertEquals(1, p.items.size)
        val d = p.items[0].doc
        assertEquals("GH", d.name); assertEquals("jacob", d.login?.username)
        assertEquals("pw", d.login?.password); assertEquals(listOf("https://gh.test"), d.login?.uris)
        assertEquals("hi", d.notes)
    }

    // andvari CSV round-trip column (spec 06 §1 / 07 §1): still detects as Chrome, maps totp;
    // an empty cell and a browser file without the column both yield totp = null.
    @Test fun totpColumn_mapsWhenPresent() {
        val p = plan("name,url,username,password,note,totp\nGH,https://gh.test,jacob,pw,,otpauth://totp/x?secret=AAAA\nNT,https://n.test,ana,pw2,,\n")
        assertEquals("otpauth://totp/x?secret=AAAA", p.items[0].doc.login?.totp)
        assertEquals(null, p.items[1].doc.login?.totp)
        assertEquals(null, plan("name,url,username,password,note\nGH,https://gh.test,jacob,pw,hi\n").items[0].doc.login?.totp)
    }

    // Two rows identical but for the TOTP seed must both survive dedup — else an
    // andvari→andvari round trip silently loses a 2FA seed (review finding).
    @Test fun totpDifferentiatesExactDupes() {
        val p = plan("name,url,username,password,note,totp\nA,https://a.test,u,p,,otpauth://x\nA,https://a.test,u,p,,\n")
        assertEquals(2, p.items.size)
        assertEquals(setOf("otpauth://x", null), p.items.map { it.doc.login?.totp }.toSet())
        // A truly exact repeat (same totp) still collapses to one.
        assertEquals(1, plan("name,url,username,password,note,totp\nA,https://a.test,u,p,,t\nA,https://a.test,u,p,,t\n").items.size)
    }

    @Test fun quoting_commaNewlineEscapedQuote() {
        val parsed = CsvImport.parse("name,url,username,password,note\n\"a,b\",https://x.test,\"u\"\"v\",p,\"l1\nl2\"\n".encodeToByteArray())
        val r = parsed.rows.single()
        assertEquals("a,b", r.name); assertEquals("u\"v", r.username); assertEquals("l1\nl2", r.notes)
    }

    @Test fun crlfAndLfMix_bothTerminate() {
        assertEquals(2, CsvImport.parse("name,url,username,password,note\r\na,u1://x,x,p,\nb,u2://y,y,q,\r\n".encodeToByteArray()).rows.size)
    }

    @Test fun loneCr_isARecordTerminator() {
        assertEquals(2, CsvImport.parse("name,url,username,password,note\ra,https://x,x,p,\rb,https://y,y,q,\r".encodeToByteArray()).rows.size)
    }

    @Test fun bom_stripped() {
        val p = plan("﻿name,url,username,password,note\nA,https://a,u,p,\n")
        assertEquals(1, p.items.size); assertEquals("A", p.items[0].doc.name)
    }

    @Test fun oldFourColumnChrome_noNote() {
        val p = plan("name,url,username,password\nA,https://a,u,p\n")
        assertEquals("A", p.items[0].doc.name); assertEquals(null, p.items[0].doc.notes)
    }

    @Test fun headerOnly_yieldsNothing() {
        assertEquals(0, plan("name,url,username,password,note\n").items.size)
    }

    @Test fun firefox_nameFromHost_httpRealmNote_guidNotItemId() {
        val fx = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n" +
            "https://mail.example/login,fox,pw,\"Realm X\",,{guid-123},0,0,1700000000000\n"
        val parsed = CsvImport.parse(fx.encodeToByteArray())
        assertEquals(CsvImport.ImportFormat.FIREFOX, parsed.format)
        val p = CsvImport.plan(parsed) { "id-x" }
        val d = p.items.single().doc
        assertEquals("mail.example", d.name)
        assertTrue(d.notes!!.contains("HTTP realm: Realm X"))
        assertTrue(p.items.none { it.itemId.contains("guid") }, "guid is never the itemId")
    }

    @Test fun hostFallback_portUserinfoIpv6BareGarbage() {
        assertEquals("host.example", CsvImport.nameFallback("https://user:pw@Host.Example:8443/p?q"))
        assertEquals("2001:db8::1", CsvImport.nameFallback("https://[2001:db8::1]:443/"))
        assertEquals("bare.host", CsvImport.nameFallback("ftp://bare.host"))
        assertEquals("plain-no-scheme", CsvImport.nameFallback("plain-no-scheme"))
        assertEquals("Imported login", CsvImport.nameFallback("   "))
    }

    @Test fun skipEmpty_whenUserAndPassBothEmpty() {
        val p = plan("name,url,username,password,note\nkeep,https://a,u,p,\njunk,https://b,,,\n")
        assertEquals(1, p.items.size); assertEquals(1, p.report.skippedEmpty)
    }

    @Test fun dedupe_collapseExact_renameDistinctPasswords() {
        val p = plan(
            "name,url,username,password,note\n" +
                "M,https://m,me,pw1,\nM,https://m,me,pw1,\nM,https://m,me,pw2,\nM,https://m,me,pw3,\n",
        )
        assertEquals(listOf("M", "M (2)", "M (3)"), p.items.map { it.doc.name })
        assertEquals(1, p.report.collapsed)
        assertEquals(listOf("M (2)", "M (3)"), p.report.flagged)
    }

    @Test fun rowErrors_wrongFieldCount_lineNumbers_goodRowsSurvive() {
        val parsed = CsvImport.parse("name,url,username,password,note\nok,https://ok,u,p,n\ntoofew,https://few,u\nok2,https://ok2,u2,p2,n2\n".encodeToByteArray())
        assertEquals(2, parsed.rows.size) // ok + ok2
        assertEquals(listOf(CsvImport.RowError(3, "wrong_field_count")), parsed.errors)
    }

    @Test fun badQuote_unterminated_atOpeningLine() {
        // The row opening at line 3 never closes its quote → bad_quote at line 3.
        val parsed = CsvImport.parse("name,url,username,password,note\nok,https://ok,u,p,n\nbad,\"open,u,p,n\n".encodeToByteArray())
        assertEquals(1, parsed.rows.size)
        assertEquals(listOf(CsvImport.RowError(3, "bad_quote")), parsed.errors)
    }

    @Test fun limits_tooManyRows_tooLarge() {
        val header = "name,url,username,password,note\n"
        val rows = (0 until CsvImport.MAX_ROWS + 1).joinToString("") { "n$it,https://x,u,p,\n" }
        assertEquals("too_many_rows", assertFailsWith<CsvImport.ImportException> { CsvImport.parse((header + rows).encodeToByteArray()) }.code)
        assertEquals("too_large", assertFailsWith<CsvImport.ImportException> { CsvImport.parse(ByteArray(CsvImport.MAX_BYTES + 1)) }.code)
    }

    @Test fun unrecognizedHeader_rejected() {
        assertEquals("unrecognized_header", assertFailsWith<CsvImport.ImportException> { CsvImport.parse("foo,bar\n1,2\n".encodeToByteArray()) }.code)
    }
}
