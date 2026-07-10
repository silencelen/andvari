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

    // ==== guided importers (0.8.0): adapters + detection (spec 06 §6-§9) ====

    private fun plan(csv: String, existing: CsvImport.ImportProjections): CsvImport.ImportPlan {
        seq = 0
        return CsvImport.plan(CsvImport.parse(csv.encodeToByteArray()), existing) { "id-${seq++}" }
    }

    private val BW_HEADER = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"

    // A3 detection is specificity-ordered: LastPass's header is a Chrome superset and MUST
    // NOT read as chrome; andvari's own export (a Chrome superset) MUST stay chrome.
    @Test fun detection_specificityOrder() {
        fun fmt(csv: String) = CsvImport.parse(csv.encodeToByteArray()).format
        assertEquals(CsvImport.ImportFormat.LASTPASS, fmt("url,username,password,totp,extra,name,grouping,fav\nhttps://a,u,p,,,A,,0\n"))
        assertEquals(CsvImport.ImportFormat.LASTPASS, fmt("url,username,password,extra,name,grouping,fav\nhttps://a,u,p,,A,,0\n")) // pre-2023 7-col
        assertEquals(CsvImport.ImportFormat.CHROME, fmt("name,url,username,password,note,totp\nA,https://a,u,p,,\n")) // andvari export
        assertEquals(CsvImport.ImportFormat.BITWARDEN, fmt("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,login,A,,,0,https://a,u,p,\n")) // org export
        assertEquals(CsvImport.ImportFormat.ONE_PASSWORD, fmt("Title,URL,Username,Password,Notes,OTPAuth\nA,https://a,u,p,,\n")) // Apple/Safari free win
        assertEquals("unrecognized_header", assertFailsWith<CsvImport.ImportException> { fmt("title,url,username,password\nA,https://a,u,p\n") }.code) // 1Password pre-8
    }

    @Test fun bitwarden_loginNoteFieldsMultiUriUnknownType() {
        val p = plan(
            BW_HEADER +
                ",1,login,GH,base,\"k: v\",0,\"https://a.example,https://b.example\",u,pw,\n" +
                ",0,note,Wifi,body,\"SSID: nest\",0,,,,\n" +
                ",,card,Visa,,,0,,,,\n",
        )
        val login = p.items[0].doc
        assertEquals(listOf("https://a.example", "https://b.example"), login.login?.uris) // A4 split
        assertEquals("base\n— custom fields —\nk: v", login.notes)
        assertTrue(login.favorite)
        val note = p.items[1].doc
        assertEquals("note", note.type)
        assertEquals("body\n— custom fields —\nSSID: nest", note.notes) // A2: notes rows too
        assertTrue(!note.favorite) // "0" is falsy (A6)
        assertEquals(listOf("Visa"), p.report.unknownTypeSkipped)
        assertEquals(listOf("Wifi"), p.report.noteItems)
    }

    @Test fun lastpass_snNote_favFalsy_emptyNameFallback() {
        val p = plan(
            "url,username,password,totp,extra,name,grouping,fav\n" +
                "http://sn,,,,note body,Codes,g,0\n" +
                "https://mail.example/x,u,pw,,,,g,1\n",
        )
        assertEquals("note", p.items[0].doc.type)
        assertEquals("note body", p.items[0].doc.notes)
        assertEquals("mail.example", p.items[1].doc.name)
        assertTrue(p.items[1].doc.favorite)
    }

    @Test fun onePassword_archivedSkipped_favoriteTruthy() {
        val p = plan(
            "title,url,username,password,otpauth,favorite,archived,tags,notes\n" +
                "Live,https://l.example,u,pw,,true,,t,\n" +
                "Shelved,https://s.example,u,pw,,,TRUE,,\n",
        )
        assertEquals(1, p.items.size)
        assertTrue(p.items[0].doc.favorite)
        assertEquals(listOf("Shelved"), p.report.archivedSkipped)
    }

    // A5: adapters never store a totp the parser rejects — kept as a notes line + bucket;
    // bare base32 wraps (original case preserved) via the ONE shared Totp.normalize.
    @Test fun adapterTotp_rejectDontCorrupt_bareWraps() {
        val p = plan(
            "url,username,password,totp,extra,name,grouping,fav\n" +
                "https://a.example,u,p,steam://XYZ,,Steam,,0\n" +
                // Empty-secret otpauth (review [1]): this build once ACCEPTED it (empty HMAC
                // key → crash at render) where the web twin rejected it — now both bucket it.
                "https://e.example,u,p,otpauth://totp/e?secret=,,Empty,,0\n" +
                "https://b.example,u,p,jbswy3dpehpk3pxp,,Bare,,0\n",
        )
        assertEquals(null, p.items[0].doc.login?.totp)
        assertEquals("Unsupported TOTP (kept as text): steam://XYZ", p.items[0].doc.notes)
        assertEquals(null, p.items[1].doc.login?.totp)
        assertEquals(listOf("Steam", "Empty"), p.report.totpUnsupported)
        assertEquals("otpauth://totp/andvari?secret=jbswy3dpehpk3pxp", p.items[2].doc.login?.totp)
    }

    // ==== vault-aware plan (F75) — A7 keying edges ====

    private fun login(name: String, uris: List<String>, user: String, pass: String, totp: String? = null) =
        CsvImport.LoginProjection(name, uris, user, pass, totp)

    private fun existing(
        logins: List<CsvImport.LoginProjection> = emptyList(),
        notes: List<CsvImport.NoteProjection> = emptyList(),
        names: List<String> = logins.map { it.name } + notes.map { it.name },
    ) = CsvImport.ImportProjections(logins, notes, names)

    @Test fun vaultRule1_uriNormalizerEquivalence_everySavedUri() {
        val ex = existing(
            logins = listOf(
                login("GH", listOf("https://www.github.com/"), "u", "p"),
                login("Multi", listOf("https://a.example", "https://b.example/x"), "u", "p"),
            ),
        )
        val p = plan(
            "name,url,username,password,note\n" +
                "GH,GITHUB.COM,u,p,\n" + // bare host, caps, www/slash variants — one class (spec 02 §3.1)
                "Multi,https://b.example/deep,u,p,\n", // matches the SECOND saved uri
            ex,
        )
        assertEquals(0, p.items.size)
        assertEquals(listOf("GH", "Multi"), p.report.alreadyInVault)
    }

    @Test fun vaultRule1_totpByParsedParams_neverRawString() {
        val ex = existing(logins = listOf(login("T", listOf("https://t.example"), "u", "p", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP")))
        // Bare base32 in the file == stored otpauth URI by PARSED params (secret bytes).
        val p = plan("name,url,username,password,note,totp\nT,https://t.example,u,p,,JBSWY3DPEHPK3PXP\n", ex)
        assertEquals(listOf("T"), p.report.alreadyInVault)
    }

    @Test fun vaultRule2_totpDiffers_vs_passwordDiffers_bothGoesToPassword() {
        val ex = existing(logins = listOf(login("T", listOf("https://t.example"), "u", "p", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP")))
        val p = plan(
            "name,url,username,password,note,totp\n" +
                "T,https://t.example,u,p,,otpauth://totp/X?secret=MFRGGZDFMZTWQ2LK\n" + // totp only
                "T,https://t.example,u,OTHER,,otpauth://totp/X?secret=MFRGGZDFMZTWQ2LK\n", // both → password bucket
            ex,
        )
        assertEquals(listOf("T (2)"), p.report.totpDiffers)
        assertEquals(listOf("T (3)"), p.report.passwordDiffers)
        assertEquals(emptyList(), p.report.flagged)
    }

    // A source with NO totp column is a totp WILDCARD in rules 1-2.
    @Test fun vaultRules_totpWildcard_whenNoTotpColumn() {
        val ex = existing(logins = listOf(login("W", listOf("https://w.example"), "u", "p", "otpauth://totp/X?secret=JBSWY3DPEHPK3PXP")))
        val p = plan("name,url,username,password,note\nW,https://w.example,u,p,\n", ex)
        assertEquals(listOf("W"), p.report.alreadyInVault)
        assertEquals(0, p.items.size)
    }

    // Empty-discriminator guard: url+username both empty → rule 1 keys on (name, password),
    // rule 2 never fires (the second row imports UNRENAMED).
    @Test fun vaultRules_emptyDiscriminatorGuard() {
        val ex = existing(logins = listOf(login("Codes", emptyList(), "", "12345")))
        val p = plan(
            "name,url,username,password,note\n" +
                "Codes,,,12345,\n" +
                "Codes,,,99999,\n",
            ex,
        )
        assertEquals(listOf("Codes"), p.report.alreadyInVault)
        assertEquals(listOf("Codes"), p.items.map { it.doc.name })
        assertEquals(emptyList(), p.report.passwordDiffers)
    }

    // uris [] and [""] are the same (A7): an existing item with [""] matches an empty-url row
    // through the sentinel class when the username is non-empty.
    @Test fun vaultRule1_emptyUriListEqualsBlankUri() {
        val ex = existing(logins = listOf(login("R", listOf(""), "admin", "pw")))
        val p = plan("name,url,username,password,note\nR,,admin,pw,\n", ex)
        assertEquals(listOf("R"), p.report.alreadyInVault)
    }

    // A9: the "(k)" rename bumps until the name is free in the vault AND this plan.
    @Test fun rename_untilFree_acrossVaultAndPlannedNames() {
        val ex = existing(
            logins = listOf(login("Site", listOf("https://s.example"), "u", "p1")),
            names = listOf("Site", "Site (2)"), // "(2)" taken by an unrelated item
        )
        val p = plan(
            "name,url,username,password,note\n" +
                "Site,https://s.example,u,p2,\n" + // seed 1 → k=2 taken → "Site (3)"
                "Dup (2),https://d2.example,x,pw,\n" +
                "Dup,https://d.example,y,pw1,\n" +
                "Dup,https://d.example,y,pw2,\n", // k=2 planned-taken → "Dup (3)"
            ex,
        )
        assertEquals(listOf("Site (3)", "Dup (2)", "Dup", "Dup (3)"), p.items.map { it.doc.name })
        assertEquals(listOf("Site (3)"), p.report.passwordDiffers)
        assertEquals(listOf("Dup (3)"), p.report.flagged)
    }

    // Vault-side note bodies are CRLF/lone-CR→LF normalized before note rule 1 (A7); a
    // same-name different-body note imports UNRENAMED (notes have no vault rule 2).
    @Test fun noteRules_vaultCrlfNormalized_kindScoped() {
        val ex = existing(notes = listOf(CsvImport.NoteProjection("Wifi", "l1\r\nl2"), CsvImport.NoteProjection("R", "a\rb")))
        val p = plan(
            BW_HEADER +
                ",,note,Wifi,\"l1\nl2\",,0,,,,\n" +
                ",,note,R,\"a\nb\",,0,,,,\n" +
                ",,note,Wifi,other,,0,,,,\n",
            ex,
        )
        assertEquals(listOf("Wifi", "R"), p.report.alreadyInVault)
        assertEquals(listOf("Wifi"), p.items.map { it.doc.name })
    }

    // A1: notes have their own exact key + name-keyed rename; skippedEmpty is kind-scoped.
    @Test fun noteRules_inFile_exactCollapse_renameAndSkip() {
        val p = plan(
            BW_HEADER +
                ",,note,N,a,,0,,,,\n" +
                ",,note,N,b,,0,,,,\n" + // distinct body → "N (2)"
                ",,note,N,a,,0,,,,\n" + // exact dup → collapsed
                ",,note,,,,0,,,,\n", // empty name AND body → skippedEmpty
        )
        assertEquals(listOf("N", "N (2)"), p.report.noteItems)
        assertEquals(1, p.report.collapsed)
        assertEquals(1, p.report.skippedEmpty)
        assertEquals(listOf("N (2)"), p.report.flagged)
    }

    // The 2-arg plan (empty projections) must behave byte-identically to today's planner.
    @Test fun planOverload_emptyProjections_identical() {
        val csv = "name,url,username,password,note\nM,https://m,me,pw1,\nM,https://m,me,pw2,\n"
        val a = plan(csv)
        val b = plan(csv, CsvImport.ImportProjections())
        assertEquals(a.items.map { it.doc }, b.items.map { it.doc })
        assertEquals(a.report, b.report)
    }
}
