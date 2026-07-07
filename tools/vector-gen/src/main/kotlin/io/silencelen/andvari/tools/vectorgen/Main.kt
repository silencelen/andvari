package io.silencelen.andvari.tools.vectorgen

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Hibp
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupSkipped
import io.silencelen.andvari.core.client.BackupSkippedItem
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.ConflictCopy
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.ExportCsv
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.TotpAlgorithm
import io.silencelen.andvari.core.crypto.TotpConfig
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.io.File

/**
 * Emits the spec/test-vectors JSON files from the Kotlin reference implementation.
 *
 * Inputs are fixed byte patterns (never random) so deterministic operations
 * reproduce byte-for-byte. Nondeterministic primitives (sealed boxes,
 * secretstream headers) are emitted in the DECRYPT direction: the stored
 * ciphertext must open to the stated plaintext; encrypt-side coverage is by
 * round-trip property tests in each implementation.
 */
private val crypto = createCryptoProvider()
private val json = Json { prettyPrint = true }

/** Deterministic patterned bytes; seed distinguishes streams. */
private fun pat(n: Int, seed: Int): ByteArray = ByteArray(n) { ((it * 7 + seed * 13 + 5) and 0xFF).toByte() }

private fun b64(b: ByteArray): String = Bytes.toB64(b)

private val FAST = KdfParams(ops = 2, memBytes = 16 * 1024 * 1024)

fun main(args: Array<String>) {
    if (args.firstOrNull() == "--bench") {
        bench()
        return
    }
    val outDir = File(args.firstOrNull() ?: error("usage: vector-gen <output-dir> | --bench"))
    outDir.mkdirs()
    write(outDir, "kdf.json", kdf())
    write(outDir, "envelope.json", envelope())
    write(outDir, "wrap.json", wrap())
    write(outDir, "seal.json", seal())
    write(outDir, "secretstream.json", secretstream())
    write(outDir, "totp.json", totp())
    write(outDir, "hibp.json", hibp())
    write(outDir, "sharedgrant.json", sharedGrant())
    write(outDir, "import.json", importVectors())
    write(outDir, "urimatch.json", uriMatch())
    write(outDir, "itemdoc.json", itemDoc())
    write(outDir, "export.json", exportVectors())
    write(outDir, "strength.json", strength())
    write(outDir, "conflictcopy.json", conflictCopy())
    write(outDir, "lifecycleproof.json", lifecycleProof())
    println("vector-gen: wrote 15 files to ${outDir.absolutePath}")
}

/** Argon2id timing on this host (spec 01 §9 benchmark table). */
private fun bench() {
    val salt = pat(16, 99)
    val pw = "benchmark password".encodeToByteArray()
    for ((ops, memMib) in listOf(2L to 64, 3L to 64, 4L to 64, 3L to 128)) {
        crypto.argon2id(pw, salt, 32, ops, memMib * 1024L * 1024) // warm-up
        val times = (1..5).map {
            val t0 = System.nanoTime()
            crypto.argon2id(pw, salt, 32, ops, memMib * 1024L * 1024)
            (System.nanoTime() - t0) / 1_000_000
        }
        println("argon2id ops=$ops mem=${memMib}MiB: median ${times.sorted()[2]} ms (runs: $times)")
    }
}

private fun write(dir: File, name: String, obj: JsonObject) {
    File(dir, name).writeText(json.encodeToString(JsonObject.serializer(), obj) + "\n")
    println("  $name")
}

private fun kdf(): JsonObject = buildJsonObject {
    putJsonArray("argon2id") {
        data class Case(val pw: String, val seed: Int, val ops: Long, val mem: Long)
        for (c in listOf(
            Case("test password 1", 1, 1, 8L * 1024 * 1024),
            Case("παράδειγμα ✓ unicode", 2, 2, 16L * 1024 * 1024),
            Case("production default params", 3, 3, 64L * 1024 * 1024),
        )) {
            val salt = pat(16, c.seed)
            val out = crypto.argon2id(c.pw.encodeToByteArray(), salt, 32, c.ops, c.mem)
            addJsonObject {
                put("passwordUtf8", c.pw)
                put("saltB64", b64(salt))
                put("ops", c.ops)
                put("memBytes", c.mem)
                put("outLen", 32)
                put("outB64", b64(out))
            }
        }
    }
    putJsonArray("hkdf") {
        val ikm = pat(32, 4)
        for ((info, len) in listOf("andvari/v1/auth" to 32, "andvari/v1/wrap" to 32, "andvari/test/long" to 64)) {
            addJsonObject {
                put("ikmB64", b64(ikm))
                put("infoUtf8", info)
                put("len", len)
                put("okmB64", b64(Hkdf.sha256(crypto, ikm, ByteArray(0), info.encodeToByteArray(), len)))
            }
        }
    }
    putJsonArray("chain") {
        for ((pw, seed) in listOf("correct horse battery staple" to 5, "🔐 emoji pass phrase 42" to 6)) {
            val salt = pat(16, seed)
            val mk = Keys.masterKey(crypto, pw, salt, FAST)
            addJsonObject {
                put("passwordUtf8", pw)
                put("saltB64", b64(salt))
                putJsonObject("kdfParams") {
                    put("v", 1); put("alg", "argon2id13"); put("ops", FAST.ops); put("memBytes", FAST.memBytes)
                }
                put("mkB64", b64(mk))
                put("authKeyB64", b64(Keys.authKey(crypto, mk)))
                put("wrapKeyB64", b64(Keys.wrapKey(crypto, mk)))
            }
        }
    }
}

private fun envelope(): JsonObject = buildJsonObject {
    val key = pat(32, 7)
    data class Case(val name: String, val plaintext: ByteArray, val nonceSeed: Int, val ad: ByteArray)
    val vaultId = "11111111-1111-4111-8111-111111111111"
    val itemId = "22222222-2222-4222-8222-222222222222"
    val cases = listOf(
        Case("empty", ByteArray(0), 8, Ad.item(vaultId, itemId, 1)),
        Case("short", "attack at dawn".encodeToByteArray(), 9, Ad.uvk("33333333-3333-4333-8333-333333333333")),
        Case("kilobyte", pat(1000, 10), 11, Ad.vaultMeta(vaultId)),
    )
    putJsonArray("seal") {
        for (c in cases) {
            val nonce = pat(24, c.nonceSeed)
            addJsonObject {
                put("name", c.name)
                put("keyB64", b64(key))
                put("nonceB64", b64(nonce))
                put("adUtf8", c.ad.decodeToString())
                put("plaintextB64", b64(c.plaintext))
                put("envelopeB64", b64(Envelope.sealWithNonce(crypto, key, nonce, c.plaintext, c.ad)))
            }
        }
    }
    putJsonArray("reject") {
        val c = cases[1]
        val nonce = pat(24, c.nonceSeed)
        val good = Envelope.sealWithNonce(crypto, key, nonce, c.plaintext, c.ad)
        fun add(reason: String, env: ByteArray, ad: ByteArray = c.ad) = addJsonObject {
            put("reason", reason)
            put("keyB64", b64(key))
            put("adUtf8", ad.decodeToString())
            put("envelopeB64", b64(env))
        }
        add("bad-version", good.copyOf().also { it[0] = 0x02 })
        add("bad-alg", good.copyOf().also { it[1] = 0x07 })
        add("bad-mac", good.copyOf().also { it[good.size - 1] = (it[good.size - 1].toInt() xor 1).toByte() })
        add("too-short", good.copyOfRange(0, Envelope.MIN_BYTES - 1))
        add("wrong-ad", good, Ad.uvk("99999999-9999-4999-8999-999999999999"))
    }
}

private fun wrap(): JsonObject = buildJsonObject {
    val userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    val vaultId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    val itemId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    val password = "correct horse battery staple"
    val kdfSalt = pat(16, 12)
    val uvk = pat(32, 13)
    val identitySeed = pat(32, 14)
    val vk = pat(32, 15)

    val mk = Keys.masterKey(crypto, password, kdfSalt, FAST)
    val wrapKey = Keys.wrapKey(crypto, mk)
    val identity = crypto.boxKeypairFromSeed(identitySeed)
    val vaultMetaPlain = """{"name":"Personal"}"""
    val itemPlain = """{"type":"login","name":"GitHub","login":{"username":"jacob","password":"hunter2","uris":["https://github.com/login"]}}"""

    put("userId", userId)
    put("personalVaultId", vaultId)
    put("itemId", itemId)
    put("passwordUtf8", password)
    put("kdfSaltB64", b64(kdfSalt))
    putJsonObject("kdfParams") {
        put("v", 1); put("alg", "argon2id13"); put("ops", FAST.ops); put("memBytes", FAST.memBytes)
    }
    put("authKeyB64", b64(Keys.authKey(crypto, mk)))
    put("uvkB64", b64(uvk))
    put("uvkNonceB64", b64(pat(24, 16)))
    put("wrappedUvkB64", b64(Envelope.sealWithNonce(crypto, wrapKey, pat(24, 16), uvk, Ad.uvk(userId))))
    put("identitySeedB64", b64(identitySeed))
    put("identityPubB64", b64(identity.publicKey))
    put("identityPrivB64", b64(identity.privateKey))
    put("idkeyNonceB64", b64(pat(24, 17)))
    put("encryptedIdentitySeedB64", b64(Envelope.sealWithNonce(crypto, uvk, pat(24, 17), identitySeed, Ad.idkey(userId))))
    put("vkB64", b64(vk))
    put("vkNonceB64", b64(pat(24, 18)))
    put("wrappedVkB64", b64(Envelope.sealWithNonce(crypto, uvk, pat(24, 18), vk, Ad.vk(vaultId, userId))))
    put("vaultMetaPlaintextUtf8", vaultMetaPlain)
    put("vaultMetaNonceB64", b64(pat(24, 19)))
    put("vaultMetaBlobB64", b64(Envelope.sealWithNonce(crypto, vk, pat(24, 19), vaultMetaPlain.encodeToByteArray(), Ad.vaultMeta(vaultId))))
    put("itemFormatVersion", 1)
    put("itemPlaintextUtf8", itemPlain)
    put("itemNonceB64", b64(pat(24, 20)))
    put("itemEnvelopeB64", b64(Envelope.sealWithNonce(crypto, vk, pat(24, 20), itemPlain.encodeToByteArray(), Ad.item(vaultId, itemId, 1))))
}

private fun seal(): JsonObject = buildJsonObject {
    val recoverySeed = pat(32, 21)
    val recovery = crypto.boxKeypairFromSeed(recoverySeed)
    put("recoverySeedB64", b64(recoverySeed))
    put("recoveryPubB64", b64(recovery.publicKey))
    put("recoveryPrivB64", b64(recovery.privateKey))
    put("fingerprint", Escrow.fingerprint(crypto, recovery.publicKey))
    put("shortFingerprint", Escrow.shortFingerprint(crypto, recovery.publicKey))

    putJsonArray("open") {
        val msg = "hello sealed box".encodeToByteArray()
        addJsonObject {
            put("sealedB64", b64(crypto.sealTo(recovery.publicKey, msg)))
            put("plaintextB64", b64(msg))
        }
    }
    val escrowUserId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    val escrowUvk = pat(32, 22)
    putJsonObject("escrowUvk") {
        put("userId", escrowUserId)
        put("uvkB64", b64(escrowUvk))
        put("sealedB64", b64(Escrow.sealUvk(crypto, recovery.publicKey, escrowUserId, escrowUvk)))
    }
    putJsonObject("canary") {
        put("sealedB64", b64(Escrow.sealCanary(crypto, recovery.publicKey)))
        put("expectedKeyB64", b64(Escrow.CANARY_KEY))
        put("expectedUserId", Escrow.CANARY_USER_ID)
    }
    putJsonObject("rejectWrongKey") {
        put("wrongSeedB64", b64(pat(32, 23)))
        put("sealedB64", b64(crypto.sealTo(recovery.publicKey, "nope".encodeToByteArray())))
    }
}

/** spec 01 §6 — shared-vault sealed grants. Seals are nondeterministic, so pin open +
 *  payload canonicalization + fingerprint; each impl round-trips its own seal. */
private fun sharedGrant(): JsonObject = buildJsonObject {
    val memberSeed = pat(32, 40)
    val member = crypto.boxKeypairFromSeed(memberSeed)
    val vaultId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    val vk = pat(32, 41)
    put("memberSeedB64", b64(memberSeed))
    put("memberIdentityPubB64", b64(member.publicKey))
    put("memberIdentityPrivB64", b64(member.privateKey))
    put("fingerprint", SharedGrant.fingerprint(crypto, member.publicKey))
    put("shortFingerprint", SharedGrant.shortFingerprint(crypto, member.publicKey))
    put("vaultId", vaultId)
    put("vkB64", b64(vk))
    // Exact canonical payload bytes both impls must reproduce before sealing.
    put("payloadUtf8", SharedGrant.canonicalPayload(vaultId, vk).decodeToString())
    // A seal that opens to the VK (open is deterministic; the seal itself is not).
    put("sealedB64", b64(SharedGrant.seal(crypto, member.publicKey, vaultId, vk)))
    // A seal whose payload names a DIFFERENT vaultId — open MUST reject under the real vaultId.
    putJsonObject("rejectVaultMismatch") {
        val wrongVaultId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        put("expectedVaultId", vaultId)
        put("sealedB64", b64(SharedGrant.seal(crypto, member.publicKey, wrongVaultId, vk)))
    }
}

/** spec 06 — CSV import. Expectations are produced by the :core reference impl. */
private fun importVectors(): JsonObject {
    val bom = "﻿"
    // name is a plain counter so the docs list is order-stable (itemId is not pinned).
    var counter = 0
    fun newId(): String = "id-${counter++}"

    fun caseObj(name: String, content: String): JsonObject = buildJsonObject {
        val bytes = content.encodeToByteArray()
        counter = 0
        val parsed = CsvImport.parse(bytes)
        val plan = CsvImport.plan(parsed, ::newId)
        put("name", name)
        put("contentB64", Bytes.toB64(bytes))
        putJsonObject("expect") {
            put("format", parsed.format.name.lowercase())
            putJsonArray("rows") {
                for (r in parsed.rows) addJsonObject {
                    put("name", r.name); put("url", r.url); put("username", r.username)
                    put("password", r.password); put("notes", r.notes)
                    r.timePasswordChangedMs?.let { put("timePasswordChangedMs", it) }
                    r.totp?.let { put("totp", it) }
                }
            }
            putJsonArray("errors") { for (e in parsed.errors) addJsonObject { put("line", e.line); put("code", e.code) } }
            putJsonArray("docs") {
                for (it in plan.items) addJsonObject {
                    put("name", it.doc.name)
                    put("username", it.doc.login?.username ?: "")
                    put("password", it.doc.login?.password ?: "")
                    put("uri", it.doc.login?.uris?.firstOrNull() ?: "")
                    put("notes", it.doc.notes ?: "")
                    it.doc.login?.totp?.let { t -> put("totp", t) }
                }
            }
            putJsonObject("report") {
                put("imported", plan.report.imported); put("skippedEmpty", plan.report.skippedEmpty)
                put("collapsed", plan.report.collapsed)
                putJsonArray("flagged") { for (n in plan.report.flagged) add(n) }
            }
        }
    }

    val chromeHeader = "name,url,username,password,note"
    val files = listOf(
        caseObj("chrome-basic", "$chromeHeader\nGitHub,https://github.com/login,jacob,s3cret,my note\n"),
        caseObj("chrome-old-4col", "name,url,username,password\nBank,https://bank.example,jo,pw\n"),
        caseObj(
            "chrome-quoting",
            "$chromeHeader\r\n\"Acme, Inc\",https://acme.test,\"user,name\",\"p\"\"w\",\"line1\nline2\"\r\n",
        ),
        caseObj("chrome-bom", "$bom$chromeHeader\r\nSite,https://site.test,u,p,n\r\n"),
        caseObj("chrome-skip-empty", "$chromeHeader\nkeep,https://a.test,u,p,\njunk,https://b.test,,,\n"),
        caseObj(
            "chrome-name-fallback",
            "$chromeHeader\n" +
                ",https://user:pw@Host.Example:8443/path?q,alice,a,\n" +
                ",https://[2001:db8::1]:443/,bob,b,\n" +
                ",ftp://bare.host,carol,c,\n",
        ),
        caseObj(
            "chrome-dupes",
            "$chromeHeader\n" +
                "Mail,https://mail.test,me,pw1,\n" +
                "Mail,https://mail.test,me,pw1,\n" + // exact dupe → collapsed
                "Mail,https://mail.test,me,pw2,\n" + // same url+user, diff pw → "(2)"
                "Mail,https://mail.test,me,pw3,\n",   // → "(3)"
        ),
        // andvari's own CSV export (spec 07 §1) is a Chrome superset with a trailing totp
        // column — this pins the andvari→andvari round-trip mapping (spec 06 §1).
        caseObj(
            "andvari-totp-roundtrip",
            "name,url,username,password,note,totp\n" +
                "GitHub,https://github.com/login,jacob,s3cret,,otpauth://totp/GitHub:jacob?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n" +
                "Bare32,https://b.test,u,p,,JBSWY3DPEHPK3PXP\n" +
                "NoTotp,https://n.test,u2,p2,note only,\n",
        ),
        caseObj(
            "firefox-basic",
            "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n" +
                "https://ff.test/login,fox,pw,,https://ff.test,{abc},1700000000000,1700000001000,1700000002000\n",
        ),
        caseObj(
            "firefox-httprealm",
            "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n" +
                "https://router.test/,admin,pw,\"Router Login\",,{x},0,0,0\n",
        ),
        caseObj(
            "errors-bad-rows",
            "$chromeHeader\n" +
                "ok,https://ok.test,u,p,n\n" +
                "toofew,https://few.test,u\n" +               // wrong_field_count
                "bad,\"https://q.test,u,p,n\n" +               // unterminated quote → bad_quote at its line
                "ok2,https://ok2.test,u2,p2,n2\n",
        ),
    )

    return buildJsonObject {
        putJsonArray("files") { for (c in files) add(c) }
        putJsonArray("reject") {
            addJsonObject {
                put("name", "unrecognized-header")
                put("reason", "unrecognized_header")
                put("contentB64", Bytes.toB64("foo,bar,baz\n1,2,3\n".encodeToByteArray()))
            }
            addJsonObject {
                put("name", "too-many-rows")
                put("reason", "too_many_rows")
                putJsonObject("construct") {
                    put("header", chromeHeader)
                    put("row", "n,https://x.test,u,p,c")
                    put("count", CsvImport.MAX_ROWS + 1)
                }
            }
            addJsonObject {
                put("name", "too-large")
                put("reason", "too_large")
                putJsonObject("construct") {
                    put("header", chromeHeader)
                    put("row", "n,https://x.test,u,p,c")
                    // rows needed to exceed 10 MiB with this row width
                    put("count", CsvImport.MAX_BYTES / ("n,https://x.test,u,p,c\n".length) + 2)
                }
            }
        }
    }
}

/** spec 02 §3.1 — autofill URI matching + field classification. Expected values are
 *  hand-authored (NOT produced by the impl) so neither impl self-certifies. */
private fun uriMatch(): JsonObject = buildJsonObject {
    // match: {savedUri, webHost?, packageName, expected}. webHost is the caller-gated
    // per-field trusted-browser domain (null when the requester isn't a trusted browser).
    fun m(saved: String, webHost: String?, pkg: String, expected: Boolean) = buildJsonObject {
        put("savedUri", saved); if (webHost != null) put("webHost", webHost) else put("webHost", JsonNull)
        put("packageName", pkg); put("expected", expected)
    }
    putJsonArray("match") {
        // exact + scheme-less + www + case + trailing dot
        add(m("https://example.com/login", "example.com", "com.android.chrome", true))
        add(m("example.com", "example.com", "com.android.chrome", true))
        add(m("https://www.example.com", "example.com", "com.android.chrome", true))
        add(m("https://example.com", "www.example.com", "com.android.chrome", true))
        add(m("https://Example.COM", "example.com", "com.android.chrome", true))
        add(m("https://example.com./", "example.com", "com.android.chrome", true))
        add(m("https://example.com:8443/path?q#f", "example.com", "com.android.chrome", true)) // port/path ignored
        // label-boundary subdomain suffix
        add(m("https://example.com", "login.example.com", "com.android.chrome", true))
        add(m("https://example.com", "a.b.example.com", "com.android.chrome", true))
        // label-boundary ATTACKS — must NOT match
        add(m("https://example.com", "evil-example.com", "com.android.chrome", false))
        add(m("https://example.com", "example.com.evil.net", "com.android.chrome", false))
        add(m("https://example.com", "notexample.com", "com.android.chrome", false))
        // ≥2-label guard: a single-label / TLD saved host is exact-only
        add(m("com", "evil.com", "com.android.chrome", false))
        add(m("router", "router", "com.android.chrome", true))
        add(m("router", "a.router", "com.android.chrome", false))
        add(m("localhost", "localhost", "com.android.chrome", true))
        // IP literals: exact only
        add(m("https://10.0.0.5", "10.0.0.5", "com.android.chrome", true))
        add(m("https://10.0.0.5", "a.10.0.0.5", "com.android.chrome", false))
        // userinfo stripped
        add(m("https://user:pw@example.com", "example.com", "com.android.chrome", true))
        // no trusted webHost → web item never matches by package
        add(m("https://example.com", null, "com.android.chrome", false))
        // androidapp exact
        add(m("androidapp://com.spotify.music", null, "com.spotify.music", true))
        add(m("androidapp://com.spotify.music", null, "com.evil.clone", false))
        add(m("androidapp://com.spotify.music", "example.com", "com.spotify.music", true))
        // garbage / empty
        add(m("", "example.com", "com.android.chrome", false))
        add(m("androidapp://", null, "com.x", false))
    }

    // classify: {hints[], inputTypeClass, inputTypeVariation, htmlType?, htmlNameOrId?, expected}
    fun c(hints: List<String>, cls: Int, varn: Int, htmlType: String?, nameId: String?, expected: String) = buildJsonObject {
        putJsonArray("hints") { for (h in hints) add(h) }
        put("inputTypeClass", cls); put("inputTypeVariation", varn)
        if (htmlType != null) put("htmlType", htmlType) else put("htmlType", JsonNull)
        if (nameId != null) put("htmlNameOrId", nameId) else put("htmlNameOrId", JsonNull)
        put("expected", expected)
    }
    val TEXT = 0x1; val NUMBER = 0x2; val V_PW = 0x80; val V_WEBPW = 0xe0; val V_VISPW = 0x90; val V_EMAIL = 0x20; val N_PW = 0x10
    putJsonArray("classify") {
        // hints win
        add(c(listOf("username"), 0, 0, null, null, "username"))
        add(c(listOf("emailAddress"), 0, 0, null, null, "username"))
        add(c(listOf("password"), 0, 0, null, null, "password"))
        add(c(listOf("smsOTPCode"), TEXT, V_PW, "password", "otp", "none")) // negative hint beats password type
        add(c(listOf("creditCardNumber"), 0, 0, null, null, "none"))
        // html type
        add(c(emptyList(), TEXT, 0, "password", "pw", "password"))
        add(c(emptyList(), TEXT, 0, "email", "email", "username"))
        add(c(emptyList(), TEXT, 0, "search", "q", "none"))
        add(c(emptyList(), TEXT, 0, "text", "username", "username"))
        add(c(emptyList(), TEXT, 0, "text", "user_password", "password"))
        add(c(emptyList(), TEXT, 0, "text", "search_query", "none"))
        // android inputType
        add(c(emptyList(), TEXT, V_PW, null, null, "password"))
        add(c(emptyList(), TEXT, V_WEBPW, null, null, "password"))
        add(c(emptyList(), TEXT, V_VISPW, null, null, "password"))
        add(c(emptyList(), TEXT, V_EMAIL, null, null, "username"))
        add(c(emptyList(), NUMBER, N_PW, null, null, "password"))
        // name-only fallback
        add(c(emptyList(), TEXT, 0, null, "login", "username"))
        add(c(emptyList(), TEXT, 0, null, "passwd", "password"))
        add(c(emptyList(), TEXT, 0, null, "captcha", "none"))
        add(c(emptyList(), TEXT, 0, null, null, "none"))
    }
}

/** spec 02 §3 — unknown-field round-trip (plaintext-level only; envelope bytes are pinned
 *  in wrap.json/envelope.json). Hand-authored, deterministic: each case is a raw item doc
 *  with unknown fields, a scripted edit applied through each impl's REAL edit shape
 *  (Kotlin `copy()`, web spread), and per-path expectations. Consumers MUST assert
 *  PER-PATH — never whole-object equality: Kotlin re-encodes with encodeDefaults=true and
 *  explicit nulls, web omits absent keys, and BOTH shapes are spec-legal. Unknown values
 *  cover every JSON kind; numbers stay within ±2^53 (outside is not preservation-
 *  guaranteed, spec 02 §3 — future writers use strings). */
private fun itemDoc(): JsonObject {
    fun pv(path: String, valueJson: String) = buildJsonObject { put("path", path); put("valueJson", valueJson) }
    fun edit(op: String, value: kotlinx.serialization.json.JsonElement) = buildJsonObject { put(op, value) }
    fun editS(op: String, value: String) = edit(op, kotlinx.serialization.json.JsonPrimitive(value))
    fun editB(op: String, value: Boolean) = edit(op, kotlinx.serialization.json.JsonPrimitive(value))
    fun case(name: String, docJson: String, edit: JsonObject, unknowns: List<JsonObject>, typed: List<JsonObject>) =
        buildJsonObject {
            put("name", name)
            put("docJson", docJson)
            put("edit", edit)
            putJsonArray("expectUnknownPaths") { for (u in unknowns) add(u) }
            putJsonArray("expectTyped") { for (t in typed) add(t) }
        }

    return buildJsonObject {
        putJsonArray("cases") {
            // Unknowns at the TOP level only (object, array, string kinds).
            add(case(
                "top-level-unknowns-rename",
                """{"type":"login","name":"GitHub","notes":"work account","favorite":false,"login":{"username":"jacob","password":"hunter2","uris":["https://github.com/login"]},"x-future":{"nested":{"deep":true},"arr":[1,"two"]},"x-tags":["a","b"],"x-note":"plain"}""",
                editS("setName", "GitHub (renamed)"),
                listOf(
                    pv("/x-future", """{"nested":{"deep":true},"arr":[1,"two"]}"""),
                    pv("/x-tags", """["a","b"]"""),
                    pv("/x-note", "\"plain\""),
                ),
                listOf(
                    pv("/name", "\"GitHub (renamed)\""),
                    pv("/type", "\"login\""),
                    pv("/login/username", "\"jacob\""),
                ),
            ))
            // Unknowns inside LOGIN only (boolean, safe integer, null kinds); deep edit.
            add(case(
                "login-unknowns-set-password",
                """{"type":"login","name":"Email","login":{"username":"jo@x.com","password":"old-pass","uris":[],"x-flag":true,"x-order":7,"x-null":null}}""",
                editS("setPassword", "n3w-p4ss!"),
                listOf(
                    pv("/login/x-flag", "true"),
                    pv("/login/x-order", "7"),
                    pv("/login/x-null", "null"),
                ),
                listOf(
                    pv("/login/password", "\"n3w-p4ss!\""),
                    pv("/login/username", "\"jo@x.com\""),
                    pv("/name", "\"Email\""),
                ),
            ))
            // Unknowns inside EACH passwordHistory entry; top-level flag edit.
            add(case(
                "history-entry-unknowns-favorite",
                """{"type":"login","name":"Bank","favorite":false,"login":{"username":"jo","password":"pw3","passwordHistory":[{"password":"pw1","retiredAt":1700000000000,"x-note":"rotated after breach"},{"password":"pw2","retiredAt":1710000000000,"x-meta":{"source":"import","gen":2}}]}}""",
                editB("setFavorite", true),
                listOf(
                    pv("/login/passwordHistory/0/x-note", "\"rotated after breach\""),
                    pv("/login/passwordHistory/1/x-meta", """{"source":"import","gen":2}"""),
                ),
                listOf(
                    pv("/favorite", "true"),
                    pv("/login/passwordHistory/0/password", "\"pw1\""),
                    pv("/login/passwordHistory/1/retiredAt", "1710000000000"),
                ),
            ))
            // Unknowns inside an ATTACHMENTS entry (incl. the 2^53-1 safe-number boundary).
            add(case(
                "attachment-unknowns-rename",
                """{"type":"login","name":"Passport","login":{"username":"traveler"},"attachments":[{"id":"11111111-1111-4111-8111-111111111111","name":"scan.pdf","size":12345,"fileKey":"c2VjcmV0LWtleS1ieXRlcw","x-tag":"receipts","x-num":9007199254740991}]}""",
                editS("setName", "Passport 2026"),
                listOf(
                    pv("/attachments/0/x-tag", "\"receipts\""),
                    pv("/attachments/0/x-num", "9007199254740991"),
                ),
                listOf(
                    pv("/attachments/0/id", "\"11111111-1111-4111-8111-111111111111\""),
                    pv("/attachments/0/size", "12345"),
                    pv("/name", "\"Passport 2026\""),
                ),
            ))
            // The SAME doc carries unknowns at all 4 levels; deep edit through login.
            // /login/uris/1 pins the uris-tail survival under a copy/spread edit.
            add(case(
                "all-levels-set-password",
                """{"type":"login","name":"Everything","notes":"n","favorite":true,"x-schema":"v9-preview","login":{"username":"u","password":"old","uris":["https://e.test","https://e2.test"],"x-generator":{"length":24,"symbols":false},"passwordHistory":[{"password":"old0","retiredAt":1690000000000,"x-strength":0.87}]},"attachments":[{"id":"22222222-2222-4222-8222-222222222222","name":"a.bin","size":1,"fileKey":"a2V5","x-hidden":false}]}""",
                editS("setPassword", "brand-new"),
                listOf(
                    pv("/x-schema", "\"v9-preview\""),
                    pv("/login/x-generator", """{"length":24,"symbols":false}"""),
                    pv("/login/passwordHistory/0/x-strength", "0.87"),
                    pv("/attachments/0/x-hidden", "false"),
                ),
                listOf(
                    pv("/login/password", "\"brand-new\""),
                    pv("/name", "\"Everything\""),
                    pv("/favorite", "true"),
                    pv("/login/uris/1", "\"https://e2.test\""),
                ),
            ))
            // No-edit round trip, unknowns at all 4 levels (null + nested-mixed-array kinds).
            add(case(
                "all-levels-no-edit",
                """{"type":"login","name":"Untouched","x-null-top":null,"x-bool":false,"login":{"username":"u6","password":"p6","x-arr":[null,{"k":"v"},[1,2]],"passwordHistory":[{"password":"p0","retiredAt":1650000000000,"x-b":true}]},"attachments":[{"id":"33333333-3333-4333-8333-333333333333","name":"b.txt","size":2,"fileKey":"a2V5Mg","x-s":"tag"}]}""",
                editB("none", true),
                listOf(
                    pv("/x-null-top", "null"),
                    pv("/x-bool", "false"),
                    pv("/login/x-arr", """[null,{"k":"v"},[1,2]]"""),
                    pv("/login/passwordHistory/0/x-b", "true"),
                    pv("/attachments/0/x-s", "\"tag\""),
                ),
                listOf(
                    pv("/name", "\"Untouched\""),
                    pv("/login/username", "\"u6\""),
                ),
            ))
            // Optional typed fields ABSENT (notes/favorite/login/attachments) — pins that
            // absence-vs-default handling never corrupts the unknowns riding alongside.
            add(case(
                "absent-optionals-note",
                """{"type":"note","name":"Just a note","x-only":"bare","x-version":42}""",
                editS("setName", "Just a note (edited)"),
                listOf(
                    pv("/x-only", "\"bare\""),
                    pv("/x-version", "42"),
                ),
                listOf(
                    pv("/name", "\"Just a note (edited)\""),
                    pv("/type", "\"note\""),
                ),
            ))
        }
    }
}

/** spec 07 — CSV export writer + `.andvari` backup container. CSV cases and the container
 *  bytes are fully deterministic (FAST-class kdfParams, fixed kdfSalt + envelope nonce via
 *  sealWithNonce, fixed fileId, pinned payloadUtf8) so both impls must PRODUCE and OPEN the
 *  exact bytes. Attachment sections are covered by per-impl round-trip + truncation tests
 *  (secretstream is nondeterministic — same posture as secretstream.json). Reject headers
 *  are RAW-JSON built (the typed KdfParams cannot even construct foreign alg/v). */
private fun exportVectors(): JsonObject {
    val itemJson = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    // ---- (a) CSV-writer cases: docs in → exact output string ----
    fun csvCase(name: String, docsJson: List<String>): JsonObject = buildJsonObject {
        put("name", name)
        putJsonArray("docs") { for (d in docsJson) add(Json.parseToJsonElement(d)) }
        put("csvUtf8", ExportCsv.write(docsJson.map { itemJson.decodeFromString(ItemDoc.serializer(), it) }))
    }
    val csvCases = listOf(
        csvCase("empty", emptyList()),
        csvCase(
            "basic-and-empty-url",
            listOf(
                """{"type":"login","name":"GitHub","notes":"work account","login":{"username":"jacob","password":"hunter2","uris":["https://github.com/login"],"totp":"otpauth://totp/GitHub:jacob?secret=JBSWY3DPEHPK3PXP"}}""",
                """{"type":"login","name":"EmptyUrl","login":{"username":"u","password":"p","uris":[]}}""",
                """{"type":"login","name":"NoLoginBlock"}""",
            ),
        ),
        csvCase(
            "quoting-and-formula-verbatim",
            listOf(
                """{"type":"login","name":"Acme, Inc","login":{"username":"user\"name","password":"p,w\"1","uris":["https://acme.test"]}}""",
                """{"type":"login","name":"=cmd()","notes":" spaced, not trimmed ","login":{"username":"=SUM(A1)","password":"+plus-@at","uris":["https://f.test"]}}""",
            ),
        ),
        csvCase(
            "crlf-normalization",
            listOf(
                """{"type":"login","name":"Multiline","notes":"line1\r\nline2\rline3\nline4","login":{"username":"u","password":"p\rq","uris":["https://m.test"]}}""",
            ),
        ),
        csvCase(
            "totp-bare-skips-and-empty-row",
            listOf(
                """{"type":"note","name":"Skipped note","notes":"never exported"}""",
                """{"type":"login","name":"Bare32","login":{"username":"u","password":"p","uris":["https://b.test"],"totp":"JBSWY3DPEHPK3PXP"}}""",
                """{"type":"login","name":"ExtraUris","login":{"username":"e","password":"pw","uris":["https://first.test","https://dropped.test"]}}""",
                """{"type":"login","name":"EmptyBoth","notes":"written; reimport skips it","login":{"username":"","password":"","uris":["https://w.test"]}}""",
            ),
        ),
    )

    // ---- (b) container cases ----
    fun buildContainer(passphrase: String, fileId: String, salt: ByteArray, nonce: ByteArray, payloadUtf8: String): ByteArray {
        val parts = ArrayList<ByteArray>()
        Backup.buildWithPayloadBytes(crypto, passphrase, fileId, salt, FAST, payloadUtf8.encodeToByteArray(), emptyList(), nonce) { parts.add(it) }
        val out = ByteArray(parts.sumOf { it.size })
        var o = 0
        for (p in parts) { p.copyInto(out, o); o += p.size }
        return out
    }
    fun kdfParamsObj() = buildJsonObject {
        put("v", 1); put("alg", "argon2id13"); put("opsLimit", FAST.ops); put("memBytes", FAST.memBytes)
    }
    fun containerCase(name: String, passphrase: String, fileId: String, saltSeed: Int, nonceSeed: Int, payloadUtf8: String): Pair<JsonObject, ByteArray> {
        val salt = pat(16, saltSeed)
        val nonce = pat(24, nonceSeed)
        val container = buildContainer(passphrase, fileId, salt, nonce, payloadUtf8)
        val obj = buildJsonObject {
            put("name", name)
            put("passphraseUtf8", passphrase)
            put("fileId", fileId)
            put("kdfSaltB64", b64(salt))
            put("kdfParams", kdfParamsObj())
            put("envelopeNonceB64", b64(nonce))
            put("payloadUtf8", payloadUtf8)
            put("containerB64", b64(container))
        }
        return obj to container
    }

    val passphrase = "export vectors passphrase"
    val fileId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    val vaultId = "11111111-1111-4111-8111-111111111111"
    val itemsOnlyPayload = BackupPayload(
        exportedAt = 1751850000000,
        origin = "https://andvari.taila2dff2.ts.net",
        userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        identityFingerprint = "0123456789abcdef",
        vaults = listOf(BackupVault(vaultId, "personal", "Personal", "owner")),
        items = listOf(
            BackupItem(
                itemId = "22222222-2222-4222-8222-222222222222", vaultId = vaultId, formatVersion = 1, updatedAt = 1751840000000,
                doc = itemJson.decodeFromString(
                    ItemDoc.serializer(),
                    """{"type":"login","name":"GitHub","login":{"username":"jacob","password":"hunter2","uris":["https://github.com/login"],"totp":"otpauth://totp/GitHub:jacob?secret=JBSWY3DPEHPK3PXP"}}""",
                ),
            ),
            BackupItem(
                itemId = "33333333-3333-4333-8333-333333333333", vaultId = vaultId, formatVersion = 1, updatedAt = 1751841000000,
                doc = itemJson.decodeFromString(ItemDoc.serializer(), """{"type":"note","name":"Wifi","notes":"router in the closet"}"""),
            ),
        ),
        skipped = BackupSkipped(
            undecryptable = listOf(BackupSkippedItem("44444444-4444-4444-8444-444444444444", vaultId, 2)),
            attachmentsOverCap = listOf("tax-archive.zip"),
            attachmentFetchFailed = listOf("scan.pdf"),
        ),
    )
    val (itemsOnlyObj, goodContainer) = containerCase(
        "items-only", passphrase, fileId, saltSeed = 50, nonceSeed = 51,
        payloadUtf8 = itemJson.encodeToString(BackupPayload.serializer(), itemsOnlyPayload),
    )

    // Unknown keys at the payload level AND inside the doc at all 4 levels — open() must
    // tolerate the former (ignoreUnknownKeys) and PRESERVE the latter (spec 02 §3 overlay).
    val unknownDoc =
        """{"type":"login","name":"Everything","x-top":"keep","login":{"username":"u","password":"p","x-l":{"deep":true},"passwordHistory":[{"password":"old","retiredAt":1690000000000,"x-h":7}]},"attachments":[{"id":"55555555-5555-4555-8555-555555555555","name":"a.bin","size":1,"fileKey":"a2V5","x-a":false}]}"""
    val unknownPayloadTyped = BackupPayload(
        exportedAt = 1751850000001,
        userId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        vaults = listOf(BackupVault(vaultId, "personal", "Personal", "owner")),
        items = listOf(
            BackupItem(
                itemId = "66666666-6666-4666-8666-666666666666", vaultId = vaultId, formatVersion = 1, updatedAt = 1751842000000,
                doc = itemJson.decodeFromString(ItemDoc.serializer(), unknownDoc),
            ),
        ),
    )
    val unknownPayloadUtf8 = run {
        val base = Json.parseToJsonElement(itemJson.encodeToString(BackupPayload.serializer(), unknownPayloadTyped)).jsonObject
        JsonObject(base + ("x-future" to buildJsonObject { put("hint", "ignore-me") })).toString()
    }
    val (unknownObj, _) = containerCase(
        "unknown-fields-tolerated", passphrase, "ffffffff-ffff-4fff-8fff-ffffffffffff", saltSeed = 52, nonceSeed = 53,
        payloadUtf8 = unknownPayloadUtf8,
    )

    // ---- (c) reject cases ----
    fun u32le(v: Int) = byteArrayOf(v.toByte(), (v ushr 8).toByte(), (v ushr 16).toByte(), (v ushr 24).toByte())
    fun u64le(v: Long) = ByteArray(8) { i -> ((v ushr (8 * i)) and 0xFF).toByte() }
    fun rawContainer(headerJson: String, sections: List<ByteArray>): ByteArray {
        var out = "ANDVBK01".encodeToByteArray() + u32le(headerJson.encodeToByteArray().size) + headerJson.encodeToByteArray()
        for (s in sections) out = out + u64le(s.size.toLong()) + s
        return out
    }
    val saltB64 = b64(pat(16, 50))
    fun headerJson(format: String = "andvari-backup", v: Int = 1, kdfV: Int = 1, alg: String = "argon2id13", opsLimit: Long = FAST.ops, memBytes: Long = FAST.memBytes): String =
        """{"format":"$format","v":$v,"fileId":"$fileId","kdfSalt":"$saltB64","kdfParams":{"v":$kdfV,"alg":"$alg","opsLimit":$opsLimit,"memBytes":$memBytes}}"""
    val dummySection = pat(42, 60)
    fun reject(name: String, reason: String, container: ByteArray, pass: String = passphrase) = buildJsonObject {
        put("name", name)
        put("reason", reason)
        put("passphraseUtf8", pass)
        put("containerB64", b64(container))
    }
    // AD/fileId mismatch: same header length, one hex digit of the fileId swapped in place.
    val fileIdSwapped = run {
        val headerLen = goodContainer.copyOfRange(8, 12).let { (it[0].toInt() and 0xFF) or ((it[1].toInt() and 0xFF) shl 8) or ((it[2].toInt() and 0xFF) shl 16) or ((it[3].toInt() and 0xFF) shl 24) }
        val headerStr = goodContainer.copyOfRange(12, 12 + headerLen).decodeToString()
        val swapped = headerStr.replace(fileId, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeef").encodeToByteArray()
        check(swapped.size == headerLen) { "fileId swap must preserve headerLen" }
        goodContainer.copyOf().also { swapped.copyInto(it, 12) }
    }
    val rejects = listOf(
        reject("bad-magic", "unknown_format", goodContainer.copyOf().also { "XNDVBK99".encodeToByteArray().copyInto(it, 0) }),
        reject("unknown-format", "unknown_format", rawContainer(headerJson(format = "andvari-backup-vault"), listOf(dummySection))),
        reject("unknown-version", "unknown_version", rawContainer(headerJson(v = 2), listOf(dummySection))),
        reject("foreign-kdf-alg", "unsupported_kdf", rawContainer(headerJson(alg = "scrypt"), listOf(dummySection))),
        reject("foreign-kdf-v", "unsupported_kdf", rawContainer(headerJson(kdfV = 2), listOf(dummySection))),
        reject("membytes-over-ceiling", "unsupported_kdf", rawContainer(headerJson(memBytes = 256L * 1024 * 1024 + 1), listOf(dummySection))),
        reject("opslimit-over-ceiling", "unsupported_kdf", rawContainer(headerJson(opsLimit = 17), listOf(dummySection))),
        reject("truncated-section", "truncated", goodContainer.copyOfRange(0, goodContainer.size - 20)),
        reject("fileid-mismatch", "wrong_passphrase_or_corrupt", fileIdSwapped),
        reject("wrong-passphrase", "wrong_passphrase_or_corrupt", goodContainer, pass = "not the export passphrase"),
    )

    return buildJsonObject {
        putJsonArray("csv") { for (c in csvCases) add(c) }
        putJsonArray("container") { add(itemsOnlyObj); add(unknownObj) }
        putJsonArray("reject") { for (r in rejects) add(r) }
    }
}

private fun secretstream(): JsonObject = buildJsonObject {
    val key = pat(32, 24)
    put("keyB64", b64(key))
    val streams = listOf(
        listOf(pat(65536, 25), pat(65536, 26), pat(1234, 27)),
        listOf(pat(10, 28)),
    )
    putJsonArray("streams") {
        for (chunks in streams) {
            val enc = crypto.secretstreamEncrypt(key, chunks)
            addJsonObject {
                put("headerB64", b64(enc.header))
                putJsonArray("chunksPlainB64") { for (c in chunks) add(b64(c)) }
                putJsonArray("chunksCipherB64") { for (c in enc.chunks) add(b64(c)) }
            }
        }
    }
    putJsonArray("reject") {
        val chunks = listOf(pat(100, 29), pat(100, 30))
        val enc = crypto.secretstreamEncrypt(key, chunks)
        addJsonObject {
            put("reason", "truncated")
            put("headerB64", b64(enc.header))
            putJsonArray("chunksCipherB64") { add(b64(enc.chunks[0])) }
        }
        addJsonObject {
            put("reason", "corrupt")
            put("headerB64", b64(enc.header))
            putJsonArray("chunksCipherB64") {
                add(b64(enc.chunks[0].copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }))
                add(b64(enc.chunks[1]))
            }
        }
        addJsonObject {
            put("reason", "reordered")
            put("headerB64", b64(enc.header))
            putJsonArray("chunksCipherB64") {
                add(b64(enc.chunks[1]))
                add(b64(enc.chunks[0]))
            }
        }
    }
}

private fun totp(): JsonObject = buildJsonObject {
    val rfcSha1 = "12345678901234567890".encodeToByteArray()
    val rfcSha256 = "12345678901234567890123456789012".encodeToByteArray()
    val rfcSha512 = "1234567890123456789012345678901234567890123456789012345678901234".encodeToByteArray()

    putJsonArray("cases") {
        data class Case(val secret: ByteArray, val alg: TotpAlgorithm, val digits: Int, val period: Int, val time: Long)
        val cases = buildList {
            for (t in listOf(59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L)) {
                add(Case(rfcSha1, TotpAlgorithm.SHA1, 8, 30, t))
                add(Case(rfcSha256, TotpAlgorithm.SHA256, 8, 30, t))
                add(Case(rfcSha512, TotpAlgorithm.SHA512, 8, 30, t))
            }
            add(Case(rfcSha1, TotpAlgorithm.SHA1, 6, 30, 59L))
            add(Case(rfcSha1, TotpAlgorithm.SHA1, 6, 60, 3600L))
            add(Case(rfcSha256, TotpAlgorithm.SHA256, 6, 30, 1751700000L))
        }
        for (c in cases) {
            val config = TotpConfig(secret = c.secret, algorithm = c.alg, digits = c.digits, periodSeconds = c.period)
            addJsonObject {
                put("secretBase32", io.silencelen.andvari.core.crypto.Base32.encode(c.secret))
                put("algorithm", c.alg.name)
                put("digits", c.digits)
                put("period", c.period)
                put("timeSec", c.time)
                put("expected", Totp.code(crypto, config, c.time))
            }
        }
    }
    putJsonArray("uris") {
        addJsonObject {
            put("uri", "otpauth://totp/GitHub:jacob%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60")
            putJsonObject("expect") {
                put("secretBase32", "JBSWY3DPEHPK3PXP")
                put("algorithm", "SHA256"); put("digits", 8); put("period", 60)
                put("label", "GitHub:jacob@example.com"); put("issuer", "GitHub")
            }
        }
        addJsonObject {
            put("uri", "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP")
            putJsonObject("expect") {
                put("secretBase32", "JBSWY3DPEHPK3PXP")
                put("algorithm", "SHA1"); put("digits", 6); put("period", 30)
                put("label", "Example"); put("issuer", "")
            }
        }
        addJsonObject {
            put("uri", "otpauth://totp/Caf%C3%A9%20Wifi?secret=jbswy3dpehpk3pxp&issuer=Caf%C3%A9")
            putJsonObject("expect") {
                put("secretBase32", "JBSWY3DPEHPK3PXP")
                put("algorithm", "SHA1"); put("digits", 6); put("period", 30)
                put("label", "Café Wifi"); put("issuer", "Café")
            }
        }
    }
}

private fun hibp(): JsonObject = buildJsonObject {
    putJsonArray("cases") {
        for ((pw, count) in listOf("password123" to 12345L, "tr0ub4dor&3" to 0L)) {
            val hash = Hibp.sha1UpperHex(crypto, pw)
            val response = buildString {
                append("0000000000000000000000000000000000A:3\r\n")
                if (count > 0) append("${Hibp.suffix(hash)}:$count\r\n")
                append("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9")
            }
            addJsonObject {
                put("passwordUtf8", pw)
                put("sha1UpperHex", hash)
                put("prefix", Hibp.prefix(hash))
                put("suffix", Hibp.suffix(hash))
                put("rangeResponse", response)
                put("expectedCount", count)
            }
        }
    }
}


/**
 * Strength-estimator vectors (spec 07 §2.3): the score gates the backup-passphrase
 * floor, so a drift between impls means one client accepts a passphrase another
 * rejects. Cases straddle every class-weight and bit-threshold boundary, incl.
 * UTF-16-length semantics (Kotlin String.length == JS String.length).
 */
private fun strength(): JsonObject = buildJsonObject {
    val cases = listOf(
        "", "a", "password", "aaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaa",
        "passwordpasswordpassword", "Password1", "Password12", "Passw0rd!",
        "correct horse battery staple", "Tr0ub4dour&3", "aA1!aA1!aA1!aA1!aA1!",
        "0123456789012345678", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
        "pässwörd pässwörd", "😀😀😀😀😀😀😀😀", "  spaces  count  too  ",
        "xX9# ", "the quick brown fox jumps over the lazy dog 42 TIMES!",
    )
    putJsonArray("cases") {
        for (pw in cases) {
            addJsonObject {
                put("password", pw)
                put("utf16Length", pw.length)
                put("score", Strength.estimateStrength(pw))
            }
        }
    }
}

/**
 * Conflict-copy-id vectors (spec 03 §5): the deterministic (itemId, rev) → UUID map that
 * makes concurrent materializers converge on ONE copy. Divergence silently doubles
 * conflict copies across the fleet.
 */
private fun conflictCopy(): JsonObject = buildJsonObject {
    val ids = listOf(
        "0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10" to 1L,
        "0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10" to 2L,
        "ffffffff-ffff-4fff-bfff-ffffffffffff" to 0L,
        "00000000-0000-4000-8000-000000000000" to 9007199254740991L,
        "5f2b9a1c-4d3e-4c7a-9b8f-1a2c3d4e5f60" to 42L,
        "e3c0418f-1118-4a5a-8888-b26efdd3eafc" to 123456789L,
    )
    putJsonArray("cases") {
        for ((itemId, rev) in ids) {
            addJsonObject {
                put("itemId", itemId)
                put("rev", rev)
                put("copyId", ConflictCopy.id(crypto, itemId, rev))
            }
        }
    }
}


/**
 * Lifecycle-proof vectors (spec 03 §11): the HKDF lifecycleKey derivation + one HMAC proof
 * per op domain string. A divergence between the JVM and TS mints means a member's client
 * would reject a genuine owner action (or accept a forged one), so every domain string is
 * pinned here — including the accept proof's wrappedVk-hash binding.
 */
private fun lifecycleProof(): JsonObject = buildJsonObject {
    val vk = pat(32, 71)
    val key = LifecycleProof.lifecycleKey(crypto, vk)
    put("vk", b64(vk))
    put("lifecycleKey", b64(key))
    val vaultId = "0b7aa1e4-31f5-4f0a-9a6e-0e6a3a3d7d10"
    val deleteId = "5f2b9a1c-4d3e-4c7a-9b8f-1a2c3d4e5f60"
    val offerId = "e3c0418f-1118-4a5a-8888-b26efdd3eafc"
    val toUser = "f42e08cb-8cd4-435c-9599-83b519815789"
    val wrappedVk = "AQFabc_deFGhijkLMnop-qrstuvwxyz0123456789ABCDEFGH"
    putJsonArray("cases") {
        addJsonObject {
            put("op", "delete"); put("vaultId", vaultId); put("deleteId", deleteId)
            put("proof", LifecycleProof.delete(crypto, key, vaultId, deleteId))
        }
        addJsonObject {
            put("op", "restore"); put("vaultId", vaultId); put("deleteId", deleteId)
            put("proof", LifecycleProof.restore(crypto, key, vaultId, deleteId))
        }
        addJsonObject {
            put("op", "offer"); put("vaultId", vaultId); put("offerId", offerId)
            put("toUserId", toUser); put("expiresAt", 1752000000000L); put("seq", 1L)
            put("proof", LifecycleProof.offer(crypto, key, vaultId, offerId, toUser, 1752000000000L, 1L))
        }
        addJsonObject {
            put("op", "accept"); put("vaultId", vaultId); put("offerId", offerId)
            put("newOwnerUserId", toUser); put("seq", 1L); put("wrappedVk", wrappedVk)
            put("proof", LifecycleProof.accept(crypto, key, vaultId, offerId, toUser, 1L, wrappedVk))
        }
        addJsonObject {
            put("op", "remove"); put("vaultId", vaultId); put("targetUserId", toUser); put("nonce", deleteId)
            put("proof", LifecycleProof.remove(crypto, key, vaultId, toUser, deleteId))
        }
    }
}
