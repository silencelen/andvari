package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.SignedStatement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.AssistedRecovery
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * `recovery-cli` as the operator types it, graded off `escrow-v3.json` (spec 04 §4 and §7 step 3 as corrected on 2026-11-16), which
 * the independent oracle wrote from the specification text alone: the `open` rows through `assist`'s own reading of its
 * arguments ([AssistCommand.parse], [RecoverCommand.parse]) and of the typed lines ([RecoverCommand.openAndConfirm]),
 * the fleet `verify` rows through [EscrowVerify.verify] (a PASS for `ok`, `refused: <verdict>` otherwise: the tool says
 * no more), and the `assist` table through the whole run as the operator runs it ([runAssist]: the command line, the
 * clock where the tool checks it, the identity file's bytes, the typed seed and lines, to the answer token on standard
 * output). A refusal is read from the tool's `REFUSED (<verdict>)`; a refusal without a name, or an exception, is
 * reported as such.
 *
 * A row the code answers otherwise is listed in [KNOWN] with its finding, left out of the graded test. The rows of
 * findings since fixed are in [FIXED]: graded with every other row, and again by the test that names the finding.
 */
class AssistV3VectorTest {
    private val crypto = createCryptoProvider()
    private val v: JsonObject = Json.parseToJsonElement(vectorFile("escrow-v3.json").readText()).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.sOrNull(key: String): String? = get(key)?.takeIf { it !is JsonNull }?.jsonPrimitive?.content
    private fun JsonObject.o(key: String): JsonObject = getValue(key).jsonObject
    private fun JsonObject.flag(key: String): Boolean = get(key)?.jsonPrimitive?.booleanOrNull == true

    private val seed = Bytes.fromB64(v.o("sheet").s("seedB64"))
    private val org = crypto.boxKeypairFromSeed(seed)
    private val req = v.o("requestKey")
    private val files = v.o("identityFiles")

    private fun check(name: String): IdentityCheck = files.o(name).let { IdentityCheck(it.s("encryptedIdentitySeedB64"), it.s("identityPubB64")) }

    /** The command line `assist` is given: the row's arguments, absent ones left out. */
    private fun argv(a: Map<String, String?>, noAnchor: Boolean): List<String> = buildList {
        for ((flag, key) in listOf("--instance" to "instance", "--request" to "request", "--request-key" to "requestKey", "--request-code" to "requestCode",
            "--user" to "user", "--identity-fp" to "identityFp", "--identity-file" to "identityFile", "--email" to "email")) {
            a[key]?.let { add(flag); add(it) }
        }
        if (noAnchor) add("--no-identity-anchor")
    }

    private fun refusal(e: Throwable): JsonObject {
        val m = Regex("^REFUSED \\(([a-z_]+)\\)").find(e.message ?: "")
        return JsonObject(mapOf("verdict" to JsonPrimitive(if (e is RecoverRefused && m != null) m.groupValues[1] else "${e::class.simpleName}: ${e.message?.lineSequence()?.first()}")))
    }

    /** Parse, open and confirm, as `assist` does; [then] makes the answer from what was opened. */
    private fun run(a: Map<String, String?>, noAnchor: Boolean, ack: String?, confirmation: String?, sealedB64: String, then: (AssistOptions, io.silencelen.andvari.core.crypto.EscrowOpened) -> JsonObject): JsonObject = try {
        val opts = AssistCommand.parse(crypto, argv(a, noAnchor))
        val lines = ArrayDeque(listOfNotNull(if (opts.recover.unanchored) ack ?: "" else null, confirmation ?: ""))
        val opened = RecoverCommand.openAndConfirm(crypto, org, opts.recover, opts.email, check(opts.recover.identityFile), sealedB64, "the answer", { lines.removeFirstOrNull() }) { }
        then(opts, opened)
    } catch (e: RecoverRefused) {
        val m = Regex("this recovery copy is ([^ ]+)'s,", RegexOption.IGNORE_CASE).find(e.message ?: "")
        if (e.message?.startsWith("REFUSED (email_mismatch)") == true && m != null) {
            JsonObject(mapOf("verdict" to JsonPrimitive("email_mismatch"), "copyEmail" to JsonPrimitive(m.groupValues[1])))
        } else {
            refusal(e)
        }
    } catch (e: Exception) {
        refusal(e)
    }

    private fun requestArgs(): Map<String, String?> = mapOf(
        "instance" to req.s("instanceId"), "request" to req.s("requestId"), "requestKey" to req.s("rPubB64"), "requestCode" to req.s("requestCode"),
    )

    private fun openRow(row: JsonObject): JsonObject {
        val i = row.o("input")
        if (i.s("mode") == "verify") {
            val f = i.sOrNull("identityFile")?.let { files.o(it) }
            val r = EscrowVerify.verify(crypto, seed, listOf(EscrowDumpRow(i.s("user"), i.s("sealedB64"), i.sOrNull("dumpFingerprint"), null, f?.s("encryptedIdentitySeedB64"), f?.s("identityPubB64")))).single()
            val verdict = if (r.pass) "ok" else Regex("^refused: ([a-z_]+)").find(r.detail)?.groupValues?.get(1) ?: "unnamed: ${r.detail}"
            return JsonObject(mapOf("verdict" to JsonPrimitive(verdict)))
        }
        val a = requestArgs() + mapOf("user" to i.sOrNull("user"), "identityFp" to i.sOrNull("identityFp"), "identityFile" to i.sOrNull("identityFile"), "email" to i.sOrNull("email"))
        val user = i.sOrNull("user") ?: ""
        return run(a, i.flag("noIdentityAnchor"), i.sOrNull("unanchoredAck"), "RECOVER ${user.take(8)}", i.s("sealedB64")) { _, o ->
            val out = JsonObject(mapOf(
                "verdict" to JsonPrimitive("ok"), "userId" to JsonPrimitive(o.userId), "email" to JsonPrimitive(o.email), "emailB64" to JsonPrimitive(Bytes.toB64(o.email!!.encodeToByteArray())),
                "uvkB64" to JsonPrimitive(Bytes.toB64(o.uvk)), "identityKeyB64" to JsonPrimitive(Bytes.toB64(o.identityKey)), "anchored" to JsonPrimitive(o.anchored),
            ))
            o.wipe()
            out
        }
    }

    /**
     * The identity file at [path], as the row says (its `_about`): the row's `identityFileB64` when it has one; else the
     * download of the `identityFiles` entry named [path], carrying the row's copy; else a file that cannot be read.
     */
    private fun identityFileBytes(row: JsonObject, path: String): ByteArray {
        row.sOrNull("identityFileB64")?.let { return Bytes.fromB64(it) }
        val f = files[path]?.jsonObject ?: throw java.io.FileNotFoundException(path)
        return JsonObject(mapOf(
            "userId" to JsonPrimitive(f.s("userId")), "sealed" to JsonPrimitive(row.s("sealedB64")),
            "encryptedIdentitySeed" to JsonPrimitive(f.s("encryptedIdentitySeedB64")), "identityPub" to JsonPrimitive(f.s("identityPubB64")),
        )).toString().encodeToByteArray()
    }

    /** One `assist` row run as the operator runs it ([runAssist]), read back from what it printed. */
    private fun assistRow(row: JsonObject): JsonObject {
        val args = row.o("args")
        val a = args.mapValues { (_, e) -> e.takeIf { it !is JsonNull }?.jsonPrimitive?.content }
        val noAnchor = args.flag("noIdentityAnchor")
        val extra = row["extraArgs"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList()
        val typed = row.o("typed")
        val lines = ArrayDeque(listOfNotNull(if (noAnchor) typed.sOrNull("unanchoredAck") ?: "" else null, typed.sOrNull("confirmation") ?: ""))
        val out = StringBuilder()
        val err = StringBuilder()
        val io = AssistIo(
            readFile = { path, _ -> identityFileBytes(row, path) },
            readSecret = { row.sOrNull("seedTyped") ?: v.o("sheet").s("seedB64") },
            readLine = { lines.removeFirstOrNull() },
            out = { out.append(it) },
            err = { err.appendLine(it) },
            clock = { row.s("clock").toLong() },
        )
        val status = try {
            runAssist(crypto, argv(a, noAnchor) + extra, io)
        } catch (e: Throwable) {
            return JsonObject(mapOf("verdict" to JsonPrimitive("threw ${e::class.simpleName}: ${e.message?.lineSequence()?.first()}")))
        }
        if (status != 0) {
            val text = err.toString()
            val verdict = Regex("REFUSED \\(([a-z_]+)\\)").find(text)?.groupValues?.get(1)
                ?: return JsonObject(mapOf("verdict" to JsonPrimitive("exit $status with no named refusal: ${text.lineSequence().firstOrNull()}")))
            val copyEmail = Regex("this recovery copy is ([^ ]+)'s,", RegexOption.IGNORE_CASE).find(text)?.groupValues?.get(1)
            return if (verdict == "email_mismatch" && copyEmail != null) {
                JsonObject(mapOf("verdict" to JsonPrimitive(verdict), "copyEmail" to JsonPrimitive(copyEmail)))
            } else {
                JsonObject(mapOf("verdict" to JsonPrimitive(verdict)))
            }
        }
        // spec 04 §7 step 3.6: the last line on standard output is the token, andvari-answer:3:<id>:<key>:<hash>:<sealed>.
        val token = out.toString().trimEnd('\n').lineSequence().last()
        val parts = token.split(':')
        assertEquals(6, parts.size, "the token has six parts: $token")
        val sealed = Bytes.fromB64(parts[5])
        val frame = crypto.sealOpen(Bytes.fromB64(req.s("rPubB64")), Bytes.fromB64(req.s("rSecB64")), sealed)
        val statement = frame.copyOfRange(SignedStatement.STATEMENT_OFFSET, frame.size).decodeToString()
        val values = Json.parseToJsonElement(statement).jsonObject
        assertEquals(parts[4], AssistedRecovery.commitHashOf(crypto, values.s("commit")), "the token's hash is the commit inside")
        return JsonObject(mapOf(
            "verdict" to JsonPrimitive("ok"),
            "answer" to JsonObject(mapOf(
                "values" to JsonObject(values.filterKeys { it != "v" && it != "purpose" && it != "commit" }),
                "statementBytes" to JsonPrimitive(statement.length), "sealedBytes" to JsonPrimitive(sealed.size),
                "tokenHead" to JsonPrimitive(parts.take(4).joinToString(":") + ":"),
            )),
        ))
    }

    private fun differences(only: Set<String>? = null): List<String> = listOf("open", "assist").flatMap { table ->
        v.getValue(table).jsonArray.map { it.jsonObject }.mapNotNull { row ->
            val name = "$table/${row.s("name")}"
            if (only != null && name !in only) return@mapNotNull null
            if (only == null && name in KNOWN) return@mapNotNull null
            val want = row.o("expect")
            val got = if (table == "open") openRow(row) else assistRow(row)
            // The fleet verify's output is PASS or FAIL with a verdict: only the verdict is compared.
            val wanted: JsonElement = if (table == "open" && row.o("input").s("mode") == "verify") JsonObject(mapOf("verdict" to want.getValue("verdict"))) else want
            if (got != wanted) "$name: the oracle expects $wanted, the tool answers $got" else null
        }
    }

    @Test
    fun theTool_everyOpenAndAssistRow() {
        val d = differences()
        assertTrue(d.isEmpty(), d.joinToString("\n"))
        assertTrue(v.getValue("assist").jsonArray.size >= 62 && v.getValue("open").jsonArray.size >= 95)
    }

    private fun fixed(finding: String) = differences(FIXED.filterValues { it == finding }.keys)

    @Test
    fun theKnownFindingsNameRowsThatExist() {
        val names = listOf("open", "assist").flatMap { t -> v.getValue(t).jsonArray.map { "$t/${it.jsonObject.s("name")}" } }.toSet()
        for (k in KNOWN.keys + FIXED.keys) assertTrue(k in names, k)
    }

    /** V4-C1, fixed: the fleet verify names a row without its identity file `identity_check_required` (spec 04 §4 step 0.3, step 9). */
    @Test
    fun fixed_V4_C1_verifyNamesTheMissingIdentityFile() {
        val d = fixed(C1)
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    /** V4-C2, fixed: `--request` with white space around it is `bad_request_id`, before anything is read (spec 04 §7 step 3.1). */
    @Test
    fun fixed_V4_C2_aRequestIdWithWhiteSpaceIsRefusedByItsName() {
        val d = fixed(C2)
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    /** V4-C3, fixed: `--request-key` with white space around it is `bad_request_key` (spec 04 §7 step 3.1: a canonical b64_32). */
    @Test
    fun fixed_V4_C3_aRequestKeyWithWhiteSpaceIsRefusedByItsName() {
        val d = fixed(C3)
        assertTrue(d.isEmpty(), d.joinToString("\n"))
    }

    private companion object {
        const val C1 = "V4-C1"
        const val C2 = "V4-C2"
        const val C3 = "V4-C3"

        /** `<table>/<row>` → a finding the code still shows: such a row is left out of the graded test. None is open. */
        val KNOWN: Map<String, String> = emptyMap()

        /** `<table>/<row>` → the finding it showed, since fixed in the code: graded with every row, and again by its own test. */
        val FIXED: Map<String, String> = mapOf(
            "open/verify-identity-file-absent" to C1,
            "assist/request-with-a-space-after" to C2,
            "assist/request-key-with-a-space-before" to C3,
        )

        /** spec/test-vectors, found from the module's directory upwards. */
        fun vectorFile(name: String): File {
            var dir: File? = File("").absoluteFile
            while (dir != null) {
                val f = File(dir, "spec/test-vectors/$name")
                if (f.isFile) return f
                dir = dir.parentFile
            }
            error("spec/test-vectors/$name not found above ${File("").absolutePath}")
        }
    }
}
