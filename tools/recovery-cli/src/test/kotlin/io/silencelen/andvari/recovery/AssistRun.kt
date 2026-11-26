package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AdminEscrowDownload
import io.silencelen.andvari.core.trust.AssistedRecovery
import kotlinx.serialization.json.Json

/**
 * `assist` run as the operator runs it ([runAssist]), against a terminal of its own that records what was read, asked
 * and produced: one member's copy under one request, an anchored command line, and the lines the operator types.
 */
internal class AssistRun {
    val crypto = createCryptoProvider()
    val seed: ByteArray = crypto.randomBytes(32)
    val org = crypto.boxKeypairFromSeed(seed)
    val instanceId = "12345678-1234-4234-8234-123456789abc"
    val requestId: String = Bytes.toB64(crypto.randomBytes(16))
    val request = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    val rPub: String = Bytes.toB64(request.publicKey)
    val code = AssistedRecovery.requestCode(crypto, request.publicKey)
    val member = Member(crypto, org.publicKey, "ann@family.example")

    /** The command line, each value replaceable by name (the copy, `--copy`, is the positional argument, absent by default). */
    fun args(vararg over: Pair<String, String>): List<String> {
        val v = linkedMapOf(
            "--instance" to instanceId, "--request" to requestId, "--request-key" to rPub, "--request-code" to code,
            "--email" to member.email, "--user" to member.userId, "--identity-fp" to member.identityFp.take(32), "--identity-file" to "f.json",
        )
        var copy: String? = null
        for ((k, value) in over) if (k == "--copy") copy = value else v[k] = value
        return v.flatMap { (k, value) -> listOf(k, value) } + listOfNotNull(copy)
    }

    /** What one run did. */
    class Seen {
        val filesRead = ArrayList<String>()
        var secretsAsked = 0
        val prompts = ArrayList<String>()

        /** Every line said on standard error and every seed prompt, in the order they came ("ask: " before a prompt). */
        val events = ArrayList<String>()
        var linesAsked = 0
        val out = StringBuilder()
        val err = StringBuilder()
        var status = -1
        override fun toString() = "status $status, files $filesRead, secrets $secretsAsked, lines $linesAsked\nout: $out\nerr: $err"
    }

    var download: AdminEscrowDownload = member.download
    var fileBytes: (() -> ByteArray)? = null
    var clock: Long = 1_794_858_966_854L

    /** Files by path, read before [fileBytes] and the download (the `--instance-file`, for one). */
    val files = HashMap<String, ByteArray>()

    /** Seeds pasted in turn, when a run asks for more than one; the prompts are kept in [Seen.prompts]. */
    var seedLines: List<String>? = null

    fun run(args: List<String>, typed: List<String> = listOf("RECOVER ${member.userId.take(8)}"), seedLine: String = Bytes.toB64(seed)): Seen {
        val seen = Seen()
        val lines = typed.iterator()
        val seeds = seedLines?.iterator()
        val io = AssistIo(
            readFile = { path, _ ->
                seen.filesRead += path
                files[path] ?: fileBytes?.invoke() ?: Json.encodeToString(AdminEscrowDownload.serializer(), download).encodeToByteArray()
            },
            readSecret = { prompt ->
                seen.secretsAsked++
                seen.prompts += prompt
                seen.events += "ask: $prompt"
                if (seeds == null) seedLine else if (seeds.hasNext()) seeds.next() else null
            },
            readLine = { seen.linesAsked++; if (lines.hasNext()) lines.next() else null },
            out = { seen.out.append(it) },
            err = { seen.err.appendLine(it); seen.events += it },
            clock = { clock },
        )
        seen.status = runAssist(crypto, args, io)
        return seen
    }
}
