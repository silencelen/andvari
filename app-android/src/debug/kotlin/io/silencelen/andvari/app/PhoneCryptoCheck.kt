package io.silencelen.andvari.app

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.UsageKey
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * The test build only (src/debug): the specification's crypto test vectors, run on the phone through the phone's own
 * native libsodium, from a screen in Settings. It is the same set of rows the instrumented test
 * (src/androidTest, AndroidCryptoVectorsTest) grades, for a person with the phone in hand and no computer attached:
 * one tap, then "N of N rows passed", or the first failing row's name. Nothing secret is shown: a row's name, never
 * its values.
 *
 * The vector files are the debug build's assets only (the module's build script copies the five it needs out of
 * spec/test-vectors); a release build has neither this file nor them (PhoneCryptoCheckTest).
 */
internal object PhoneCryptoCheck {
    /** The vector files the rows read, in spec/test-vectors. */
    val FILES: List<String> = listOf("kdf.json", "envelope.json", "seal.json", "sharedgrant.json", "usagekey.json")

    class Outcome(val passed: Int, val total: Int, val firstFailure: String?)

    private class Row(val name: String, val check: () -> Boolean)

    /** Runs every row with [crypto] over the files [read] gives by name. A row that throws, or answers wrong, fails. */
    fun run(crypto: CryptoProvider, read: (String) -> String): Outcome {
        val rows = rows(crypto) { name -> Json.parseToJsonElement(read(name)).jsonObject }
        var passed = 0
        var first: String? = null
        for (r in rows) {
            val ok = try {
                r.check()
            } catch (_: Exception) {
                false
            }
            if (ok) passed++ else if (first == null) first = r.name
        }
        return Outcome(passed, rows.size, first)
    }

    private fun JsonObject.s(k: String): String = getValue(k).jsonPrimitive.content
    private fun JsonObject.b(k: String): ByteArray = Bytes.fromB64(s(k))
    private fun JsonObject.arr(k: String): List<JsonObject> = getValue(k).jsonArray.map { it.jsonObject }
    private fun JsonObject.obj(k: String): JsonObject = getValue(k).jsonObject
    private fun JsonObject.i(k: String): Int = getValue(k).jsonPrimitive.int
    private fun JsonObject.l(k: String): Long = getValue(k).jsonPrimitive.long
    private fun JsonObject.params(k: String): KdfParams = obj(k).let { KdfParams(v = it.i("v"), alg = it.s("alg"), ops = it.l("ops"), memBytes = it.l("memBytes")) }

    private fun refuses(block: () -> Unit): Boolean = try {
        block()
        false
    } catch (_: CryptoException) {
        true
    }

    private fun rows(crypto: CryptoProvider, load: (String) -> JsonObject): List<Row> {
        val out = mutableListOf<Row>()
        val kdf = load("kdf.json")
        kdf.arr("argon2id").forEachIndexed { n, c ->
            out += Row("kdf argon2id ${n + 1}") {
                c.b("outB64").contentEquals(crypto.argon2id(c.s("passwordUtf8").encodeToByteArray(), c.b("saltB64"), c.i("outLen"), c.l("ops"), c.l("memBytes")))
            }
        }
        kdf.arr("hkdf").forEachIndexed { n, c ->
            out += Row("kdf hkdf ${n + 1}") {
                c.b("okmB64").contentEquals(Hkdf.sha256(crypto, c.b("ikmB64"), ByteArray(0), c.s("infoUtf8").encodeToByteArray(), c.i("len")))
            }
        }
        kdf.arr("chain").forEachIndexed { n, c ->
            out += Row("kdf chain ${n + 1}") {
                val mk = Keys.masterKey(crypto, c.s("passwordUtf8"), c.b("saltB64"), c.params("kdfParams"))
                c.b("mkB64").contentEquals(mk) && c.b("authKeyB64").contentEquals(Keys.authKey(crypto, mk)) &&
                    c.b("wrapKeyB64").contentEquals(Keys.wrapKey(crypto, mk))
            }
        }
        val env = load("envelope.json")
        env.arr("seal").forEachIndexed { n, c ->
            out += Row("envelope seal ${n + 1}") {
                val ad = c.s("adUtf8").encodeToByteArray()
                c.b("envelopeB64").contentEquals(Envelope.sealWithNonce(crypto, c.b("keyB64"), c.b("nonceB64"), c.b("plaintextB64"), ad)) &&
                    c.b("plaintextB64").contentEquals(Envelope.open(crypto, c.b("keyB64"), c.b("envelopeB64"), ad))
            }
        }
        env.arr("reject").forEachIndexed { n, c ->
            out += Row("envelope refuse ${n + 1}") {
                refuses { Envelope.open(crypto, c.b("keyB64"), c.b("envelopeB64"), c.s("adUtf8").encodeToByteArray()) }
            }
        }
        val seal = load("seal.json")
        out += Row("sealed box keys") {
            val kp = crypto.boxKeypairFromSeed(seal.b("recoverySeedB64"))
            seal.b("recoveryPubB64").contentEquals(kp.publicKey) && seal.b("recoveryPrivB64").contentEquals(kp.privateKey) &&
                seal.s("fingerprint") == Escrow.fingerprint(crypto, kp.publicKey) &&
                seal.s("shortFingerprint") == Escrow.shortFingerprint(crypto, kp.publicKey)
        }
        seal.arr("open").forEachIndexed { n, c ->
            out += Row("sealed box open ${n + 1}") {
                val kp = crypto.boxKeypairFromSeed(seal.b("recoverySeedB64"))
                c.b("plaintextB64").contentEquals(crypto.sealOpen(kp.publicKey, kp.privateKey, c.b("sealedB64")))
            }
        }
        out += Row("sealed box escrow") {
            val kp = crypto.boxKeypairFromSeed(seal.b("recoverySeedB64"))
            val e = seal.obj("escrowUvk")
            val payload = Json.parseToJsonElement(crypto.sealOpen(kp.publicKey, kp.privateKey, e.b("sealedB64")).decodeToString()).jsonObject
            payload.s("userId") == e.s("userId") && payload.s("keyType") == Escrow.KEY_TYPE_UVK &&
                Bytes.fromB64(payload.s("key")).contentEquals(e.b("uvkB64"))
        }
        out += Row("sealed box refuse a wrong key") {
            val r = seal.obj("rejectWrongKey")
            val wrong = crypto.boxKeypairFromSeed(r.b("wrongSeedB64"))
            refuses { crypto.sealOpen(wrong.publicKey, wrong.privateKey, r.b("sealedB64")) }
        }
        val grant = load("sharedgrant.json")
        out += Row("shared grant open") {
            val kp = crypto.boxKeypairFromSeed(grant.b("memberSeedB64"))
            val vaultId = grant.s("vaultId")
            grant.b("memberIdentityPubB64").contentEquals(kp.publicKey) &&
                grant.s("fingerprint") == SharedGrant.fingerprint(crypto, kp.publicKey) &&
                grant.s("shortFingerprint") == SharedGrant.shortFingerprint(crypto, kp.publicKey) &&
                grant.s("payloadUtf8").encodeToByteArray().contentEquals(SharedGrant.canonicalPayload(vaultId, grant.b("vkB64"))) &&
                grant.b("vkB64").contentEquals(SharedGrant.open(crypto, kp.publicKey, kp.privateKey, vaultId, grant.b("sealedB64")))
        }
        for (k in listOf("rejectVaultMismatch", "rejectVkLength", "rejectVersion")) {
            out += Row("shared grant refuse ${k.removePrefix("reject")}") {
                val kp = crypto.boxKeypairFromSeed(grant.b("memberSeedB64"))
                val r = grant.obj(k)
                refuses { SharedGrant.open(crypto, kp.publicKey, kp.privateKey, r.s("expectedVaultId"), r.b("sealedB64")) }
            }
        }
        out += Row("shared grant own seal") {
            val kp = crypto.boxKeypairFromSeed(grant.b("memberSeedB64"))
            val own = SharedGrant.seal(crypto, kp.publicKey, grant.s("vaultId"), grant.b("vkB64"))
            grant.b("vkB64").contentEquals(SharedGrant.open(crypto, kp.publicKey, kp.privateKey, grant.s("vaultId"), own))
        }
        val usage = load("usagekey.json")
        out += Row("usage key") {
            usage.s("usageKeyB64") == Bytes.toB64(UsageKey.usageKey(crypto, usage.b("vkB64"))) &&
                usage.s("adUtf8") == Ad.usage(usage.s("adUserId")).decodeToString()
        }
        return out
    }
}

/** The test build's entry in Settings. */
internal val phoneCheck: PhoneCheckEntry? = PhoneCheckEntry { onClose -> PhoneCryptoCheckScreen(onClose) }

@Composable
private fun PhoneCryptoCheckScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    var outcome by remember { mutableStateOf<PhoneCryptoCheck.Outcome?>(null) }
    LaunchedEffect(Unit) {
        outcome = withContext(Dispatchers.Default) {
            PhoneCryptoCheck.run(createCryptoProvider()) { name -> context.assets.open(name).bufferedReader().use { it.readText() } }
        }
    }
    Column {
        Text("Test build: this phone's crypto against the specification's test vectors", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(12.dp))
        when (val o = outcome) {
            null -> LinearProgressIndicator()
            else -> {
                Text("${o.passed} of ${o.total} rows passed", style = MaterialTheme.typography.headlineSmall)
                o.firstFailure?.let { Text("First failing row: $it", color = MaterialTheme.colorScheme.error) }
            }
        }
        Spacer(Modifier.height(12.dp))
        OutlinedButton(onClick = onClose) { Text("Close") }
    }
}
