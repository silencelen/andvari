package io.silencelen.andvari.cli

import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject

/**
 * `seed` and `check` for the App Review demo accounts (design §9.5 R11): ordinary member accounts, seeded and checked
 * over loopback by a timer on the instance host. `seed` adds the demo items the personal vault lacks (by name, so a
 * rerun adds nothing); `check` signs in, syncs and fails unless every demo item is there and opens.
 */
class Demo(private val c: Ctx, private val s: AccountSession) {
    private fun name(i: Int) = "Demo login ${i + 1}"

    private fun doc(i: Int) = buildJsonObject {
        put("type", JsonPrimitive("login"))
        put("name", JsonPrimitive(name(i)))
        put("notes", JsonPrimitive("A sample item for reviewers."))
        put("login", buildJsonObject {
            put("username", JsonPrimitive("reviewer${i + 1}"))
            put("password", JsonPrimitive("Sample-Password-${i + 1}"))
            put("uris", buildJsonArray { add(JsonPrimitive("https://example.com/${i + 1}")) })
        })
    }

    private suspend fun present(): Set<String> {
        if (s.sync() !is SyncOutcome.Synced) throw CliError("sync failed")
        val v = s.personalVaultId ?: throw CliError("this account has no personal vault in force")
        return s.items(v).mapNotNull { (it.doc["name"] as? JsonPrimitive)?.content }.toSet()
    }

    suspend fun seed(n: Int) {
        val have = present()
        val v = s.personalVaultId!!
        var added = 0
        for (i in 0 until n) if (name(i) !in have) {
            val (_, err) = s.putItem(v, doc(i))
            if (err != null) throw CliError("seeding ${name(i)} failed: $err")
            added++
        }
        c.term.say("seeded: $added added, ${n - added} already there")
    }

    suspend fun check(n: Int) {
        val have = present()
        val missing = (0 until n).map(::name).filter { it !in have }
        if (missing.isNotEmpty()) throw CliError("check failed: missing ${missing.joinToString()}")
        c.term.say("check ok: ${s.held.emailNorm} signs in, syncs and opens all $n demo items")
    }
}
