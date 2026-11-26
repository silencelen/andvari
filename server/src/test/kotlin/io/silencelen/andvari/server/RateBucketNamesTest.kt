package io.silencelen.andvari.server

import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.Caller
import io.silencelen.andvari.core.model.wire.WireRoute
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Every rate bucket has a name of its own (spec 03 §0.2). The limiter keeps one window per name and key, and resets and
 * limits each call by that call's own window and limit, so two definitions under one name undo each other: the assisted
 * recovery verify (20 an hour per IP) was given the kit verify's name (`recovery_verify`, 5 a minute per IP), and one
 * kit verify a minute let the assisted route serve about 190 calls in ten minutes from one address, while five
 * assisted verifies refused the kit verify. A name is therefore defined exactly once in the server's sources, and
 * routes that share a budget draw on that one definition ([SharedBuckets]).
 */
class RateBucketNamesTest {
    private val post = HttpMethod.Post

    private class Site(val file: String, val line: Int, val name: String, val factory: String, val limit: String) {
        override fun toString() = "$file:$line $factory(\"$name\", $limit)"
    }

    private val factory = Regex(
        """\bBucket\.(ipPerMinute|ipPerHour|ipPerDay|devicePerMinute|devicePerHour|devicePerDay|givenPerDay)\(\s*([^,]*?)\s*,\s*([^)]*?)\s*\)""",
    )
    private val constructor = Regex("""\bBucket\(""")

    /** The bucket definitions in the server's sources, and every line that builds a bucket some other way. */
    private fun scan(): Pair<List<Site>, List<String>> {
        val dir = listOf(File("src/main/kotlin"), File("server/src/main/kotlin")).first { it.isDirectory }
        val sites = ArrayList<Site>()
        val strays = ArrayList<String>()
        dir.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.forEach { f ->
            f.readLines().forEachIndexed { i, line ->
                val at = "${f.name}:${i + 1}"
                // The class itself and its six factories are the only direct constructor calls.
                if (constructor.containsMatchIn(line) && !(f.name == "Api.kt" && (line.contains("class Bucket(") || line.contains("= Bucket(name, n,")))) strays += "$at: $line"
                for (m in factory.findAll(line)) {
                    val arg = m.groupValues[2]
                    val literal = Regex("^\"([a-z0-9_]+)\"$").find(arg)?.groupValues?.get(1)
                    when {
                        literal != null -> sites += Site(f.name, i + 1, literal, m.groupValues[1], m.groupValues[3])
                        // The default buckets of spec 03 §0.1, one per route by the route's name (checked below).
                        f.name == "Api.kt" && arg.matches(Regex("^\"(reauth|read|write)_\\$\\{r\\.name\\.lowercase\\(\\)}\"$")) -> {}
                        else -> strays += "$at: a bucket whose name is not a literal: $line"
                    }
                }
            }
        }
        return sites to strays
    }

    @Test
    fun everyBucketNameIsDefinedOnce_withOneLimitAndOneWindow() {
        val (sites, strays) = scan()
        assertTrue(strays.isEmpty(), "buckets built outside the scan's reach:\n" + strays.joinToString("\n"))
        assertTrue(sites.size > 40, "the scan found ${sites.size} definitions; it no longer reads the sources")
        val byName = sites.groupBy { it.name }
        // Two definitions under one name, whether their limits and windows agree or not, are two budgets that one
        // limiter key mixes. A shared budget is one definition in SharedBuckets, drawn on by each route.
        val twice = byName.filterValues { it.size > 1 }
        assertTrue(twice.isEmpty(), "bucket names defined more than once:\n" + twice.values.joinToString("\n") { it.joinToString("; ") })
        val windows = byName.filterValues { list -> list.map { it.factory to it.limit }.toSet().size > 1 }
        assertTrue(windows.isEmpty(), "a name with two limits or windows: $windows")
        // The default buckets, one per route, never take a name a route's own bucket has.
        val defaults = WireRoute.entries.map { defaultBucket(it).name }
        assertEquals(defaults.size, defaults.toSet().size, "two routes with one default bucket name")
        val clash = defaults.toSet().intersect(byName.keys)
        assertTrue(clash.isEmpty(), "default bucket names that a named bucket also uses: $clash")
        // The two verify routes of recovery have names of their own.
        assertEquals("ipPerMinute", byName.getValue("recovery_verify").single().factory)
        assertEquals("ipPerHour", byName.getValue("recovery_request_verify").single().factory)
        assertEquals("recovery_request_verify", Assisted.VERIFY_BUCKET.name)
    }

    /**
     * The key each bucket uses (spec 03 §0.2): a route that needs a session spends only its device's budget, with a
     * ceiling per account of four times it, and a route that needs none spends its caller's address's. Kept per
     * account, a session in the wrong hands could spend the budget of a route the owner needs on every device (five
     * requests an hour kept the owner from deleting the account). No bucket is kept by the account alone any more, and
     * the only buckets with a key of their own are the three per typed address (since 2026-11-17 the ceiling of requests
     * taken with a mailbox value is the third).
     */
    @Test
    fun everyBucketOfARouteThatNeedsASession_isKeptPerDevice_withItsCeilingPerAccount() {
        assertEquals(listOf(BucketKey.IP, BucketKey.DEVICE, BucketKey.GIVEN), BucketKey.entries.toList(), "a bucket key kept by the account alone")
        val (sites, _) = scan()
        val keyOf = mapOf(
            "ipPerMinute" to BucketKey.IP, "ipPerHour" to BucketKey.IP, "ipPerDay" to BucketKey.IP,
            "devicePerMinute" to BucketKey.DEVICE, "devicePerHour" to BucketKey.DEVICE, "devicePerDay" to BucketKey.DEVICE,
            "givenPerDay" to BucketKey.GIVEN,
        )
        assertEquals(setOf("signup_start_address", "recovery_request_address", "recovery_request_mailbox"), sites.filter { keyOf[it.factory] == BucketKey.GIVEN }.map { it.name }.toSet())
        // The buckets that routes share, read by value.
        val named = mapOf(
            "SharedBuckets.TOTP_VERIFY" to SharedBuckets.TOTP_VERIFY, "SharedBuckets.DEVICE_LINK_POLL" to SharedBuckets.DEVICE_LINK_POLL,
            "SharedBuckets.VAULT_DESTRUCTIVE" to SharedBuckets.VAULT_DESTRUCTIVE, "SharedBuckets.RECOVERY_COMMIT" to SharedBuckets.RECOVERY_COMMIT,
            "SharedBuckets.login(s.config)" to SharedBuckets.login(TestKit.config()), "Assisted.VERIFY_BUCKET" to Assisted.VERIFY_BUCKET,
        )
        for (b in named.values + WS_BEARER_BUCKET + REFRESH_SESSION_BUCKET + REFRESH_ADDRESS_BUCKET + WireRoute.entries.map { defaultBucket(it) }) {
            assertEquals(if (b.key == BucketKey.DEVICE) b.limit * 4 else null, b.accountCeiling, "${b.name}: its ceiling per account")
        }
        assertEquals(BucketKey.DEVICE, WS_BEARER_BUCKET.key)
        // Every route registered with a bucket of its own, or with the default: the key follows from who may call.
        val dir = listOf(File("src/main/kotlin"), File("server/src/main/kotlin")).first { it.isDirectory }
        val withBucket = Regex("""\bapi\(WireRoute\.([A-Z_]+), s, (.+?)\) \{""")
        val withDefault = Regex("""\bapi\(WireRoute\.([A-Z_]+), s\) \{""")
        val seen = HashSet<WireRoute>()
        val ownDraw = HashSet<WireRoute>()
        val wrong = ArrayList<String>()
        dir.walkTopDown().filter { it.isFile && it.name.endsWith(".kt") }.forEach { f ->
            f.readLines().forEachIndexed { i, line ->
                val at = "${f.name}:${i + 1}"
                withDefault.find(line)?.let { m ->
                    val r = WireRoute.valueOf(m.groupValues[1]); seen += r
                    val want = if (r.caller == Caller.NONE) null else BucketKey.DEVICE
                    val got = if (r.caller == Caller.NONE) null else defaultBucket(r).key
                    if (want != got) wrong += "$at: ${r.name} default bucket keyed $got"
                }
                withBucket.find(line)?.let { m ->
                    val r = WireRoute.valueOf(m.groupValues[1]); seen += r
                    val arg = m.groupValues[2]
                    val got: BucketKey? = when {
                        arg == "bucket = null" -> { ownDraw += r; return@let } // the handler draws its own (checked below by its definition)
                        factory.matches(arg) -> keyOf.getValue(factory.find(arg)!!.groupValues[1])
                        arg in named -> named.getValue(arg).key
                        else -> { wrong += "$at: a route bucket this test cannot read: $arg"; return@let }
                    }
                    val want = if (r.caller == Caller.NONE) BucketKey.IP else BucketKey.DEVICE
                    if (got != want) wrong += "$at: ${r.name} (${r.caller}) keyed $got, not $want"
                }
                // A bucket drawn in a handler with a key of its own is a given one, and only a given one takes a key.
                if (line.contains("keySuffix =") != line.contains("take(Bucket.givenPerDay(")) wrong += "$at: a key of its own on a bucket that is not a given one: $line"
            }
        }
        assertTrue(wrong.isEmpty(), wrong.joinToString("\n"))
        assertTrue(seen.size > 60, "the scan found ${seen.size} routes; it no longer reads the sources")
        // The handlers that draw their own, each read below by its definitions.
        assertEquals(setOf(WireRoute.LOG_APPEND, WireRoute.SIGNUP_START, WireRoute.REFRESH, WireRoute.ACCOUNT_DELETE), ownDraw, "routes whose handler draws its own bucket")
        // The account deletion draws its own so that a refusal for a moved log can give it back (rule of 2026-11-17): per
        // device, with its ceiling.
        assertEquals(Bucket("account_delete", 5, Clock.HOUR_MS, BucketKey.DEVICE), ACCOUNT_DELETE_BUCKET)
        assertEquals(20, ACCOUNT_DELETE_BUCKET.accountCeiling)
        // The log's kinds (a session route) are per device.
        for (kind in listOf("genesis", "offer", "delete", "remove", "add", "role", "restore")) assertEquals(BucketKey.DEVICE, VaultLogs.bucketOf(kind).key, kind)
        // Row 11 needs no session, yet a token that names a live session draws that session's device with its ceiling
        // (rule of 2026-11-17), and every other refresh the caller's address, each under a name of its own.
        assertEquals(Bucket("refresh", 30, Clock.MINUTE_MS, BucketKey.IP), REFRESH_ADDRESS_BUCKET)
        assertEquals(Bucket("refresh_session", 30, Clock.MINUTE_MS, BucketKey.DEVICE), REFRESH_SESSION_BUCKET)
        assertEquals(120, REFRESH_SESSION_BUCKET.accountCeiling)
    }

    @Test
    fun theKitVerifyAndTheRequestVerify_neverUndoEachOthersLimits() = testApplication {
        val clock = MutableClock(1_800_000_000_000L)
        val s = TestKit.services(clock = clock)
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val ip = "10.9.9.9"
        val requestId = Bytes.toB64(ByteArray(16)) // no request has it; the answer is the uniform bad_code
        var n = 0
        // A new address each time, so the address's own back-off never answers in place of the IP bucket.
        fun kitBody() = """{"email":"nobody${n++}@example.com","recoveryAuthKey":"${b32()}"}"""
        suspend fun assisted() = c.call(post, "/api/v1/recovery/requests/$requestId/verify", """{"code":"000000"}""", ip = ip)
        suspend fun kit() = c.call(post, "/api/v1/recovery/self/verify", kitBody(), ip = ip)
        // The smallest sequence that showed it: 20 assisted verifies, a minute's wait, one kit verify, then more
        // assisted verifies. The assisted bucket is 20 an hour, so the 21st and every later one in the hour is refused.
        repeat(20) { i -> assertEquals("bad_code", assisted().errorCode(), "assisted verify ${i + 1}") }
        assertEquals(429, assisted().status.value)
        clock.advance(61_000)
        val k = kit()
        assertEquals(401, k.status.value, k.bodyAsText())
        repeat(19) { i -> assertEquals(429, assisted().status.value, "assisted verify after the kit's, ${i + 1}") }
        // The other way: the assisted verifies never refuse the kit verify, which allows 5 a minute per IP and nothing else.
        val other = "10.9.9.10"
        repeat(5) { assertEquals("bad_code", c.call(post, "/api/v1/recovery/requests/$requestId/verify", """{"code":"000000"}""", ip = other).errorCode()) }
        repeat(5) { i ->
            val r = c.call(post, "/api/v1/recovery/self/verify", kitBody(), ip = other)
            assertEquals(401, r.status.value, "kit verify ${i + 1}: ${r.bodyAsText()}")
        }
        assertEquals(429, c.call(post, "/api/v1/recovery/self/verify", kitBody(), ip = other).status.value)
    }
}
