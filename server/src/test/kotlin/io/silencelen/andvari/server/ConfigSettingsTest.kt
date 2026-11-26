package io.silencelen.andvari.server

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A setting the server cannot read stops it at its start, whatever the setting (decided on 2026-11-17): a value that is
 * present and cannot be read is refused with a line that names the setting and the value; an unset or blank value takes
 * the default, except where a blank value had a meaning of its own (the two lists: blank is "none"). Before, a number that was not a number or out of its range, and a switch that was neither on nor off,
 * quietly took the default (with a warning at most, fatal only under `ANDVARI_STRICT_ENV=1`): "yes" for
 * `ANDVARI_TOTP_REQUIRED` turned required two-step sign-in OFF, and a sign-up cap meant lower could be raised. Each
 * setting is checked by name below; the first test shows that the lists cover every setting the server reads.
 */
class ConfigSettingsTest {
    private val base = mapOf("ANDVARI_CANONICAL_ORIGIN" to "http://127.0.0.1:8080", "ANDVARI_ENUM_SECRET" to "A".repeat(43))

    private fun start(vararg set: Pair<String, String>): Config = (base + set).let { env -> Config.fromEnv { env[it] } }

    private fun refused(vararg set: Pair<String, String>): String = assertFailsWith<ConfigError>("refused: ${set.toList()}") { start(*set) }.message!!

    /** Settings whose value is text taken as written (blank is unset), and the three secrets and the key read as base64url. */
    private val text = setOf(
        "ANDVARI_HOST", "ANDVARI_DB", "ANDVARI_BLOB_DIR", "ANDVARI_WEB_DIR", "ANDVARI_DOWNLOADS_DIR", "ANDVARI_CANONICAL_ORIGIN",
        "ANDVARI_INSTANCE_NAME", "ANDVARI_SELFHOST_DOCS_URL", "ANDVARI_RECOVERY_FINGERPRINT", "ANDVARI_SIGNUP_BLOCKLIST",
        "ANDVARI_TRUSTED_IP_HEADERS", "ANDVARI_SMTP_HOST", "ANDVARI_SMTP_USER", "ANDVARI_SMTP_PASS", "ANDVARI_SMTP_FROM",
        "ANDVARI_GRAPH_TENANT", "ANDVARI_GRAPH_CLIENT_ID", "ANDVARI_GRAPH_CLIENT_SECRET", "ANDVARI_GRAPH_SENDER",
        "ANDVARI_MAIL_SINK", "ANDVARI_TEST_CLOCK",
    )
    private val base64 = setOf("ANDVARI_ENUM_SECRET", "ANDVARI_SIGNUP_SECRET", "ANDVARI_RECOVERY_PUBKEY")

    @Test
    fun everySettingTheServerReads_isInOneOfTheLists() {
        val listed = Config.NUM_RANGES.keys + Config.BOOL_ENV + Config.ENUM_ENV.keys + text + base64 + "ANDVARI_TRUSTED_PROXY_CIDRS"
        assertEquals(Config.KNOWN_ENV, listed)
    }

    @Test
    fun aNumberThatIsNotOne_orOutsideItsRange_stopsTheStart_andBlankIsTheDefault() {
        for ((name, range) in Config.NUM_RANGES) {
            val word = refused(name to "twelve")
            assertTrue("$name='twelve'" in word && "not a whole number" in word, "$name: $word")
            val above = refused(name to "${range.last + 1}")
            assertTrue("$name=${range.last + 1}" in above && "outside the range" in above, "$name: $above")
            if (range.first > Long.MIN_VALUE) {
                val below = refused(name to "${range.first - 1}")
                assertTrue("$name=${range.first - 1}" in below, "$name: $below")
            }
            start(name to "")
            start(name to "  ")
        }
        // The figures are taken as set, and blank is the default.
        assertEquals(12L, start("ANDVARI_SIGNUP_CAP" to " 12 ").signupCap)
        assertEquals(200L, start("ANDVARI_SIGNUP_CAP" to "").signupCap)
        assertEquals(9090, start("ANDVARI_PORT" to "9090").port)
    }

    @Test
    fun aSwitchThatIsNeitherOnNorOff_stopsTheStart_andBlankIsTheDefault() {
        for (name in Config.BOOL_ENV) {
            val yes = refused(name to "yes")
            assertTrue("$name='yes'" in yes && "neither on nor off" in yes, "$name: $yes")
            start(name to "")
        }
        // The case the decision names: required two-step sign-in is never turned off by a word the server cannot read.
        assertTrue("ANDVARI_TOTP_REQUIRED='yes'" in refused("ANDVARI_TOTP_REQUIRED" to "yes"))
        assertEquals(true, start("ANDVARI_TOTP_REQUIRED" to " TRUE ").totpRequired)
        assertEquals(true, start("ANDVARI_TOTP_REQUIRED" to "1").totpRequired)
        assertEquals(false, start("ANDVARI_TOTP_REQUIRED" to "0").totpRequired)
        assertEquals(false, start("ANDVARI_TOTP_REQUIRED" to "").totpRequired)
        assertEquals(true, start("ANDVARI_OFFLINE_CACHE_ALLOWED" to " ").offlineCacheAllowedFloor)
    }

    @Test
    fun aChoiceOffItsList_stopsTheStart_andBlankIsTheDefault() {
        for (name in Config.ENUM_ENV.keys) {
            val bogus = refused(name to "bogus")
            assertTrue("$name='bogus'" in bogus, "$name: $bogus")
            start(name to "")
        }
        assertEquals("links", start("ANDVARI_SIGNUP_MODE" to " ").signupMode)
        assertEquals("closed", start("ANDVARI_SIGNUP_MODE" to "closed").signupMode)
        assertEquals("members", start("ANDVARI_REGISTER_LINKS" to "").registerLinks)
    }

    @Test
    fun aProxyEntryThatIsNoAddressBlock_stopsTheStart_insteadOfBeingDropped() {
        val bad = refused("ANDVARI_TRUSTED_PROXY_CIDRS" to "10.0.0.0/8, nonsense")
        assertTrue("ANDVARI_TRUSTED_PROXY_CIDRS entry 'nonsense'" in bad, bad)
        assertEquals(listOf("10.0.0.0/8", "fd00::/8"), start("ANDVARI_TRUSTED_PROXY_CIDRS" to "10.0.0.0/8, fd00::/8").trustedProxyCidrs)
        assertEquals(listOf("127.0.0.0/8", "::1/128"), start().trustedProxyCidrs, "unset is loopback")
    }

    /**
     * A blank list keeps the meaning it had (decided on 2026-11-17): a blank `ANDVARI_TRUSTED_PROXY_CIDRS` trusts no
     * proxy, not even loopback, and a blank `ANDVARI_TRUSTED_IP_HEADERS` reads no forwarded header. For a while both took
     * the default, which turned a proxy and a header the operator had switched off back on.
     */
    @Test
    fun aBlankList_meansNone_asItAlwaysHas() {
        for (blank in listOf("", " ", " , ,")) {
            val proxies = start("ANDVARI_TRUSTED_PROXY_CIDRS" to blank)
            assertEquals(emptyList(), proxies.trustedProxyCidrs, "'$blank'")
            assertEquals(emptyList(), proxies.trustedProxyNets, "'$blank': no peer is a trusted proxy")
            assertEquals(emptyList(), start("ANDVARI_TRUSTED_IP_HEADERS" to blank).trustedIpHeaders, "'$blank'")
        }
        assertEquals(listOf("X-Forwarded-For"), start().trustedIpHeaders, "unset is the default header")
    }

    @Test
    fun aBlankTextSetting_isTheDefault() {
        assertEquals("127.0.0.1", start("ANDVARI_HOST" to "").host)
        assertEquals("andvari.db", start("ANDVARI_DB" to " ").dbPath)
        assertEquals(null, start("ANDVARI_SMTP_HOST" to " ").smtpHost)
    }
}
