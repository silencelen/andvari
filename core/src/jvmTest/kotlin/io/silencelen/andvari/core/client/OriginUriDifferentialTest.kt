package io.silencelen.andvari.core.client

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * iOS parses server addresses with [parseUriRfc2396] and the JVM with java.net.URI. The two must
 * agree, because this parse decides whether a typed address reaches the Trust Gate and which
 * host it shows. Generated input is seeded, so a failure reproduces.
 */
class OriginUriDifferentialTest {
    private val tokens = listOf(
        "http", "https", "HTTP", "ftp", "h2", "1a", ":", "//", "/", "?", "#", "@", "[", "]", "%", "%41", "%4", "%zz", ".", "..", "-", "_",
        "+", "a", "Z", "9", "a-b", "-a", "a-", "example.com", "example.com.", "EXAMPLE.org", "1.2.3.4", "1.2.3", "256.1.1.1", "1.2.3.4.5",
        "01.02.03.004", "1234.1.1.1", "::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7:8:9", "::ffff:1.2.3.4",
        "1:2:3:4:5:6:1.2.3.4", "12345::", "g::", "[::1]", "[::]", "[1:2:3:4:5:6:7:8]", "[::ffff:1.2.3.4]", "[fe80::1%25en0]", "[fe80::1%en0]",
        "[fe80::1%]", "[::1", "::1]", ":80", ":443", ":8443", ":0", ":65536", ":99999999999", ":abc", ":8a", "user", "user:pw", "u@v", "a@b@c",
        "\u00e9", "\u00a0", "\u0080", "\u0081", "\u2003", "\u2028", "\u4e2d", "\ud83d\ude00", " ", "\t", "\n", "\\", "|", "^", "`", "{", "}",
        "<", ">", "\"", "'", "(", ")", "*", "!", "~", "$", ",", ";", "=", "&",
    )

    private fun describe(p: UriParts?): String =
        if (p == null) "malformed" else listOf(p.scheme, p.userInfo, p.host, p.port, p.rawPath, p.rawQuery, p.rawFragment).toString()

    private fun check(input: String) = assertEquals(describe(parseUriParts(input)), describe(parseUriRfc2396(input)), "input: <$input>")

    @Test
    fun realisticAddressesAgree() {
        val schemes = listOf("https://", "http://", "HTTPS://", "ftp://", "", "//", "https:", "https:/", "mailto:")
        val users = listOf("", "user@", "user:pw@", "real.host@", "a@b@", "@")
        val hosts = tokens.filter { it.any(Char::isLetterOrDigit) || it in listOf("", "::") } + "my_host" + "x.y_z.com" + "a..b" + ".a" + "localhost"
        val ports = listOf("", ":", ":80", ":443", ":8443", ":65535", ":65536", ":2147483647", ":2147483648", ":x")
        val tails = listOf("", "/", "/a", "//", "?", "?q=1", "#", "#f", "/?#", "/a b", "%", "%2f", "\\", "/\u00e9")
        for (a in schemes) for (b in users) for (c in hosts) for (d in ports) for (e in tails) check(a + b + c + d + e)
    }

    @Test
    fun generatedStringsAgree() {
        val random = Random(20261109)
        repeat(400_000) { check(buildString { repeat(random.nextInt(1, 8)) { append(tokens.random(random)) } }) }
    }

    @Test
    fun randomCharactersAgree() {
        val random = Random(20261110)
        val pool = (0..0x17f).map { it.toChar() } + "\u2003\u2028\u2029\u3000\ud83d\ude00\ufeff".toList()
        repeat(400_000) {
            val tail = buildString { repeat(random.nextInt(0, 12)) { append(pool.random(random)) } }
            check(listOf("https://", "http:", "", "a://u@").random(random) + tail)
        }
    }
}
