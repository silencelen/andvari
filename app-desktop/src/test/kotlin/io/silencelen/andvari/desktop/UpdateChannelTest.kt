package io.silencelen.andvari.desktop

import com.sun.net.httpserver.HttpServer
import io.silencelen.andvari.core.client.UpdateVerify
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.desktop.trust.Placeholder
import io.silencelen.andvari.desktop.trust.UiText
import io.silencelen.andvari.desktop.trust.updateStatusLines
import java.io.File
import java.net.InetSocketAddress
import java.net.URI
import java.nio.file.Files
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes

/**
 * By the owner's decision of 2026-11-15: the attached server sets the update channel,
 * GitHub's releases are the default; nothing before a server is chosen; never the old address; whatever the source,
 * the list is verified against the pinned key, with the rollback floor.
 */
class UpdateChannelTest {
    private val crypto = createCryptoProvider()
    private val keys = crypto.signKeypairFromSeed(ByteArray(32) { 7 })
    private val pinned = listOf(Bytes.toB64(keys.publicKey))
    private val verify: (ByteArray, ByteArray) -> Boolean = { raw, sig -> UpdateVerify.verify(crypto, raw, sig, pinned) }
    private val linux = false to false

    private fun manifest(seq: Long, version: String, signedAt: String = Instant.now().toString()) =
        """{"seq":$seq,"signedAt":"$signedAt","linux":{"version":"$version","url":"/downloads/a.deb","sha256":"aa"},"windows":{"version":"$version","url":"/downloads/a.msi","sha256":"bb"}}"""
            .toByteArray()

    private fun signed(raw: ByteArray) = Bytes.toB64(crypto.signDetached(keys.privateKey, raw)).toByteArray()

    /** A fake network: url to answer; every URL asked is recorded. */
    private class Net(val answers: Map<String, Fetched>) {
        val asked = ArrayList<String>()
        fun fetch(url: String, limit: Int): Fetched {
            asked += url
            return answers[url] ?: Fetched.Missing
        }
    }

    private fun serve(base: String, raw: ByteArray, sig: ByteArray) =
        mapOf("$base/downloads/manifest.json" to Fetched.Body(raw), "$base/downloads/manifest.json.sig" to Fetched.Body(sig))

    private fun github(raw: ByteArray, sig: ByteArray) =
        mapOf(UpdateChannel.GITHUB_MANIFEST_URL to Fetched.Body(raw), UpdateChannel.GITHUB_MANIFEST_URL + ".sig" to Fetched.Body(sig))

    private fun check(origin: String?, net: Net, floor: Long = 0, sources: List<UpdateSource> = UpdateChannel.sources(origin)) =
        checkForUpdates(origin, floor, nowMs = 1000, enabled = true, sources = sources, fetch = net::fetch, verify = verify, platform = linux)

    /** The address pattern the release process must publish to. */
    @Test
    fun theGitHubAddressPattern() {
        assertEquals("https://github.com/silencelen/andvari/releases/latest/download/manifest.json", UpdateChannel.GITHUB_MANIFEST_URL)
        assertEquals("https://github.com/silencelen/andvari/releases/latest/download/manifest.json.sig", UpdateSource.GitHubReleases.signatureUrl)
        assertEquals("https://github.com/silencelen/andvari/releases/latest", UpdateChannel.GITHUB_RELEASES_PAGE)
        assertEquals("https://vault.example/downloads/manifest.json", UpdateSource.Server("https://vault.example").manifestUrl)
    }

    @Test
    fun nothingIsAskedBeforeAServerIsChosenAndTheSwitchTurnsGitHubOn() {
        assertFalse(UpdateChannel.ASK_GITHUB_BEFORE_A_SERVER, "built as nothing until the owner says otherwise")
        assertEquals(emptyList(), UpdateChannel.sources(null))
        assertEquals(listOf(UpdateSource.GitHubReleases), UpdateChannel.sources(null, askGitHubBeforeAServer = true))
        val net = Net(emptyMap())
        val r = check(null, net)
        assertEquals(UpdateCheck.NotAsked, r.check)
        assertTrue(net.asked.isEmpty(), "no request at all")
    }

    @Test
    fun theOldAddressIsNeverAsked() {
        for (old in listOf("https://andvari.monahanhosting.com", "https://andvari.monahanhosting.com/", "https://ANDVARI.monahanhosting.com.")) {
            assertEquals(listOf(UpdateSource.GitHubReleases), UpdateChannel.sources(old), old)
        }
        assertFalse(UpdateChannel.mayAsk(URI("https://andvari.monahanhosting.com/downloads/manifest.json")))
        assertFalse(UpdateChannel.mayAsk(URI("https://x.${UpdateChannel.RETIRED_HOST}/")))
        assertTrue(UpdateChannel.mayAsk(URI("https://objects.githubusercontent.com/x")))
        // A redirect there is refused before any connection is made.
        assertEquals(Fetched.Refused, fetchUpdateFile("https://andvari.monahanhosting.com/downloads/manifest.json", 1024))
    }

    @Test
    fun theAttachedServerIsAskedFirstAndGitHubIsNotAskedWhenItServesAList() {
        val raw = manifest(5, "99.0.0")
        val net = Net(serve("https://vault.example", raw, signed(raw)))
        val r = check("https://vault.example/", net)
        assertEquals(UpdateSource.Server("https://vault.example"), r.from)
        val got = assertIs<UpdateCheck.Available>(r.check)
        assertEquals(UpdateCheck.Available("99.0.0", 5), got.copy(signedAt = ""))
        assertTrue(r.signedAt.isNotBlank() && r.signedAt == got.signedAt, "the list's own signed date is carried for About")
        assertEquals(listOf("https://vault.example/downloads/manifest.json", "https://vault.example/downloads/manifest.json.sig"), net.asked)
    }

    @Test
    fun aServerThatServesNoneHandsOverToGitHub() {
        val raw = manifest(5, "0.0.1")
        val net = Net(github(raw, signed(raw)))
        val r = check("https://vault.example", net)
        assertEquals(UpdateSource.GitHubReleases, r.from)
        assertIs<UpdateCheck.UpToDate>(r.check)
    }

    @Test
    fun aSourceCanWithholdButNeverForge() {
        val good = manifest(9, "99.0.0")
        val forged = manifest(10, "99.9.9")
        // A forged list (signed by another key) from the server: not believed; GitHub's verified one is.
        val other = crypto.signKeypairFromSeed(ByteArray(32) { 1 })
        val forgedSig = Bytes.toB64(crypto.signDetached(other.privateKey, forged)).toByteArray()
        val net = Net(serve("https://vault.example", forged, forgedSig) + github(good, signed(good)))
        assertEquals(UpdateCheck.Available("99.0.0", 9), assertIs<UpdateCheck.Available>(check("https://vault.example", net).check).copy(signedAt = ""))

        // A replayed list below the floor from the server: not believed either.
        val old = manifest(3, "98.0.0")
        val net2 = Net(serve("https://vault.example", old, signed(old)))
        val r2 = check("https://vault.example", net2, floor = 4)
        assertEquals(UpdateCheck.Unverified, r2.check, "below the floor, and GitHub had none")
        assertEquals(UpdateSource.Server("https://vault.example"), r2.from)

        // A list whose signature is missing is one that cannot be verified, never one that is read.
        val net3 = Net(mapOf("https://vault.example/downloads/manifest.json" to Fetched.Body(good)))
        assertEquals(UpdateCheck.Unverified, check("https://vault.example", net3).check)
    }

    @Test
    fun noSourceReachedIsCouldNotCheck() {
        val net = Net(mapOf(UpdateChannel.GITHUB_MANIFEST_URL to Fetched.Failed))
        val r = check("https://vault.example", net)
        assertEquals(UpdateCheck.Unreachable, r.check)
    }

    @Test
    fun onlyAVerifiedListRatchetsTheFloorAndCountsAsChecked() {
        val dir = Files.createTempDirectory("andvari-l7-upd").toFile()
        try {
            val prefs = DesktopSessionStore(dir)
            recordUpdateReport(prefs, UpdateReport(UpdateSource.GitHubReleases, UpdateCheck.Unverified, 5))
            assertEquals(0, prefs.lastAcceptedSeq)
            assertEquals(0L to "", prefs.lastUpdateCheck)
            recordUpdateReport(prefs, UpdateReport(UpdateSource.Server("https://vault.example"), UpdateCheck.UpToDate(7, "2026-11-01T00:00:00Z"), 1234))
            assertEquals(7, prefs.lastAcceptedSeq)
            assertEquals(1234L to "https://vault.example", DesktopSessionStore(dir).lastUpdateCheck, "kept across starts")
            assertEquals("2026-11-01T00:00:00Z", DesktopSessionStore(dir).lastUpdateListSignedAt, "with the list's own signed date")
            recordUpdateReport(prefs, UpdateReport(UpdateSource.GitHubReleases, UpdateCheck.UpToDate(6), 2000))
            assertEquals(7, prefs.lastAcceptedSeq, "the floor never goes down")
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun aboutShowsWhereAndWhenAndTheTwoQuietStates() {
        val fmt: (Long) -> String = { "T$it" }
        fun lines(r: UpdateReport?, last: Pair<Long, String>, signedAt: String = "1970-01-01T00:00:00.005Z") =
            updateStatusLines(r, last, fmt, signedAt).map { (it as UiText.Ph).placeholder to it.args }
        // Three things: the source, the date the list itself was signed, and when it was last checked.
        assertEquals(listOf(Placeholder.UPDATE_LAST_CHECKED to listOf("https://vault.example", "T5", "T9")), lines(UpdateReport(UpdateSource.Server("https://vault.example"), UpdateCheck.UpToDate(1), 9), 9L to "https://vault.example"))
        assertEquals(
            listOf(Placeholder.UPDATE_LAST_CHECKED to listOf("gh", "T5", "T9"), Placeholder.UPDATE_COULD_NOT_CHECK_SINCE to listOf("T9")),
            lines(UpdateReport(UpdateSource.GitHubReleases, UpdateCheck.Unreachable, 20), 9L to "gh"),
        )
        // No signed date recorded (a list from before this build): said as such, never as today.
        assertEquals(listOf("gh", UiText.ph(Placeholder.UPDATE_SIGNED_NOT_GIVEN).shown(), "T9"), lines(null, 9L to "gh", signedAt = "").single().second)
        // A date that does not parse is shown as the list signed it, cut short and with no control characters.
        assertEquals("not-a-date", lines(null, 9L to "gh", signedAt = "not-a-date\n").single().second[1])
        assertEquals(
            listOf(Placeholder.UPDATE_COULD_NOT_VERIFY to listOf("https://vault.example")),
            lines(UpdateReport(UpdateSource.Server("https://vault.example"), UpdateCheck.Unverified, 20), 0L to ""),
        )
        assertEquals(listOf(Placeholder.UPDATE_NOT_ASKED to emptyList<String>()), lines(UpdateReport(null, UpdateCheck.NotAsked, 1), 0L to ""))
    }

    /** Redirects are followed by hand, each hop checked (GitHub's latest-asset address redirects to its storage). */
    @Test
    fun redirectsAreFollowedHopByHop() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val body = "{\"seq\":1}".toByteArray()
        server.createContext("/hop") { ex ->
            ex.responseHeaders.add("Location", "/final")
            ex.sendResponseHeaders(302, -1)
            ex.close()
        }
        server.createContext("/to-old") { ex ->
            ex.responseHeaders.add("Location", "https://andvari.monahanhosting.com/downloads/manifest.json")
            ex.sendResponseHeaders(302, -1)
            ex.close()
        }
        server.createContext("/final") { ex ->
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}"
            assertContentEquals(body, (fetchUpdateFile("$base/hop", 1024) as Fetched.Body).bytes)
            assertEquals(Fetched.Refused, fetchUpdateFile("$base/to-old", 1024), "never the old address, even by redirect")
            assertEquals(Fetched.Missing, fetchUpdateFile("$base/none", 1024))
            assertEquals(Fetched.Refused, fetchUpdateFile("$base/final", 4), "the cap holds")
        } finally {
            server.stop(0)
        }
    }

    // ---- the attached server, the banner's address and redirects ----

    private fun manifestWithUrl(seq: Long, version: String, url: String) =
        """{"seq":$seq,"signedAt":"${Instant.now()}","linux":{"version":"$version","url":"$url","sha256":"aa"}}""".toByteArray()

    /** The attack: a hostile server relays the genuine list; the banner must not name the server's own page. */
    @Test
    fun theBannerNeverNamesTheRelayingServer() {
        val raw = manifest(50, "99.0.0")
        val net = Net(serve("https://evil.example", raw, signed(raw)))
        val r = check("https://evil.example", net)
        val a = assertIs<UpdateCheck.Available>(r.check)
        val banner = updateBanner(a).shown()
        assertFalse("evil.example" in banner, banner)
        assertTrue(UpdateChannel.GITHUB_RELEASES_PAGE in banner, "the list's relative address gives the project's releases page")
        val main = listOf(File("src/main/kotlin/io/silencelen/andvari/desktop/Main.kt"), File("app-desktop/src/main/kotlin/io/silencelen/andvari/desktop/Main.kt")).first { it.isFile }.readText()
        assertFalse(UpdateChannel.RETIRED_HOST.substringAfter('.').substringBefore('.') in main)
        assertFalse("downloadsPage" in main)
        assertTrue("updateBanner(a).shown()" in main)
    }

    @Test
    fun theBannerNamesTheSignedListsOwnAddressOnlyOnThePublishersHosts() {
        val good = "https://github.com/silencelen/andvari/releases/download/v99.0.0/andvari_99.0.0_amd64.deb"
        val raw = manifestWithUrl(51, "99.0.0", good)
        val a = assertIs<UpdateCheck.Available>(check("https://evil.example", Net(serve("https://evil.example", raw, signed(raw)))).check)
        assertEquals(good, a.downloadUrl)
        assertEquals("https://andvaripass.com/downloads/andvari.deb", UpdateChannel.bannerAddress("https://andvaripass.com/downloads/andvari.deb"))
        for (bad in listOf(
            "http://andvaripass.com/downloads/andvari.deb", "https://evil.example/andvari.deb", "/downloads/a.deb",
            "https://andvaripass.com.evil.example/a.deb", "https://user@andvaripass.com/a.deb", "https://andvaripass.com:8443/a.deb",
            "https://github.com/someone-else/andvari/releases/download/v1/a.deb", "https://evil.andvaripass.com/a.deb", "", "not a url",
        )) {
            assertEquals(UpdateChannel.GITHUB_RELEASES_PAGE, UpdateChannel.bannerAddress(bad), bad)
        }
        assertEquals(UpdateChannel.GITHUB_RELEASES_PAGE, UpdateChannel.bannerAddress(null))
    }

    /** "Attached" is a server this computer holds an account on; one only on show is never asked. */
    @Test
    fun onlyAServerWithAnAccountHereIsAttached() {
        val invite = FakeScenes.desktopAt(FakeScene.CREATE_ACCOUNT_INVITED).snapshot
        assertNotNull(invite.instance, "a server on show")
        assertNull(attachedOrigin(invite), "an invite's server before any account: not attached")
        assertNull(attachedOrigin(FakeScenes.desktopAt(FakeScene.GATE_TYPED_ADDRESS).snapshot), "a Trust Gate not yet answered")
        assertNull(attachedOrigin(FakeScenes.desktopAt(FakeScene.FIRST_RUN).snapshot))
        assertEquals(UpdateChannel.sources(null), UpdateChannel.sources(attachedOrigin(invite)), "so nothing is asked")
        val locked = FakeScenes.desktopAt(FakeScene.LOCKED)
        assertEquals(assertNotNull(locked.snapshot.locked).prompt.instance.origin, attachedOrigin(locked.snapshot))
        val open = FakeScenes.desktopAt(FakeScene.VAULTS)
        assertEquals(assertNotNull(open.snapshot.instance).label.origin, attachedOrigin(open.snapshot))
        open.script.sessionEndedByServer()
        open.signInAgain(assertNotNull(open.snapshot.locked))
        assertEquals(assertNotNull(open.snapshot.keptSignedOut).instance.origin, attachedOrigin(open.snapshot), "a kept account its server signed out")
    }

    /** The update fetch follows no redirect to another host (GitHub's own asset hosts from github.com only). */
    @Test
    fun noRedirectToAnotherHost() {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/away") { ex ->
            ex.responseHeaders.add("Location", "http://localhost:${server.address.port}/final")
            ex.sendResponseHeaders(302, -1)
            ex.close()
        }
        server.createContext("/final") { ex ->
            ex.sendResponseHeaders(200, 2)
            ex.responseBody.use { it.write("{}".toByteArray()) }
        }
        server.start()
        try {
            val base = "http://127.0.0.1:${server.address.port}"
            assertEquals(Fetched.Refused, fetchUpdateFile("$base/away", 1024), "127.0.0.1 to localhost is another host")
            assertIs<Fetched.Body>(fetchUpdateFile("$base/final", 1024))
        } finally {
            server.stop(0)
        }
        assertTrue(UpdateChannel.mayRedirect(URI("https://github.com/a"), URI("https://objects.githubusercontent.com/b")))
        assertTrue(UpdateChannel.mayRedirect(URI("https://github.com/a"), URI("https://release-assets.githubusercontent.com/b")))
        assertFalse(UpdateChannel.mayRedirect(URI("https://vault.example/a"), URI("https://objects.githubusercontent.com/b")), "not from a server")
        assertFalse(UpdateChannel.mayRedirect(URI("https://github.com/a"), URI("https://evil.example/b")))
        assertTrue(UpdateChannel.mayRedirect(URI("https://vault.example/a"), URI("https://VAULT.example/b")))
    }

    // ---- the same, for the paths the first fix did not pin ----

    /** A browser resolves dot segments and encoded slashes: none passes for the publisher's GitHub path. */
    @Test
    fun theBannersAddressCannotWalkOutOfTheProjectsReleases() {
        for (bad in listOf(
            "https://github.com/silencelen/andvari/releases/../../evil/repo/releases/download/v1/a.deb",
            "https://github.com/silencelen/andvari/releases/%2e%2e/%2E%2E/evil/repo/releases/download/v1/a.deb",
            "https://github.com/silencelen/andvari/releases/..%2f..%2fevil/a.deb",
            "https://github.com/silencelen/andvari/releases/./../x",
        )) {
            assertEquals(UpdateChannel.GITHUB_RELEASES_PAGE, UpdateChannel.bannerAddress(bad), bad)
        }
        val good = "https://github.com/silencelen/andvari/releases/download/v99.0.0/andvari_99.0.0_amd64.deb"
        assertEquals(good, UpdateChannel.bannerAddress(good))
    }

    /** A list relayed by the attached server makes the app ask that server's two list files and nothing else. */
    @Test
    fun aRelayedListMakesTheAppAskNothingButTheTwoListFiles() {
        val raw = manifestWithUrl(52, "99.0.0", "https://evil.example/elsewhere/a.deb")
        val net = Net(serve("https://evil.example", raw, signed(raw)))
        val a = assertIs<UpdateCheck.Available>(check("https://evil.example", net).check)
        assertEquals(listOf("https://evil.example/downloads/manifest.json", "https://evil.example/downloads/manifest.json.sig"), net.asked)
        assertEquals(UpdateChannel.GITHUB_RELEASES_PAGE, a.downloadUrl)
        // An origin that carries a path, a query or a fragment is no origin: nothing is asked of it.
        for (o in listOf("https://evil.example/x?y=", "https://evil.example/elsewhere", "https://evil.example#f", "https://evil.example?q")) {
            assertNull(UpdateChannel.serverOrigin(o), o)
            assertEquals(listOf<UpdateSource>(UpdateSource.GitHubReleases), UpdateChannel.sources(o), o)
        }
        assertEquals("https://vault.example:8443", UpdateChannel.serverOrigin("https://vault.example:8443/"))
    }

    @Test
    fun aRedirectToAnotherPortOfTheSameNameIsAnotherHost() {
        assertFalse(UpdateChannel.mayRedirect(URI("https://vault.example/a"), URI("https://vault.example:8443/b")))
        assertTrue(UpdateChannel.mayRedirect(URI("https://vault.example/a"), URI("https://vault.example:443/b")))
        assertFalse(UpdateChannel.mayRedirect(URI("https://github.com/a"), URI("https://objects.githubusercontent.com:8443/b")))
        assertFalse(UpdateChannel.mayRedirect(URI("https://objects.githubusercontent.com/a"), URI("https://release-assets.githubusercontent.com/b")), "only from github.com")
    }
}
