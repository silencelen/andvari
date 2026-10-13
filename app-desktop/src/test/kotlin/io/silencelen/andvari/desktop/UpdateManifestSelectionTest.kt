package io.silencelen.andvari.desktop

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Arch pacman package (2026-10-13) adds a `linuxArch` entry to the signed update manifest,
 * beside the deb's `linux`. Three things must hold, and each has a cheap pure seam:
 *
 *  1. The manifest model is ADDITIVE — a manifest without `linuxArch` (every one published before
 *     the Arch package) still parses, and every pre-existing key keeps its shape.
 *  2. Distro detection is the house convention, exactly: os-release `ID` or any `ID_LIKE` token
 *     EQUAL to `arch`. Omarchy is `ID=omarchy` / `ID_LIKE=arch`. Equality, not prefix.
 *  3. [selectPlatformBuild] picks `linuxArch` on Arch, `linux` elsewhere, `windows` on Windows —
 *     and an Arch build facing a pre-Arch manifest falls back to `linux` (same fleet version)
 *     rather than reporting a quiet, false "up to date".
 */
class UpdateManifestSelectionTest {
    private val json = Json { ignoreUnknownKeys = true }

    private val signedWithArch = """
        {
          "seq": 14, "signedAt": "2026-10-13T00:00:00Z",
          "linux":     { "version": "0.28.0", "url": "/downloads/andvari-0.28.0.deb", "sha256": "aa" },
          "linuxArch": { "version": "0.28.0", "url": "/downloads/andvari-0.28.0-x86_64.pkg.tar.zst", "sha256": "bb" },
          "browserExtension": { "version": "0.27.0", "chromeStoreUrl": "https://example.invalid/x", "chromeUrl": "/downloads/c.zip", "firefoxUrl": "/downloads/f.xpi" },
          "windows":   { "version": "0.28.0", "url": "/downloads/andvari-0.28.0.msi", "sha256": "cc" }
        }
    """.trimIndent()

    // The live seq-13 shape (before the Arch package existed): no linuxArch key at all.
    private val signedBeforeArch = """
        {
          "seq": 13, "signedAt": "2026-09-14T23:47:17Z",
          "linux":   { "version": "0.27.0", "url": "/downloads/andvari-0.27.0.deb", "sha256": "aa" },
          "browserExtension": { "version": "0.27.0", "chromeStoreUrl": "https://example.invalid/x", "chromeUrl": "/downloads/c.zip", "firefoxUrl": "/downloads/f.xpi" },
          "windows": { "version": "0.27.0", "url": "/downloads/andvari-0.27.0.msi", "sha256": "cc" }
        }
    """.trimIndent()

    private fun parse(text: String) = json.decodeFromString(DownloadsManifest.serializer(), text)

    @Test
    fun manifestWithLinuxArchParsesAndKeepsEveryExistingKey() {
        val m = parse(signedWithArch)
        assertEquals(14, m.seq)
        assertEquals("0.28.0", m.linux?.version)
        assertEquals("/downloads/andvari-0.28.0.deb", m.linux?.url)
        assertEquals("0.28.0", m.linuxArch?.version)
        assertEquals("/downloads/andvari-0.28.0-x86_64.pkg.tar.zst", m.linuxArch?.url)
        assertEquals("bb", m.linuxArch?.sha256)
        assertEquals("0.28.0", m.windows?.version)
    }

    @Test
    fun manifestWithoutLinuxArchStillParsesAdditively() {
        val m = parse(signedBeforeArch)
        assertNull(m.linuxArch)
        assertEquals("0.27.0", m.linux?.version)
        assertEquals(13, m.seq)
    }

    @Test
    fun archDetectionIsTheHouseConvention() {
        // Omarchy, verbatim shape: ID is not arch, ID_LIKE is.
        assertTrue(isArchLike("NAME=\"Omarchy\"\nID=omarchy\nID_LIKE=arch\nPRETTY_NAME=\"Omarchy\"\n"))
        // Arch itself.
        assertTrue(isArchLike("NAME=\"Arch Linux\"\nID=arch\nBUILD_ID=rolling\n"))
        // Quoted ID_LIKE with several tokens, arch among them.
        assertTrue(isArchLike("ID=manjaro\nID_LIKE=\"arch somethingelse\"\n"))
        assertTrue(isArchLike("ID=endeavouros\nID_LIKE='arch'\n"))
        // Debian/Ubuntu: neither key says arch.
        assertFalse(isArchLike("PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n"))
        assertFalse(isArchLike("ID=ubuntu\nID_LIKE=debian\n"))
        assertFalse(isArchLike("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"))
        // Token EQUALITY: a prefix match would be a different (wrong) convention.
        assertFalse(isArchLike("ID=archcraft\nID_LIKE=archlinux\n"))
        // Only the two keys count; a comment or an unrelated field mentioning arch does not.
        assertFalse(isArchLike("# ID=arch\nNAME=arch\nVARIANT_ID=arch\n"))
        assertFalse(isArchLike(""))
    }

    @Test
    fun selectionPicksThisBuildsPackageFamily() {
        val m = parse(signedWithArch)
        assertEquals("/downloads/andvari-0.28.0.msi", selectPlatformBuild(m, isWindows = true, isArch = false)?.url)
        assertEquals("/downloads/andvari-0.28.0-x86_64.pkg.tar.zst", selectPlatformBuild(m, isWindows = false, isArch = true)?.url)
        assertEquals("/downloads/andvari-0.28.0.deb", selectPlatformBuild(m, isWindows = false, isArch = false)?.url)
        // Windows wins even if a detector misfired on os-release text.
        assertEquals("/downloads/andvari-0.28.0.msi", selectPlatformBuild(m, isWindows = true, isArch = true)?.url)
    }

    @Test
    fun archBuildFallsBackToLinuxWhenTheManifestPredatesTheArchPackage() {
        val old = parse(signedBeforeArch)
        assertEquals("0.27.0", selectPlatformBuild(old, isWindows = false, isArch = true)?.version)
        // A present-but-empty linuxArch entry is the same as an absent one.
        val blank = parse(signedWithArch.replace("\"version\": \"0.28.0\", \"url\": \"/downloads/andvari-0.28.0-x86_64.pkg.tar.zst\"", "\"version\": \"\", \"url\": \"\""))
        assertEquals("/downloads/andvari-0.28.0.deb", selectPlatformBuild(blank, isWindows = false, isArch = true)?.url)
    }
}
