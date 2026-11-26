package io.silencelen.andvari.app

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One app, one key (decided on 2026-11-16): a release build of the app's own id refuses any keystore whose certificate
 * is not the one spec/public-instance.json records. Two throwaway keystores, made here with keytool, stand in for the
 * app's key and for any other; no real key is read.
 */
class ReleaseSigningCheckTest {
    private val ownId = "com.andvaripass.app"
    private val buildFile = File("build.gradle.kts").readText()

    private fun keytool(): String = File(System.getProperty("java.home"), "bin/keytool").takeIf { it.canExecute() }?.path ?: "keytool"

    private fun keytool(vararg args: String): String {
        val p = ProcessBuilder(keytool(), *args).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        assertEquals(0, p.waitFor(), out)
        return out
    }

    private fun store(dir: File, name: String): File {
        val f = File(dir, "$name.p12")
        keytool(
            "-genkeypair", "-keystore", f.path, "-storetype", "PKCS12", "-storepass", "throwaway", "-keypass", "throwaway",
            "-alias", "k", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=$name", "-validity", "2", "-noprompt",
        )
        return f
    }

    /** The fingerprint as keytool prints it: the check's own digest is not used to make the expected value. */
    private fun fingerprint(f: File): String =
        assertNotNull(Regex("SHA256: ([0-9A-F:]{95})").find(keytool("-list", "-v", "-keystore", f.path, "-storepass", "throwaway", "-alias", "k"))).groupValues[1]

    private fun marked(text: String): String =
        text.substringAfter("// BEGIN releaseCertificateMismatch\n").substringBefore("// END releaseCertificateMismatch")

    @Test
    fun theAppsOwnKeyPassesAndAnyOtherKeyIsRefusedWithOneSentence() {
        val dir = Files.createTempDirectory("release-key-check").toFile()
        try {
            val own = store(dir, "own")
            val other = store(dir, "other")
            val expected = fingerprint(own)
            assertNull(releaseCertificateMismatch(own, "throwaway", "k", expected, ownId))
            assertNull(releaseCertificateMismatch(own, "throwaway", "k", expected.lowercase(), ownId), "either case")

            val said = assertNotNull(releaseCertificateMismatch(other, "throwaway", "k", expected, ownId))
            assertTrue(said.contains(fingerprint(other).take(23)) && said.contains(expected.take(23)), said)
            assertTrue(said.endsWith("$ownId is signed only with the app's own key."), said)
            assertEquals(1, said.lines().size, "one line")
            assertFalse(said.contains(fingerprint(other)), "the first bytes only")
            // No certificate under the alias is a refusal too, never a pass.
            assertNotNull(releaseCertificateMismatch(own, "throwaway", "missing", expected, ownId))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun theBuildRunsTheTestedCheckOnlyForTheAppsOwnIdAndOnlyWithReleaseSigningConfigured() {
        assertEquals(marked(File("src/test/kotlin/io/silencelen/andvari/app/ReleaseSigningCheck.kt").readText()), marked(buildFile), "the build's copy is the tested one")
        val spec = File("../spec/public-instance.json").readText()
        assertTrue(
            spec.contains("\"releaseCertSha256\": \"3C:49:4F:27:57:7F:C3:5D:EA:0F:2A:D7:AF:32:B1:D4:76:BB:70:A2:4F:B7:F3:04:6A:B5:0F:A6:A0:FC:F7:F1\""),
            "the fingerprint is recorded beside the application id",
        )
        assertTrue(buildFile.contains("if (keystoreProps.isNotEmpty() && andvariApplicationId == appOwnId) {"), "no release signing, or another id: nothing is checked")
        assertTrue(buildFile.contains("tasks.matching { it.name == \"preReleaseBuild\" }.configureEach { dependsOn(checkReleaseSigningKey) }"), "before anything is signed")
        assertFalse(buildFile.contains("is not confirmed by the owner"), "the id was confirmed on 2026-11-15")
        // The dev build and the debug build keep their own keys: nothing of the check is in the debug signing block.
        val debugSigning = buildFile.substringAfter("getByName(\"debug\") {\n            val dev = devSigning").substringBefore("        if (keystoreProps.isNotEmpty()) {")
        assertFalse(debugSigning.contains("releaseCertificateMismatch"))
    }
}
